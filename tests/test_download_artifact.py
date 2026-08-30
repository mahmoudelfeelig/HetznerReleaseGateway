from __future__ import annotations

import hashlib
import io
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from download_artifact import (  # noqa: E402
    MAX_ARTIFACT_BYTES,
    MAX_REDIRECTS,
    MAX_UNCOMPRESSED_BYTES,
    MAX_ZIP_ENTRIES,
    _NoRedirect,
    _validated_zip_entries,
    download_and_extract,
    safe_extract_zip,
)

from helpers import SOURCE_SHA  # noqa: E402


def make_zip(entries: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in entries:
            archive.writestr(name, value)
    return output.getvalue()


def artifact_plan(
    payload: bytes, *, digest: str | None = None, size: int | None = None
) -> dict[str, Any]:
    return {
        "strategy": "artifact-images",
        "repository": "owner/example-app",
        "artifact": {
            "run_id": 101,
            "run_attempt": 3,
            "id": 501,
            "name": f"release-{SOURCE_SHA}-attempt-3",
            "digest": digest or f"sha256:{hashlib.sha256(payload).hexdigest()}",
            "size": len(payload) if size is None else size,
            "archive": "images.tar.gz",
            "checksums": "SHA256SUMS",
        },
    }


class FakeResponse(io.BytesIO):
    def __init__(self, payload: bytes, status: int, headers: dict[str, str]) -> None:
        super().__init__(payload)
        self.status = status
        self.headers = headers

    def getcode(self) -> int:
        return self.status


class FakeOpener:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = responses
        self.requests: list[Any] = []

    def open(self, request: Any, timeout: int) -> FakeResponse:
        self.requests.append((request, timeout))
        if not self.responses:
            raise AssertionError("unexpected HTTP request")
        return self.responses.pop(0)


def zip_info(
    name: str,
    *,
    size: int = 0,
    mode: int = 0,
    flag_bits: int = 0,
) -> zipfile.ZipInfo:
    entry = zipfile.ZipInfo(name)
    entry.file_size = size
    entry.compress_size = 0
    entry.flag_bits = flag_bits
    if mode:
        entry.create_system = 3
        entry.external_attr = mode << 16
    return entry


class DownloadArtifactTests(unittest.TestCase):
    def test_download_uses_immutable_id_and_drops_authorization_after_redirect(self) -> None:
        payload = make_zip(
            [("images.tar.gz", b"archive"), ("SHA256SUMS", b"digest  images.tar.gz\n")]
        )
        opener = FakeOpener(
            [
                FakeResponse(b"", 302, {"Location": "https://cdn.example/first"}),
                FakeResponse(b"", 307, {"Location": "https://cdn.example/final"}),
                FakeResponse(payload, 200, {"Content-Length": str(len(payload))}),
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "release-artifact"
            download_and_extract(
                artifact_plan(payload),
                "token",
                "https://api.github.com",
                output,
                opener=opener,
            )
            self.assertEqual((output / "images.tar.gz").read_bytes(), b"archive")
            self.assertTrue((output / "SHA256SUMS").is_file())

        requests = [request for request, _timeout in opener.requests]
        self.assertTrue(requests[0].full_url.endswith("/actions/artifacts/501/zip"))
        self.assertEqual(requests[0].get_header("Authorization"), "Bearer token")
        self.assertIsNone(requests[1].get_header("Authorization"))
        self.assertIsNone(requests[2].get_header("Authorization"))

    def test_production_client_installs_no_redirect_handler(self) -> None:
        payload = make_zip([("images.tar.gz", b"archive")])
        opener = FakeOpener(
            [FakeResponse(payload, 200, {"Content-Length": str(len(payload))})]
        )
        with tempfile.TemporaryDirectory() as directory, patch(
            "download_artifact.urllib.request.build_opener", return_value=opener
        ) as build_opener:
            download_and_extract(
                artifact_plan(payload),
                "token",
                "https://api.github.com",
                Path(directory) / "release-artifact",
            )
        handler = build_opener.call_args.args[0]
        self.assertIsInstance(handler, _NoRedirect)
        response = FakeResponse(b"", 302, {"Location": "https://cdn.example/file"})
        self.assertIs(
            handler.http_error_302(object(), response, 302, "Found", response.headers),
            response,
        )

    def test_download_rejects_insecure_or_credentialed_redirects(self) -> None:
        payload = make_zip([("images.tar.gz", b"archive")])
        for location in (
            "http://cdn.example/artifact.zip",
            "https://user:password@cdn.example/artifact.zip",
        ):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as directory:
                opener = FakeOpener([FakeResponse(b"", 302, {"Location": location})])
                with self.assertRaisesRegex(RuntimeError, "HTTPS without user information"):
                    download_and_extract(
                        artifact_plan(payload),
                        "token",
                        "https://api.github.com",
                        Path(directory) / "release-artifact",
                        opener=opener,
                    )

    def test_download_enforces_redirect_limit(self) -> None:
        payload = make_zip([("images.tar.gz", b"archive")])
        responses = [
            FakeResponse(b"", 302, {"Location": f"https://cdn.example/{index}"})
            for index in range(MAX_REDIRECTS + 1)
        ]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "redirect limit"):
                download_and_extract(
                    artifact_plan(payload),
                    "token",
                    "https://api.github.com",
                    Path(directory) / "release-artifact",
                    opener=FakeOpener(responses),
                )

    def test_digest_and_size_are_verified_before_extraction(self) -> None:
        payload = make_zip([("images.tar.gz", b"archive")])
        cases = (
            ("sha256:" + "0" * 64, len(payload), "digest"),
            (None, len(payload) + 1, "size"),
        )
        for digest, size, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "release-artifact"
                opener = FakeOpener(
                    [FakeResponse(payload, 200, {"Content-Length": str(len(payload))})]
                )
                with self.assertRaisesRegex(RuntimeError, message):
                    download_and_extract(
                        artifact_plan(payload, digest=digest, size=size),
                        "token",
                        "https://api.github.com",
                        output,
                        opener=opener,
                    )
                self.assertFalse(output.exists())

    def test_streaming_size_checks_do_not_depend_on_content_length(self) -> None:
        payload = make_zip([("images.tar.gz", b"archive")])
        cases = (
            (payload[:-1], {}, len(payload), "size"),
            (payload + b"x", {}, len(payload), "declared size"),
            (
                payload + b"x",
                {"Content-Length": str(len(payload))},
                len(payload),
                "declared size",
            ),
            (
                payload,
                {"Content-Length": "not-a-number"},
                len(payload),
                "Content-Length",
            ),
        )
        for body, headers, expected_size, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "release-artifact"
                with self.assertRaisesRegex(RuntimeError, message):
                    download_and_extract(
                        artifact_plan(payload, size=expected_size),
                        "token",
                        "https://api.github.com",
                        output,
                        opener=FakeOpener([FakeResponse(body, 200, headers)]),
                    )
                self.assertFalse(output.exists())

    def test_plan_rejects_nonpositive_or_excessive_size(self) -> None:
        payload = make_zip([("images.tar.gz", b"archive")])
        for size in (0, MAX_ARTIFACT_BYTES + 1):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(RuntimeError, "size"):
                    download_and_extract(
                        artifact_plan(payload, size=size),
                        "token",
                        "https://api.github.com",
                        Path(directory) / "release-artifact",
                        opener=FakeOpener([]),
                    )

    def test_zip_entry_names_reject_escape_absolute_and_backslash_paths(self) -> None:
        for name in ("../escape", "/absolute", "C:/absolute", r"dir\file"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                _validated_zip_entries([zip_info(name)])

    def test_zip_rejects_duplicates_conflicts_encryption_and_special_files(self) -> None:
        cases = (
            [zip_info("same"), zip_info("same")],
            [zip_info("Name"), zip_info("name")],
            [zip_info("parent"), zip_info("parent/child")],
            [zip_info("secret", flag_bits=1)],
            [zip_info("link", mode=stat.S_IFLNK | 0o777)],
            [zip_info("fifo", mode=stat.S_IFIFO | 0o600)],
        )
        for entries in cases:
            with self.subTest(entries=[entry.filename for entry in entries]):
                with self.assertRaises(RuntimeError):
                    _validated_zip_entries(entries)

    def test_zip_enforces_entry_and_uncompressed_size_bounds(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "number of entries"):
            _validated_zip_entries([])
        too_many = [zip_info(f"entry-{index}") for index in range(MAX_ZIP_ENTRIES + 1)]
        with self.assertRaisesRegex(RuntimeError, "number of entries"):
            _validated_zip_entries(too_many)
        with self.assertRaisesRegex(RuntimeError, "uncompressed size"):
            _validated_zip_entries(
                [zip_info("large", size=MAX_UNCOMPRESSED_BYTES + 1)]
            )
        with self.assertRaisesRegex(RuntimeError, "uncompressed size"):
            _validated_zip_entries(
                [
                    zip_info("first", size=MAX_UNCOMPRESSED_BYTES // 2 + 1),
                    zip_info("second", size=MAX_UNCOMPRESSED_BYTES // 2 + 1),
                ]
            )

    def test_safe_extraction_rejects_traversal_before_writing(self) -> None:
        payload = make_zip([("../escape", b"bad"), ("images.tar.gz", b"archive")])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "artifact.zip"
            archive_path.write_bytes(payload)
            output = root / "release-artifact"
            with self.assertRaises(RuntimeError):
                safe_extract_zip(archive_path, output)
            self.assertFalse(output.exists())
            self.assertFalse((root / "escape").exists())

    def test_safe_extraction_rejects_dangling_output_symlink(self) -> None:
        payload = make_zip([("images.tar.gz", b"archive")])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "artifact.zip"
            archive_path.write_bytes(payload)
            output = root / "release-artifact"
            outside = root / "outside"
            try:
                output.symlink_to(outside, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                safe_extract_zip(archive_path, output)
            self.assertTrue(output.is_symlink())
            self.assertFalse(outside.exists())


if __name__ == "__main__":
    unittest.main()
