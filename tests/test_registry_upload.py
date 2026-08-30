from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import registry_upload  # noqa: E402
from registry_upload import (  # noqa: E402
    CHUNK_SIZE,
    Descriptor,
    RegistryUploadError,
    load_oci_layout,
)


HOST = "registry.example.test"
REPOSITORY = "apps/example/web"
TAG = "a" * 40
IMAGE = f"{HOST}/{REPOSITORY}:{TAG}"


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _write_blob(root: Path, value: bytes) -> dict[str, object]:
    digest = _digest(value)
    path = root / "blobs" / "sha256" / digest.removeprefix("sha256:")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return {"digest": digest, "size": len(value)}


def _make_layout(
    root: Path,
    *,
    layers: list[bytes] | None = None,
    diff_ids: list[str] | None = None,
    config_updates: dict[str, object] | None = None,
    omit_config_fields: set[str] | None = None,
    manifest_platform: dict[str, object] | None = None,
) -> tuple[str, bytes]:
    layer_values = layers if layers is not None else [b"first compressed layer"]
    if diff_ids is None:
        diff_ids = [_digest(b"uncompressed:" + value) for value in layer_values]
    config_value: dict[str, object] = {
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": diff_ids},
    }
    config_value.update(config_updates or {})
    for field in omit_config_fields or set():
        config_value.pop(field, None)
    config_bytes = _json_bytes(config_value)
    config = {
        **_write_blob(root, config_bytes),
        "mediaType": registry_upload.OCI_CONFIG_MEDIA_TYPE,
    }
    layer_descriptors = [
        {
            **_write_blob(root, layer),
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        }
        for layer in layer_values
    ]
    manifest_bytes = _json_bytes(
        {
            "schemaVersion": 2,
            "mediaType": registry_upload.OCI_MANIFEST_MEDIA_TYPE,
            "config": config,
            "layers": layer_descriptors,
        }
    )
    manifest = {
        **_write_blob(root, manifest_bytes),
        "mediaType": registry_upload.OCI_MANIFEST_MEDIA_TYPE,
        "annotations": {"org.opencontainers.image.ref.name": TAG},
    }
    if manifest_platform is not None:
        manifest["platform"] = manifest_platform
    (root / "oci-layout").write_bytes(_json_bytes({"imageLayoutVersion": "1.0.0"}))
    (root / "index.json").write_bytes(
        _json_bytes(
            {
                "schemaVersion": 2,
                "mediaType": registry_upload.OCI_LAYOUT_MEDIA_TYPE,
                "manifests": [manifest],
            }
        )
    )
    return manifest["digest"], manifest_bytes


def _headers(**values: str) -> Message:
    headers = Message()
    for name, value in values.items():
        headers.add_header(name.replace("_", "-"), value)
    return headers


def _response(status: int, **headers: str) -> registry_upload._Response:
    return registry_upload._Response(status=status, headers=_headers(**headers), body=b"")


class _FakeHTTPResponse:
    def __init__(
        self,
        url: str,
        status: int,
        *,
        headers: Message | None = None,
        body: bytes = b"",
        response_url: str | None = None,
    ) -> None:
        self._url = response_url or url
        self._status = status
        self.headers = headers or Message()
        self._body = body
        self._position = 0
        self.closed = False

    def geturl(self) -> str:
        return self._url

    def getcode(self) -> int:
        return self._status

    def read(self, amount: int) -> bytes:
        value = self._body[self._position : self._position + amount]
        self._position += len(value)
        return value

    def close(self) -> None:
        self.closed = True


class _FakeOpener:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.requests: list[object] = []

    def open(self, request: object, timeout: int) -> object:
        self.requests.append(request)
        if not self.responses:
            raise AssertionError("unexpected HTTP request")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class OCILayoutTests(unittest.TestCase):
    def test_valid_layout_is_fully_hashed_and_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest, manifest_bytes = _make_layout(root)
            loaded = load_oci_layout(root)
        self.assertEqual(loaded.manifest.digest, digest)
        self.assertEqual(loaded.manifest_bytes, manifest_bytes)
        self.assertEqual(len(loaded.layers), 1)

    def test_optional_index_media_type_may_be_omitted_by_oci_layout_writer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest, _ = _make_layout(root)
            index = json.loads((root / "index.json").read_text(encoding="utf-8"))
            del index["mediaType"]
            (root / "index.json").write_bytes(_json_bytes(index))
            loaded = load_oci_layout(root)
        self.assertEqual(loaded.manifest.digest, digest)

    def test_optional_manifest_media_type_may_be_omitted_from_manifest_body(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_layout(root)
            index = json.loads((root / "index.json").read_text(encoding="utf-8"))
            old_manifest = root / "blobs" / "sha256" / index["manifests"][0][
                "digest"
            ].removeprefix("sha256:")
            value = json.loads(old_manifest.read_text(encoding="utf-8"))
            del value["mediaType"]
            manifest_bytes = _json_bytes(value)
            descriptor = {
                **_write_blob(root, manifest_bytes),
                "mediaType": registry_upload.OCI_MANIFEST_MEDIA_TYPE,
            }
            index["manifests"] = [descriptor]
            (root / "index.json").write_bytes(_json_bytes(index))
            loaded = load_oci_layout(root)
        self.assertEqual(loaded.manifest_bytes, manifest_bytes)

    def test_image_config_requires_architecture_and_os(self) -> None:
        for missing in ("architecture", "os"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _make_layout(root, omit_config_fields={missing})
                with self.assertRaisesRegex(RegistryUploadError, missing):
                    load_oci_layout(root)

    def test_index_platform_must_match_image_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_layout(
                root,
                manifest_platform={"architecture": "arm64", "os": "linux"},
            )
            with self.assertRaisesRegex(RegistryUploadError, "does not match"):
                load_oci_layout(root)

    def test_duplicate_layer_digest_is_rejected_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_layout(
                root,
                layers=[b"same compressed layer", b"same compressed layer"],
                diff_ids=[_digest(b"first diff"), _digest(b"second diff")],
            )
            with self.assertRaisesRegex(RegistryUploadError, "duplicate layer digests"):
                load_oci_layout(root)

    def test_duplicate_diff_ids_are_rejected_before_publication(self) -> None:
        duplicate = _digest(b"same uncompressed layer")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_layout(
                root,
                layers=[b"first compressed layer", b"second compressed layer"],
                diff_ids=[duplicate, duplicate],
            )
            with self.assertRaisesRegex(RegistryUploadError, "duplicate diff_ids"):
                load_oci_layout(root)

    def test_blob_digest_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_layout(root)
            config_path = next(
                path
                for path in (root / "blobs" / "sha256").iterdir()
                if b"rootfs" in path.read_bytes()
            )
            config_path.write_bytes(config_path.read_bytes() + b"tampered")
            with self.assertRaisesRegex(RegistryUploadError, "size does not match"):
                load_oci_layout(root)

    def test_multiple_manifests_and_non_oci_media_types_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_layout(root)
            index = json.loads((root / "index.json").read_text(encoding="utf-8"))
            index["manifests"].append(index["manifests"][0])
            (root / "index.json").write_bytes(_json_bytes(index))
            with self.assertRaisesRegex(RegistryUploadError, "exactly one"):
                load_oci_layout(root)

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symbolic links unavailable")
    def test_blob_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _make_layout(root)
            blob = next((root / "blobs" / "sha256").iterdir())
            original = root / "original-blob"
            blob.replace(original)
            try:
                blob.symlink_to(original)
            except OSError:
                self.skipTest("symbolic links are unavailable")
            with self.assertRaisesRegex(RegistryUploadError, "symbolic links"):
                load_oci_layout(root)


class AuthenticationTests(unittest.TestCase):
    def _client(self, opener: _FakeOpener, provider: mock.Mock) -> registry_upload._RegistryClient:
        reference = registry_upload._parse_image(IMAGE, HOST)
        return registry_upload._RegistryClient(
            reference,
            token_provider=provider,
            opener=opener,
        )

    def test_oidc_is_sent_only_to_same_origin_challenge_realm(self) -> None:
        challenge_headers = _headers(
            WWW_Authenticate=(
                f'Bearer realm="https://{HOST}/zot/auth/token",'
                f'service="{HOST}",scope=""'
            ),
            Content_Length="0",
        )
        token = _json_bytes({"token": "registry.header.payload", "expires_in": 300})
        token_headers = _headers(Content_Type="application/json", Content_Length=str(len(token)))
        opener = _FakeOpener(
            [
                _FakeHTTPResponse(f"https://{HOST}/v2/", 401, headers=challenge_headers),
                _FakeHTTPResponse(
                    (
                        f"https://{HOST}/zot/auth/token?service={HOST}"
                        "&scope=repository%3Aapps%2Fexample%2Fweb%3Apull%2Cpush"
                        "&account=github-actions"
                    ),
                    200,
                    headers=token_headers,
                    body=token,
                ),
            ]
        )
        provider = mock.Mock(return_value="github.header.payload")
        client = self._client(opener, provider)
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            before = set(Path(directory).iterdir())
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                client.authenticate()
            after = set(Path(directory).iterdir())
        provider.assert_called_once_with(f"https://{HOST}")
        first, second = opener.requests
        self.assertIsNone(first.get_header("Authorization"))
        authorization = second.get_header("Authorization")
        self.assertTrue(authorization.startswith("Basic "))
        self.assertNotIn("github.header.payload", authorization)
        self.assertEqual(client._bearer_token, "registry.header.payload")
        self.assertEqual(before, after)
        self.assertNotIn("github.header.payload", output.getvalue())
        self.assertNotIn("registry.header.payload", output.getvalue())
        self.assertFalse(
            any(
                b"github.header.payload" in request.data
                for request in opener.requests
                if request.data
            )
        )
        self.assertFalse(
            any("github.header.payload" in request.full_url for request in opener.requests)
        )
        self.assertFalse(hasattr(registry_upload, "subprocess"))

    def test_cross_origin_realm_is_rejected_before_requesting_oidc(self) -> None:
        challenge = _headers(
            WWW_Authenticate=(
                f'Bearer realm="https://evil.example/token",service="{HOST}",scope=""'
            ),
            Content_Length="0",
        )
        opener = _FakeOpener(
            [_FakeHTTPResponse(f"https://{HOST}/v2/", 401, headers=challenge)]
        )
        provider = mock.Mock(return_value="must.not.escape")
        with self.assertRaisesRegex(RegistryUploadError, "cross-origin"):
            self._client(opener, provider).authenticate()
        provider.assert_not_called()
        self.assertEqual(len(opener.requests), 1)

    def test_redirect_is_rejected_without_following_it(self) -> None:
        opener = _FakeOpener(
            [
                _FakeHTTPResponse(
                    f"https://{HOST}/v2/",
                    302,
                    response_url="https://evil.example/v2/",
                )
            ]
        )
        provider = mock.Mock()
        with self.assertRaisesRegex(RegistryUploadError, "redirects"):
            self._client(opener, provider).authenticate()
        provider.assert_not_called()


class ChunkedUploadTests(unittest.TestCase):
    def _client(self) -> registry_upload._RegistryClient:
        reference = registry_upload._parse_image(IMAGE, HOST)
        client = registry_upload._RegistryClient(reference, opener=_FakeOpener([]))
        client._bearer_token = "registry.header.payload"
        return client

    def test_network_eof_queries_status_and_does_not_blindly_replay_chunk(self) -> None:
        content = b"a" * CHUNK_SIZE + b"end"
        digest = _digest(content)
        upload_url = f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/upload-1"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blob"
            path.write_bytes(content)
            descriptor = Descriptor(
                media_type="application/vnd.oci.image.layer.v1.tar",
                digest=digest,
                size=len(content),
                path=path,
            )
            calls: list[tuple[str, str, dict[str, str], bytes | None]] = []
            scripted: list[object] = [
                _response(404),
                _response(202, Location=upload_url),
                registry_upload._TransportError("simulated EOF"),
                _response(204, Location=upload_url, Range=f"0-{CHUNK_SIZE - 1}"),
                _response(202, Location=upload_url, Range=f"0-{len(content) - 1}"),
                _response(
                    201,
                    Location=f"/v2/{REPOSITORY}/blobs/{digest}",
                    Docker_Content_Digest=digest,
                ),
                _response(200, Docker_Content_Digest=digest, Content_Length=str(len(content))),
            ]

            def send(
                method: str,
                url: str,
                *,
                headers: dict[str, str] | None = None,
                body: bytes | None = None,
            ) -> registry_upload._Response:
                calls.append((method, url, dict(headers or {}), body))
                result = scripted.pop(0)
                if isinstance(result, BaseException):
                    raise result
                return result

            client = self._client()
            with (
                mock.patch.object(client, "_send", side_effect=send),
                mock.patch.object(client, "_get_blob"),
            ):
                client.upload_blob(descriptor)

        self.assertFalse(scripted)
        patches = [call for call in calls if call[0] == "PATCH"]
        self.assertEqual(len(patches), 2)
        self.assertEqual(len(patches[0][3]), CHUNK_SIZE)
        self.assertEqual(patches[0][2]["Content-Range"], f"0-{CHUNK_SIZE - 1}")
        self.assertEqual(patches[1][3], b"end")
        self.assertEqual(
            patches[1][2]["Content-Range"], f"{CHUNK_SIZE}-{len(content) - 1}"
        )
        self.assertEqual([call[0] for call in calls[2:5]], ["PATCH", "GET", "PATCH"])
        finalize = next(call for call in calls if call[0] == "PUT")
        self.assertEqual(finalize[3], b"")
        self.assertIn("digest=sha256%3A", finalize[1])

    def test_401_and_gateway_errors_refresh_or_resume_before_patch_replay(self) -> None:
        for first_status in (401, 502, 503, 504):
            with (
                self.subTest(first_status=first_status),
                tempfile.TemporaryDirectory() as directory,
            ):
                content = b"bounded retry"
                path = Path(directory) / "blob"
                path.write_bytes(content)
                descriptor = Descriptor(
                    media_type="application/vnd.oci.image.layer.v1.tar",
                    digest=_digest(content),
                    size=len(content),
                    path=path,
                )
                upload_url = (
                    f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/retry-{first_status}"
                )
                calls: list[tuple[str, str]] = []
                scripted = [
                    _response(first_status),
                    _response(204, Location=upload_url, Range="bytes=0-0"),
                    _response(
                        202,
                        Location=(
                            f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/"
                            f"replacement-{first_status}"
                        ),
                    ),
                    _response(
                        202,
                        Location=(
                            f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/"
                            f"replacement-{first_status}"
                        ),
                        Range=f"0-{len(content) - 1}",
                    ),
                ]

                def send(
                    method: str,
                    url: str,
                    *,
                    headers: dict[str, str] | None = None,
                    body: bytes | None = None,
                ) -> registry_upload._Response:
                    calls.append((method, url))
                    return scripted.pop(0)

                client = self._client()
                with (
                    path.open("rb") as handle,
                    mock.patch.object(client, "_send", side_effect=send),
                    mock.patch.object(client, "authenticate") as authenticate,
                ):
                    client._patch_blob(upload_url, descriptor, handle)

                self.assertEqual(
                    [method for method, _ in calls],
                    ["PATCH", "GET", "POST", "PATCH"],
                )
                patch_urls = [url for method, url in calls if method == "PATCH"]
                self.assertEqual(patch_urls[0], upload_url)
                self.assertNotEqual(patch_urls[1], upload_url)
                self.assertFalse(scripted)
                self.assertEqual(authenticate.call_count, 1 if first_status == 401 else 0)

    def test_first_patch_eof_with_ambiguous_one_byte_range_restarts_session(self) -> None:
        content = b"server may have committed byte zero"
        descriptor = Descriptor(
            media_type="application/vnd.oci.image.layer.v1.tar",
            digest=_digest(content),
            size=len(content),
            path=Path("unused"),
        )
        original = f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/original"
        replacement = f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/replacement"
        scripted: list[object] = [
            registry_upload._TransportError("simulated EOF after one committed byte"),
            _response(204, Location=original, Range="0-0"),
            _response(202, Location=replacement),
            _response(202, Location=replacement, Range=f"0-{len(content) - 1}"),
        ]
        calls: list[tuple[str, str]] = []

        def send(
            method: str,
            url: str,
            *,
            headers: dict[str, str] | None = None,
            body: bytes | None = None,
        ) -> registry_upload._Response:
            calls.append((method, url))
            result = scripted.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result

        client = self._client()
        with tempfile.TemporaryFile("w+b") as handle:
            handle.write(content)
            handle.seek(0)
            with mock.patch.object(client, "_send", side_effect=send):
                client._patch_blob(original, descriptor, handle)
        self.assertEqual(
            calls,
            [
                ("PATCH", original),
                ("GET", original),
                ("POST", f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/"),
                ("PATCH", replacement),
            ],
        )
        self.assertFalse(scripted)

    def test_upload_range_accepts_oci_and_legacy_prefix_and_rejects_ambiguous_zero(
        self,
    ) -> None:
        self.assertEqual(
            registry_upload._upload_next_offset(_headers(Range="0-9")),
            10,
        )
        self.assertEqual(
            registry_upload._upload_next_offset(_headers(Range="bytes=0-9")),
            10,
        )
        with self.assertRaisesRegex(RegistryUploadError, "ambiguous"):
            registry_upload._upload_next_offset(
                _headers(Range="bytes=0-0"),
                reject_ambiguous_zero=True,
            )

    def test_http_sender_sets_exact_content_length_for_patch_bytes(self) -> None:
        upload_url = f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/content-length"
        response = _FakeHTTPResponse(
            upload_url,
            202,
            headers=_headers(Content_Length="0"),
        )
        opener = _FakeOpener([response])
        reference = registry_upload._parse_image(IMAGE, HOST)
        client = registry_upload._RegistryClient(reference, opener=opener)
        body = b"exact bytes"
        client._send(
            "PATCH",
            upload_url,
            headers={"Content-Range": f"0-{len(body) - 1}"},
            body=body,
        )
        request = opener.requests[0]
        self.assertEqual(request.data, body)
        self.assertEqual(request.get_header("Content-length"), str(len(body)))
        self.assertIsNone(request.get_header("Transfer-encoding"))

    def test_partial_416_resume_starts_at_server_confirmed_offset(self) -> None:
        content = b"x" * (CHUNK_SIZE + 5)
        digest = _digest(content)
        confirmed = CHUNK_SIZE // 2
        upload_url = f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/upload-2"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blob"
            path.write_bytes(content)
            descriptor = Descriptor(
                media_type="application/vnd.oci.image.layer.v1.tar",
                digest=digest,
                size=len(content),
                path=path,
            )
            patches: list[tuple[str, bytes]] = []
            scripted: list[object] = [
                _response(404),
                _response(202, Location=upload_url),
                _response(416),
                _response(204, Location=upload_url, Range=f"0-{confirmed - 1}"),
                _response(202, Location=upload_url, Range=f"0-{len(content) - 1}"),
                _response(
                    201,
                    Location=f"/v2/{REPOSITORY}/blobs/{digest}",
                    Docker_Content_Digest=digest,
                ),
                _response(200, Docker_Content_Digest=digest, Content_Length=str(len(content))),
            ]

            def send(
                method: str,
                url: str,
                *,
                headers: dict[str, str] | None = None,
                body: bytes | None = None,
            ) -> registry_upload._Response:
                if method == "PATCH":
                    patches.append((dict(headers or {})["Content-Range"], body or b""))
                result = scripted.pop(0)
                if isinstance(result, BaseException):
                    raise result
                return result

            client = self._client()
            with (
                mock.patch.object(client, "_send", side_effect=send),
                mock.patch.object(client, "_get_blob"),
            ):
                client.upload_blob(descriptor)

        self.assertFalse(scripted)
        self.assertEqual(patches[0][0], f"0-{CHUNK_SIZE - 1}")
        self.assertEqual(patches[1][0], f"{confirmed}-{len(content) - 1}")
        self.assertLessEqual(len(patches[1][1]), CHUNK_SIZE)

    def test_begin_upload_retries_transient_gateway_response(self) -> None:
        upload_url = f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/begin-retry"
        client = self._client()
        with (
            mock.patch.object(
                client,
                "_send",
                side_effect=[_response(503), _response(202, Location=upload_url)],
            ) as send,
            mock.patch("registry_upload._retry_delay"),
        ):
            self.assertEqual(client._begin_upload(), upload_url)
        self.assertEqual([call.args[0] for call in send.call_args_list], ["POST", "POST"])

    def test_begin_upload_refreshes_expired_bearer(self) -> None:
        upload_url = f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/begin-refresh"
        client = self._client()
        with (
            mock.patch.object(
                client,
                "_send",
                side_effect=[_response(401), _response(202, Location=upload_url)],
            ) as send,
            mock.patch.object(client, "authenticate") as authenticate,
            mock.patch("registry_upload._retry_delay"),
        ):
            self.assertEqual(client._begin_upload(), upload_url)
        authenticate.assert_called_once_with()
        self.assertEqual([call.args[0] for call in send.call_args_list], ["POST", "POST"])

    def test_finalization_gateway_error_checks_status_before_retry(self) -> None:
        content = b"finalized content"
        descriptor = Descriptor(
            media_type="application/vnd.oci.image.layer.v1.tar",
            digest=_digest(content),
            size=len(content),
            path=Path("unused"),
        )
        upload_url = f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/final-retry"
        scripted = [
            _response(502),
            _response(404),
            _response(204, Location=upload_url, Range=f"bytes=0-{len(content) - 1}"),
            _response(
                201,
                Location=f"/v2/{REPOSITORY}/blobs/{descriptor.digest}",
                Docker_Content_Digest=descriptor.digest,
            ),
            _response(
                200,
                Docker_Content_Digest=descriptor.digest,
                Content_Length=str(len(content)),
            ),
        ]
        methods: list[str] = []

        def send(
            method: str,
            url: str,
            *,
            headers: dict[str, str] | None = None,
            body: bytes | None = None,
        ) -> registry_upload._Response:
            methods.append(method)
            return scripted.pop(0)

        client = self._client()
        with (
            mock.patch.object(client, "_send", side_effect=send),
            mock.patch.object(client, "_get_blob"),
        ):
            client._finalize_blob(upload_url, descriptor)
        self.assertEqual(methods, ["PUT", "HEAD", "GET", "PUT", "HEAD"])
        self.assertFalse(scripted)

    def test_zero_length_blob_uses_no_patch(self) -> None:
        client = self._client()
        descriptor = Descriptor(
            media_type="application/vnd.oci.image.layer.v1.tar",
            digest=_digest(b""),
            size=0,
            path=Path("unused"),
        )
        with tempfile.TemporaryFile("w+b") as handle:
            with mock.patch.object(client, "_send") as send:
                upload_url = client._patch_blob(
                    f"https://{HOST}/v2/{REPOSITORY}/blobs/uploads/zero",
                    descriptor,
                    handle,
                )
        self.assertTrue(upload_url.endswith("/zero"))
        send.assert_not_called()

    def test_blob_get_hashes_exact_remote_bytes(self) -> None:
        content = b"verified remote blob"
        descriptor = Descriptor(
            media_type="application/vnd.oci.image.layer.v1.tar",
            digest=_digest(content),
            size=len(content),
            path=Path("unused"),
        )
        url = f"https://{HOST}/v2/{REPOSITORY}/blobs/{descriptor.digest}"
        response = _FakeHTTPResponse(
            url,
            200,
            headers=_headers(
                Docker_Content_Digest=descriptor.digest,
                Content_Length=str(len(content)),
            ),
            body=content,
        )
        reference = registry_upload._parse_image(IMAGE, HOST)
        opener = _FakeOpener([response])
        client = registry_upload._RegistryClient(reference, opener=opener)
        client._bearer_token = "registry.header.payload"
        client._get_blob(descriptor)
        self.assertTrue(response.closed)
        self.assertEqual(len(opener.requests), 1)

    def test_manifest_put_retries_conditionally_and_verifies_result(self) -> None:
        manifest_bytes = b'{"schemaVersion":2}'
        manifest = Descriptor(
            media_type=registry_upload.OCI_MANIFEST_MEDIA_TYPE,
            digest=_digest(manifest_bytes),
            size=len(manifest_bytes),
            path=Path("unused"),
        )
        client = self._client()
        created = _response(
            201,
            Location=f"/v2/{REPOSITORY}/manifests/{manifest.digest}",
            Docker_Content_Digest=manifest.digest,
        )
        with (
            mock.patch.object(client, "_send", side_effect=[_response(503), created]) as send,
            mock.patch.object(client, "tag_state", return_value=False) as tag_state,
            mock.patch.object(client, "_get_manifest") as get_manifest,
            mock.patch("registry_upload._retry_delay"),
        ):
            client.put_manifest(manifest, manifest_bytes)
        self.assertEqual(send.call_count, 2)
        for call in send.call_args_list:
            self.assertEqual(call.kwargs["headers"]["If-None-Match"], "*")
        tag_state.assert_called_once_with(manifest, manifest_bytes)
        get_manifest.assert_called_once_with(TAG, manifest.digest, manifest_bytes)

    def test_manifest_head_and_get_must_match_local_bytes(self) -> None:
        manifest_bytes = b'{"schemaVersion":2}'
        digest = _digest(manifest_bytes)
        common = {
            "Docker_Content_Digest": digest,
            "Content_Length": str(len(manifest_bytes)),
            "Content_Type": registry_upload.OCI_MANIFEST_MEDIA_TYPE,
        }
        head = _response(200, **common)
        fetched = registry_upload._Response(
            status=200,
            headers=_headers(**common),
            body=manifest_bytes,
        )
        client = self._client()
        with mock.patch.object(
            client,
            "_authorized_request",
            side_effect=[head, fetched],
        ):
            client._get_manifest(TAG, digest, manifest_bytes)

    def test_manifest_conditional_conflict_is_reread_not_overwritten(self) -> None:
        manifest_bytes = b'{"schemaVersion":2}'
        manifest = Descriptor(
            media_type=registry_upload.OCI_MANIFEST_MEDIA_TYPE,
            digest=_digest(manifest_bytes),
            size=len(manifest_bytes),
            path=Path("unused"),
        )
        client = self._client()
        with (
            mock.patch.object(client, "_send", return_value=_response(412)) as send,
            mock.patch.object(client, "tag_state", return_value=True) as tag_state,
        ):
            client.put_manifest(manifest, manifest_bytes)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(send.call_args.kwargs["headers"]["If-None-Match"], "*")
        tag_state.assert_called_once_with(manifest, manifest_bytes)

    def test_cross_origin_and_wrong_repository_upload_locations_are_rejected(self) -> None:
        client = self._client()
        client._send = mock.Mock(
            return_value=_response(
                202,
                Location="https://evil.example/v2/apps/example/web/blobs/uploads/id",
            )
        )
        with self.assertRaisesRegex(RegistryUploadError, "cross-origin"):
            client._begin_upload()
        client._send.return_value = _response(
            202,
            Location=f"https://{HOST}/v2/apps/other/web/blobs/uploads/id",
        )
        with self.assertRaisesRegex(RegistryUploadError, "escaped"):
            client._begin_upload()

    def test_existing_immutable_tag_cannot_be_replaced(self) -> None:
        client = self._client()
        manifest = Descriptor(
            media_type=registry_upload.OCI_MANIFEST_MEDIA_TYPE,
            digest="sha256:" + "1" * 64,
            size=2,
            path=Path("unused"),
        )
        client._send = mock.Mock(
            return_value=_response(
                200,
                Docker_Content_Digest="sha256:" + "2" * 64,
                Content_Length="2",
                Content_Type=registry_upload.OCI_MANIFEST_MEDIA_TYPE,
            )
        )
        with self.assertRaisesRegex(RegistryUploadError, "overwrite"):
            client.tag_state(manifest, b"{}")


class InputValidationTests(unittest.TestCase):
    def test_image_must_match_registry_and_standard_repository_grammar(self) -> None:
        reference = registry_upload._parse_image(IMAGE, HOST)
        self.assertEqual(reference.repository, REPOSITORY)
        for image in (
            f"other.example/{REPOSITORY}:{TAG}",
            f"{HOST}/Apps/example/web:{TAG}",
            f"{HOST}/{REPOSITORY}@sha256:" + "a" * 64,
            f"{HOST}/{REPOSITORY}:bad tag",
        ):
            with self.subTest(image=image), self.assertRaises(RegistryUploadError):
                registry_upload._parse_image(image, HOST)


if __name__ == "__main__":
    unittest.main()
