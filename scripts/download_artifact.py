from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ARTIFACT_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:/")
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 5
MAX_ARTIFACT_BYTES = 5 * 1024 * 1024 * 1024
MAX_ZIP_ENTRIES = 256
MAX_UNCOMPRESSED_BYTES = 10 * 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def _return_response(
        self,
        request: urllib.request.Request,
        response: Any,
        code: int,
        message: str,
        headers: Any,
    ) -> Any:
        del request, code, message, headers
        return response

    http_error_301 = _return_response
    http_error_302 = _return_response
    http_error_303 = _return_response
    http_error_307 = _return_response
    http_error_308 = _return_response


def _validated_https_url(url: str) -> str:
    if not isinstance(url, str) or any(ord(character) < 32 for character in url):
        raise RuntimeError("artifact download URL is invalid")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise RuntimeError("artifact download URL is invalid") from error
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port is not None
        and not 1 <= port <= 65535
    ):
        raise RuntimeError("artifact download URL must be HTTPS without user information")
    return url


def _artifact_from_plan(plan: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(plan, dict) or plan.get("strategy") != "artifact-images":
        raise RuntimeError("release plan does not describe an artifact image release")
    repository = plan.get("repository")
    artifact = plan.get("artifact")
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
        raise RuntimeError("release plan has an invalid repository")
    expected_fields = {
        "run_id",
        "run_attempt",
        "id",
        "name",
        "digest",
        "size",
        "archive",
        "checksums",
    }
    if not isinstance(artifact, dict) or set(artifact) != expected_fields:
        raise RuntimeError("release plan has invalid artifact provenance")
    for key in ("run_id", "run_attempt", "id"):
        value = artifact.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise RuntimeError(f"release plan artifact {key} is invalid")
    size = artifact.get("size")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or not 1 <= size <= MAX_ARTIFACT_BYTES
    ):
        raise RuntimeError("release plan artifact size is invalid")
    name = artifact.get("name")
    if not isinstance(name, str) or not name or any(character in name for character in "\r\n"):
        raise RuntimeError("release plan artifact name is invalid")
    digest = artifact.get("digest")
    if not isinstance(digest, str) or not ARTIFACT_DIGEST.fullmatch(digest):
        raise RuntimeError("release plan artifact digest is invalid")
    return repository, artifact


def _open_download(
    url: str,
    token: str,
    opener: Any,
) -> Any:
    current = _validated_https_url(url)
    send_authorization = True
    for redirect_count in range(MAX_REDIRECTS + 1):
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "elfeel-release-gateway",
        }
        if send_authorization:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(current, headers=headers)
        try:
            response = opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            detail = error.read(500).decode("utf-8", errors="replace")
            raise RuntimeError(
                f"artifact download failed with HTTP {error.code}: {detail}"
            ) from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"artifact download request failed: {error.reason}") from error
        status = getattr(response, "status", response.getcode())
        if status == 200:
            return response
        if status not in REDIRECT_STATUSES:
            try:
                detail = response.read(500).decode("utf-8", errors="replace")
            finally:
                response.close()
            raise RuntimeError(f"artifact download failed with HTTP {status}: {detail}")
        location = response.headers.get("Location")
        response.close()
        if redirect_count >= MAX_REDIRECTS:
            raise RuntimeError("artifact download exceeded the redirect limit")
        if not isinstance(location, str) or not location:
            raise RuntimeError("artifact download redirect has no location")
        current = _validated_https_url(urllib.parse.urljoin(current, location))
        send_authorization = False
    raise RuntimeError("artifact download exceeded the redirect limit")


def download_artifact_zip(
    plan: Any,
    token: str,
    api_url: str,
    destination: Path,
    *,
    opener: Any | None = None,
) -> None:
    repository, artifact = _artifact_from_plan(plan)
    base_url = _validated_https_url(api_url.rstrip("/"))
    url = (
        f"{base_url}/repos/{repository}/actions/artifacts/"
        f"{artifact['id']}/zip"
    )
    client = opener or urllib.request.build_opener(_NoRedirect())
    response = _open_download(url, token, client)
    expected_size = artifact["size"]
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        if not content_length.isascii() or not content_length.isdecimal():
            response.close()
            raise RuntimeError("artifact download has an invalid Content-Length")
        if int(content_length) != expected_size:
            response.close()
            raise RuntimeError("artifact download size does not match GitHub metadata")

    digest = hashlib.sha256()
    total = 0
    try:
        with destination.open("xb") as handle:
            while True:
                chunk = response.read(CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > expected_size or total > MAX_ARTIFACT_BYTES:
                    raise RuntimeError("artifact download exceeded its declared size")
                digest.update(chunk)
                handle.write(chunk)
    finally:
        response.close()
    if total != expected_size:
        raise RuntimeError("artifact download size does not match GitHub metadata")
    actual_digest = f"sha256:{digest.hexdigest()}"
    if not hmac.compare_digest(actual_digest, artifact["digest"]):
        raise RuntimeError("artifact download digest does not match GitHub metadata")


def _validated_zip_entries(
    entries: list[zipfile.ZipInfo],
) -> list[tuple[zipfile.ZipInfo, PurePosixPath, bool]]:
    if not 1 <= len(entries) <= MAX_ZIP_ENTRIES:
        raise RuntimeError("artifact ZIP has an invalid number of entries")
    validated: list[tuple[zipfile.ZipInfo, PurePosixPath, bool]] = []
    kinds: dict[str, bool] = {}
    casefolded: set[str] = set()
    uncompressed = 0
    for entry in entries:
        raw_name = entry.orig_filename
        if (
            not isinstance(raw_name, str)
            or not raw_name
            or len(raw_name) > 512
            or any(ord(character) < 32 for character in raw_name)
            or "\\" in raw_name
            or raw_name.startswith("/")
            or WINDOWS_ABSOLUTE_PATH.match(raw_name)
            or entry.flag_bits & 0x41
        ):
            raise RuntimeError("artifact ZIP contains an unsafe entry")
        is_directory = entry.is_dir()
        normalized_name = raw_name[:-1] if is_directory else raw_name
        if not normalized_name or normalized_name.endswith("/"):
            raise RuntimeError("artifact ZIP contains an unsafe entry")
        relative = PurePosixPath(normalized_name)
        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
            or str(relative) != normalized_name
        ):
            raise RuntimeError("artifact ZIP entry escaped its extraction root")
        canonical = str(relative)
        folded = canonical.casefold()
        if canonical in kinds or folded in casefolded:
            raise RuntimeError("artifact ZIP contains duplicate entries")
        kinds[canonical] = is_directory
        casefolded.add(folded)

        mode = (entry.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise RuntimeError("artifact ZIP contains a symlink or special entry")
        if is_directory != (file_type == stat.S_IFDIR) and file_type != 0:
            raise RuntimeError("artifact ZIP entry type is inconsistent")
        if entry.file_size < 0 or entry.compress_size < 0:
            raise RuntimeError("artifact ZIP contains invalid size metadata")
        if is_directory and entry.file_size != 0:
            raise RuntimeError("artifact ZIP directory has file contents")
        if not is_directory:
            uncompressed += entry.file_size
            if uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise RuntimeError("artifact ZIP exceeds the uncompressed size limit")
        validated.append((entry, relative, is_directory))

    for canonical, is_directory in kinds.items():
        relative = PurePosixPath(canonical)
        for parent in relative.parents:
            parent_name = str(parent)
            if parent_name == ".":
                break
            if parent_name in kinds and not kinds[parent_name]:
                raise RuntimeError("artifact ZIP contains conflicting entries")
        if not is_directory and any(
            other.startswith(f"{canonical}/") for other in kinds if other != canonical
        ):
            raise RuntimeError("artifact ZIP contains conflicting entries")
    return validated


def safe_extract_zip(archive_path: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("artifact output directory already exists")
    try:
        parent = destination.parent.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("artifact output parent directory does not exist") from error
    if not parent.is_dir():
        raise RuntimeError("artifact output parent directory does not exist")
    destination = parent / destination.name
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("artifact output directory already exists")
    try:
        with zipfile.ZipFile(archive_path) as archive:
            entries = _validated_zip_entries(archive.infolist())
            with tempfile.TemporaryDirectory(
                prefix="release-artifact-extract-", dir=destination.parent
            ) as directory:
                root = Path(directory) / "payload"
                root.mkdir()
                extracted = 0
                for entry, relative, is_directory in entries:
                    target = root.joinpath(*relative.parts)
                    try:
                        target.resolve().relative_to(root.resolve())
                    except ValueError as error:
                        raise RuntimeError(
                            "artifact ZIP entry escaped its extraction root"
                        ) from error
                    if is_directory:
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    written = 0
                    with archive.open(entry) as source, target.open("xb") as output:
                        while True:
                            chunk = source.read(CHUNK_BYTES)
                            if not chunk:
                                break
                            written += len(chunk)
                            extracted += len(chunk)
                            if (
                                written > entry.file_size
                                or extracted > MAX_UNCOMPRESSED_BYTES
                            ):
                                raise RuntimeError(
                                    "artifact ZIP exceeded its declared extraction size"
                                )
                            output.write(chunk)
                    if written != entry.file_size:
                        raise RuntimeError("artifact ZIP entry size is inconsistent")
                root.replace(destination)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise RuntimeError(f"cannot safely extract artifact ZIP: {error}") from error


def download_and_extract(
    plan: Any,
    token: str,
    api_url: str,
    output_directory: Path,
    *,
    opener: Any | None = None,
) -> None:
    if not output_directory.parent.is_dir():
        raise RuntimeError("artifact output parent directory does not exist")
    with tempfile.TemporaryDirectory(
        prefix="release-artifact-download-", dir=output_directory.parent
    ) as directory:
        archive_path = Path(directory) / "artifact.zip"
        download_artifact_zip(
            plan,
            token,
            api_url,
            archive_path,
            opener=opener,
        )
        safe_extract_zip(archive_path, output_directory)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download and safely extract one immutable GitHub Actions artifact"
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument(
        "--api-url",
        default=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )
    args = parser.parse_args()
    if not args.github_token:
        parser.error("a GitHub token is required")
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        download_and_extract(
            plan,
            args.github_token,
            args.api_url,
            args.output_directory,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError) as error:
        print(f"artifact download failed: {error}", file=sys.stderr)
        return 1
    print(f"downloaded artifact to {args.output_directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
