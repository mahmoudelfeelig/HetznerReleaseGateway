from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import ssl
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import Message
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable, Mapping

from request_oidc import request_token


OCI_LAYOUT_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.oci.image.layer.nondistributable.v1.tar",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
    }
)

CHUNK_SIZE = 8 * 1024 * 1024
MAX_RESPONSE_BODY = 4 * 1024 * 1024
MAX_METADATA_FILE = 4 * 1024 * 1024
MAX_BLOB_SIZE = 1 << 40
MAX_LAYERS = 4096
MAX_ATTEMPTS = 4
HTTP_TIMEOUT_SECONDS = 30

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REPOSITORY_COMPONENT = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*\Z")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_UPLOAD_IDENTIFIER = re.compile(r"[A-Za-z0-9._~=-]+\Z")
_UPLOAD_RANGE = re.compile(r"(?:bytes=)?0-([0-9]+)\Z")
_TOKEN_VALUE = re.compile(r"[^\x00-\x20\x7f]+\Z")

_RETRYABLE_STATUS = frozenset({416, 502, 503, 504})


class RegistryUploadError(RuntimeError):
    """A fail-closed OCI layout or registry protocol error."""


class _TransportError(RegistryUploadError):
    pass


class _AmbiguousUploadOffset(RegistryUploadError):
    pass


@dataclass(frozen=True)
class Descriptor:
    media_type: str
    digest: str
    size: int
    path: Path
    platform: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class OCILayout:
    root: Path
    manifest: Descriptor
    manifest_bytes: bytes
    config: Descriptor
    layers: tuple[Descriptor, ...]

    @property
    def blobs(self) -> tuple[Descriptor, ...]:
        return (self.config, *self.layers)


@dataclass(frozen=True)
class _ImageReference:
    host: str
    repository: str
    tag: str

    @property
    def tagged(self) -> str:
        return f"{self.host}/{self.repository}:{self.tag}"

    def digested(self, digest: str) -> str:
        return f"{self.host}/{self.repository}@{digest}"


@dataclass(frozen=True)
class _Response:
    status: int
    headers: Message
    body: bytes


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers: Message,
        new_url: str,
    ) -> None:
        return None


def _reject_constant(value: str) -> None:
    raise RegistryUploadError(f"JSON contains the unsupported numeric constant {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RegistryUploadError(f"JSON contains a duplicate {key!r} member")
        value[key] = item
    return value


def _decode_json(data: bytes, description: str) -> Any:
    try:
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RegistryUploadError(f"{description} is not strict UTF-8 JSON") from error


def _read_file_limited(path: Path, description: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise RegistryUploadError(f"cannot inspect {description}") from error
    if size < 0 or size > MAX_METADATA_FILE:
        raise RegistryUploadError(f"{description} exceeds the metadata size limit")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise RegistryUploadError(f"cannot read {description}") from error
    if len(data) != size:
        raise RegistryUploadError(f"{description} changed while it was read")
    return data


def _secure_file(root: Path, *parts: str) -> Path:
    candidate = root.joinpath(*parts)
    current = root
    try:
        for part in parts:
            current = current / part
            if current.is_symlink():
                raise RegistryUploadError("OCI layout paths must not contain symbolic links")
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        mode = resolved.stat().st_mode
    except RegistryUploadError:
        raise
    except (OSError, ValueError) as error:
        raise RegistryUploadError("OCI layout contains a missing or escaping file") from error
    if not stat.S_ISREG(mode):
        raise RegistryUploadError("OCI layout descriptors must resolve to regular files")
    return resolved


def _validate_annotations(value: Any, description: str) -> None:
    if value is None:
        return
    if not isinstance(value, dict) or len(value) > 1024:
        raise RegistryUploadError(f"{description} annotations must be a bounded object")
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(item, str)
            or not key
            or len(key) > 1024
            or len(item) > 4096
            or any(ord(character) < 0x20 for character in key + item)
        ):
            raise RegistryUploadError(f"{description} contains an invalid annotation")


def _validate_platform(value: Any, description: str) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not set(value).issubset(
        {"architecture", "os", "os.version", "os.features", "variant", "features"}
    ):
        raise RegistryUploadError(f"{description} has an invalid platform")
    for required in ("architecture", "os"):
        item = value.get(required)
        if (
            not isinstance(item, str)
            or not item
            or len(item) > 64
            or re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", item) is None
        ):
            raise RegistryUploadError(f"{description} has an invalid platform {required}")
    for optional in ("os.version", "variant"):
        item = value.get(optional)
        if item is not None and (
            not isinstance(item, str)
            or not item
            or len(item) > 256
            or any(ord(character) < 0x20 for character in item)
        ):
            raise RegistryUploadError(f"{description} has an invalid platform {optional}")
    for list_name in ("os.features", "features"):
        items = value.get(list_name)
        if items is not None and (
            not isinstance(items, list)
            or len(items) > 256
            or not all(
                isinstance(item, str)
                and item
                and len(item) <= 256
                and not any(ord(character) < 0x20 for character in item)
                for item in items
            )
        ):
            raise RegistryUploadError(f"{description} has invalid platform {list_name}")
    return value


def _validate_descriptor(
    value: Any,
    root: Path,
    description: str,
    allowed_media_types: Iterable[str],
) -> Descriptor:
    if not isinstance(value, dict):
        raise RegistryUploadError(f"{description} must be an OCI descriptor object")
    allowed_keys = {"mediaType", "digest", "size", "annotations", "platform"}
    if not set(value).issubset(allowed_keys):
        raise RegistryUploadError(f"{description} contains unsupported descriptor members")
    media_type = value.get("mediaType")
    if not isinstance(media_type, str) or media_type not in set(allowed_media_types):
        raise RegistryUploadError(f"{description} has an unsupported media type")
    digest = value.get("digest")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise RegistryUploadError(f"{description} must use a lowercase sha256 digest")
    size = value.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_BLOB_SIZE:
        raise RegistryUploadError(f"{description} has an invalid size")
    _validate_annotations(value.get("annotations"), description)
    platform = _validate_platform(value.get("platform"), description)
    algorithm, encoded = digest.split(":", 1)
    path = _secure_file(root, "blobs", algorithm, encoded)
    try:
        actual_size = path.stat().st_size
    except OSError as error:
        raise RegistryUploadError(f"cannot inspect {description} blob") from error
    if actual_size != size:
        raise RegistryUploadError(f"{description} blob size does not match its descriptor")
    try:
        with path.open("rb") as handle:
            actual_digest = f"sha256:{hashlib.file_digest(handle, 'sha256').hexdigest()}"
    except OSError as error:
        raise RegistryUploadError(f"cannot hash {description} blob") from error
    if not hmac.compare_digest(actual_digest, digest):
        raise RegistryUploadError(f"{description} blob digest does not match its descriptor")
    return Descriptor(
        media_type=media_type,
        digest=digest,
        size=size,
        path=path,
        platform=platform,
    )


def load_oci_layout(layout: Path) -> OCILayout:
    """Load and fully validate one single-platform OCI image layout."""

    supplied = Path(layout)
    if supplied.is_symlink():
        raise RegistryUploadError("OCI layout root must not be a symbolic link")
    try:
        root = supplied.resolve(strict=True)
    except OSError as error:
        raise RegistryUploadError("OCI layout does not exist") from error
    if not root.is_dir():
        raise RegistryUploadError("OCI layout must be a directory")

    layout_path = _secure_file(root, "oci-layout")
    layout_value = _decode_json(_read_file_limited(layout_path, "oci-layout"), "oci-layout")
    if layout_value != {"imageLayoutVersion": "1.0.0"}:
        raise RegistryUploadError("oci-layout must declare exactly imageLayoutVersion 1.0.0")

    index_path = _secure_file(root, "index.json")
    index = _decode_json(_read_file_limited(index_path, "index.json"), "index.json")
    if not isinstance(index, dict):
        raise RegistryUploadError("index.json must be an OCI image index object")
    if not set(index).issubset({"schemaVersion", "mediaType", "manifests", "annotations"}):
        raise RegistryUploadError("index.json contains unsupported members")
    index_media_type = index.get("mediaType")
    if index.get("schemaVersion") != 2 or index_media_type not in {
        None,
        OCI_LAYOUT_MEDIA_TYPE,
    }:
        raise RegistryUploadError("index.json has an invalid OCI image index media type")
    _validate_annotations(index.get("annotations"), "index.json")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise RegistryUploadError("OCI layout must contain exactly one image manifest")
    manifest = _validate_descriptor(
        manifests[0], root, "image manifest", {OCI_MANIFEST_MEDIA_TYPE}
    )
    if manifest.size > MAX_METADATA_FILE:
        raise RegistryUploadError("image manifest exceeds the metadata size limit")
    manifest_bytes = _read_file_limited(manifest.path, "image manifest")
    manifest_value = _decode_json(manifest_bytes, "image manifest")
    if not isinstance(manifest_value, dict):
        raise RegistryUploadError("image manifest must be an object")
    if not set(manifest_value).issubset(
        {"schemaVersion", "mediaType", "config", "layers", "annotations", "artifactType", "subject"}
    ):
        raise RegistryUploadError("image manifest contains unsupported members")
    manifest_media_type = manifest_value.get("mediaType")
    if (
        manifest_value.get("schemaVersion") != 2
        or manifest_media_type not in {None, OCI_MANIFEST_MEDIA_TYPE}
        or "artifactType" in manifest_value
        or "subject" in manifest_value
    ):
        raise RegistryUploadError("layout entry must be a plain OCI image manifest v1")
    _validate_annotations(manifest_value.get("annotations"), "image manifest")
    config = _validate_descriptor(
        manifest_value.get("config"), root, "image config", {OCI_CONFIG_MEDIA_TYPE}
    )
    if config.platform is not None:
        raise RegistryUploadError("image config descriptor must not declare a platform")
    if config.size > MAX_METADATA_FILE:
        raise RegistryUploadError("image config exceeds the metadata size limit")
    layer_values = manifest_value.get("layers")
    if not isinstance(layer_values, list) or not 0 <= len(layer_values) <= MAX_LAYERS:
        raise RegistryUploadError("image manifest has an invalid layer list")
    layers = tuple(
        _validate_descriptor(value, root, f"image layer {index}", OCI_LAYER_MEDIA_TYPES)
        for index, value in enumerate(layer_values)
    )
    if any(layer.platform is not None for layer in layers):
        raise RegistryUploadError("image layer descriptors must not declare a platform")
    layer_digests = [layer.digest for layer in layers]
    if len(layer_digests) != len(set(layer_digests)):
        raise RegistryUploadError("image manifest contains duplicate layer digests")

    config_value = _decode_json(_read_file_limited(config.path, "image config"), "image config")
    if not isinstance(config_value, dict):
        raise RegistryUploadError("image config must be an object")
    config_keys = {
        "created",
        "author",
        "architecture",
        "os",
        "os.version",
        "os.features",
        "variant",
        "config",
        "rootfs",
        "history",
    }
    if not set(config_value).issubset(config_keys):
        raise RegistryUploadError("image config contains unsupported top-level members")
    for required in ("architecture", "os"):
        item = config_value.get(required)
        if (
            not isinstance(item, str)
            or not item
            or len(item) > 64
            or re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", item) is None
        ):
            raise RegistryUploadError(f"image config has an invalid {required}")
    for optional in ("created", "author", "os.version", "variant"):
        item = config_value.get(optional)
        if item is not None and (
            not isinstance(item, str)
            or len(item) > 4096
            or any(ord(character) < 0x20 for character in item)
        ):
            raise RegistryUploadError(f"image config has an invalid {optional}")
    os_features = config_value.get("os.features")
    if os_features is not None and (
        not isinstance(os_features, list)
        or len(os_features) > 256
        or not all(isinstance(item, str) and 0 < len(item) <= 256 for item in os_features)
    ):
        raise RegistryUploadError("image config has invalid os.features")
    runtime_config = config_value.get("config")
    if runtime_config is not None and (
        not isinstance(runtime_config, dict) or len(runtime_config) > 4096
    ):
        raise RegistryUploadError("image config runtime settings must be a bounded object")
    history = config_value.get("history")
    if history is not None and (
        not isinstance(history, list)
        or len(history) > 16384
        or not all(isinstance(item, dict) and len(item) <= 16 for item in history)
    ):
        raise RegistryUploadError("image config history must be a bounded object list")
    rootfs = config_value.get("rootfs")
    if not isinstance(rootfs, dict) or set(rootfs) != {"type", "diff_ids"}:
        raise RegistryUploadError("image config must contain an exact OCI rootfs object")
    diff_ids = rootfs.get("diff_ids")
    if rootfs.get("type") != "layers" or not isinstance(diff_ids, list):
        raise RegistryUploadError("image config rootfs must describe layers")
    if len(diff_ids) != len(layers):
        raise RegistryUploadError("image config diff_ids must match the manifest layer count")
    if not all(isinstance(value, str) and _DIGEST.fullmatch(value) for value in diff_ids):
        raise RegistryUploadError("image config contains an invalid diff_id")
    if len(diff_ids) != len(set(diff_ids)):
        raise RegistryUploadError("image config contains duplicate diff_ids")
    if manifest.platform is not None:
        for field in ("architecture", "os", "os.version", "os.features", "variant"):
            if field in manifest.platform and manifest.platform[field] != config_value.get(field):
                raise RegistryUploadError(
                    f"image index platform {field} does not match the image config"
                )

    return OCILayout(
        root=root,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        config=config,
        layers=layers,
    )


def _validate_registry_host(registry_host: str) -> str:
    if (
        not isinstance(registry_host, str)
        or not registry_host
        or registry_host != registry_host.lower()
    ):
        raise RegistryUploadError("registry host must be a lowercase DNS name")
    if any(character.isspace() or ord(character) < 0x20 for character in registry_host):
        raise RegistryUploadError("registry host contains invalid characters")
    try:
        parsed = urllib.parse.urlsplit(f"//{registry_host}")
        port = parsed.port
    except ValueError as error:
        raise RegistryUploadError("registry host contains an invalid port") from error
    if parsed.netloc != registry_host or parsed.username or parsed.password or not parsed.hostname:
        raise RegistryUploadError("registry host must not contain a scheme, path, or userinfo")
    hostname = parsed.hostname
    if hostname != hostname.lower() or len(hostname) > 253:
        raise RegistryUploadError("registry host must be a lowercase DNS name")
    labels = hostname.split(".")
    if any(_HOST_LABEL.fullmatch(label) is None for label in labels):
        raise RegistryUploadError("registry host is not a valid DNS name")
    if port is not None and not 1 <= port <= 65535:
        raise RegistryUploadError("registry host contains an invalid port")
    return registry_host


def _parse_image(image: str, registry_host: str) -> _ImageReference:
    host = _validate_registry_host(registry_host)
    if not isinstance(image, str) or any(
        character.isspace() or ord(character) < 0x20 for character in image
    ):
        raise RegistryUploadError("image reference contains invalid characters")
    prefix = f"{host}/"
    if not image.startswith(prefix) or "@" in image or "://" in image:
        raise RegistryUploadError("image reference must use the selected registry host and a tag")
    repository_and_tag = image[len(prefix) :]
    repository, separator, tag = repository_and_tag.rpartition(":")
    if separator != ":" or _TAG.fullmatch(tag) is None:
        raise RegistryUploadError("image reference must contain a valid immutable tag")
    if not repository or len(repository) > 255:
        raise RegistryUploadError("image repository length is invalid")
    components = repository.split("/")
    if any(_REPOSITORY_COMPONENT.fullmatch(component) is None for component in components):
        raise RegistryUploadError("image repository contains an invalid component")
    return _ImageReference(host=host, repository=repository, tag=tag)


def _origin(url: str) -> tuple[str, str, int]:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise RegistryUploadError("registry returned a malformed URL") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise RegistryUploadError("registry URL must use HTTPS without userinfo or fragments")
    return (parsed.scheme, parsed.hostname.lower(), port or 443)


def _same_origin_url(base_url: str, value: str, description: str) -> str:
    if not isinstance(value, str) or not value or any(
        character.isspace() or ord(character) < 0x20 for character in value
    ):
        raise RegistryUploadError(f"registry returned an invalid {description}")
    resolved = urllib.parse.urljoin(base_url, value)
    if _origin(resolved) != _origin(base_url):
        raise RegistryUploadError(f"registry returned a cross-origin {description}")
    parsed = urllib.parse.urlsplit(resolved)
    if not parsed.path.startswith("/") or "//" in parsed.path:
        raise RegistryUploadError(f"registry returned a malformed {description} path")
    return resolved


def _single_header(headers: Message, name: str, description: str) -> str:
    values = headers.get_all(name, [])
    if len(values) != 1 or not values[0] or "\r" in values[0] or "\n" in values[0]:
        raise RegistryUploadError(f"registry response lacks one exact {description} header")
    return values[0].strip()


def _optional_single_header(headers: Message, name: str, description: str) -> str | None:
    values = headers.get_all(name, [])
    if not values:
        return None
    if len(values) != 1 or not values[0] or "\r" in values[0] or "\n" in values[0]:
        raise RegistryUploadError(f"registry response has an invalid {description} header")
    return values[0].strip()


def _content_type(headers: Message, expected: str, description: str) -> None:
    value = _single_header(headers, "Content-Type", f"{description} Content-Type")
    if value != expected:
        raise RegistryUploadError(f"registry returned an unexpected {description} media type")


def _content_length(headers: Message, expected: int, description: str) -> None:
    value = _single_header(headers, "Content-Length", f"{description} Content-Length")
    if not value.isascii() or not value.isdigit() or int(value) != expected:
        raise RegistryUploadError(f"registry returned an unexpected {description} size")


def _digest_header(headers: Message, expected: str, description: str) -> None:
    value = _single_header(headers, "Docker-Content-Digest", "Docker-Content-Digest")
    if _DIGEST.fullmatch(value) is None or not hmac.compare_digest(value, expected):
        raise RegistryUploadError(f"registry returned the wrong {description} digest")


def _upload_next_offset(headers: Message, *, reject_ambiguous_zero: bool = False) -> int:
    value = _single_header(headers, "Range", "upload Range")
    match = _UPLOAD_RANGE.fullmatch(value)
    if match is None:
        raise RegistryUploadError("registry returned a malformed upload Range")
    end = int(match.group(1))
    if reject_ambiguous_zero and end == 0:
        raise _AmbiguousUploadOffset(
            "registry returned an ambiguous zero-byte upload Range"
        )
    return end + 1


def _parse_challenge(value: str) -> Mapping[str, str]:
    if not value.startswith("Bearer "):
        raise RegistryUploadError("registry did not return a Bearer challenge")
    source = value[len("Bearer ") :]
    position = 0
    parameters: dict[str, str] = {}
    while position < len(source):
        while position < len(source) and source[position] in " \t,":
            position += 1
        match = re.match(r"([A-Za-z][A-Za-z0-9_-]*)=\"((?:[^\"\\]|\\.)*)\"", source[position:])
        if match is None:
            raise RegistryUploadError("registry returned a malformed Bearer challenge")
        key = match.group(1).lower()
        raw = match.group(2)
        decoded = re.sub(r"\\(.)", r"\1", raw)
        if key in parameters or any(ord(character) < 0x20 for character in decoded):
            raise RegistryUploadError("registry returned a malformed Bearer challenge")
        parameters[key] = decoded
        position += match.end()
        if position < len(source) and source[position] not in " \t,":
            raise RegistryUploadError("registry returned a malformed Bearer challenge")
    if set(parameters) - {"realm", "service", "scope", "error"}:
        raise RegistryUploadError("registry returned unsupported Bearer challenge parameters")
    if not parameters.get("realm") or not parameters.get("service"):
        raise RegistryUploadError("registry Bearer challenge lacks realm or service")
    return parameters


def _read_response_body(response: Any) -> bytes:
    length_values = response.headers.get_all("Content-Length", [])
    declared_length: int | None = None
    if len(length_values) > 1:
        raise RegistryUploadError("registry response contains duplicate Content-Length headers")
    if length_values:
        value = length_values[0]
        if not value.isascii() or not value.isdigit():
            raise RegistryUploadError("registry response has a malformed Content-Length")
        declared_length = int(value)
        if declared_length > MAX_RESPONSE_BODY:
            raise RegistryUploadError("registry response body exceeds the size limit")
    try:
        body = response.read(MAX_RESPONSE_BODY + 1)
    except (http.client.HTTPException, OSError) as error:
        raise _TransportError("registry response ended before it was complete") from error
    if len(body) > MAX_RESPONSE_BODY:
        raise RegistryUploadError("registry response body exceeds the size limit")
    if declared_length is not None and len(body) != declared_length:
        raise _TransportError("registry response ended before its declared Content-Length")
    return body


def _retry_delay(attempt: int) -> None:
    time.sleep(min(0.25 * (2**attempt), 1.0))


class _RegistryClient:
    def __init__(
        self,
        reference: _ImageReference,
        *,
        token_provider: Callable[[str], str] | None = None,
        opener: Any | None = None,
    ) -> None:
        self.reference = reference
        self.base_url = f"https://{reference.host}"
        self._token_provider = request_token if token_provider is None else token_provider
        context = ssl.create_default_context()
        self._opener = opener or urllib.request.build_opener(
            _RejectRedirects(), urllib.request.HTTPSHandler(context=context)
        )
        self._bearer_token: str | None = None

    def _send(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> _Response:
        if _origin(url) != _origin(self.base_url):
            raise RegistryUploadError("refusing to send a registry request across origins")
        request_headers = dict(headers or {})
        if body is not None:
            request_headers["Content-Length"] = str(len(body))
        request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
        try:
            response = self._opener.open(request, timeout=HTTP_TIMEOUT_SECONDS)
        except urllib.error.HTTPError as error:
            response = error
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as error:
            raise _TransportError(
                "registry request failed before a response was received"
            ) from error
        try:
            response_url = response.geturl()
            if response_url != url:
                raise RegistryUploadError("registry redirects are not permitted")
            status = int(response.getcode())
            body_bytes = b"" if method == "HEAD" else _read_response_body(response)
            headers_value = response.headers
            if not isinstance(headers_value, Message):
                converted = Message()
                for name, value in headers_value.items():
                    converted.add_header(name, value)
                headers_value = converted
            return _Response(status=status, headers=headers_value, body=body_bytes)
        finally:
            response.close()

    def authenticate(self) -> None:
        response: _Response | None = None
        for attempt in range(MAX_ATTEMPTS):
            try:
                response = self._send("GET", f"{self.base_url}/v2/")
            except _TransportError:
                response = None
            if response is not None and response.status not in {502, 503, 504}:
                break
            if attempt + 1 < MAX_ATTEMPTS:
                _retry_delay(attempt)
        if response is None:
            raise RegistryUploadError("registry authentication challenge remained unavailable")
        if response.status != 401:
            raise RegistryUploadError(
                "registry did not issue the required authentication challenge"
            )
        challenge_value = _single_header(
            response.headers, "WWW-Authenticate", "WWW-Authenticate"
        )
        challenge = _parse_challenge(challenge_value)
        realm = _same_origin_url(self.base_url, challenge["realm"], "authentication realm")
        if challenge["service"] != self.reference.host:
            raise RegistryUploadError("registry challenge service does not match its host")
        parsed_realm = urllib.parse.urlsplit(realm)
        query = urllib.parse.parse_qsl(parsed_realm.query, keep_blank_values=True)
        if any(key in {"service", "scope", "account"} for key, _ in query):
            raise RegistryUploadError(
                "registry authentication realm contains conflicting query data"
            )
        query.extend(
            [
                ("service", challenge["service"]),
                ("scope", f"repository:{self.reference.repository}:pull,push"),
                ("account", "github-actions"),
            ]
        )
        token_url = urllib.parse.urlunsplit(
            parsed_realm._replace(query=urllib.parse.urlencode(query))
        )
        token_response: _Response | None = None
        for attempt in range(MAX_ATTEMPTS):
            oidc_token = self._token_provider(f"https://{self.reference.host}")
            if not isinstance(oidc_token, str) or not _TOKEN_VALUE.fullmatch(oidc_token):
                raise RegistryUploadError("GitHub returned an invalid OIDC credential")
            basic = base64.b64encode(
                f"github-actions:{oidc_token}".encode("utf-8")
            ).decode("ascii")
            try:
                token_response = self._send(
                    "GET",
                    token_url,
                    headers={
                        "Authorization": f"Basic {basic}",
                        "Accept": "application/json",
                        "User-Agent": "elfeel-release-gateway",
                    },
                )
            except _TransportError:
                token_response = None
            if token_response is not None and token_response.status not in {
                401,
                502,
                503,
                504,
            }:
                break
            if attempt + 1 < MAX_ATTEMPTS:
                _retry_delay(attempt)
        if token_response is None:
            raise RegistryUploadError("registry token endpoint remained unavailable")
        if token_response.status != 200:
            raise RegistryUploadError("registry rejected the GitHub OIDC credential")
        _content_type(token_response.headers, "application/json", "token response")
        token_value = _decode_json(token_response.body, "registry token response")
        if not isinstance(token_value, dict):
            raise RegistryUploadError("registry token response must be an object")
        if not set(token_value).issubset({"token", "access_token", "expires_in", "issued_at"}):
            raise RegistryUploadError("registry token response contains unsupported members")
        candidates = [token_value.get(name) for name in ("token", "access_token")]
        candidates = [value for value in candidates if value is not None]
        if (
            not candidates
            or any(
                not isinstance(value, str) or not _TOKEN_VALUE.fullmatch(value)
                for value in candidates
            )
            or any(not hmac.compare_digest(candidates[0], value) for value in candidates[1:])
        ):
            raise RegistryUploadError("registry returned an invalid Bearer token")
        if len(candidates[0]) > 32768:
            raise RegistryUploadError("registry Bearer token exceeds the size limit")
        expires_in = token_value.get("expires_in")
        if expires_in is not None and (
            isinstance(expires_in, bool)
            or not isinstance(expires_in, int)
            or not 1 <= expires_in <= 300
        ):
            raise RegistryUploadError("registry returned an invalid token lifetime")
        self._bearer_token = candidates[0]

    def _authorization(self) -> dict[str, str]:
        if self._bearer_token is None:
            raise RegistryUploadError("registry client has not authenticated")
        return {"Authorization": f"Bearer {self._bearer_token}"}

    def _authorized_request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> _Response:
        last_transport_error: _TransportError | None = None
        for attempt in range(MAX_ATTEMPTS):
            request_headers = {**self._authorization(), **dict(headers or {})}
            try:
                response = self._send(
                    method,
                    url,
                    headers=request_headers,
                    body=body,
                )
            except _TransportError as error:
                last_transport_error = error
                response = None
            if response is not None and response.status == 401:
                self.authenticate()
            elif response is not None and response.status not in {502, 503, 504}:
                return response
            if attempt + 1 < MAX_ATTEMPTS:
                _retry_delay(attempt)
        raise RegistryUploadError(
            "registry request retries were exhausted"
        ) from last_transport_error

    def _repository_url(self, suffix: str) -> str:
        return f"{self.base_url}/v2/{self.reference.repository}/{suffix}"

    def _validate_upload_location(self, base_url: str, headers: Message) -> str:
        value = _single_header(headers, "Location", "upload Location")
        location = _same_origin_url(base_url, value, "upload Location")
        path = urllib.parse.urlsplit(location).path
        prefix = f"/v2/{self.reference.repository}/blobs/uploads/"
        suffix = path.removeprefix(prefix)
        if path != prefix + suffix or _UPLOAD_IDENTIFIER.fullmatch(suffix) is None:
            raise RegistryUploadError("registry upload Location escaped its repository upload path")
        return location

    def _head_blob(self, descriptor: Descriptor, *, allow_missing: bool) -> bool:
        response = self._authorized_request(
            "HEAD",
            self._repository_url(f"blobs/{descriptor.digest}"),
        )
        if response.status == 404 and allow_missing:
            return False
        if response.status != 200:
            raise RegistryUploadError("registry blob HEAD request failed")
        _digest_header(response.headers, descriptor.digest, "blob")
        _content_length(response.headers, descriptor.size, "blob")
        self._get_blob(descriptor)
        return True

    def _get_blob(self, descriptor: Descriptor) -> None:
        url = self._repository_url(f"blobs/{descriptor.digest}")
        last_transport_error: _TransportError | None = None
        for attempt in range(MAX_ATTEMPTS):
            request = urllib.request.Request(
                url,
                headers=self._authorization(),
                method="GET",
            )
            try:
                response = self._opener.open(request, timeout=HTTP_TIMEOUT_SECONDS)
            except urllib.error.HTTPError as error:
                response = error
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
                last_transport_error = _TransportError("registry blob GET failed")
                response = None
            if response is None:
                if attempt + 1 < MAX_ATTEMPTS:
                    _retry_delay(attempt)
                    continue
                break
            try:
                if response.geturl() != url:
                    raise RegistryUploadError("registry redirects are not permitted")
                status_code = int(response.getcode())
                if status_code == 401:
                    self.authenticate()
                elif status_code in {502, 503, 504}:
                    pass
                elif status_code != 200:
                    raise RegistryUploadError("registry blob GET verification failed")
                else:
                    headers = response.headers
                    if not isinstance(headers, Message):
                        converted = Message()
                        for name, value in headers.items():
                            converted.add_header(name, value)
                        headers = converted
                    _digest_header(headers, descriptor.digest, "blob")
                    _content_length(headers, descriptor.size, "blob")
                    digest = hashlib.sha256()
                    remaining = descriptor.size
                    while remaining:
                        chunk = response.read(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            raise _TransportError(
                                "registry blob ended before its declared size"
                            )
                        if len(chunk) > remaining:
                            raise RegistryUploadError(
                                "registry blob exceeded its declared size"
                            )
                        digest.update(chunk)
                        remaining -= len(chunk)
                    if response.read(1):
                        raise RegistryUploadError(
                            "registry blob exceeded its declared size"
                        )
                    actual = f"sha256:{digest.hexdigest()}"
                    if not hmac.compare_digest(actual, descriptor.digest):
                        raise RegistryUploadError("registry returned corrupt blob bytes")
                    return
            except (http.client.HTTPException, OSError):
                last_transport_error = _TransportError(
                    "registry blob response ended before it was complete"
                )
            except _TransportError as error:
                last_transport_error = error
            finally:
                response.close()
            if attempt + 1 < MAX_ATTEMPTS:
                _retry_delay(attempt)
        raise RegistryUploadError(
            "registry blob GET retries were exhausted"
        ) from last_transport_error

    def _query_upload(self, upload_url: str, known_offset: int) -> tuple[str, int]:
        last_transport_error: _TransportError | None = None
        for attempt in range(MAX_ATTEMPTS):
            try:
                response = self._send("GET", upload_url, headers=self._authorization())
            except _TransportError as error:
                last_transport_error = error
                if attempt + 1 < MAX_ATTEMPTS:
                    _retry_delay(attempt)
                    continue
                raise RegistryUploadError("registry upload status remained unavailable") from error
            if response.status == 401:
                self.authenticate()
                if attempt + 1 < MAX_ATTEMPTS:
                    continue
            if response.status in {502, 503, 504} and attempt + 1 < MAX_ATTEMPTS:
                _retry_delay(attempt)
                continue
            if response.status != 204:
                raise RegistryUploadError("registry returned an invalid upload status response")
            next_url = self._validate_upload_location(upload_url, response.headers)
            return next_url, _upload_next_offset(
                response.headers,
                reject_ambiguous_zero=known_offset == 0,
            )
        raise RegistryUploadError(
            "registry upload status remained unavailable"
        ) from last_transport_error

    def _begin_upload(self) -> str:
        response = self._authorized_request(
            "POST",
            self._repository_url("blobs/uploads/"),
            headers={"Content-Type": "application/octet-stream"},
            body=b"",
        )
        if response.status != 202:
            raise RegistryUploadError("registry refused to start a blob upload")
        minimum = _optional_single_header(
            response.headers,
            "OCI-Chunk-Min-Length",
            "OCI-Chunk-Min-Length",
        )
        if minimum is not None and (
            not minimum.isascii()
            or not minimum.isdigit()
            or int(minimum) > CHUNK_SIZE
        ):
            raise RegistryUploadError("registry requires chunks above the safe size bound")
        return self._validate_upload_location(self.base_url, response.headers)

    def _patch_blob(self, upload_url: str, descriptor: Descriptor, handle: BinaryIO) -> str:
        offset = 0
        while offset < descriptor.size:
            handle.seek(offset)
            chunk = handle.read(min(CHUNK_SIZE, descriptor.size - offset))
            if not isinstance(chunk, bytes) or not chunk:
                raise RegistryUploadError("OCI blob ended before its declared size")
            attempted_end = offset + len(chunk)
            for attempt in range(MAX_ATTEMPTS):
                try:
                    response = self._send(
                        "PATCH",
                        upload_url,
                        headers={
                            **self._authorization(),
                            "Content-Type": "application/octet-stream",
                            "Content-Range": f"{offset}-{attempted_end - 1}",
                        },
                        body=chunk,
                    )
                except _TransportError:
                    response = None
                if response is not None and response.status == 202:
                    next_url = self._validate_upload_location(upload_url, response.headers)
                    next_offset = _upload_next_offset(response.headers)
                    if next_offset != attempted_end:
                        raise RegistryUploadError(
                            "registry acknowledged the wrong upload byte range"
                        )
                    upload_url = next_url
                    offset = next_offset
                    break
                if response is not None and response.status == 401:
                    self.authenticate()
                elif response is not None and response.status not in _RETRYABLE_STATUS:
                    raise RegistryUploadError("registry rejected a blob upload chunk")
                try:
                    upload_url, remote_offset = self._query_upload(upload_url, offset)
                except _AmbiguousUploadOffset:
                    upload_url = self._begin_upload()
                    remote_offset = 0
                if not offset <= remote_offset <= attempted_end:
                    raise RegistryUploadError(
                        "registry upload status moved outside the attempted byte range"
                    )
                offset = remote_offset
                if offset != attempted_end:
                    handle.seek(offset)
                    chunk = handle.read(min(CHUNK_SIZE, descriptor.size - offset))
                    if not isinstance(chunk, bytes) or not chunk:
                        raise RegistryUploadError("OCI blob ended while resuming its upload")
                    attempted_end = offset + len(chunk)
                if offset == attempted_end:
                    break
                if attempt + 1 == MAX_ATTEMPTS:
                    raise RegistryUploadError("registry blob chunk retries were exhausted")
            else:
                raise RegistryUploadError("registry blob chunk retries were exhausted")
        return upload_url

    def _validate_blob_location(self, base_url: str, headers: Message, digest: str) -> None:
        value = _single_header(headers, "Location", "blob Location")
        location = _same_origin_url(base_url, value, "blob Location")
        parsed = urllib.parse.urlsplit(location)
        expected = f"/v2/{self.reference.repository}/blobs/{digest}"
        if parsed.path != expected or parsed.query:
            raise RegistryUploadError("registry returned the wrong finalized blob Location")

    def _finalize_blob(self, upload_url: str, descriptor: Descriptor) -> None:
        for attempt in range(MAX_ATTEMPTS):
            parsed = urllib.parse.urlsplit(upload_url)
            query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            if any(key == "digest" for key, _ in query):
                raise RegistryUploadError("registry upload Location already contains a digest")
            query.append(("digest", descriptor.digest))
            finalize_url = urllib.parse.urlunsplit(
                parsed._replace(query=urllib.parse.urlencode(query))
            )
            try:
                response = self._send(
                    "PUT",
                    finalize_url,
                    headers=self._authorization(),
                    body=b"",
                )
            except _TransportError:
                response = None
            if response is not None and response.status == 201:
                _digest_header(response.headers, descriptor.digest, "finalized blob")
                self._validate_blob_location(finalize_url, response.headers, descriptor.digest)
                self._head_blob(descriptor, allow_missing=False)
                return
            if response is not None and response.status == 401:
                self.authenticate()
            elif response is not None and response.status not in _RETRYABLE_STATUS:
                raise RegistryUploadError("registry rejected blob finalization")
            if self._head_blob(descriptor, allow_missing=True):
                return
            try:
                upload_url, remote_offset = self._query_upload(upload_url, descriptor.size)
            except _AmbiguousUploadOffset:
                if descriptor.size != 0:
                    raise
                upload_url = self._begin_upload()
                remote_offset = 0
            if remote_offset != descriptor.size:
                raise RegistryUploadError("registry lost bytes before blob finalization")
            if attempt + 1 == MAX_ATTEMPTS:
                break
        raise RegistryUploadError("registry blob finalization retries were exhausted")

    def upload_blob(self, descriptor: Descriptor) -> None:
        if self._head_blob(descriptor, allow_missing=True):
            return
        upload_url = self._begin_upload()
        try:
            with descriptor.path.open("rb") as handle:
                file_stat = os.fstat(handle.fileno())
                if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size != descriptor.size:
                    raise RegistryUploadError("OCI blob changed after layout validation")
                actual = f"sha256:{hashlib.file_digest(handle, 'sha256').hexdigest()}"
                if not hmac.compare_digest(actual, descriptor.digest):
                    raise RegistryUploadError("OCI blob changed after layout validation")
                handle.seek(0)
                upload_url = self._patch_blob(upload_url, descriptor, handle)
        except OSError as error:
            raise RegistryUploadError("cannot read OCI blob for publication") from error
        self._finalize_blob(upload_url, descriptor)

    def _manifest_url(self, reference: str) -> str:
        encoded = urllib.parse.quote(reference, safe="._-:")
        return self._repository_url(f"manifests/{encoded}")

    def _get_manifest(self, reference: str, expected_digest: str, expected: bytes) -> None:
        headers = {"Accept": OCI_MANIFEST_MEDIA_TYPE}
        head = self._authorized_request(
            "HEAD",
            self._manifest_url(reference),
            headers=headers,
        )
        if head.status != 200:
            raise RegistryUploadError("registry manifest HEAD verification failed")
        _digest_header(head.headers, expected_digest, "manifest")
        _content_type(head.headers, OCI_MANIFEST_MEDIA_TYPE, "manifest")
        _content_length(head.headers, len(expected), "manifest")
        fetched = self._authorized_request(
            "GET",
            self._manifest_url(reference),
            headers=headers,
        )
        if fetched.status != 200:
            raise RegistryUploadError("registry manifest GET verification failed")
        _digest_header(fetched.headers, expected_digest, "manifest")
        _content_type(fetched.headers, OCI_MANIFEST_MEDIA_TYPE, "manifest")
        _content_length(fetched.headers, len(expected), "manifest")
        actual_digest = f"sha256:{hashlib.sha256(fetched.body).hexdigest()}"
        if (
            not hmac.compare_digest(actual_digest, expected_digest)
            or not hmac.compare_digest(fetched.body, expected)
        ):
            raise RegistryUploadError("registry returned different manifest bytes")

    def tag_state(self, manifest: Descriptor, manifest_bytes: bytes) -> bool:
        response = self._authorized_request(
            "HEAD",
            self._manifest_url(self.reference.tag),
            headers={"Accept": OCI_MANIFEST_MEDIA_TYPE},
        )
        if response.status == 404:
            return False
        if response.status != 200:
            raise RegistryUploadError("registry immutable-tag preflight failed")
        digest = _single_header(response.headers, "Docker-Content-Digest", "Docker-Content-Digest")
        if _DIGEST.fullmatch(digest) is None or not hmac.compare_digest(digest, manifest.digest):
            raise RegistryUploadError("refusing to overwrite an existing immutable tag")
        self._get_manifest(self.reference.tag, manifest.digest, manifest_bytes)
        return True

    def put_manifest(self, manifest: Descriptor, manifest_bytes: bytes) -> None:
        url = self._manifest_url(self.reference.tag)
        for attempt in range(MAX_ATTEMPTS):
            try:
                response = self._send(
                    "PUT",
                    url,
                    headers={
                        **self._authorization(),
                        "Content-Type": OCI_MANIFEST_MEDIA_TYPE,
                        "Accept": OCI_MANIFEST_MEDIA_TYPE,
                        "If-None-Match": "*",
                    },
                    body=manifest_bytes,
                )
            except _TransportError:
                response = None
            if response is not None and response.status == 201:
                _digest_header(response.headers, manifest.digest, "manifest")
                value = _single_header(response.headers, "Location", "manifest Location")
                location = _same_origin_url(self.base_url, value, "manifest Location")
                parsed = urllib.parse.urlsplit(location)
                permitted = {
                    f"/v2/{self.reference.repository}/manifests/{self.reference.tag}",
                    f"/v2/{self.reference.repository}/manifests/{manifest.digest}",
                }
                if parsed.path not in permitted or parsed.query:
                    raise RegistryUploadError("registry returned the wrong manifest Location")
                self._get_manifest(self.reference.tag, manifest.digest, manifest_bytes)
                return
            if response is not None and response.status == 401:
                self.authenticate()
            elif response is not None and response.status not in {
                403,
                409,
                412,
                502,
                503,
                504,
            }:
                raise RegistryUploadError("registry rejected the OCI image manifest")
            if self.tag_state(manifest, manifest_bytes):
                return
            if attempt + 1 < MAX_ATTEMPTS:
                _retry_delay(attempt)
        raise RegistryUploadError("registry manifest publication retries were exhausted")


def publish_oci_layout(layout: Path, image: str, registry_host: str) -> str:
    """Publish one validated OCI layout through bounded Registry V2 chunks.

    The image tag is treated as immutable: an existing tag may be reused only
    when its verified remote manifest is byte-for-byte identical. The registry
    authorization policy must grant create but deny update for these tags;
    conditional creation is sent as an additional client-side guard.
    """

    reference = _parse_image(image, registry_host)
    loaded = load_oci_layout(Path(layout))
    client = _RegistryClient(reference)
    client.authenticate()
    if client.tag_state(loaded.manifest, loaded.manifest_bytes):
        return reference.digested(loaded.manifest.digest)
    for descriptor in loaded.blobs:
        client.upload_blob(descriptor)
    client.put_manifest(loaded.manifest, loaded.manifest_bytes)
    return reference.digested(loaded.manifest.digest)


__all__ = [
    "CHUNK_SIZE",
    "Descriptor",
    "OCILayout",
    "RegistryUploadError",
    "load_oci_layout",
    "publish_oci_layout",
]
