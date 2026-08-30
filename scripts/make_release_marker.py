from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import tarfile
from datetime import datetime
from pathlib import Path
from typing import Any


APP_ID = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
COMPONENT = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW_PATH = re.compile(r"^\.github/workflows/[^@\r\n]+\.ya?ml$")
DIGEST_REFERENCE = re.compile(
    r"^registry\.elfeel\.me/apps/([a-z][a-z0-9-]{1,31})/"
    r"([a-z][a-z0-9-]{0,31})@sha256:[0-9a-f]{64}$"
)
ARTIFACT_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_ARTIFACT_BYTES = 5 * 1024 * 1024 * 1024
OCI_LAYOUT_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar"


def _artifact_provenance(
    plan: dict[str, Any], required_runs: dict[str, Any]
) -> dict[str, Any] | None:
    strategy = plan.get("strategy")
    artifact = plan.get("artifact")
    if strategy == "source-build":
        if artifact is not None:
            raise ValueError("source-build plan contains artifact provenance")
        return None
    if strategy != "artifact-images":
        raise ValueError("plan has an unsupported release strategy")
    fields = {
        "run_id",
        "run_attempt",
        "id",
        "name",
        "digest",
        "size",
        "archive",
        "checksums",
    }
    if not isinstance(artifact, dict) or set(artifact) != fields:
        raise ValueError("artifact release has invalid provenance")
    for key in ("run_id", "run_attempt", "id"):
        value = artifact.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError(f"artifact provenance {key} is invalid")
    size = artifact.get("size")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or not 1 <= size <= MAX_ARTIFACT_BYTES
    ):
        raise ValueError("artifact provenance size is invalid")
    digest = artifact.get("digest")
    if not isinstance(digest, str) or not ARTIFACT_DIGEST.fullmatch(digest):
        raise ValueError("artifact provenance digest is invalid")
    for key in ("name", "archive", "checksums"):
        value = artifact.get(key)
        if (
            not isinstance(value, str)
            or not value
            or any(character in value for character in "\r\n")
        ):
            raise ValueError(f"artifact provenance {key} is invalid")
    matching_runs = [
        run
        for run in required_runs.values()
        if isinstance(run, dict)
        and run.get("id") == artifact["run_id"]
        and run.get("run_attempt") == artifact["run_attempt"]
    ]
    if len(matching_runs) != 1:
        raise ValueError("artifact provenance does not match one required CI run")
    return {key: artifact[key] for key in sorted(fields)}


def make_release(
    plan: dict[str, Any],
    digests: dict[str, str],
    gateway: dict[str, str],
) -> dict[str, Any]:
    app = plan.get("app")
    repository = plan.get("repository")
    source_sha = plan.get("sha")
    if not isinstance(app, str) or not APP_ID.fullmatch(app):
        raise ValueError("plan has an invalid application identifier")
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
        raise ValueError("plan has an invalid source repository")
    if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
        raise ValueError("plan has an invalid source SHA")
    if set(gateway) != {"repository", "workflow_path", "sha"}:
        raise ValueError("gateway identity has unexpected fields")
    if not isinstance(gateway["repository"], str) or not REPOSITORY.fullmatch(
        gateway["repository"]
    ):
        raise ValueError("gateway repository is invalid")
    if not isinstance(gateway["workflow_path"], str) or not WORKFLOW_PATH.fullmatch(
        gateway["workflow_path"]
    ):
        raise ValueError("gateway workflow path is invalid")
    if not isinstance(gateway["sha"], str) or not SHA.fullmatch(gateway["sha"]):
        raise ValueError("gateway SHA is invalid")
    published_at = plan.get("published_at")
    if not isinstance(published_at, str):
        raise ValueError("publication timestamp is invalid")
    try:
        parsed_time = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("publication timestamp is invalid") from error
    if parsed_time.tzinfo is None:
        raise ValueError("publication timestamp must include a timezone")

    components = plan.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("plan has no components")
    expected = {
        component.get("name")
        for component in components
        if isinstance(component, dict)
        and isinstance(component.get("name"), str)
        and COMPONENT.fullmatch(component["name"])
    }
    if (
        len(expected) != len(components)
        or not isinstance(digests, dict)
        or set(digests) != expected
    ):
        raise ValueError("digest set does not exactly match the release components")

    images: dict[str, str] = {}
    for name in sorted(expected):
        reference = digests[name]
        match = DIGEST_REFERENCE.fullmatch(reference)
        if not match or match.group(1) != app or match.group(2) != name:
            raise ValueError(f"component {name} has an out-of-scope digest reference")
        images[name] = reference

    required_runs = plan.get("required_runs")
    if not isinstance(required_runs, dict) or not required_runs:
        raise ValueError("plan has no required CI evidence")
    artifact = _artifact_provenance(plan, required_runs)
    return {
        "version": 2,
        "app": app,
        "repository": repository,
        "source_sha": source_sha,
        "gateway": gateway,
        "published_at": published_at,
        "required_runs": required_runs,
        "artifact": artifact,
        "images": images,
    }


def compact_label(release: dict[str, Any]) -> str:
    serialized = json.dumps(release, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(serialized).decode("ascii").rstrip("=")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _write_blob(root: Path, value: bytes, media_type: str) -> dict[str, Any]:
    encoded = hashlib.sha256(value).hexdigest()
    digest = f"sha256:{encoded}"
    path = root / "blobs" / "sha256" / encoded
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return {"mediaType": media_type, "digest": digest, "size": len(value)}


def _release_layer(release: dict[str, Any]) -> tuple[bytes, bytes]:
    release_json = (
        json.dumps(release, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    timestamp = int(
        datetime.fromisoformat(
            release["published_at"].replace("Z", "+00:00")
        ).timestamp()
    )
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo("release.json")
        member.size = len(release_json)
        member.mode = 0o444
        member.uid = 0
        member.gid = 0
        member.uname = ""
        member.gname = ""
        member.mtime = timestamp
        archive.addfile(member, io.BytesIO(release_json))
    return output.getvalue(), release_json


def write_oci_layout(release: dict[str, Any], output_directory: Path) -> str:
    """Write one deterministic, single-platform OCI release-marker image."""

    root = Path(output_directory)
    if root.exists() or root.is_symlink():
        raise ValueError("release marker OCI output already exists")
    root.mkdir(mode=0o700)

    layer_bytes, _ = _release_layer(release)
    layer = _write_blob(root, layer_bytes, OCI_LAYER_MEDIA_TYPE)
    config_bytes = _canonical_json(
        {
            "architecture": "amd64",
            "os": "linux",
            "created": release["published_at"],
            "config": {
                "Labels": {
                    "org.elfeel.release": compact_label(release),
                    "org.opencontainers.image.revision": release["source_sha"],
                    "org.opencontainers.image.source": (
                        f"https://github.com/{release['repository']}"
                    ),
                }
            },
            "rootfs": {"type": "layers", "diff_ids": [layer["digest"]]},
            "history": [
                {
                    "created": release["published_at"],
                    "created_by": "elfeel release gateway",
                    "comment": "deterministic schema-v2 release marker",
                }
            ],
        }
    )
    config = _write_blob(root, config_bytes, OCI_CONFIG_MEDIA_TYPE)
    manifest_bytes = _canonical_json(
        {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "config": config,
            "layers": [layer],
            "annotations": {
                "org.opencontainers.image.created": release["published_at"],
                "org.opencontainers.image.revision": release["source_sha"],
                "org.opencontainers.image.source": (
                    f"https://github.com/{release['repository']}"
                ),
            },
        }
    )
    manifest = _write_blob(root, manifest_bytes, OCI_MANIFEST_MEDIA_TYPE)
    manifest["platform"] = {"architecture": "amd64", "os": "linux"}
    manifest["annotations"] = {"org.opencontainers.image.ref.name": "release"}

    (root / "oci-layout").write_bytes(
        _canonical_json({"imageLayoutVersion": "1.0.0"})
    )
    (root / "index.json").write_bytes(
        _canonical_json(
            {
                "schemaVersion": 2,
                "mediaType": OCI_LAYOUT_MEDIA_TYPE,
                "manifests": [manifest],
            }
        )
    )
    return manifest["digest"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a schema-v2 OCI release marker")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--digests", type=Path, required=True)
    parser.add_argument("--gateway-repository", required=True)
    parser.add_argument("--gateway-workflow-path", required=True)
    parser.add_argument("--gateway-sha", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()

    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    digests = json.loads(args.digests.read_text(encoding="utf-8"))
    release = make_release(
        plan,
        digests,
        {
            "repository": args.gateway_repository,
            "workflow_path": args.gateway_workflow_path,
            "sha": args.gateway_sha,
        },
    )
    digest = write_oci_layout(release, args.output_directory)
    print(
        f"created deterministic schema-v2 OCI release marker {digest} "
        f"for {release['app']} at {release['source_sha']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
