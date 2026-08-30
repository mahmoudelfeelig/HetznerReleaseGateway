from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from request_oidc import request_token


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CHECKSUM_ENTRY = re.compile(r"^([0-9a-fA-F]{64}) [ *](.+)$")


def run(command: list[str], description: str, *, cwd: Path | None = None) -> None:
    print(description, flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def registry_login(host: str) -> None:
    token = request_token(f"https://{host}")
    print(f"Authenticating to {host} with a short-lived identity", flush=True)
    subprocess.run(
        ["docker", "login", host, "--username", "github-actions", "--password-stdin"],
        input=token,
        text=True,
        check=True,
    )


def inspect_digest(image: str) -> str:
    completed = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"],
        check=True,
        text=True,
        capture_output=True,
    )
    try:
        repo_digests = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"registry returned invalid digest metadata for {image}") from error
    repository = image.rsplit(":", 1)[0]
    if not isinstance(repo_digests, list):
        raise RuntimeError(f"registry returned invalid digest metadata for {image}")
    matches = [
        value
        for value in repo_digests
        if isinstance(value, str) and value.startswith(f"{repository}@")
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one pushed digest for {image}, found {len(matches)}")
    digest = matches[0].split("@", 1)[1]
    if not DIGEST.fullmatch(digest):
        raise RuntimeError(f"registry returned an invalid digest for {image}")
    return f"{repository}@{digest}"


def _safe_source_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise RuntimeError(f"source path escaped its checkout: {relative}") from error
    return candidate


def checksum_for_archive(root: Path, archive: Path, checksums: Path) -> str:
    expected: list[str] = []
    for line in checksums.read_text(encoding="utf-8").splitlines():
        match = CHECKSUM_ENTRY.fullmatch(line)
        if not match:
            continue
        manifest_path = _safe_source_path(root, match.group(2))
        if manifest_path == archive:
            expected.append(match.group(1).lower())
    if len(expected) != 1:
        raise RuntimeError("checksum manifest must cover the selected image archive exactly once")
    with archive.open("rb") as handle:
        actual = hashlib.file_digest(handle, "sha256").hexdigest()
    if not hmac.compare_digest(actual, expected[0]):
        raise RuntimeError("selected image archive checksum does not match the manifest")
    return actual


def publish_source_build(plan: dict[str, Any], source_root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for component in plan["components"]:
        dockerfile = _safe_source_path(source_root, component["dockerfile"])
        context = _safe_source_path(source_root, component["context"])
        if not dockerfile.is_file():
            raise RuntimeError(f"component {component['name']} has no Dockerfile")
        if not context.is_dir():
            raise RuntimeError(f"component {component['name']} has no build context")
        command = [
            "docker",
            "build",
            "--file",
            str(dockerfile),
            "--tag",
            component["destination"],
            "--label",
            f"org.opencontainers.image.revision={plan['sha']}",
            "--label",
            f"org.opencontainers.image.source=https://github.com/{plan['repository']}",
        ]
        if component.get("target"):
            command.extend(["--target", component["target"]])
        for key, value in sorted(component.get("build_args", {}).items()):
            command.extend(["--build-arg", f"{key}={value}"])
        command.append(str(context))
        run(command, f"Building component {component['name']}")
        registry_login(plan["registry"]["host"])
        run(
            ["docker", "push", component["destination"]],
            f"Publishing component {component['name']}",
        )
        run(
            ["docker", "pull", component["destination"]],
            f"Verifying component {component['name']}",
        )
        result[component["name"]] = inspect_digest(component["destination"])
    return result


def publish_artifact_images(
    plan: dict[str, Any], artifact_root: Path, archive: str, checksums: str
) -> dict[str, str]:
    archive_path = _safe_source_path(artifact_root, archive)
    checksums_path = _safe_source_path(artifact_root, checksums)
    if not archive_path.is_file() or not checksums_path.is_file():
        raise RuntimeError("release artifact is missing its image archive or checksum manifest")
    checksum_for_archive(artifact_root, archive_path, checksums_path)
    if archive_path.name.endswith(".tar.gz"):
        run(
            [
                "bash",
                "-o",
                "pipefail",
                "-c",
                'gzip -dc "$1" | docker load',
                "--",
                str(archive_path),
            ],
            "Loading the verified image archive",
        )
    else:
        run(
            ["docker", "load", "--input", str(archive_path)],
            "Loading the verified image archive",
        )

    result: dict[str, str] = {}
    for component in plan["components"]:
        run(
            ["docker", "image", "inspect", component["artifact_image"]],
            f"Inspecting component {component['name']}",
        )
        run(
            ["docker", "tag", component["artifact_image"], component["destination"]],
            f"Tagging component {component['name']}",
        )
        registry_login(plan["registry"]["host"])
        run(
            ["docker", "push", component["destination"]],
            f"Publishing component {component['name']}",
        )
        run(
            ["docker", "pull", component["destination"]],
            f"Verifying component {component['name']}",
        )
        result[component["name"]] = inspect_digest(component["destination"])
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Publish immutable application images")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    if plan["strategy"] == "source-build":
        digests = publish_source_build(plan, args.source_root.resolve())
    elif plan["strategy"] == "artifact-images":
        if args.artifact_root is None:
            parser.error("--artifact-root is required for artifact-images")
        digests = publish_artifact_images(
            plan,
            args.artifact_root.resolve(),
            plan["artifact"]["archive"],
            plan["artifact"]["checksums"],
        )
    else:
        raise RuntimeError("release plan has an unsupported strategy")
    args.output.write_text(
        json.dumps(digests, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"published {len(digests)} immutable component image(s)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        print(
            f"image publication command failed with exit code {error.returncode}",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except (OSError, RuntimeError) as error:
        print(f"image publication failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
