from __future__ import annotations

from typing import Any


SOURCE_SHA = "a" * 40
GATEWAY_SHA = "b" * 40
ARTIFACT_DIGEST = "sha256:" + "c" * 64


def source_manifest() -> dict[str, Any]:
    return {
        "version": 1,
        "id": "example-app",
        "source": {
            "repository": "owner/example-app",
            "default_branch": "main",
            "required_workflows": ["CI"],
        },
        "registry": {
            "host": "registry.elfeel.me",
            "image_namespace": "apps/example-app",
            "release_repository": "releases/example-app",
        },
        "release": {
            "strategy": "source-build",
            "components": [
                {
                    "name": "web",
                    "context": ".",
                    "dockerfile": "Dockerfile",
                    "build_args": {"SOURCE_REVISION": "{sha}"},
                }
            ],
        },
    }


def artifact_manifest() -> dict[str, Any]:
    value = source_manifest()
    value["release"] = {
        "strategy": "artifact-images",
        "artifact": {
            "name": "release-{sha}-attempt-{attempt}",
            "archive": "images.tar.gz",
            "checksums": "SHA256SUMS",
        },
        "components": [{"name": "web", "artifact_image": "example-web:{sha}"}],
    }
    return value


def resolved_artifact(*, run_attempt: int = 1) -> dict[str, Any]:
    return {
        "run_id": 101,
        "run_attempt": run_attempt,
        "id": 501,
        "name": f"release-{SOURCE_SHA}-attempt-{run_attempt}",
        "digest": ARTIFACT_DIGEST,
        "size": 4096,
    }


def workflow_run(
    *,
    name: str = "CI",
    run_id: int = 101,
    workflow_id: int = 11,
    path: str = ".github/workflows/ci.yml@main",
    run_attempt: int = 1,
    status: str = "completed",
    conclusion: str = "success",
    updated_at: str = "2026-08-30T00:10:00Z",
) -> dict[str, Any]:
    return {
        "name": name,
        "id": run_id,
        "run_attempt": run_attempt,
        "workflow_id": workflow_id,
        "path": path,
        "head_sha": SOURCE_SHA,
        "head_branch": "main",
        "event": "push",
        "status": status,
        "conclusion": conclusion,
        "updated_at": updated_at,
    }


def workflow_attempt(
    *,
    run_attempt: int = 1,
    started_at: str = "2026-08-30T00:00:00Z",
    completed_at: str = "2026-08-30T00:10:00Z",
) -> dict[str, Any]:
    value = workflow_run(run_attempt=run_attempt)
    value["run_started_at"] = started_at
    value["updated_at"] = completed_at
    return value


def workflow_event() -> dict[str, Any]:
    run = workflow_run()
    run["head_repository"] = {"full_name": "owner/example-app"}
    run["repository"] = {"full_name": "owner/example-app"}
    return {
        "action": "completed",
        "repository": {"full_name": "owner/example-app", "default_branch": "main"},
        "workflow_run": run,
    }
