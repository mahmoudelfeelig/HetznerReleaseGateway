from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from release_config import APP_ID, load_config, manifest_path, validate_config


SHA = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW_PATH = re.compile(r"^\.github/workflows/[^@\r\n]+\.ya?ml(?:@[^@\r\n]+)?$")
ARTIFACT_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_ARTIFACT_BYTES = 5 * 1024 * 1024 * 1024
MAX_ARTIFACT_RESULTS = 100


@dataclass(frozen=True)
class AuthorityIssue:
    message: str


def normalized_workflow_path(value: Any, branch: str) -> str | None:
    if not isinstance(value, str) or not WORKFLOW_PATH.fullmatch(value):
        return None
    path, separator, ref = value.partition("@")
    if separator and ref != branch:
        return None
    return path


def github_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RuntimeError(f"GitHub Actions {label} timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeError(f"GitHub Actions {label} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise RuntimeError(f"GitHub Actions {label} timestamp is invalid")
    return parsed.astimezone(UTC)


class GitHubApi:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def get(self, path: str, query: dict[str, str] | None = None) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "elfeel-release-gateway",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"GitHub API {error.code} for {url}: {detail}") from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"GitHub API request failed for {url}: {error.reason}") from error


def verify_trigger(
    config: dict[str, Any],
    event: dict[str, Any],
    source_sha: str,
    run_id: int,
) -> list[AuthorityIssue]:
    issues: list[AuthorityIssue] = []
    source = config["source"]
    expected_repository = source["repository"]
    repository = event.get("repository")
    event_repository = repository.get("full_name") if isinstance(repository, dict) else None
    if not isinstance(event_repository, str) or (
        event_repository.casefold() != expected_repository.casefold()
    ):
        issues.append(AuthorityIssue("event repository does not match the release manifest"))
    event_default_branch = (
        repository.get("default_branch") if isinstance(repository, dict) else None
    )
    if event_default_branch != source["default_branch"]:
        issues.append(AuthorityIssue("event default branch does not match the release manifest"))
    if event.get("action") != "completed":
        issues.append(AuthorityIssue("workflow_run action must be completed"))

    workflow_run = event.get("workflow_run")
    if not isinstance(workflow_run, dict):
        return issues + [AuthorityIssue("event has no workflow_run object")]
    if workflow_run.get("id") != run_id:
        issues.append(AuthorityIssue("workflow run id does not match the caller input"))
    run_attempt = workflow_run.get("run_attempt")
    if (
        not isinstance(run_attempt, int)
        or isinstance(run_attempt, bool)
        or run_attempt <= 0
    ):
        issues.append(AuthorityIssue("workflow run attempt is invalid"))
    head_repository = workflow_run.get("head_repository")
    head_repository_name = (
        head_repository.get("full_name") if isinstance(head_repository, dict) else None
    )
    if not isinstance(head_repository_name, str) or (
        head_repository_name.casefold() != expected_repository.casefold()
    ):
        issues.append(AuthorityIssue("workflow run originated from an untrusted repository"))
    run_repository = workflow_run.get("repository")
    run_repository_name = (
        run_repository.get("full_name") if isinstance(run_repository, dict) else None
    )
    if run_repository_name is not None and (
        not isinstance(run_repository_name, str)
        or run_repository_name.casefold() != expected_repository.casefold()
    ):
        issues.append(AuthorityIssue("workflow run repository does not match the release manifest"))
    if workflow_run.get("head_sha") != source_sha:
        issues.append(AuthorityIssue("workflow run SHA does not match the caller input"))
    if workflow_run.get("head_branch") != source["default_branch"]:
        issues.append(AuthorityIssue("workflow run did not target the configured default branch"))
    if workflow_run.get("event") != "push":
        issues.append(AuthorityIssue("only push-triggered CI runs can authorize production"))
    if workflow_run.get("status") != "completed" or workflow_run.get("conclusion") != "success":
        issues.append(AuthorityIssue("triggering CI run did not complete successfully"))
    if workflow_run.get("name") not in source["required_workflows"]:
        issues.append(AuthorityIssue("triggering workflow is not required by the release manifest"))
    return issues


def select_required_runs(
    config: dict[str, Any],
    runs: list[dict[str, Any]],
    source_sha: str,
) -> tuple[dict[str, dict[str, Any]], list[AuthorityIssue]]:
    selected: dict[str, dict[str, Any]] = {}
    issues: list[AuthorityIssue] = []
    branch = config["source"]["default_branch"]
    for workflow_name in config["source"]["required_workflows"]:
        candidates = [
            run
            for run in runs
            if run.get("name") == workflow_name
            and run.get("head_sha") == source_sha
            and run.get("head_branch") == branch
            and run.get("event") == "push"
        ]
        if not candidates:
            issues.append(
                AuthorityIssue(f"required workflow {workflow_name!r} has no run for this SHA")
            )
            continue
        identities: set[tuple[int, str]] = set()
        invalid_identity = False
        for run in candidates:
            run_id = run.get("id")
            run_attempt = run.get("run_attempt")
            workflow_id = run.get("workflow_id")
            path = normalized_workflow_path(run.get("path"), branch)
            if (
                not isinstance(run_id, int)
                or isinstance(run_id, bool)
                or run_id <= 0
                or not isinstance(run_attempt, int)
                or isinstance(run_attempt, bool)
                or run_attempt <= 0
                or not isinstance(workflow_id, int)
                or isinstance(workflow_id, bool)
                or workflow_id <= 0
                or path is None
            ):
                invalid_identity = True
                break
            identities.add((workflow_id, path))
        if invalid_identity:
            issues.append(
                AuthorityIssue(f"required workflow {workflow_name!r} has invalid identity metadata")
            )
            continue
        if len(identities) != 1:
            issues.append(
                AuthorityIssue(f"required workflow {workflow_name!r} has ambiguous identity")
            )
            continue
        latest = max(
            candidates,
            key=lambda run: (int(run.get("id") or 0), int(run.get("run_attempt") or 0)),
        )
        if latest.get("status") != "completed" or latest.get("conclusion") != "success":
            issues.append(
                AuthorityIssue(
                    f"latest run of required workflow {workflow_name!r} is not successful"
                )
            )
            continue
        selected[workflow_name] = {
            **latest,
            "path": normalized_workflow_path(latest.get("path"), branch),
        }
    selected_identities = {
        (run["workflow_id"], run["path"]) for run in selected.values()
    }
    if len(selected_identities) != len(selected):
        issues.append(AuthorityIssue("required workflows do not have distinct identities"))
    return selected, issues


def verify_trigger_selection(
    event: dict[str, Any], selected_runs: dict[str, dict[str, Any]]
) -> list[AuthorityIssue]:
    workflow_run = event.get("workflow_run")
    if not isinstance(workflow_run, dict):
        return [AuthorityIssue("event has no workflow_run object")]
    workflow_name = workflow_run.get("name")
    selected = selected_runs.get(workflow_name) if isinstance(workflow_name, str) else None
    if (
        not isinstance(selected, dict)
        or selected.get("id") != workflow_run.get("id")
        or selected.get("run_attempt") != workflow_run.get("run_attempt")
    ):
        return [
            AuthorityIssue(
                "triggering workflow attempt is not the selected successful required run"
            )
        ]
    return []


def resolve_artifact(
    api: GitHubApi,
    repository: str,
    source_sha: str,
    selected_run: dict[str, Any],
    artifact_config: dict[str, Any],
) -> dict[str, Any]:
    run_id = selected_run["id"]
    run_attempt = selected_run["run_attempt"]
    expected_name = artifact_config["name"].replace("{sha}", source_sha).replace(
        "{attempt}", str(run_attempt)
    )
    attempt = api.get(
        f"repos/{repository}/actions/runs/{run_id}/attempts/{run_attempt}"
    )
    branch = selected_run.get("head_branch")
    selected_path = (
        normalized_workflow_path(selected_run.get("path"), branch)
        if isinstance(branch, str)
        else None
    )
    attempt_path = (
        normalized_workflow_path(attempt.get("path"), branch)
        if isinstance(attempt, dict) and isinstance(branch, str)
        else None
    )
    if (
        not isinstance(attempt, dict)
        or attempt.get("id") != run_id
        or attempt.get("run_attempt") != run_attempt
        or attempt.get("name") != selected_run.get("name")
        or attempt.get("workflow_id") != selected_run.get("workflow_id")
        or selected_path is None
        or attempt_path != selected_path
        or attempt.get("head_sha") != source_sha
        or attempt.get("head_branch") != branch
        or attempt.get("event") != "push"
        or attempt.get("status") != "completed"
        or attempt.get("conclusion") != "success"
    ):
        raise RuntimeError("selected workflow attempt is invalid")
    attempt_started = github_timestamp(attempt.get("run_started_at"), "attempt start")
    attempt_completed = github_timestamp(attempt.get("updated_at"), "attempt completion")
    if attempt_completed <= attempt_started:
        raise RuntimeError("selected workflow attempt timing is invalid")
    response = api.get(
        f"repos/{repository}/actions/runs/{run_id}/artifacts",
        {"name": expected_name, "per_page": str(MAX_ARTIFACT_RESULTS)},
    )
    if not isinstance(response, dict):
        raise RuntimeError("GitHub Actions artifact response is not an object")
    total_count = response.get("total_count")
    artifacts = response.get("artifacts")
    if (
        not isinstance(total_count, int)
        or isinstance(total_count, bool)
        or total_count < 0
        or total_count > MAX_ARTIFACT_RESULTS
        or not isinstance(artifacts, list)
        or len(artifacts) != total_count
    ):
        raise RuntimeError("GitHub Actions artifact response is incomplete or unbounded")

    current: list[dict[str, Any]] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get("name") != expected_name:
            raise RuntimeError("GitHub Actions returned an artifact with an unexpected name")
        expired = artifact.get("expired")
        if not isinstance(expired, bool):
            raise RuntimeError("GitHub Actions artifact has invalid expiration metadata")
        if not expired:
            current.append(artifact)
    if len(current) != 1:
        raise RuntimeError(
            "expected exactly one nonexpired artifact named "
            f"{expected_name!r}, found {len(current)}"
        )

    artifact = current[0]
    artifact_id = artifact.get("id")
    size = artifact.get("size_in_bytes")
    digest = artifact.get("digest")
    workflow_run = artifact.get("workflow_run")
    artifact_created = github_timestamp(artifact.get("created_at"), "artifact creation")
    if (
        not isinstance(artifact_id, int)
        or isinstance(artifact_id, bool)
        or artifact_id <= 0
    ):
        raise RuntimeError("GitHub Actions artifact has an invalid immutable ID")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or not 1 <= size <= MAX_ARTIFACT_BYTES
    ):
        raise RuntimeError("GitHub Actions artifact has an invalid or excessive size")
    if not isinstance(digest, str) or not ARTIFACT_DIGEST.fullmatch(digest):
        raise RuntimeError("GitHub Actions artifact has an invalid digest")
    if (
        not isinstance(workflow_run, dict)
        or workflow_run.get("id") != run_id
        or workflow_run.get("head_sha") != source_sha
    ):
        raise RuntimeError("GitHub Actions artifact does not match the selected workflow run")
    if not attempt_started < artifact_created <= attempt_completed:
        raise RuntimeError(
            "GitHub Actions artifact was not created during the selected workflow attempt"
        )
    return {
        "run_id": run_id,
        "run_attempt": run_attempt,
        "id": artifact_id,
        "name": expected_name,
        "digest": digest,
        "size": size,
    }


def build_plan(
    config: dict[str, Any],
    source_sha: str,
    selected_runs: dict[str, dict[str, Any]],
    resolved_artifact: dict[str, Any] | None = None,
) -> dict[str, Any]:
    registry = config["registry"]
    release = config["release"]
    strategy = release["strategy"]
    if not selected_runs:
        raise ValueError("release plan requires successful CI evidence")
    completed = [
        github_timestamp(run.get("updated_at"), f"{name} completion")
        for name, run in selected_runs.items()
    ]
    published_at = max(completed).isoformat().replace("+00:00", "Z")
    components: list[dict[str, Any]] = []
    for component in release["components"]:
        item: dict[str, Any] = {
            "name": component["name"],
            "destination": (
                f"{registry['host']}/{registry['image_namespace']}/"
                f"{component['name']}:{source_sha}"
            ),
        }
        if strategy == "source-build":
            item.update(
                {
                    "context": component["context"],
                    "dockerfile": component["dockerfile"],
                    "target": component.get("target"),
                    "build_args": {
                        key: value.replace("{sha}", source_sha).replace(
                            "{repository}", config["source"]["repository"]
                        )
                        for key, value in component.get("build_args", {}).items()
                    },
                }
            )
        else:
            item["artifact_image"] = component["artifact_image"].replace("{sha}", source_sha)
        components.append(item)

    artifact = None
    if strategy == "artifact-images":
        if resolved_artifact is None:
            raise ValueError("artifact-images requires resolved artifact provenance")
        artifact_config = release["artifact"]
        artifact = {
            **resolved_artifact,
            "archive": artifact_config["archive"],
            "checksums": artifact_config["checksums"],
        }

    return {
        "version": 1,
        "app": config["id"],
        "repository": config["source"]["repository"],
        "sha": source_sha,
        "published_at": published_at,
        "strategy": strategy,
        "registry": registry,
        "components": components,
        "artifact": artifact,
        "required_runs": {
            name: {
                "id": run["id"],
                "run_attempt": run["run_attempt"],
                "workflow_id": run["workflow_id"],
                "path": run["path"],
            }
            for name, run in selected_runs.items()
        },
    }


def _write_github_output(path: Path, plan: dict[str, Any]) -> None:
    artifact = plan.get("artifact") or {}
    values = {
        "app": plan["app"],
        "repository": plan["repository"],
        "sha": plan["sha"],
        "strategy": plan["strategy"],
        "registry_host": plan["registry"]["host"],
        "release_repository": plan["registry"]["release_repository"],
        "artifact_run_id": str(artifact.get("run_id", "")),
        "artifact_run_attempt": str(artifact.get("run_attempt", "")),
        "artifact_id": str(artifact.get("id", "")),
        "artifact_name": str(artifact.get("name", "")),
        "artifact_digest": str(artifact.get("digest", "")),
        "artifact_size": str(artifact.get("size", "")),
    }
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Authorize an exact application release")
    parser.add_argument("--app", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument(
        "--api-url",
        default=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )
    parser.add_argument("--github-output", type=Path, default=os.environ.get("GITHUB_OUTPUT"))
    parser.add_argument("--plan-output", type=Path, required=True)
    parser.add_argument("--wait-required-seconds", type=int, default=0)
    args = parser.parse_args()

    if not APP_ID.fullmatch(args.app):
        parser.error("--app has an invalid application identifier")
    if not SHA.fullmatch(args.source_sha):
        parser.error("--source-sha must be a lowercase 40-character commit SHA")
    if not args.github_token:
        parser.error("a GitHub token is required")
    if not 0 <= args.wait_required_seconds <= 1800:
        parser.error("--wait-required-seconds must be between 0 and 1800")

    try:
        config_path = manifest_path(args.source_root)
        config = load_config(config_path)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1
    config_issues = validate_config(config)
    if config_issues:
        for issue in config_issues:
            print(f"release manifest: {issue}", file=sys.stderr)
        return 1
    if config["id"] != args.app:
        print("application identifier does not match the release manifest", file=sys.stderr)
        return 1

    try:
        with args.event.open(encoding="utf-8") as handle:
            event = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"cannot read the GitHub event: {error}", file=sys.stderr)
        return 1
    if not isinstance(event, dict):
        print("GitHub event must contain an object", file=sys.stderr)
        return 1
    authority_issues = verify_trigger(config, event, args.source_sha, args.run_id)

    api = GitHubApi(args.api_url, args.github_token)
    repository = config["source"]["repository"]
    branch = config["source"]["default_branch"]
    deadline = time.monotonic() + args.wait_required_seconds
    resolved_artifact: dict[str, Any] | None = None
    artifact_error: RuntimeError | None = None
    try:
        while True:
            runs_response = api.get(
                f"repos/{repository}/actions/runs",
                {
                    "head_sha": args.source_sha,
                    "branch": branch,
                    "event": "push",
                    "per_page": "100",
                },
            )
            if not isinstance(runs_response, dict):
                raise RuntimeError("GitHub Actions response is not an object")
            workflow_runs = runs_response.get("workflow_runs")
            if not isinstance(workflow_runs, list):
                raise RuntimeError("GitHub Actions response has no workflow run list")
            selected_runs, run_issues = select_required_runs(
                config, workflow_runs, args.source_sha
            )
            trigger_selection_issues = verify_trigger_selection(event, selected_runs)
            resolved_artifact = None
            artifact_error = None
            if not run_issues and config["release"]["strategy"] == "artifact-images":
                workflow_name = config["source"]["required_workflows"][0]
                try:
                    resolved_artifact = resolve_artifact(
                        api,
                        repository,
                        args.source_sha,
                        selected_runs[workflow_name],
                        config["release"]["artifact"],
                    )
                except RuntimeError as error:
                    artifact_error = error
            if (
                not run_issues
                and not trigger_selection_issues
                and artifact_error is None
                or time.monotonic() >= deadline
            ):
                break
            print("waiting for required CI workflows and release artifact", flush=True)
            time.sleep(min(15, max(1, int(deadline - time.monotonic()))))
        authority_issues.extend(run_issues)
        authority_issues.extend(trigger_selection_issues)
        if artifact_error is not None:
            raise artifact_error
        encoded_branch = urllib.parse.quote(branch, safe="")
        ref = api.get(f"repos/{repository}/git/ref/heads/{encoded_branch}")
    except RuntimeError as error:
        print(f"release authorization failed: {error}", file=sys.stderr)
        return 1
    ref_object = ref.get("object") if isinstance(ref, dict) else None
    if not isinstance(ref_object, dict) or ref_object.get("sha") != args.source_sha:
        authority_issues.append(AuthorityIssue("the default branch advanced after the CI run"))
    if authority_issues:
        for issue in authority_issues:
            print(f"release authorization failed: {issue.message}", file=sys.stderr)
        return 1

    plan = build_plan(config, args.source_sha, selected_runs, resolved_artifact)
    args.plan_output.write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if args.github_output:
        _write_github_output(args.github_output, plan)
    print(
        f"authorized {plan['app']} at {plan['sha']} with "
        f"{len(plan['required_runs'])} required CI run(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
