from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


APP_ID = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
BUILD_ARG = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
BUILD_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
COMPONENT = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
ARTIFACT_NAME_REMAINDER = re.compile(r"^[A-Za-z0-9_.-]*$")
LOCAL_IMAGE = re.compile(
    r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*:"
    r"[A-Za-z0-9_.-]*\{sha\}[A-Za-z0-9_.-]*$"
)
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MANIFEST_RELATIVE_PATH = Path(".github/hetzner-release.json")
MAX_CONFIG_BYTES = 64 * 1024
REGISTRY_HOST = "registry.elfeel.me"


@dataclass(frozen=True)
class ConfigIssue:
    location: str
    message: str

    def __str__(self) -> str:
        return f"{self.location}: {self.message}"


def _object(value: Any, location: str, issues: list[ConfigIssue]) -> dict[str, Any]:
    if not isinstance(value, dict):
        issues.append(ConfigIssue(location, "must be an object"))
        return {}
    return value


def _exact_keys(
    value: dict[str, Any],
    required: set[str],
    optional: set[str],
    location: str,
    issues: list[ConfigIssue],
) -> None:
    for key in sorted(required - set(value)):
        issues.append(ConfigIssue(f"{location}.{key}", "is required"))
    for key in sorted(set(value) - required - optional):
        issues.append(ConfigIssue(f"{location}.{key}", "is not allowed"))


def _safe_path(
    value: Any,
    location: str,
    issues: list[ConfigIssue],
    *,
    dot: bool = False,
) -> None:
    if not isinstance(value, str) or not value or len(value) > 256:
        issues.append(ConfigIssue(location, "must be a non-empty path of at most 256 characters"))
        return
    if value == "." and dot:
        return
    path = PurePosixPath(value)
    if (
        value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or str(path) != value
    ):
        issues.append(ConfigIssue(location, "must be a normalized repository-relative POSIX path"))


def manifest_path(source_root: Path) -> Path:
    root = source_root.resolve()
    candidate = root / MANIFEST_RELATIVE_PATH
    try:
        candidate.parent.resolve().relative_to(root)
    except ValueError as error:
        raise ValueError("release manifest escaped the source checkout") from error
    return candidate


def load_config(path: Path) -> dict[str, Any]:
    try:
        details = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect release manifest {path}: {error}") from error
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"release manifest must be a regular file: {path}")
    if details.st_size > MAX_CONFIG_BYTES:
        raise ValueError(f"release manifest is too large: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read release manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"release manifest must contain an object: {path}")
    return value


def validate_config(config: Any) -> list[ConfigIssue]:
    issues: list[ConfigIssue] = []
    root = _object(config, "manifest", issues)
    _exact_keys(root, {"version", "id", "source", "registry", "release"}, set(), "manifest", issues)

    if root.get("version") != 1:
        issues.append(ConfigIssue("version", "must equal 1"))
    app = root.get("id")
    if not isinstance(app, str) or not APP_ID.fullmatch(app):
        issues.append(ConfigIssue("id", "must be a lowercase application identifier"))
        app = ""

    source = _object(root.get("source"), "source", issues)
    _exact_keys(
        source,
        {"repository", "default_branch", "required_workflows"},
        set(),
        "source",
        issues,
    )
    repository = source.get("repository")
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
        issues.append(ConfigIssue("source.repository", "must be an owner/repository name"))
    branch = source.get("default_branch")
    if (
        not isinstance(branch, str)
        or not BRANCH.fullmatch(branch)
        or ".." in branch
        or branch.endswith("/")
        or branch.endswith(".lock")
        or "@{" in branch
    ):
        issues.append(ConfigIssue("source.default_branch", "must be a safe Git branch name"))
    workflows = source.get("required_workflows")
    workflow_values = [name for name in workflows if isinstance(name, str)] if isinstance(
        workflows, list
    ) else []
    if (
        not isinstance(workflows, list)
        or not 1 <= len(workflows) <= 8
        or len(workflow_values) != len(workflows)
        or len(workflow_values) != len(set(workflow_values))
        or any(
            not isinstance(name, str)
            or not name.strip()
            or name != name.strip()
            or len(name) > 128
            or any(character in name for character in "\r\n")
            for name in workflows
        )
    ):
        issues.append(
            ConfigIssue(
                "source.required_workflows",
                "must contain 1 to 8 unique workflow names",
            )
        )

    registry = _object(root.get("registry"), "registry", issues)
    _exact_keys(
        registry,
        {"host", "image_namespace", "release_repository"},
        set(),
        "registry",
        issues,
    )
    if registry.get("host") != REGISTRY_HOST:
        issues.append(ConfigIssue("registry.host", f"must equal {REGISTRY_HOST!r}"))
    if registry.get("image_namespace") != f"apps/{app}":
        issues.append(
            ConfigIssue(
                "registry.image_namespace", "must be derived from the application id"
            )
        )
    if registry.get("release_repository") != f"releases/{app}":
        issues.append(
            ConfigIssue(
                "registry.release_repository", "must be derived from the application id"
            )
        )

    release = _object(root.get("release"), "release", issues)
    strategy = release.get("strategy")
    if strategy == "source-build":
        _exact_keys(release, {"strategy", "components"}, set(), "release", issues)
    elif strategy == "artifact-images":
        _exact_keys(
            release,
            {"strategy", "artifact", "components"},
            set(),
            "release",
            issues,
        )
    else:
        issues.append(ConfigIssue("release.strategy", "must be source-build or artifact-images"))

    components = release.get("components")
    if not isinstance(components, list) or not 1 <= len(components) <= 8:
        issues.append(ConfigIssue("release.components", "must contain 1 to 8 components"))
        components = []
    names: list[str] = []
    for index, raw_component in enumerate(components):
        location = f"release.components[{index}]"
        component = _object(raw_component, location, issues)
        name = component.get("name")
        if not isinstance(name, str) or not COMPONENT.fullmatch(name):
            issues.append(
                ConfigIssue(
                    f"{location}.name", "must be a lowercase component identifier"
                )
            )
        else:
            names.append(name)
        if strategy == "source-build":
            _exact_keys(
                component,
                {"name", "context", "dockerfile"},
                {"dockerfile_origin", "target", "build_args"},
                location,
                issues,
            )
            _safe_path(component.get("context"), f"{location}.context", issues, dot=True)
            _safe_path(component.get("dockerfile"), f"{location}.dockerfile", issues)
            if component.get("dockerfile_origin", "source") != "source":
                issues.append(ConfigIssue(f"{location}.dockerfile_origin", "must equal source"))
            target = component.get("target")
            if target is not None and (
                not isinstance(target, str) or not BUILD_TARGET.fullmatch(target)
            ):
                issues.append(ConfigIssue(f"{location}.target", "must be a safe build target"))
            build_args = component.get("build_args", {})
            if not isinstance(build_args, dict) or len(build_args) > 16:
                issues.append(
                    ConfigIssue(
                        f"{location}.build_args",
                        "must be an object with at most 16 entries",
                    )
                )
            else:
                for key, value in build_args.items():
                    if not isinstance(key, str) or not BUILD_ARG.fullmatch(key):
                        issues.append(
                            ConfigIssue(
                                f"{location}.build_args",
                                "contains an invalid build argument name",
                            )
                        )
                    if (
                        not isinstance(value, str)
                        or len(value) > 512
                        or any(c in value for c in "\r\n")
                    ):
                        issues.append(
                            ConfigIssue(
                                f"{location}.build_args.{key}",
                                "must be a short single-line string",
                            )
                        )
        elif strategy == "artifact-images":
            _exact_keys(component, {"name", "artifact_image"}, set(), location, issues)
            image = component.get("artifact_image")
            if not isinstance(image, str) or not LOCAL_IMAGE.fullmatch(image):
                issues.append(
                    ConfigIssue(
                        f"{location}.artifact_image",
                        "must be one SHA-bound local image name",
                    )
                )
    if len(names) != len(set(names)):
        issues.append(ConfigIssue("release.components", "component names must be unique"))

    if strategy == "artifact-images":
        artifact = _object(release.get("artifact"), "release.artifact", issues)
        _exact_keys(
            artifact,
            {"name", "archive", "checksums"},
            set(),
            "release.artifact",
            issues,
        )
        name = artifact.get("name")
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 256
            or name.count("{sha}") != 1
            or name.count("{attempt}") != 1
            or not ARTIFACT_NAME_REMAINDER.fullmatch(
                name.replace("{sha}", "").replace("{attempt}", "")
            )
        ):
            issues.append(
                ConfigIssue(
                    "release.artifact.name",
                    "must contain exactly one {sha} and one {attempt}",
                )
            )
        for key in ("archive", "checksums"):
            _safe_path(artifact.get(key), f"release.artifact.{key}", issues)

    return issues
