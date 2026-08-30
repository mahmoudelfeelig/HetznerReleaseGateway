from __future__ import annotations

import argparse
import ipaddress
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


MAX_FILE_BYTES = 1024 * 1024
EXCLUDED_DIRECTORIES = {
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
FORBIDDEN_DIRECTORIES = {"apps", "builders", "host", "release-apps"}
ALLOWED_HOSTS = {"registry.elfeel.me", "deployment.elfeel.me"}
ALLOWED_REPOSITORIES = {
    ("actions", "checkout"),
    ("mahmoudelfeelig", "hetznerreleasegateway"),
}
SYNTHETIC_OWNERS = {"owner", "attacker", "octocat"}

PRIVATE_KEY = re.compile(r"-{5}BEGIN(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-{5}")
GITHUB_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b")
AWS_TOKEN = re.compile(r"\bA[K]IA[A-Z0-9]{16}\b")
BEARER_TOKEN = re.compile(r"\bB[e]arer\s+[A-Za-z0-9._~+/=-]{20,}\b")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*"
    r"[\"']?([A-Za-z0-9._~+/=-]{16,})"
)
IPV4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
ELFEEL_HOST = re.compile(
    r"(?i)(?<![A-Za-z0-9.-])(?:[A-Za-z0-9-]+\.)*elfeel\.me(?![A-Za-z0-9.-])"
)
GITHUB_URL_REPOSITORY = re.compile(
    r"(?i)https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"
)
REPOSITORY_ASSIGNMENT = re.compile(
    r"(?i)\brepository[\"']?\s*[:=]\s*[\"']"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)[\"']"
)
WORKFLOW_USE = re.compile(
    r"(?im)^\s*uses:\s*([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:/[^@\s]+)?@"
)


@dataclass(frozen=True, order=True)
class SurfaceIssue:
    path: str
    rule: str
    line: int | None = None

    def __str__(self) -> str:
        location = f"{self.path}:{self.line}" if self.line is not None else self.path
        return f"{location}: {self.rule}"


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _repository_is_allowed(owner: str, repository: str) -> bool:
    identity = (owner.casefold(), repository.casefold())
    return identity in ALLOWED_REPOSITORIES or identity[0] in SYNTHETIC_OWNERS


def _scan_text(relative: str, text: str) -> list[SurfaceIssue]:
    issues: list[SurfaceIssue] = []
    indicators = (
        (PRIVATE_KEY, "private key material"),
        (GITHUB_TOKEN, "GitHub token"),
        (AWS_TOKEN, "cloud access token"),
        (BEARER_TOKEN, "bearer token"),
        (SECRET_ASSIGNMENT, "assigned secret or token"),
    )
    for pattern, rule in indicators:
        for match in pattern.finditer(text):
            issues.append(SurfaceIssue(relative, rule, _line_number(text, match.start())))

    host_path = "/" + "op" + "t/"
    for offset in (match.start() for match in re.finditer(re.escape(host_path), text)):
        issues.append(SurfaceIssue(relative, "host installation path", _line_number(text, offset)))

    for match in IPV4.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if address.version == 4 and address.is_global:
            issues.append(
                SurfaceIssue(
                    relative,
                    "literal public IPv4 topology",
                    _line_number(text, match.start()),
                )
            )

    for match in ELFEEL_HOST.finditer(text):
        if match.group(0).casefold() not in ALLOWED_HOSTS:
            issues.append(
                SurfaceIssue(
                    relative,
                    "unapproved public hostname",
                    _line_number(text, match.start()),
                )
            )

    for pattern in (GITHUB_URL_REPOSITORY, REPOSITORY_ASSIGNMENT, WORKFLOW_USE):
        for match in pattern.finditer(text):
            if not _repository_is_allowed(match.group(1), match.group(2)):
                issues.append(
                    SurfaceIssue(
                        relative,
                        "concrete non-gateway repository reference",
                        _line_number(text, match.start()),
                    )
                )
    return issues


def _scan_file(path: Path, relative: str) -> list[SurfaceIssue]:
    try:
        details = path.stat(follow_symlinks=False)
    except OSError:
        return [SurfaceIssue(relative, "publishable file is unreadable")]
    if not stat.S_ISREG(details.st_mode):
        return [SurfaceIssue(relative, "publishable path is not a regular file")]
    if not 0 <= details.st_size <= MAX_FILE_BYTES:
        return [SurfaceIssue(relative, "publishable file is unexpectedly large")]
    try:
        payload = path.read_bytes()
    except OSError:
        return [SurfaceIssue(relative, "publishable file is unreadable")]
    if len(payload) > MAX_FILE_BYTES:
        return [SurfaceIssue(relative, "publishable file is unexpectedly large")]
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return [SurfaceIssue(relative, "publishable file is not readable UTF-8 text")]
    issues = _scan_text(relative, text)
    if path.suffix.casefold() == ".json":
        issues.append(SurfaceIssue(relative, "central JSON inventory is not allowed"))
    return issues


def scan_repository(root: Path) -> list[SurfaceIssue]:
    root = root.resolve()
    issues: list[SurfaceIssue] = []

    def visit(directory: Path, relative_directory: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name.casefold())
        except OSError:
            relative = relative_directory.as_posix() or "."
            issues.append(SurfaceIssue(relative, "publishable directory is unreadable"))
            return
        for entry in entries:
            if entry.name in EXCLUDED_DIRECTORIES:
                continue
            relative_path = relative_directory / entry.name
            relative = relative_path.as_posix()
            try:
                details = entry.stat(follow_symlinks=False)
            except OSError:
                issues.append(SurfaceIssue(relative, "publishable path is unreadable"))
                continue
            if stat.S_ISLNK(details.st_mode):
                issues.append(SurfaceIssue(relative, "publishable symlink is not allowed"))
            elif stat.S_ISDIR(details.st_mode):
                if entry.name in FORBIDDEN_DIRECTORIES:
                    issues.append(SurfaceIssue(relative, "forbidden central platform directory"))
                visit(Path(entry.path), relative_path)
            elif stat.S_ISREG(details.st_mode):
                issues.extend(_scan_file(Path(entry.path), relative))
            else:
                issues.append(SurfaceIssue(relative, "publishable special file is not allowed"))

    visit(root, Path())
    return sorted(set(issues))


def main() -> int:
    parser = argparse.ArgumentParser(description="Check every publishable repository file")
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    issues = scan_repository(args.root)
    if issues:
        for issue in issues:
            print(issue, file=sys.stderr)
        return 1
    print("public repository surface is clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
