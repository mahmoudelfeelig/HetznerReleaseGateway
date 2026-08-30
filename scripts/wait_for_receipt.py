from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any


APP_ID = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
RELEASE_REFERENCE = re.compile(
    r"^registry\.elfeel\.me/releases/([a-z][a-z0-9-]{1,31})@sha256:[0-9a-f]{64}$"
)
TERMINAL = {"succeeded", "failed", "rolled_back"}
RECEIPT_FIELDS = {
    "version",
    "app",
    "source_sha",
    "release_reference",
    "status",
    "completed_at",
    "rollback_scope",
    "persistent_state_restored",
}
ROLLBACK_SCOPES = {"not_applicable", "runtime_only", "runtime_and_state"}
MAX_RECEIPT_BYTES = 64 * 1024


def validate_receipt(
    receipt: Any, app: str, source_sha: str, release_reference: str
) -> str | None:
    if not isinstance(receipt, dict):
        return "receipt must be a JSON object"
    if set(receipt) != RECEIPT_FIELDS:
        return "receipt fields do not match the minimal schema"
    if receipt.get("version") != 2:
        return "receipt version is unsupported"
    if receipt.get("app") != app:
        return "receipt application does not match"
    if receipt.get("source_sha") != source_sha:
        return "receipt is for a different source SHA"
    if receipt.get("release_reference") != release_reference:
        return "receipt is for a different release marker"
    if receipt.get("status") not in TERMINAL:
        return "receipt has an invalid terminal status"
    rollback_scope = receipt.get("rollback_scope")
    state_restored = receipt.get("persistent_state_restored")
    if rollback_scope not in ROLLBACK_SCOPES or type(state_restored) is not bool:
        return "receipt has invalid rollback semantics"
    status = receipt["status"]
    if status in {"succeeded", "failed"} and (
        rollback_scope != "not_applicable" or state_restored
    ):
        return "receipt rollback semantics do not match terminal status"
    if status == "rolled_back" and (
        (rollback_scope == "runtime_only" and state_restored)
        or (rollback_scope == "runtime_and_state" and not state_restored)
        or rollback_scope == "not_applicable"
    ):
        return "receipt rollback semantics do not match terminal status"
    completed_at = receipt.get("completed_at")
    if not isinstance(completed_at, str) or not completed_at.endswith("Z"):
        return "receipt has an invalid completion timestamp"
    try:
        parsed = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
    except ValueError:
        return "receipt has an invalid completion timestamp"
    if parsed.tzinfo is None:
        return "receipt has an invalid completion timestamp"
    return None


def verify_signature(public_key: Path, payload: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory(prefix="deployment-receipt-") as directory:
        root = Path(directory)
        payload_path = root / "receipt.json"
        signature_path = root / "receipt.sig"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        try:
            completed = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_key),
                    "-rawin",
                    "-in",
                    str(payload_path),
                    "-sigfile",
                    str(signature_path),
                ],
                text=True,
                capture_output=True,
            )
        except OSError:
            return False
    return completed.returncode == 0


def fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"Cache-Control": "no-cache", "User-Agent": "elfeel-release-gateway"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = response.read(MAX_RECEIPT_BYTES + 1)
    if len(payload) > MAX_RECEIPT_BYTES:
        raise ValueError("receipt response is too large")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Wait for a signed minimal deployment receipt")
    parser.add_argument("--app", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--release-reference", required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--base-url", default="https://deployment.elfeel.me/status")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--interval-seconds", type=int, default=10)
    args = parser.parse_args()

    if not APP_ID.fullmatch(args.app) or not SHA.fullmatch(args.source_sha):
        parser.error("invalid application identifier or source SHA")
    reference_match = RELEASE_REFERENCE.fullmatch(args.release_reference)
    if reference_match is None or reference_match.group(1) != args.app:
        parser.error("release reference is invalid")
    if not args.public_key.is_file() or args.public_key.is_symlink():
        parser.error("deployment receipt public key must be a regular file")
    if not 30 <= args.timeout_seconds <= 1800:
        parser.error("timeout must be between 30 and 1800 seconds")
    if not 1 <= args.interval_seconds <= 60:
        parser.error("interval must be between 1 and 60 seconds")

    base = f"{args.base_url.rstrip('/')}/{args.app}"
    deadline = time.monotonic() + args.timeout_seconds
    last_observation = "no receipt published yet"
    while time.monotonic() < deadline:
        nonce = int(time.time())
        try:
            payload = fetch(f"{base}.json?cache={nonce}")
            signature = fetch(f"{base}.sig?cache={nonce}")
        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            last_observation = f"receipt endpoint unavailable: {error}"
            time.sleep(args.interval_seconds)
            continue
        if not verify_signature(args.public_key, payload, signature):
            last_observation = "receipt signature is invalid or changed during retrieval"
            time.sleep(args.interval_seconds)
            continue
        try:
            receipt = json.loads(payload)
        except json.JSONDecodeError:
            last_observation = "signed receipt is not valid JSON"
            time.sleep(args.interval_seconds)
            continue
        if isinstance(receipt, dict) and receipt.get("source_sha") != args.source_sha:
            last_observation = "host still reports a different source release"
            time.sleep(args.interval_seconds)
            continue
        if isinstance(receipt, dict) and (
            receipt.get("release_reference") != args.release_reference
        ):
            last_observation = "host still reports a different release marker"
            time.sleep(args.interval_seconds)
            continue
        issue = validate_receipt(
            receipt, args.app, args.source_sha, args.release_reference
        )
        if issue:
            print(f"invalid signed deployment receipt: {issue}", file=sys.stderr)
            return 1
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        if receipt["status"] == "succeeded":
            return 0
        print(f"deployment ended with status {receipt['status']}", file=sys.stderr)
        return 1

    print(f"timed out waiting for deployment: {last_observation}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
