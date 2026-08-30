from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from wait_for_receipt import validate_receipt  # noqa: E402

from helpers import SOURCE_SHA  # noqa: E402


APP = "example-app"
REFERENCE = "registry.elfeel.me/releases/example-app@sha256:" + "d" * 64


def receipt() -> dict[str, object]:
    return {
        "version": 2,
        "app": APP,
        "source_sha": SOURCE_SHA,
        "release_reference": REFERENCE,
        "status": "succeeded",
        "completed_at": "2026-08-30T00:00:00Z",
        "rollback_scope": "not_applicable",
        "persistent_state_restored": False,
    }


class ReceiptTests(unittest.TestCase):
    def test_minimal_terminal_receipt_is_valid(self) -> None:
        self.assertIsNone(validate_receipt(receipt(), APP, SOURCE_SHA, REFERENCE))

    def test_operational_evidence_is_rejected(self) -> None:
        value = receipt()
        value["gates"] = [{"name": "internal", "passed": True}]
        self.assertEqual(
            validate_receipt(value, APP, SOURCE_SHA, REFERENCE),
            "receipt fields do not match the minimal schema",
        )

    def test_release_reference_must_match_exactly(self) -> None:
        value = receipt()
        value["release_reference"] = (
            "registry.elfeel.me/releases/example-app@sha256:" + "e" * 64
        )
        self.assertEqual(
            validate_receipt(value, APP, SOURCE_SHA, REFERENCE),
            "receipt is for a different release marker",
        )

    def test_only_terminal_statuses_are_accepted(self) -> None:
        value = receipt()
        value["status"] = "deploying"
        self.assertEqual(
            validate_receipt(value, APP, SOURCE_SHA, REFERENCE),
            "receipt has an invalid terminal status",
        )

    def test_timestamp_requires_timezone(self) -> None:
        value = receipt()
        value["completed_at"] = "2026-08-30T00:00:00"
        self.assertEqual(
            validate_receipt(value, APP, SOURCE_SHA, REFERENCE),
            "receipt has an invalid completion timestamp",
        )

    def test_runtime_only_rollback_is_explicit(self) -> None:
        value = receipt()
        value.update(
            {
                "status": "rolled_back",
                "rollback_scope": "runtime_only",
                "persistent_state_restored": False,
            }
        )
        self.assertIsNone(validate_receipt(value, APP, SOURCE_SHA, REFERENCE))

    def test_full_state_rollback_requires_state_restoration(self) -> None:
        value = receipt()
        value.update(
            {
                "status": "rolled_back",
                "rollback_scope": "runtime_and_state",
                "persistent_state_restored": False,
            }
        )
        self.assertEqual(
            validate_receipt(value, APP, SOURCE_SHA, REFERENCE),
            "receipt rollback semantics do not match terminal status",
        )

    def test_non_rollback_status_rejects_rollback_claim(self) -> None:
        value = receipt()
        value["rollback_scope"] = "runtime_only"
        self.assertEqual(
            validate_receipt(value, APP, SOURCE_SHA, REFERENCE),
            "receipt rollback semantics do not match terminal status",
        )


if __name__ == "__main__":
    unittest.main()
