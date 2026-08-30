from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from make_release_marker import compact_label, make_release  # noqa: E402
from release_plan import build_plan  # noqa: E402

from helpers import (  # noqa: E402
    GATEWAY_SHA,
    SOURCE_SHA,
    artifact_manifest,
    resolved_artifact,
    source_manifest,
    workflow_run,
)


class ReleaseMarkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = build_plan(
            source_manifest(), SOURCE_SHA, {"CI": workflow_run()}
        )
        self.reference = (
            "registry.elfeel.me/apps/example-app/web@sha256:" + "c" * 64
        )
        self.gateway = {
            "repository": "mahmoudelfeelig/HetznerReleaseGateway",
            "workflow_path": ".github/workflows/release.yml",
            "sha": GATEWAY_SHA,
        }

    def test_marker_v2_has_only_public_release_evidence(self) -> None:
        release = make_release(
            self.plan,
            {"web": self.reference},
            self.gateway,
            "2026-08-30T00:00:00Z",
        )
        self.assertEqual(
            set(release),
            {
                "version",
                "app",
                "repository",
                "source_sha",
                "gateway",
                "published_at",
                "required_runs",
                "artifact",
                "images",
            },
        )
        self.assertEqual(release["version"], 2)
        self.assertEqual(release["gateway"], self.gateway)
        self.assertIsNone(release["artifact"])
        self.assertEqual(release["images"], {"web": self.reference})
        self.assertIsInstance(release["images"]["web"], str)
        serialized = json.dumps(release)
        self.assertNotIn('"service"', serialized)
        self.assertNotIn("additional_services", serialized)

    def test_artifact_marker_carries_exact_provenance(self) -> None:
        run = workflow_run(run_attempt=3)
        plan = build_plan(
            artifact_manifest(),
            SOURCE_SHA,
            {"CI": run},
            resolved_artifact(run_attempt=3),
        )
        release = make_release(
            plan,
            {"web": self.reference},
            self.gateway,
            "2026-08-30T00:00:00Z",
        )
        self.assertEqual(release["artifact"], plan["artifact"])

    def test_artifact_marker_rejects_provenance_for_another_attempt(self) -> None:
        plan = build_plan(
            artifact_manifest(),
            SOURCE_SHA,
            {"CI": workflow_run()},
            resolved_artifact(),
        )
        plan["artifact"]["run_attempt"] = 2
        with self.assertRaisesRegex(ValueError, "does not match one required CI run"):
            make_release(
                plan,
                {"web": self.reference},
                self.gateway,
                "2026-08-30T00:00:00Z",
            )

    def test_marker_rejects_missing_or_extra_component_digest(self) -> None:
        with self.assertRaisesRegex(ValueError, "digest set"):
            make_release(
                self.plan,
                {"web": self.reference, "extra": self.reference},
                self.gateway,
                "2026-08-30T00:00:00Z",
            )

    def test_marker_rejects_foreign_application_digest(self) -> None:
        foreign = "registry.elfeel.me/apps/other-app/web@sha256:" + "c" * 64
        with self.assertRaisesRegex(ValueError, "out-of-scope"):
            make_release(
                self.plan,
                {"web": foreign},
                self.gateway,
                "2026-08-30T00:00:00Z",
            )

    def test_gateway_identity_is_exact(self) -> None:
        gateway = {**self.gateway, "unexpected": "value"}
        with self.assertRaisesRegex(ValueError, "unexpected fields"):
            make_release(
                self.plan,
                {"web": self.reference},
                gateway,
                "2026-08-30T00:00:00Z",
            )

    def test_compact_label_round_trips(self) -> None:
        release = make_release(
            self.plan,
            {"web": self.reference},
            self.gateway,
            "2026-08-30T00:00:00Z",
        )
        label = compact_label(release)
        decoded = base64.urlsafe_b64decode(label + "=" * (-len(label) % 4))
        self.assertEqual(json.loads(decoded), release)


if __name__ == "__main__":
    unittest.main()
