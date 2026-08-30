from __future__ import annotations

import base64
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from make_release_marker import (  # noqa: E402
    compact_label,
    make_release,
    write_oci_layout,
)
from registry_upload import load_oci_layout  # noqa: E402
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
        self.assertEqual(release["published_at"], self.plan["published_at"])
        self.assertIsNone(release["artifact"])
        self.assertEqual(release["images"], {"web": self.reference})
        self.assertIsInstance(release["images"]["web"], str)
        serialized = json.dumps(release)
        self.assertNotIn('"service"', serialized)
        self.assertNotIn("additional_services", serialized)

    def test_same_release_identity_produces_the_same_marker(self) -> None:
        first = make_release(
            self.plan,
            {"web": self.reference},
            self.gateway,
        )
        second = make_release(
            json.loads(json.dumps(self.plan)),
            {"web": self.reference},
            dict(self.gateway),
        )
        self.assertEqual(first, second)
        self.assertEqual(compact_label(first), compact_label(second))

    def test_deterministic_oci_layout_preserves_label_and_release_file(self) -> None:
        release = make_release(
            self.plan,
            {"web": self.reference},
            self.gateway,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            second = root / "second"
            first_digest = write_oci_layout(release, first)
            second_digest = write_oci_layout(
                json.loads(json.dumps(release)),
                second,
            )
            first_files = {
                path.relative_to(first).as_posix(): path.read_bytes()
                for path in first.rglob("*")
                if path.is_file()
            }
            second_files = {
                path.relative_to(second).as_posix(): path.read_bytes()
                for path in second.rglob("*")
                if path.is_file()
            }
            loaded = load_oci_layout(first)
            config = json.loads(loaded.config.path.read_text(encoding="utf-8"))
            labels = config["config"]["Labels"]
            with tarfile.open(loaded.layers[0].path, mode="r:") as archive:
                members = archive.getmembers()
                release_file = archive.extractfile(members[0])
                self.assertIsNotNone(release_file)
                archived_release = json.load(release_file)

        self.assertEqual(first_digest, second_digest)
        self.assertEqual(first_files, second_files)
        self.assertEqual(loaded.manifest.digest, first_digest)
        self.assertEqual(labels["org.elfeel.release"], compact_label(release))
        self.assertEqual(
            labels["org.opencontainers.image.revision"],
            self.plan["sha"],
        )
        self.assertEqual(
            labels["org.opencontainers.image.source"],
            f"https://github.com/{self.plan['repository']}",
        )
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0].name, "release.json")
        self.assertEqual(members[0].mode, 0o444)
        self.assertEqual(members[0].uid, 0)
        self.assertEqual(members[0].gid, 0)
        self.assertEqual(archived_release, release)

    def test_marker_layout_output_is_create_only(self) -> None:
        release = make_release(
            self.plan,
            {"web": self.reference},
            self.gateway,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "already exists"):
                write_oci_layout(release, root)

    def test_marker_requires_the_plan_bound_ci_timestamp(self) -> None:
        plan = {**self.plan, "published_at": "not-a-timestamp"}
        with self.assertRaisesRegex(ValueError, "publication timestamp"):
            make_release(plan, {"web": self.reference}, self.gateway)

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
            )

    def test_marker_rejects_missing_or_extra_component_digest(self) -> None:
        with self.assertRaisesRegex(ValueError, "digest set"):
            make_release(
                self.plan,
                {"web": self.reference, "extra": self.reference},
                self.gateway,
            )

    def test_marker_rejects_foreign_application_digest(self) -> None:
        foreign = "registry.elfeel.me/apps/other-app/web@sha256:" + "c" * 64
        with self.assertRaisesRegex(ValueError, "out-of-scope"):
            make_release(
                self.plan,
                {"web": foreign},
                self.gateway,
            )

    def test_gateway_identity_is_exact(self) -> None:
        gateway = {**self.gateway, "unexpected": "value"}
        with self.assertRaisesRegex(ValueError, "unexpected fields"):
            make_release(
                self.plan,
                {"web": self.reference},
                gateway,
            )

    def test_compact_label_round_trips(self) -> None:
        release = make_release(
            self.plan,
            {"web": self.reference},
            self.gateway,
        )
        label = compact_label(release)
        decoded = base64.urlsafe_b64decode(label + "=" * (-len(label) % 4))
        self.assertEqual(json.loads(decoded), release)


if __name__ == "__main__":
    unittest.main()
