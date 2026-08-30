from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from publish_images import (  # noqa: E402
    canonical_plan_digest,
    checksum_for_archive,
    component_provenance,
    publish_artifact_images,
    publish_local_image,
    publish_source_build,
    stamp_oci_layout,
    verify_skopeo,
)
from make_release_marker import write_oci_layout  # noqa: E402
from registry_upload import load_oci_layout  # noqa: E402

from helpers import SOURCE_SHA  # noqa: E402


class PublishImagesTests(unittest.TestCase):
    def test_checksum_manifest_binds_exact_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "images.tar"
            archive.write_bytes(b"immutable image archive")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            checksums = root / "SHA256SUMS"
            checksums.write_text(f"{digest}  images.tar\n", encoding="utf-8")
            self.assertEqual(
                checksum_for_archive(root, archive, checksums), digest
            )

    def test_checksum_manifest_rejects_parent_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "images.tar"
            archive.write_bytes(b"archive")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            checksums = root / "SHA256SUMS"
            checksums.write_text(f"{digest}  ../images.tar\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "escaped"):
                checksum_for_archive(root, archive, checksums)

    @mock.patch("publish_images.subprocess.run")
    def test_skopeo_version_is_fail_closed(self, run: mock.Mock) -> None:
        run.return_value.stdout = "skopeo version 1.13.3\n"
        self.assertEqual(verify_skopeo(), (1, 13, 3))
        run.return_value.stdout = "skopeo version 1.12.9\n"
        with self.assertRaisesRegex(RuntimeError, "audited Skopeo"):
            verify_skopeo()
        run.return_value.stdout = "skopeo version 1.14.0\n"
        with self.assertRaisesRegex(RuntimeError, "audited Skopeo"):
            verify_skopeo()

    @mock.patch("publish_images.publish_oci_layout")
    @mock.patch("publish_images.stamp_oci_layout")
    @mock.patch("publish_images.run")
    def test_local_image_is_converted_then_uploaded_in_bounded_chunks(
        self,
        run: mock.Mock,
        stamp: mock.Mock,
        publish: mock.Mock,
    ) -> None:
        publish.return_value = (
            "registry.elfeel.me/apps/example-app/web@sha256:" + "a" * 64
        )
        image = f"registry.elfeel.me/apps/example-app/web:{SOURCE_SHA}"
        annotations = {"io.elfeel.release.provenance-version": "1"}
        value = publish_local_image(
            image,
            "registry.elfeel.me",
            "Publishing web",
            annotations,
        )
        self.assertEqual(value, publish.return_value)
        command = run.call_args.args[0]
        self.assertEqual(
            command[:4], ["skopeo", "copy", "--format", "oci"]
        )
        self.assertEqual(command[4], f"docker-daemon:{image}")
        self.assertRegex(command[5], r"^oci:.+:release$")
        layout = publish.call_args.args[0]
        self.assertEqual(command[5], f"oci:{layout}:release")
        stamp.assert_called_once_with(layout, annotations)
        publish.assert_called_once_with(layout, image, "registry.elfeel.me")

    @mock.patch("publish_images.publish_local_image")
    @mock.patch("publish_images.resolve_existing_oci_image", return_value=None)
    @mock.patch("publish_images.subprocess.run")
    def test_build_argument_value_is_not_logged_by_gateway(
        self,
        run: mock.Mock,
        resolve: mock.Mock,
        publish: mock.Mock,
    ) -> None:
        publish.return_value = (
            "registry.elfeel.me/apps/example-app/web@sha256:" + "a" * 64
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            plan = {
                "app": "example-app",
                "repository": "owner/example-app",
                "sha": SOURCE_SHA,
                "published_at": "2026-08-30T00:10:00Z",
                "strategy": "source-build",
                "registry": {"host": "registry.elfeel.me"},
                "components": [
                    {
                        "name": "web",
                        "destination": (
                            "registry.elfeel.me/apps/example-app/web:" + SOURCE_SHA
                        ),
                        "context": ".",
                        "dockerfile": "Dockerfile",
                        "target": None,
                        "build_args": {"PUBLIC_VALUE": "do-not-echo-this-value"},
                    }
                ],
            }
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                publish_source_build(plan, root, "b" * 40)
        self.assertNotIn("do-not-echo-this-value", output.getvalue())
        build_command = run.call_args_list[0].args[0]
        self.assertIn("PUBLIC_VALUE=do-not-echo-this-value", build_command)
        resolve.assert_called_once()
        publish.assert_called_once()

    def test_plan_digest_is_canonical_and_binds_release_inputs(self) -> None:
        first = {
            "app": "example-app",
            "sha": SOURCE_SHA,
            "components": [{"name": "web", "build_args": {"B": "2", "A": "1"}}],
        }
        reordered = json.loads(json.dumps(first, sort_keys=True))
        self.assertEqual(canonical_plan_digest(first), canonical_plan_digest(reordered))
        changed = json.loads(json.dumps(first))
        changed["components"][0]["build_args"]["A"] = "different"
        self.assertNotEqual(canonical_plan_digest(first), canonical_plan_digest(changed))

    def test_provenance_stamping_is_valid_and_deterministic(self) -> None:
        plan = {
            "app": "example-app",
            "repository": "owner/example-app",
            "sha": SOURCE_SHA,
            "published_at": "2026-08-30T00:10:00Z",
            "strategy": "source-build",
            "registry": {"host": "registry.elfeel.me"},
            "components": [{"name": "web"}],
        }
        annotations = component_provenance(plan, plan["components"][0], "b" * 40)
        release = {
            "published_at": plan["published_at"],
            "source_sha": SOURCE_SHA,
            "repository": plan["repository"],
        }
        with tempfile.TemporaryDirectory() as directory:
            layout = Path(directory) / "layout"
            write_oci_layout(release, layout)
            stamp_oci_layout(layout, annotations)
            first = load_oci_layout(layout)
            first_manifest = json.loads(first.manifest_bytes)
            stamp_oci_layout(layout, annotations)
            second = load_oci_layout(layout)
        self.assertEqual(first.manifest.digest, second.manifest.digest)
        for key, value in annotations.items():
            self.assertEqual(first_manifest["annotations"][key], value)

    @mock.patch("publish_images.publish_local_image")
    @mock.patch("publish_images.resolve_existing_oci_image")
    @mock.patch("publish_images.subprocess.run")
    def test_valid_existing_component_skips_build_and_publication(
        self,
        run: mock.Mock,
        resolve: mock.Mock,
        publish: mock.Mock,
    ) -> None:
        reference = "registry.elfeel.me/apps/example-app/web@sha256:" + "c" * 64
        resolve.return_value = reference
        plan = {
            "app": "example-app",
            "repository": "owner/example-app",
            "sha": SOURCE_SHA,
            "published_at": "2026-08-30T00:10:00Z",
            "strategy": "source-build",
            "registry": {"host": "registry.elfeel.me"},
            "components": [
                {
                    "name": "web",
                    "destination": (
                        "registry.elfeel.me/apps/example-app/web:" + SOURCE_SHA
                    ),
                    "context": ".",
                    "dockerfile": "Dockerfile",
                    "target": None,
                    "build_args": {},
                }
            ],
        }
        self.assertEqual(
            publish_source_build(plan, Path("unused"), "b" * 40),
            {"web": reference},
        )
        run.assert_not_called()
        publish.assert_not_called()

    @mock.patch("publish_images.publish_local_image")
    @mock.patch("publish_images.resolve_existing_oci_image")
    @mock.patch("publish_images.run")
    def test_invalid_existing_component_fails_before_build_or_publication(
        self,
        run: mock.Mock,
        resolve: mock.Mock,
        publish: mock.Mock,
    ) -> None:
        resolve.side_effect = RuntimeError("remote image provenance mismatch")
        plan = {
            "app": "example-app",
            "repository": "owner/example-app",
            "sha": SOURCE_SHA,
            "published_at": "2026-08-30T00:10:00Z",
            "strategy": "source-build",
            "registry": {"host": "registry.elfeel.me"},
            "components": [
                {
                    "name": "web",
                    "destination": (
                        "registry.elfeel.me/apps/example-app/web:" + SOURCE_SHA
                    ),
                    "context": ".",
                    "dockerfile": "Dockerfile",
                    "target": None,
                    "build_args": {},
                }
            ],
        }
        with self.assertRaisesRegex(RuntimeError, "provenance mismatch"):
            publish_source_build(plan, Path("unused"), "b" * 40)
        run.assert_not_called()
        publish.assert_not_called()

    @mock.patch("publish_images.publish_local_image")
    @mock.patch("publish_images.resolve_existing_oci_image")
    @mock.patch("publish_images.run")
    def test_artifact_release_reuses_valid_components_and_loads_only_when_needed(
        self,
        run: mock.Mock,
        resolve: mock.Mock,
        publish: mock.Mock,
    ) -> None:
        existing = "registry.elfeel.me/apps/example-app/web@sha256:" + "c" * 64
        created = "registry.elfeel.me/apps/example-app/api@sha256:" + "d" * 64
        resolve.side_effect = [existing, None]
        publish.return_value = created
        plan = {
            "app": "example-app",
            "repository": "owner/example-app",
            "sha": SOURCE_SHA,
            "published_at": "2026-08-30T00:10:00Z",
            "strategy": "artifact-images",
            "registry": {"host": "registry.elfeel.me"},
            "components": [
                {
                    "name": "web",
                    "destination": (
                        "registry.elfeel.me/apps/example-app/web:" + SOURCE_SHA
                    ),
                    "artifact_image": "example-web:" + SOURCE_SHA,
                },
                {
                    "name": "api",
                    "destination": (
                        "registry.elfeel.me/apps/example-app/api:" + SOURCE_SHA
                    ),
                    "artifact_image": "example-api:" + SOURCE_SHA,
                },
            ],
            "artifact": {"digest": "sha256:" + "e" * 64},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "images.tar"
            archive.write_bytes(b"verified archive")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            (root / "SHA256SUMS").write_text(
                f"{digest}  images.tar\n",
                encoding="utf-8",
            )
            result = publish_artifact_images(
                plan,
                root,
                "images.tar",
                "SHA256SUMS",
                "b" * 40,
            )
        self.assertEqual(result, {"web": existing, "api": created})
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[0][:3], ["docker", "load", "--input"])
        self.assertEqual(
            [command[:2] for command in commands[1:]],
            [["docker", "image"], ["docker", "tag"]],
        )
        publish.assert_called_once()
        annotations = publish.call_args.args[3]
        self.assertEqual(
            annotations["io.elfeel.release.strategy"],
            "artifact-images",
        )
        self.assertEqual(
            annotations["io.elfeel.release.component"],
            "api",
        )


if __name__ == "__main__":
    unittest.main()
