from __future__ import annotations

import contextlib
import hashlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from publish_images import (  # noqa: E402
    checksum_for_archive,
    publish_local_image,
    publish_source_build,
    verify_skopeo,
)

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
    @mock.patch("publish_images.run")
    def test_local_image_is_converted_then_uploaded_in_bounded_chunks(
        self,
        run: mock.Mock,
        publish: mock.Mock,
    ) -> None:
        publish.return_value = (
            "registry.elfeel.me/apps/example-app/web@sha256:" + "a" * 64
        )
        image = f"registry.elfeel.me/apps/example-app/web:{SOURCE_SHA}"
        value = publish_local_image(image, "registry.elfeel.me", "Publishing web")
        self.assertEqual(value, publish.return_value)
        command = run.call_args.args[0]
        self.assertEqual(
            command[:4], ["skopeo", "copy", "--format", "oci"]
        )
        self.assertEqual(command[4], f"docker-daemon:{image}")
        self.assertRegex(command[5], r"^oci:.+:release$")
        layout = publish.call_args.args[0]
        self.assertEqual(command[5], f"oci:{layout}:release")
        publish.assert_called_once_with(layout, image, "registry.elfeel.me")

    @mock.patch("publish_images.publish_local_image")
    @mock.patch("publish_images.subprocess.run")
    def test_build_argument_value_is_not_logged_by_gateway(
        self,
        run: mock.Mock,
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
                publish_source_build(plan, root)
        self.assertNotIn("do-not-echo-this-value", output.getvalue())
        build_command = run.call_args_list[0].args[0]
        self.assertIn("PUBLIC_VALUE=do-not-echo-this-value", build_command)
        publish.assert_called_once()


if __name__ == "__main__":
    unittest.main()
