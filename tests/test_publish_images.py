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
    checksum_for_archive,
    inspect_digest,
    publish_source_build,
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
    def test_digest_selection_requires_one_exact_repository(self, run: mock.Mock) -> None:
        run.return_value.stdout = json.dumps(
            ["registry.elfeel.me/apps/example-app/web@sha256:" + "a" * 64]
        )
        value = inspect_digest(
            f"registry.elfeel.me/apps/example-app/web:{SOURCE_SHA}"
        )
        self.assertEqual(
            value,
            "registry.elfeel.me/apps/example-app/web@sha256:" + "a" * 64,
        )

    @mock.patch("publish_images.inspect_digest")
    @mock.patch("publish_images.registry_login")
    @mock.patch("publish_images.subprocess.run")
    def test_build_argument_value_is_not_logged_by_gateway(
        self,
        run: mock.Mock,
        _login: mock.Mock,
        digest: mock.Mock,
    ) -> None:
        digest.return_value = (
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


if __name__ == "__main__":
    unittest.main()
