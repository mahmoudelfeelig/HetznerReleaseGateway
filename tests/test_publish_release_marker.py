from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from publish_release_marker import (  # noqa: E402
    promote_marker,
    publish_marker,
    write_new_reference,
)


HOST = "registry.elfeel.me"
SOURCE_SHA = "a" * 40
IMAGE = f"{HOST}/releases/example-app:{SOURCE_SHA}"
REFERENCE = f"{HOST}/releases/example-app@sha256:" + "b" * 64


class PublishReleaseMarkerTests(unittest.TestCase):
    def test_reference_output_is_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "reference.txt"
            write_new_reference(output, REFERENCE)
            self.assertEqual(output.read_text(encoding="utf-8"), REFERENCE + "\n")
            with self.assertRaisesRegex(RuntimeError, "cannot create"):
                write_new_reference(output, REFERENCE)

    @mock.patch("publish_release_marker.publish_oci_layout", return_value=REFERENCE)
    def test_publish_uses_the_prebuilt_oci_layout_and_writes_reference(
        self,
        publish: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = root / "marker-oci"
            output = root / "reference.txt"
            self.assertEqual(
                publish_marker(IMAGE, HOST, layout, output),
                REFERENCE,
            )
            self.assertEqual(output.read_text(encoding="utf-8"), REFERENCE + "\n")
        publish.assert_called_once_with(layout, IMAGE, HOST)

    @mock.patch(
        "publish_release_marker.promote_release_marker",
        return_value=REFERENCE,
    )
    def test_promote_delegates_only_the_immutable_image_and_layout(
        self,
        promote: mock.Mock,
    ) -> None:
        layout = Path("marker-oci")
        self.assertEqual(promote_marker(IMAGE, HOST, layout), REFERENCE)
        promote.assert_called_once_with(layout, IMAGE, HOST)


if __name__ == "__main__":
    unittest.main()
