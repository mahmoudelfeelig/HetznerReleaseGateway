from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from check_public_surface import MAX_FILE_BYTES, scan_repository  # noqa: E402


def write_text(root: Path, relative: str, value: str = "safe public text\n") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    return path


class PublicSurfaceTests(unittest.TestCase):
    def test_current_repository_surface_is_clean(self) -> None:
        self.assertEqual(scan_repository(ROOT), [])

    def test_safe_nested_files_are_scanned_and_generated_caches_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_text(
                root,
                "tests/case.py",
                "registry." + "elfeel" + ".me\n"
                "deployment." + "elfeel" + ".me\n"
                "https://github.com/mahmoudelfeelig/HetznerReleaseGateway\n"
                '"repository": "owner/example-app"\n'
                "uses: actions/checkout@" + "a" * 40 + "\n",
            )
            hidden_value = "/" + "op" + "t/private/config\n"
            write_text(root, "__pycache__/generated.py", hidden_value)
            write_text(root, ".git/config", hidden_value)
            self.assertEqual(scan_repository(root), [])

    def test_concrete_secret_and_topology_indicators_are_rejected_inside_tests(self) -> None:
        indicators = {
            "private key material": "-" * 5 + "BEGIN " + "PRIVATE" + " KEY" + "-" * 5,
            "GitHub token": "gh" + "p_" + "A" * 36,
            "host installation path": "/" + "op" + "t/private/config",
            "literal public IPv4 topology": ".".join(("8", "8", "8", "8")),
            "concrete non-gateway repository reference": (
                "https://github.com/" + "real" + "owner/" + "private" + "-app"
            ),
            "unapproved public hostname": "admin." + "elfeel" + ".me",
        }
        for expected_rule, value in indicators.items():
            with self.subTest(rule=expected_rule), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_text(root, "tests/synthetic_fixture.py", value + "\n")
                rules = {issue.rule for issue in scan_repository(root)}
                self.assertIn(expected_rule, rules)

    def test_forbidden_directories_and_json_inventory_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_text(root, "nested/apps/readme.txt")
            write_text(root, "config/catalog.json", "{}\n")
            rules = {issue.rule for issue in scan_repository(root)}
            self.assertIn("forbidden central platform directory", rules)
            self.assertIn("central JSON inventory is not allowed", rules)

    def test_large_and_non_utf8_publishable_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            large = write_text(root, "large.txt", "")
            large.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
            binary = root / "binary.dat"
            binary.write_bytes(b"\xff\xfe")
            rules = {issue.rule for issue in scan_repository(root)}
            self.assertIn("publishable file is unexpectedly large", rules)
            self.assertIn("publishable file is not readable UTF-8 text", rules)

    def test_publishable_symlinks_and_special_files_are_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = write_text(root, "target.txt")
            link = root / "link.txt"
            try:
                link.symlink_to(target)
            except OSError:
                pass
            else:
                rules = {issue.rule for issue in scan_repository(root)}
                self.assertIn("publishable symlink is not allowed", rules)

            if hasattr(os, "mkfifo"):
                fifo = root / "named-pipe"
                os.mkfifo(fifo)
                rules = {issue.rule for issue in scan_repository(root)}
                self.assertIn("publishable special file is not allowed", rules)


if __name__ == "__main__":
    unittest.main()
