from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from release_config import load_config, manifest_path, validate_config  # noqa: E402

from helpers import artifact_manifest, source_manifest  # noqa: E402


class ReleaseConfigTests(unittest.TestCase):
    def test_source_manifest_is_valid(self) -> None:
        self.assertEqual(validate_config(source_manifest()), [])

    def test_artifact_manifest_is_valid(self) -> None:
        self.assertEqual(validate_config(artifact_manifest()), [])

    def test_artifact_name_requires_one_sha_and_attempt_placeholder(self) -> None:
        invalid_names = (
            "release-{sha}",
            "release-{attempt}",
            "release-{sha}-{sha}-{attempt}",
            "release-{sha}-{attempt}-{attempt}",
            "release-{sha}-{attempt}-{other}",
        )
        for name in invalid_names:
            with self.subTest(name=name):
                manifest = artifact_manifest()
                manifest["release"]["artifact"]["name"] = name
                issues = validate_config(manifest)
                self.assertIn(
                    "release.artifact.name: must contain exactly one {sha} and one {attempt}",
                    map(str, issues),
                )

    def test_runtime_service_mapping_is_rejected(self) -> None:
        manifest = source_manifest()
        manifest["release"]["components"][0]["service"] = "web"
        issues = validate_config(manifest)
        self.assertIn("release.components[0].service: is not allowed", map(str, issues))

    def test_gateway_owned_dockerfile_is_rejected(self) -> None:
        manifest = source_manifest()
        manifest["release"]["components"][0]["dockerfile_origin"] = "gateway"
        issues = validate_config(manifest)
        self.assertIn(
            "release.components[0].dockerfile_origin: must equal source",
            map(str, issues),
        )

    def test_absolute_and_parent_paths_are_rejected(self) -> None:
        for value in ("/srv/Dockerfile", "../Dockerfile", "deploy\\Dockerfile"):
            with self.subTest(value=value):
                manifest = source_manifest()
                manifest["release"]["components"][0]["dockerfile"] = value
                issues = validate_config(manifest)
                self.assertTrue(any(issue.location.endswith("dockerfile") for issue in issues))

    def test_registry_scope_must_be_derived_from_app(self) -> None:
        manifest = source_manifest()
        manifest["registry"]["image_namespace"] = "apps/another-app"
        manifest["registry"]["release_repository"] = "releases/another-app"
        issues = validate_config(manifest)
        self.assertEqual(
            {issue.location for issue in issues},
            {"registry.image_namespace", "registry.release_repository"},
        )

    def test_unknown_top_level_policy_is_rejected(self) -> None:
        manifest = source_manifest()
        manifest["deployment"] = {"path": "/private"}
        issues = validate_config(manifest)
        self.assertIn("manifest.deployment: is not allowed", map(str, issues))

    def test_manifest_path_is_fixed_inside_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            expected = source / ".github" / "hetzner-release.json"
            expected.parent.mkdir()
            expected.write_text(json.dumps(source_manifest()), encoding="utf-8")
            self.assertEqual(manifest_path(source), expected.resolve())
            self.assertEqual(load_config(expected)["id"], "example-app")

    def test_symlink_manifest_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text(json.dumps(source_manifest()), encoding="utf-8")
            link = root / "manifest.json"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks are unavailable")
            with self.assertRaisesRegex(ValueError, "regular file"):
                load_config(link)


if __name__ == "__main__":
    unittest.main()
