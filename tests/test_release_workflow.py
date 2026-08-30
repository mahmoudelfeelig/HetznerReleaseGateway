from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_external_actions_are_pinned_to_full_shas(self) -> None:
        uses = re.findall(r"^\s*uses:\s*([^\s]+)", self.text, flags=re.MULTILINE)
        self.assertGreaterEqual(len(uses), 2)
        for value in uses:
            if value.startswith("mahmoudelfeelig/"):
                continue
            self.assertRegex(value, r"^[^@]+@[0-9a-f]{40}$")

    def test_artifact_download_uses_gateway_verifier_not_download_action(self) -> None:
        self.assertNotIn("actions/download-artifact", self.text)
        self.assertIn("gateway/scripts/download_artifact.py", self.text)
        self.assertIn('--plan "$RUNNER_TEMP/release-plan.json"', self.text)
        self.assertIn(
            '--output-directory "$RUNNER_TEMP/release-artifact"', self.text
        )

    def test_releases_are_serialized_without_cancellation(self) -> None:
        self.assertIn("group: production-${{ inputs.app }}", self.text)
        self.assertIn("cancel-in-progress: false", self.text)

    def test_source_manifest_path_is_fixed_by_gateway_code(self) -> None:
        self.assertIn("--source-root source", self.text)
        self.assertNotIn("--manifest", self.text)
        self.assertNotIn("release-apps", self.text)

    def test_caller_must_use_exact_gateway_sha(self) -> None:
        self.assertIn(
            'test "$WORKFLOW_REF" = "$WORKFLOW_REPOSITORY/$WORKFLOW_FILE@$WORKFLOW_SHA"',
            self.text,
        )
        self.assertIn('test "$(git -C gateway rev-parse HEAD)" = "$WORKFLOW_SHA"', self.text)

    def test_workflow_has_no_secret_inheritance_or_host_access(self) -> None:
        self.assertNotIn("secrets: inherit", self.text)
        self.assertNotIn("ssh", self.text.casefold())
        self.assertNotIn("/" + "op" + "t/", self.text)

    def test_marker_receipt_and_revalidation_are_present(self) -> None:
        self.assertIn("make_release_marker.py", self.text)
        self.assertIn("wait_for_receipt.py", self.text)
        self.assertEqual(self.text.count("release_plan.py"), 3)


if __name__ == "__main__":
    unittest.main()
