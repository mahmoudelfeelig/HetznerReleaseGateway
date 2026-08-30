from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
CHECKOUT_V6_SHA = "d23441a48e516b6c34aea4fa41551a30e30af803"


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

    def test_all_workflows_use_the_audited_checkout_v6_commit(self) -> None:
        checkout_uses = []
        for workflow in WORKFLOW_DIRECTORY.glob("*.yml"):
            text = workflow.read_text(encoding="utf-8")
            checkout_uses.extend(
                re.findall(r"^\s*uses:\s*(actions/checkout@[^\s]+)", text, re.MULTILINE)
            )
        self.assertGreaterEqual(len(checkout_uses), 3)
        self.assertEqual(
            set(checkout_uses),
            {f"actions/checkout@{CHECKOUT_V6_SHA}"},
        )

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

    def test_release_runner_provides_audited_skopeo_interface(self) -> None:
        self.assertIn("runs-on: ubuntu-24.04", self.text)
        publisher = (ROOT / "scripts" / "publish_images.py").read_text(encoding="utf-8")
        self.assertIn("AUDITED_SKOPEO_VERSION = (1, 13, 3)", publisher)

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
        self.assertIn("publish_release_marker.py publish", self.text)
        self.assertIn("publish_release_marker.py promote", self.text)
        self.assertIn("wait_for_receipt.py", self.text)
        self.assertEqual(self.text.count("release_plan.py"), 3)

    def test_component_publication_is_bound_to_exact_gateway_sha(self) -> None:
        step_start = self.text.index("- name: Publish immutable application images")
        step_end = self.text.index("\n      - name:", step_start + 1)
        step = self.text[step_start:step_end]
        self.assertIn("GATEWAY_SHA: ${{ job.workflow_sha }}", step)
        self.assertIn('--gateway-sha "$GATEWAY_SHA"', step)

    def test_marker_uses_in_memory_oidc_client_without_docker_credentials(self) -> None:
        for command in (
            "docker build",
            "docker login",
            "docker push",
            "docker pull",
            "docker tag",
            "docker logout",
        ):
            with self.subTest(command=command):
                self.assertNotIn(command, self.text)
        self.assertNotIn("password-stdin", self.text)

    def test_final_revalidation_is_adjacent_to_production_promotion(self) -> None:
        final_step = self.text.index(
            "- name: Revalidate and promote verified OCI release marker"
        )
        final_plan = self.text.index(
            '--plan-output "$RUNNER_TEMP/final-release-plan.json"',
            final_step,
        )
        comparison = self.text.index(
            'cmp "$RUNNER_TEMP/release-plan.json" '
            '"$RUNNER_TEMP/final-release-plan.json"',
            final_plan,
        )
        promotion = self.text.index(
            "publish_release_marker.py promote",
            comparison,
        )
        next_step = self.text.index("\n      - name:", final_step + 1)
        self.assertLess(final_plan, comparison)
        self.assertLess(comparison, promotion)
        self.assertLess(promotion, next_step)


if __name__ == "__main__":
    unittest.main()
