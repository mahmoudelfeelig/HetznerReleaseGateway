from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from release_plan import (  # noqa: E402
    MAX_ARTIFACT_BYTES,
    build_plan,
    resolve_artifact,
    select_required_runs,
    verify_trigger,
    verify_trigger_selection,
)

from helpers import (  # noqa: E402
    ARTIFACT_DIGEST,
    SOURCE_SHA,
    artifact_manifest,
    resolved_artifact,
    source_manifest,
    workflow_event,
    workflow_attempt,
    workflow_run,
)


class FakeApi:
    def __init__(self, responses: object | list[object]) -> None:
        self.responses = responses if isinstance(responses, list) else [responses]
        self.calls: list[tuple[str, dict[str, str] | None]] = []

    def get(self, path: str, query: dict[str, str] | None = None) -> object:
        self.calls.append((path, query))
        if not self.responses:
            raise AssertionError("unexpected GitHub API request")
        return self.responses.pop(0)


class ReleasePlanTests(unittest.TestCase):
    def test_exact_workflow_run_is_authorized(self) -> None:
        self.assertEqual(
            verify_trigger(source_manifest(), workflow_event(), SOURCE_SHA, 101), []
        )

    def test_fork_and_non_push_runs_are_rejected(self) -> None:
        event = workflow_event()
        event["workflow_run"]["head_repository"]["full_name"] = "attacker/fork"
        event["workflow_run"]["event"] = "pull_request"
        messages = {
            issue.message
            for issue in verify_trigger(source_manifest(), event, SOURCE_SHA, 101)
        }
        self.assertIn("workflow run originated from an untrusted repository", messages)
        self.assertIn("only push-triggered CI runs can authorize production", messages)

    def test_trigger_attempt_must_be_the_selected_successful_attempt(self) -> None:
        event = workflow_event()
        event["workflow_run"]["run_attempt"] = 1
        selected = {"CI": workflow_run(run_attempt=2)}
        issues = verify_trigger_selection(event, selected)
        self.assertEqual(len(issues), 1)
        self.assertIn("triggering workflow attempt", issues[0].message)

    def test_trigger_attempt_is_required(self) -> None:
        event = workflow_event()
        del event["workflow_run"]["run_attempt"]
        messages = {
            issue.message
            for issue in verify_trigger(source_manifest(), event, SOURCE_SHA, 101)
        }
        self.assertIn("workflow run attempt is invalid", messages)

    def test_latest_required_run_must_be_successful(self) -> None:
        older = workflow_run(run_id=101)
        newer = workflow_run(run_id=102, conclusion="failure")
        selected, issues = select_required_runs(
            source_manifest(), [older, newer], SOURCE_SHA
        )
        self.assertEqual(selected, {})
        self.assertEqual(len(issues), 1)
        self.assertIn("latest run", issues[0].message)

    def test_ambiguous_workflow_identity_is_rejected(self) -> None:
        first = workflow_run(run_id=101, workflow_id=11)
        second = workflow_run(run_id=102, workflow_id=12)
        _, issues = select_required_runs(
            source_manifest(), [first, second], SOURCE_SHA
        )
        self.assertEqual(len(issues), 1)
        self.assertIn("ambiguous identity", issues[0].message)

    def test_required_run_attempt_is_mandatory(self) -> None:
        run = workflow_run()
        del run["run_attempt"]
        selected, issues = select_required_runs(source_manifest(), [run], SOURCE_SHA)
        self.assertEqual(selected, {})
        self.assertEqual(len(issues), 1)
        self.assertIn("invalid identity metadata", issues[0].message)

    def test_source_plan_contains_build_data_but_no_runtime_mapping(self) -> None:
        run = workflow_run()
        plan = build_plan(source_manifest(), SOURCE_SHA, {"CI": run})
        component = plan["components"][0]
        self.assertEqual(component["name"], "web")
        self.assertEqual(component["build_args"]["SOURCE_REVISION"], SOURCE_SHA)
        self.assertNotIn("service", component)
        self.assertNotIn("additional_services", component)
        self.assertNotIn("dockerfile_origin", component)

    def test_artifact_plan_uses_successful_ci_run(self) -> None:
        run = workflow_run(run_attempt=3)
        provenance = resolved_artifact(run_attempt=3)
        plan = build_plan(
            artifact_manifest(), SOURCE_SHA, {"CI": run}, provenance
        )
        self.assertEqual(plan["artifact"]["run_id"], 101)
        self.assertEqual(plan["artifact"]["run_attempt"], 3)
        self.assertEqual(plan["artifact"]["id"], 501)
        self.assertEqual(
            plan["artifact"]["name"], f"release-{SOURCE_SHA}-attempt-3"
        )
        self.assertEqual(plan["artifact"]["digest"], ARTIFACT_DIGEST)
        self.assertEqual(plan["artifact"]["size"], 4096)
        self.assertEqual(plan["artifact"]["archive"], "images.tar.gz")
        self.assertEqual(plan["artifact"]["checksums"], "SHA256SUMS")
        self.assertEqual(plan["components"][0]["artifact_image"], f"example-web:{SOURCE_SHA}")

    def test_artifact_plan_has_no_run_id_only_fallback(self) -> None:
        with self.assertRaisesRegex(ValueError, "resolved artifact provenance"):
            build_plan(
                artifact_manifest(), SOURCE_SHA, {"CI": workflow_run()}
            )

    def test_artifact_is_resolved_by_attempt_specific_name_and_identity(self) -> None:
        run = workflow_run(run_attempt=3)
        expected_name = f"release-{SOURCE_SHA}-attempt-3"
        api = FakeApi(
            [
                workflow_attempt(run_attempt=3),
                {
                "total_count": 1,
                "artifacts": [
                    {
                        "id": 501,
                        "name": expected_name,
                        "expired": False,
                        "size_in_bytes": 4096,
                        "digest": ARTIFACT_DIGEST,
                        "created_at": "2026-08-30T00:05:00Z",
                        "workflow_run": {"id": 101, "head_sha": SOURCE_SHA},
                    }
                ],
                },
            ]
        )
        artifact = resolve_artifact(
            api, "owner/example-app", SOURCE_SHA, run, artifact_manifest()["release"]["artifact"]
        )
        self.assertEqual(artifact, resolved_artifact(run_attempt=3))
        self.assertEqual(
            api.calls,
            [
                (
                    "repos/owner/example-app/actions/runs/101/attempts/3",
                    None,
                ),
                (
                    "repos/owner/example-app/actions/runs/101/artifacts",
                    {"name": expected_name, "per_page": "100"},
                )
            ],
        )

    def test_artifact_resolution_requires_exactly_one_nonexpired_match(self) -> None:
        name = f"release-{SOURCE_SHA}-attempt-1"
        base = {
            "id": 501,
            "name": name,
            "expired": False,
            "size_in_bytes": 4096,
            "digest": ARTIFACT_DIGEST,
            "created_at": "2026-08-30T00:05:00Z",
            "workflow_run": {"id": 101, "head_sha": SOURCE_SHA},
        }
        for artifacts in (
            [],
            [{**base, "expired": True}],
            [base, {**base, "id": 502}],
        ):
            with self.subTest(count=len(artifacts)):
                api = FakeApi(
                    [
                        workflow_attempt(),
                        {"total_count": len(artifacts), "artifacts": artifacts},
                    ]
                )
                with self.assertRaisesRegex(RuntimeError, "exactly one nonexpired"):
                    resolve_artifact(
                        api,
                        "owner/example-app",
                        SOURCE_SHA,
                        workflow_run(),
                        artifact_manifest()["release"]["artifact"],
                    )

    def test_artifact_resolution_rejects_untrusted_metadata(self) -> None:
        name = f"release-{SOURCE_SHA}-attempt-1"
        base = {
            "id": 501,
            "name": name,
            "expired": False,
            "size_in_bytes": 4096,
            "digest": ARTIFACT_DIGEST,
            "created_at": "2026-08-30T00:05:00Z",
            "workflow_run": {"id": 101, "head_sha": SOURCE_SHA},
        }
        cases = {
            "unexpected name": {**base, "name": "wrong-artifact"},
            "immutable ID": {**base, "id": 0},
            "size": {**base, "size_in_bytes": MAX_ARTIFACT_BYTES + 1},
            "digest": {**base, "digest": "sha256:not-a-digest"},
            "selected workflow run": {
                **base,
                "workflow_run": {"id": 101, "head_sha": "d" * 40},
            },
        }
        for message, artifact in cases.items():
            with self.subTest(message=message):
                api = FakeApi(
                    [workflow_attempt(), {"total_count": 1, "artifacts": [artifact]}]
                )
                with self.assertRaisesRegex(RuntimeError, message):
                    resolve_artifact(
                        api,
                        "owner/example-app",
                        SOURCE_SHA,
                        workflow_run(),
                        artifact_manifest()["release"]["artifact"],
                    )

    def test_artifact_must_be_created_inside_selected_attempt_window(self) -> None:
        run = workflow_run(run_attempt=2)
        expected_name = f"release-{SOURCE_SHA}-attempt-2"
        artifact = {
            "id": 501,
            "name": expected_name,
            "expired": False,
            "size_in_bytes": 4096,
            "digest": ARTIFACT_DIGEST,
            "created_at": "2026-08-30T00:09:59Z",
            "workflow_run": {"id": 101, "head_sha": SOURCE_SHA},
        }
        api = FakeApi(
            [
                workflow_attempt(
                    run_attempt=2,
                    started_at="2026-08-30T00:10:00Z",
                    completed_at="2026-08-30T00:20:00Z",
                ),
                {"total_count": 1, "artifacts": [artifact]},
            ]
        )
        with self.assertRaisesRegex(RuntimeError, "selected workflow attempt"):
            resolve_artifact(
                api,
                "owner/example-app",
                SOURCE_SHA,
                run,
                artifact_manifest()["release"]["artifact"],
            )


if __name__ == "__main__":
    unittest.main()
