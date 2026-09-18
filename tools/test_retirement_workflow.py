#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Protected retirement configuration and fail-closed runner regression tests."""

import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def workflow_contract(workflow):
    dispatch = workflow["on"]["workflow_dispatch"]["inputs"]
    assert list(workflow["on"]) == ["workflow_dispatch"]
    assert dispatch["dry_run"]["type"] == "boolean"
    assert dispatch["dry_run"]["default"] is True
    assert dispatch["maintenance_tag"]["required"] is True
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {"group": "retire-crates-0.2.3", "cancel-in-progress": False}
    jobs = workflow["jobs"]
    assert jobs["ci"]["uses"] == "./.github/workflows/ci.yml"
    for job, environment in (("approve", "release"), ("approve-second", "release-second")):
        assert jobs[job]["environment"] == environment
        assert jobs[job]["needs"] == ["ci"]
        assert jobs[job]["permissions"] == {}
    final = jobs["retire"]
    assert final["needs"] == ["ci", "approve", "approve-second"]
    assert final["environment"] == "release"
    assert final["permissions"] == {"contents": "read"}
    assert final["runs-on"] == "ubuntu-24.04"
    steps = final["steps"]
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["uses"] == "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
    assert checkout["with"] == {"ref": "${{ github.sha }}", "fetch-depth": 0, "persist-credentials": False}
    python = next(step for step in steps if step.get("id") == "python")
    assert python["uses"] == "actions/setup-python@83679a892e2d95755f2dac6acb0bfd1e9ac5d548"
    assert python["with"]["python-version"] == "3.13.7"
    node = next(step for step in steps if step.get("uses", "").startswith("actions/setup-node@"))
    assert node["uses"] == "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020"
    assert node["with"]["node-version"] == "22.14.0"
    secret_steps = [step for step in steps if "CARGO_REGISTRY_TOKEN" in json.dumps(step)]
    assert len(secret_steps) == 1
    apply = secret_steps[0]
    assert apply["if"] == "${{ !inputs.dry_run }}"
    assert apply["env"]["CARGO_REGISTRY_TOKEN"] == "${{ secrets.CARGO_REGISTRY_TOKEN }}"
    assert apply["run"] == "/bin/bash --noprofile --norc -p tools/run_retirement_023.sh"
    public = next(step for step in steps if step.get("name") == "Public preflight only")
    assert public["if"] == "${{ inputs.dry_run }}"
    assert public["run"] == apply["run"]
    assert "CARGO_REGISTRY_TOKEN" not in json.dumps(public)
    # Secrets belong to one final narrow step, never a job/global environment.
    without_apply = copy.deepcopy(workflow)
    without_apply["jobs"]["retire"]["steps"].remove(apply)
    assert "secrets." not in json.dumps(without_apply)
    assert "id-token" not in json.dumps(workflow)
    assert final["env"]["RETIREMENT_TAG"] == "${{ inputs.maintenance_tag }}"
    assert final["env"]["DRY_RUN"] == "${{ inputs.dry_run }}"
    assert "GITHUB_SHA" not in final["env"]
    artifact = steps[-1]
    assert artifact["if"] == "${{ always() }}"
    assert artifact["uses"] == "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    assert artifact["with"]["path"] == "${{ runner.temp }}/retirement-023-receipts.jsonl"


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / ".github/workflows/retire-0.2.3.yml"
        self.assertTrue(path.is_file(), "protected retirement workflow is missing")
        # JSON is a YAML subset: this deliberately dependency-free workflow
        # representation lets CI inspect the actual structure without PyYAML.
        source = "\n".join(line for line in path.read_text().splitlines() if not line.startswith("#"))
        self.workflow = json.loads(source)

    def test_current_workflow_enforces_the_protected_contract(self):
        workflow_contract(self.workflow)

    def test_approval_messages_have_one_line_ending(self):
        for name in ("approve", "approve-second"):
            result = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", "-p", "-c",
                 self.workflow["jobs"][name]["steps"][0]["run"]],
                env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            self.assertTrue(result.stdout.endswith("\n"))
            self.assertEqual(result.stdout.count("\n"), 1)

    def test_missing_approval_dependency_is_rejected(self):
        self.workflow["jobs"]["retire"]["needs"].remove("approve-second")
        with self.assertRaises(AssertionError):
            workflow_contract(self.workflow)

    def test_broad_secret_scope_is_rejected(self):
        self.workflow["env"] = {"CARGO_REGISTRY_TOKEN": "${{ secrets.CARGO_REGISTRY_TOKEN }}"}
        with self.assertRaises(AssertionError):
            workflow_contract(self.workflow)

    def test_live_default_is_rejected(self):
        self.workflow["on"]["workflow_dispatch"]["inputs"]["dry_run"]["default"] = False
        with self.assertRaises(AssertionError):
            workflow_contract(self.workflow)

    def test_mutable_checkout_is_rejected(self):
        self.workflow["jobs"]["retire"]["steps"][0]["with"]["ref"] = "main"
        with self.assertRaises(AssertionError):
            workflow_contract(self.workflow)

    def test_checkout_action_sha_downgrade_is_rejected(self):
        self.workflow["jobs"]["retire"]["steps"][0]["uses"] = "actions/checkout@main"
        with self.assertRaises(AssertionError):
            workflow_contract(self.workflow)

    def test_setup_python_action_sha_downgrade_is_rejected(self):
        self.workflow["jobs"]["retire"]["steps"][1]["uses"] = "actions/setup-python@main"
        with self.assertRaises(AssertionError):
            workflow_contract(self.workflow)

    def test_setup_node_action_sha_downgrade_is_rejected(self):
        self.workflow["jobs"]["retire"]["steps"][2]["uses"] = "actions/setup-node@main"
        with self.assertRaises(AssertionError):
            workflow_contract(self.workflow)

    def test_receipt_upload_action_sha_downgrade_is_rejected(self):
        self.workflow["jobs"]["retire"]["steps"][-1]["uses"] = "actions/upload-artifact@main"
        with self.assertRaises(AssertionError):
            workflow_contract(self.workflow)

    def test_python_version_downgrade_is_rejected(self):
        self.workflow["jobs"]["retire"]["steps"][1]["with"]["python-version"] = "3.13"
        with self.assertRaises(AssertionError):
            workflow_contract(self.workflow)

    def test_node_version_downgrade_is_rejected(self):
        self.workflow["jobs"]["retire"]["steps"][2]["with"]["node-version"] = "22"
        with self.assertRaises(AssertionError):
            workflow_contract(self.workflow)


class RunnerTests(unittest.TestCase):
    def check_rejection(self, overrides, expected):
        env = {
            "PATH": "/usr/bin:/bin", "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "exochain/exochain",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": "a" * 40,
            "GITHUB_REF": "refs/tags/v0.2.7-retire-0.2.3.1",
            "RETIREMENT_TAG": "v0.2.7-retire-0.2.3.1", "DRY_RUN": "true",
            **overrides,
        }
        result = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-p", str(ROOT / "tools/run_retirement_023.sh")],
            env=env, capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(expected, result.stderr)

    def test_rejects_non_actions_execution(self):
        self.check_rejection({"GITHUB_ACTIONS": "false"}, "requires the canonical workflow-dispatch context")

    def test_rejects_other_repository(self):
        self.check_rejection({"GITHUB_REPOSITORY": "attacker/exochain"}, "requires the canonical workflow-dispatch context")

    def test_rejects_product_tag(self):
        self.check_rejection({"RETIREMENT_TAG": "v0.2.7"}, "invalid maintenance tag")

    def test_rejects_zero_maintenance_revision(self):
        self.check_rejection({"RETIREMENT_TAG": "v0.2.7-retire-0.2.3.0"}, "invalid maintenance tag")

    def test_rejects_branch_dispatch(self):
        self.check_rejection({"GITHUB_REF": "refs/heads/main"}, "dispatch must use the exact maintenance tag")

    def test_rejects_invalid_sha(self):
        self.check_rejection({"GITHUB_SHA": "main"}, "dispatch SHA must be a full commit identity")

    def test_rejects_invalid_dry_run(self):
        self.check_rejection({"DRY_RUN": "yes"}, "DRY_RUN must be exactly true or false")

    def source_fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="retirement-source-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        workspace = root / "checkout"
        (workspace / "tools").mkdir(parents=True)
        shutil.copyfile(ROOT / "tools/verify_release_source.sh", workspace / "tools/verify_release_source.sh")
        (workspace / "owned.txt").write_text("reviewed source\n")
        def git(*args):
            return subprocess.check_output(["/usr/bin/git", *args], cwd=workspace, text=True).strip()
        git("init", "-q")
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-qm", "source")
        context = {
            "GITHUB_WORKSPACE": str(workspace), "RUNNER_TEMP": str(root),
            "GITHUB_SHA": git("rev-parse", "HEAD"),
            "RELEASE_GITHUB_TOKEN": "fixture-not-a-credential",
            "EXOCHAIN_RELEASE_SIGNING_PUBLIC_KEY_ASC": "invalid-key-never-reached",
            "EXOCHAIN_CRATES_IO_ALLOWED_OWNERS": "exochain",
        }
        return workspace, git, context

    def test_rejects_dispatch_commit_different_from_actual_head(self):
        workspace, git, context = self.source_fixture()
        (workspace / "owned.txt").write_text("new commit\n")
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-qm", "different head")
        self.check_rejection(context, "identity mismatch")

    def test_rejects_mutated_helper_before_loading_it(self):
        workspace, _, context = self.source_fixture()
        (workspace / "tools/verify_release_source.sh").write_text("exit 0\n")
        self.check_rejection(context, "tracked file bytes differ from immutable commit")

    def test_rejects_ignored_untracked_source(self):
        workspace, _, context = self.source_fixture()
        (workspace / ".git/info/exclude").write_text("hidden.py\n")
        (workspace / "hidden.py").write_text("# ignored injection\n")
        self.check_rejection(context, "checkout must be clean, including ignored and nonignored untracked files")


if __name__ == "__main__":
    unittest.main()
