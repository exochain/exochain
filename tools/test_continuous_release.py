#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Fast-feedback and candidate evidence regression firewall (stdlib only)."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INDEPENDENT_BUILD_JOBS = (
    "test", "coverage", "sbom", "integration-tests", "integration-tests-db",
    "consensus-integration", "state-sync-integration", "cross-platform",
    "zerodentity-coverage", "root-genesis-coverage", "root-genesis-portal-coverage",
    "unaudited-feature-matrix",
)


def job(source, name):
    matches = list(re.finditer(rf"^  {re.escape(name)}:\s*$", source, re.M))
    if len(matches) != 1:
        raise ValueError(f"expected one {name} job")
    start = matches[0].end()
    following = re.search(r"^  [\w-]+:\s*$", source[start:], re.M)
    return source[start:start + following.start()] if following else source[start:]


def workflow_policy(source):
    # Match executable YAML lines, never comments or prose. The repository's
    # shared action pinning guard separately parses the full workflow AST.
    def require(condition, reason):
        if not condition:
            raise ValueError(reason)

    require(re.search(r"^  group: constitutional-ci-\$\{\{ github.workflow \}\}-\$\{\{ github.event_name \}\}-\$\{\{ github.event.pull_request.number \|\| github.run_id \}\}$", source, re.M), "isolate release runs and PR groups")
    require(re.search(r"^  cancel-in-progress: \$\{\{ github.event_name == 'pull_request' \}\}$", source, re.M), "only superseded PR runs may be cancelled")
    lynk = job(source, "lynk")
    candidate = job(source, "release-candidate")
    aggregate = job(source, "all-gates")
    for name in INDEPENDENT_BUILD_JOBS:
        require(not re.search(r"^    needs:", job(source, name), re.M),
                f"independent {name} must not wait for another build")
    for name in ("build", *INDEPENDENT_BUILD_JOBS):
        require(re.search(rf"^      - {re.escape(name)}$", aggregate, re.M),
                f"all-gates must still require {name}")
    require(re.search(r"^    needs: build-wasm$", job(source, "test-bridge"), re.M),
            "bridge tests must wait for the WASM artifact")
    for block in (lynk, candidate):
        require(not re.search(r"^    (?:if|continue-on-error):", block, re.M), "jobs must fail closed")
        require("secrets." not in block and "id-token:" not in block, "no publication authority")
        require(re.search(r"^    permissions:\n      contents: read$", block, re.M), "read-only job")
        require(re.search(r"^          persist-credentials: false$", block, re.M), "no stored checkout token")
        require(re.search(r"^    timeout-minutes: (?:10|15)$", block, re.M), "bounded job")
    require(not re.search(r"^    needs:", lynk, re.M), "LYNK feedback must not wait for Rust")
    for line in (
        "      fail-fast: false", '        node: ["20.0.0", "24.15.0"]',
        "          cache: npm", "          cache-dependency-path: packages/exochain-llm-proxy/package-lock.json",
        "        working-directory: packages/exochain-llm-proxy",
        "        run: npm ci --ignore-scripts --no-audit --no-fund",
        "        run: npm run lint", "        run: npm test", "        run: npm run pack:dry-run",
    ):
        require(line in lynk.splitlines(), f"missing LYNK contract: {line}")
    require("        if: matrix.node == '24.15.0'\n        run: npm run test:coverage" in lynk,
            "Node 24 must enforce coverage thresholds")
    require(re.search(r"^      - lynk$", job(source, "all-gates"), re.M), "LYNK must block all-gates")
    require(re.search(r"^        run: python3 -B tools/test_continuous_release.py$", job(source, "hygiene"), re.M), "guard must run in CI")
    for line in (
        "    needs: [all-gates]", "          ref: ${{ github.sha }}",
        "          CI_NEEDS_JSON: ${{ toJSON(needs) }}",
        '        run: python3 -I -B tools/write_ci_candidate.py "$RUNNER_TEMP/release-candidate.json"',
        "          name: release-candidate-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}",
        "          path: ${{ runner.temp }}/release-candidate.json",
        "          if-no-files-found: error", "          overwrite: false",
    ):
        require(line in candidate.splitlines(), f"missing candidate contract: {line}")


class WorkflowTests(unittest.TestCase):
    def test_current_workflow(self):
        workflow_policy((ROOT / ".github/workflows/ci.yml").read_text())

    def test_independent_scheduling_never_removes_required_gates_or_artifact_edges(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        for name in INDEPENDENT_BUILD_JOBS:
            with self.subTest(serialized_job=name), self.assertRaises(ValueError):
                workflow_policy(source.replace(f"  {name}:\n", f"  {name}:\n    needs: build\n"))
        for name in ("build", *INDEPENDENT_BUILD_JOBS):
            with self.subTest(missing_gate=name), self.assertRaises(ValueError):
                workflow_policy(source.replace(f"      - {name}\n", ""))
        with self.assertRaises(ValueError):
            workflow_policy(source.replace("    needs: build-wasm\n", ""))

    def test_removed_checks_cancellation_and_authority_are_rejected(self):
        source = (ROOT / ".github/workflows/ci.yml").read_text()
        mutations = [
            ("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", "cancel-in-progress: true"),
            ("github.event.pull_request.number || github.run_id", "github.ref"),
            ("      - lynk\n", ""),
            ("        run: npm test", "        run: echo skipped"),
            ("        run: npm run lint", "        # run: npm run lint"),
            ("        run: npm run pack:dry-run", "        run: echo skipped"),
            ("        run: npm run test:coverage", "        run: echo skipped"),
            ("    needs: [all-gates]", "    needs: [lynk]"),
            ("  lynk:\n", "  lynk:\n    continue-on-error: true\n"),
            ("  release-candidate:\n", "  release-candidate:\n    if: always()\n"),
            ("          overwrite: false", "          overwrite: true"),
        ]
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertTrue(old in source, f"mutation target missing: {old}")
                with self.assertRaises(ValueError):
                    workflow_policy(source.replace(old, new))


class CandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("candidate", ROOT / "tools/write_ci_candidate.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        self.env = {
            "CI_NEEDS_JSON": json.dumps({"all-gates": {"result": "success", "outputs": {}}}),
            "GITHUB_SHA": "a" * 40, "GITHUB_REPOSITORY": "exochain/exochain",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKFLOW_REF": "exochain/exochain/.github/workflows/ci.yml@refs/heads/main",
        }

    def test_success_is_source_bound_and_never_publish_authority(self):
        value = self.module.build_report(self.env, "0.3.1")
        self.assertEqual(value["source_commit"], "a" * 40)
        self.assertEqual(value["status"], "quality-gates-passed")
        self.assertIs(value["publication_authorized"], False)
        self.assertEqual(value["run_url"], "https://github.com/exochain/exochain/actions/runs/123/attempts/1")

    def test_failed_skipped_cancelled_missing_or_forged_gates_fail(self):
        for result in ("failure", "skipped", "cancelled", "", None, True):
            with self.subTest(result=result):
                self.env["CI_NEEDS_JSON"] = json.dumps({"all-gates": {"result": result}})
                with self.assertRaises(ValueError):
                    self.module.build_report(self.env, "0.3.1")
        for needs in ({}, {"lynk": {"result": "success"}}, [], None):
            self.env["CI_NEEDS_JSON"] = json.dumps(needs)
            with self.assertRaises(ValueError):
                self.module.build_report(self.env, "0.3.1")

    def test_malformed_identity_fails(self):
        for key, value in (("GITHUB_SHA", "main"), ("GITHUB_RUN_ID", "1\n2"),
                           ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_REPOSITORY", "../evil"),
                           ("GITHUB_WORKFLOW_REF", "another/repo/.github/workflows/ci.yml@main")):
            env = copy.deepcopy(self.env)
            env[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.module.build_report(env, "0.3.1")

    def test_real_git_source_guard_rejects_wrong_sha_and_dirty_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            checkout = Path(temp) / "repo"
            checkout.mkdir()
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            (checkout / "Cargo.toml").write_text('[workspace.package]\nversion = "0.3.1"\n')
            subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
            subprocess.run(["git", "-C", str(checkout), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], check=True)
            sha = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
            env = dict(os.environ, **self.env, GITHUB_WORKSPACE=str(checkout), RUNNER_TEMP=temp,
                       GITHUB_STEP_SUMMARY=str(Path(temp) / "summary.md"))
            env["GITHUB_SHA"] = sha
            self.module.verify_source(env)
            output = Path(temp) / "candidate.json"
            command = [sys.executable, "-I", "-B", str(ROOT / "tools/write_ci_candidate.py"), str(output)]
            success = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual(json.loads(output.read_text())["source_commit"], sha)
            before = output.read_bytes()
            overwrite = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertNotEqual(overwrite.returncode, 0)
            self.assertEqual(output.read_bytes(), before)
            output.unlink()
            env["GITHUB_SHA"] = "b" * 40
            with self.assertRaises(subprocess.CalledProcessError):
                self.module.verify_source(env)
            env["GITHUB_SHA"] = sha
            (checkout / "Cargo.toml").write_text('[workspace.package]\nversion = "9.9.9"\n')
            with self.assertRaises(subprocess.CalledProcessError):
                self.module.verify_source(env)
            dirty = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertNotEqual(dirty.returncode, 0)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
