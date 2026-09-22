#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Regression firewall for the fixed recovery DAG and dispatch boundary."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
NORMAL = (
    "release-build package-release install-cargo-cyclonedx generate-sbom "
    "validate-sbom attest-release preflight-crates reproduce-crates publish "
    "install-wasm-pack build-wasm-npm prepare-wasm-npm test-llm-proxy-npm "
    "prepare-llm-proxy-npm prepare-sdk-npm prepare-python-package "
    "publish-wasm-npm publish-llm-proxy-npm publish-sdk-npm "
    "publish-python-package github-release"
).split()
RECOVERY = "recovery-import recovery-wasm recovery-llm recovery-sdk recovery-python recovery-github".split()


class RecoveryWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / ".github/workflows/release.yml").read_text()
        cls.jobs = dict(re.findall(r"^  ([a-z][a-z0-9-]+):\n(.*?)(?=^  [a-z][a-z0-9-]+:|\Z)", cls.text.split("jobs:\n", 1)[1], re.M | re.S))

    def test_modes_are_mutually_exclusive_at_job_level(self):
        for name in NORMAL:
            with self.subTest(job=name):
                self.assertTrue(re.search(r"^    if:.*outputs.operation == 'release'", self.jobs[name], re.M), name)
        for name in RECOVERY:
            with self.subTest(job=name):
                self.assertTrue(name in self.jobs, name)
                self.assertTrue(re.search(r"^    if:.*outputs.operation == 'recover-0.2.7'", self.jobs[name], re.M), name)

    def test_actual_input_boundary(self):
        code = self.jobs["validate-release-inputs"].split("# BEGIN RELEASE OPERATION VALIDATION\n", 1)[1].split("# END RELEASE OPERATION VALIDATION", 1)[0]
        code = "\n".join(line[10:] if line.startswith(" " * 10) else line for line in code.splitlines())
        cases = [
            ("release", "0.2.7", "refs/heads/main", True, "v0.2.7"),
            ("recover-0.2.7", "0.2.7", "refs/tags/v0.2.7-recover.1", True, "v0.2.7-recover.1"),
            ("recover-0.2.7", "0.2.7", "refs/tags/v0.2.7-recover.25", True, "v0.2.7-recover.25"),
            ("recover-0.2.7", "0.2.8", "refs/tags/v0.2.7-recover.1", False, ""),
            ("recover-0.2.7", "0.2.7", "refs/tags/v0.2.7", False, ""),
            ("recover-0.2.7", "0.2.7", "refs/heads/v0.2.7-recover.1", False, ""),
            ("recover-0.2.7", "0.2.7", "refs/tags/v0.2.7-recover.0", False, ""),
            ("recover-0.2.7", "0.2.7", "refs/tags/v0.2.7-recover.01", False, ""),
            ("release", "0.2.7", "refs/tags/v0.2.7-recover.1", False, ""),
            ("bad\nrelease", "0.2.7", "refs/tags/v0.2.7-recover.1", False, ""),
        ]
        for operation, version, ref, success, tag in cases:
            with self.subTest(operation=operation, version=version, ref=ref), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "output"
                result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-p", "-e", "-u", "-o", "pipefail", "-c", 'version="$RELEASE_VERSION_INPUT"\n' + code], env={"PATH":"/usr/bin:/bin", "RELEASE_VERSION_INPUT":version, "RELEASE_OPERATION_INPUT":operation, "GITHUB_REF":ref, "GITHUB_OUTPUT":str(output)}, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                if success:
                    self.assertEqual(output.read_text(), f"tag={tag}\noperation={operation}\n")
                else:
                    self.assertFalse(output.exists(), "invalid dispatch wrote accepted outputs")

    def test_recovery_authority_and_dry_run_boundaries(self):
        imported = self.jobs["recovery-import"]
        self.assertIn("needs: [ci, approve, approve-second, verify-signed-tag, validate-release-inputs]", imported)
        for name in ("recovery-import", "recovery-wasm"):
            block = self.jobs[name]
            self.assertNotIn("id-token:", block)
            self.assertNotIn("secrets.", block)
            self.assertNotIn("contents: write", block)
        for name in ("recovery-llm", "recovery-sdk", "recovery-python", "recovery-github"):
            block = self.jobs[name]
            self.assertTrue(re.search(r"^    if:.*!inputs.dry_run", block, re.M), name)
            self.assertIn("    environment: release\n", block)
        self.assertIn("recovery-wasm", self.jobs["recovery-llm"].split("    steps:")[0])
        self.assertIn("recovery-llm", self.jobs["recovery-sdk"].split("    steps:")[0])
        self.assertIn("recovery-sdk", self.jobs["recovery-python"].split("    steps:")[0])
        for name in ("recovery-import", "recovery-wasm", "recovery-llm", "recovery-sdk", "recovery-python"):
            self.assertIn(name, self.jobs["recovery-github"].split("    steps:")[0])
        self.assertIn('if [ "$DRY_RUN" = "true" ] && [ "$RELEASE_OPERATION" = release ]; then', self.jobs["verify-signed-tag"])

    def test_npm_receipts_require_initialized_validated_output(self):
        for name in ("recovery-wasm", "recovery-llm", "recovery-sdk"):
            block = self.jobs[name]
            self.assertEqual(block.count("id: npm-publication"), 1)
            receipt = block.split("- name: Retain Bounded Public Recovery Receipts", 1)[1]
            self.assertIn("if: ${{ always() && steps.npm-publication.outputs.receipts_ready == 'true' }}", receipt)
            profile = name.removeprefix("recovery-")
            self.assertIn("${{ runner.temp }}/exochain-recovery-receipts/npm-" + profile + "/", receipt)

    def test_python_orchestration_uses_declared_hash_locked_test_environment(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        jobs = dict(re.findall(r"^  ([a-z][a-z0-9-]+):\n(.*?)(?=^  [a-z][a-z0-9-]+:|\Z)", text.split("jobs:\n", 1)[1], re.M | re.S))
        command = "bash tools/test_recover_release_python_027.sh"
        owners = [name for name, body in jobs.items() if command in body]
        self.assertEqual(owners, ["python-sdk"])
        block = jobs["python-sdk"]
        self.assertLess(block.index("--require-hashes"), block.index(command))
        self.assertLess(block.index("tools/python-release-requirements.lock"), block.index(command))

    def test_hosted_token_contract_is_read_only_and_excluded_from_pr_execution(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text()
        jobs = dict(re.findall(r"^  ([a-z][a-z0-9-]+):\n(.*?)(?=^  [a-z][a-z0-9-]+:|\Z)", text.split("jobs:\n", 1)[1], re.M | re.S))
        command = "python3 -I -B tools/test_import_release_recovery_027.py --token-contract"
        owners = [name for name, body in jobs.items() if command in body]
        self.assertEqual(owners, ["hygiene"])
        block = jobs["hygiene"]
        self.assertIn("    permissions:\n      contents: read\n", block.split("    steps:", 1)[0])
        steps = re.split(r"^      - ", block.split("    steps:\n", 1)[1], flags=re.M)
        contract = next(step for step in steps if command in step)
        # Source guard: removing this restriction hands a real credential to
        # PR-controlled Python instead of running credential-free fixtures.
        self.assertIn("if: github.event_name == 'push' || github.event_name == 'workflow_dispatch'\n", contract)
        self.assertIn("RELEASE_GITHUB_TOKEN: ${{ github.token }}", contract)
        self.assertNotIn("secrets.", contract)
        fixtures = next(step for step in steps if "name: Fixed recovery custody and workflow boundaries\n" in step)
        self.assertNotIn("RELEASE_GITHUB_TOKEN", fixtures)

    def test_exact_source_artifacts_and_direct_python_publisher(self):
        for name in RECOVERY:
            block = self.jobs[name]
            self.assertIn("ref: ${{ needs.validate-release-inputs.outputs.trusted_ref }}", block)
            self.assertIn("persist-credentials: false", block)
            self.assertIn("EXPECTED_COMMIT_SHA: ${{ needs.validate-release-inputs.outputs.commit_sha }}", block)
            self.assertNotIn("GITHUB_SHA:", block, "must use the genuine runner dispatch identity")
            if name != "recovery-import":
                self.assertIn("artifact-ids: ${{ needs.recovery-import.outputs.artifact_id }}", block)
                self.assertIn("merge-multiple: true", block)
        python = self.jobs["recovery-python"]
        self.assertIn("pypa/gh-action-pypi-publish@cef221092ed1bacb1cc03d23a2d87d1d172e277b", python)
        self.assertIn("skip-existing: false", python)
        self.assertIn("attestations: true", python)
        self.assertIn("packages-dir: ${{ steps.python-preflight.outputs.packages_dir }}", python)
        self.assertIn("steps.python-preflight.outputs.publish_needed == 'true'", python)
        self.assertNotIn("--clobber", self.jobs["recovery-github"])

    def test_actual_launcher_commands_form_one_safe_pipeline(self):
        for name in RECOVERY:
            scripts = re.findall(r"^        run: \|\n((?:^          .*\n|^\n)+)", self.jobs[name], re.M)
            self.assertTrue(scripts, name)
            for script in scripts:
                lines = [line[10:] for line in script.splitlines()]
                # A literal pair of backslashes is not a shell continuation.
                # Parse the resulting logical command using shell tokenization,
                # then execute an instrumented pipeline with no Git/network I/O.
                self.assertTrue(all(not line.endswith("\\\\") for line in lines), name)
                logical = "\n".join(lines).replace("\\\n", "")
                command = logical.split("\n", 1)[1]
                import shlex
                tokens = shlex.split(command)
                self.assertEqual(tokens[:2], ["/usr/bin/env", "-i"])
                self.assertEqual(tokens.count("|"), 1)
                divider = tokens.index("|")
                self.assertEqual(tokens[divider + 1:divider + 7], ["/bin/bash", "--noprofile", "--norc", "-p", "-s", "--"])
                self.assertEqual(tokens[divider - 2:divider], ["show", "${GITHUB_SHA}:tools/run_release_recovery_027.sh"])
                self.assertEqual(len(tokens), divider + 8)
                with tempfile.TemporaryDirectory() as tmp:
                    probe = Path(tmp) / "git-probe"
                    probe.write_text('#!/bin/bash\n[ "$1" = --no-replace-objects ] && [ "$2" = -C ] && [ "$4" = show ] || exit 2\nprintf \'%s\\n\' \'printf "dispatch:%s\\n" "$1"\'\n')
                    probe.chmod(0o500)
                    executable = "\n".join(lines).replace("/usr/bin/git", shlex.quote(str(probe)))
                    environment = {"PATH":"/usr/bin:/bin", "GITHUB_SHA":"a" * 40, "GITHUB_WORKSPACE":tmp}
                    result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-p", "-c", executable], env=environment, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "dispatch:" + tokens[-1] + "\n")
                    broken = executable.replace("\\\n", "\\\\\n", 1)
                    rejected = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-p", "-c", broken], env=environment, capture_output=True, text=True)
                    self.assertNotEqual(rejected.returncode, 0, "doubled continuation regression accepted")


if __name__ == "__main__":
    unittest.main()
