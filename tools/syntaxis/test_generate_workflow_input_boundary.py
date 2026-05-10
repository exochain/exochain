#!/usr/bin/env python3
"""Regression tests for untrusted Syntaxis workflow codegen input."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = REPO_ROOT / "tools" / "syntaxis" / "generate_workflow.py"


class GenerateWorkflowInputBoundaryTests(unittest.TestCase):
    def run_generator(self, workflow: dict, output_dir: Path) -> subprocess.CompletedProcess[str]:
        workflow_file = output_dir.parent / "workflow.json"
        workflow_file.write_text(json.dumps(workflow), encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                str(workflow_file),
                "--output-dir",
                str(output_dir),
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def minimal_workflow(self, **overrides: object) -> dict:
        workflow = {
            "name": "consent-gated-action",
            "description": "Verify identity before consent-gated action.",
            "steps": [{"node": "identity-verify", "id": "step_1"}],
            "composition": "sequence",
            "error_strategy": "fail_fast",
        }
        workflow.update(overrides)
        return workflow

    def test_rejects_workflow_name_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output_dir = root / "generated"
            result = self.run_generator(
                self.minimal_workflow(name="../outside"),
                output_dir,
            )

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((root / "outside.rs").exists())
            self.assertFalse((root / "outside_integration.rs").exists())

    def test_rejects_step_id_rust_string_injection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output_dir = Path(temp) / "generated"
            result = self.run_generator(
                self.minimal_workflow(
                    steps=[
                        {
                            "node": "identity-verify",
                            "id": "step_1\";\npub fn injected() {}\n//",
                        }
                    ]
                ),
                output_dir,
            )

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((output_dir / "consent_gated_action.rs").exists())

    def test_rejects_unknown_node_types(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output_dir = Path(temp) / "generated"
            result = self.run_generator(
                self.minimal_workflow(
                    steps=[{"node": "not-in-registry", "id": "step_1"}]
                ),
                output_dir,
            )

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("not-in-registry", result.stdout + result.stderr)

    def test_multiline_description_remains_doc_comment(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output_dir = Path(temp) / "generated"
            result = self.run_generator(
                self.minimal_workflow(
                    description="first line\npub fn injected() {}",
                ),
                output_dir,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            generated = (output_dir / "consent_gated_action.rs").read_text(
                encoding="utf-8"
            )
            self.assertIn("//! first line", generated)
            self.assertIn("//! pub fn injected() {}", generated)
            self.assertNotIn("\npub fn injected() {}", generated)


if __name__ == "__main__":
    unittest.main()
