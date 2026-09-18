#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/verify_release_recovery_python_stage.py"


class StageTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.is_file(), "Python container custody context absent")
        spec = importlib.util.spec_from_file_location("stage_check", HELPER)
        self.v = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.v)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.stage = self.workspace / ".release-recovery-python-stage"
        self.stage.mkdir()
        self.state = self.root / "state.json"
        self.sha = "a" * 40
        self.ref = "refs/tags/v0.2.7-recover.1"
        self.name = "exochain-0.2.7-py3-none-any.whl"
        self.inventory = {self.name: {"sha256": hashlib.sha256(b"abc").hexdigest(), "size": 3}}
        self.record = {"schema":"exochain-python-recovery-stage/v1", "controller_sha":self.sha, "controller_ref":self.ref, "staged":[self.name]}
        self.state.write_text(json.dumps(self.record))
        (self.stage / self.name).write_bytes(b"abc")

    def check(self, phase="staged"):
        return self.v.validate_stage(self.workspace, self.state, phase, self.sha, self.ref, self.inventory)

    def test_staged_exact_subset_and_empty(self):
        self.assertEqual(self.check(), [".release-recovery-python-stage/" + self.name])
        (self.stage / self.name).unlink()
        self.record["staged"] = []
        self.state.write_text(json.dumps(self.record))
        self.assertEqual(self.check("readback"), [])

    def test_changed_artifact_and_extra_path_fail(self):
        (self.stage / self.name).write_bytes(b"xyz")
        with self.assertRaises(ValueError): self.check()
        (self.stage / self.name).write_bytes(b"abc")
        (self.stage / "extra").write_bytes(b"x")
        with self.assertRaises(ValueError): self.check()

    def test_state_identity_and_links_fail(self):
        self.record["controller_sha"] = "b" * 40
        self.state.write_text(json.dumps(self.record))
        with self.assertRaises(ValueError): self.check()
        self.record["controller_sha"] = self.sha
        self.state.write_text(json.dumps(self.record))
        (self.stage / self.name).unlink()
        (self.stage / self.name).symlink_to(self.state)
        with self.assertRaises(ValueError): self.check()

    def test_real_action_shape_and_sidecar_required(self):
        with self.assertRaises(ValueError): self.check("readback")
        (self.stage / (self.name + ".publish.attestation")).write_text("{}")
        action = self.workspace / self.v.ACTION_PATH
        action.parent.mkdir(parents=True)
        value = {"name":"🏃", "description":self.v.ACTION_DESCRIPTION,
                 "inputs":{name:{"description":"data", "required":False} for name in self.v.ACTION_INPUTS},
                 "runs":{"using":"docker", "image":self.v.ACTION_IMAGE}}
        action.write_text(json.dumps(value))
        self.assertEqual(len(self.check("readback")), 3)
        value["runs"]["image"] = "docker://attacker.invalid/image"
        action.write_text(json.dumps(value))
        with self.assertRaises(ValueError): self.check("readback")


if __name__ == "__main__": unittest.main()
