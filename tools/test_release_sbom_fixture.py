#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Prevent the SBOM corpus test from silently exercising stale committed source."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]


class SbomFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="exochain-sbom-source-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "tools").mkdir()
        (self.root / "crates/example/src").mkdir(parents=True)
        for name in ("test_verify_release_sbom.sh", "verify_release_sbom.py"):
            shutil.copyfile(ROOT / "tools" / name, self.root / "tools" / name)
        (self.root / "Cargo.toml").write_text(f'[workspace.package]\nversion = "{VERSION}"\n')
        (self.root / "Cargo.lock").write_text("version = 4\n")
        (self.root / "crates/example/src/lib.rs").write_text("// committed source\n")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")

    def git(self, *args):
        subprocess.run(["/usr/bin/git", *args], cwd=self.root, check=True,
                       capture_output=True, text=True)

    def assert_rejected_before_generation(self, message):
        # No Cargo dependency is needed: stale source must fail before tool use.
        result = subprocess.run(
            ["/bin/bash", "tools/test_verify_release_sbom.sh"], cwd=self.root,
            env={**os.environ, "PATH": "/usr/bin:/bin", "PYTHON": sys.executable},
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def test_rejects_unreviewed_workspace_version(self):
        (self.root / "Cargo.toml").write_text('[workspace.package]\nversion = "9.9.9"\n')
        self.git("add", "Cargo.toml")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "new version")
        self.assert_rejected_before_generation("does not match reviewed SBOM corpus version")

    def test_rejects_uncommitted_cargo_manifest(self):
        with (self.root / "Cargo.toml").open("a") as handle:
            handle.write("# uncommitted manifest\n")
        self.assert_rejected_before_generation("SBOM source inputs differ from HEAD")

    def test_rejects_staged_lockfile(self):
        (self.root / "Cargo.lock").write_text("version = 4\n# staged lock change\n")
        self.git("add", "Cargo.lock")
        self.assert_rejected_before_generation("SBOM source inputs differ from HEAD")

    def test_rejects_uncommitted_crate_source(self):
        (self.root / "crates/example/src/lib.rs").write_text("// different source\n")
        self.assert_rejected_before_generation("SBOM source inputs differ from HEAD")

    def test_rejects_untracked_cargo_target(self):
        target = self.root / "crates/example/src/bin/untracked.rs"
        target.parent.mkdir()
        target.write_text("fn main() {}\n")
        self.assert_rejected_before_generation("untracked SBOM source inputs are absent from HEAD")


if __name__ == "__main__":
    unittest.main()
