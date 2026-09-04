#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the token-free Cargo archive verifier."""

from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from test_publish_sealed_crate import archive_bytes


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "tools" / "verify_crate_release_archive.py"
SPEC = importlib.util.spec_from_file_location("verify_crate_release_archive", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load crate release archive verifier")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

CRATE = "exochain-fixture"
VERSION = "0.2.6"
COMMIT = "4" * 40


class CrateReleaseArchiveVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="crate-archive-verifier-")
        self.root = Path(self.temp.name)
        self.archive = self.root / f"{CRATE}-{VERSION}.crate"
        self.original = archive_bytes()
        self.archive.write_bytes(self.original)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_verifier(self) -> str:
        output = io.StringIO()
        arguments = [
            str(MODULE_PATH),
            str(self.archive),
            CRATE,
            VERSION,
            COMMIT,
        ]
        with mock.patch.object(sys, "argv", arguments), redirect_stdout(output):
            self.assertEqual(VERIFIER.main(), 0)
        return output.getvalue()

    def test_valid_archive_is_bound_to_its_exact_captured_bytes(self) -> None:
        output = self.run_verifier()
        self.assertIn(hashlib.sha256(self.original).hexdigest(), output)

    def test_path_replacement_after_open_cannot_change_validation_or_digest(self) -> None:
        real_tarfile_open = VERIFIER.tarfile.open

        def replace_path_then_open(*args, **kwargs):
            self.archive.write_bytes(b"attacker replacement")
            return real_tarfile_open(*args, **kwargs)

        with mock.patch.object(
            VERIFIER.tarfile,
            "open",
            side_effect=replace_path_then_open,
        ):
            output = self.run_verifier()
        self.assertIn(hashlib.sha256(self.original).hexdigest(), output)
        self.assertEqual(self.archive.read_bytes(), b"attacker replacement")

    def test_ambiguous_member_spelling_fails_closed(self) -> None:
        self.archive.write_bytes(archive_bytes(ambiguous_readme=True))
        with self.assertRaises(SystemExit):
            self.run_verifier()

    def test_reader_fails_closed_without_nofollow_support(self) -> None:
        with mock.patch.object(os, "O_NOFOLLOW", 0):
            with self.assertRaises(SystemExit):
                self.run_verifier()


if __name__ == "__main__":
    unittest.main()
