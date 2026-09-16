#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Publication claims remain historical facts when Git tags change."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


VALIDATOR = Path(__file__).resolve().with_name("check_published_release_claim.py")
SNAPSHOT = {
    "schema_version": 1,
    "observed_at": "2026-09-16T18:00:00Z",
    "version": "0.2.4",
    "github": {
        "release_id": 123,
        "url": "https://github.com/exochain/exochain/releases/tag/v0.2.4",
        "published_at": "2026-08-18T17:15:29Z",
        "draft": False,
        "prerelease": False,
    },
    "crates_io": {"version": "0.2.4", "packages": ["exochain-core"]},
    "npm": {"version": "0.2.4", "packages": ["@exochain/exochain-wasm"]},
}
README = """Git tags are not publication evidence.
| Metric | Value | Source |
| Last verified published release | `v0.2.4` (observed `2026-09-16T18:00:00Z`; packages listed in snapshot) | [Publication snapshot](governance/releases/published-release-snapshot.json) |
"""


class PublishedReleaseClaimTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="exochain-publication-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.readme = self.root / "README.md"
        self.snapshot = self.root / "publication.json"
        self.readme.write_text(README, encoding="utf-8")
        self.snapshot.write_text(json.dumps(SNAPSHOT), encoding="utf-8")

    def check(self):
        return subprocess.run(
            [sys.executable, str(VALIDATOR), "--readme", str(self.readme),
             "--snapshot", str(self.snapshot)],
            cwd=self.root, text=True, capture_output=True, check=False,
        )

    def assert_valid(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("v0.2.4", result.stdout)
        self.assertIn("2026-09-16T18:00:00Z", result.stdout)

    def assert_invalid(self):
        result = self.check()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("publication claim failed:", result.stderr)

    def test_dated_publication_claim_does_not_require_git_tags(self):
        self.assert_valid()

    def test_new_candidate_and_prerelease_tags_do_not_become_publications(self):
        git_env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull,
                   "GIT_CONFIG_NOSYSTEM": "1"}

        def git(*args):
            subprocess.run(["git", "-c", "commit.gpgsign=false", "-c",
                            "tag.gpgsign=false", "-c", "user.name=Fixture",
                            "-c", "user.email=fixture@example.invalid", *args],
                           cwd=self.root, env=git_env, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        git("init", "--quiet")
        git("add", "README.md", "publication.json")
        git("commit", "--quiet", "-m", "publication fixture")
        git("tag", "v0.2.4")
        self.assert_valid()
        git("tag", "-a", "v0.2.6", "-m", "unpublished candidate")
        git("tag", "-a", "v0.2.7", "-m", "unpublished correction")
        git("tag", "v9.0.0-rc.1")
        self.assert_valid()
        # Use real shallow checkouts: neither omitted tags nor a candidate-tag
        # checkout may change the meaning of the provider observation.
        for name, options in [("shallow-branch", ["--no-tags"]),
                              ("shallow-tag", ["--branch", "v0.2.7"])]:
            clone = self.root / name
            git("clone", "--quiet", "--depth=1", *options, self.root.as_uri(), str(clone))
            self.readme = clone / "README.md"
            self.snapshot = clone / "publication.json"
            self.assert_valid()

    def test_claim_cannot_advance_without_matching_provider_snapshot(self):
        self.readme.write_text(README.replace("`v0.2.4`", "`v0.2.7`"), encoding="utf-8")
        self.assert_invalid()

    def test_claim_requires_exact_observation_timestamp(self):
        self.readme.write_text(README.replace("18:00:00Z", "18:00:01Z"), encoding="utf-8")
        self.assert_invalid()

    def test_undated_or_duplicate_or_unbounded_latest_claims_fail(self):
        for value in [README.replace("Last verified", "Latest"),
                      README + README.splitlines()[-1] + "\n",
                      README.replace(" (observed `2026-09-16T18:00:00Z`; packages listed in snapshot)", "")]:
            with self.subTest(value=value):
                self.readme.write_text(value, encoding="utf-8")
                self.assert_invalid()

    def test_missing_or_malformed_snapshot_fails(self):
        self.snapshot.unlink()
        self.assert_invalid()
        self.snapshot.write_text("{broken", encoding="utf-8")
        self.assert_invalid()

    def test_duplicate_json_keys_fail(self):
        serialized = json.dumps(SNAPSHOT).replace('"schema_version": 1',
                                                '"schema_version": 2, "schema_version": 1')
        self.snapshot.write_text(serialized, encoding="utf-8")
        self.assert_invalid()

    def test_inconsistent_or_unpublished_provider_records_fail(self):
        cases = [
            ("github", "draft", True), ("github", "prerelease", True),
            ("github", "release_id", False),
            ("github", "url", "https://example.invalid/releases/tag/v0.2.4"),
            ("github", "published_at", "2027-01-01T00:00:00Z"),
            ("crates_io", "version", "0.2.7"), ("npm", "version", "0.2.7"),
            ("crates_io", "packages", []), ("npm", "packages", []),
            ("npm", "packages", ["@exochain/exochain-wasm"] * 2),
            ("crates_io", "packages", ["unrelated-crate"]),
        ]
        for provider, key, value in cases:
            with self.subTest(provider=provider, key=key, value=value):
                snapshot = copy.deepcopy(SNAPSHOT)
                snapshot[provider][key] = value
                self.snapshot.write_text(json.dumps(snapshot), encoding="utf-8")
                self.assert_invalid()

    def test_invalid_schema_version_or_observation_fails(self):
        for key, value in [("schema_version", True), ("schema_version", 2),
                           ("version", "0.2.7-rc.1"),
                           ("observed_at", "2026-02-30T00:00:00Z")]:
            with self.subTest(key=key, value=value):
                snapshot = copy.deepcopy(SNAPSHOT)
                snapshot[key] = value
                self.snapshot.write_text(json.dumps(snapshot), encoding="utf-8")
                self.assert_invalid()


if __name__ == "__main__":
    unittest.main()
