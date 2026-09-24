#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

HELPER = Path(__file__).with_name("recover_github_release_027.py")


class FakeProvider:
    def __init__(self, release=None, assets=None):
        self.release = release
        self.assets = assets or {}
        self.mutations = []

    def lookup(self): return self.release
    def list_assets(self, release_id):
        return [{"id":number, "name":name, "size":len(data), "state":"uploaded"} for number, (name, data) in enumerate(self.assets.items(), 1)]
    def download(self, asset): return self.assets[asset["name"]]
    def create(self, expected):
        self.mutations.append("create")
        self.release = {**expected, "id":123, "draft":True, "prerelease":False}
        return self.release
    def upload(self, release_id, name, data):
        self.mutations.append("upload:" + name)
        self.assets[name] = data
    def publish(self, release_id):
        self.mutations.append("publish")
        self.release["draft"] = False


class GithubRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.is_file(), "GitHub exact-asset recovery absent")
        spec = importlib.util.spec_from_file_location("github_recovery", HELPER)
        self.v = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.v)
        self.expected = {"tag_name":"v0.2.7", "target_commitish":"666c578f719d1e54fce95d6831a3af92ea80df93", "name":"EXOCHAIN v0.2.7", "body":"fixed reviewed identity"}
        self.binds = []
        self.assets = {"archive.tar.gz":b"abc", "RECOVERY-CUSTODY.json":b"{}"}

    def run_recovery(self, provider):
        return self.v.recover(provider, self.expected, self.assets, lambda:self.binds.append("bind"))

    def test_successor_receipt_distinguishes_package_publishers_from_controller(self):
        root = HELPER.parent.parent / "governance/releases/v0.2.7"
        manifest = json.loads((root / "RECOVERY-MANIFEST.json").read_text())
        publications = json.loads((root / "PUBLICATION-IDENTITIES.json").read_text())
        receipt, expected = self.v.release_metadata(manifest, publications, "a" * 40, "refs/tags/v0.2.7-recover.3")
        self.assertEqual(receipt["controller"], {"sha": "a" * 40, "ref": "refs/tags/v0.2.7-recover.3"})
        self.assertEqual(receipt["publication_identities"], publications)
        self.assertEqual(receipt["product"], manifest["product"])
        self.assertEqual(receipt["artifacts"], manifest["artifacts"])
        self.assertIn("Acceptance and GitHub Release controller", expected["body"])
        self.assertIn("prior package publishers", expected["body"])
        self.assertNotIn("Recovery publisher:", expected["body"])
        self.assertNotIn("attestations identify this recovery controller", receipt["attestation_scope"])

    def test_absent_release_creates_draft_uploads_verifies_then_publishes(self):
        provider = FakeProvider()
        self.run_recovery(provider)
        self.assertEqual(provider.mutations, ["create", "upload:archive.tar.gz", "upload:RECOVERY-CUSTODY.json", "publish"])
        self.assertGreaterEqual(len(self.binds), len(provider.mutations) + 1)
        self.assertFalse(provider.release["draft"])

    def test_partial_draft_resumes_only_missing_assets(self):
        provider = FakeProvider({**self.expected, "id":123, "draft":True, "prerelease":False}, {"archive.tar.gz":b"abc"})
        self.run_recovery(provider)
        self.assertEqual(provider.mutations, ["upload:RECOVERY-CUSTODY.json", "publish"])

    def test_existing_exact_public_release_never_mutates(self):
        provider = FakeProvider({**self.expected, "id":123, "draft":False, "prerelease":False}, dict(self.assets))
        self.run_recovery(provider)
        self.assertEqual(provider.mutations, [])

    def test_conflicts_and_incomplete_public_release_do_not_mutate(self):
        for field, value in [("tag_name", "v0.2.8"), ("target_commitish", ""), ("target_commitish", None), ("body", "different"), ("prerelease", True)]:
            with self.subTest(field=field):
                release = {**self.expected, "id":123, "draft":True, "prerelease":False, field:value}
                provider = FakeProvider(release, dict(self.assets))
                with self.assertRaises(ValueError): self.run_recovery(provider)
                self.assertEqual(provider.mutations, [])
        for assets, draft in [({"archive.tar.gz":b"xyz"}, True), ({"extra":b"x"}, True), ({}, False)]:
            provider = FakeProvider({**self.expected, "id":123, "draft":draft, "prerelease":False}, assets)
            with self.assertRaises(ValueError): self.run_recovery(provider)
            self.assertEqual(provider.mutations, [])

    def test_target_commitish_is_bookkeeping_not_signed_tag_proof(self):
        for draft in (True, False):
            provider = FakeProvider({**self.expected, "target_commitish":"main", "id":123, "draft":draft, "prerelease":False}, dict(self.assets))
            self.run_recovery(provider)
            self.assertEqual(provider.mutations, ["publish"] if draft else [])
        # A moved or invalid signed tag is still terminal, irrespective of the
        # non-authoritative target_commitish string returned by GitHub.
        provider = FakeProvider({**self.expected, "target_commitish":"main", "id":123, "draft":True, "prerelease":False}, dict(self.assets))
        def reject_tag():
            raise ValueError("original tag object or peel differs")
        with self.assertRaises(ValueError):
            self.v.recover(provider, self.expected, self.assets, reject_tag)
        self.assertEqual(provider.mutations, [])

    def test_create_always_supplies_fixed_product_source(self):
        client = self.v.GitHub("test-only-token", lambda b, label:json.loads(b))
        calls = []
        client.json = lambda *args:calls.append(args)
        client.create({**self.expected, "target_commitish":"main"})
        self.assertEqual(calls[0][2]["target_commitish"], self.v.PRODUCT_SHA)

    def test_unknown_upload_stops_with_durable_intent_and_uncertainty(self):
        provider = FakeProvider({**self.expected, "id":123, "draft":True, "prerelease":False})
        def ambiguous_upload(identifier, name, data):
            provider.mutations.append("upload:" + name)
            raise OSError("connection lost after request")
        provider.upload = ambiguous_upload
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            journal = self.v.Journal(path)
            with self.assertRaises(OSError):
                self.v.recover(provider, self.expected, self.assets, lambda:None, journal)
            events = [json.loads(row) for row in path.read_text().splitlines()]
            self.assertEqual([e["outcome"] for e in events], ["intent", "unknown"])
            self.assertEqual(events[0]["asset"], "archive.tar.gz")
            self.assertEqual(events[0]["release_id"], 123)
            self.assertEqual(provider.mutations, ["upload:archive.tar.gz"])

    def test_real_client_draft_pagination_and_terminal_page(self):
        client = self.v.GitHub("test-only-token", lambda b, label:json.loads(b))
        calls = []
        pages = [[{**self.expected, "id":123, "draft":True, "prerelease":False}], []]
        def response(method, path, **kwargs):
            calls.append((method, path)); return pages.pop(0)
        client.json = response
        self.assertTrue(client.lookup()["draft"])
        self.assertEqual(calls, [("GET", "/releases?per_page=100&page=1"), ("GET", "/releases?per_page=100&page=2")])

    def test_real_client_does_not_forward_authorization_on_redirect_or_public_read(self):
        client = self.v.GitHub("test-only-token", lambda b, label:json.loads(b))
        calls = []
        responses = [(302, b"", {"Location":"https://release-assets.githubusercontent.com/test?signature=fixture"}), (200,b"abc",{}), (200,b"{}",{})]
        class Transport:
            def open(self, request, timeout):
                calls.append(request)
                status, body, headers = responses.pop(0)
                result = io.BytesIO(body); result.status = status; result.headers = headers
                return result
        client.transport = Transport()
        self.assertEqual(client.download({"id":12,"size":3}), b"abc")
        client.request("GET", "https://crates.io/api/v1/crates/exochain-core/0.2.7", auth=False)
        self.assertEqual(calls[0].get_header("Authorization"), "Bearer test-only-token")
        self.assertIsNone(calls[1].get_header("Authorization"))
        self.assertIsNone(calls[2].get_header("Authorization"))
        with self.assertRaises(ValueError):
            client.request("GET", "https://attacker.invalid/file", auth=False)
        with self.assertRaises(ValueError):
            client.request("POST", "https://crates.io/file", b"x", auth=False)
        with self.assertRaises(ValueError):
            client.request("GET", "https://uploads.github.com/other/private", auth=True)
        self.assertEqual(len(calls), 3)

    def test_real_client_rejects_provider_errors_and_wrong_asset_redirect(self):
        client = self.v.GitHub("test-only-token", lambda b, label:json.loads(b))
        client.request = lambda *args, **kwargs:(500,b"{}",{})
        with self.assertRaises(ValueError): client.json("GET", "/releases")
        with self.assertRaises(ValueError): client.upload(123,"asset",b"abc")
        client.request = lambda *args, **kwargs:(200,b"too-long",{})
        with self.assertRaises(ValueError): client.download({"id":12,"size":3})


if __name__ == "__main__": unittest.main()
