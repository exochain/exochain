#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
import importlib.util
import io
import json
import copy
import os
from pathlib import Path
import tempfile
import unittest
import types
from unittest.mock import patch

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

    def test_read_only_preflight_never_creates_uploads_or_publishes(self):
        self.assertTrue(callable(getattr(self.v, 'preflight', None)), 'read-only preflight absent')
        for draft, assets in [(None, {}), (True, {}), (True, self.assets), (False, self.assets)]:
            release = None if draft is None else {**self.expected,'id':123,'draft':draft,'prerelease':False}
            provider = FakeProvider(release, dict(assets))
            result = self.v.preflight(provider,self.expected,self.assets,lambda:self.binds.append('bind'))
            self.assertFalse(result['mutation_attempted'])
            self.assertEqual(provider.mutations, [])

    def test_retained_writer_requires_current_receipts_before_public_checks_or_writes(self):
        self.assertTrue(callable(getattr(self.v, 'complete_retained', None)), 'retained writer gate absent')
        for fault in ('receipts','public',None):
            events = []
            provider = FakeProvider()
            def receipt_gate():
                events.append('receipts')
                if fault == 'receipts': raise ValueError('replayed receipt')
            def public_gate():
                events.append('public')
                if fault == 'public': raise ValueError('public bytes changed')
            args = (provider,self.expected,self.assets,lambda:events.append('rebind'),receipt_gate,public_gate)
            if fault:
                with self.assertRaises(ValueError): self.v.complete_retained(*args)
                self.assertEqual(provider.mutations,[])
            else:
                self.v.complete_retained(*args)
                self.assertFalse(provider.release['draft'])
            self.assertEqual(events[:2] if fault != 'receipts' else events, ['receipts','public'] if fault != 'receipts' else ['receipts'])

    def test_retained_receipt_context_is_bound_to_actual_environment(self):
        self.assertTrue(callable(getattr(self.v, 'receipt_handoff', None)), 'direct handoff parser absent')
        context = {'controller_sha':'a'*40,'controller_ref':'refs/tags/v0.2.7-recover.3',
            'controller_tag_object':'b'*40,'run_id':40000000000,'run_attempt':2,'producer_job_id':333,
            'checker_sha256':'c'*64,'dry_run':False,'checked_at':'2026-09-24T21:00:00Z',
            'runtime_versions':{'python':'3.13.7','node':'24.15.0','npm':'11.12.1','gh':'2.80.0'}}
        env = {'GITHUB_SHA':context['controller_sha'],'GITHUB_REF':context['controller_ref'],
            'EXPECTED_TAG_OBJECT_SHA':context['controller_tag_object'],'GITHUB_RUN_ID':'40000000000',
            'GITHUB_RUN_ATTEMPT':'2','RELEASE_WORKFLOW_DRY_RUN':'false',
            'RELEASE_RECEIPT_ARTIFACT_ID':'444','RELEASE_RECEIPT_ARTIFACT_DIGEST':'d'*64,
            'RELEASE_RECEIPT_PRODUCER_JOB_ID':'333','RELEASE_RECEIPT_RECEIPT_CONTEXT':json.dumps(context),
            'RELEASE_RECEIPT_RECEIPT_MEMBERS':'[]'}
        # Canonical member/schema checks follow in the Task1 profile validator.
        self.v.receipt_handoff(env,json.loads,'c'*64)
        for key,bad in [('run_attempt',1),('run_id',40000000001),('controller_sha','e'*40),
                        ('controller_ref','refs/tags/v0.2.7-recover.2'),('controller_tag_object','e'*40),
                        ('checker_sha256','e'*64),('dry_run',True),('producer_job_id',334)]:
            altered = dict(context,**{key:bad})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.v.receipt_handoff(dict(env,RELEASE_RECEIPT_RECEIPT_CONTEXT=json.dumps(altered)),json.loads,'c'*64)
        for key in ['RELEASE_RECEIPT_ARTIFACT_ID','RELEASE_RECEIPT_ARTIFACT_DIGEST','RELEASE_RECEIPT_PRODUCER_JOB_ID','RELEASE_RECEIPT_RECEIPT_CONTEXT','RELEASE_RECEIPT_RECEIPT_MEMBERS']:
            changed = dict(env); changed.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError): self.v.receipt_handoff(changed,json.loads,'c'*64)

    def test_receipt_acquisition_rejects_replay_before_download_and_changed_after_metadata(self):
        self.assertTrue(callable(getattr(self.v,'receive_current_receipts',None)))
        spec=importlib.util.spec_from_file_location('retained_receipt_test_fixture',HELPER.with_name('test_release_recovery_027.py'))
        fixtures=importlib.util.module_from_spec(spec); spec.loader.exec_module(fixtures)
        fixtures.RetainedTests.setUpClass()
        fixture=fixtures.RetainedTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        record,publications,envelope,receipts=fixture.receipt_fixture()
        receipt=fixture.write_receipt_fixture(envelope,receipts)
        importer=types.ModuleType('receipt_import_test')
        source=HELPER.with_name('import_release_recovery_027.sh').read_text().split('# BEGIN RECOVERY_IMPORT_PYTHON\n',1)[1].split('# END RECOVERY_IMPORT_PYTHON',1)[0]
        exec(compile(source,'captured-fixture-importer','exec'),importer.__dict__)
        for fault in (None,'before-id','before-digest','before-url','before-size','old-attempt','after','bytes'):
            evidence=fixture.root/str(fault); evidence.mkdir()
            downloads=[]
            class Transport:
                authenticated=set()
                def get(self,url,path,limit):
                    if url.endswith('/attempts/2'): value=envelope['current_run']
                    elif '/jobs?' in url:
                        value=copy.deepcopy(envelope['current_jobs'])
                        if fault=='old-attempt': value['jobs'][0]['run_attempt']=1
                    else:
                        value=copy.deepcopy(envelope['metadata_before'])
                        if 'before' in path.name:
                            for key,bad in {'before-id':('id',1),'before-digest':('digest','sha256:'+'e'*64),
                                'before-url':('archive_download_url','https://attacker.invalid/zip'),
                                'before-size':('size_in_bytes',1048577)}.items():
                                if fault==key: value[bad[0]]=bad[1]
                        elif fault=='after': value['expired']=True
                    path.write_text(json.dumps(value))
                def receipt_archive(self,metadata,path):
                    downloads.append(metadata['id']); path.write_bytes(b'wrong' if fault=='bytes' else receipt.read_bytes())
            args=(fixture.v,importer,fixture.manifest,record,publications,Transport(),evidence,'fixture','fixture',
                  envelope['origin'],(envelope['context'],envelope['members'],envelope['upload_outputs']))
            if fault:
                with self.subTest(fault=fault), self.assertRaises(ValueError): self.v.receive_current_receipts(*args)
                self.assertEqual(downloads,[] if fault.startswith('before') or fault=='old-attempt' else [12000000000])
            else:
                result=self.v.receive_current_receipts(*args)
                self.assertEqual(result['receipts_verified'],2)

    def test_concurrent_draft_change_stops_before_upload(self):
        provider=FakeProvider({**self.expected,'id':123,'draft':True,'prerelease':False})
        lookups=0
        def lookup():
            nonlocal lookups
            lookups+=1
            return dict(provider.release,body='foreign' if lookups>1 else self.expected['body'])
        provider.lookup=lookup
        with self.assertRaises(ValueError): self.run_recovery(provider)
        self.assertEqual(provider.mutations,[])

    def test_final_public_readback_uses_canonical_bounded_modes_without_producer_results(self):
        root = HELPER.parent.parent/'governance/releases/v0.2.7'
        publications=json.loads((root/'PUBLICATION-IDENTITIES.json').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); evidence=directory/'evidence'; evidence.mkdir()
            calls=[]
            def command(argv,receipt,environment,timeout,bounded):
                calls.append(argv[-2:] if argv[-1]=='retained-readback' and argv[-2] in ('wasm','llm','sdk') else argv[-1:])
                self.assertEqual(timeout,1200); self.assertTrue(bounded)
                self.assertEqual(environment['RELEASE_OPERATION'],'recover-0.2.7-retained')
                self.assertNotIn('NODE_AUTH_TOKEN',environment)
                receipt.write_text('fixture external crypto diagnostics')
            importer=types.SimpleNamespace(command=command)
            with patch.dict(os.environ,{'RUNNER_TEMP':tmp,'RELEASE_OPERATION':'recover-0.2.7-retained'},clear=True):
                self.v.readback_publications(importer,publications,directory/'artifacts',directory,evidence)
            self.assertEqual(calls,[['wasm','retained-readback'],['llm','retained-readback'],['sdk','retained-readback'],['retained-readback']])
            self.assertFalse((directory/'exochain-recovery-receipts').exists())

    def test_unknown_create_and_publish_do_not_retry(self):
        for operation in ('create','publish'):
            release=None if operation=='create' else {**self.expected,'id':123,'draft':True,'prerelease':False}
            provider=FakeProvider(release,{} if operation=='create' else dict(self.assets))
            def uncertain(*args):
                provider.mutations.append(operation); raise OSError('unknown')
            setattr(provider,operation,uncertain)
            events=[]
            with self.assertRaises(OSError): self.v.recover(provider,self.expected,self.assets,lambda:None,events.append)
            self.assertEqual(provider.mutations,[operation])
            self.assertEqual([e['outcome'] for e in events],['intent','unknown'])

    def test_preflight_rejects_conflicting_draft_and_incomplete_public(self):
        self.assertTrue(callable(getattr(self.v, 'preflight', None)), 'read-only preflight absent')
        for draft, assets, body in [(True, {'foreign':b'x'},self.expected['body']), (True,{},'foreign'), (False,{},self.expected['body'])]:
            provider = FakeProvider({**self.expected,'id':123,'draft':draft,'prerelease':False,'body':body},assets)
            with self.assertRaises(ValueError): self.v.preflight(provider,self.expected,self.assets,lambda:None)
            self.assertEqual(provider.mutations, [])

    def test_retained_metadata_is_stable_and_names_only_the_35_public_assets(self):
        self.assertTrue(callable(getattr(self.v, 'retained_release_metadata', None)), 'retained metadata absent')
        root = HELPER.parent.parent / 'governance/releases/v0.2.7'
        manifest, publications, record = [json.loads((root / name).read_text()) for name in
            ['RECOVERY-MANIFEST.json','PUBLICATION-IDENTITIES.json','RETAINED-CUSTODY.json']]
        first = self.v.retained_release_metadata(manifest,publications,record,'a'*40,'refs/tags/v0.2.7-recover.3')
        self.assertEqual(first, self.v.retained_release_metadata(manifest,publications,record,'a'*40,'refs/tags/v0.2.7-recover.3'))
        receipt, metadata = first
        self.assertEqual(receipt['schema'],'exochain-release-retained-custody/v1')
        self.assertEqual(len(receipt['github_release_assets']),35)
        self.assertIn('RECOVERY-CUSTODY.json',receipt['github_release_assets'])
        self.assertFalse(any(name.endswith(('.whl','.tgz')) for name in receipt['github_release_assets']))
        self.assertNotIn('run_attempt', receipt['controller'])
        self.assertNotIn('checked_at', receipt)
        self.assertIn('expired',metadata['body'])

    def test_v2_public_custody_is_stable_and_discloses_loss(self):
        root = HELPER.parent.parent / 'governance/releases/v0.2.7'
        manifest, publications, record, policy = [json.loads((root / name).read_text()) for name in
            ['RECOVERY-MANIFEST.json','PUBLICATION-IDENTITIES.json','RETAINED-CUSTODY.json',
             'RETAINED-METADATA-POLICY.json']]
        first, body = self.v.retained_release_metadata(manifest, publications, record,
            'a'*40, 'refs/tags/v0.2.7-recover.3', policy=policy)
        second, second_body = self.v.retained_release_metadata(manifest, publications, record,
            'a'*40, 'refs/tags/v0.2.7-recover.3', policy=policy)
        disclosure = ('Selected original artifact metadata may be unavailable after its recorded expiry. '
            'Historical identity is authenticated from retained custody; it is not a claim of current metadata '
            'visibility or proof of deletion.')
        self.assertEqual(first, second)
        self.assertEqual(body, second_body)
        self.assertEqual(first['schema'], 'exochain-release-retained-custody/v2')
        self.assertEqual(first['metadata_policy_sha256'], 'bf9968454e1fb95fde2b2c435f61940a39cc25e6fb45a28ff9523a82f755c244')
        self.assertEqual(first['unavailable_originals'], policy['unavailable_originals'])
        self.assertEqual(first['original_metadata_disclosure'], disclosure)
        self.assertIn(disclosure, body['body'])
        self.assertIn(first['metadata_policy_sha256'], body['body'])
        self.assertEqual(len(first['github_release_assets']), 35)
        self.assertNotIn('original_observations', first)
        self.assertNotIn('observed_at', first)
        v1, v1_body = self.v.retained_release_metadata(manifest, publications, record,
            'a'*40, 'refs/tags/v0.2.7-recover.3')
        encoded = lambda value:(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
        assets={'RECOVERY-CUSTODY.json':encoded(first)}
        for release_body, existing_asset in ((v1_body['body'],encoded(first)),(body['body'],encoded(v1))):
            provider=FakeProvider({**body,'body':release_body,'id':123,'draft':True,'prerelease':False},
                {'RECOVERY-CUSTODY.json':existing_asset})
            with self.assertRaises(ValueError):
                self.v.preflight(provider,body,assets,lambda:None)
            self.assertEqual(provider.mutations,[])

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
