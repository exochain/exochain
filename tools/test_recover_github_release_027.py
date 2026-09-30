#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
import importlib.util
import io
import hashlib
import json
import copy
from email.message import Message
import os
from pathlib import Path
import tempfile
import unittest
import types
import zipfile
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
        self.release['published_at'] = '2026-09-30T21:00:00Z'


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

    def fixed_predecessor(self):
        root=HELPER.parent.parent/'governance/releases/v0.2.7'
        manifest,publications,record,policy=[json.loads((root/name).read_text()) for name in
            ('RECOVERY-MANIFEST.json','PUBLICATION-IDENTITIES.json','RETAINED-CUSTODY.json',
             'RETAINED-METADATA-POLICY.json')]
        return self.v.fixed_empty_predecessor(manifest,publications,record,policy)

    def test_read_only_preflight_never_creates_uploads_or_publishes(self):
        self.assertTrue(callable(getattr(self.v, 'preflight', None)), 'read-only preflight absent')
        for draft, assets in [(None, {}), (True, {}), (True, self.assets), (False, self.assets)]:
            release = None if draft is None else {**self.expected,'id':123,'draft':draft,'prerelease':False}
            provider = FakeProvider(release, dict(assets))
            result = self.v.preflight(provider,self.expected,self.assets,lambda:self.binds.append('bind'))
            self.assertFalse(result['mutation_attempted'])
            self.assertEqual(provider.mutations, [])

    def test_only_exact_empty_predecessor_can_pass_retained_preflight(self):
        predecessor = self.fixed_predecessor()
        provider = FakeProvider(dict(predecessor))
        result = self.v.preflight(provider,self.expected,self.assets,lambda:None,
                                  predecessor=predecessor)
        self.assertEqual(result['release_id'],400420101)
        self.assertEqual(result['existing_assets'],0)
        self.assertEqual(provider.mutations,[])
        for change in ({'id':400420102}, {'body':'foreign'}, {'updated_at':'later'},
                       {'draft':False}, {'prerelease':True}, {'published_at':'now'},
                       {'created_at':'later'}, {'immutable':True},
                       {'target_commitish':'foreign'}, {'node_id':'foreign'},
                       {'assets':[{'name':'foreign'}]}):
            with self.subTest(change=change):
                bad=FakeProvider({**predecessor,**change})
                with self.assertRaises(ValueError):
                    self.v.preflight(bad,self.expected,self.assets,lambda:None,
                                     predecessor=predecessor)
                self.assertEqual(bad.mutations,[])
        missing=FakeProvider({key:value for key,value in predecessor.items() if key!='published_at'})
        with self.assertRaises(ValueError):
            self.v.preflight(missing,self.expected,self.assets,lambda:None,predecessor=predecessor)
        nonempty=FakeProvider(dict(predecessor),{'archive.tar.gz':b'abc'})
        with self.assertRaises(ValueError):
            self.v.preflight(nonempty,self.expected,self.assets,lambda:None,predecessor=predecessor)
        for release in (None,{**self.expected,'id':400420102,'draft':True,'prerelease':False}):
            with self.subTest(release=release),self.assertRaises(ValueError):
                self.v.preflight(FakeProvider(release),self.expected,self.assets,lambda:None,
                                 predecessor=predecessor)
        with self.assertRaises(ValueError):
            self.v.preflight(FakeProvider(dict(predecessor)),self.expected,self.assets,lambda:None)

    def test_retained_transition_runs_after_all_gates_and_before_recovery(self):
        events=[]
        provider=FakeProvider()
        def transition():
            events.append('transition')
            provider.release={**self.expected,'id':400420101,'draft':True,'prerelease':False,
                'published_at':None,'assets':[]}
            return 400420101,True,lambda release:None
        self.v.complete_retained(provider,self.expected,self.assets,
            lambda:events.append('rebind'),lambda:events.append('receipts'),
            lambda:events.append('public'),prepare_gate=lambda:events.append('prepare'),
            acquire_gate=lambda:events.append('acquire'),final_gate=lambda:events.append('final'),
            transition_gate=transition)
        self.assertEqual(events[:6],['prepare','acquire','receipts','public','final','transition'])
        self.assertEqual(provider.mutations[0],'upload:archive.tar.gz')

    def test_transition_rechecks_exact_empty_draft_and_stops_on_drift(self):
        predecessor=self.fixed_predecessor()
        for change in ({'id':12},{'body':'foreign'},{'draft':False},{'assets':[{'name':'x'}]}):
            with self.subTest(change=change):
                provider=FakeProvider({**predecessor,**change})
                provider.update_body=lambda *args:provider.mutations.append('patch')
                with self.assertRaises(ValueError):
                    self.v.transition_empty_draft(provider,self.expected,predecessor,lambda:None,[] .append)
                self.assertEqual(provider.mutations,[])
        provider=FakeProvider(dict(predecessor),{'archive.tar.gz':b'abc'})
        provider.update_body=lambda *args:provider.mutations.append('patch')
        with self.assertRaises(ValueError):
            self.v.transition_empty_draft(provider,self.expected,predecessor,lambda:None,None)
        self.assertEqual(provider.mutations,[])

    def test_transition_unknown_or_postwrite_drift_never_uploads_or_retries(self):
        predecessor=self.fixed_predecessor()
        for fault in ('unknown','http-status','response','response-target','readback',
                      'readback-target','listed-assets'):
            with self.subTest(fault=fault):
                provider=FakeProvider(dict(predecessor))
                journal=[]
                def update(identifier,body):
                    provider.mutations.append('patch')
                    provider.release={**predecessor,'body':body}
                    if fault=='unknown': raise OSError('uncertain')
                    if fault=='http-status': raise self.v.GitHubUploadError(422,b'private',{},
                        operation='release body transition')
                    if fault=='response': return {**provider.release,'body':'wrong'}
                    if fault=='response-target': return {**provider.release,'target_commitish':'foreign'}
                    return dict(provider.release)
                provider.update_body=update
                original_lookup=provider.lookup
                def lookup():
                    result=original_lookup()
                    return {**result,'body':'foreign'} if fault=='readback' and provider.mutations else result
                def drift_lookup():
                    result=lookup()
                    return {**result,'target_commitish':'foreign'} if fault=='readback-target' and provider.mutations else result
                provider.lookup=drift_lookup
                original_assets=provider.list_assets
                def list_assets(identifier):
                    if fault=='listed-assets' and provider.mutations:
                        return [{'id':123,'name':'foreign','size':1,'state':'uploaded'}]
                    return original_assets(identifier)
                provider.list_assets=list_assets
                with self.assertRaises((ValueError,OSError)):
                    self.v.complete_retained(provider,self.expected,self.assets,lambda:None,
                        lambda:None,lambda:None,journal.append,prepare_gate=lambda:None,
                        acquire_gate=lambda:None,final_gate=lambda:None,
                        transition_gate=lambda:self.v.transition_empty_draft(provider,self.expected,
                            predecessor,lambda:None,journal.append))
                self.assertEqual(provider.mutations,['patch'])
                self.assertEqual(journal[-1]['outcome'],'unknown')
                if fault=='http-status':
                    self.assertEqual(journal[-1]['http_diagnostics']['http_status'],422)

    def test_actual_transition_acceptance_precedes_first_asset_upload(self):
        predecessor=self.fixed_predecessor()
        provider=FakeProvider(dict(predecessor))
        journal=[]
        gates=[]
        def update(identifier,body):
            provider.mutations.append('patch')
            provider.release={**predecessor,'body':body,'updated_at':'2026-09-30T20:42:00Z'}
            return dict(provider.release)
        provider.update_body=update
        self.v.complete_retained(provider,self.expected,self.assets,lambda:gates.append('rebind'),
            lambda:gates.append('receipt'),lambda:gates.append('public'),journal.append,
            prepare_gate=lambda:gates.append('prepare'),acquire_gate=lambda:gates.append('acquire'),
            final_gate=lambda:gates.append('final'),
            transition_gate=lambda:(self.v.transition_empty_draft(provider,self.expected,
                predecessor,lambda:gates.append('transition-rebind'),journal.append),True,
                lambda release:self.v.validate_continued_release(release,self.expected,predecessor)))
        self.assertEqual(provider.mutations[0],'patch')
        self.assertEqual(provider.mutations[1],'upload:archive.tar.gz')
        transition=[row['outcome'] for row in journal if row['operation']=='transition_controller_body']
        self.assertEqual(transition,['intent','response_received_not_yet_accepted','accepted'])
        self.assertLess(journal.index(next(row for row in journal if row['outcome']=='accepted')),
                        journal.index(next(row for row in journal if row['operation']=='upload_asset')))
        self.assertEqual(gates[:3],['prepare','acquire','receipt'])

    def test_stale_receipt_or_final_gate_never_enters_transition(self):
        for fault in ('prepare','acquire','receipt','public','final'):
            with self.subTest(fault=fault):
                events=[]
                provider=FakeProvider()
                def gate(label):
                    def run():
                        events.append(label)
                        if fault==label: raise ValueError(label)
                    return run
                with self.assertRaises(ValueError):
                    self.v.complete_retained(provider,self.expected,self.assets,lambda:None,
                        gate('receipt'),gate('public'),prepare_gate=gate('prepare'),
                        acquire_gate=gate('acquire'),final_gate=gate('final'),
                        transition_gate=lambda:events.append('transition'))
                self.assertNotIn('transition',events)
                self.assertEqual(provider.mutations,[])

    def test_recovery_guard_catches_nonbody_drift_after_transition_readback(self):
        predecessor=self.fixed_predecessor()
        provider=FakeProvider(dict(predecessor))
        journal=[]
        lookups=0
        def lookup():
            nonlocal lookups
            lookups+=1
            current=dict(provider.release)
            if lookups>=3: current['target_commitish']='foreign'
            return current
        provider.lookup=lookup
        def update(identifier,body):
            provider.mutations.append('patch')
            provider.release={**predecessor,'body':body,'updated_at':'2026-09-30T20:42:00Z'}
            return dict(provider.release)
        provider.update_body=update
        with self.assertRaises(ValueError):
            self.v.complete_retained(provider,self.expected,self.assets,lambda:None,
                lambda:None,lambda:None,journal.append,prepare_gate=lambda:None,
                acquire_gate=lambda:None,final_gate=lambda:None,
                transition_gate=lambda:(self.v.transition_empty_draft(provider,self.expected,
                    predecessor,lambda:None,journal.append),True,
                    lambda release:self.v.validate_continued_release(release,self.expected,predecessor)))
        self.assertEqual(provider.mutations,['patch'])

    def test_preflight_rejects_duplicate_same_tag_releases(self):
        predecessor=self.fixed_predecessor()
        client=self.v.GitHub('test-only-token',lambda raw,label:json.loads(raw))
        def listed(method,path,**kwargs):
            return [dict(predecessor),{**predecessor,'id':400420102}] if path.endswith('page=1') else []
        client.json=listed
        with self.assertRaises(ValueError):
            self.v.preflight(client,self.expected,self.assets,lambda:None,predecessor=predecessor)

    def test_body_transition_uses_only_exact_patch_payload_and_requires_http_200(self):
        client=self.v.GitHub('test-only-token',lambda raw,label:json.loads(raw))
        calls=[]
        def request(method,url,data=None,**kwargs):
            calls.append((method,url,data))
            return 200,json.dumps({**self.expected,'id':400420101,'draft':True,
                'prerelease':False,'published_at':None,'assets':[]}).encode(),{}
        client.request=request
        client.update_body(400420101,self.expected['body'])
        self.assertEqual(calls,[('PATCH','https://api.github.com/repos/exochain/exochain/releases/400420101',
                                 b'{"body":"fixed reviewed identity"}')])
        client.request=lambda *args,**kwargs:(201,b'{}',{})
        with self.assertRaises(ValueError): client.update_body(400420101,'body')

    def test_transition_route_does_not_create_if_pinned_draft_disappears(self):
        provider=FakeProvider()
        with self.assertRaises(ValueError):
            self.v.complete_retained(provider,self.expected,self.assets,lambda:None,
                lambda:None,lambda:None,prepare_gate=lambda:None,acquire_gate=lambda:None,
                final_gate=lambda:None,transition_gate=lambda:(400420101,True,lambda release:None))
        self.assertEqual(provider.mutations,[])

    def test_already_transitioned_same_draft_can_resume_verified_assets(self):
        provider=FakeProvider({**self.expected,'id':400420101,'draft':True,'prerelease':False},
                              {'archive.tar.gz':b'abc'})
        self.v.complete_retained(provider,self.expected,self.assets,lambda:None,
            lambda:None,lambda:None,prepare_gate=lambda:None,acquire_gate=lambda:None,
            final_gate=lambda:None,transition_gate=lambda:(400420101,False,lambda release:None))
        self.assertEqual(provider.mutations,['upload:RECOVERY-CUSTODY.json','publish'])

    def test_historical_failure_requires_exact_live_metadata_archive_and_member(self):
        root=HELPER.parent.parent/'governance/releases/v0.2.7'
        manifest,publications,record,policy=[json.loads((root/name).read_text()) for name in
            ('RECOVERY-MANIFEST.json','PUBLICATION-IDENTITIES.json','RETAINED-CUSTODY.json',
             'RETAINED-METADATA-POLICY.json')]
        context={'controller_sha':'b5871abd548d427cacab27e748b49e75897a5f66',
            'controller_ref':'refs/tags/v0.2.7-recover.4','run_id':36653810772,
            'run_attempt':1,'original_source':self.v.PRODUCT_SHA}
        rows=[{**context,'operation':operation,'outcome':outcome,
               **({'release_id':400420101,'asset':'first.cdx.json'} if operation=='upload_asset' else {})}
              for operation,outcome in (('create_draft','intent'),
                ('create_draft','response_received_not_yet_accepted'),
                ('upload_asset','intent'),('upload_asset','unknown'))]
        journal='\n'.join(json.dumps(row,separators=(',',':')) for row in rows)
        journal=(journal+' '*(1473-len(journal)-1)+'\n').encode()
        self.assertEqual(len(journal),1473)
        with io.BytesIO() as output:
            with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED) as bundle:
                info=zipfile.ZipInfo(self.v.HISTORICAL_MEMBER)
                info.compress_type=zipfile.ZIP_DEFLATED
                info.external_attr=0o100600<<16
                bundle.writestr(info,journal)
            raw=output.getvalue()
        self.assertLessEqual(len(raw),603)
        with io.BytesIO(raw) as output:
            with zipfile.ZipFile(output,'a') as bundle:
                bundle.comment=b'x'*(603-len(raw))
            archive=output.getvalue()
        self.assertEqual(len(archive),603)
        endpoint='https://api.github.com/repos/exochain/exochain/actions/artifacts/11124850978'
        metadata={'id':11124850978,'name':'exochain-027-retained-github-receipts',
            'size_in_bytes':603,'url':endpoint,'archive_download_url':endpoint+'/zip',
            'node_id':'MDg6QXJ0aWZhY3QxMTEyNDg1MDk3OA==',
            'digest':'sha256:'+hashlib.sha256(archive).hexdigest(),
            'created_at':'2026-09-30T20:41:02Z','updated_at':'2026-09-30T20:41:02Z',
            'expires_at':'2026-10-30T20:41:01Z','expired':False,
            'workflow_run':{'id':36653810772,'repository_id':1116455646,
                'head_repository_id':1116455646,
                'head_sha':context['controller_sha'],'head_branch':'v0.2.7-recover.4'}}
        spec=importlib.util.spec_from_file_location('historical_custody',HELPER.with_name('verify_release_recovery_027.py'))
        custody=importlib.util.module_from_spec(spec);spec.loader.exec_module(custody)
        importer=types.SimpleNamespace(API='https://api.github.com/repos/exochain/exochain/actions',
            JSON_LIMIT=4*1024*1024,utc_now=lambda:'2026-09-30T20:42:00Z')
        for fault in (None,'wrong-id','node','digest','head-repository','expired',
                      'after-drift','archive','member','late'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as tmp:
                evidence=Path(tmp)
                downloads=[]
                class Transport:
                    def get(self,url,path,limit):
                        self_outer.assertEqual(url,endpoint)
                        current=copy.deepcopy(metadata)
                        if fault=='wrong-id': current['id']=1
                        if fault=='node': current['node_id']='foreign'
                        if fault=='digest': current['digest']='sha256:'+'0'*64
                        if fault=='head-repository': current['workflow_run']['head_repository_id']=1
                        if fault=='expired': current['expired']=True
                        if fault=='after-drift' and 'after' in path.name: current['updated_at']='changed'
                        path.write_text(json.dumps(current))
                    def receipt_archive(self,current,path):
                        downloads.append(current['id'])
                        path.write_bytes(b'bad' if fault=='archive' else archive)
                self_outer=self
                clock=types.SimpleNamespace(**vars(importer))
                if fault=='late': clock.utc_now=lambda:'2026-10-30T20:41:01Z'
                member_hash=hashlib.sha256(journal).hexdigest()
                archive_hash=hashlib.sha256(archive).hexdigest()
                if fault=='member': member_hash='0'*64
                with patch.object(self.v,'HISTORICAL_ARCHIVE_SHA256',archive_hash),\
                     patch.object(self.v,'HISTORICAL_MEMBER_SHA256',member_hash):
                    args=(Transport(),custody,clock,evidence,manifest,publications,record,policy)
                    if fault:
                        with self.assertRaises(ValueError): self.v.authenticate_failed_predecessor(*args)
                    else:
                        self.assertEqual(self.v.authenticate_failed_predecessor(*args)['id'],400420101)
                self.assertEqual(downloads,[] if fault in ('wrong-id','node','digest',
                    'head-repository','expired','late') else [11124850978])

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

    def test_preliminary_handoff_precedes_acquisition_and_full_receipt(self):
        """Breaking the stage order would let invalid direct provenance reach public I/O."""
        for fault in ('authoritative-provenance', 'canonical-acquisition', 'full-receipt',
                      'public-readback', 'post-public-finalizer', None):
            with self.subTest(fault=fault):
                events = []
                provider = FakeProvider()
                def gate(name):
                    def check():
                        events.append(name)
                        if fault == name:
                            raise ValueError(name)
                    return check
                args = (provider, self.expected, self.assets, gate('rebind'),
                        gate('full-receipt'), gate('public-readback'))
                kwargs = {'prepare_gate':gate('authoritative-provenance'),
                          'acquire_gate':gate('canonical-acquisition'),
                          'final_gate':gate('post-public-finalizer')}
                if fault:
                    with self.assertRaises(ValueError):
                        self.v.complete_retained(*args, **kwargs)
                else:
                    self.v.complete_retained(*args, **kwargs)
                self.assertEqual(events[:3], ['authoritative-provenance',
                                               'canonical-acquisition', 'full-receipt'][:min(3, len(events))])
                if fault in ('authoritative-provenance', 'canonical-acquisition', 'full-receipt'):
                    self.assertEqual(provider.mutations, [])
                    self.assertNotIn('public-readback', events)
                if fault == 'post-public-finalizer':
                    self.assertEqual(provider.mutations, [])
                if fault is None:
                    self.assertLess(events.index('full-receipt'), events.index('public-readback'))
                    self.assertLess(events.index('public-readback'), events.index('post-public-finalizer'))
                    self.assertEqual(provider.mutations[0], 'create')

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

    def test_v2_preliminary_receipt_uses_actual_running_writer_and_no_origin(self):
        """Removing the running writer or replacing the direct handoff must fail before acquisition."""
        spec = importlib.util.spec_from_file_location('retained_writer_fixture',
            HELPER.with_name('test_release_recovery_027.py'))
        fixtures = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixtures)
        fixtures.RetainedTests.setUpClass()
        fixture = fixtures.RetainedTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        record, publications, policy, envelope, receipts = fixture.v2_receipt_fixture()
        fixture.write_receipt_fixture(envelope, receipts)
        envelope['origin'] = fixture.writer_origin_fixture(envelope)
        writer = envelope['current_jobs']['jobs'][1]
        evidence = fixture.root / 'writer-preliminary'; evidence.mkdir()
        events = []
        class Transport:
            authenticated = set()
            def get(self, url, path, limit):
                events.append('metadata-before')
                path.write_text(json.dumps(envelope['metadata_before']))
        importer = types.SimpleNamespace(API='https://api.github.com/repos/exochain/exochain/actions',
            JSON_LIMIT=4*1024*1024,
            fetch_run_jobs=lambda custody, transport, location, endpoints, total: (
                copy.deepcopy(envelope['current_run']), copy.deepcopy(envelope['current_jobs'])),
            utc_now=lambda:'2026-09-25T22:04:30Z',
            dump=lambda path, value:path.write_text(json.dumps(value)))
        env = {'RELEASE_OPERATION':'recover-0.2.7-retained-404', 'GITHUB_JOB':'retained-github',
               'GITHUB_RUN_ID':str(envelope['context']['run_id']),
               'GITHUB_RUN_ATTEMPT':str(envelope['context']['run_attempt']),
               'GITHUB_SHA':envelope['context']['controller_sha'],
               'GITHUB_REF':envelope['context']['controller_ref'],
               'EXPECTED_TAG_OBJECT_SHA':envelope['context']['controller_tag_object']}
        handoff = (envelope['context'], envelope['members'], envelope['upload_outputs'])
        with patch.dict(os.environ, env, clear=True):
            prepared = self.v.prepare_current_receipt(fixture.v, importer, fixture.manifest,
                record, policy, Transport(), evidence, handoff)
        self.assertEqual(prepared['schema'], 'exochain-retained-receipts-input-027/v2')
        self.assertEqual(prepared['observed_at'], '2026-09-25T22:04:30Z')
        self.assertNotIn('origin', prepared)
        self.assertNotIn('metadata_after', prepared)
        self.assertEqual(prepared['current_jobs']['jobs'][1]['id'], writer['id'])
        self.assertEqual(events, ['metadata-before'])
        for mutation in ('wrong-operation', 'missing-writer', 'wrong-run', 'wrong-policy'):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(envelope)
                changed_env = dict(env)
                if mutation == 'wrong-operation': changed_env['RELEASE_OPERATION'] = 'recover-0.2.7-retained'
                if mutation == 'missing-writer':
                    changed['current_jobs']['jobs'].pop(); changed['current_jobs']['total_count'] = 1
                if mutation == 'wrong-run': changed_env['GITHUB_RUN_ATTEMPT'] = '3'
                if mutation == 'wrong-policy':
                    changed_policy = dict(policy, operation='recover-0.2.7-retained')
                else:
                    changed_policy = policy
                importer.fetch_run_jobs = lambda custody, transport, location, endpoints, total: (
                    copy.deepcopy(changed['current_run']), copy.deepcopy(changed['current_jobs']))
                (evidence / mutation).mkdir()
                with patch.dict(os.environ, changed_env, clear=True), self.assertRaises(ValueError):
                    self.v.prepare_current_receipt(fixture.v, importer, fixture.manifest,
                        record, changed_policy, Transport(), evidence / mutation,
                        handoff)

    def test_v2_full_receipt_requires_fresh_post_download_time_and_writer_vector(self):
        """A preliminary pass cannot stand in for final ZIP and chronology acceptance."""
        spec = importlib.util.spec_from_file_location('retained_full_writer_fixture',
            HELPER.with_name('test_release_recovery_027.py'))
        fixtures = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixtures)
        fixtures.RetainedTests.setUpClass()
        fixture = fixtures.RetainedTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        record, publications, policy, envelope, receipts = fixture.v2_receipt_fixture()
        receipt = fixture.write_receipt_fixture(envelope, receipts)
        envelope['origin'] = fixture.writer_origin_fixture(envelope)
        prepared = {key:copy.deepcopy(value) for key,value in envelope.items()
                    if key not in ('origin', 'metadata_after')}
        prepared['observed_at'] = '2026-09-25T22:04:30Z'
        handoff = (envelope['context'], envelope['members'], envelope['upload_outputs'])
        events = []
        class Transport:
            authenticated = set()
            def get(self, url, path, limit):
                events.append(path.name)
                path.write_text(json.dumps(envelope['metadata_before']))
            def receipt_archive(self, metadata, path):
                events.append('receipt-zip')
                path.write_bytes(receipt.read_bytes())
        def current_jobs(custody, transport, location, endpoints, total):
            events.append(location.name)
            return copy.deepcopy(envelope['current_run']), copy.deepcopy(envelope['current_jobs'])
        def clock(*values):
            times = iter(values)
            def utc_now():
                value = next(times)
                events.append('clock:' + value)
                return value
            return utc_now
        importer = types.SimpleNamespace(API='https://api.github.com/repos/exochain/exochain/actions',
            JSON_LIMIT=4*1024*1024, fetch_run_jobs=current_jobs,
            utc_now=clock('2026-09-25T22:06:00Z', '2026-09-25T22:06:01Z'),
            dump=lambda path, value:path.write_text(json.dumps(value)))
        evidence = fixture.root/'full-writer'; evidence.mkdir()
        live = {'RELEASE_OPERATION':'recover-0.2.7-retained-404'}
        with patch.dict(os.environ, live):
            result = self.v.receive_current_receipts(fixture.v, importer, fixture.manifest, record,
                publications, Transport(), evidence, 'fixture', 'fixture', envelope['origin'], handoff,
                policy=policy, prepared=prepared)
        self.assertEqual(result['receipts_verified'], 2)
        self.assertEqual(result['original_vector'], fixture.v.verify_retained_origin(
            fixture.manifest, record, envelope['origin'], 'fixture', 'fixture', policy=policy)['original_vector'])
        completed = json.loads((evidence/'receipt-input.json').read_text())
        self.assertEqual(completed['observed_at'], '2026-09-25T22:06:01Z')
        self.assertEqual(prepared['observed_at'], '2026-09-25T22:04:30Z')
        self.assertEqual(events, ['current-attempt-before', 'receipt-metadata-before.json',
            'clock:2026-09-25T22:06:00Z', 'receipt-zip', 'receipt-metadata-after.json',
            'current-attempt-after', 'clock:2026-09-25T22:06:01Z'])
        for label, final_time in (
            ('earlier-final', '2026-09-25T22:04:29Z'),
            ('expired-at-equality', '2026-10-25T22:02:30Z'),
            ('expired-after-download', '2026-10-25T22:02:31Z')):
            with self.subTest(label=label):
                events.clear()
                importer.utc_now = clock('2026-09-25T22:06:00Z', final_time)
                other = fixture.root/label; other.mkdir()
                provider = FakeProvider()
                public_calls = []
                def receipt_gate():
                    self.v.receive_current_receipts(fixture.v, importer, fixture.manifest, record,
                        publications, Transport(), other, 'fixture', 'fixture', envelope['origin'],
                        handoff, policy=policy, prepared=prepared)
                with patch.dict(os.environ, live), self.assertRaises(ValueError):
                    self.v.complete_retained(provider, self.expected, self.assets, lambda:None,
                        receipt_gate, lambda:public_calls.append('public'))
                self.assertEqual(events, ['current-attempt-before', 'receipt-metadata-before.json',
                    'clock:2026-09-25T22:06:00Z', 'receipt-zip', 'receipt-metadata-after.json',
                    'current-attempt-after', 'clock:' + final_time])
                self.assertEqual(public_calls, [])
                self.assertEqual(provider.mutations, [])
        with patch.dict(os.environ, live), self.assertRaises(ValueError):
            self.v.receive_current_receipts(fixture.v, importer, fixture.manifest, record,
                publications, Transport(), fixture.root/'no-prepared', 'fixture', 'fixture',
                envelope['origin'], handoff, policy=policy)
        reads = []
        def writer_completed_after_zip(custody, transport, location, endpoints, total):
            reads.append(location)
            jobs = copy.deepcopy(envelope['current_jobs'])
            if len(reads) == 2:
                jobs['jobs'][1].update(status='completed',conclusion='success',
                                       completed_at='2026-09-25T22:05:59Z')
            return copy.deepcopy(envelope['current_run']), jobs
        importer.utc_now = lambda:'2026-09-25T22:06:00Z'
        importer.fetch_run_jobs = writer_completed_after_zip
        completed_writer = fixture.root/'completed-writer'; completed_writer.mkdir()
        with patch.dict(os.environ, live), self.assertRaises(ValueError):
            self.v.receive_current_receipts(fixture.v, importer, fixture.manifest, record,
                publications, Transport(), completed_writer, 'fixture', 'fixture', envelope['origin'],
                handoff, policy=policy, prepared=prepared)

    def test_rebind_stops_transition_before_each_mutation_and_final_readback(self):
        """A transition at any public write boundary preserves earlier IDs and stops the next write."""
        assets = {f'asset-{number:02d}':bytes([number]) for number in range(35)}
        expected_mutations = ['create'] + [f'upload:{name}' for name in assets] + ['publish']
        for failing_rebind in range(1, 41):
            with self.subTest(rebind=failing_rebind):
                provider = FakeProvider()
                journal = []
                checks = []
                def rebind():
                    checks.append('rebind')
                    if len(checks) == failing_rebind:
                        raise ValueError('original availability changed')
                with self.assertRaises(ValueError):
                    self.v.recover(provider, self.expected, assets, rebind, journal.append)
                self.assertEqual(len(checks), failing_rebind)
                self.assertEqual(provider.mutations, expected_mutations[:max(0, failing_rebind-2)])
                self.assertEqual([entry['operation'] for entry in journal if entry['outcome'] == 'intent'],
                                 ['create_draft' if item == 'create' else
                                  'publish_release' if item == 'publish' else 'upload_asset'
                                  for item in provider.mutations])
                self.assertFalse(any(entry.get('operation') == 'final_readback' for entry in journal))

    def test_publish_is_followed_by_fresh_rebind_before_final_public_readback(self):
        """A status transition during publication must be caught before final public reads."""
        events = []
        provider = FakeProvider()
        lookup, publish = provider.lookup, provider.publish
        def observed_lookup():
            events.append('lookup')
            return lookup()
        def observed_publish(identifier):
            events.append('publish')
            return publish(identifier)
        provider.lookup = observed_lookup
        provider.publish = observed_publish
        self.v.recover(provider,self.expected,self.assets,lambda:events.append('rebind'))
        published = events.index('publish')
        self.assertEqual(events[published+1:published+3], ['rebind','lookup'])
        self.assertEqual(events[-1], 'rebind')

    def test_real_rebind_rejects_original_vector_and_retained_control_changes(self):
        """The real finalizer checks all nine observations and both retained controls."""
        spec = importlib.util.spec_from_file_location('retained_rebind_fixture',
            HELPER.with_name('test_release_recovery_027.py'))
        fixtures = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixtures)
        fixtures.RetainedTests.setUpClass()
        fixture = fixtures.RetainedTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        record, publications, policy, envelope, receipts = fixture.v2_receipt_fixture()
        initial = fixture.writer_origin_fixture(envelope)
        observer = initial['observations']['observer']
        importer = types.ModuleType('real_rebind_importer')
        source = HELPER.with_name('import_release_recovery_027.sh').read_text().split(
            '# BEGIN RECOVERY_IMPORT_PYTHON\n',1)[1].split('# END RECOVERY_IMPORT_PYTHON',1)[0]
        exec(compile(source,'captured-rebind-importer','exec'),importer.__dict__)
        retained = copy.deepcopy(initial['controls_after'])
        retained['observed_at'] = '2026-09-25T22:07:00Z'
        observed = copy.deepcopy(initial['observations']['after'])
        observed['observed_at'] = '2026-09-25T22:06:40Z'
        for index, item in enumerate(observed['records']):
            item['request_started_at'] = f'2026-09-25T22:06:{index*2:02d}Z'
            item['request_finished_at'] = f'2026-09-25T22:06:{index*2+1:02d}Z'
        events = []
        importer.fetch_original_observation_pass = lambda *args, **kwargs:copy.deepcopy(observed)
        importer.fetch_retained_controls = lambda *args, **kwargs:copy.deepcopy(retained)
        importer.fetch_run_jobs = lambda *args, **kwargs:(events.append('diagnostic-run-jobs-recheck') or ({},{}))
        transport = types.SimpleNamespace(endpoints={'run':'original-run','jobs':['original-jobs'],
            'retaining_run':'retaining-run','retaining_jobs':['retaining-jobs']})
        original_files = fixture.v.verify_files
        fixture.v.verify_files = lambda *args:events.append('files')
        self.addCleanup(setattr, fixture.v, 'verify_files', original_files)
        def execute(label):
            location = fixture.root/label; location.mkdir()
            return self.v.check_retained_rebind(fixture.v, importer, fixture.manifest, record,
                policy, transport, location, 'fixture', 'fixture', initial, observer,
                fixture.root, lambda:events.append('source'))
        execute('valid')
        self.assertEqual(events[:2], ['source', 'files'])
        historical = fixture.v.read_historical_custody(fixture.manifest, record, 'fixture')['metadata']
        def unavailable(artifact_id):
            item = next(value for value in observed['records'] if value['id'] == artifact_id)
            item.update(status=404,variant='unavailable_404')
            item.pop('metadata',None)
        def present(artifact_id):
            item = next(value for value in observed['records'] if value['id'] == artifact_id)
            metadata = next(value for value in historical if value['id'] == artifact_id)
            item.update(status=200,variant='present',metadata=dict(metadata,expired=True))
        for label, mutate in (
            ('eligible-200-to-404', lambda: unavailable(10517854663)),
            ('eligible-404-to-200', lambda: present(10518086890)),
            ('fifth-404', lambda: unavailable(10517981432)),
            ('retained-payload-expired', lambda: retained['retained_metadata'][0].update(expired=True)),
            ('retained-custody-absent', lambda: retained['retained_metadata'].pop()),
            ('retained-expiry-equality', lambda: retained.update(observed_at=record['payload']['metadata']['expires_at']))):
            prior_observed, prior_retained = copy.deepcopy(observed), copy.deepcopy(retained)
            mutate()
            with self.subTest(label=label), self.assertRaises(ValueError): execute(label)
            self.assertIn('diagnostic-run-jobs-recheck', events)
            self.assertTrue((fixture.root/label/'diagnostic-result.json').exists())
            observed.clear(); observed.update(prior_observed)
            retained.clear(); retained.update(prior_retained)
        importer.fetch_run_jobs = lambda *args, **kwargs: (_ for _ in ()).throw(OSError('fixture diagnostic unavailable'))
        unavailable(10517854663)
        with self.assertRaises(ValueError): execute('diagnostic-failed')
        self.assertEqual(json.loads((fixture.root/'diagnostic-failed'/'diagnostic-result.json').read_text())['status'],
                         'failed')

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

    def test_upload_sends_raw_bytes_but_requests_json_metadata(self):
        client = self.v.GitHub("test-only-token", lambda b, label:json.loads(b))
        calls = []
        class Transport:
            def open(self, request, timeout):
                calls.append(request)
                result = io.BytesIO(b'{"name":"asset +.bin","size":3}')
                result.status = 201
                result.headers = {"Content-Type":"application/json"}
                return result
        client.transport = Transport()
        client.upload(123, "asset +.bin", b"\x00\xff\x01")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].full_url, "https://uploads.github.com/repos/exochain/exochain/releases/123/assets?name=asset%20%2B.bin")
        self.assertEqual(calls[0].method, "POST")
        self.assertEqual(calls[0].data, b"\x00\xff\x01")
        self.assertEqual(calls[0].get_header("Content-type"), "application/octet-stream")
        self.assertEqual(calls[0].get_header("Accept"), "application/vnd.github+json")

    def test_http_upload_failure_keeps_safe_diagnostics_and_stops_before_next_write(self):
        for status in (403, 406, 415, 422, 429, 500, 502):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                client = self.v.GitHub("test-only-token", lambda b, label:json.loads(b))
                calls = []
                release = {**self.expected, "id":123, "draft":True, "prerelease":False}
                class Transport:
                    def open(inner, request, timeout):
                        calls.append(request)
                        if request.method == "POST":
                            headers = Message()
                            headers["X-GitHub-Request-Id"] = "AB12:CD34:EF56:7890"
                            headers["Content-Type"] = "application/json; charset=utf-8"
                            headers["Set-Cookie"] = "private-cookie-fixture"
                            raise self.v.urllib.error.HTTPError(request.full_url, status,
                                "private-reason-fixture", headers, io.BytesIO(b"provider-private-response"))
                        self.assertEqual(request.method, "GET")
                        body = ([release] if request.full_url.endswith("/releases?per_page=100&page=1") else [])
                        result = io.BytesIO(json.dumps(body).encode())
                        result.status = 200
                        result.headers = {}
                        return result
                client.transport = Transport()
                path = Path(tmp) / "journal.jsonl"
                with self.assertRaises(ValueError) as error:
                    self.v.recover(client, self.expected, self.assets, lambda:None, self.v.Journal(path))
                events = [json.loads(row) for row in path.read_text().splitlines()]
                self.assertEqual([event["outcome"] for event in events], ["intent", "unknown"])
                self.assertEqual(events[1].get("http_diagnostics"), {
                    "http_status":status, "github_request_id":"AB12:CD34:EF56:7890",
                    "response_content_type":"application/json", "response_size":25,
                    "response_sha256":"83aadd2b184b91b53c50dec327824a5a8f497708c0cafeaf27177bb89f1929e1"})
                self.assertIn("HTTP " + str(status), str(error.exception))
                self.assertEqual([request.method for request in calls if request.method != "GET"], ["POST"])
                self.assertTrue(calls[-1].full_url.endswith("/assets?name=archive.tar.gz"))
                for private in ("test-only-token", "private-cookie-fixture", "private-reason-fixture", "provider-private-response"):
                    self.assertNotIn(private, path.read_text() + str(error.exception))

    def test_upload_error_diagnostics_reject_untrusted_header_text(self):
        for request_id in ("Bearer test-only-token", "ABCD\nforged", "A" * 129, "", None):
            with self.subTest(request_id=request_id):
                client = self.v.GitHub("test-only-token", lambda b, label:json.loads(b))
                class Transport:
                    def open(inner, request, timeout):
                        result = io.BytesIO(b"provider-private-response")
                        result.status = 415
                        result.headers = {"X-GitHub-Request-Id":request_id,
                                          "Content-Type":"application/x-private-test-only-token"}
                        return result
                client.transport = Transport()
                with self.assertRaises(ValueError) as error:
                    client.upload(123, "asset", b"abc")
                diagnostics = getattr(error.exception, "diagnostics", {})
                self.assertEqual(diagnostics.get("http_status"), 415)
                self.assertIsNone(diagnostics.get("github_request_id"))
                self.assertEqual(diagnostics.get("response_content_type"), "other")
                self.assertNotIn("test-only-token", str(error.exception))
                self.assertNotIn("provider-private-response", str(error.exception))

    def test_oversized_upload_error_preserves_status_and_labels_only_a_bounded_prefix(self):
        client = self.v.GitHub("test-only-token", lambda b, label:json.loads(b))
        release = {**self.expected, "id":123, "draft":True, "prerelease":False}
        calls, reads = [], []
        class BoundedErrorBody(io.BytesIO):
            def read(inner, bound=-1):
                reads.append(bound)
                self.assertEqual(bound, 4 * 1024 * 1024 + 1)
                return super().read(bound)
        class Transport:
            def open(inner, request, timeout):
                calls.append(request)
                if request.method == "POST":
                    headers = Message()
                    headers["X-GitHub-Request-Id"] = "AB12:CD34:EF56:7890"
                    headers["Content-Type"] = "text/html"
                    raise self.v.urllib.error.HTTPError(request.full_url, 502, "private-reason",
                        headers, BoundedErrorBody(b"x" * (4 * 1024 * 1024 + 2)))
                self.assertEqual(request.method, "GET")
                body = [release] if request.full_url.endswith("/releases?per_page=100&page=1") else []
                result = io.BytesIO(json.dumps(body).encode())
                result.status = 200
                result.headers = {}
                return result
        client.transport = Transport()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.jsonl"
            with self.assertRaises(ValueError):
                self.v.recover(client, self.expected, self.assets, lambda:None, self.v.Journal(path))
            events = [json.loads(row) for row in path.read_text().splitlines()]
        diagnostics = events[1].get("http_diagnostics", {})
        self.assertEqual(diagnostics.get("http_status"), 502)
        self.assertEqual(diagnostics.get("github_request_id"), "AB12:CD34:EF56:7890")
        self.assertEqual(diagnostics.get("response_content_type"), "text/html")
        self.assertIs(diagnostics.get("response_truncated"), True)
        self.assertIsNone(diagnostics.get("response_size"))
        self.assertIsNone(diagnostics.get("response_sha256"))
        self.assertEqual(diagnostics.get("response_prefix_size"), 4194305)
        self.assertEqual(diagnostics.get("response_prefix_sha256"),
                         "8d3d3c04baadfd31cbebf771836900097b5f36cc142b74e40747c7b372beab8b")
        self.assertEqual(reads, [4194305])
        self.assertEqual([event["outcome"] for event in events], ["intent", "unknown"])
        self.assertEqual([request.method for request in calls if request.method != "GET"], ["POST"])

    def test_download_still_requests_binary_response_after_upload_header_split(self):
        client = self.v.GitHub("test-only-token", lambda b, label:json.loads(b))
        calls = []
        class Transport:
            def open(inner, request, timeout):
                calls.append(request)
                result = io.BytesIO(b"abc")
                result.status = 200
                result.headers = {}
                return result
        client.transport = Transport()
        self.assertEqual(client.download({"id":12, "size":3}), b"abc")
        self.assertEqual(calls[0].get_header("Accept"), "application/octet-stream")
        self.assertIsNone(calls[0].get_header("Content-type"))


if __name__ == "__main__": unittest.main()
