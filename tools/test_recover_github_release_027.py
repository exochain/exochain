#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
import importlib.util
import io
import hashlib
import json
import copy
from datetime import datetime, timezone
from email.message import Message
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
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
    def publish(self, release_id, body=None):
        self.mutations.append("publish")
        self.release["draft"] = False
        self.release['published_at'] = '2026-09-30T21:00:00Z'


class GithubRecoveryTests(unittest.TestCase):
    def budget_fixture(self, remaining=1000, limit=1000):
        self.assertTrue(hasattr(self.v, 'ProviderBudget'), 'preserved writer lacks bounded provider admission')
        clock = types.SimpleNamespace(now=1790812800.0, mono=0.0, sleeps=[], calls=[], remaining=remaining,
                                      reset=1790816400, limit=limit)
        def sleep(seconds):
            self.assertLessEqual(seconds,60)
            clock.sleeps.append(seconds); clock.now+=seconds; clock.mono+=seconds
        budget=self.v.ProviderBudget(wall=lambda:clock.now, monotonic=lambda:clock.mono, sleeper=sleep)
        client=self.v.GitHub('SECRET_SENTINEL',lambda raw,label:json.loads(raw),budget=budget)
        def headers():
            return {'X-RateLimit-Limit':str(clock.limit),'X-RateLimit-Remaining':str(clock.remaining),
                    'X-RateLimit-Used':str(clock.limit-clock.remaining),'X-RateLimit-Reset':str(clock.reset),
                    'X-RateLimit-Resource':'core'}
        def response(request,timeout):
            if clock.now>=clock.reset:
                clock.remaining=clock.limit;clock.reset=int(clock.now)+3600
            admission=request.full_url=='https://api.github.com/rate_limit'
            if not admission:clock.remaining-=1
            clock.calls.append((request.method,request.full_url,clock.mono))
            result=io.BytesIO(b'{"resources":{"core":{"remaining":999999}}}')
            result.status=200;result.headers=headers()
            return result
        client.transport=types.SimpleNamespace(open=response)
        return budget,client,clock,headers

    def test_shared_budget_crosses_default_primary_reset_without_retry(self):
        self.shared_budget_case(1000,1)
        self.shared_budget_case(0,2)

    def shared_budget_case(self,remaining,waits):
        budget,client,clock,headers=self.budget_fixture(remaining)
        with tempfile.TemporaryDirectory() as tmp:
            importer=types.ModuleType('budget_importer')
            source=HELPER.with_name('import_release_recovery_027.sh').read_text().split(
                '# BEGIN RECOVERY_IMPORT_PYTHON\n',1)[1].split('# END RECOVERY_IMPORT_PYTHON',1)[0]
            exec(compile(source,'budget-importer','exec'),importer.__dict__)
            manifest,_,record,policy,preserved=self.preserved_inputs()
            transport=importer.Transport(Path(tmp),'SECRET_SENTINEL',manifest,record,
                                         policy=policy,preserved=preserved,budget=budget)
            def curl(argv,**kwargs):
                if clock.now>=clock.reset:
                    clock.remaining=clock.limit;clock.reset=int(clock.now)+3600
                clock.remaining-=1
                clock.calls.append(('GET',argv[-1],clock.mono))
                Path(argv[argv.index('--output')+1]).write_bytes(b'{}')
                raw='HTTP/2 200\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers().items())+'\r\n'
                Path(argv[argv.index('--dump-header')+1]).write_bytes(raw.encode())
                return subprocess.CompletedProcess(argv,0,b'200',b'')
            with patch.object(importer.subprocess,'run',side_effect=curl):
                for n in range(1325):
                    if n%70==0:budget.admit(client,'test-phase')
                    if n%2:transport.get(transport.endpoints['run'],Path(tmp)/f'{n}.json',1024)
                    else:client.request('GET',self.v.API+'/releases')
            self.assertEqual(len([c for c in clock.calls if not c[1].endswith('/rate_limit')]),1325)
            self.assertEqual(budget.waits,waits)
            self.assertGreaterEqual(clock.now,1790816400)
            self.assertTrue(all(b[2]-a[2]>=1 for a,b in zip(clock.calls,clock.calls[1:])))

    def test_budget_blocks_129th_request_and_missing_allowance(self):
        budget,client,clock,_=self.budget_fixture(limit=15000,remaining=15000)
        budget.admit(client,'bounded')
        for _ in range(128):client.request('GET',self.v.API+'/releases')
        count=len(clock.calls)
        with self.assertRaisesRegex(ValueError,'phase'):client.request('GET',self.v.API+'/releases')
        self.assertEqual(len(clock.calls),count)
        budget,client,clock,_=self.budget_fixture()
        def bad(request,timeout):
            result=io.BytesIO(b'{}');result.status=200;result.headers={};return result
        client.transport.open=bad
        with self.assertRaisesRegex(ValueError,'rate'):budget.admit(client,'missing')

    def test_writer_public_gate_requires_both_native_crypto_results(self):
        self.assertTrue(hasattr(self.v,'writer_public_checks'), 'writer public gate omits independent native crypto')
        spec=importlib.util.spec_from_file_location('native_writer_tests',HELPER.with_name('test_import_release_recovery_027.py'))
        tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(tests)
        tests.ImportTests.setUpClass()
        fixture=tests.ImportTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        _,proof=fixture.attestation()
        for reject in (None,'native-x86_64','native-aarch64'):
            with self.subTest(reject=reject), tempfile.TemporaryDirectory() as tmp:
                evidence=Path(tmp);calls=[];provider=FakeProvider({**self.expected,'id':123,'draft':True,'prerelease':False})
                def process(argv,**kwargs):
                    self.assertEqual(argv[:3],['/usr/bin/gh','attestation','verify'])
                    self.assertEqual(kwargs['env']['GH_TOKEN'],'configured-test-token')
                    lane=Path(argv[3]).parent.name;calls.append(lane)
                    return subprocess.CompletedProcess(argv,1 if lane==reject else 0,json.dumps(proof).encode(),b'')
                def gate():
                    self.v.writer_public_checks(fixture.i,fixture.custody,fixture.manifest,{},evidence,
                        evidence,evidence,'python','node','configured-test-token',transport=None,preserved=True)
                with patch.object(fixture.i.subprocess,'run',side_effect=process), \
                     patch.object(fixture.i,'validate_packages',return_value={}), \
                     patch.object(fixture.i,'fetch_rust',return_value={}), \
                     patch.object(self.v,'readback_publications',return_value=None):
                    if reject:
                        with self.assertRaisesRegex(ValueError,'cryptographic'):
                            self.v.complete_retained(provider,self.expected,self.assets,lambda:None,lambda:None,gate)
                        self.assertEqual(provider.mutations,[])
                    else:
                        self.v.complete_retained(provider,self.expected,self.assets,lambda:None,lambda:None,gate)
                        self.assertEqual(calls,['native-x86_64','native-aarch64'])
                        for lane in calls:
                            self.assertEqual(json.loads((evidence/(lane+'-verified-attestations.json')).read_text()),proof)
                outcome=json.loads((evidence/'writer-native-outcome.json').read_text())
                self.assertEqual(outcome['independent_crypto_verification_succeeded'],reject is None)

    def test_budget_depleted_enterprise_regional_and_concurrent_allowance(self):
        for remaining,limit,waits in ((0,1000,1),(127,1000,1),(128,1000,0),(15000,15000,0)):
            with self.subTest(remaining=remaining):
                budget,client,clock,_=self.budget_fixture(remaining,limit)
                self.assertEqual(budget.admit(client,'allowance'),bool(waits))
                self.assertEqual(budget.waits,waits)
                client.request('GET',self.v.API+'/releases')
        budget,client,clock,_=self.budget_fixture()
        budget.admit(client,'regional')
        clock.remaining=200
        client.request('GET',self.v.API+'/releases')
        self.assertEqual(budget.remaining,199)
        clock.remaining=900
        client.request('GET',self.v.API+'/releases')
        self.assertEqual(budget.remaining,198)
        clock.remaining=1
        client.request('GET',self.v.API+'/releases')
        count=len(clock.calls)
        with self.assertRaisesRegex(ValueError,'allowance'):client.request('GET',self.v.API+'/releases')
        self.assertEqual(len(clock.calls),count)

    def test_budget_malformed_headers_fail_without_exposing_provider_data(self):
        for field,value in [('X-RateLimit-Limit',None),('X-RateLimit-Limit','-1'),
                ('X-RateLimit-Remaining','SECRET_SENTINEL'),('X-RateLimit-Remaining','1001'),
                ('X-RateLimit-Used','2'),('X-RateLimit-Reset','1790812799'),
                ('X-RateLimit-Reset','1790816461'),('X-RateLimit-Resource','search'),
                ('duplicate','X-RateLimit-Remaining')]:
            with self.subTest(field=field,value=value):
                budget,client,clock,headers=self.budget_fixture()
                def response(request,timeout):
                    header=Message()
                    for key,original in headers().items():
                        if field!=key or value is not None:header[key]=value if field==key else original
                    if field=='duplicate':header[value]='1000'
                    result=io.BytesIO(b'SECRET_SENTINEL');result.status=200;result.headers=header;return result
                client.transport.open=response
                with self.assertRaises(ValueError) as error:budget.admit(client,'malformed')
                self.assertNotIn('SECRET_SENTINEL',str(error.exception))
                self.assertTrue(budget.stopped)

    def test_budget_wait_deadline_expiry_clock_and_count_bounds(self):
        for fault in ('expiry','deadline','third','cumulative','wall-backward','mono-backward','clock-jump'):
            with self.subTest(fault=fault):
                budget,client,clock,_=self.budget_fixture(0)
                if fault=='expiry':budget.dependency(clock.now+100)
                elif fault=='deadline':budget.deadline=100
                elif fault=='third':budget.waits=2
                elif fault=='cumulative':budget.wait_seconds=7320
                elif fault=='wall-backward':clock.now-=1
                elif fault=='mono-backward':clock.mono-=1
                elif fault=='clock-jump':clock.now+=100
                with self.assertRaises(ValueError):budget.admit(client,'bounded-wait')
                self.assertFalse(clock.sleeps)

    def test_budget_paces_mutation_before_fresh_gate_and_rejects_auth_extensions(self):
        budget,client,clock,_=self.budget_fixture()
        budget.admit(client,'first')
        client.request('PATCH',self.v.API+'/releases/400420101',b'{}')
        before=len(clock.calls)
        with self.assertRaisesRegex(ValueError,'spacing'):
            client.request('PATCH',self.v.API+'/releases/400420101',b'{}')
        self.assertEqual(len(clock.calls),before)
        budget.admit(client,'second')
        fresh=clock.mono
        sleeps=len(clock.sleeps)
        client.request('PATCH',self.v.API+'/releases/400420101',b'{}')
        self.assertEqual(clock.mono,fresh);self.assertEqual(len(clock.sleeps),sleeps)
        for method,url in [('POST','https://api.github.com/rate_limit'),
                ('GET','https://api.github.com/rate_limit?x=1'),('GET','https://api.github.com/orgs/exochain')]:
            with self.assertRaisesRegex(ValueError,'credential'):client.request(method,url)

    def test_production_retained_main_public_gate_rejects_native_crypto_before_writes(self):
        h=self.preserved_writer_fixture()
        context=h.envelope['context']
        budget,client,clock,_=self.budget_fixture()
        # Epoch matches the authenticated October fixture; no real clock/provider I/O.
        clock.now=1790892000.;clock.reset=int(clock.now)+3600
        budget.last_wall=clock.now
        env={'RELEASE_OPERATION':'recover-0.2.7-preserved','RELEASE_VERSION':'0.2.7',
            'GITHUB_JOB':'retained-github','RELEASE_WORKFLOW_DRY_RUN':'false','GITHUB_ACTIONS':'true',
            'GITHUB_EVENT_NAME':'workflow_dispatch','RUNNER_ENVIRONMENT':'github-hosted',
            'GITHUB_SHA':context['controller_sha'],'GITHUB_REF':context['controller_ref'],
            'RUNNER_TEMP':str(h.fixture.root),'GITHUB_WORKSPACE':str(h.workspace),
            'RELEASE_GITHUB_TOKEN':'fixture-token','RELEASE_PYTHON':'python','RELEASE_NODE':'node'}
        calls=[]
        def source(argv,**kwargs):return (h.workspace/argv[-1].split(':',1)[1]).read_bytes()
        def process(argv,**kwargs):
            if argv[:3]==['/usr/bin/gh','attestation','verify']:
                calls.append(argv);return subprocess.CompletedProcess(argv,1,b'[]',b'')
            if 'show' in argv:return subprocess.CompletedProcess(argv,0,source(argv),b'')
            return subprocess.CompletedProcess(argv,0,b'',b'')
        def stages(provider,expected,assets,rebind,receipt_gate,public_gate,*args,**kwargs):
            importer=dict(zip(public_gate.__code__.co_freevars,(cell.cell_contents for cell in public_gate.__closure__)))['importer']
            with patch.object(importer,'validate_packages',return_value={}):public_gate()
        with patch.dict(os.environ,env,clear=True),patch.object(self.v,'ProviderBudget',return_value=budget), \
             patch.object(self.v,'GitHub',return_value=client),patch.object(self.v.subprocess,'check_output',side_effect=source), \
             patch.object(self.v.subprocess,'run',side_effect=process),patch.object(self.v,'complete_retained',side_effect=stages), \
             patch.object(self.v,'receipt_handoff',return_value=(context,h.envelope['members'],h.envelope['upload_outputs'])):
            with self.assertRaisesRegex(ValueError,'cryptographic'):self.v.retained_main()
        self.assertEqual(len(calls),1)
        self.assertTrue(all(method=='GET' for method,_,_ in clock.calls))
        self.assertFalse(list(h.fixture.root.glob('exochain-retained-github.*/evidence/release-result.json')))

    def test_budget_mutation_failures_are_single_attempt_unknown_and_diagnostic(self):
        for operation in ('upload','body','publish'):
            for fault in (403,429,500,'timeout','truncated','malformed'):
                with self.subTest(operation=operation,fault=fault):
                    budget,client,clock,headers=self.budget_fixture()
                    original=client.transport.open
                    release=(self.fixed_predecessor() if operation=='body' else
                        {**self.expected,'id':123,'draft':True,'prerelease':False})
                    mutations=[];journal=[]
                    def response(request,timeout):
                        if request.full_url==self.v.RATE_URL:return original(request,timeout)
                        clock.remaining-=1
                        if request.method!='GET':
                            mutations.append(request.method)
                            if fault=='timeout':raise TimeoutError('private timeout detail')
                            status=fault if type(fault) is int else (201 if operation=='upload' else 200)
                            raw=b'x'*(4*1024*1024+1) if fault=='truncated' else b'SECRET_SENTINEL'
                        else:
                            status=200
                            raw=json.dumps([release] if request.full_url.endswith('/releases?per_page=100&page=1') else []).encode()
                        result=io.BytesIO(raw);result.status=status;result.headers=headers();return result
                    client.transport.open=response
                    rebind=lambda:budget.admit(client,'mutation')
                    with self.assertRaises((ValueError,OSError)):
                        if operation=='body':
                            expected={**self.expected,'body':'corrected-controller-body'}
                            self.v.transition_empty_draft(client,expected,release,rebind,journal.append)
                        else:
                            self.v.recover(client,self.expected,{'file':b'bytes'} if operation=='upload' else {},rebind,journal.append)
                    self.assertEqual(len(mutations),1)
                    self.assertEqual([event['outcome'] for event in journal],['intent','unknown'])
                    self.assertNotIn('SECRET_SENTINEL',json.dumps(journal))
                    if type(fault) is int:
                        self.assertEqual(journal[-1].get('http_diagnostics',{}).get('http_status'),fault)

    def test_slow_stream_deadline_stops_unknown_mutation_and_restores_alarm(self):
        budget,client,clock,headers=self.budget_fixture()
        original=client.transport.open
        release={**self.expected,'id':123,'draft':True,'prerelease':False}
        mutations=[];journal=[]
        class SlowBody(io.BytesIO):
            def read(self,*args):
                time.sleep(0.2)
                return super().read(*args)
        def response(request,timeout):
            if request.full_url==self.v.RATE_URL:return original(request,timeout)
            clock.remaining-=1
            if request.method=='POST':
                mutations.append('upload')
                result=SlowBody(b'{"name":"file","size":5}')
                result.status=201
            else:
                result=io.BytesIO(json.dumps([release] if request.full_url.endswith('/releases?per_page=100&page=1') else []).encode())
                result.status=200
                if budget.phase==2 and '/assets?' in request.full_url and request.full_url.endswith('page=2'):
                    budget.deadline=clock.mono+0.03
            result.headers=headers();return result
        client.transport.open=response
        saved_handler=signal.getsignal(signal.SIGALRM)
        saved_timer=signal.getitimer(signal.ITIMER_REAL)
        handler=lambda signum,frame:None
        signal.signal(signal.SIGALRM,handler)
        signal.setitimer(signal.ITIMER_REAL,10)
        try:
            with self.assertRaises(ValueError):
                self.v.recover(client,self.expected,{'file':b'bytes'},lambda:budget.admit(client,'stream'),journal.append)
            self.assertEqual(mutations,['upload'])
            self.assertEqual([e['outcome'] for e in journal],['intent','unknown'])
            self.assertIs(signal.getsignal(signal.SIGALRM),handler)
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0],9)
            self.assertLess(signal.getitimer(signal.ITIMER_REAL)[0],10)
        finally:
            signal.setitimer(signal.ITIMER_REAL,0)
            signal.signal(signal.SIGALRM,saved_handler)
            signal.setitimer(signal.ITIMER_REAL,*saved_timer)

    def test_post_wait_receipt_refresh_rejects_changed_identity_before_pending_write(self):
        self.assertTrue(hasattr(self.v,'admit_preserved_phase'),'wait lacks canonical fresh receipt/run/writer revalidation')
        for fault in (None,'expired','replaced','writer-completed','writer-changed'):
            with self.subTest(fault=fault):
                h=self.preserved_writer_fixture()
                budget,client,clock,_=self.budget_fixture(0)
                context=h.envelope['context']
                handoff=context,h.envelope['members'],h.envelope['upload_outputs']
                env={'RELEASE_OPERATION':'recover-0.2.7-preserved','GITHUB_JOB':'retained-github',
                    'GITHUB_RUN_ID':str(context['run_id']),'GITHUB_RUN_ATTEMPT':str(context['run_attempt']),
                    'GITHUB_SHA':context['controller_sha'],'GITHUB_REF':context['controller_ref'],
                    'EXPECTED_TAG_OBJECT_SHA':context['controller_tag_object']}
                evidence=h.fixture.root/'wait-test';evidence.mkdir()
                with patch.dict(os.environ,env,clear=True):
                    prepared=self.v.prepare_current_receipt(h.custody,h.importer,h.manifest,h.record,
                        h.policy,h.transport,evidence,handoff,preserved=h.preserved)
                    state={'prepared':prepared,'observer':h.initial['observations']['observer']}
                    original=budget.sleeper
                    def sleep(seconds):
                        original(seconds)
                        h.state['now']='2026-10-01T23:08:00Z'
                        if fault=='expired':h.envelope['metadata_before']['expired']=True
                        if fault=='replaced':h.envelope['metadata_before']['id']+=1
                        if fault and fault.startswith('writer-'):
                            writer=next(j for j in h.envelope['current_jobs']['jobs'] if j['name']==h.custody.RECEIPT_WRITER_JOB)
                            if fault=='writer-completed':writer.update(status='completed',conclusion='success',completed_at='2026-10-01T23:00:00Z')
                            else:writer['id']+=1
                    budget.sleeper=sleep
                    def admit():
                        self.v.admit_preserved_phase(budget,client,'pending-write',h.custody,h.importer,
                            h.manifest,h.record,h.policy,h.transport,evidence,handoff,h.preserved,state)
                    if fault:
                        with self.assertRaises(ValueError):admit()
                    else:
                        admit()
                        self.assertEqual(state['prepared']['observed_at'],'2026-10-01T23:08:00Z')
                        self.assertTrue(list(evidence.glob('after-wait-1-phase-1/preliminary-receipt-input.json')))
                    self.assertTrue(all(method=='GET' for method,_,_ in clock.calls))

    def test_canonical_rebind_and_maximum_pages_all_35_asset_bytes_fit_admission(self):
        self.canonical_budget_recovery_case()

    def test_wait_precedes_canonical_source_file_custody_vector_and_transport_checks(self):
        for fault in ('valid-wait','source','payload','custody','custody-deleted','vector','transport'):
            with self.subTest(fault=fault):self.canonical_budget_recovery_case(fault)

    def canonical_budget_recovery_case(self,fault=None):
        h=self.preserved_writer_fixture()
        budget,client,clock,headers=self.budget_fixture(15000,15000)
        clock.now=h.custody.timestamp('2026-10-01T22:08:00Z','fixture').timestamp()
        clock.reset=int(clock.now)+3600;budget.last_wall=clock.now
        importer=types.ModuleType('full_budget_importer')
        source=HELPER.with_name('import_release_recovery_027.sh').read_text().split(
            '# BEGIN RECOVERY_IMPORT_PYTHON\n',1)[1].split('# END RECOVERY_IMPORT_PYTHON',1)[0]
        exec(compile(source,'full-budget-importer','exec'),importer.__dict__)
        importer.utc_now=lambda:datetime.fromtimestamp(clock.now,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        transport=importer.Transport(h.fixture.root,'fixture',h.manifest,h.record,
            policy=h.policy,preserved=h.preserved,budget=budget)
        controls=h.initial['controls_after']
        responses={transport.endpoints['run']:(200,controls['original_run']),
            transport.endpoints['jobs'][0]:(200,controls['original_jobs']),
            transport.endpoints['retaining_run']:(200,controls['retaining_run']),
            transport.endpoints['retaining_jobs'][0]:(200,controls['retaining_jobs']),
            h.record['custody']['metadata']['url']:(200,h.record['custody']['metadata'])}
        for item in h.initial['observations']['after']['records']:
            responses[importer.API+f"/artifacts/{item['id']}"]=(item['status'],item.get('metadata',{}))
        for (_,url),item in zip(transport.endpoints['preserved'],controls['preserved_observation']['requests']):
            responses[url]=(200,item['data'])
        def curl(argv,**kwargs):
            status,value=responses[argv[-1]]
            clock.remaining-=1;clock.calls.append(('GET',argv[-1],clock.mono))
            Path(argv[argv.index('--output')+1]).write_bytes(json.dumps(value).encode())
            Path(argv[argv.index('--dump-header')+1]).write_bytes((f'HTTP/2 {status}\r\n'+
                ''.join(k+': '+v+'\r\n' for k,v in headers().items())+'\r\n').encode())
            return subprocess.CompletedProcess(argv,0,str(status).encode(),b'')
        release={**self.expected,'id':123,'draft':True,'prerelease':False}
        assets={f'asset-{n}':bytes([n]) for n in range(35)}
        inventory=[{'id':n+1,'name':name,'size':1,'state':'uploaded'} for n,name in enumerate(assets)]
        original=client.transport.open
        downloads=[];writes=[];phases=[];rebind_counts=[]
        waited_source=[]
        def source_gate():
            waited_source.append(budget.waits)
            if budget.waits and fault=='source':raise ValueError('source drift during wait')
        def files(*args):
            if budget.waits and fault=='payload':raise ValueError('payload drift during wait')
            return {}
        original_sleep=budget.sleeper
        def sleep(seconds):
            original_sleep(seconds)
            if not budget.waits:return
            if fault=='custody':
                responses[h.record['custody']['metadata']['url']]=(200,{**h.record['custody']['metadata'],'expired':True})
            elif fault=='custody-deleted':responses[h.record['custody']['metadata']['url']]=(404,{})
            elif fault=='vector':
                item=next(item for item in h.initial['observations']['after']['records'] if item['status']==200)
                responses[importer.API+f"/artifacts/{item['id']}"]=(404,{})
            elif fault=='transport':
                url=transport.endpoints['preserved'][6][1]
                responses[url]=(200,{**responses[url][1],'id':1})
        budget.sleeper=sleep
        def response(request,timeout):
            if request.full_url==self.v.RATE_URL:return original(request,timeout)
            clock.remaining-=1;clock.calls.append((request.method,request.full_url,clock.mono))
            if request.method=='PATCH':
                writes.append((budget.phase,budget.phase_requests));release['draft']=False;raw=json.dumps(release).encode()
            elif '/releases/assets/' in request.full_url:
                identifier=int(request.full_url.rsplit('/',1)[1]);downloads.append(identifier);raw=bytes([identifier-1])
            elif '/releases/123/assets?' in request.full_url:
                raw=json.dumps(inventory if request.full_url.endswith('page=1') else []).encode()
            else:
                page=int(request.full_url.rsplit('=',1)[1])
                raw=json.dumps(([release] if page==1 else [{'id':1000+page,'tag_name':'other'}]) if page<10 else []).encode()
            result=io.BytesIO(raw);result.status=200;result.headers=headers();return result
        client.transport.open=response
        def rebind():
            if budget.phase:phases.append(budget.phase_requests)
            if fault and budget.phase==1:clock.remaining=budget.remaining=0
            budget.admit(client,'canonical')
            directory=h.fixture.root/f'actual-requests-{budget.phase}';directory.mkdir()
            before=budget.requests
            self.v.check_retained_rebind(h.custody,importer,h.manifest,h.record,h.policy,
                transport,directory,'fixture','fixture',h.initial,h.initial['observations']['observer'],
                h.candidate,source_gate,preserved=h.preserved)
            rebind_counts.append(budget.requests-before)
        with patch.object(importer.subprocess,'run',side_effect=curl), \
             patch.object(h.custody,'verify_files',side_effect=files):
            if fault not in (None,'valid-wait'):
                with self.assertRaises(ValueError):self.v.recover(client,self.expected,assets,rebind)
                self.assertEqual(writes,[])
                self.assertEqual(waited_source,[0,1])
                return
            result=self.v.recover(client,self.expected,assets,rebind)
        self.assertEqual(result['asset_count'],35)
        self.assertTrue(result['published'])
        self.assertEqual(rebind_counts,[22,22,22,22])
        self.assertEqual(phases,[71,33,69])
        self.assertEqual(downloads,list(range(1,36))*2)
        self.assertEqual(writes,[(2,33)])
        if fault=='valid-wait':self.assertEqual(waited_source,[0,1,1,1])

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

    def preserved_inputs(self):
        root=HELPER.parent.parent/'governance/releases/v0.2.7'
        return [json.loads((root/name).read_text()) for name in
            ('RECOVERY-MANIFEST.json','PUBLICATION-IDENTITIES.json','RETAINED-CUSTODY.json',
             'RETAINED-METADATA-POLICY.json','PRESERVED-PAYLOAD-TRANSPORT.json')]

    def preserved_writer_fixture(self, *, actual=False):
        """Offline v3 fixture; actual mode additionally acquires exact local archives."""
        audit=os.environ.get('EXO_RETAINED_AUDIT_DIR')
        failure_input=os.environ.get('EXO_RETAINED_FAILED_WRITER_ZIP')
        if actual and not audit:self.skipTest('actual preserved ZIP requires explicit local audit directory')
        if actual and not failure_input:self.skipTest('actual failed-writer ZIP requires explicit local evidence path')
        spec=importlib.util.spec_from_file_location('preserved_writer_end_to_end_fixture',
            HELPER.with_name('test_release_recovery_027.py'))
        fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
        fixtures.RetainedTests.setUpClass()
        fixture=fixtures.RetainedTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        custody=fixture.v
        record,publications,policy,preserved,envelope,receipts=fixture.v3_receipt_fixture()
        receipt_zip=fixture.write_receipt_fixture(envelope,receipts)
        importer=types.ModuleType('preserved_writer_importer_fixture')
        source=HELPER.with_name('import_release_recovery_027.sh').read_text().split(
            '# BEGIN RECOVERY_IMPORT_PYTHON\n',1)[1].split('# END RECOVERY_IMPORT_PYTHON',1)[0]
        exec(compile(source,'captured-preserved-writer-importer','exec'),importer.__dict__)
        root=fixture.root
        capture=root/'capture';capture.mkdir()
        workspace=HELPER.parent.parent
        for source_path,name in self.v.retained_capture_paths('recover-0.2.7-preserved').items():
            shutil.copyfile(workspace/source_path,capture/name)
        audit_root=Path(audit) if audit else None
        failed_archive=Path(failure_input) if failure_input else None
        if actual:
            self.assertTrue(failed_archive.is_file(),'actual failed-writer ZIP evidence required')
            self.assertEqual(hashlib.sha256(failed_archive.read_bytes()).hexdigest(),
                             '29f4c3a4e9075aabd725ad4c4ab7225f8e98be5aca3df67309c3e0e0ff0ae09d')
        failure_url=importer.API+'/artifacts/11124850978'
        failure_metadata={'id':11124850978,'name':'exochain-027-retained-github-receipts',
            'size_in_bytes':603,'url':failure_url,'archive_download_url':failure_url+'/zip',
            'node_id':'MDg6QXJ0aWZhY3QxMTEyNDg1MDk3OA==',
            'digest':'sha256:29f4c3a4e9075aabd725ad4c4ab7225f8e98be5aca3df67309c3e0e0ff0ae09d',
            'created_at':'2026-09-30T20:41:02Z','updated_at':'2026-09-30T20:41:02Z',
            'expires_at':'2026-10-30T20:41:01Z','expired':False,
            'workflow_run':{'id':36653810772,'repository_id':1116455646,
                'head_repository_id':1116455646,'head_sha':'b5871abd548d427cacab27e748b49e75897a5f66',
                'head_branch':'v0.2.7-recover.4'}}
        state={'now':'2026-10-01T22:05:30Z','rebind':0,'fault':None,'events':[]}
        class Transport:
            authenticated=set()
            endpoints={'run':'original-run','jobs':['original-jobs'],
                'retaining_run':'retaining-run','retaining_jobs':['retaining-jobs']}
            def get(self,url,path,limit):
                value=failure_metadata if url==failure_url else envelope['metadata_before']
                if state['fault']=='stale-receipt' and url!=failure_url:
                    value={**value,'expired':True}
                path.write_text(json.dumps(value))
            def receipt_archive(self,metadata,path):
                if metadata['id']==11124850978:
                    if not actual:raise AssertionError('actual historical writer ZIP unavailable in portable fixture')
                    shutil.copyfile(failed_archive,path)
                else:shutil.copyfile(receipt_zip,path)
            def preserved_archive(self,path):
                if not actual:raise AssertionError('actual preserved ZIP unavailable in portable fixture')
                state['events'].append('fresh-preserved-payload')
                shutil.copyfile(audit_root/'10779404529.zip',path)
            def archive(self,metadata,path):
                if not actual:raise AssertionError('actual retained archive unavailable in portable fixture')
                self_outer.assertEqual(metadata['id'],10780480598)
                shutil.copyfile(audit_root/'10780480598.zip',path)
        self_outer=self
        transport=Transport()
        original=envelope['origin']
        def controls(*args,phase,preserved=None,**kwargs):
            self.assertIsNotNone(preserved)
            value=copy.deepcopy(original['controls_before'] if phase=='acquisition-start'
                else original['controls_after'])
            if state['fault']=='transport' and state['rebind']==state.get('fault_at') and phase in ('writer-final','writer-readback'):
                value['preserved_observation']['requests'][6]['data']['id']+=1
            return value
        def observations(*args,phase,**kwargs):
            return copy.deepcopy(original['observations']['before'] if phase=='acquisition-before'
                                 else original['observations']['after'])
        importer.fetch_retained_controls=controls
        importer.fetch_original_observation_pass=observations
        importer.fetch_run_jobs=lambda *args:(copy.deepcopy(envelope['current_run']),
                                              copy.deepcopy(envelope['current_jobs']))
        importer.utc_now=lambda:state['now']
        archives=root/'archives';archives.mkdir()
        candidate=root/'candidate'
        acquisition=root/'acquisition';acquisition.mkdir()
        if actual:
            acquired,_=importer.acquire_retained(fixture.manifest,record,custody,transport,acquisition,
                archives,candidate,'fixture',policy=policy,
                observer=original['observations']['observer'],preserved=preserved)
            initial=custody.load_json(acquisition/'acquisition-origin-input.json','v3 acquisition input')
        else:
            initial=copy.deepcopy(original)
            acquired=custody.verify_retained_origin(fixture.manifest,record,initial,
                'fixture','fixture',policy=policy,preserved=preserved)
        self.assertEqual(acquired['schema'],'exochain-retained-origin-result-027/v3')
        receipt,expected=self.v.retained_release_metadata(fixture.manifest,publications,record,
            envelope['context']['controller_sha'],envelope['context']['controller_ref'],
            policy=policy,preserved=preserved)
        assets=(self.v.release_assets(custody,fixture.manifest,candidate,receipt) if actual else
            {name:name.encode() for name in receipt['github_release_assets'][:-1]} |
            {'RECOVERY-CUSTODY.json':json.dumps(receipt,sort_keys=True).encode()})
        self.assertEqual(len(assets),35)
        predecessor=self.v.fixed_empty_predecessor(fixture.manifest,publications,record,policy)
        return types.SimpleNamespace(fixture=fixture,custody=custody,importer=importer,
            manifest=fixture.manifest,record=record,publications=publications,policy=policy,
            preserved=preserved,envelope=envelope,transport=transport,capture=capture,
            workspace=workspace,archives=archives,candidate=candidate,initial=initial,
            expected=expected,assets=assets,predecessor=predecessor,state=state,
            failure_url=failure_url,actual=actual)

    def run_preserved_writer_case(self,h,label,*,fault=None,fault_at=None,full_files=False):
        """Run the canonical writer stages against local provider and I/O boundaries."""
        directory=h.fixture.root/label;directory.mkdir()
        evidence=directory/'evidence';evidence.mkdir()
        state=h.state
        state.update(now='2026-10-01T22:05:30Z',rebind=0,fault=fault,fault_at=fault_at,events=[])
        context=h.envelope['context']
        env={'RELEASE_OPERATION':'recover-0.2.7-preserved','GITHUB_JOB':'retained-github',
             'GITHUB_RUN_ID':str(context['run_id']),'GITHUB_RUN_ATTEMPT':str(context['run_attempt']),
             'GITHUB_SHA':context['controller_sha'],'GITHUB_REF':context['controller_ref'],
             'EXPECTED_TAG_OBJECT_SHA':context['controller_tag_object'],
             'GITHUB_WORKSPACE':str(h.workspace)}
        provider=FakeProvider(copy.deepcopy(h.predecessor))
        provider.patches=[]
        def update_body(identifier,body):
            provider.mutations.append('patch')
            provider.patches.append((identifier,body))
            if fault=='unknown-body':raise OSError('body response uncertain')
            provider.release={**provider.release,'body':body,'updated_at':'2026-10-01T22:08:30Z'}
            return dict(provider.release)
        provider.update_body=update_body
        ordinary_upload=provider.upload
        def upload(identifier,name,data):
            if fault=='unknown-asset' and name==next(iter(h.assets)):
                provider.mutations.append('upload:'+name)
                raise OSError('asset response uncertain')
            return ordinary_upload(identifier,name,data)
        provider.upload=upload
        ordinary_publish=provider.publish
        def publish(identifier, body=None):
            if fault=='unknown-publish':
                provider.mutations.append('publish')
                raise OSError('publication response uncertain')
            return ordinary_publish(identifier, body)
        provider.publish=publish
        journal=[]
        saved_policy=(h.capture/'PRESERVED-PAYLOAD-TRANSPORT.json').read_bytes()
        target_file=(h.candidate/'sbom'/next(file['path'] for lane in h.manifest['artifacts']
            if lane['lane']=='sbom' for file in lane['files'])) if h.actual else None
        saved_file=None
        saved_file_mode=None
        real_files=h.custody.verify_files
        def files(manifest,candidate):
            if h.actual and (full_files or (fault=='file' and state['rebind']==fault_at)):
                return real_files(manifest,candidate)
            return {'files_verified':40}
        def git_source(argv,**kwargs):
            path=argv[-1].split(':',1)[1]
            data=(h.workspace/path).read_bytes()
            if fault=='source' and state['rebind']==fault_at and path=='tools/recover_github_release_027.py':
                data=b'wrong reviewed writer source'
            return subprocess.CompletedProcess(argv,0,data,b'')
        def source_gate():
            state['events'].append(('source',state['rebind']))
            if fault=='captured-policy' and state['rebind']==fault_at:
                (h.capture/'PRESERVED-PAYLOAD-TRANSPORT.json').write_bytes(b'{}')
            h.importer.assert_captured_inputs(h.capture,h.custody,
                policy=h.policy,preserved=h.preserved)
        def check(phase='writer-final'):
            location=evidence/f'rebind-{state["rebind"]}-{phase}'
            location.mkdir()
            return self.v.check_retained_rebind(h.custody,h.importer,h.manifest,h.record,h.policy,
                h.transport,location,h.archives/'10780480598.zip','fixture',h.initial,
                h.initial['observations']['observer'],h.candidate,source_gate,
                preserved=h.preserved,phase=phase)
        def rebind():
            nonlocal saved_file,saved_file_mode
            state['rebind']+=1
            state['events'].append(('rebind',state['rebind']))
            if fault=='file' and state['rebind']==fault_at:
                saved_file=target_file.read_bytes()
                saved_file_mode=target_file.stat().st_mode
                target_file.chmod(saved_file_mode|0o200)
                target_file.write_bytes(saved_file+b'changed')
            return check()
        def prepare_gate():
            state['events'].append('preliminary-v3')
            state['prepared']=self.v.prepare_current_receipt(h.custody,h.importer,h.manifest,
                h.record,h.policy,h.transport,evidence,
                (context,h.envelope['members'],h.envelope['upload_outputs']),preserved=h.preserved)
            state['observer']=h.importer.capture_observer(h.custody,h.transport,h.capture,evidence,
                'retained-github')
            self.assertEqual(state['observer'],h.initial['observations']['observer'])
        def acquire_gate():
            state['events'].append('independent-v3-acquisition' if h.actual else 'fixture-v3-origin-verification')
            checked=h.custody.verify_retained_origin(h.manifest,h.record,h.initial,
                h.archives/'10780480598.zip' if h.actual else 'fixture',
                'fixture',policy=h.policy,preserved=h.preserved)
            self.assertEqual(checked['schema'],'exochain-retained-origin-result-027/v3')
            if full_files:
                h.custody.verify_retained_transport(h.manifest,h.record,h.archives)
        def receipt_gate():
            state['events'].append('full-v3-receipt')
            state['now']='2026-10-01T22:08:00Z'
            state['receipt']=self.v.receive_current_receipts(h.custody,h.importer,h.manifest,
                h.record,h.publications,h.transport,evidence,h.archives/'10780480598.zip',
                'fixture',h.initial,(context,h.envelope['members'],h.envelope['upload_outputs']),
                policy=h.policy,prepared=state['prepared'],preserved=h.preserved)
            self.assertEqual(state['receipt']['schema'],'exochain-retained-receipts-result-027/v3')
        def public_gate():
            state['events'].append('public-file-gate' if h.actual else 'fixture-public-file-boundary')
            if full_files:real_files(h.manifest,h.candidate)
        def final_gate():
            state['events'].append('post-public-v3-finalizer')
            state['rebind']=0
            return check()
        def transition_gate():
            state['events'].append('predecessor-authentication' if h.actual else 'fixture-fixed-predecessor')
            predecessor=(self.v.authenticate_failed_predecessor(h.transport,h.custody,h.importer,
                evidence,h.manifest,h.publications,h.record,h.policy) if h.actual else
                self.v.fixed_empty_predecessor(h.manifest,h.publications,h.record,h.policy))
            self.assertEqual(predecessor,h.predecessor)
            rebind()
            return self.v.begin_predecessor_transition(provider,h.expected,predecessor,rebind,journal.append)
        def readback_gate():
            state['events'].append('final-fresh-v3-payload' if h.actual else 'fixture-readback-boundary')
            if h.actual:
                location=evidence/'fresh-payload';location.mkdir()
                state['fresh']=self.v.verify_fresh_preserved_payload(h.custody,h.transport,h.manifest,
                    h.record,location)
            else:state['events'].append('fixture-readback-no-archive')
            state['rebind']=42
            check('writer-readback')
        error=result=None
        try:
            with patch.dict(os.environ,env,clear=True), \
                 patch.object(h.importer.subprocess,'run',side_effect=git_source), \
                 patch.object(h.custody,'verify_files',side_effect=files):
                result=self.v.complete_retained(provider,h.expected,h.assets,rebind,receipt_gate,
                    public_gate,journal.append,prepare_gate=prepare_gate,acquire_gate=acquire_gate,
                    final_gate=final_gate,transition_gate=transition_gate,readback_gate=readback_gate)
        except Exception as failure:
            error=failure
        finally:
            (h.capture/'PRESERVED-PAYLOAD-TRANSPORT.json').write_bytes(saved_policy)
            if saved_file is not None:
                target_file.write_bytes(saved_file)
                target_file.chmod(saved_file_mode)
        return types.SimpleNamespace(provider=provider,journal=journal,state=state.copy(),
                                     result=result,error=error)

    def test_preserved_public_receipt_and_body_disclose_distinct_production_and_rehosting(self):
        manifest, publications, record, policy, preserved = self.preserved_inputs()
        receipt, expected = self.v.retained_release_metadata(manifest,publications,record,
            'a'*40,'refs/tags/v0.2.7-recover.5',policy=policy,preserved=preserved)
        self.assertEqual(receipt['schema'],'exochain-release-retained-custody/v3')
        self.assertEqual(receipt['preserved_payload']['historical_actions_artifact_id'],10779404529)
        self.assertEqual(receipt['preserved_payload']['custody_release_id'],400603306)
        self.assertEqual(receipt['preserved_payload']['custody_asset_id'],602278328)
        self.assertEqual(receipt['preserved_payload']['sha256'],
            'eb4138638b9305b406fb50f5e49e205982611af6bcba9aedf92bb34dd7d06b5a')
        self.assertFalse(receipt['preserved_payload']['continuous_hosted_custody_proven'])
        self.assertEqual(receipt['controller'],{'sha':'a'*40,'ref':'refs/tags/v0.2.7-recover.5'})
        for phrase in ('authorized local', 'historical', 'not a new build', '400603306'):
            self.assertIn(phrase,expected['body'])
        self.assertEqual(len(receipt['github_release_assets']),35)
        with self.assertRaises(ValueError):
            self.v.retained_release_metadata(manifest,publications,record,'a'*40,
                'refs/tags/v0.2.7-recover.5',preserved=preserved)

    def test_final_preserved_byte_check_precedes_accepted_result(self):
        events=[]
        provider=FakeProvider()
        journal=[]
        def readback():
            events.append('fresh-full-payload')
            self.assertEqual(len(provider.assets),2)
            raise ValueError('preserved payload disappeared after publication')
        with self.assertRaisesRegex(ValueError,'preserved payload disappeared'):
            self.v.complete_retained(provider,self.expected,self.assets,
                lambda:events.append('rebind'),lambda:events.append('receipts'),
                lambda:events.append('public'),journal.append,
                prepare_gate=lambda:events.append('prepare'),acquire_gate=lambda:events.append('acquire'),
                final_gate=lambda:events.append('before-writes'),readback_gate=readback)
        self.assertEqual(events[-1],'fresh-full-payload')
        self.assertNotIn('final_readback',[row['operation'] for row in journal])

    def test_preserved_exact_35_assets_same_draft_final_acceptance(self):
        h=self.preserved_writer_fixture(actual=True)
        outcome=self.run_preserved_writer_case(h,'actual-v3-success',full_files=True)
        self.assertIsNone(outcome.error,repr(outcome.error))
        self.assertEqual(outcome.result,{'tag':'v0.2.7','release_id':400420101,
                                         'asset_count':35,'published':True})
        self.assertEqual(outcome.provider.patches,[(400420101,h.expected['body'])])
        for field in self.v.PRESERVED_RELEASE_FIELDS:
            if field not in ('draft','published_at'):
                self.assertEqual(outcome.provider.release[field],h.predecessor[field],field)
        self.assertEqual(outcome.provider.mutations,
            ['patch']+['upload:'+name for name in h.assets]+['publish'])
        self.assertEqual(set(outcome.provider.assets),set(h.assets))
        for name,data in h.assets.items():
            self.assertEqual(outcome.provider.assets[name],data,name)
        self.assertEqual(outcome.state['events'][:6],
            ['preliminary-v3','independent-v3-acquisition','full-v3-receipt',
             'public-file-gate','post-public-v3-finalizer',('source',0)])
        self.assertLess(outcome.state['events'].index('predecessor-authentication'),
                        outcome.state['events'].index(('rebind',1)))
        self.assertLess(outcome.state['events'].index('final-fresh-v3-payload'),
                        outcome.state['events'].index('fresh-preserved-payload'))
        transition=[(i,row['outcome']) for i,row in enumerate(outcome.journal)
                    if row['operation']=='transition_controller_body']
        self.assertEqual([value for _,value in transition],
                         ['intent','response_received_not_yet_accepted','accepted'])
        first_upload=next(i for i,row in enumerate(outcome.journal)
                          if row['operation']=='upload_asset')
        self.assertLess(transition[-1][0],first_upload)
        self.assertEqual(outcome.journal[-1]['operation'],'final_readback')
        self.assertEqual(outcome.journal[-1]['outcome'],'accepted')

    def test_preserved_source_rebind_halts_each_mutation_and_final_boundary(self):
        h=self.preserved_writer_fixture()
        names=list(h.assets)
        for boundary in (2,*range(4,40),40,41,42):
            with self.subTest(boundary=boundary):
                outcome=self.run_preserved_writer_case(h,f'source-boundary-{boundary}',
                    fault='source',fault_at=boundary)
                self.assertIsNotNone(outcome.error)
                self.assertIn('captured controller helper',str(outcome.error).lower())
                self.assertIn(('source',boundary),outcome.state['events'])
                if boundary==2:
                    expected=[]
                elif boundary<=39:
                    expected=['patch']+['upload:'+name for name in names[:max(0,boundary-5)]]
                elif boundary==40:
                    expected=['patch']+['upload:'+name for name in names]
                else:
                    expected=['patch']+['upload:'+name for name in names]+['publish']
                self.assertEqual(outcome.provider.mutations,expected)
                self.assertNotIn('final_readback',
                    [row['operation'] for row in outcome.journal])

    def test_preserved_policy_transport_receipt_and_unknown_writes_halt(self):
        h=self.preserved_writer_fixture()
        scenarios=(
            ('captured-policy',2,[]),
            ('captured-policy',40,['patch']+['upload:'+name for name in h.assets]),
            ('transport',4,['patch']),
            ('transport',38,['patch']+['upload:'+name for name in list(h.assets)[:33]]),
            ('transport',42,['patch']+['upload:'+name for name in h.assets]+['publish']),
            ('stale-receipt',None,[]),
            ('unknown-body',None,['patch']),
            ('unknown-asset',None,['patch','upload:'+next(iter(h.assets))]),
            ('unknown-publish',None,['patch']+['upload:'+name for name in h.assets]+['publish']),
        )
        for number,(fault,boundary,writes) in enumerate(scenarios):
            with self.subTest(fault=fault,boundary=boundary):
                outcome=self.run_preserved_writer_case(h,f'fault-{number}',
                    fault=fault,fault_at=boundary)
                self.assertIsNotNone(outcome.error)
                if fault=='transport':
                    self.assertIn('preserved',str(outcome.error).lower())
                if fault=='captured-policy':
                    self.assertIn('captured',str(outcome.error).lower())
                self.assertEqual(outcome.provider.mutations,writes)
                self.assertNotIn('final_readback',
                    [row['operation'] for row in outcome.journal])
                if fault.startswith('unknown-'):
                    self.assertEqual(outcome.journal[-1]['outcome'],'unknown')

    def test_actual_preserved_staged_file_drift_halts_before_upload(self):
        h=self.preserved_writer_fixture(actual=True)
        outcome=self.run_preserved_writer_case(h,'actual-staged-file-drift',
            fault='file',fault_at=4)
        self.assertIsNotNone(outcome.error)
        self.assertIn('file',str(outcome.error).lower())
        self.assertEqual(outcome.provider.mutations,['patch'])
        self.assertNotIn('final_readback',[row['operation'] for row in outcome.journal])

    def test_writer_fresh_payload_readback_strictly_verifies_actual_preserved_zip(self):
        audit=os.environ.get('EXO_RETAINED_AUDIT_DIR')
        if not audit:self.skipTest('actual preserved ZIP requires explicit local audit directory')
        manifest,_,record,_,_=self.preserved_inputs()
        spec=importlib.util.spec_from_file_location('preserved_readback_custody',
            HELPER.with_name('verify_release_recovery_027.py'))
        custody=importlib.util.module_from_spec(spec);spec.loader.exec_module(custody)
        source=Path(audit)/'10779404529.zip'
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            calls=[]
            class Transport:
                def preserved_archive(self,destination):
                    calls.append(destination)
                    shutil.copyfile(source,destination)
            result=self.v.verify_fresh_preserved_payload(custody,Transport(),manifest,record,root)
            self.assertEqual(result,{'files_verified':40,
                'zip_sha256':'eb4138638b9305b406fb50f5e49e205982611af6bcba9aedf92bb34dd7d06b5a'})
            self.assertEqual(calls,[root/'10779404529.zip'])

    def test_preserved_preliminary_receipt_binds_current_producer_before_acquisition(self):
        spec=importlib.util.spec_from_file_location('preserved_writer_fixture',
            HELPER.with_name('test_release_recovery_027.py'))
        fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
        fixtures.RetainedTests.setUpClass()
        fixture=fixtures.RetainedTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        record,_,policy,preserved,envelope,receipts=fixture.v3_receipt_fixture()
        fixture.write_receipt_fixture(envelope,receipts)
        handoff=(envelope['context'],envelope['members'],envelope['upload_outputs'])
        evidence=fixture.root/'preserved-preliminary';evidence.mkdir()
        class Transport:
            authenticated=set()
            def get(self,url,path,limit): path.write_text(json.dumps(envelope['metadata_before']))
        importer=types.SimpleNamespace(API='https://api.github.com/repos/exochain/exochain/actions',
            JSON_LIMIT=4*1024*1024,
            fetch_run_jobs=lambda *args:(copy.deepcopy(envelope['current_run']),copy.deepcopy(envelope['current_jobs'])),
            utc_now=lambda:envelope['observed_at'],
            dump=lambda path,value:path.write_text(json.dumps(value)))
        context=envelope['context']
        env={'RELEASE_OPERATION':'recover-0.2.7-preserved','GITHUB_JOB':'retained-github',
             'GITHUB_RUN_ID':str(context['run_id']),'GITHUB_RUN_ATTEMPT':str(context['run_attempt']),
             'GITHUB_SHA':context['controller_sha'],'GITHUB_REF':context['controller_ref'],
             'EXPECTED_TAG_OBJECT_SHA':context['controller_tag_object']}
        with patch.dict(os.environ,env,clear=True):
            prepared=self.v.prepare_current_receipt(fixture.v,importer,fixture.manifest,record,
                policy,Transport(),evidence,handoff,preserved=preserved)
        self.assertEqual(prepared['schema'],'exochain-retained-receipts-input-027/v3')
        self.assertEqual(prepared['preserved_policy_sha256'],fixture.v.PRESERVED_PAYLOAD_POLICY_SHA256)
        self.assertEqual(prepared['operation'],'recover-0.2.7-preserved')
        self.assertNotIn('origin',prepared)

    def test_preserved_writer_captures_both_policies_from_controller(self):
        paths=self.v.retained_capture_paths('recover-0.2.7-preserved')
        self.assertEqual(paths['governance/releases/v0.2.7/PRESERVED-PAYLOAD-TRANSPORT.json'],
                         'PRESERVED-PAYLOAD-TRANSPORT.json')
        self.assertEqual(paths['governance/releases/v0.2.7/RETAINED-METADATA-POLICY.json'],
                         'RETAINED-METADATA-POLICY.json')
        self.assertNotIn('governance/releases/v0.2.7/PRESERVED-PAYLOAD-TRANSPORT.json',
                         self.v.retained_capture_paths('recover-0.2.7-retained-404'))
        with self.assertRaises(ValueError): self.v.retained_capture_paths('release')

    def test_preserved_full_writer_receipt_accepts_only_v3_same_attempt(self):
        spec=importlib.util.spec_from_file_location('preserved_full_writer_fixture',
            HELPER.with_name('test_release_recovery_027.py'))
        fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
        fixtures.RetainedTests.setUpClass()
        fixture=fixtures.RetainedTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        record,publications,policy,preserved,envelope,receipts=fixture.v3_receipt_fixture()
        receipt=fixture.write_receipt_fixture(envelope,receipts)
        prepared={key:copy.deepcopy(value) for key,value in envelope.items()
                  if key not in ('origin','metadata_after')}
        prepared['observed_at']='2026-10-01T22:05:30Z'
        evidence=fixture.root/'writer-full-v3';evidence.mkdir()
        class Transport:
            authenticated=set()
            def get(self,url,path,limit):path.write_text(json.dumps(envelope['metadata_before']))
            def receipt_archive(self,metadata,path):path.write_bytes(receipt.read_bytes())
        importer=types.SimpleNamespace(API='https://api.github.com/repos/exochain/exochain/actions',
            JSON_LIMIT=4*1024*1024,
            fetch_run_jobs=lambda *args:(copy.deepcopy(envelope['current_run']),copy.deepcopy(envelope['current_jobs'])),
            utc_now=lambda:'2026-10-01T22:08:00Z',
            dump=lambda path,value:path.write_text(json.dumps(value)))
        handoff=(envelope['context'],envelope['members'],envelope['upload_outputs'])
        with patch.dict(os.environ,{'RELEASE_OPERATION':'recover-0.2.7-preserved'}):
            result=self.v.receive_current_receipts(fixture.v,importer,fixture.manifest,record,
                publications,Transport(),evidence,'fixture','fixture',envelope['origin'],handoff,
                policy=policy,prepared=prepared,preserved=preserved)
        self.assertEqual(result['schema'],'exochain-retained-receipts-result-027/v3')
        self.assertEqual(result['producer_job_id'],envelope['context']['producer_job_id'])
        self.assertEqual(result['preserved_policy_sha256'],fixture.v.PRESERVED_PAYLOAD_POLICY_SHA256)

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

    def test_omitted_draft_listing_fails_closed_before_any_create(self):
        predecessor = self.fixed_predecessor()
        provider = FakeProvider(None)
        with self.assertRaisesRegex(ValueError, r'^pinned retained draft is missing or replaced$'):
            self.v.preflight(provider, self.expected, self.assets, lambda: None, predecessor=predecessor)
        self.assertEqual(provider.mutations, [])

    def test_read_only_github_client_refuses_mutation_before_opening_a_request(self):
        opened = []
        client = self.v.GitHub('SECRET_SENTINEL', lambda raw, label: json.loads(raw), read_only=True)
        client.transport = types.SimpleNamespace(open=lambda *args, **kwargs: opened.append(args))
        for method in ('POST', 'PATCH', 'PUT', 'DELETE'):
            with self.subTest(method=method):
                with self.assertRaisesRegex(ValueError, r'^read-only GitHub client forbids release mutation$') as caught:
                    client.request(method, 'https://api.github.com/repos/exochain/exochain/releases', data=b'{}')
                self.assertNotIn('SECRET_SENTINEL', str(caught.exception))
        self.assertEqual(opened, [])

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

    def test_body_transition_reasserts_product_tag_and_requires_http_200(self):
        client=self.v.GitHub('test-only-token',lambda raw,label:json.loads(raw))
        calls=[]
        def request(method,url,data=None,**kwargs):
            calls.append((method,url,data))
            return 200,json.dumps({**self.expected,'id':400420101,'draft':True,
                'prerelease':False,'published_at':None,'assets':[]}).encode(),{}
        client.request=request
        client.update_body(400420101,self.expected['body'])
        self.assertEqual(calls,[('PATCH','https://api.github.com/repos/exochain/exochain/releases/400420101',
            b'{"tag_name":"v0.2.7","target_commitish":"666c578f719d1e54fce95d6831a3af92ea80df93",'
            b'"name":"EXOCHAIN v0.2.7","body":"fixed reviewed identity","draft":true,"prerelease":false}')])
        calls.clear()
        client.publish(400420101,self.expected['body'])
        self.assertEqual(calls,[('PATCH','https://api.github.com/repos/exochain/exochain/releases/400420101',
            b'{"tag_name":"v0.2.7","target_commitish":"666c578f719d1e54fce95d6831a3af92ea80df93",'
            b'"name":"EXOCHAIN v0.2.7","body":"fixed reviewed identity","draft":false,"prerelease":false,'
            b'"make_latest":"true"}')])
        client.request=lambda *args,**kwargs:(201,b'{}',{})
        with self.assertRaises(ValueError): client.update_body(400420101,'body')

    def test_untagged_transition_response_stops_before_any_asset_upload(self):
        predecessor=self.fixed_predecessor()
        provider=FakeProvider(dict(predecessor))
        journal=[]
        def update(identifier,body):
            provider.mutations.append('patch')
            provider.release={**predecessor,'body':body,
                'tag_name':'untagged-5dbc4793108251330e78','updated_at':'2026-10-05T17:46:15Z'}
            return dict(provider.release)
        provider.update_body=update
        with self.assertRaisesRegex(ValueError,'conflicting release tag_name'):
            self.v.complete_retained(provider,self.expected,self.assets,lambda:None,
                lambda:None,lambda:None,journal.append,prepare_gate=lambda:None,
                acquire_gate=lambda:None,final_gate=lambda:None,
                transition_gate=lambda:self.v.begin_predecessor_transition(
                    provider,self.expected,predecessor,lambda:None,journal.append))
        self.assertEqual(provider.mutations,['patch'])
        self.assertEqual(journal[-1]['outcome'],'unknown')
        self.assertNotIn('upload_asset',[row['operation'] for row in journal])

    def test_detached_pinned_draft_is_read_only_until_tag_is_reasserted(self):
        predecessor=self.fixed_predecessor()
        detached={**predecessor,'tag_name':'untagged-5dbc4793108251330e78',
            'body':'recover.7 controller body already stored','updated_at':'2026-10-05T17:46:15Z'}
        provider=FakeProvider(dict(detached))
        result=self.v.preflight(provider,self.expected,self.assets,lambda:None,predecessor=predecessor)
        self.assertEqual(result['release_id'],400420101)
        self.assertEqual(result['existing_assets'],0)
        self.assertIs(result['mutation_attempted'],False)
        self.assertEqual(provider.mutations,[])
        journal=[]
        def update(identifier,body):
            provider.mutations.append('patch')
            self.assertEqual((identifier,body),(400420101,self.expected['body']))
            provider.release={**provider.release,'body':body,'tag_name':'v0.2.7',
                'updated_at':'2026-10-05T18:00:00Z'}
            return dict(provider.release)
        provider.update_body=update
        self.v.complete_retained(provider,self.expected,self.assets,lambda:None,
            lambda:None,lambda:None,journal.append,prepare_gate=lambda:None,
            acquire_gate=lambda:None,final_gate=lambda:None,
            transition_gate=lambda:self.v.begin_predecessor_transition(
                provider,self.expected,predecessor,lambda:None,journal.append))
        self.assertEqual(provider.release['tag_name'],'v0.2.7')
        self.assertEqual(provider.release['id'],400420101)
        self.assertEqual(provider.mutations[0],'patch')
        self.assertIn('upload:archive.tar.gz',provider.mutations)
        self.assertEqual([row['outcome'] for row in journal if row['operation']=='transition_controller_body'],
            ['intent','response_received_not_yet_accepted','accepted'])

    def test_detached_draft_rejects_foreign_identity_before_patch(self):
        predecessor=self.fixed_predecessor()
        base={**predecessor,'tag_name':'untagged-5dbc4793108251330e78',
            'body':'stored','updated_at':'2026-10-05T17:46:15Z'}
        for change in ({'tag_name':'untagged-GGGG'},{'tag_name':'v0.2.7-recover.7'},
                {'id':400420102},{'node_id':'other'},{'assets':[{'name':'x'}]},
                {'draft':False},{'target_commitish':'main'},
                {'updated_at':'2026-09-30T20:40:07Z'}):
            with self.subTest(change=change):
                provider=FakeProvider({**base,**change})
                provider.update_body=lambda *args:provider.mutations.append('patch')
                with self.assertRaises(ValueError):
                    self.v.preflight(provider,self.expected,self.assets,lambda:None,
                        predecessor=predecessor)
                self.assertEqual(provider.mutations,[])

    def test_real_client_rebinds_detached_draft_by_id(self):
        predecessor=self.fixed_predecessor()
        detached={**predecessor,'tag_name':'untagged-5dbc4793108251330e78',
            'body':'recover.7 body','updated_at':'2026-10-05T17:46:15Z'}
        controller={'id':402544806,'tag_name':'v0.2.7-recover.7','name':'','draft':False,'prerelease':False}
        custody={'id':400603306,'tag_name':'v0.2.7-custody.1','draft':False,'prerelease':True}
        state={'release':dict(detached)}
        client=self.v.GitHub('test-only-token',lambda raw,label:json.loads(raw))
        calls=[]
        def request(method,url,data=None,**kwargs):
            calls.append((method,url,data))
            if method=='PATCH' and url.endswith('/releases/400420101'):
                payload=json.loads(data)
                self.assertEqual(payload['tag_name'],'v0.2.7')
                self.assertEqual(payload['target_commitish'],self.v.PRODUCT_SHA)
                self.assertIs(payload['draft'],True)
                self.assertNotIn('make_latest',payload)
                state['release']={**state['release'],'tag_name':'v0.2.7','body':payload['body'],
                    'updated_at':'2026-10-05T18:00:00Z'}
                return 200,json.dumps(state['release']).encode(),{}
            if '/assets?' in url:
                return 200,b'[]',{}
            if method=='GET' and url.endswith('/releases/400420101'):
                return 200,json.dumps(state['release']).encode(),{}
            if '/releases?' in url:
                page=url.rsplit('page=',1)[1]
                payload=[state['release'],controller,custody] if page=='1' else []
                return 200,json.dumps(payload).encode(),{}
            raise AssertionError(method+' '+url)
        client.request=request
        client.read_only=True
        result=self.v.preflight(client,self.expected,self.assets,lambda:None,predecessor=predecessor)
        self.assertEqual(result['release_id'],400420101)
        self.assertIs(result['mutation_attempted'],False)
        self.assertFalse(any(method=='PATCH' for method,_,_ in calls))
        self.assertTrue(any(method=='GET' and url.endswith('/releases/400420101') for method,url,_ in calls))
        client.read_only=False
        calls.clear()
        journal=[]
        identifier=self.v.transition_empty_draft(client,self.expected,predecessor,lambda:None,journal.append)
        self.assertEqual(identifier,400420101)
        self.assertEqual(state['release']['tag_name'],'v0.2.7')
        self.assertEqual(state['release']['id'],400420101)
        self.assertEqual([row['outcome'] for row in journal],
            ['intent','response_received_not_yet_accepted','accepted'])
        self.assertEqual(sum(method=='PATCH' for method,_,_ in calls),1)

    def test_different_v027_release_is_not_adopted(self):
        predecessor=self.fixed_predecessor()
        other={**predecessor,'id':402544806,'tag_name':'v0.2.7','name':''}
        client=self.v.GitHub('test-only-token',lambda raw,label:json.loads(raw))
        def response(method,path,**kwargs):
            return [other] if path.endswith('page=1') else []
        client.json=response
        with self.assertRaisesRegex(ValueError,'not the pinned draft'):
            client.pinned_product_release()

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
        def observed_publish(identifier, body=None):
            events.append('publish')
            return publish(identifier, body)
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
            def command(argv,receipt,environment,timeout,bounded,budget=None):
                self.assertIsNone(budget)
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

    def test_live_upload_201_without_rate_headers_is_accepted_and_api_host_is_not(self):
        # Exact asset object returned by the recover.9 upload that run 37649006650 rejected.
        body = (
            b'{"url":"https://api.github.com/repos/exochain/exochain/releases/assets/619480612",'
            b'"id":619480612,"node_id":"RA_kwDOQovC3s4k7IYk","name":"exochain-0.2.7-exochain-api.cdx.json",'
            b'"label":"","uploader":{"login":"github-actions[bot]","id":41898282,'
            b'"node_id":"MDM6Qm90NDE4OTgyODI=","avatar_url":"https://avatars.githubusercontent.com/in/15368?v=4",'
            b'"gravatar_id":"","url":"https://api.github.com/users/github-actions%5Bbot%5D",'
            b'"html_url":"https://github.com/apps/github-actions",'
            b'"followers_url":"https://api.github.com/users/github-actions%5Bbot%5D/followers",'
            b'"following_url":"https://api.github.com/users/github-actions%5Bbot%5D/following{/other_user}",'
            b'"gists_url":"https://api.github.com/users/github-actions%5Bbot%5D/gists{/gist_id}",'
            b'"starred_url":"https://api.github.com/users/github-actions%5Bbot%5D/starred{/owner}{/repo}",'
            b'"subscriptions_url":"https://api.github.com/users/github-actions%5Bbot%5D/subscriptions",'
            b'"organizations_url":"https://api.github.com/users/github-actions%5Bbot%5D/orgs",'
            b'"repos_url":"https://api.github.com/users/github-actions%5Bbot%5D/repos",'
            b'"events_url":"https://api.github.com/users/github-actions%5Bbot%5D/events{/privacy}",'
            b'"received_events_url":"https://api.github.com/users/github-actions%5Bbot%5D/received_events",'
            b'"type":"Bot","user_view_type":"public","site_admin":false},"content_type":"application/octet-stream",'
            b'"state":"uploaded","size":77306,'
            b'"digest":"sha256:e83a76ed74897d9b314f65005d3c7eec6df87add00d2efc0d9485531d4176c52",'
            b'"download_count":0,"created_at":"2026-10-07T18:35:21Z","updated_at":"2026-10-07T18:35:21Z",'
            b'"browser_download_url":"https://github.com/exochain/exochain/releases/download/'
            b'untagged-38320051a3d07f9c500c/exochain-0.2.7-exochain-api.cdx.json"}'
        )
        self.assertEqual(len(body), 1695)
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         '0081366cb7f25746b05778fb3c01eac377452ad2c1885a026cb3a3b8e21c7c57')
        asset = json.loads(body)
        self.assertEqual(asset['state'], 'uploaded')
        self.assertEqual(asset['digest'], 'sha256:e83a76ed74897d9b314f65005d3c7eec6df87add00d2efc0d9485531d4176c52')

        def upload_headers(extra=()):
            header = Message()
            header['Cache-Control'] = 'no-cache'
            header['Content-Type'] = 'application/json; charset=utf-8'
            header['X-GitHub-Request-Id'] = 'F400:177F46:FA3D:15750:6AC690E8'
            for key, value in extra:
                header[key] = value
            return header

        budget, client, clock, _ = self.budget_fixture()
        budget.admit(client, 'upload-host')
        remaining = budget.remaining
        def created(request, timeout):
            self.assertEqual(request.method, 'POST')
            self.assertTrue(request.full_url.startswith('https://uploads.github.com/repos/exochain/exochain/'))
            result = io.BytesIO(body)
            result.status = 201
            result.headers = upload_headers()
            return result
        client.transport.open = created
        client.upload(400420101, asset['name'], b'x' * asset['size'])
        self.assertFalse(budget.stopped)
        self.assertEqual(budget.remaining, remaining - 1)

        budget, client, clock, _ = self.budget_fixture()
        budget.admit(client, 'api-host')
        def unrated(request, timeout):
            result = io.BytesIO(b'{}')
            result.status = 200
            result.headers = upload_headers()
            return result
        client.transport.open = unrated
        with self.assertRaisesRegex(self.v.GitHubUploadError, r'release mutation failed or unknown with HTTP 200'):
            client.request('PATCH', self.v.API + '/releases/400420101', b'{}')
        self.assertTrue(budget.stopped)

        for extra, status in (((), 403), ((('X-RateLimit-Resource', 'search'),), 201),
                              ((('X-RateLimit-Resource', 'core'),), 201)):
            with self.subTest(extra=extra, status=status):
                budget, client, clock, _ = self.budget_fixture()
                budget.admit(client, 'rejected-upload')
                def rejected(request, timeout, extra=extra, status=status):
                    result = io.BytesIO(body)
                    result.status = status
                    result.headers = upload_headers(extra)
                    return result
                client.transport.open = rejected
                with self.assertRaisesRegex(self.v.GitHubUploadError, r'release mutation failed or unknown with HTTP ' + str(status)):
                    client.upload(400420101, asset['name'], b'x' * asset['size'])
                self.assertTrue(budget.stopped)

    def test_prior_controller_draft_keeps_uploaded_asset_and_rejects_partial_or_foreign_bytes(self):
        manifest, publications, record, policy, preserved = self.preserved_inputs()
        predecessor = self.fixed_predecessor()
        _, prior = self.v.retained_release_metadata(manifest, publications, record,
            '601383caec1ce20b559cfe7c8e0f2786ba299132', 'refs/tags/v0.2.7-recover.9',
            policy=policy, preserved=preserved)
        _, successor = self.v.retained_release_metadata(manifest, publications, record,
            'b' * 40, 'refs/tags/v0.2.7-recover.10', policy=policy, preserved=preserved)
        self.assertEqual(hashlib.sha256(prior['body'].encode()).hexdigest(),
                         '38711d33e3b370816035e0c30c7a12394669002aac11ecdb3ac8dbe09437de0e')
        self.assertNotEqual(prior['body'], successor['body'])
        self.assertIn('refs/tags/v0.2.7-recover.10', successor['body'])
        authenticator = self.v.controller_body_authenticator(manifest, publications, record, policy, preserved,
            successor['body'], predecessor['body'])
        self.assertIs(authenticator(prior['body']), True)
        self.assertIs(authenticator('foreign'), False)
        self.assertIs(authenticator(prior['body'] + '\n'), False)
        name = 'exochain-0.2.7-exochain-api.cdx.json'
        payload = b'abc'
        assets = {name: payload, 'RECOVERY-CUSTODY.json': b'{}'}
        embedded = {'id':619480612, 'name':name, 'size':len(payload), 'state':'uploaded',
                    'digest':'sha256:' + hashlib.sha256(payload).hexdigest()}
        html_url = 'https://github.com/exochain/exochain/releases/tag/untagged-38320051a3d07f9c500c'

        def provider_for(body, asset_rows, stored):
            release = {**predecessor, 'body':body, 'updated_at':'2026-10-07T18:35:21Z',
                       'html_url':html_url, 'assets':[dict(row) for row in asset_rows]}
            provider = FakeProvider(release, dict(stored))
            provider.list_assets = lambda identifier: [dict(row) for row in asset_rows]
            provider.update_body = lambda *args: provider.mutations.append('patch')
            return provider

        ready = provider_for(prior['body'], [embedded], {name: payload})
        preview = self.v.preflight(ready, successor, assets, lambda:None, predecessor=predecessor,
                                   prior_controller=authenticator)
        self.assertEqual(preview['release_id'], 400420101)
        self.assertEqual(preview['existing_assets'], 1)
        self.assertEqual(preview['missing_assets'], ['RECOVERY-CUSTODY.json'])
        self.assertIs(preview['mutation_attempted'], False)
        self.assertEqual(ready.mutations, [])
        self.assertEqual(ready.release['html_url'], html_url)
        self.assertEqual(ready.release['tag_name'], 'v0.2.7')

        journal = []
        ids = {name:619480612, 'RECOVERY-CUSTODY.json':700000001}
        def list_assets(identifier):
            return [{'id':ids[item], 'name':item, 'size':len(data), 'state':'uploaded'}
                    for item, data in ready.assets.items()]
        ready.list_assets = list_assets
        def update(identifier, body):
            ready.mutations.append('patch')
            self.assertEqual((identifier, body), (400420101, successor['body']))
            ready.release = {**ready.release, 'body':body, 'tag_name':'v0.2.7',
                             'updated_at':'2026-10-07T18:40:00Z', 'assets':[{
                                 'id':619480612, 'name':name, 'size':len(payload), 'state':'uploaded'}]}
            return dict(ready.release)
        ready.update_body = update
        self.v.complete_retained(ready, successor, assets, lambda:None, lambda:None, lambda:None, journal.append,
            prepare_gate=lambda:None, acquire_gate=lambda:None, final_gate=lambda:None,
            transition_gate=lambda:self.v.begin_predecessor_transition(
                ready, successor, predecessor, lambda:None, journal.append,
                assets=assets, prior_controller=authenticator))
        self.assertEqual(ready.mutations, ['patch', 'upload:RECOVERY-CUSTODY.json', 'publish'])
        self.assertNotIn('upload:' + name, ready.mutations)
        self.assertEqual(ready.release['id'], 400420101)
        self.assertEqual(ready.release['tag_name'], 'v0.2.7')
        self.assertEqual(ready.assets[name], payload)
        self.assertEqual([row['outcome'] for row in journal if row['operation'] == 'transition_controller_body'],
                         ['intent', 'response_received_not_yet_accepted', 'accepted'])
        uploaded = [row for row in journal if row['operation'] == 'upload_asset']
        self.assertEqual([row['asset'] for row in uploaded], ['RECOVERY-CUSTODY.json', 'RECOVERY-CUSTODY.json'])
        self.assertEqual([row['outcome'] for row in uploaded], ['intent', 'response_received_not_yet_accepted'])

        for label, body, rows, stored, message in (
                ('starter', prior['body'], [{**embedded, 'state':'starter'}], {name:payload}, 'size or state'),
                ('bytes', prior['body'], [embedded], {name:b'xyz'}, 'replacement forbidden'),
                ('foreign', 'foreign', [embedded], {name:payload}, 'not the approved predecessor'),
                ('detached-with-asset', prior['body'], [embedded], {name:payload}, 'not empty')):
            with self.subTest(label=label):
                current_rows = rows
                if label == 'detached-with-asset':
                    current = provider_for(body, current_rows, stored)
                    current.release['tag_name'] = 'untagged-38320051a3d07f9c500c'
                else:
                    current = provider_for(body, current_rows, stored)
                with self.assertRaisesRegex(ValueError, message):
                    self.v.preflight(current, successor, assets, lambda:None, predecessor=predecessor,
                                     prior_controller=authenticator)
                self.assertEqual(current.mutations, [])


if __name__ == "__main__": unittest.main()
