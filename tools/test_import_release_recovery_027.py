#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Read-only import regression tests; mocked transport is not crypto evidence."""
from __future__ import annotations

import copy
import argparse
from contextlib import ExitStack
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/import_release_recovery_027.sh"
MANIFEST = ROOT / "governance/releases/v0.2.7/RECOVERY-MANIFEST.json"
POLICY = ROOT / "governance/releases/v0.2.7/RETAINED-METADATA-POLICY.json"


def module_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def importer_module():
    source = SCRIPT.read_text().split("# BEGIN RECOVERY_IMPORT_PYTHON\n", 1)[1].split("# END RECOVERY_IMPORT_PYTHON", 1)[0]
    result = types.ModuleType("import_recovery027_test")
    exec(compile(source, str(SCRIPT), "exec"), result.__dict__)
    return result


class ImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.importer = None
        if SCRIPT.is_file():
            cls.importer = importer_module()
        cls.custody = module_file("import_test_custody", ROOT / "tools/verify_release_recovery_027.py")
        cls.fixture_class = module_file("import_test_fixtures", ROOT / "tools/test_release_recovery_027.py").RecoveryTests

    def setUp(self):
        self.assertIsNotNone(self.importer, "the fixed import helper has not been implemented")
        self.i = self.importer
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.manifest = self.custody.load_manifest(MANIFEST)
        fixture = self.fixture_class()
        fixture.manifest = self.manifest
        self.run, self.jobs, metadata = fixture.fixtures()
        self.metadata = {a["id"]: a for a in metadata}

    def reject(self, function, *args):
        with self.assertRaises((self.i.ImportFailure, self.custody.RecoveryError)):
            function(*args)

    def test_retained_dispatcher_rejects_credentials_before_bootstrap(self):
        for credential in ("NODE_AUTH_TOKEN", "NPM_TOKEN", "PYPI_API_TOKEN", "PYPI_TOKEN",
                           "TWINE_PASSWORD", "CARGO_REGISTRY_TOKEN",
                           "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
            result = subprocess.run(["/bin/bash", str(ROOT / "tools/run_release_recovery_027.sh"),
                                     "retained-acceptance"], env={"RELEASE_OPERATION":"recover-0.2.7-retained",
                                     "RELEASE_WORKFLOW_DRY_RUN":"true", credential:"fixture"}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("retained acceptance forbids publication credentials", result.stderr)

    def test_retained_dispatcher_rejects_mode_switch_in_ordinary_operation(self):
        result = subprocess.run(["/bin/bash", str(ROOT / "tools/run_release_recovery_027.sh"), "import"],
                                env={"RELEASE_OPERATION":"recover-0.2.7-retained"}, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("operation and release mode differ", result.stderr)

    def test_full_dispatcher_retained_child_environment_is_allowlisted(self):
        # Execute the complete dispatcher. Only absolute external Git/GPG
        # binaries are replaced by fixture transports; no dispatcher function
        # is extracted, copied around a guard, or short-circuited. This proves
        # routing/environment behavior, never signature acceptance.
        fixtures = self.root / "fixtures"; fixtures.mkdir()
        tool_view = self.root / "view"; tool_view.mkdir()
        (tool_view / ".release-tool-identity").write_text("fixture-closure\n")
        (fixtures / "verify_release_recovery_027.sh").write_text(
            "#!/bin/bash\n[ \"$DRY_RUN\" = false ] && [[ \"$RELEASE_OPERATION\" = recover-0.2.7-retained || \"$RELEASE_OPERATION\" = recover-0.2.7-retained-404 ]]\n")
        (fixtures / 'verify_release_recovery_027.py').write_text('# fixture captured validator\n')
        shutil.copyfile(POLICY,fixtures/'RETAINED-METADATA-POLICY.json')
        (fixtures / "resolve_release_tool_path.sh").write_text(
            "#!/bin/bash\nif [ \"$1\" = --identity ]; then printf fixture-closure; else printf '%s' " + shlex.quote(str(tool_view)) + "; fi\n")
        (fixtures / "import_release_recovery_027.sh").write_text(
            "#!/bin/bash\n[ \"$1\" = retained-acceptance ] || exit 9\n" + shlex.quote(sys.executable) +
            " -I -B -c 'import json,os; print(json.dumps(dict(os.environ)))'\n")
        git = self.root / "fixture-git"
        git.write_text(f"#!{sys.executable}\nimport pathlib,sys\nname=pathlib.Path(sys.argv[-1].split(':',1)[1]).name\nsys.stdout.write((pathlib.Path({str(fixtures)!r})/name).read_text())\n")
        gpg = self.root / "fixture-gpg"
        gpg.write_text(f"#!{sys.executable}\nimport sys\nsys.stdin.read()\n")
        git.chmod(0o700); gpg.chmod(0o700)
        dispatcher = self.root / "dispatcher.sh"
        dispatcher.write_text((ROOT / "tools/run_release_recovery_027.sh").read_text()
                              .replace("/usr/bin/git",str(git)).replace("/usr/bin/gpg",str(gpg)))
        env = {"RELEASE_OPERATION":"recover-0.2.7-retained","RELEASE_WORKFLOW_DRY_RUN":"true",
            "GITHUB_SHA":"a"*40,"GITHUB_WORKSPACE":str(self.root),"GITHUB_REF":"refs/tags/v0.2.7-recover.3",
            "GITHUB_REPOSITORY":"exochain/exochain","GITHUB_SERVER_URL":"https://github.com",
            "RUNNER_TEMP":str(self.root),"RELEASE_PYTHON":sys.executable,"RELEASE_TRUSTED_PYTHON_ROOT":str(self.root),
            "RELEASE_TRUSTED_NODE_ROOT":str(self.root),"EXPECTED_COMMIT_SHA":"a"*40,"TRUSTED_RELEASE_REF":"a"*40,
            "EXPECTED_TAG_OBJECT_SHA":"b"*40,"EXPECTED_TAG_COMMIT_SHA":"a"*40,"RELEASE_TAG":"v0.2.7-recover.3",
            "EXOCHAIN_RELEASE_SIGNING_FINGERPRINT":"A"*40,"EXOCHAIN_RELEASE_SIGNING_PUBLIC_KEY_ASC":"fixture",
            "GITHUB_ACTIONS":"true","GITHUB_EVENT_NAME":"workflow_dispatch","RUNNER_ENVIRONMENT":"github-hosted",
            "GITHUB_WORKFLOW_REF":"exochain/exochain/.github/workflows/release.yml@refs/tags/v0.2.7-recover.3",
            "GITHUB_RUN_ID":"40000000000","GITHUB_RUN_ATTEMPT":"2","GITHUB_JOB":"retained-acceptance",
            "RELEASE_GITHUB_TOKEN":"fixture-read-only","EVIL":"sentinel","PYTHONPATH":"sentinel",
            "GIT_CONFIG_COUNT":"1","RELEASE_RETAINED_DIRECTORY":"attacker","BASH_ENV":"/nonexistent"}
        result = subprocess.run(["/bin/bash","--noprofile","--norc","-p",str(dispatcher)],
                                env=env,capture_output=True,text=True)
        # The operation must remain an explicit argument, never an env switch.
        self.assertNotEqual(result.returncode,0)
        result = subprocess.run(["/bin/bash","--noprofile","--norc","-p",str(dispatcher),"retained-acceptance"],
                                env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        child = json.loads(result.stdout)
        for key in ("EVIL","PYTHONPATH","GIT_CONFIG_COUNT","RELEASE_RETAINED_DIRECTORY","NODE_AUTH_TOKEN","ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
            self.assertNotIn(key,child)
        for key in ("GITHUB_SHA","GITHUB_REF","GITHUB_RUN_ID","GITHUB_RUN_ATTEMPT","GITHUB_JOB","RELEASE_WORKFLOW_DRY_RUN","RELEASE_GITHUB_TOKEN"):
            self.assertEqual(child[key],env[key])
        self.assertEqual(child["DRY_RUN"],"false")
        (fixtures/'recover_github_release_027.py').write_text("import json,os,sys\nassert sys.argv[1:] == ['retained-github']\nprint(json.dumps(dict(os.environ)))\n")
        env.update(GITHUB_JOB='retained-github',RELEASE_WORKFLOW_DRY_RUN='false')
        for name in ('ARTIFACT_ID','ARTIFACT_DIGEST','PRODUCER_JOB_ID','RECEIPT_MEMBERS','RECEIPT_CONTEXT'):
            env['RELEASE_RECEIPT_'+name] = 'direct-fixture-'+name
        result = subprocess.run(['/bin/bash','--noprofile','--norc','-p',str(dispatcher),'retained-github'],
                                env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        child=json.loads(result.stdout)
        self.assertEqual(child['GITHUB_JOB'],'retained-github')
        self.assertNotIn('EVIL',child)
        for name in ('ARTIFACT_ID','ARTIFACT_DIGEST','PRODUCER_JOB_ID','RECEIPT_MEMBERS','RECEIPT_CONTEXT'):
            self.assertEqual(child['RELEASE_RECEIPT_'+name],env['RELEASE_RECEIPT_'+name])
        env['RELEASE_WORKFLOW_DRY_RUN']='true'
        result = subprocess.run(['/bin/bash',str(dispatcher),'retained-github'],env=env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('live current receipt handoff',result.stderr)
        env.update(RELEASE_OPERATION='recover-0.2.7-retained-404',GITHUB_JOB='retained-acceptance',RELEASE_WORKFLOW_DRY_RUN='true')
        result = subprocess.run(['/bin/bash','--noprofile','--norc','-p',str(dispatcher),'retained-acceptance'],
            env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        child=json.loads(result.stdout)
        self.assertEqual(child['RELEASE_OPERATION'],'recover-0.2.7-retained-404')
        self.assertNotIn('NODE_AUTH_TOKEN',child)
        self.assertNotIn('ACTIONS_ID_TOKEN_REQUEST_TOKEN',child)
        env.update(GITHUB_JOB='retained-github',RELEASE_WORKFLOW_DRY_RUN='false')
        result = subprocess.run(['/bin/bash','--noprofile','--norc','-p',str(dispatcher),'retained-github'],
            env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['RELEASE_OPERATION'],'recover-0.2.7-retained-404')
        (fixtures/'RETAINED-METADATA-POLICY.json').unlink()
        result = subprocess.run(['/bin/bash','--noprofile','--norc','-p',str(dispatcher),'retained-github'],
            env=env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)

    def test_retained_transport_has_only_two_archives_and_separate_bound(self):
        record = self.custody.load_retained_record(self.manifest,
            ROOT / "governance/releases/v0.2.7/RETAINED-CUSTODY.json")
        transport = self.i.Transport(self.root, "fixture", self.manifest, record)
        self.assertEqual([item[0] for item in transport.endpoints["archives"]], [10779404529, 10780480598])
        self.reject(transport.archive, self.manifest["artifacts"][0], self.root / "original.zip")
        self.reject(transport._get, self.i.RUN, self.root / "too-large", 147126946, True)

    def test_scoped_original_metadata_status_uses_actual_http_code_only(self):
        record = self.custody.load_retained_record(self.manifest, ROOT / 'governance/releases/v0.2.7/RETAINED-CUSTODY.json')
        policy = self.custody.load_retained_metadata_policy(self.manifest, record, POLICY)
        transport = self.i.Transport(self.root, 'fixture-secret', self.manifest, record, policy=policy)
        selected = policy['unavailable_originals'][0]['id']
        def process(status, body, header_status=None):
            def run(argv, **kwargs):
                Path(argv[argv.index('--output') + 1]).write_bytes(body)
                Path(argv[argv.index('--dump-header') + 1]).write_bytes(
                    f'HTTP/2 {header_status or status}\r\n\r\n'.encode())
                return subprocess.CompletedProcess(argv, 0, str(status).encode(), b'')
            return run
        with patch.object(self.i.subprocess, 'run', side_effect=process(404, b'{"status":200}')):
            observed = transport.original_metadata(selected, self.root / 'missing.json')
        self.assertEqual((observed['status'], observed['variant']), (404, 'unavailable_404'))
        self.assertNotIn('metadata', observed)
        self.assertNotIn('expired', observed)
        self.assertFalse((self.root / 'missing.json').exists())
        selected_ids = {item['id'] for item in policy['unavailable_originals']}
        original_ids = {item['id'] for item in self.manifest['artifacts']+self.manifest['rust_preparation']}
        self.assertEqual((len(selected_ids),len(original_ids-selected_ids)),(4,5))
        for artifact_id in sorted(selected_ids):
            with self.subTest(selected_404=artifact_id), patch.object(self.i.subprocess,'run',
                    side_effect=process(404,b'BODY_SENTINEL')):
                item=transport.original_metadata(artifact_id,self.root/f'selected-{artifact_id}.json')
                self.assertEqual((item['status'],item['variant']),(404,'unavailable_404'))
                self.assertNotIn('metadata',item)
        for artifact_id in sorted(original_ids-selected_ids):
            with self.subTest(unselected_404=artifact_id), patch.object(self.i.subprocess,'run',
                    side_effect=process(404,b'BODY_SENTINEL')):
                self.reject(transport.original_metadata,artifact_id,self.root/f'unselected-{artifact_id}.json')
        with patch.object(self.i.subprocess, 'run', side_effect=process(200, b'{"status":404}')):
            observed = transport.original_metadata(selected, self.root / 'present.json')
        self.assertEqual((observed['status'], observed['variant']), (200, 'present'))
        self.assertEqual(observed['metadata'], {'status':404})
        historical = {'metadata':self.retained_fixture().origin_fixture()[1]['original_metadata']}
        with self.assertRaises(self.custody.RecoveryError):
            self.custody.validate_original_observation(self.manifest,record,policy,historical,observed,
                now=observed['request_finished_at'])
        with patch.object(self.i.subprocess, 'run') as run:
            self.reject(transport.original_metadata, 1, self.root / 'arbitrary.json')
            run.assert_not_called()

    def test_scoped_status_rejects_failures_and_secret_leaks(self):
        record = self.custody.load_retained_record(self.manifest, ROOT / 'governance/releases/v0.2.7/RETAINED-CUSTODY.json')
        policy = self.custody.load_retained_metadata_policy(self.manifest, record, POLICY)
        transport = self.i.Transport(self.root, 'TOKEN_SENTINEL', self.manifest, record, policy=policy)
        selected = policy['unavailable_originals'][0]['id']
        for status in (301, 302, 307, 401, 403, 410, 429, 500):
            with self.subTest(status=status):
                target = self.root / f'bad-{status}.json'
                def process(argv, **kwargs):
                    Path(argv[argv.index('--output') + 1]).write_bytes(b'BODY_SENTINEL')
                    Path(argv[argv.index('--dump-header') + 1]).write_bytes(
                        f'HTTP/2 {status}\r\nLocation: https://example.invalid/?sig=SIGNED_URL_SENTINEL\r\n\r\n'.encode())
                    return subprocess.CompletedProcess(argv, 0, str(status).encode(), b'STDERR_SENTINEL')
                with patch.object(self.i.subprocess, 'run', side_effect=process):
                    with self.assertRaises(self.i.ImportFailure) as error:
                        transport.original_metadata(selected, target)
                self.assertFalse(any(s in str(error.exception) for s in
                    ('TOKEN_SENTINEL','BODY_SENTINEL','SIGNED_URL_SENTINEL','STDERR_SENTINEL')))
                self.assertFalse(target.exists())
        for label, wire, header, body in (
            ('mismatch',b'404',b'HTTP/2 200\r\n\r\n',b'BODY_SENTINEL'),
            ('multiple',b'404',b'HTTP/2 200\r\n\r\nHTTP/2 404\r\n\r\n',b'BODY_SENTINEL'),
            ('malformed',b'404',b'HTTP/2 404\n\n',b'BODY_SENTINEL'),
            ('truncated-status',b'40',b'HTTP/2 404\r\n\r\n',b'BODY_SENTINEL'),
            ('truncated-header',b'404',b'HTTP/2 404\r\n',b'BODY_SENTINEL'),
            ('oversize-header',b'404',b'HTTP/2 404\r\nX-Fill: '+b'x'*65536+b'\r\n\r\n',b'BODY_SENTINEL'),
            ('oversize-body',b'404',b'HTTP/2 404\r\n\r\n',b'x'*(self.i.JSON_LIMIT+1)),
        ):
            with self.subTest(label=label):
                target = self.root / (label+'.json')
                def process(argv, **kwargs):
                    target.write_bytes(body)
                    Path(argv[argv.index('--dump-header')+1]).write_bytes(header)
                    return subprocess.CompletedProcess(argv,0,wire,b'STDERR_SENTINEL')
                with patch.object(self.i.subprocess,'run',side_effect=process):
                    with self.assertRaises(self.i.ImportFailure) as error:
                        transport.original_metadata(selected,target)
                self.assertFalse(target.exists())
                self.assertNotIn('STDERR_SENTINEL',str(error.exception))
        with patch.object(self.i.subprocess,'run',side_effect=subprocess.TimeoutExpired(['/usr/bin/curl'],250)):
            with self.assertRaises(self.i.ImportFailure) as error:
                transport.original_metadata(selected,self.root/'timeout.json')
        self.assertEqual(str(error.exception),'bounded provider GET failed')
        for endpoint in [transport.endpoints['run'],transport.endpoints['jobs'][0],
                         record['payload']['metadata']['url'],record['custody']['metadata']['url'],
                         self.i.API+'/artifacts/777',transport.endpoints['rust'][0][1]]:
            with self.subTest(endpoint=endpoint):
                def process(argv, **kwargs):
                    Path(argv[argv.index('--output')+1]).write_bytes(b'BODY_SENTINEL')
                    Path(argv[argv.index('--dump-header')+1]).write_bytes(b'HTTP/2 404\r\n\r\n')
                    return subprocess.CompletedProcess(argv,0,b'404',b'')
                with patch.object(self.i.subprocess,'run',side_effect=process):
                    self.reject(transport.get,endpoint,self.root/'strict.json',self.i.JSON_LIMIT)
        def missing_archive(argv, **kwargs):
            Path(argv[argv.index('--output')+1]).write_bytes(b'BODY_SENTINEL')
            Path(argv[argv.index('--dump-header')+1]).write_bytes(b'HTTP/2 404\r\n\r\n')
            return subprocess.CompletedProcess(argv,0,b'404',b'STDERR_SENTINEL')
        with patch.object(self.i.subprocess,'run',side_effect=missing_archive):
            self.reject(transport.archive,record['payload']['metadata'],self.root/'strict-archive.zip')
            self.reject(transport.receipt_archive,{'id':444,'size_in_bytes':100,
                'url':self.i.API+'/artifacts/444',
                'archive_download_url':self.i.API+'/artifacts/444/zip'},self.root/'strict-receipt.zip')
        self.assertFalse((self.root/'strict-archive.zip').exists())
        self.assertFalse((self.root/'strict-receipt.zip').exists())

    def test_controls_before_and_after_expensive_checks_are_exact(self):
        record, historical_input = self.retained_fixture().origin_fixture()
        policy = self.custody.load_retained_metadata_policy(self.manifest, record, POLICY)
        events = []
        def controls(*args, phase):
            events.append('controls-' + phase)
            return {'original_run':historical_input['original_run'], 'original_jobs':historical_input['original_jobs'],
                    'retaining_run':historical_input['retaining_run'], 'retaining_jobs':historical_input['retaining_jobs'],
                    'retained_metadata':[record[k]['metadata'] for k in ('payload','custody')],
                    'observed_at':historical_input['observed_at']}
        def observations(*args, phase):
            events.append('observations-' + phase)
            return {'observed_at':historical_input['observed_at'], 'records':[]}
        transport = types.SimpleNamespace(archive=lambda *args:events.append('archive'))
        evidence=self.root/'sequence'; evidence.mkdir()
        archives=self.root/'archives'; archives.mkdir()
        with patch.object(self.i,'fetch_retained_controls',side_effect=controls), \
             patch.object(self.i,'fetch_original_observation_pass',side_effect=observations), \
             patch.object(self.custody,'verify_retained_origin',side_effect=lambda *a,**k: {'original_vector':[]} ), \
             patch.object(self.custody,'verify_retained_transport',return_value={}):
            self.i.acquire_retained(self.manifest,record,self.custody,transport,evidence,archives,
                self.root/'candidate',self.root/'workflow',policy=policy,observer={'job_id':1})
        self.assertEqual(events[:2], ['controls-acquisition-start','observations-acquisition-before'])
        self.assertEqual(events[-2:], ['observations-acquisition-after','controls-acquisition-end'])
        self.assertEqual(events.count('archive'),2)
        self.assertTrue((evidence/'acquisition-origin-input.json').is_file())

    def test_real_acquisition_and_finalizer_bind_controls_and_vector(self):
        fixture = self.retained_fixture()
        record, expected = fixture.origin_v2_fixture((10518086890,))
        policy = self.custody.load_retained_metadata_policy(self.manifest, record, POLICY)
        old = fixture.origin_fixture()[1]
        transport = self.i.Transport(self.root, 'fixture', self.manifest, record, policy=policy)
        evidence = self.root/'actual-sequence'; evidence.mkdir()
        archives = self.root/'actual-archives'; archives.mkdir()
        events=[]
        def get(url,path,limit):
            events.append('control:'+path.name)
            if url == transport.endpoints['run']: value=old['original_run']
            elif url == transport.endpoints['jobs'][0]: value=old['original_jobs']
            elif url == transport.endpoints['retaining_run']: value=old['retaining_run']
            elif url == transport.endpoints['retaining_jobs'][0]: value=old['retaining_jobs']
            else:
                value=next(record[k]['metadata'] for k in ('payload','custody') if url==record[k]['metadata']['url'])
            path.write_text(json.dumps(value))
        observations = (expected['observations']['before']['records']+
                        expected['observations']['after']['records'])
        def original(artifact_id,path):
            item=copy.deepcopy(observations[len([event for event in events if event.startswith('original:')])])
            self.assertEqual(item['id'],artifact_id)
            events.append('original:'+str(artifact_id))
            return item
        def archive(metadata,path):
            events.append('archive:'+str(metadata['id']))
            path.write_bytes(b'fixture boundary')
        transport.get,transport.original_metadata,transport.archive=get,original,archive
        clocks=iter(('2026-09-25T22:00:00Z','2026-09-25T22:01:20Z',
                     '2026-09-25T22:01:40Z','2026-09-25T22:02:00Z'))
        with patch.object(self.i,'utc_now',side_effect=lambda:next(clocks)), \
             patch.object(self.custody,'verify_retained_transport',return_value={'retained_archives_verified':2}):
            result,_=self.i.acquire_retained(self.manifest,record,self.custody,transport,evidence,archives,
                self.root/'candidate',self.root/'workflow',policy=policy,observer=expected['observations']['observer'])
        self.assertEqual(result['schema'],'exochain-retained-origin-result-027/v2')
        self.assertEqual(events.index('control:run.json') < events.index('original:10517457207'),True)
        self.assertEqual(events.index('archive:10779404529') > events.index('original:10518128532'),True)
        self.assertEqual(len([event for event in events if event.startswith('original:')]),18)
        initial=self.custody.load_json(evidence/'acquisition-origin-input.json','acquisition fixture')
        self.assertEqual(initial['observations'],expected['observations'])
        later=fixture.observation_fixture((10518086890,),offset_seconds=60)['after']['records']
        followup=[]
        def later_original(artifact_id,path):
            item=copy.deepcopy(later[len(followup)])
            self.assertEqual(item['id'],artifact_id)
            followup.append(artifact_id)
            return item
        transport.original_metadata=later_original
        clocks=iter(('2026-09-25T22:02:40Z','2026-09-25T22:03:00Z'))
        with patch.object(self.i,'utc_now',side_effect=lambda:next(clocks)):
            finalized=self.i.finalize_retained_observations(self.manifest,record,policy,self.custody,transport,
                evidence,archives/'10780480598.zip',self.root/'workflow',
                observer=expected['observations']['observer'],initial_input=initial,phase='producer-final')
        self.assertEqual(finalized['observations']['after']['records'],later)
        self.assertEqual(len(followup),9)
        self.assertEqual(self.custody.load_json(evidence/'acquisition-origin-input.json','acquisition fixture'),initial)
        self.assertTrue((evidence/'producer-final-origin-input.json').is_file())

    def test_original_vector_transition_prevents_receipt_output(self):
        fixture=self.retained_fixture()
        record, initial=fixture.origin_v2_fixture((10518086890,))
        policy=self.custody.load_retained_metadata_policy(self.manifest,record,POLICY)
        altered=copy.deepcopy(fixture.observation_fixture((10518086890,),offset_seconds=60)['after']['records'])
        target=next(item for item in altered if item['id']==10518086890)
        historical=self.custody.read_historical_custody(self.manifest,record,'fixture')['metadata']
        target.update(status=200,variant='present',metadata=dict(next(item for item in historical if item['id']==10518086890),expired=True))
        evidence=self.root/'transition'; evidence.mkdir()
        controls=copy.deepcopy(initial['controls_after']); controls['observed_at']='2026-09-25T22:03:00Z'
        requests=iter(altered)
        transport=types.SimpleNamespace(original_metadata=lambda artifact_id,path:next(requests))
        with patch.object(self.i,'utc_now',return_value='2026-09-25T22:02:40Z'), \
             patch.object(self.i,'fetch_retained_controls',return_value=controls):
            with self.assertRaisesRegex(self.custody.RecoveryError,'original availability transition'):
                self.i.finalize_retained_observations(self.manifest,record,policy,self.custody,transport,
                    evidence,self.root/'historical.zip',self.root/'workflow',
                    observer=initial['observations']['observer'],initial_input=initial,phase='producer-final')
        self.assertFalse((evidence/'producer-final-origin-input.json').exists())
        self.assertFalse((evidence/'current-receipts').exists())

    def test_capture_observer_requires_actual_unique_in_progress_job(self):
        fixture=self.retained_fixture()
        _,_,envelope,_=fixture.receipt_fixture()
        context=envelope['context']
        run_url=self.i.API+f"/runs/{context['run_id']}/attempts/{context['run_attempt']}"
        jobs=copy.deepcopy(envelope['current_jobs'])
        job=next(item for item in jobs['jobs'] if item['id']==context['producer_job_id'])
        job.update(status='in_progress',conclusion=None,completed_at=None)
        environment={'GITHUB_JOB':'retained-acceptance','GITHUB_RUN_ID':str(context['run_id']),
            'GITHUB_RUN_ATTEMPT':str(context['run_attempt']),'GITHUB_SHA':context['controller_sha'],
            'GITHUB_REF':context['controller_ref'],'EXPECTED_TAG_OBJECT_SHA':context['controller_tag_object']}
        for fault in (None,'wrong-attempt','duplicate','completed'):
            evidence=self.root/f'observer-{fault}'; evidence.mkdir()
            current=copy.deepcopy(jobs)
            if fault=='wrong-attempt': current['jobs'][0]['run_attempt']=1
            if fault=='duplicate':
                extra=copy.deepcopy(job); extra['id']+=1
                current['jobs'].append(extra);current['total_count']+=1
            if fault=='completed':
                for item in current['jobs']:
                    if item['id']==job['id']: item.update(status='completed',conclusion='success')
            def get(url,path,limit):
                path.write_text(json.dumps(envelope['current_run'] if url==run_url else current))
            transport=types.SimpleNamespace(authenticated=set(),get=get)
            with patch.dict(self.i.os.environ,environment,clear=True):
                if fault is None:
                    observer=self.i.capture_observer(self.custody,transport,self.root,evidence,'retained-acceptance')
                    self.assertEqual(observer['job_id'],context['producer_job_id'])
                    self.assertNotIn('completed_at',observer)
                else:
                    self.reject(self.i.capture_observer,self.custody,transport,self.root,evidence,'retained-acceptance')

    def test_controls_reject_missing_duplicate_and_expired_positive_evidence(self):
        fixture=self.retained_fixture()
        record,old=fixture.origin_fixture()
        for fault in ('original-omission','original-duplicate','retaining-omission','retaining-duplicate',
                      'payload-drift','payload-expiry-equality','custody-drift','custody-expiry-equality'):
            current_record=copy.deepcopy(record)
            observed='2026-09-25T22:00:00Z'
            if fault=='payload-expiry-equality': observed=record['payload']['metadata']['expires_at']
            if fault=='custody-expiry-equality':
                # Isolated helper boundary: the real fixed payload expires first.
                # A synthetic later payload permits reaching the custody equality branch.
                current_record['payload']['metadata']['expires_at']='2026-10-24T00:00:00Z'
                observed=record['custody']['metadata']['expires_at']
            responses={self.i.RUN:copy.deepcopy(old['original_run']),
                self.i.RUN+'/jobs?per_page=100&page=1':copy.deepcopy(old['original_jobs'])}
            transport=self.i.Transport(self.root,'fixture',self.manifest,current_record)
            responses[transport.endpoints['retaining_run']]=copy.deepcopy(old['retaining_run'])
            responses[transport.endpoints['retaining_jobs'][0]]=copy.deepcopy(old['retaining_jobs'])
            for kind in ('payload','custody'):
                metadata=current_record[kind]['metadata']
                responses[metadata['url']]=copy.deepcopy(metadata)
            original_jobs=responses[self.i.RUN+'/jobs?per_page=100&page=1']
            retaining_jobs=responses[transport.endpoints['retaining_jobs'][0]]
            if fault=='original-omission': original_jobs['jobs'].pop()
            if fault=='original-duplicate': original_jobs['jobs'][1]['id']=original_jobs['jobs'][0]['id']
            if fault=='retaining-omission': retaining_jobs['jobs'].pop()
            if fault=='retaining-duplicate': retaining_jobs['jobs'][1]['id']=retaining_jobs['jobs'][0]['id']
            if fault=='payload-drift': responses[current_record['payload']['metadata']['url']]['digest']='sha256:'+'0'*64
            if fault=='custody-drift': responses[current_record['custody']['metadata']['url']]['digest']='sha256:'+'0'*64
            evidence=self.root/('controls-'+fault);evidence.mkdir()
            def get(url,path,limit): path.write_text(json.dumps(responses[url]))
            transport.get=get
            with patch.object(self.i,'utc_now',return_value=observed):
                with self.assertRaises((self.i.ImportFailure,self.custody.RecoveryError)):
                    self.i.fetch_retained_controls(self.manifest,current_record,self.custody,transport,
                        evidence,phase='acquisition-start')
            self.assertFalse((evidence/'acquisition-start-controls/controls.json').exists())

    def test_python_retained_bootstrap_has_explicit_accept_and_no_credentials(self):
        helper = ROOT / "tools/recover_release_python_027.sh"
        for operation in ('recover-0.2.7-retained','recover-0.2.7-retained-404'):
            for dry in ("true", "false"):
                for credential in ("PYPI_API_TOKEN", "NODE_AUTH_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
                    result = subprocess.run(["/bin/bash", str(helper), "accept"], env={
                        "RELEASE_OPERATION":operation, "RELEASE_WORKFLOW_DRY_RUN":dry,
                        credential:"fixture"}, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("publication credentials must be absent", result.stderr)
            result = subprocess.run(["/bin/bash", str(helper), "preflight"],
                env={"RELEASE_OPERATION":operation}, capture_output=True, text=True)
            self.assertIn("operation and release mode differ", result.stderr)

    def retained_fixture(self):
        fixtures = module_file("retained_import_fixtures", ROOT / "tools/test_release_recovery_027.py")
        fixture = fixtures.RetainedTests()
        fixture.v, fixture.manifest = self.custody, self.manifest
        fixture.record_path = ROOT / "governance/releases/v0.2.7/RETAINED-CUSTODY.json"
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_current_receipt_transport_uses_only_exact_id_and_small_bound(self):
        record = self.custody.load_retained_record(self.manifest, ROOT / 'governance/releases/v0.2.7/RETAINED-CUSTODY.json')
        transport = self.i.Transport(self.root,'fixture',self.manifest,record)
        self.assertTrue(callable(getattr(transport,'receipt_archive',None)), 'receipt download API absent')
        metadata = {'id':444,'size_in_bytes':100,'url':self.i.API+'/artifacts/444',
            'archive_download_url':self.i.API+'/artifacts/444/zip'}
        calls=[]
        def get(url,path,limit,auth):
            calls.append((url,limit,auth)); path.write_bytes(b'x'*100); return 200,[]
        with patch.object(transport,'_get',side_effect=get):
            transport.receipt_archive(metadata,self.root/'receipt.zip')
            self.assertEqual(calls,[(self.i.API+'/artifacts/444/zip',100,True)])
            for key,value in [('id',True),('size_in_bytes',1048577),('archive_download_url','https://attacker.invalid/zip')]:
                with self.subTest(key=key):
                    self.reject(transport.receipt_archive,dict(metadata,**{key:value}),self.root/'bad.zip')
            self.assertEqual(len(calls),1)

    def test_retained_producer_github_preflight_cannot_mutate(self):
        self.assertTrue(callable(getattr(self.i,'retained_github_preflight',None)), 'producer GitHub preflight absent')
        helper=module_file('producer_github_preflight',ROOT/'tools/recover_github_release_027.py')
        record=self.custody.load_retained_record(self.manifest,ROOT/'governance/releases/v0.2.7/RETAINED-CUSTODY.json')
        publications=self.custody.load_publications(self.manifest,ROOT/'governance/releases/v0.2.7/PUBLICATION-IDENTITIES.json')
        events=[]
        policy=self.custody.load_retained_metadata_policy(self.manifest,record,POLICY)
        class Provider:
            def lookup(self): events.append('lookup'); return None
            def create(self,*args): raise AssertionError('preflight create')
            def upload(self,*args): raise AssertionError('preflight upload')
            def publish(self,*args): raise AssertionError('preflight publish')
        for selected in (None,policy):
            events.clear()
            evidence=self.root/('github-v2' if selected else 'github-v1');evidence.mkdir()
            expected_values=[]
            original_preflight=helper.preflight
            def recorded_preflight(provider,expected,assets,rebind):
                expected_values.append(expected)
                return original_preflight(provider,expected,assets,rebind)
            with patch.object(self.i,'load_module',return_value=helper),patch.object(helper,'GitHub',return_value=Provider()), \
                 patch.object(helper,'release_assets',return_value={'fixture':b'x'}), \
                 patch.object(helper,'preflight',side_effect=recorded_preflight), \
                 patch.object(self.custody,'verify_files',side_effect=lambda *args:events.append('files')), \
                 patch.dict(self.i.os.environ,{'GITHUB_SHA':'a'*40,'GITHUB_REF':'refs/tags/v0.2.7-recover.3','RELEASE_GITHUB_TOKEN':'fixture'},clear=True):
                self.i.retained_github_preflight(self.root,self.custody,self.manifest,publications,record,self.root,evidence,
                    policy=selected)
            self.assertEqual(events,['files','lookup','files'])
            self.assertIs(json.loads((evidence/'github-preflight.json').read_text())['mutation_attempted'],False)
            if selected:
                self.assertIn(self.custody.RETAINED_METADATA_POLICY_SHA256,expected_values[0]['body'])
                self.assertIn('Selected original artifact metadata may be unavailable',expected_values[0]['body'])

    def test_retained_acquisition_rechecks_metadata_and_never_exposes_bad_bytes(self):
        record, origin = self.retained_fixture().origin_fixture()
        for fault in ("before", "after", "archive"):
            directory = self.root / fault; directory.mkdir()
            evidence = directory / "evidence"; evidence.mkdir()
            archives = directory / "archives"; archives.mkdir()
            candidate = directory / "candidate"
            transport = self.i.Transport(directory, "fixture", self.manifest, record)
            data = {self.i.RUN:origin["original_run"], self.i.RUN+"/jobs?per_page=100&page=1":origin["original_jobs"],
                transport.endpoints["retaining_run"]:origin["retaining_run"],
                transport.endpoints["retaining_jobs"][0]:origin["retaining_jobs"]}
            data.update({f"{self.i.API}/artifacts/{m['id']}":m for m in origin["original_metadata"]})
            data.update({record[k]["metadata"]["url"]:record[k]["metadata"] for k in ("payload","custody")})
            calls, downloads = [], []
            def get(url, path, limit):
                self.assertEqual(limit, self.i.JSON_LIMIT)
                calls.append(url)
                value = copy.deepcopy(data[url])
                if fault in path.name and path.name.startswith("retained-payload"):
                    value["digest"] = "sha256:" + "0"*64
                path.write_text(json.dumps(value))
            def archive(metadata, path):
                downloads.append(metadata["id"])
                path.write_bytes(b"not a retained archive")
            transport.get, transport.archive = get, archive
            with patch.object(self.i, "utc_now", return_value=origin["observed_at"]):
                self.reject(self.i.acquire_retained, self.manifest, record, self.custody, transport,
                            evidence, archives, candidate, directory / "workflow")
            self.assertFalse(candidate.exists())
            self.assertEqual(downloads, [] if fault == "before" else [10779404529,10780480598])
            self.assertFalse(any("/zip" in url for url in calls))

    def test_current_receipts_match_exact_task_one_schema_and_refuse_failed_native(self):
        record, publications, envelope, expected = self.retained_fixture().receipt_fixture()
        origin = self.custody.verify_retained_origin(self.manifest, record, envelope["origin"], "fixture", "fixture")
        summary = {"origin":origin,"rust":{"version":"0.2.7","crates_verified":32},
                   "files":{"files_verified":40},"retained_transport":{"retained_archives_verified":2,
                       "payload_files_verified":40,"original_zip_envelopes_verified":0},
                   "packages":{},"native_attestations":[]}
        for artifact in self.manifest["artifacts"]:
            if artifact["lane"].startswith("native-"):
                summary["packages"][artifact["lane"]] = {"libraries":29,"executables":0}
                summary["native_attestations"].append({"lane":artifact["lane"],"verified_attestations":1,
                    "original_invocation":self.manifest["origin"]["native_attestation_invocation"]})
        for failed in ("native","files",False):
            evidence = self.root / str(failed); evidence.mkdir()
            identity = {key:True for key in ("controller_signature_verified","product_signature_verified","retaining_signature_verified")}
            (evidence / "identity-after.json").write_text(json.dumps(identity))
            changed = copy.deepcopy(summary)
            if failed:
                if failed == "native": changed["native_attestations"][0]["verified_attestations"] = 0
                else: changed["files"]["files_verified"] = 39
                self.reject(self.i.create_retained_receipts,self.custody,self.manifest,record,envelope["context"],changed,
                    expected["acceptance-receipt.json"]["results"]["publications"],evidence)
                self.assertFalse((evidence / "current-receipts").exists())
            else:
                members = self.i.create_retained_receipts(self.custody,self.manifest,record,envelope["context"],changed,
                    expected["acceptance-receipt.json"]["results"]["publications"],evidence)
                self.assertEqual([m["path"] for m in members], ["custody-receipt.json","acceptance-receipt.json"])
                for name, receipt in expected.items():
                    path = evidence / "current-receipts" / name
                    self.assertEqual(self.custody.load_json(path,"receipt"),receipt)
                    self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_v2_receipts_preserve_producer_observations_in_both_members(self):
        fixture=self.retained_fixture()
        record,publications,policy,envelope,expected=fixture.v2_receipt_fixture()
        origin=self.custody.verify_retained_origin(self.manifest,record,envelope['origin'],'fixture','fixture',policy=policy)
        summary={'origin':origin,'rust':{'version':'0.2.7','crates_verified':32},
                 'files':{'files_verified':40},'retained_transport':{'retained_archives_verified':2,
                 'payload_files_verified':40,'original_zip_envelopes_verified':0},
                 'packages':{},'native_attestations':[]}
        for artifact in self.manifest['artifacts']:
            if artifact['lane'].startswith('native-'):
                summary['packages'][artifact['lane']]={'libraries':29,'executables':0}
                summary['native_attestations'].append({'lane':artifact['lane'],'verified_attestations':1,
                    'original_invocation':self.manifest['origin']['native_attestation_invocation']})
        evidence=self.root/'v2-receipts';evidence.mkdir()
        (evidence/'identity-after.json').write_text(json.dumps({key:True for key in
            ('controller_signature_verified','product_signature_verified','retaining_signature_verified')}))
        members=self.i.create_retained_receipts(self.custody,self.manifest,record,envelope['context'],summary,
            expected['acceptance-receipt.json']['results']['publications'],evidence,policy=policy)
        self.assertEqual(len(members),2)
        for name,receipt in expected.items():
            actual=self.custody.load_json(evidence/'current-receipts'/name,'v2 receipt')
            self.assertEqual(actual,receipt)
            self.assertEqual(actual['original_observations'],origin['observations'])

    def test_aggregate_requires_each_fresh_child_exit_and_complete_success_result(self):
        publications = self.custody.load_publications(self.manifest,ROOT / "governance/releases/v0.2.7/PUBLICATION-IDENTITIES.json")
        for operation in ('recover-0.2.7-retained','recover-0.2.7-retained-404'):
            for fault in (None,"wasm-exit","llm-result","sdk-history","sdk-readback","python-crypto","python-missing"):
                runner = self.root / (operation+'-'+str(fault)); runner.mkdir()
                capture = runner / "capture"; capture.mkdir()
                evidence = capture / "evidence"; evidence.mkdir()
                events = []
                def child(argv, output, environment=None, timeout=240, bounded=False):
                    name = argv[-2] if argv[-1] == "retained-accept" else "python"
                    events.append(name)
                    self.assertEqual(environment["RELEASE_OPERATION"],operation)
                    self.assertNotIn("NODE_AUTH_TOKEN",environment)
                    self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN",environment)
                    if fault == name+"-exit":
                        raise self.i.ImportFailure("actual fixture child exit nonzero")
                    output.write_text("")
                    destination = runner / "exochain-recovery-receipts" / (name if name == "python" else "npm-"+name)
                    destination.mkdir(parents=True)
                    result = {"operation":operation,"controller_commit":"a"*40,
                        "controller_ref":"refs/tags/v0.2.7-recover.3","exit_code":0,"acceptance_verified":True,"mutation_attempted":False}
                    if name == "python":
                        result.update(schema="exochain-python-retained-acceptance/v1",files=[{
                            "filename":Path(p["file"]["path"]).name,"sha256":p["file"]["sha256"],"source":p["source"],
                            "public_bytes_verified":True,"crypto_verified":True,"exit_code":0,"mutation_attempted":False}
                            for p in publications["publications"][3:]])
                        if fault == "python-crypto": result["files"][1]["crypto_verified"] = False
                        if fault == "python-missing": result["files"].pop()
                    else:
                        p, = [p for p in publications["publications"] if p["id"] == name]
                        result.update(package=p["package"],version="0.2.7",tarball_sha256=p["file"]["sha256"],
                            provenance_commit=p["source"]["commit"],provenance_ref=p["source"]["ref"],
                            upload_exit_code=None,mutation_outcome="verified",phase="finished")
                        if fault == name+"-result": result["acceptance_verified"] = False
                        if fault == name+"-history": result["controller_commit"] = self.i.PRODUCT_SHA
                        if fault == name+'-readback':
                            result.pop('acceptance_verified')
                            result['readback_verified']=True
                        for file in ("registry.json","audit.json"):
                            (destination / file).write_text('{}')
                    (destination / "result.json").write_text(json.dumps(result))
                with patch.dict(self.i.os.environ,{"GITHUB_SHA":"a"*40,"GITHUB_REF":"refs/tags/v0.2.7-recover.3",
                     "RELEASE_OPERATION":operation},clear=True),patch.object(self.i,"command",side_effect=child):
                    args = (self.custody,publications,runner / "candidate",capture,evidence,runner)
                    if fault:
                        self.reject(self.i.accept_publications,*args)
                    else:
                        result = self.i.accept_publications(*args)
                        self.assertEqual([p["id"] for p in result],["wasm","llm","sdk","python-wheel","python-sdist"])
                        self.assertEqual(events,["wasm","llm","sdk","python"])
                self.assertFalse((evidence / "current-receipts").exists())

    def test_public_child_diagnostics_are_bounded_even_when_command_fails(self):
        for stream in ("stdout","stderr"):
            output = self.root / (stream+".txt")
            with self.assertRaises(self.i.ImportFailure):
                self.i.command([sys.executable,"-I","-B","-c",
                    "import sys; sys."+stream+".write('x'*(1024*1024+1))"],output,bounded=True)
            self.assertLessEqual(output.stat().st_size,1024*1024)
            self.assertLessEqual(Path(str(output)+".stderr").stat().st_size,1024*1024)

    def test_public_diagnostic_overflow_stops_before_long_running_child_finishes(self):
        for stream in ("stdout", "stderr"):
            output = self.root / (stream+"-overflow.txt")
            finished = self.root / (stream+"-finished")
            code = ("import pathlib,sys,time; sys."+stream+".write('x'*(1024*1024+1)); "
                    "sys."+stream+".flush(); time.sleep(3); pathlib.Path(sys.argv[1]).touch()")
            started = time.monotonic()
            with self.assertRaises(self.i.ImportFailure):
                self.i.command([sys.executable,"-I","-B","-c",code,str(finished)],output,
                               timeout=10,bounded=True)
            self.assertLess(time.monotonic()-started,2.5)
            self.assertFalse(finished.exists(), "overflow waited for the long-running child to finish")
            self.assertLessEqual(output.stat().st_size,1024*1024)
            self.assertLessEqual(Path(str(output)+".stderr").stat().st_size,1024*1024)

    def test_public_timeout_stops_descendant_writes_after_return(self):
        output = self.root / "descendant.txt"
        error_output = Path(str(output)+".stderr")
        heartbeat = self.root / "descendant-heartbeat"
        pid_path = self.root / "descendant-pid"
        child_code = ("import os,pathlib,sys,time\n"
                      "for n in range(250):\n"
                      " os.write(1,b'out\\n'); os.write(2,b'err\\n')\n"
                      " pathlib.Path(sys.argv[1]).write_text(str(n))\n"
                      " time.sleep(0.02)\n")
        parent_code = ("import pathlib,subprocess,sys,time; "
                       "child=subprocess.Popen([sys.executable,'-I','-B','-c',sys.argv[1],sys.argv[2]]); "
                       "pathlib.Path(sys.argv[3]).write_text(str(child.pid)); time.sleep(10)")
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.i.command([sys.executable,"-I","-B","-c",parent_code,child_code,
                    str(heartbeat),str(pid_path)],output,timeout=0.75,bounded=True)
            self.assertTrue(heartbeat.exists(), "descendant did not actually execute")
            before = (output.stat().st_size,error_output.stat().st_size,heartbeat.read_text())
            time.sleep(0.25)
            after = (output.stat().st_size,error_output.stat().st_size,heartbeat.read_text())
            self.assertEqual(after,before, "a timed-out descendant kept writing after command returned")
            self.assertLessEqual(after[0],1024*1024)
            self.assertLessEqual(after[1],1024*1024)
        finally:
            # RED must not leave the deliberately orphaned fixture running.
            if pid_path.exists():
                try:
                    os.kill(int(pid_path.read_text()),signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_public_collector_drains_both_pipes_without_deadlock(self):
        output = self.root / "both-pipes.txt"
        code = "import os\nfor _ in range(8):\n os.write(1,b'o'*65536); os.write(2,b'e'*65536)\n"
        self.i.command([sys.executable,"-I","-B","-c",code],output,timeout=5,bounded=True)
        self.assertEqual(output.read_bytes(),b'o'*(512*1024))
        self.assertEqual(Path(str(output)+".stderr").read_bytes(),b'e'*(512*1024))

    def test_public_timeout_applies_after_both_pipes_close(self):
        output = self.root / "closed-pipes.txt"
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            self.i.command([sys.executable,"-I","-B","-c",
                "import os,time; os.close(1); os.close(2); time.sleep(10)"],output,timeout=0.2,bounded=True)
        self.assertLess(time.monotonic()-started,2)
        self.assertEqual(output.read_bytes(),b'')
        self.assertEqual(Path(str(output)+".stderr").read_bytes(),b'')

    def test_current_context_uses_authoritative_numeric_job_and_pinned_runtimes(self):
        _, _, envelope, _ = self.retained_fixture().receipt_fixture()
        context = envelope["context"]
        capture = self.root / "capture"; capture.mkdir()
        shutil.copyfile(ROOT / "tools/verify_release_recovery_027.py",capture / "verify_release_recovery_027.py")
        environment = {"GITHUB_SHA":context["controller_sha"],"GITHUB_REF":context["controller_ref"],
            "EXPECTED_TAG_OBJECT_SHA":context["controller_tag_object"],"GITHUB_RUN_ID":str(context["run_id"]),
            "GITHUB_RUN_ATTEMPT":str(context["run_attempt"]),"GITHUB_JOB":"retained-acceptance",
            "RELEASE_WORKFLOW_DRY_RUN":"true","TRUSTED_RELEASE_PATH":str(self.root),
            "RELEASE_PRODUCER_JOB_ID":"999", "RELEASE_GITHUB_TOKEN":"fixture-secret"}
        run_url = self.i.API + f"/runs/{context['run_id']}/attempts/{context['run_attempt']}"
        for fault in (None,"attempt","duplicate","runtime"):
            evidence = self.root / str(fault); evidence.mkdir()
            jobs = copy.deepcopy(envelope["current_jobs"])
            jobs["jobs"][0].update(status="in_progress",conclusion=None,completed_at=None)
            if fault == "attempt": jobs["jobs"][0]["run_attempt"] = 1
            if fault == "duplicate":
                extra = copy.deepcopy(jobs["jobs"][0]); extra["id"] += 1
                jobs["jobs"].append(extra); jobs["total_count"] += 1
            def get(url,path,limit):
                value = envelope["current_run"] if url == run_url else jobs
                self.assertIn(url,(run_url,run_url+"/jobs?per_page=100&page=1"))
                path.write_text(json.dumps(value))
            transport = types.SimpleNamespace(authenticated=set(),get=get)
            def version(argv,**kwargs):
                self.assertNotIn("RELEASE_GITHUB_TOKEN",kwargs["env"])
                if argv[0] == "python": value = b"3.13.7\n"
                elif argv[0] == "/usr/bin/gh": value = b"gh version 2.80.0 (fixture)\n"
                elif "npm" in argv[1]: value = b"11.12.1\n"
                else: value = b"v24.15.1\n" if fault == "runtime" else b"v24.15.0\n"
                return subprocess.CompletedProcess(argv,0,value,b"")
            with patch.dict(self.i.os.environ,environment,clear=True),patch.object(self.i.subprocess,"run",side_effect=version):
                if fault in ("attempt","duplicate"):
                    self.reject(self.i.current_receipt_context,self.custody,transport,capture,evidence,"python","node")
                else:
                    actual = self.i.current_receipt_context(self.custody,transport,capture,evidence,"python","node")
                    self.assertEqual(actual["producer_job_id"],context["producer_job_id"])
                    if fault == "runtime":
                        record, origin = self.retained_fixture().origin_fixture()
                        verified = self.custody.verify_retained_origin(self.manifest,record,origin,"fixture","fixture")
                        with self.assertRaises(ValueError):
                            self.custody.retained_receipt_bindings(self.manifest,record,actual,verified)
                    else:
                        self.assertEqual(actual["runtime_versions"],context["runtime_versions"])

    def test_endpoint_allowlist_is_fixed_to_attempt_one_and_reviewed_ids(self):
        urls = self.i.fixed_endpoints(self.manifest)
        self.assertIn("https://api.github.com/repos/exochain/exochain/actions/runs/35257955565/attempts/1", urls["run"])
        self.assertEqual(len(urls["metadata"]), 9)
        self.assertEqual(len(urls["archives"]), 7)
        self.assertEqual(len(urls["rust"]), 32)
        transport = self.i.Transport(self.root, "unit_test_readonly_token", self.manifest)
        for url in ["https://attacker.invalid/", urls["run"].replace("attempts/1", "attempts/2"),
                    urls["run"].replace("exochain/exochain", "attacker/exochain"),
                    "https://api.github.com/repos/exochain/exochain/actions/artifacts/1",
                    "https://crates.io/api/v1/crates/exochain-core/0.2.8"]:
            self.reject(transport.get, url, self.root / "rejected", 1024)
        self.assertFalse((self.root / "rejected").exists())

    def test_curl_github_auth_is_stdin_only_and_public_reads_have_no_credentials(self):
        # Deliberately synthetic RFC 6750 section 2.1 punctuation, not a secret.
        token = "unit.test-readonly_token~with+padding/=="
        transport = self.i.Transport(self.root, token, self.manifest)
        calls = []

        def process(argv, **kwargs):
            calls.append((argv, kwargs))
            Path(argv[argv.index("--output") + 1]).write_bytes(b"{}")
            Path(argv[argv.index("--dump-header") + 1]).write_text("HTTP/2 200\r\n\r\n")
            return subprocess.CompletedProcess(argv, 0, b"200", b"")

        with patch.object(self.i.subprocess, "run", side_effect=process):
            transport.get(self.i.fixed_endpoints(self.manifest)["run"], self.root / "run.json", 1024)
            transport.get(self.i.fixed_endpoints(self.manifest)["rust"][0][1], self.root / "crate.json", 1024)
        self.assertEqual(len(calls), 2)
        for argv, kwargs in calls:
            self.assertEqual(argv[0], "/usr/bin/curl")
            self.assertEqual(argv[argv.index("--request") + 1], "GET")
            self.assertNotIn("--location", argv)
            self.assertNotIn(token, " ".join(argv))
            self.assertNotIn("RELEASE_GITHUB_TOKEN", kwargs["env"])
            self.assertNotIn("GH_TOKEN", kwargs["env"])
        self.assertIn(b'header = "Authorization: Bearer unit.test-readonly_token~with+padding/=="\n',
                      calls[0][1]["input"])
        self.assertNotIn(b"Authorization", calls[1][1]["input"])

    def test_bearer_token_is_opaque_and_accepts_the_standard_transport_alphabet(self):
        # A legacy-prefix/length assumption or rejected Bearer punctuation breaks
        # this contract. These are invented non-credentials, never real tokens.
        for token in ("unit_test_readonly_token", "unit.header-payload.signature",
                      "unit~token+/=", "unit~token+/==", "x" * 4096):
            with self.subTest(token=token):
                try:
                    self.i.Transport(self.root, token, self.manifest)
                except self.i.ImportFailure:
                    self.fail("standard Bearer transport token was rejected")

    def test_bearer_token_rejects_config_header_injection_and_malformed_padding(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/"
        invalid = ["", None, "=", "==", "=unit", "unit=token", "unit==token",
                   "unit\u00e9token", "unit\u2028token", 'unit"\nurl = "https://attacker.invalid/']
        invalid += ["unit" + chr(code) + "token" for code in range(128) if chr(code) not in alphabet]
        with patch.object(self.i.subprocess, "run") as process:
            for token in invalid:
                with self.subTest(token=token):
                    with self.assertRaises(self.i.ImportFailure) as failure:
                        self.i.Transport(self.root, token, self.manifest)
                    self.assertEqual(str(failure.exception), "malformed read-only GitHub credential")
        process.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_token_contract_cli_never_emits_the_token_and_fails_closed(self):
        for token, expected_status in (("unit.header-payload.signature", 0),
                                       ('unit"\nurl = "https://attacker.invalid/', 1), ("", 1)):
            with self.subTest(expected_status=expected_status):
                result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                                         "--token-contract"], env={"RELEASE_GITHUB_TOKEN": token},
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, expected_status)
                if token:
                    self.assertNotIn(token, result.stdout + result.stderr)
                if expected_status == 0:
                    self.assertEqual(result.stdout, "recovery GitHub credential transport contract accepted\n")
                    self.assertEqual(result.stderr, "")
                else:
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "recovery GitHub credential transport contract rejected\n")

    def test_artifact_redirect_is_separate_unauthenticated_and_host_checked(self):
        transport = self.i.Transport(self.root, "unit_test_readonly_token", self.manifest)
        artifact = self.manifest["artifacts"][0]
        storage = "https://productionresultssa19.blob.core.windows.net/actions-results/a?sig=opaque"
        calls = []

        def process(argv, **kwargs):
            calls.append((argv, kwargs))
            Path(argv[argv.index("--output") + 1]).write_bytes(b"zip")
            headers = "HTTP/2 200\r\n\r\n" if len(calls) == 2 else "HTTP/2 302\r\nLocation: " + storage + "\r\n\r\n"
            Path(argv[argv.index("--dump-header") + 1]).write_text(headers)
            return subprocess.CompletedProcess(argv, 0, b"200" if len(calls) == 2 else b"302", b"")

        with patch.object(self.i.subprocess, "run", side_effect=process):
            transport.archive(artifact, self.root / "result.zip")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][0][-1], storage)
        self.assertNotIn(b"Authorization", calls[1][1]["input"])
        for bad in ["http://productionresultssa19.blob.core.windows.net/a", "https://blob.core.windows.net.attacker.invalid/a",
                    "https://user@productionresultssa19.blob.core.windows.net/a", "https://productionresultssa19.blob.core.windows.net:444/a",
                    "https://attacker.invalid/a", storage + "\nHeader: injected"]:
            self.reject(self.i.validate_storage_url, bad)

    def transport_fixture(self, jobs=None, run=None, metadata=None):
        endpoints = self.i.fixed_endpoints(self.manifest)
        data = {endpoints["run"]: self.run if run is None else run,
                endpoints["jobs"][0]: self.jobs if jobs is None else jobs}
        source = self.metadata if metadata is None else metadata
        data.update({url: source[ident] for ident, url in endpoints["metadata"]})
        calls = []

        def get(url, destination, limit):
            calls.append(url)
            if url not in data:
                raise AssertionError("unexpected endpoint: " + url)
            destination.write_text(json.dumps(data[url]))
        return types.SimpleNamespace(get=get), calls

    def test_origin_fetch_uses_terminal_attempt_page_and_exact_nine_metadata(self):
        transport, calls = self.transport_fixture()
        result = self.i.fetch_origin(self.manifest, self.custody, transport, self.root)
        self.assertEqual(result["run_attempt"], 1)
        self.assertEqual(len(calls), 11)
        self.assertEqual(sum("/jobs?per_page=100&page=1" in url for url in calls), 1)
        self.assertEqual(len(list((self.root / "artifact-metadata").glob("*.json"))), 9)

    def test_origin_rejects_truncated_pagination_second_attempt_and_wrong_producer(self):
        variants = []
        truncated = copy.deepcopy(self.jobs); truncated["jobs"].pop(); variants.append((None, truncated))
        later = copy.deepcopy(self.run); later["run_attempt"] = 2; variants.append((later, None))
        wrong = copy.deepcopy(self.jobs)
        next(j for j in wrong["jobs"] if j["id"] == 105363096810)["id"] = 9999999
        variants.append((None, wrong))
        failed = copy.deepcopy(self.jobs)
        next(j for j in failed["jobs"] if j["id"] == 105363096810)["conclusion"] = "failure"
        variants.append((None, failed))
        for index, (run, jobs) in enumerate(variants):
            directory = self.root / str(index); directory.mkdir()
            transport, calls = self.transport_fixture(jobs=jobs, run=run)
            self.reject(self.i.fetch_origin, self.manifest, self.custody, transport, directory)
            self.assertFalse(any(url.endswith("/zip") for url in calls))

    def test_rust_reads_exact_thirty_two_and_rejects_yanked_or_wrong_hash(self):
        for bad in [None, "yanked", "checksum"]:
            directory = self.root / str(bad); directory.mkdir()
            calls = []
            def get(url, destination, limit):
                calls.append(url)
                crate = next(c for c in self.manifest["rust_crates"] if "/" + c["name"] + "/" in url)
                record = {"version": {"id": 123, "crate": crate["name"], "num": "0.2.7", "yanked": False, "checksum": crate["sha256"]}}
                if bad == "yanked": record["version"]["yanked"] = True
                if bad == "checksum": record["version"]["checksum"] = "a" * 64
                destination.write_text(json.dumps(record))
            transport = types.SimpleNamespace(get=get)
            with patch.object(self.i.time, "sleep"):
                if bad:
                    self.reject(self.i.fetch_rust, self.manifest, self.custody, transport, directory)
                else:
                    self.assertEqual(self.i.fetch_rust(self.manifest, self.custody, transport, directory)["crates_verified"], 32)
            self.assertEqual(len(calls), 32)
            self.assertTrue(all(url.startswith("https://crates.io/api/v1/crates/") and url.endswith("/0.2.7") for url in calls))

    def test_rust_requests_are_serial_and_paced_across_fetch_calls(self):
        # Catches a missing first delay, concurrent batching, reordering, or
        # a rate state that resets between producer and final-writer passes.
        expected = ["https://crates.io/api/v1/crates/" + crate["name"] + "/0.2.7"
                    for crate in self.manifest["rust_crates"]]
        self.assertEqual(len(expected), 32)
        self.assertEqual(len(set(expected)), 32)
        crates = {crate["name"]: crate for crate in self.manifest["rust_crates"]}
        clock = [0]
        delays = []
        calls = []
        active = [0]
        maximum_active = [0]

        def sleep(seconds):
            delays.append(seconds)
            clock[0] += seconds

        def get(url, destination, limit):
            active[0] += 1
            maximum_active[0] = max(maximum_active[0], active[0])
            try:
                calls.append((url, clock[0], limit))
                if len(calls) == 1:
                    threading.Event().wait(0.02)
                crate = crates[url.split("/")[-2]]
                destination.write_text(json.dumps({"version": {"id": 123, "crate": crate["name"],
                    "num": "0.2.7", "yanked": False, "checksum": crate["sha256"]}}))
            finally:
                active[0] -= 1

        transport = types.SimpleNamespace(get=get)
        with patch.object(self.i.time, "sleep", side_effect=sleep):
            for pass_name in ("producer", "final-writer"):
                evidence = self.root / pass_name
                evidence.mkdir()
                result = self.i.fetch_rust(self.manifest, self.custody, transport, evidence)
                self.assertEqual(result["crates_verified"], 32)
        self.assertEqual([url for url, _, _ in calls], expected + expected)
        self.assertEqual([limit for _, _, limit in calls], [self.i.JSON_LIMIT] * 64)
        self.assertEqual(maximum_active[0], 1)
        self.assertEqual(len(delays), 64)
        self.assertTrue(all(delay >= 1 for delay in delays))
        request_times = [timestamp for _, timestamp, _ in calls]
        self.assertGreaterEqual(request_times[0], 1)
        self.assertTrue(all(after - before >= 1 for before, after in
                            zip(request_times, request_times[1:])))

    def test_rust_transport_failure_stops_without_retry_or_later_requests(self):
        # Catches executor prefetch, retry, or partial-inventory acceptance.
        expected = ["https://crates.io/api/v1/crates/" + crate["name"] + "/0.2.7"
                    for crate in self.manifest["rust_crates"][:3]]
        calls = []
        delays = []

        def get(url, destination, limit):
            calls.append(url)
            if len(calls) == 3:
                raise self.i.ImportFailure("fixture HTTP 403")
            crate = self.manifest["rust_crates"][len(calls) - 1]
            destination.write_text(json.dumps({"version": {"id": 123, "crate": crate["name"],
                "num": "0.2.7", "yanked": False, "checksum": crate["sha256"]}}))

        with patch.object(self.i.time, "sleep", side_effect=lambda seconds: delays.append(seconds)):
            self.reject(self.i.fetch_rust, self.manifest, self.custody,
                        types.SimpleNamespace(get=get), self.root)
        self.assertEqual(calls, expected)
        self.assertEqual(len(delays), 3)
        self.assertTrue(all(delay >= 1 for delay in delays))

    def attestation(self):
        artifact = next(a for a in self.manifest["artifacts"] if a["lane"] == "native-x86_64")
        invocation = self.manifest["origin"]["native_attestation_invocation"]
        sha = self.manifest["product"]["commit"]
        certificate = {"issuer":"https://token.actions.githubusercontent.com",
                       "sourceRepositoryURI":"https://github.com/exochain/exochain",
                       "sourceRepositoryDigest":sha,"sourceRepositoryRef":"refs/tags/v0.2.7",
                       "sourceRepositoryIdentifier":"1116455646","sourceRepositoryOwnerIdentifier":"129763194",
                       "buildSignerURI":"https://github.com/exochain/exochain/.github/workflows/release.yml@refs/tags/v0.2.7",
                       "buildSignerDigest":sha,"runnerEnvironment":"github-hosted",
                       "buildTrigger":"workflow_dispatch","runInvocationURI":invocation}
        proof = [{"verificationResult":{"mediaType":"application/vnd.dev.sigstore.verificationresult+json;version=0.1",
                 "signature":{"certificate":certificate},"verifiedTimestamps":[{"type":"Tlog","timestamp":"2026-09-17T23:00:00Z"}],
                 "statement":{"_type":"https://in-toto.io/Statement/v1", "predicateType":"https://slsa.dev/provenance/v1",
                 "subject":sorted([{"name":a["files"][0]["path"],"digest":{"sha256":a["files"][0]["sha256"]}}
                                   for a in self.manifest["artifacts"] if a["lane"].startswith("native-")], key=lambda s:s["name"]),
                 "predicate":{"runDetails":{"metadata":{"invocationId":invocation}}}}}}]
        return artifact, proof

    def test_verified_attestation_data_requires_original_certificate_invocation(self):
        artifact, proof = self.attestation()
        self.i.check_attestation(self.manifest, artifact, proof)
        for field, value in [("runInvocationURI", self.manifest["origin"]["native_attestation_invocation"].replace("attempts/1", "attempts/2")),
                             ("sourceRepositoryDigest", "a" * 40), ("runnerEnvironment", "self-hosted"),
                             ("sourceRepositoryURI", "https://github.com/attacker/exochain")]:
            changed = copy.deepcopy(proof)
            changed[0]["verificationResult"]["signature"]["certificate"][field] = value
            self.reject(self.i.check_attestation, self.manifest, artifact, changed)
        changed = copy.deepcopy(proof); changed[0]["verificationResult"]["verifiedTimestamps"] = []
        self.reject(self.i.check_attestation, self.manifest, artifact, changed)
        changed = copy.deepcopy(proof); changed[0]["verificationResult"]["statement"]["subject"].pop()
        self.reject(self.i.check_attestation, self.manifest, artifact, changed)
        self.reject(self.i.check_attestation, self.manifest, artifact, [{"bundle":proof}])

    def test_attestation_process_must_succeed_before_its_output_is_accepted(self):
        artifact, proof = self.attestation()
        calls = []
        def process(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 1, json.dumps(proof).encode(), b"fixture signature rejection")
        with patch.object(self.i.subprocess, "run", side_effect=process):
            self.reject(self.i.verify_attestation, self.manifest, artifact, self.root / "native.tar.gz", self.root,
                        "unit_test_readonly_token", self.custody)
        argv, kwargs = calls[0]
        self.assertEqual(argv[:3], ["/usr/bin/gh", "attestation", "verify"])
        self.assertIn("--deny-self-hosted-runners", argv)
        self.assertIn("--source-digest", argv)
        self.assertIn("--signer-digest", argv)
        self.assertIn("--signer-workflow", argv)
        self.assertEqual(kwargs["env"]["GH_TOKEN"], "unit_test_readonly_token")

    def test_final_directories_reject_reuse_links_and_outside_runner_temp(self):
        expected = self.root / "exochain-recovery-artifacts"
        self.i.check_destinations(self.root, expected)
        for bad in [self.root / "other", self.root.parent / "exochain-recovery-artifacts", self.root / "x/../exochain-recovery-artifacts"]:
            self.reject(self.i.check_destinations, self.root, bad)
        expected.symlink_to(self.root / "absent")
        self.reject(self.i.check_destinations, self.root, expected)
        expected.unlink(); expected.mkdir()
        self.reject(self.i.check_destinations, self.root, expected)

    def test_shell_rejects_publishing_authority_before_git_or_provider_reads(self):
        for credential in ["NPM_TOKEN", "NODE_AUTH_TOKEN", "CARGO_REGISTRY_TOKEN", "TWINE_PASSWORD", "PYPI_TOKEN",
                           "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"]:
            result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-p", str(SCRIPT)],
                                    env={credential:"unit-test-forbidden"}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("publication credentials and OIDC", result.stderr)

    def test_import_rejects_wrong_producer_or_zip_without_exposing_outputs(self):
        for fault in ("producer", "zip"):
            runner = self.root / fault; runner.mkdir()
            capture = runner / "captured"; capture.mkdir()
            shutil.copyfile(ROOT / "tools/verify_release_recovery_027.py", capture / "verify_release_recovery_027.py")
            shutil.copyfile(MANIFEST, capture / "RECOVERY-MANIFEST.json")
            (capture / "identity-before.json").write_text(json.dumps({"controller_sha":"a" * 40, "controller_ref":"refs/tags/v0.2.7-recover.1"}))
            output = runner / "github-output"; output.touch()
            jobs = copy.deepcopy(self.jobs)
            if fault == "producer":
                next(j for j in jobs["jobs"] if j["id"] == 105363096810)["conclusion"] = "failure"
            transport, reads = self.transport_fixture(jobs=jobs)
            archives = []
            def archive(artifact, destination):
                archives.append(artifact["id"])
                destination.write_bytes(b"not the digest-pinned original ZIP")
            transport.archive = archive
            environment = {"RUNNER_TEMP":str(runner), "RELEASE_RECOVERY_DIRECTORY":str(runner / "exochain-recovery-artifacts"),
                           "RELEASE_GITHUB_TOKEN":"unit_test_readonly_token", "RELEASE_PYTHON":sys.executable,
                           "RELEASE_NODE":sys.executable, "GITHUB_OUTPUT":str(output)}
            commands = []
            actual_run = subprocess.run
            def recorded_run(argv, **kwargs):
                commands.append(argv)
                return actual_run(argv, **kwargs)
            with patch.dict(self.i.os.environ, environment, clear=True), patch.object(self.i.sys, "argv", ["importer", str(capture)]), \
                 patch.object(self.i, "Transport", return_value=transport), \
                 patch.object(self.i.shutil, "disk_usage", return_value=types.SimpleNamespace(free=8 * 1024**3)), \
                 patch.object(self.i.subprocess, "run", side_effect=recorded_run):
                with self.assertRaises(ValueError):
                    self.i.main()
            self.assertFalse((runner / "exochain-recovery-artifacts").exists())
            self.assertFalse((runner / "exochain-recovery-evidence").exists())
            self.assertEqual(output.read_bytes(), b"")
            self.assertEqual(archives, [] if fault == "producer" else [a["id"] for a in self.manifest["artifacts"]])
            self.assertEqual(len(reads), 11)
            for argv in commands:
                self.assertEqual(Path(argv[3]).name, "verify_release_recovery_027.py")
                self.assertIn(argv[4], ("origin", "artifacts"))

    def test_v2_producer_late_failures_and_output_transaction_never_expose_acceptance(self):
        fixture=self.retained_fixture()
        record,origin=fixture.origin_v2_fixture((10518086890,))
        policy=self.custody.load_retained_metadata_policy(self.manifest,record,POLICY)
        later=fixture.observation_fixture((10518086890,),offset_seconds=60)['after']
        publications=self.custody.load_publications(self.manifest,
            ROOT/'governance/releases/v0.2.7/PUBLICATION-IDENTITIES.json')
        for fault in ('crypto','final-transition','source','files','short-write','fsync','replace',
                      'output-content-change','output-path-swap','stdout',None):
            runner=self.root/('v2-main-'+str(fault));runner.mkdir()
            capture=runner/'captured';capture.mkdir()
            for source,name in ((MANIFEST,'RECOVERY-MANIFEST.json'),(POLICY,'RETAINED-METADATA-POLICY.json'),
                (ROOT/'governance/releases/v0.2.7/RETAINED-CUSTODY.json','RETAINED-CUSTODY.json'),
                (ROOT/'governance/releases/v0.2.7/PUBLICATION-IDENTITIES.json','PUBLICATION-IDENTITIES.json'),
                (ROOT/'tools/verify_release_recovery_027.py','verify_release_recovery_027.py')):
                shutil.copyfile(source,capture/name)
            (capture/'identity-before.json').write_text(json.dumps({'controller_sha':'a'*40,
                'controller_ref':'refs/tags/v0.2.7-recover.3','product_commit':self.i.PRODUCT_SHA,
                'product_tag_object':'be47589ec7dbefe821ada35ed0a89dedc9751953'}))
            (capture/'retaining-workflow.yml').write_bytes(b'fixture source boundary')
            output=runner/'github-output';output.write_bytes(b'pre-existing-output\n');output.chmod(0o640)
            events=[]
            diagnostics=[]
            controls=iter((origin['controls_before'],origin['controls_after'],
                           {**origin['controls_after'],'observed_at':'2026-09-25T22:03:00Z'}))
            final=copy.deepcopy(later)
            if fault=='final-transition':
                item=next(value for value in final['records'] if value['id']==10518086890)
                historical=self.custody.read_historical_custody(self.manifest,record,'fixture')['metadata']
                item.update(status=200,variant='present',metadata=dict(next(value for value in historical if value['id']==10518086890),expired=True))
            passes=iter((origin['observations']['before'],origin['observations']['after'],final))
            def control(*args,phase):
                events.append('controls-'+phase)
                return copy.deepcopy(next(controls))
            def observation(*args,phase):
                events.append('observations-'+phase)
                return copy.deepcopy(next(passes))
            def archive(metadata,path):
                path.write_bytes(b'fixture archive boundary')
            transport=types.SimpleNamespace(archive=archive)
            def source_check(*args,**kwargs):
                events.append('source')
                if fault=='source' and events.count('source')==2:
                    raise self.i.ImportFailure('controller source changed')
            def file_check(*args,**kwargs):
                events.append('files')
                if fault=='files': raise self.custody.RecoveryError('original file bytes changed')
                return {'files_verified':40}
            def attestation(manifest,artifact,archive_path,evidence_path,token,custody):
                events.append('native-crypto')
                if fault=='crypto': raise self.i.ImportFailure('native crypto rejected')
                return {'lane':artifact['lane'],'original_invocation':self.manifest['origin']['native_attestation_invocation'],
                        'verified_attestations':1}
            def identity(argv,**kwargs):
                events.append('identity-after')
                kwargs['stdout'].write(json.dumps({'controller_sha':'a'*40,
                    'controller_ref':'refs/tags/v0.2.7-recover.3','product_commit':self.i.PRODUCT_SHA,
                    'product_tag_object':'be47589ec7dbefe821ada35ed0a89dedc9751953',
                    'controller_signature_verified':True,'product_signature_verified':True,
                    'retaining_signature_verified':True}).encode())
                return subprocess.CompletedProcess(argv,0,b'',b'')
            def verified_transport(manifest,record,archives,destination):
                destination.mkdir(mode=0o700)
                return {'retained_archives_verified':2,'payload_files_verified':40,'original_zip_envelopes_verified':0}
            def checked_context(*args,**kwargs):
                events.append('checked-at')
                return {'producer_job_id':110000000000}
            def receipts(*args,**kwargs):
                events.append('receipt-output')
                directory=args[-1]/'current-receipts';directory.mkdir()
                return [{'path':'custody-receipt.json','size':1,'sha256':'a'*64},
                        {'path':'acceptance-receipt.json','size':1,'sha256':'b'*64}]
            environment={'RUNNER_TEMP':str(runner),'RELEASE_RECOVERY_DIRECTORY':str(runner/'exochain-recovery-artifacts'),
                'RELEASE_GITHUB_TOKEN':'fixture','RELEASE_PYTHON':sys.executable,'RELEASE_NODE':sys.executable,
                'GITHUB_OUTPUT':str(output),'RELEASE_OPERATION':'recover-0.2.7-retained-404'}
            with ExitStack() as stack:
                stack.enter_context(patch.dict(self.i.os.environ,environment,clear=True))
                stack.enter_context(patch.object(self.i.sys,'argv',['importer',str(capture)]))
                for name, options in (
                    ('load_module',{'return_value':self.custody}),
                    ('Transport',{'return_value':transport}),
                    ('capture_observer',{'return_value':origin['observations']['observer']}),
                    ('fetch_retained_controls',{'side_effect':control}),
                    ('fetch_original_observation_pass',{'side_effect':observation}),
                    ('assert_captured_inputs',{'side_effect':source_check}),
                    ('fetch_rust',{'return_value':{'version':'0.2.7','crates_verified':32}}),
                    ('validate_packages',{'return_value':{}}),
                    ('verify_attestation',{'side_effect':attestation}),
                    ('accept_publications',{'return_value':[self.i.publication_result(p) for p in publications['publications']]}),
                    ('retained_github_preflight',{}),
                    ('current_receipt_context',{'side_effect':checked_context}),
                    ('create_retained_receipts',{'side_effect':receipts}),
                    ('command',{'side_effect':lambda argv,path,*a,**k:path.write_text('fixture')})):
                    stack.enter_context(patch.object(self.i,name,**options))
                stack.enter_context(patch.object(self.i.shutil,'disk_usage',return_value=types.SimpleNamespace(free=8*1024**3)))
                stack.enter_context(patch.object(self.custody,'verify_retained_transport',side_effect=verified_transport))
                stack.enter_context(patch.object(self.custody,'verify_files',side_effect=file_check))
                stack.enter_context(patch.object(self.i.subprocess,'run',side_effect=identity))
                if fault=='short-write':
                    real_write=self.i.os.write
                    stack.enter_context(patch.object(self.i.os,'write',
                        side_effect=lambda fd,data:real_write(fd,data[:max(1,len(data)//2)])))
                if fault=='stdout':
                    real_write=self.i.os.write
                    def broken_stdout(fd,data):
                        if fd==1: raise OSError('fixture diagnostic stdout fault')
                        return real_write(fd,data)
                    stack.enter_context(patch.object(self.i.os,'write',side_effect=broken_stdout))
                if fault is None:
                    real_write=self.i.os.write
                    def capture_diagnostic(fd,data):
                        if fd==1:
                            diagnostics.append(bytes(data))
                            return len(data)
                        return real_write(fd,data)
                    stack.enter_context(patch.object(self.i.os,'write',side_effect=capture_diagnostic))
                if fault=='fsync':
                    real_fsync=self.i.os.fsync
                    attempts=iter((True,False))
                    def fault_fsync(fd):
                        if next(attempts,False): raise OSError('fixture output sync fault')
                        return real_fsync(fd)
                    stack.enter_context(patch.object(self.i.os,'fsync',side_effect=fault_fsync))
                if fault=='replace':
                    stack.enter_context(patch.object(self.i.os,'replace',side_effect=OSError('fixture replace fault')))
                if fault in ('output-content-change','output-path-swap'):
                    real_fsync=self.i.os.fsync
                    original_stat=output.stat()
                    changed=False
                    def mutate_output(fd):
                        nonlocal changed
                        if not changed:
                            changed=True
                            if fault=='output-content-change':
                                output.write_bytes(b'X'*len(b'pre-existing-output\n'))
                                self.i.os.utime(output,ns=(original_stat.st_atime_ns,original_stat.st_mtime_ns))
                            else:
                                replacement=runner/'fixture-output-swap'
                                replacement.write_bytes(b'pre-existing-output\n')
                                replacement.chmod(0o640)
                                self.i.os.replace(replacement,output)
                        return real_fsync(fd)
                    stack.enter_context(patch.object(self.i.os,'fsync',side_effect=mutate_output))
                if fault in (None,'stdout'):
                    self.i.main()
                else:
                    with self.assertRaises((self.i.ImportFailure,self.custody.RecoveryError,OSError)):
                        self.i.main()
            if fault in (None,'stdout'):
                self.assertTrue((runner/'exochain-recovery-artifacts').is_dir())
                self.assertTrue((runner/'exochain-recovery-evidence/current-receipts').is_dir())
                self.assertTrue(output.read_bytes().startswith(b'pre-existing-output\n'))
                self.assertIn(b'receipt_directory=',output.read_bytes())
                self.assertEqual(output.stat().st_mode & 0o777,0o640)
                if fault is None:
                    self.assertEqual(len(diagnostics),1)
                    self.assertEqual(json.loads(diagnostics[0]),{
                        'artifact_directory':str(runner/'exochain-recovery-artifacts'),
                        'evidence_directory':str(runner/'exochain-recovery-evidence')})
            else:
                self.assertFalse((runner/'exochain-recovery-artifacts').exists())
                self.assertFalse((runner/'exochain-recovery-evidence').exists())
                expected_output=(b'X'*len(b'pre-existing-output\n') if fault=='output-content-change'
                                 else b'pre-existing-output\n')
                self.assertEqual(output.read_bytes(),expected_output)
                self.assertEqual(output.stat().st_mode & 0o777,0o640)
                self.assertEqual(list(runner.glob('exochain-output-*')),[])
                if fault not in ('short-write','fsync','replace','output-content-change','output-path-swap'):
                    self.assertFalse((capture/'evidence/current-receipts').exists())
            self.assertLess(events.index('controls-acquisition-start'),events.index('observations-acquisition-before'))
            if fault!='crypto':
                self.assertLess(events.index('native-crypto'),events.index('observations-producer-final'))
            if fault in (None,'stdout'):
                self.assertLess(events.index('observations-producer-final'),events.index('controls-producer-final'))
                self.assertLess(events.index('controls-producer-final'),events.index('checked-at'))
                self.assertLess(events.index('checked-at'),events.index('receipt-output'))

    def test_transport_rejects_status_duplicate_redirect_and_oversize(self):
        for status, headers, body in [(b"404", "HTTP/2 404\r\n\r\n", b"{}"),
                                      (b"302", "HTTP/2 302\r\nLocation: https://a.blob.core.windows.net/a\r\nLocation: https://a.blob.core.windows.net/b\r\n\r\n", b"{}"),
                                      (b"200", "HTTP/2 200\r\n\r\n", b"x" * 1025)]:
            with tempfile.TemporaryDirectory(dir=self.root) as scratch:
                directory = Path(scratch)
                transport = self.i.Transport(directory, "unit_test_readonly_token", self.manifest)
                def process(argv, **kwargs):
                    Path(argv[argv.index("--output") + 1]).write_bytes(body)
                    Path(argv[argv.index("--dump-header") + 1]).write_text(headers)
                    return subprocess.CompletedProcess(argv, 0, status, b"")
                with patch.object(self.i.subprocess, "run", side_effect=process):
                    self.reject(transport.get, self.i.fixed_endpoints(self.manifest)["run"], directory / "response", 1024)

    def test_verified_attestation_rejects_subject_checksum_substitution(self):
        artifact, proof = self.attestation()
        proof[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "a" * 64
        self.reject(self.i.check_attestation, self.manifest, artifact, proof)

    def test_native_canonical_boundary_accepts_libraries_and_rejects_links_extras_modes(self):
        native = module_file("import_test_native", ROOT / "tools/transport_release_build_output.py")
        for fault in (None, "link", "extra", "mode", "append"):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                root = tarfile.TarInfo("./"); root.type = tarfile.DIRTYPE; root.mode = 0o700
                archive.addfile(root)
                for index, name in enumerate(native.EXPECTED_FILES):
                    member = tarfile.TarInfo("./" + name); member.mode = 0o644; member.size = 1
                    if index == 0 and fault == "mode": member.mode = 0o755
                    if index == 0 and fault == "link":
                        member.type = tarfile.SYMTYPE; member.linkname = "outside"; member.size = 0
                    archive.addfile(member, io.BytesIO(b"x"))
                if fault == "extra": archive.addfile(tarfile.TarInfo("./extra"), io.BytesIO())
            path = self.root / (str(fault) + ".tar.gz")
            payload = gzip.compress(stream.getvalue(), mtime=0)
            if fault == "append": payload += gzip.compress(b"extra", mtime=0)
            path.write_bytes(payload)
            if fault:
                with self.assertRaises((ValueError, SystemExit)):
                    self.i.validate_native(path, ROOT / "tools")
            else:
                self.assertEqual(self.i.validate_native(path, ROOT / "tools"), {"libraries":29,"executables":0})

    def test_sbom_canonical_boundary_rejects_duplicate_json_and_local_paths(self):
        validator = module_file("import_test_sbom", ROOT / "tools/verify_release_sbom.py")
        value = {"$schema":validator.SCHEMA_URI,"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
                 "components":[],"dependencies":[],"metadata":{"timestamp":validator.EXPECTED_TIMESTAMP,
                 "tools":[validator.EXPECTED_TOOL],"properties":[validator.EXPECTED_TARGET_PROPERTY],
                 "component":{"name":"exochain-core","version":"0.2.7"}}}
        name = "exochain-0.2.7-exochain-core.cdx.json"
        manifest = {"artifacts":[{"lane":"sbom","files":[{"path":name}]}]}
        path = self.root / name
        canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        path.write_bytes(canonical)
        self.assertEqual(self.i.validate_sboms(manifest, self.root, ROOT / "tools"), {"canonical_sboms":1})
        for bad in [canonical.replace(b'"version":1', b'"version":1,"version":1'),
                    canonical.replace(b'"components":[]', b'"components":["file:///home/runner/private"]'),
                    json.dumps(value, indent=2).encode()]:
            path.write_bytes(bad)
            with self.assertRaises((ValueError, SystemExit)):
                self.i.validate_sboms(manifest, self.root, ROOT / "tools")


def real_evidence_check():
    """Explicit local evidence checks, separate from mocked transport tests.

    This does not run the hosted signer wrapper or redo gh cryptography. It
    rechecks actual original bytes and the retained successful gh verify result.
    No flags are added to the production import helper.
    """
    parser = argparse.ArgumentParser(description=real_evidence_check.__doc__)
    parser.add_argument("--real-evidence", required=True, type=Path)
    parser.add_argument("--original-run-evidence", required=True, type=Path)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--evidence-directory", required=True, type=Path)
    args = parser.parse_args()
    if args.evidence_directory.exists() or args.evidence_directory.is_symlink():
        parser.error("evidence directory must be absent")
    node = args.node.resolve(strict=True)
    result = subprocess.run([str(node), "--version"], env={}, capture_output=True, text=True, check=True)
    if result.stdout.strip() != "v24.15.0":
        parser.error("real npm package checks require Node 24.15.0")
    args.evidence_directory.mkdir(mode=0o700)
    importer = importer_module()
    custody = module_file("import_real_custody", ROOT / "tools/verify_release_recovery_027.py")
    manifest = custody.load_manifest(MANIFEST)
    metadata = [custody.load_json(args.real_evidence / "metadata" / f"{a['id']}.json", "real original metadata")
                for a in manifest["artifacts"] + manifest["rust_preparation"]]
    summary = {"origin":custody.verify_origin(manifest,
               custody.load_json(args.original_run_evidence / "run.json", "real original run"),
               custody.load_json(args.original_run_evidence / "jobs.json", "real original jobs"), metadata)}
    for artifact in manifest["artifacts"]:
        custody.verify_zip(args.real_evidence / "archives" / f"{artifact['id']}.zip", artifact)
    artifacts = args.real_evidence / "extracted"
    summary["files"] = custody.verify_files(manifest, artifacts)
    summary["rust"] = custody.verify_rust(manifest, {c["name"]:custody.load_json(
        args.real_evidence / "rust-responses" / (c["name"] + ".json"), "observed public Rust version") for c in manifest["rust_crates"]})
    summary["packages"] = importer.validate_packages(manifest, artifacts, ROOT / "tools", args.evidence_directory, sys.executable, str(node))
    summary["native_attestation_identities"] = [importer.check_attestation(manifest, a, custody.load_json(
        args.original_run_evidence / (a["lane"] + "-verified-attestations.json"), "retained actual gh verification result"))
        for a in manifest["artifacts"] if a["lane"].startswith("native-")]
    summary["limits"] = "Local canonical checks and retained gh-verified result identity recheck; not a hosted signed-controller execution or fresh cryptographic verification."
    importer.dump(args.evidence_directory / "positive-check.json", summary)
    print(json.dumps(summary, sort_keys=True))


def token_contract_check():
    """Exercise real transport validation without network or credential output.

    CI supplies only its scoped GitHub token. No credential is decoded, persisted,
    put in a unittest assertion, or passed to the normal fixture test suite.
    """
    token = os.environ.pop("RELEASE_GITHUB_TOKEN", "")
    importer = importer_module()
    custody = module_file("token_contract_custody", ROOT / "tools/verify_release_recovery_027.py")
    manifest = custody.load_manifest(MANIFEST)
    try:
        importer.Transport(ROOT, token, manifest)
    except importer.ImportFailure:
        print("recovery GitHub credential transport contract rejected", file=sys.stderr)
        return 1
    print("recovery GitHub credential transport contract accepted")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--token-contract"]:
        sys.exit(token_contract_check())
    elif "--real-evidence" in sys.argv:
        real_evidence_check()
    else:
        unittest.main()
