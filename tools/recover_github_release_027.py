#!/usr/bin/env python3
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
"""Complete only the fixed original release; never replace a release asset."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import types
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com/repos/exochain/exochain"
UPLOADS = "https://uploads.github.com/repos/exochain/exochain"
PRODUCT_SHA = "666c578f719d1e54fce95d6831a3af92ea80df93"


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Journal:
    """Private append-only mutation intents; deliberately excludes credentials."""
    def __init__(self, path, context=None):
        self.path = path
        self.context = {} if context is None else context
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)

    def __call__(self, event):
        data = (json.dumps({**self.context, **event}, sort_keys=True, separators=(",", ":")) + "\n").encode()
        require(len(data) < 4096, "mutation journal entry exceeds bound")
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "ab") as output:
            identity = os.fstat(output.fileno())
            require(stat.S_ISREG(identity.st_mode) and identity.st_nlink == 1, "mutation journal changed file type")
            output.write(data)
            output.flush()
            os.fsync(output.fileno())


def validate_release(value, expected):
    require(type(value) is dict, "missing release object")
    for field, wanted in expected.items():
        # GitHub documents target_commitish as unused when the tag exists.
        # The signed tag object, peel and authoritative remote rebind establish
        # source identity; an echoed bookkeeping branch is not that proof.
        if field == "target_commitish":
            continue
        require(type(value.get(field)) is type(wanted) and value[field] == wanted, "conflicting release " + field)
    target = value.get("target_commitish")
    require(type(target) is str and 0 < len(target) <= 1024 and all(ord(c) >= 32 for c in target), "invalid target_commitish metadata")
    require(type(value.get("id")) is int and 0 < value["id"] < 10**15, "invalid release ID")
    require(type(value.get("draft")) is bool and value.get("prerelease") is False, "unexpected release state")
    return value["id"]


def verified_assets(provider, release_id, expected, verified=None):
    if verified is None:
        verified = set()
    assets = provider.list_assets(release_id)
    require(type(assets) is list and len(assets) <= len(expected), "unexpected release asset count")
    found = set()
    ids = set()
    for asset in assets:
        require(type(asset) is dict, "malformed release asset")
        name = asset.get("name")
        identifier = asset.get("id")
        require(type(name) is str and name in expected and name not in found, "unknown or duplicate release asset")
        require(type(identifier) is int and 0 < identifier < 10**15 and identifier not in ids, "duplicate or invalid asset ID")
        require(type(asset.get("size")) is int and asset["size"] == len(expected[name]) and asset.get("state") == "uploaded", "release asset size or state differs")
        # GitHub asset contents cannot be edited in place: replacement has a
        # new asset ID. Cache only an already byte-verified ID/name pair within
        # this process; final published readback deliberately uses a fresh set.
        if (identifier, name) not in verified:
            require(provider.download(asset) == expected[name], "existing asset bytes differ; replacement forbidden")
            verified.add((identifier, name))
        found.add(name)
        ids.add(identifier)
    return found


def recover(provider, expected, assets, rebind, journal=None):
    def mutate(operation, details, callback):
        event = {"operation":operation, "product_tag":"v0.2.7", **details}
        if journal is not None:
            journal({**event, "outcome":"intent"})
        try:
            result = callback()
        except Exception as error:
            if journal is not None:
                journal({**event, "outcome":"unknown", "error_type":type(error).__name__})
            raise
        if journal is not None:
            journal({**event, "outcome":"response_received_not_yet_accepted"})
        return result

    rebind()
    release = provider.lookup()
    if release is None:
        rebind()
        release = mutate("create_draft", {}, lambda:provider.create(expected))
    identifier = validate_release(release, expected)
    proof_cache = set()
    found = verified_assets(provider, identifier, assets, proof_cache)
    missing = [name for name in assets if name not in found]
    require(not missing or release["draft"], "incomplete already-public release cannot be silently changed")
    for name in missing:
        rebind()
        # Check for a concurrent release/asset change immediately before write.
        current = provider.lookup()
        require(validate_release(current, expected) == identifier and current["draft"], "draft changed during recovery")
        current_assets = verified_assets(provider, identifier, assets, proof_cache)
        if name not in current_assets:
            mutate("upload_asset", {"release_id":identifier, "asset":name, "size":len(assets[name]), "sha256":hashlib.sha256(assets[name]).hexdigest()}, lambda:provider.upload(identifier, name, assets[name]))
    require(verified_assets(provider, identifier, assets, proof_cache) == set(assets), "final release asset inventory incomplete")
    rebind()
    current = provider.lookup()
    require(validate_release(current, expected) == identifier, "release identity changed")
    if current["draft"]:
        mutate("publish_release", {"release_id":identifier}, lambda:provider.publish(identifier))
        rebind()
    final = provider.lookup()
    require(validate_release(final, expected) == identifier and final["draft"] is False, "release publication not confirmed")
    require(verified_assets(provider, identifier, assets) == set(assets), "published release asset inventory differs")
    rebind()
    if journal is not None:
        journal({"operation":"final_readback", "outcome":"accepted", "release_id":identifier, "asset_count":len(assets), "product_tag":"v0.2.7"})
    return {"tag":"v0.2.7", "release_id":identifier, "asset_count":len(assets), "published":True}


def preflight(provider, expected, assets, rebind):
    """Read the full draft/public inventory without entering any mutation path."""
    rebind()
    release = provider.lookup()
    found = set()
    identifier = None
    if release is not None:
        identifier = validate_release(release, expected)
        found = verified_assets(provider, identifier, assets)
        require(release['draft'] or found == set(assets), 'incomplete already-public release')
    rebind()
    return {'release_id':identifier, 'existing_assets':len(found),
            'missing_assets':[name for name in assets if name not in found], 'mutation_attempted':False}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token, parser):
        self.token = token
        self.parser = parser
        # Do not inherit proxy environment or an arbitrary redirect policy.
        self.transport = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, url, data=None, binary=False, auth=True, limit=4*1024*1024):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == "https" and not parsed.username and not parsed.password and not parsed.fragment, "unsafe provider URL")
        if auth:
            require(parsed.netloc in ("api.github.com", "uploads.github.com") and parsed.path.startswith("/repos/exochain/exochain/"), "credential destination forbidden")
        else:
            require(method == "GET" and parsed.netloc in ("release-assets.githubusercontent.com", "crates.io"), "public destination forbidden")
        headers = {"User-Agent":"exochain-027-release-recovery", "Accept":"application/octet-stream" if binary else "application/vnd.github+json"}
        if auth:
            headers["Authorization"] = "Bearer " + self.token
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        if data is not None:
            headers["Content-Type"] = "application/octet-stream" if binary else "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            response = self.transport.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            payload = response.read(limit + 1)
            require(len(payload) <= limit, "provider response exceeded size limit")
            return response.status, payload, response.headers

    def json(self, method, suffix, payload=None, allow_absent=False):
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        status, raw, _ = self.request(method, API + suffix, data)
        if allow_absent and status == 404:
            return None
        require(status in (200, 201), "GitHub API request failed with HTTP " + str(status))
        return self.parser(raw, "GitHub response")

    def lookup(self):
        # The by-tag endpoint is documented for published releases. List with
        # the configured write token also sees resumable drafts; never mistake
        # an existing draft for an absent release and create a duplicate.
        matches = []
        seen = set()
        for page in range(1, 11):
            values = self.json("GET", f"/releases?per_page=100&page={page}")
            require(type(values) is list and len(values) <= 100, "malformed release listing")
            for value in values:
                require(type(value) is dict and type(value.get("id")) is int and value["id"] not in seen, "duplicate or malformed release listing")
                seen.add(value["id"])
                if value.get("tag_name") == "v0.2.7":
                    matches.append(value)
            if not values:
                require(len(matches) <= 1, "duplicate original-tag releases")
                return matches[0] if matches else None
        raise ValueError("release pagination exceeded the bounded inventory")

    def list_assets(self, identifier):
        first = self.json("GET", f"/releases/{identifier}/assets?per_page=100&page=1")
        require(type(first) is list and len(first) < 100, "unexpected asset pagination")
        # Explicitly prove terminal pagination instead of assuming one page.
        require(self.json("GET", f"/releases/{identifier}/assets?per_page=100&page=2") == [], "extra release assets on later page")
        return first

    def download(self, asset):
        status, data, headers = self.request("GET", API + f"/releases/assets/{asset['id']}", binary=True, limit=asset["size"])
        if status == 302:
            location = headers.get("Location", "")
            status, data, _ = self.request("GET", location, binary=True, auth=False, limit=asset["size"])
        require(status == 200 and len(data) == asset["size"], "asset download failed")
        return data

    def create(self, expected):
        return self.json("POST", "/releases", {**expected, "target_commitish":PRODUCT_SHA, "draft":True, "prerelease":False, "make_latest":"false"})

    def upload(self, identifier, name, data):
        url = UPLOADS + f"/releases/{identifier}/assets?name=" + urllib.parse.quote(name, safe="")
        status, response, _ = self.request("POST", url, data, binary=True)
        require(status == 201, "asset upload failed or unknown; do not retry blindly")
        result = self.parser(response, "uploaded asset")
        require(result.get("name") == name and result.get("size") == len(data), "uploaded asset identity differs")

    def publish(self, identifier):
        return self.json("PATCH", f"/releases/{identifier}", {"draft":False, "make_latest":"true"})


def release_metadata(manifest, publications, sha, ref):
    receipt = {
        "schema": "exochain-release-recovery-custody/v1",
        "product": manifest["product"], "origin": manifest["origin"],
        "controller": {"sha": sha, "ref": ref},
        "publication_identities": publications,
        "artifacts": manifest["artifacts"], "rust_crates": manifest["rust_crates"],
        "native_archive_contents": "29 legacy libexo_*.rlib per archive; no server executables",
        "attestation_scope": "Original native archives have original build attestations. Package attestations identify the exact prior sources/refs in publication_identities, not this acceptance controller. Observed publishing run/attempt fields are reviewed evidence metadata, not additional invocation constraints enforced by the certificate verifiers. Original payload custody is the fixed reviewed artifact manifest and producer evidence.",
    }
    body = (
        "Security remediation release 0.2.7. Original signed product tag and payload bytes are preserved.\n\n"
        f"Original artifact source: `{PRODUCT_SHA}`. Acceptance and GitHub Release controller: `{sha}` at `{ref}`. "
        "See RECOVERY-CUSTODY.json for the prior package publishers and fixed original run, producer, artifact and checksum inventory.\n\n"
        "All 32 Rust crates and the WASM, LYNK, TypeScript and Python packages passed their exact registry acceptance gates before this release job. "
        "Native archives contain 29 legacy libexo_*.rlib libraries each, not server executables. Only those native archives have original GitHub build attestations; "
        "package attestations retain their original publication sources/refs. No package re-upload or runtime deployment is claimed.\n"
    )
    return receipt, {"tag_name": "v0.2.7", "target_commitish": PRODUCT_SHA, "name": "EXOCHAIN v0.2.7", "body": body}


def retained_release_metadata(manifest, publications, record, sha, ref, *, policy=None):
    """Stable public custody; execution observations belong only in run evidence."""
    receipt, expected = release_metadata(manifest, publications, sha, ref)
    receipt['schema'] = 'exochain-release-retained-custody/v1'
    receipt['retained_custody'] = record
    receipt['github_release_assets'] = [file['path'] for lane in manifest['artifacts']
        if lane['lane'] in ('native-x86_64','native-aarch64','sbom') for file in lane['files']] + ['RECOVERY-CUSTODY.json']
    require(len(receipt['github_release_assets']) == 35, 'unexpected public asset inventory')
    receipt['attestation_scope'] += (' Original download envelopes may be expired; the pinned successful pre-expiry import and '
        'retained transport establish the reviewed custody chain. Current native/package cryptographic acceptance, '
        'actual original expiry and execution identity are separate same-attempt run evidence. The 40 retained payload '
        'files are not all GitHub Release assets: only the listed 34 original native/SBOM files plus this receipt are public assets.')
    expected['body'] += ('\nRetained recovery preserves the pinned pre-expiry import; original download envelopes may now be expired. '
        'Fresh acceptance checks the retained bytes, signatures and original publication identities. '
        'RECOVERY-CUSTODY.json distinguishes original production, historical retention, prior package publication and this acceptance controller. '
        'The release contains exactly 34 original native/SBOM assets and the custody receipt. '
        'Current run/attempt, observations and acceptance receipts remain separate Actions evidence.\n')
    if policy is not None:
        # The canonical validator pins the semantic policy; no provider or
        # per-run observation enters this stable public asset.
        checker = Path(__file__).with_name('verify_release_recovery_027.py')
        spec = importlib.util.spec_from_file_location('retained_public_policy_validator', checker)
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        validator.validate_retained_metadata_policy(manifest, record, policy)
        disclosure = ('Selected original artifact metadata may be unavailable after its recorded expiry. '
            'Historical identity is authenticated from retained custody; it is not a claim of current metadata '
            'visibility or proof of deletion.')
        receipt['schema'] = 'exochain-release-retained-custody/v2'
        receipt['metadata_policy_sha256'] = validator.RETAINED_METADATA_POLICY_SHA256
        receipt['unavailable_originals'] = policy['unavailable_originals']
        receipt['original_metadata_disclosure'] = disclosure
        expected['body'] += ('\nMetadata policy SHA-256: `' + validator.RETAINED_METADATA_POLICY_SHA256 + '`. '
                             + disclosure + '\n')
    return receipt, expected


def release_assets(custody, manifest, directory, receipt):
    assets = {}
    for lane in manifest['artifacts']:
        if lane['lane'] not in ('native-x86_64','native-aarch64','sbom'):
            continue
        for file in lane['files']:
            name = file['path']
            require('/' not in name and name not in assets, 'unexpected public asset name')
            data = custody.read_regular(directory / lane['lane'] / name, custody.MAX_ZIP_BYTES, 'original release asset')
            require(len(data) == file['size'] and hashlib.sha256(data).hexdigest() == file['sha256'], 'original release asset changed')
            assets[name] = data
    require(len(assets) == 34, 'original release must have two native archives and 32 SBOMs')
    assets['RECOVERY-CUSTODY.json'] = (json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode()
    return assets


def receipt_handoff(env, parser, checker_sha256):
    """Only direct job outputs bound to the actual live controller are inputs."""
    def field(name, bound):
        value = env.get('RELEASE_RECEIPT_' + name, '')
        require(type(value) is str and 0 < len(value.encode()) <= bound, 'missing or oversized direct receipt output')
        return value
    def number(name):
        value = field(name, 15)
        require(re.fullmatch(r'[1-9][0-9]*',value) is not None, 'invalid direct receipt numeric output')
        return int(value)
    outputs = {'artifact_id':number('ARTIFACT_ID'), 'producer_job_id':number('PRODUCER_JOB_ID'),
               'artifact_digest':field('ARTIFACT_DIGEST',64)}
    require(re.fullmatch(r'[0-9a-f]{64}',outputs['artifact_digest']) is not None, 'invalid direct receipt digest')
    context = parser(field('RECEIPT_CONTEXT',8192))
    members = parser(field('RECEIPT_MEMBERS',4096))
    require(type(context) is dict, 'invalid receipt context')
    for name in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'):
        require(re.fullmatch(r'[1-9][0-9]*',env.get(name,'')) is not None, 'actual current run/attempt required')
    require(env.get('RELEASE_WORKFLOW_DRY_RUN') == 'false', 'retained GitHub writer requires live execution')
    expected = {'controller_sha':env.get('GITHUB_SHA'), 'controller_ref':env.get('GITHUB_REF'),
        'controller_tag_object':env.get('EXPECTED_TAG_OBJECT_SHA'), 'run_id':int(env['GITHUB_RUN_ID']),
        'run_attempt':int(env['GITHUB_RUN_ATTEMPT']), 'producer_job_id':outputs['producer_job_id'],
        'checker_sha256':checker_sha256, 'dry_run':False}
    for name, value in expected.items():
        require(type(context.get(name)) is type(value) and context[name] == value, 'receipt differs from actual controller ' + name)
    return context, members, outputs


def _receipt_endpoints(importer, context, outputs, transport):
    url = importer.API + f"/artifacts/{outputs['artifact_id']}"
    run_url = importer.API + f"/runs/{context['run_id']}/attempts/{context['run_attempt']}"
    endpoints = {'run':run_url, 'jobs':[run_url+f'/jobs?per_page=100&page={p}' for p in range(1,11)]}
    transport.authenticated.update([url,run_url,*endpoints['jobs']])
    return url, endpoints


def _require_running_writer(custody, jobs, context, observed_at, observer=None):
    current = custody.complete_jobs(jobs,context['run_id'],context['run_attempt'],context['controller_sha'],
                                    context['controller_ref'].removeprefix('refs/tags/'))
    writers = [job for job in current.values() if job.get('name') == custody.RECEIPT_WRITER_JOB]
    require(len(writers) == 1 and writers[0].get('status') == 'in_progress' and
            writers[0].get('conclusion') is None and writers[0].get('completed_at') is None,
            'actual retained writer is not uniquely running')
    writer = writers[0]
    if observer is not None:
        for field, expected in (('job_id',writer['id']),('job_name',writer['name']),
                                ('job_started_at',writer['started_at'])):
            custody.exact(observer[field],expected,'fresh writer observer ' + field)
    require(custody.timestamp(writer['started_at'],'writer start') <=
            custody.timestamp(observed_at,'writer observation'), 'writer job starts after observation')
    return writer


def prepare_current_receipt(custody, importer, manifest, record, policy, transport, evidence, handoff):
    """Authenticate current direct receipt provenance before canonical acquisition."""
    require(os.environ.get('RELEASE_OPERATION') == custody.RETAINED_METADATA_OPERATION and
            os.environ.get('GITHUB_JOB') == 'retained-github', 'actual staged writer operation required')
    custody.validate_retained_metadata_policy(manifest, record, policy)
    context, members, outputs = handoff
    for field, actual in (('run_id',os.environ.get('GITHUB_RUN_ID')),
                          ('run_attempt',os.environ.get('GITHUB_RUN_ATTEMPT'))):
        require(type(actual) is str and re.fullmatch(r'[1-9][0-9]*',actual) is not None and
                context.get(field) == int(actual), 'actual writer ' + field + ' differs')
    for field, actual in (('controller_sha',os.environ.get('GITHUB_SHA')),
                          ('controller_ref',os.environ.get('GITHUB_REF')),
                          ('controller_tag_object',os.environ.get('EXPECTED_TAG_OBJECT_SHA'))):
        require(context.get(field) == actual, 'actual writer ' + field + ' differs')
    url, endpoints = _receipt_endpoints(importer, context, outputs, transport)
    run, jobs = importer.fetch_run_jobs(custody,transport,evidence/'preliminary-current-attempt',endpoints,None)
    path = evidence/'preliminary-receipt-metadata.json'
    transport.get(url,path,importer.JSON_LIMIT)
    prepared = {'schema':'exochain-retained-receipts-input-027/v2',
        'operation':custody.RETAINED_METADATA_OPERATION,'policy_sha256':custody.RETAINED_METADATA_POLICY_SHA256,
        'observed_at':importer.utc_now(),'context':context,'current_run':run,'current_jobs':jobs,
        'upload_outputs':outputs,'metadata_before':custody.load_json(path,'preliminary current receipt metadata'),
        'members':members}
    _require_running_writer(custody,jobs,context,prepared['observed_at'])
    custody.retained_receipt_provenance(manifest,record,policy,prepared)
    importer.dump(evidence/'preliminary-receipt-input.json',prepared)
    return prepared


def receive_current_receipts(custody, importer, manifest, record, publications, transport,
                            evidence, historical, workflow, origin, handoff, *, policy=None, prepared=None):
    context, members, outputs = handoff
    url, endpoints = _receipt_endpoints(importer,context,outputs,transport)
    if policy is not None:
        require(type(prepared) is dict, 'preliminary receipt provenance required')
        require(os.environ.get('RELEASE_OPERATION') == custody.RETAINED_METADATA_OPERATION,
                'actual staged writer operation required')
        custody.retained_receipt_provenance(manifest,record,policy,prepared)
        require(prepared['context'] == context and prepared['members'] == members and
                prepared['upload_outputs'] == outputs, 'direct receipt handoff changed after preliminary proof')
        run,jobs = importer.fetch_run_jobs(custody,transport,evidence/'current-attempt-before',endpoints,None)
        before_path = evidence/'receipt-metadata-before.json'
        transport.get(url,before_path,importer.JSON_LIMIT)
        metadata_before = custody.load_json(before_path,'fresh receipt metadata before download')
        custody.exact(metadata_before,prepared['metadata_before'],'receipt metadata changed after preliminary proof')
        envelope = {'schema':'exochain-retained-receipts-input-027/v2',
            'operation':custody.RETAINED_METADATA_OPERATION,'policy_sha256':custody.RETAINED_METADATA_POLICY_SHA256,
            'observed_at':importer.utc_now(),'origin':origin,'context':context,
            'current_run':run,'current_jobs':jobs,'upload_outputs':outputs,
            'metadata_before':metadata_before,'members':members}
        _require_running_writer(custody,jobs,context,envelope['observed_at'],origin['observations']['observer'])
        custody.retained_receipt_profile(manifest,record,publications,envelope,historical,workflow,policy=policy)
        receipt = evidence/'current-receipts.zip'
        transport.receipt_archive(metadata_before,receipt)
        after_path = evidence/'receipt-metadata-after.json'
        transport.get(url,after_path,importer.JSON_LIMIT)
        envelope['metadata_after'] = custody.load_json(after_path,'fresh receipt metadata after download')
        run,jobs = importer.fetch_run_jobs(custody,transport,evidence/'current-attempt-after',endpoints,None)
        envelope['current_run'],envelope['current_jobs'] = run,jobs
        envelope['observed_at'] = importer.utc_now()
        _require_running_writer(custody,jobs,context,envelope['observed_at'],origin['observations']['observer'])
        require(custody.timestamp(envelope['observed_at'],'final receipt observation') >=
                custody.timestamp(prepared['observed_at'],'preliminary receipt observation'),
                'final receipt observation precedes preliminary proof')
        result = custody.verify_retained_receipts(manifest,record,publications,envelope,historical,
                                                  workflow,receipt,policy=policy)
        importer.dump(evidence/'receipt-input.json',envelope)
        importer.dump(evidence/'receipt-result.json',result)
        return result
    run,jobs = importer.fetch_run_jobs(custody,transport,evidence/'current-attempt',endpoints,None)
    transport.get(url,evidence/'receipt-metadata-before.json',importer.JSON_LIMIT)
    envelope = {'schema':'exochain-retained-receipts-input-027/v1','origin':origin,'context':context,
        'current_run':run,'current_jobs':jobs,'upload_outputs':outputs,'members':members,
        'metadata_before':custody.load_json(evidence/'receipt-metadata-before.json','current receipt metadata')}
    # This stage has no after observation and cannot claim completed acceptance.
    custody.retained_receipt_profile(manifest,record,publications,envelope,historical,workflow)
    receipt = evidence/'current-receipts.zip'
    transport.receipt_archive(envelope['metadata_before'],receipt)
    transport.get(url,evidence/'receipt-metadata-after.json',importer.JSON_LIMIT)
    envelope['metadata_after'] = custody.load_json(evidence/'receipt-metadata-after.json','rechecked receipt metadata')
    result = custody.verify_retained_receipts(manifest,record,publications,envelope,historical,workflow,receipt)
    importer.dump(evidence/'receipt-input.json',envelope)
    importer.dump(evidence/'receipt-result.json',result)
    return result


def readback_publications(importer, publications, candidate, capture, evidence):
    """Fresh canonical public reads, with producer result generation disabled."""
    environment = dict(os.environ,RELEASE_RECOVERY_DIRECTORY=str(candidate))
    for profile in ('wasm','llm','sdk'):
        publication, = [p for p in publications['publications'] if p['id'] == profile]
        output = evidence/f'npm-{profile}-readback-output.txt'
        output.touch(mode=0o600,exist_ok=False)
        child = dict(environment,GITHUB_OUTPUT=str(output),
            RELEASE_NPM_TARBALL=str(candidate/publication['lane']/publication['file']['path']),
            RELEASE_EXPECTED_TARBALL_SHA256=publication['file']['sha256'])
        importer.command(['/bin/bash','--noprofile','--norc','-p',str(capture/'publish_release_npm_package.sh'),profile,'retained-readback'],
            evidence/f'npm-{profile}-readback.txt',child,timeout=1200,bounded=True)
    importer.command(['/bin/bash','--noprofile','--norc','-p',str(capture/'recover_release_python_027.sh'),'retained-readback'],
        evidence/'python-readback.txt',environment,timeout=1200,bounded=True)
    require(not os.path.lexists(Path(environment['RUNNER_TEMP'])/'exochain-recovery-receipts'),
            'readback cannot mint producer acceptance receipts')


def check_retained_rebind(custody, importer, manifest, record, policy, transport, evidence,
                          historical, workflow, initial_input, observer, candidate, source_gate):
    """Revalidate source, exact files, retained controls and the original Vector."""
    try:
        source_gate()
        custody.verify_files(manifest,candidate)
        return importer.finalize_retained_observations(manifest,record,policy,custody,transport,evidence,
            historical,workflow,observer=observer,initial_input=initial_input,phase='writer-final')
    except Exception as failure:
        # A failed safety check never authorizes the pending write. The bounded
        # original/retaining read is diagnostic evidence, not a retry of it.
        endpoints = transport.endpoints
        try:
            importer.fetch_run_jobs(custody,transport,evidence/'diagnostic-original',
                {'run':endpoints['run'],'jobs':endpoints['jobs']},manifest['origin']['jobs_total'])
            importer.fetch_run_jobs(custody,transport,evidence/'diagnostic-retaining',
                {'run':endpoints['retaining_run'],'jobs':endpoints['retaining_jobs']},
                record['retaining']['jobs_total'])
            importer.dump(evidence/'diagnostic-result.json',{'status':'read','stop_reason':type(failure).__name__})
        except Exception as diagnostic_failure:
            importer.dump(evidence/'diagnostic-result.json',
                {'status':'failed','stop_reason':type(failure).__name__,
                 'diagnostic_error_type':type(diagnostic_failure).__name__})
            raise failure from diagnostic_failure
        raise


def complete_retained(provider, expected, assets, rebind, receipt_gate, public_gate, journal=None,
                      *, prepare_gate=None, acquire_gate=None, final_gate=None):
    if prepare_gate is not None:
        require(acquire_gate is not None and final_gate is not None, 'incomplete staged writer gates')
        prepare_gate()
        acquire_gate()
    receipt_gate()
    public_gate()
    if final_gate is not None:
        final_gate()
    return recover(provider,expected,assets,rebind,journal)


def retained_main():
    env = os.environ
    operation = env.get('RELEASE_OPERATION')
    require(operation in ('recover-0.2.7-retained', 'recover-0.2.7-retained-404') and
            env.get('RELEASE_VERSION') == '0.2.7', 'wrong retained operation')
    require(env.get('GITHUB_JOB') == 'retained-github' and env.get('RELEASE_WORKFLOW_DRY_RUN') == 'false', 'actual live retained writer job required')
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'genuine hosted dispatch required')
    for name in ('NODE_AUTH_TOKEN','NPM_TOKEN','CARGO_REGISTRY_TOKEN','PYPI_TOKEN','PYPI_API_TOKEN',
                 'TWINE_PASSWORD','ACTIONS_ID_TOKEN_REQUEST_TOKEN','ACTIONS_ID_TOKEN_REQUEST_URL','RELEASE_RECOVERY_PYTHON_PHASE'):
        require(not env.get(name), 'retained writer forbids publication credentials, OIDC and staging')
    sha,ref = env['GITHUB_SHA'],env['GITHUB_REF']
    require(re.fullmatch(r'[0-9a-f]{40}',sha) is not None and sha != PRODUCT_SHA, 'invalid controller')
    require(re.fullmatch(r'refs/tags/v0\.2\.7-recover\.[1-9][0-9]*',ref) is not None, 'invalid controller ref')
    temporary,workspace = Path(env['RUNNER_TEMP']),Path(env['GITHUB_WORKSPACE'])
    require(temporary.is_absolute() and temporary.is_dir() and not temporary.is_symlink(), 'invalid temporary root')
    capture = Path(tempfile.mkdtemp(prefix='exochain-retained-github.',dir=temporary))
    git_env = {'PATH':'/usr/bin:/bin','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_NOSYSTEM':'1','GIT_NO_REPLACE_OBJECTS':'1'}
    paths = {'tools/'+name:name for name in ('verify_release_recovery_027.sh','verify_release_recovery_027.py',
        'import_release_recovery_027.sh','recover_github_release_027.py','publish_release_npm_package.sh',
        'recover_release_python_027.sh','verify_npm_release_tarball.py','verify_npm_release_package.mjs',
        'verify_python_release_package.py','verify_release_sbom.py','transport_release_build_output.py')}
    paths.update({'governance/releases/v0.2.7/'+name:name for name in
                  ('RECOVERY-MANIFEST.json','PUBLICATION-IDENTITIES.json','RETAINED-CUSTODY.json')})
    if operation == 'recover-0.2.7-retained-404':
        paths['governance/releases/v0.2.7/RETAINED-METADATA-POLICY.json'] = 'RETAINED-METADATA-POLICY.json'
    def source(path, commit=sha):
        return subprocess.check_output(['/usr/bin/git','--no-replace-objects','-c','core.fsmonitor=false',
            '-C',str(workspace),'show',commit+':'+path],env=git_env,timeout=30)
    for path,name in paths.items():
        data = source(path)
        require(len(data) <= 4*1024*1024, 'captured source exceeds bound')
        with (capture/name).open('xb') as output: output.write(data)
        (capture/name).chmod(0o400)
    spec = importlib.util.spec_from_file_location('retained_github_custody',capture/'verify_release_recovery_027.py')
    custody = importlib.util.module_from_spec(spec); spec.loader.exec_module(custody)
    require(custody.read_regular(Path(__file__),4*1024*1024,'running writer') ==
            custody.read_regular(capture/'recover_github_release_027.py',4*1024*1024,'captured writer'), 'running writer source differs')
    importer = types.ModuleType('retained_github_importer')
    module_source = custody.read_regular(capture/'import_release_recovery_027.sh',4*1024*1024,'captured importer').decode()
    require(module_source.count('# BEGIN RECOVERY_IMPORT_PYTHON\n') == 1 and module_source.count('# END RECOVERY_IMPORT_PYTHON') == 1, 'importer code boundary ambiguous')
    exec(compile(module_source.split('# BEGIN RECOVERY_IMPORT_PYTHON\n',1)[1].split('# END RECOVERY_IMPORT_PYTHON',1)[0],
                 str(capture/'import_release_recovery_027.sh'),'exec'),importer.__dict__)
    manifest = custody.load_manifest(capture/'RECOVERY-MANIFEST.json')
    publications = custody.load_publications(manifest,capture/'PUBLICATION-IDENTITIES.json')
    record = custody.load_retained_record(manifest,capture/'RETAINED-CUSTODY.json')
    policy = (custody.load_retained_metadata_policy(manifest,record,capture/'RETAINED-METADATA-POLICY.json')
              if operation == 'recover-0.2.7-retained-404' else None)
    workflow = capture/'retaining-workflow.yml'
    with workflow.open('xb') as output: output.write(source('.github/workflows/release.yml',record['retaining']['controller_sha']))
    workflow.chmod(0o400)
    handoff = receipt_handoff(env,lambda raw:custody.parse_json(raw.encode(),'direct receipt output'),
        hashlib.sha256(custody.read_regular(capture/'verify_release_recovery_027.py',4*1024*1024,'captured checker')).hexdigest())
    evidence = capture/'evidence'; evidence.mkdir(mode=0o700)
    archives = capture/'archives'; archives.mkdir(mode=0o700)
    candidate = capture/'artifacts'
    transport = importer.Transport(capture,env.get('RELEASE_GITHUB_TOKEN',''),manifest,record,policy=policy)
    def identities():
        importer.assert_captured_inputs(capture,custody,policy=policy)
        require(source('tools/recover_github_release_027.py') == custody.read_regular(capture/'recover_github_release_027.py',4*1024*1024,'writer'), 'writer source changed')
        subprocess.run(['/bin/bash','--noprofile','--norc','-p',str(capture/'verify_release_recovery_027.sh')],
            env=dict(env),stdout=subprocess.DEVNULL,timeout=240,check=True)
    identities()
    provider = GitHub(env['RELEASE_GITHUB_TOKEN'],custody.parse_json)
    expected, assets, state = {}, {}, {}
    historical = archives/f"{record['custody']['metadata']['id']}.zip"
    if policy is None:
        importer.acquire_retained(manifest,record,custody,transport,evidence,archives,candidate,workflow)
        state['origin'] = custody.load_json(evidence/'retained-origin-input.json','fresh origin')
        receipt, public = retained_release_metadata(manifest,publications,record,sha,ref)
        expected.update(public)
        assets.update(release_assets(custody,manifest,candidate,receipt))
    rebind_count = 0
    def rebind():
        nonlocal rebind_count
        rebind_count += 1
        if policy is not None:
            directory = evidence/f'rebind-{rebind_count}'
            directory.mkdir(mode=0o700)
            check_retained_rebind(custody,importer,manifest,record,policy,transport,directory,
                historical,workflow,state['origin'],state['observer'],candidate,identities)
        else:
            identities()
            custody.verify_files(manifest,candidate)
            for kind in ('payload','custody'):
                pinned = record[kind]['metadata']; path = evidence/f'rebind-{rebind_count}-{kind}.json'
                transport.get(pinned['url'],path,importer.JSON_LIMIT)
                observed = custody.load_json(path,'fresh retained availability')
                custody.exact(custody.semantic_digest(observed),custody.semantic_digest(pinned),'fresh retained availability')
                require(custody.timestamp(importer.utc_now(),'observation') < custody.timestamp(pinned['expires_at'],'expiry'), 'retained artifact expired')
    def prepare_gate():
        state['prepared'] = prepare_current_receipt(custody,importer,manifest,record,policy,transport,evidence,handoff)
        state['observer'] = importer.capture_observer(custody,transport,capture,evidence,'retained-github')
    def acquire_gate():
        importer.acquire_retained(manifest,record,custody,transport,evidence,archives,candidate,workflow,
                                  policy=policy,observer=state['observer'])
        state['origin'] = custody.load_json(evidence/'acquisition-origin-input.json','fresh acquisition origin')
        receipt, public = retained_release_metadata(manifest,publications,record,sha,ref,policy=policy)
        expected.update(public)
        assets.update(release_assets(custody,manifest,candidate,receipt))
    def receipt_gate():
        state['receipt'] = receive_current_receipts(custody,importer,manifest,record,publications,
            transport,evidence,historical,workflow,state['origin'],handoff,policy=policy,
            prepared=state.get('prepared'))
    def public_gate():
        importer.validate_packages(manifest,candidate,capture,evidence,env['RELEASE_PYTHON'],env['RELEASE_NODE'])
        importer.fetch_rust(manifest,custody,transport,evidence)
        readback_publications(importer,publications,candidate,capture,evidence)
        rebind()
    def final_gate():
        directory = evidence/'post-public-final'
        directory.mkdir(mode=0o700)
        state['public_final'] = check_retained_rebind(custody,importer,manifest,record,policy,
            transport,directory,historical,workflow,state['origin'],state['observer'],candidate,identities)
    journal = Journal(capture/'mutation-journal.jsonl',{'controller_sha':sha,'controller_ref':ref,
        'run_id':handoff[0]['run_id'],'run_attempt':handoff[0]['run_attempt'],'original_source':PRODUCT_SHA})
    print('GitHub retained mutation journal: '+str(journal.path),flush=True)
    result = complete_retained(provider,expected,assets,rebind,receipt_gate,public_gate,journal,
        prepare_gate=prepare_gate if policy is not None else None,
        acquire_gate=acquire_gate if policy is not None else None,
        final_gate=final_gate if policy is not None else None)
    importer.dump(evidence/'release-result.json',result)
    print(json.dumps(result,sort_keys=True))


def main():
    env = os.environ
    if env.get('RELEASE_OPERATION') in ('recover-0.2.7-retained', 'recover-0.2.7-retained-404'):
        require(sys.argv[1:] == ['retained-github'], 'explicit retained writer operation required')
        return retained_main()
    require(env.get("RELEASE_OPERATION") == "recover-0.2.7" and env.get("RELEASE_VERSION") == "0.2.7", "wrong recovery operation")
    require(env.get("GITHUB_ACTIONS") == "true" and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and env.get("RUNNER_ENVIRONMENT") == "github-hosted", "genuine hosted dispatch required")
    sha = env["GITHUB_SHA"]
    ref = env["GITHUB_REF"]
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None and sha != PRODUCT_SHA, "invalid controller source")
    require(re.fullmatch(r"refs/tags/v0\.2\.7-recover\.[1-9][0-9]*", ref) is not None, "invalid maintenance ref")
    workspace = Path(env["GITHUB_WORKSPACE"])
    temporary = Path(env["RUNNER_TEMP"])
    require(temporary.is_absolute() and temporary.is_dir() and not temporary.is_symlink(), "invalid private temporary root")
    capture = Path(tempfile.mkdtemp(prefix="exochain-github-recovery.", dir=temporary))
    git_env = {"PATH":"/usr/bin:/bin", "GIT_CONFIG_GLOBAL":"/dev/null", "GIT_CONFIG_NOSYSTEM":"1", "GIT_NO_REPLACE_OBJECTS":"1"}
    for path in ("tools/verify_release_recovery_027.py", "tools/verify_release_recovery_027.sh", "governance/releases/v0.2.7/RECOVERY-MANIFEST.json", "governance/releases/v0.2.7/PUBLICATION-IDENTITIES.json"):
        data = subprocess.check_output(["/usr/bin/git", "--no-replace-objects", "-c", "core.fsmonitor=false", "-C", str(workspace), "show", sha + ":" + path], env=git_env)
        destination = capture / Path(path).name
        with destination.open("xb") as output: output.write(data)
        destination.chmod(0o400)
    spec = importlib.util.spec_from_file_location("fixed_recovery", capture / "verify_release_recovery_027.py")
    custody = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(custody)
    manifest = custody.load_manifest(capture / "RECOVERY-MANIFEST.json")
    publications = custody.load_publications(manifest, capture / "PUBLICATION-IDENTITIES.json")
    directory = Path(env["RELEASE_RECOVERY_DIRECTORY"])
    require(directory == temporary / "exochain-recovery-artifacts", "unexpected artifact root")

    def rebind():
        subprocess.run(["/bin/bash", "--noprofile", "--norc", "-p", str(capture / "verify_release_recovery_027.sh")], check=True, stdout=subprocess.DEVNULL, env=dict(env))
        custody.verify_files(manifest, directory)

    rebind()
    token = env.get("RELEASE_GITHUB_TOKEN", "")
    require(bool(token), "GitHub release token missing")
    provider = GitHub(token, custody.parse_json)
    rust = {}
    for crate in manifest["rust_crates"]:
        status, raw, _ = provider.request("GET", "https://crates.io/api/v1/crates/" + crate["name"] + "/0.2.7", auth=False)
        require(status == 200, "Rust replacement publication missing before release creation")
        rust[crate["name"]] = custody.parse_json(raw, "public Rust version")
    custody.verify_rust(manifest, rust)
    receipt, expected = release_metadata(manifest, publications, sha, ref)
    assets = release_assets(custody,manifest,directory,receipt)
    journal = Journal(capture / "mutation-journal.jsonl", {"controller_sha":sha, "controller_ref":ref, "original_source":PRODUCT_SHA})
    print("GitHub recovery mutation journal: " + str(journal.path), flush=True)
    result = recover(provider, expected, assets, rebind, journal)
    (capture / "release-receipt.json").write_text(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print("GitHub recovery failed: " + str(error), file=sys.stderr)
        raise SystemExit(1) from error
