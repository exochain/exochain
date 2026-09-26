#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
# Fixed, read-only recovery import. The dispatcher captures this entry point
# from the actual controller GITHUB_SHA, before introducing any publication key.
set -euo pipefail
umask 077
fail() { printf 'release recovery import failed: %s\n' "$1" >&2; exit 1; }
if [ "$#" -eq 1 ] && [ "$1" = retained-acceptance ]; then
  [[ "${RELEASE_OPERATION:-}" = recover-0.2.7-retained || "${RELEASE_OPERATION:-}" = recover-0.2.7-retained-404 ]] \
    || fail 'operation and release mode differ'
  [[ "${RELEASE_WORKFLOW_DRY_RUN:-}" = true || "${RELEASE_WORKFLOW_DRY_RUN:-}" = false ]] \
    || fail 'explicit workflow dry-run boolean required'
else
  [ "$#" -eq 0 ] && [ "${RELEASE_OPERATION:-recover-0.2.7}" = recover-0.2.7 ] \
    || fail 'operation and release mode differ'
fi
if /usr/bin/env | /usr/bin/grep -Eq '^BASH_FUNC_.*%%='; then
  fail "inherited shell functions are forbidden"
fi
for credential_name in CARGO_REGISTRY_TOKEN NPM_TOKEN NODE_AUTH_TOKEN \
    TWINE_PASSWORD PYPI_TOKEN PYPI_API_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL; do
  [ -z "${!credential_name:-}" ] || fail "publication credentials and OIDC must be absent"
done
[ "${RELEASE_VERSION:-}" = 0.2.7 ] \
  && [ "${DRY_RUN:-false}" = false ] || fail "only the fixed recovery import is supported"
[ -z "${RELEASE_RECOVERY_PYTHON_PHASE:-}" ] || fail "import must use a fresh clean workspace"
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || fail "real controller GITHUB_SHA is required"
[[ "${GITHUB_WORKSPACE:-}" = /* && "${RUNNER_TEMP:-}" = /* ]] \
  && [ -d "$GITHUB_WORKSPACE" ] && [ ! -L "$GITHUB_WORKSPACE" ] \
  && [ -d "$RUNNER_TEMP" ] && [ ! -L "$RUNNER_TEMP" ] || fail "absolute real workspace and RUNNER_TEMP are required"
[ "${RELEASE_RECOVERY_DIRECTORY:-}" = "$RUNNER_TEMP/exochain-recovery-artifacts" ] \
  && [ ! -e "$RELEASE_RECOVERY_DIRECTORY" ] && [ ! -L "$RELEASE_RECOVERY_DIRECTORY" ] \
  && [ ! -e "$RUNNER_TEMP/exochain-recovery-evidence" ] \
  && [ ! -L "$RUNNER_TEMP/exochain-recovery-evidence" ] || fail "fixed recovery destinations must be absent"
[ -n "${RELEASE_GITHUB_TOKEN:-}" ] || fail "read-only GitHub credential is required"
[[ "${RELEASE_PYTHON:-}" = /* && "${RELEASE_NODE:-}" = /* ]] \
  || fail "absolute pinned Python and Node runtimes are required"
[[ "${GITHUB_OUTPUT:-}" = /* ]] && [ -f "$GITHUB_OUTPUT" ] && [ ! -L "$GITHUB_OUTPUT" ] \
  || fail "a regular absolute GITHUB_OUTPUT file is required"

trusted_git() {
  /usr/bin/env -i PATH=/usr/bin:/bin GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0 \
    /usr/bin/git --no-replace-objects -c core.fsmonitor=false \
    -c core.untrackedCache=false -c core.ignoreStat=false -C "$GITHUB_WORKSPACE" "$@"
}
trusted_git fsck --strict --no-reflogs --no-progress --no-dangling "$GITHUB_SHA" >/dev/null
[ "$(trusted_git rev-parse --verify 'HEAD^{commit}')" = "$GITHUB_SHA" ] \
  || fail "checkout differs from actual controller dispatch"
capture="$(/usr/bin/mktemp -d "$RUNNER_TEMP/exochain-import-027.XXXXXX")"
for helper in verify_release_recovery_027.sh verify_release_recovery_027.py \
    verify_npm_release_tarball.py verify_npm_release_package.mjs \
    verify_python_release_package.py verify_release_sbom.py transport_release_build_output.py; do
  trusted_git show "$GITHUB_SHA:tools/$helper" > "$capture/$helper"
  /bin/chmod 400 "$capture/$helper"
done
trusted_git show "$GITHUB_SHA:governance/releases/v0.2.7/RECOVERY-MANIFEST.json" > "$capture/RECOVERY-MANIFEST.json"
/bin/chmod 400 "$capture/RECOVERY-MANIFEST.json"
if [[ "$RELEASE_OPERATION" = recover-0.2.7-retained || "$RELEASE_OPERATION" = recover-0.2.7-retained-404 ]]; then
  for helper in import_release_recovery_027.sh publish_release_npm_package.sh recover_release_python_027.sh recover_github_release_027.py; do
    trusted_git show "$GITHUB_SHA:tools/$helper" > "$capture/$helper"
    /bin/chmod 400 "$capture/$helper"
  done
  /usr/bin/cmp "${BASH_SOURCE[0]}" "$capture/import_release_recovery_027.sh" \
    || fail 'running retained orchestration differs from actual controller source'
  for record in RETAINED-CUSTODY PUBLICATION-IDENTITIES; do
    trusted_git show "$GITHUB_SHA:governance/releases/v0.2.7/$record.json" > "$capture/$record.json"
    /bin/chmod 400 "$capture/$record.json"
  done
  if [ "$RELEASE_OPERATION" = recover-0.2.7-retained-404 ]; then
    trusted_git show "$GITHUB_SHA:governance/releases/v0.2.7/RETAINED-METADATA-POLICY.json" > "$capture/RETAINED-METADATA-POLICY.json"
    /bin/chmod 400 "$capture/RETAINED-METADATA-POLICY.json"
  fi
  trusted_git show '2198e4ef610e9ef6d04adf726f7f4b3e156a3bc1:.github/workflows/release.yml' > "$capture/retaining-workflow.yml"
  /bin/chmod 400 "$capture/retaining-workflow.yml"
fi
# The wrapper verifies the pinned Python root/version, both signed tags and
# authoritative remote identities, keeping GITHUB_SHA bound to the controller.
/bin/bash --noprofile --norc -p "$capture/verify_release_recovery_027.sh" > "$capture/identity-before.json"
[ "$(/usr/bin/env -i "$RELEASE_NODE" --version)" = v24.15.0 ] || fail "Node must be exactly 24.15.0"

"$RELEASE_PYTHON" -I -B - "$capture" <<'RECOVERY_IMPORT_PYTHON'
# BEGIN RECOVERY_IMPORT_PYTHON
"""Fixed import orchestration. Network and subprocess boundaries are testable;
there are no runtime endpoint, command, manifest, or proof overrides."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit

API = "https://api.github.com/repos/exochain/exochain/actions"
RUN = API + "/runs/35257955565/attempts/1"
PRODUCT_SHA = "666c578f719d1e54fce95d6831a3af92ea80df93"
BASE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
JSON_LIMIT = 4 * 1024 * 1024


class ImportFailure(ValueError):
    """The read-only import did not establish every required identity."""


def require(condition, message):
    if not condition:
        raise ImportFailure(message)


def fixed_endpoints(manifest):
    # The only manifest admitted by main is the canonical semantic digest
    # pinned in the captured validator. Its records supply IDs, never URLs.
    return {"run": RUN,
            "jobs": [RUN + f"/jobs?per_page=100&page={page}" for page in range(1, 11)],
            "metadata": [(a["id"], API + f"/artifacts/{a['id']}") for a in manifest["artifacts"] + manifest["rust_preparation"]],
            "archives": [(a["id"], API + f"/artifacts/{a['id']}/zip") for a in manifest["artifacts"]],
            "rust": [(c["name"], f"https://crates.io/api/v1/crates/{c['name']}/0.2.7") for c in manifest["rust_crates"]]}


def validate_storage_url(url):
    require(type(url) is str and not any(ord(c) < 33 or c == "\\" for c in url), "invalid artifact redirect")
    parsed = urlsplit(url)
    require(parsed.scheme == "https" and parsed.username is None and parsed.password is None
            and parsed.port is None and not parsed.fragment
            and re.fullmatch(r"[a-z0-9-]+\.blob\.core\.windows\.net", parsed.hostname or "") is not None
            and parsed.path.startswith("/"), "artifact redirect is not approved HTTPS storage")
    return url


class Transport:
    """GET-only curl. GitHub Authorization is never used with redirect following.

    A validated storage Location is fetched in a separate credential-free
    process. Signed storage URLs and authorization values are never receipts.
    """
    def __init__(self, scratch, token, manifest, retained=None, *, policy=None):
        # Opaque Bearer transport syntax (RFC 6750 section 2.1), not a
        # GitHub token-prefix/length assumption. This alphabet cannot break
        # the quoted curl config below: no quotes, backslashes or whitespace.
        require(re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token or "") is not None,
                "malformed read-only GitHub credential")
        self.scratch, self.token = Path(scratch), token
        self.endpoints = fixed_endpoints(manifest)
        self.retained = retained
        self.policy = policy
        self.manifest = manifest
        if policy is not None:
            require(retained is not None and policy.get("operation") == "recover-0.2.7-retained-404",
                    "original observation policy is not selected")
        self.retained_storage = set()
        if retained is not None:
            metadata = [retained[kind]["metadata"] for kind in ("payload", "custody")]
            self.endpoints["archives"] = [(m["id"], m["archive_download_url"]) for m in metadata]
            self.endpoints["metadata"] += [(m["id"], m["url"]) for m in metadata]
            retaining_run = API + f"/runs/{retained['retaining']['run_id']}/attempts/1"
            self.endpoints["retaining_run"] = retaining_run
            self.endpoints["retaining_jobs"] = [retaining_run + f"/jobs?per_page=100&page={page}" for page in range(1, 11)]
        self.authenticated = {self.endpoints["run"], *self.endpoints["jobs"],
                              *(url for _, url in self.endpoints["metadata"]),
                              *(url for _, url in self.endpoints["archives"])}
        self.public = {url for _, url in self.endpoints["rust"]}
        if retained is not None:
            self.authenticated.update([self.endpoints["retaining_run"], *self.endpoints["retaining_jobs"]])

    def _get(self, url, destination, limit, authenticated, *, allow_original_404=False):
        retained_payload = (self.retained is not None and limit == self.retained["payload"]["metadata"]["size_in_bytes"]
                            and (url == self.retained["payload"]["metadata"]["archive_download_url"]
                                 or (not authenticated and url in self.retained_storage)))
        require(type(limit) is int and 0 < limit and (limit <= 96 * 1024 * 1024 or retained_payload), "invalid response bound")
        destination = Path(destination)
        require(not os.path.lexists(destination), "download destination must be absent")
        descriptor, header_name = tempfile.mkstemp(prefix="headers-", dir=self.scratch)
        os.close(descriptor)
        header_path = Path(header_name)
        config = 'header = "User-Agent: exochain-release-recovery-027"\n'
        if authenticated:
            config += 'header = "Accept: application/vnd.github+json"\nheader = "X-GitHub-Api-Version: 2022-11-28"\n'
            config += 'header = "Authorization: Bearer ' + self.token + '"\n'
        argv = ["/usr/bin/curl", "--disable", "--silent", "--show-error", "--globoff", "--request", "GET",
                "--proto", "=https", "--tlsv1.2", "--connect-timeout", "10", "--max-time", "240",
                "--max-filesize", str(limit), "--output", str(destination), "--dump-header", str(header_path),
                "--write-out", "%{http_code}", "--config", "-", url]
        succeeded = False
        try:
            try:
                result = subprocess.run(argv, input=config.encode(), capture_output=True, env=BASE_ENV, timeout=250, check=False)
            except (OSError, subprocess.SubprocessError) as error:
                raise ImportFailure("bounded provider GET failed") from error
            # Do not propagate curl diagnostics: a URL may contain a storage SAS.
            require(result.returncode == 0, "bounded provider GET failed")
            require(result.stdout in ((b"200", b"302", b"404") if allow_original_404 else (b"200", b"302")),
                    "unexpected provider HTTP status")
            require(destination.is_file() and not destination.is_symlink() and destination.stat().st_size <= limit,
                    "provider response exceeded its bound")
            require(header_path.stat().st_size <= 65536, "provider response headers exceeded their bound")
            raw_headers = header_path.read_bytes()
            require(raw_headers.endswith(b"\r\n\r\n"), "provider final HTTP headers malformed")
            blocks = raw_headers[:-4].split(b"\r\n\r\n")
            codes = []
            for block in blocks:
                lines = block.split(b"\r\n")
                match = re.fullmatch(rb"HTTP/(?:1\.[01]|2|3) ([1-5][0-9]{2})(?: [\x20-\x7e]*)?", lines[0])
                require(match is not None and all(re.fullmatch(rb"[\x20-\x7e]*", line) is not None for line in lines[1:]),
                        "provider HTTP header block malformed")
                codes.append(int(match.group(1)))
            require(len(codes) >= 1 and all(code in (100, 103) for code in codes[:-1]) and
                    codes[-1] == int(result.stdout), "provider final HTTP status differs from curl status")
            headers = blocks[-1].decode("latin-1")
            locations = [line.split(":", 1)[1].strip() for line in headers.splitlines() if line.lower().startswith("location:")]
            require(len(locations) <= 1, "duplicate provider redirect")
            succeeded = True
            return int(result.stdout), locations
        finally:
            header_path.unlink(missing_ok=True)
            if not succeeded:
                destination.unlink(missing_ok=True)

    def get(self, url, destination, limit):
        require(url in self.authenticated or url in self.public, "endpoint is outside fixed read-only inventory")
        status, locations = self._get(url, destination, limit, url in self.authenticated)
        require(status == 200 and not locations, "metadata and registry redirects are forbidden")

    def original_metadata(self, artifact_id: int, destination: Path) -> dict:
        require(self.policy is not None and type(artifact_id) is int,
                "original observation requires selected policy and numeric ID")
        originals = {item["id"] for item in self.manifest["artifacts"] + self.manifest["rust_preparation"]}
        require(artifact_id in originals, "original observation ID is outside fixed inventory")
        selected = {item["id"]: item for item in self.policy["unavailable_originals"]}.get(artifact_id)
        url = API + f"/artifacts/{artifact_id}"
        require(url in self.authenticated, "original observation endpoint is outside fixed inventory")
        started = utc_now()
        status, locations = self._get(url, destination, JSON_LIMIT, True, allow_original_404=True)
        finished = utc_now()
        if locations or status not in (200, 404) or (status == 404 and selected is None):
            Path(destination).unlink(missing_ok=True)
        require(not locations, "original metadata redirects are forbidden")
        require(status == 200 or (status == 404 and selected is not None),
                "unselected original metadata is unavailable")
        member = f"artifact-metadata/{artifact_id}.json"
        hashes = {item["path"]: item["sha256"] for item in self.retained["custody"]["files"]}
        require(member in hashes, "original historical member is absent")
        observation = {"id": artifact_id, "endpoint_role": "original-artifact-metadata",
                       "request_started_at": started, "request_finished_at": finished,
                       "status": status, "variant": "present" if status == 200 else "unavailable_404",
                       "historical_member": member, "historical_sha256": hashes[member]}
        if status == 404:
            Path(destination).unlink(missing_ok=True)
            require(datetime.fromisoformat(started.replace("Z", "+00:00")) >=
                    datetime.fromisoformat(selected["expires_at"].replace("Z", "+00:00")),
                    "original metadata 404 precedes selected expiry")
        else:
            raw = Path(destination).read_bytes()
            require(len(raw) <= JSON_LIMIT, "original metadata response exceeded bound")
            def unique(pairs):
                value = {}
                for key, item in pairs:
                    require(key not in value, "original metadata has duplicate keys")
                    value[key] = item
                return value
            try:
                observation["metadata"] = json.loads(raw, object_pairs_hook=unique)
            except (UnicodeError, ValueError, TypeError) as error:
                Path(destination).unlink(missing_ok=True)
                raise ImportFailure("original metadata is malformed JSON") from error
            if type(observation["metadata"]) is not dict:
                Path(destination).unlink(missing_ok=True)
            require(type(observation["metadata"]) is dict, "original metadata is not an object")
        return observation

    def archive(self, artifact, destination):
        fixed = dict(self.endpoints["archives"])
        require(artifact["id"] in fixed, "archive is outside fixed artifact inventory")
        # GitHub normally returns 302, but a direct 200 is also checked later
        # against the exact original ZIP digest and size by the custody helper.
        limit = artifact["zip_size"] if self.retained is None else artifact["size_in_bytes"]
        if self.retained is not None:
            require(artifact in [self.retained[k]["metadata"] for k in ("payload", "custody")], "retained artifact is not exactly pinned")
        payload = self.retained is not None and artifact['id'] == self.retained['payload']['metadata']['id']
        self._archive_bytes(fixed[artifact['id']], destination, limit, payload)

    def receipt_archive(self, metadata, destination):
        identifier, limit = metadata.get('id'), metadata.get('size_in_bytes')
        require(type(identifier) is int and 0 < identifier < 10**15, 'invalid receipt artifact ID')
        require(type(limit) is int and 0 < limit <= 1024*1024, 'invalid receipt archive bound')
        url = API + f'/artifacts/{identifier}'
        require(metadata.get('url') == url and metadata.get('archive_download_url') == url+'/zip',
                'receipt endpoint differs from exact ID')
        self._archive_bytes(url+'/zip', destination, limit)

    def _archive_bytes(self, url, destination, limit, retained_payload=False):
        status, locations = self._get(url, destination, limit, True)
        if status == 302:
            require(len(locations) == 1, "artifact download lacks one storage redirect")
            url = validate_storage_url(locations[0])
            Path(destination).unlink()
            if retained_payload:
                self.retained_storage.add(url)
            try:
                status, locations = self._get(url, destination, limit, False)
            finally:
                self.retained_storage.discard(url)
        require(status == 200 and not locations, "artifact storage must return bytes without another redirect")


def dump(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")


def load_module(capture, name):
    spec = importlib.util.spec_from_file_location(name, Path(capture) / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def fetch_run_jobs(custody, transport, evidence, endpoints, expected_total):
    evidence.mkdir(mode=0o700, exist_ok=True)
    transport.get(endpoints["run"], evidence / "run.json", JSON_LIMIT)
    run = custody.load_json(evidence / "run.json", "original run")
    jobs = []
    for page, url in enumerate(endpoints["jobs"], 1):
        path = evidence / f"jobs-page-{page}.json"
        transport.get(url, path, JSON_LIMIT)
        response = custody.load_json(path, "original attempt job page")
        require(type(response) is dict and type(response.get("jobs")) is list, "malformed job page")
        if expected_total is None:
            expected_total = response.get("total_count")
            require(type(expected_total) is int and 0 < expected_total <= 250, "current job inventory is unbounded")
        require(type(response.get("total_count")) is int and response["total_count"] == expected_total,
                "attempt job count differs from the fixed original inventory")
        require(len(response["jobs"]) <= 100, "job page exceeds fixed pagination size")
        jobs.extend(response["jobs"])
        require(len(jobs) <= expected_total, "attempt pagination exceeds fixed inventory")
        if len(response["jobs"]) < 100:
            require(len(jobs) == response["total_count"], "attempt job pagination is incomplete")
            break
    else:
        raise ImportFailure("attempt job pagination did not terminate")
    combined = {"total_count": len(jobs), "jobs": jobs}
    dump(evidence / "jobs.json", combined)
    return run, combined


def fetch_origin_records(manifest, custody, transport, evidence):
    endpoints = fixed_endpoints(manifest)
    run, combined = fetch_run_jobs(custody, transport, evidence, endpoints, manifest["origin"]["jobs_total"])
    metadata_directory = evidence / "artifact-metadata"
    metadata_directory.mkdir(mode=0o700)
    records = []
    for artifact_id, url in endpoints["metadata"]:
        path = metadata_directory / f"{artifact_id}.json"
        transport.get(url, path, JSON_LIMIT)
        records.append(custody.load_json(path, "original artifact metadata"))
    return run, combined, records


def fetch_origin(manifest, custody, transport, evidence):
    return custody.verify_origin(manifest, *fetch_origin_records(manifest, custody, transport, evidence))


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def capture_observer(custody, transport, capture: Path, evidence: Path, role: str) -> dict:
    require(role in ("retained-acceptance", "retained-github") and os.environ.get("GITHUB_JOB") == role,
            "actual retained observer role differs")
    run_text, attempt_text = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[1-9][0-9]*", run_text) is not None and
            re.fullmatch(r"[1-9][0-9]*", attempt_text) is not None, "actual observer run and attempt required")
    run_id, attempt = int(run_text), int(attempt_text)
    sha, ref = os.environ["GITHUB_SHA"], os.environ["GITHUB_REF"]
    run_url = API + f"/runs/{run_id}/attempts/{attempt}"
    endpoints = {"run":run_url,"jobs":[run_url + f"/jobs?per_page=100&page={page}" for page in range(1,11)]}
    transport.authenticated.update([run_url,*endpoints["jobs"]])
    run, response = fetch_run_jobs(custody, transport, evidence / "observer-current", endpoints, None)
    custody.validate_run_identity(run, run_id, attempt, sha, ref.removeprefix("refs/tags/"), completed=False)
    jobs = custody.complete_jobs(response, run_id, attempt, sha, ref.removeprefix("refs/tags/"))
    name = custody.RECEIPT_JOB if role == "retained-acceptance" else custody.RECEIPT_WRITER_JOB
    matches = [job for job in jobs.values() if job.get("name") == name]
    require(len(matches) == 1 and matches[0].get("status") == "in_progress" and matches[0].get("conclusion") is None
            and matches[0].get("completed_at") is None,
            "actual retained observer job is not uniquely running")
    job = matches[0]
    observer = {"run_id":run_id,"run_attempt":attempt,"controller_sha":sha,"controller_ref":ref,
                "controller_tag_object":os.environ["EXPECTED_TAG_OBJECT_SHA"],"job_id":job["id"],
                "job_name":name,"job_started_at":job["started_at"]}
    custody.timestamp(observer["job_started_at"], "actual observer job start")
    dump(evidence / "observer.json", observer)
    return observer


def fetch_retained_controls(manifest, record, custody, transport, evidence: Path, *, phase: str) -> dict:
    require(phase in ("acquisition-start", "acquisition-end", "producer-final", "writer-final", "writer-readback"),
            "invalid retained control phase")
    directory = evidence / (phase + "-controls")
    directory.mkdir(mode=0o700)
    original_run, original_jobs = fetch_run_jobs(custody, transport, directory / "original",
        {"run":transport.endpoints["run"], "jobs":transport.endpoints["jobs"]}, manifest["origin"]["jobs_total"])
    retaining_run, retaining_jobs = fetch_run_jobs(custody, transport, directory / "retaining",
        {"run":transport.endpoints["retaining_run"], "jobs":transport.endpoints["retaining_jobs"]},
        record["retaining"]["jobs_total"])
    retained = []
    for kind in ("payload", "custody"):
        pinned = record[kind]["metadata"]
        path = directory / (kind + "-metadata.json")
        transport.get(pinned["url"], path, JSON_LIMIT)
        retained.append(custody.load_json(path, "fresh retained metadata"))
    controls = {"original_run":original_run,"original_jobs":original_jobs,
                "retaining_run":retaining_run,"retaining_jobs":retaining_jobs,
                "retained_metadata":retained,"observed_at":utc_now()}
    custody.validate_run_identity(original_run, custody.RUN_ID, 1, custody.PRODUCT_COMMIT, "v0.2.7")
    custody.exact(len(custody.complete_jobs(original_jobs, custody.RUN_ID, 1,
        custody.PRODUCT_COMMIT, "v0.2.7")), manifest["origin"]["jobs_total"], "fresh original jobs")
    custody.validate_run_identity(retaining_run, custody.RETAINED_RUN_ID, 1, custody.RETAINED_COMMIT,
                                  "v0.2.7-recover.2")
    custody.exact(len(custody.complete_jobs(retaining_jobs, custody.RETAINED_RUN_ID, 1,
        custody.RETAINED_COMMIT, "v0.2.7-recover.2")), record["retaining"]["jobs_total"], "fresh retaining jobs")
    observed = custody.timestamp(controls["observed_at"], "retained control observation")
    for actual, kind in zip(retained, ("payload", "custody")):
        pinned = record[kind]["metadata"]
        custody.exact(custody.semantic_digest(actual), custody.semantic_digest(pinned), "fresh retained " + kind)
        require(actual == pinned and actual.get("expired") is False and
                custody.timestamp(actual["created_at"], "retained creation") <= observed <
                custody.timestamp(actual["expires_at"], "retained expiry"),
                "fresh retained artifact unavailable")
    dump(directory / "controls.json", controls)
    return controls


def fetch_original_observation_pass(manifest, record, policy, custody, transport, evidence: Path,
                                    observer: dict, *, phase: str) -> dict:
    require(phase in ("acquisition-before", "acquisition-after", "producer-final", "writer-final", "writer-readback"),
            "invalid original observation phase")
    directory = evidence / (phase + "-observations")
    directory.mkdir(mode=0o700)
    records = []
    for artifact_id in sorted(item["id"] for item in manifest["artifacts"] + manifest["rust_preparation"]):
        observation = transport.original_metadata(artifact_id, directory / f"{artifact_id}.json")
        records.append(observation)
    result = {"observed_at":utc_now(),"records":records}
    dump(directory / "pass.json", result)
    return result


def acquire_retained(manifest, record, custody, transport, evidence, archives, candidate, workflow, *, policy=None, observer=None):
    """Canonical custody acquisition; no local archive fallback or caller endpoints.

    Callers still perform the shared package/native structure and genuine native
    cryptography before claiming acceptance. Neither output alone asserts crypto.
    """
    if policy is not None:
        custody.validate_retained_metadata_policy(manifest, record, policy)
        require(type(observer) is dict, "actual retained observer is required")
        controls_before = fetch_retained_controls(manifest, record, custody, transport, evidence, phase="acquisition-start")
        observations_before = fetch_original_observation_pass(manifest, record, policy, custody, transport,
            evidence, observer, phase="acquisition-before")
        for kind in ("payload", "custody"):
            transport.archive(record[kind]["metadata"], archives / f"{record[kind]['metadata']['id']}.zip")
        historical = archives / f"{record['custody']['metadata']['id']}.zip"
        verified = custody.verify_retained_transport(manifest, record, archives, candidate)
        authenticated_history = custody.read_historical_custody(manifest, record, historical)
        custody.verify_origin(manifest, controls_before["original_run"], controls_before["original_jobs"],
                              authenticated_history["metadata"])
        retaining_tag = {"object":record["retaining"]["tag_object"],
                         "commit":record["retaining"]["controller_sha"],
                         "ref":record["retaining"]["controller_ref"]}
        custody._verify_retaining_context(record, controls_before["retaining_run"],
            controls_before["retaining_jobs"], retaining_tag, workflow)
        dump(evidence / "acquisition-historical-result.json", authenticated_history["origin"])
        observations_after = fetch_original_observation_pass(manifest, record, policy, custody, transport,
            evidence, observer, phase="acquisition-after")
        controls_after = fetch_retained_controls(manifest, record, custody, transport, evidence, phase="acquisition-end")
        origin_input = {"schema":"exochain-retained-origin-027/v2","operation":custody.RETAINED_METADATA_OPERATION,
            "policy_sha256":custody.RETAINED_METADATA_POLICY_SHA256,
            "observations":{"schema":"exochain-retained-original-observations-027/v1",
                "operation":custody.RETAINED_METADATA_OPERATION,"policy_sha256":custody.RETAINED_METADATA_POLICY_SHA256,
                "observer":observer,"before":observations_before,"after":observations_after},
            "controls_before":controls_before,"controls_after":controls_after,
            "retaining_tag":retaining_tag}
        origin = custody.verify_retained_origin(manifest, record, origin_input, historical, workflow, policy=policy)
        dump(evidence / "acquisition-origin-input.json", origin_input)
        dump(evidence / "acquisition-origin-result.json", origin)
        dump(evidence / "retained-transport-result.json", verified)
        return origin, verified
    before, after = [], []
    for kind in ("payload", "custody"):
        pinned = record[kind]["metadata"]
        path = evidence / f"retained-{kind}-before.json"
        transport.get(pinned["url"], path, JSON_LIMIT)
        current = custody.load_json(path, "current retained metadata")
        require(type(current) is dict and current == pinned and current.get("expired") is False,
                "retained metadata differs before download")
        before.append(current)
        transport.archive(pinned, archives / f"{pinned['id']}.zip")
    for kind in ("payload", "custody"):
        pinned = record[kind]["metadata"]
        path = evidence / f"retained-{kind}-after.json"
        transport.get(pinned["url"], path, JSON_LIMIT)
        after.append(custody.load_json(path, "rechecked retained metadata"))
    original_run, original_jobs, metadata = fetch_origin_records(manifest, custody, transport, evidence / "current-original")
    retaining_run, retaining_jobs = fetch_run_jobs(custody, transport, evidence / "retaining",
        {"run":transport.endpoints["retaining_run"], "jobs":transport.endpoints["retaining_jobs"]},
        record["retaining"]["jobs_total"])
    retaining = record["retaining"]
    origin_input = {"schema":"exochain-retained-origin-input-027/v1", "observed_at":utc_now(),
        "retaining_run":retaining_run, "retaining_jobs":retaining_jobs,
        "retaining_tag":{"object":retaining["tag_object"],"commit":retaining["controller_sha"],"ref":retaining["controller_ref"]},
        "original_run":original_run,"original_jobs":original_jobs,"original_metadata":metadata,
        "retained_before":before,"retained_after":after}
    historical = archives / f"{record['custody']['metadata']['id']}.zip"
    origin = custody.verify_retained_origin(manifest, record, origin_input, historical, workflow)
    dump(evidence / "retained-origin-input.json", origin_input)
    dump(evidence / "retained-origin-result.json", origin)
    verified = custody.verify_retained_transport(manifest, record, archives, candidate)
    dump(evidence / "retained-transport-result.json", verified)
    return origin, verified


def finalize_retained_observations(manifest, record, policy, custody, transport, evidence: Path,
                                   historical: Path, workflow: Path, *, observer: dict,
                                   initial_input: dict, phase: str) -> dict:
    require(phase in ("producer-final", "writer-final", "writer-readback"), "invalid final observation phase")
    custody.validate_retained_metadata_policy(manifest, record, policy)
    require(initial_input.get("schema") == "exochain-retained-origin-027/v2" and
            initial_input["observations"]["observer"] == observer, "initial origin or observer differs")
    initial = custody.verify_retained_origin(manifest, record, initial_input, historical, workflow, policy=policy)
    after = fetch_original_observation_pass(manifest, record, policy, custody, transport,
        evidence, observer, phase=phase)
    controls_after = fetch_retained_controls(manifest, record, custody, transport, evidence, phase=phase)
    final_input = {**initial_input, "observations":{**initial_input["observations"],"after":after},
                   "controls_after":controls_after}
    final = custody.verify_retained_origin(manifest, record, final_input, historical, workflow, policy=policy)
    require(final["original_vector"] == initial["original_vector"], "original availability transitioned after acquisition")
    dump(evidence / (phase + "-origin-input.json"), final_input)
    dump(evidence / (phase + "-origin-result.json"), final)
    return final_input


def fetch_rust(manifest, custody, transport, evidence):
    directory = evidence / "rust-responses"
    directory.mkdir(mode=0o700)
    def fetch(item):
        name, url = item
        path = directory / (name + ".json")
        transport.get(url, path, JSON_LIMIT)
        return name, custody.load_json(path, "public Rust version")
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = dict(pool.map(fetch, fixed_endpoints(manifest)["rust"]))
    return custody.verify_rust(manifest, responses)


def check_attestation(manifest, artifact, results):
    require(type(results) is list and 0 < len(results) <= 10, "native archive lacks bounded verified attestations")
    invocation = manifest["origin"]["native_attestation_invocation"]
    expected = {"issuer":"https://token.actions.githubusercontent.com",
                "sourceRepositoryURI":"https://github.com/exochain/exochain",
                "sourceRepositoryDigest":PRODUCT_SHA,"sourceRepositoryRef":"refs/tags/v0.2.7",
                "sourceRepositoryIdentifier":"1116455646","sourceRepositoryOwnerIdentifier":"129763194",
                "buildSignerURI":"https://github.com/exochain/exochain/.github/workflows/release.yml@refs/tags/v0.2.7",
                "buildSignerDigest":PRODUCT_SHA,"runnerEnvironment":"github-hosted",
                "buildTrigger":"workflow_dispatch","runInvocationURI":invocation}
    require(artifact["lane"] in ("native-x86_64", "native-aarch64"), "only original native archives have build attestations")
    subjects = sorted([{"name":a["files"][0]["path"], "digest":{"sha256":a["files"][0]["sha256"]}}
                       for a in manifest["artifacts"] if a["lane"].startswith("native-")], key=lambda s:s["name"])
    for result in results:
        require(type(result) is dict and type(result.get("verificationResult")) is dict, "raw bundle is not a verified native attestation")
        verified = result["verificationResult"]
        require(verified.get("mediaType") == "application/vnd.dev.sigstore.verificationresult+json;version=0.1", "unknown native verification result")
        certificate = verified.get("signature", {}).get("certificate", {})
        require(all(type(certificate.get(key)) is str and certificate[key] == value for key, value in expected.items()),
                "verified native certificate differs from original producer invocation")
        require(type(verified.get("verifiedTimestamps")) is list and len(verified["verifiedTimestamps"]) > 0,
                "native verification lacks authenticated timestamps")
        statement = verified.get("statement", {})
        require(statement.get("_type") == "https://in-toto.io/Statement/v1"
                and statement.get("predicateType") == "https://slsa.dev/provenance/v1", "wrong verified native statement type")
        require(statement.get("subject") == subjects,
                "verified native subject differs from original bytes")
        require(statement.get("predicate", {}).get("runDetails", {}).get("metadata", {}).get("invocationId") == invocation,
                "verified native statement differs from original invocation")
    return {"lane":artifact["lane"], "original_invocation":invocation, "verified_attestations":len(results)}


def verify_attestation(manifest, artifact, archive, evidence, token, custody):
    config = evidence / (artifact["lane"] + "-gh-config")
    config.mkdir(mode=0o700)
    argv = ["/usr/bin/gh", "attestation", "verify", str(archive), "--repo", "exochain/exochain",
            "--source-ref", "refs/tags/v0.2.7", "--source-digest", PRODUCT_SHA, "--signer-digest", PRODUCT_SHA,
            "--signer-workflow", "exochain/exochain/.github/workflows/release.yml",
            "--deny-self-hosted-runners", "--format", "json"]
    environment = dict(BASE_ENV, GH_HOST="github.com", GH_TOKEN=token, GH_CONFIG_DIR=str(config),
                       HOME=str(config), GH_PROMPT_DISABLED="1")
    result = subprocess.run(argv, env=environment, capture_output=True, timeout=240, check=False)
    require(result.returncode == 0, "gh cryptographic native attestation verification failed")
    verified = custody.parse_json(result.stdout, "cryptographically verified native attestations")
    receipt = check_attestation(manifest, artifact, verified)
    dump(evidence / (artifact["lane"] + "-verified-attestations.json"), verified)
    return receipt


def validate_native(archive, capture):
    gzip = load_module(capture, "verify_npm_release_tarball")
    native = load_module(capture, "transport_release_build_output")
    stream = gzip.read_one_gzip_member(archive)
    with tarfile.open(fileobj=io.BytesIO(stream), mode="r:") as bundle:
        members = []
        for member in bundle:
            members.append(member)
            require(len(members) <= len(native.EXPECTED_FILES) + 1, "native final archive contains extra members")
        gzip.validate_tar_boundary(stream, members)
        require(len(members) == len(native.EXPECTED_FILES) + 1, "native final library inventory is incomplete")
        root = members[0]
        require(root.name == "." and root.isdir() and root.size == 0 and root.mode == 0o700, "native final archive root differs")
        total = 0
        for member, name in zip(members[1:], native.EXPECTED_FILES):
            require(member.name == "./" + name and member.isreg() and member.mode == 0o644
                    and 0 < member.size <= native.FILE_SIZE_LIMITS[name], "native final archive library differs")
            total += member.size
        require(total <= native.MAX_TOTAL_PAYLOAD_SIZE, "native final archive expands beyond its bound")
        for member in members:
            require(member.uid == 0 and member.gid == 0 and member.mtime == 0 and not member.uname
                    and not member.gname and not member.pax_headers and not member.linkname
                    and member.offset_data == member.offset + 512, "native final archive has noncanonical metadata")
    return {"libraries":len(native.EXPECTED_FILES), "executables":0}


def validate_sboms(manifest, directory, capture):
    validator = load_module(capture, "verify_release_sbom")
    artifact = next(a for a in manifest["artifacts"] if a["lane"] == "sbom")
    for file in artifact["files"]:
        raw = validator.read_regular(directory / file["path"], validator.RAW_FILE_LIMIT, "original canonical SBOM")
        value = validator.parse_json(raw, "original canonical SBOM")
        require(type(value) is dict and set(value) == validator.TOP_LEVEL_KEYS | {"$schema"}
                and value.get("$schema") == validator.SCHEMA_URI
                and value.get("bomFormat") == "CycloneDX" and value.get("specVersion") == "1.5"
                and type(value.get("version")) is int and value["version"] == 1, "canonical SBOM format differs")
        metadata = value.get("metadata", {})
        require(set(metadata) == validator.METADATA_KEYS and metadata.get("timestamp") == validator.EXPECTED_TIMESTAMP
                and metadata.get("tools") == [validator.EXPECTED_TOOL]
                and metadata.get("properties") == [validator.EXPECTED_TARGET_PROPERTY], "canonical SBOM metadata differs")
        component = metadata.get("component", {})
        require(component.get("version") == "0.2.7"
                and file["path"] == "exochain-0.2.7-" + component.get("name", "") + ".cdx.json", "canonical SBOM package differs")
        validator.reject_forbidden_strings(value, ("/home/runner/", "/Users/", "/tmp/"), "original canonical SBOM")
        require(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n" == raw,
                "SBOM bytes are not canonical JSON")
    # Original graph/lock validation is established by the pinned successful
    # producer and exact original bytes, not by rebuilding a new Cargo graph.
    return {"canonical_sboms":len(artifact["files"])}


def command(argv, receipt, extra_env=None, timeout=240, bounded=False):
    environment = dict(BASE_ENV)
    environment.update(extra_env or {})
    with receipt.open("xb") as stream:
        if bounded:
            # Only this collector owns diagnostic file descriptors. Children
            # get pipes in a private process group, so neither buffering nor a
            # surviving descendant can grow retained diagnostics after return.
            with Path(str(receipt)+".stderr").open("xb") as errors:
                with subprocess.Popen(argv, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      start_new_session=True) as process:
                    deadline = time.monotonic() + timeout
                    try:
                        with selectors.DefaultSelector() as pending:
                            for pipe, output in ((process.stdout,stream),(process.stderr,errors)):
                                pending.register(pipe,selectors.EVENT_READ,[output,0])
                            while pending.get_map():
                                remaining = deadline - time.monotonic()
                                if remaining <= 0:
                                    raise subprocess.TimeoutExpired(argv,timeout)
                                for key, _ in pending.select(remaining):
                                    chunk = os.read(key.fd,65536)
                                    if not chunk:
                                        pending.unregister(key.fileobj)
                                        continue
                                    output, written = key.data
                                    available = 1024 * 1024 - written
                                    output.write(chunk[:available])
                                    key.data[1] += min(len(chunk),available)
                                    require(len(chunk) <= available, "public checker diagnostics exceeded their bound")
                            process.wait(timeout=max(0,deadline-time.monotonic()))
                        result = process
                    finally:
                        # On rejection, kill the complete group before reaping
                        # the direct child. Also remove background descendants
                        # when the direct shell returned or closed its pipes.
                        try:
                            os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                        stream.flush()
                        errors.flush()
        else:
            result = subprocess.run(argv, env=environment, stdout=stream, stderr=subprocess.PIPE, timeout=timeout, check=False)
    require(result.returncode == 0, "captured canonical artifact validator rejected input: " + Path(argv[0]).name)


def validate_packages(manifest, artifacts, capture, evidence, python, node):
    for lane, profile in [("npm-wasm", "wasm"), ("npm-llm", "llm"), ("npm-sdk", "sdk")]:
        artifact = next(a for a in manifest["artifacts"] if a["lane"] == lane)
        archive = artifacts / lane / artifact["files"][0]["path"]
        unpacked = evidence / (lane + "-inspected")
        command([python, "-I", "-B", str(capture / "verify_npm_release_tarball.py"), str(archive), str(unpacked)],
                evidence / (lane + "-tarball-check.txt"))
        command([node, str(capture / "verify_npm_release_package.mjs"), profile, str(unpacked / "package")],
                evidence / (lane + "-package-check.txt"), {"RELEASE_EXPECTED_VERSION":"0.2.7"})
        # These inspected copies are temporary data, never package lifecycle input.
        shutil.rmtree(unpacked)
    command([python, "-I", "-B", str(capture / "verify_python_release_package.py"), "artifacts",
             str(artifacts / "python/dist"), "exochain", "0.2.7", "--expect-manifest", str(artifacts / "python/artifact-manifest.tsv")],
            evidence / "python-artifact-check.json")
    summary = {"npm_packages":3,"python_distributions":2,"sbom":validate_sboms(manifest, artifacts / "sbom", capture)}
    for lane in ("native-x86_64", "native-aarch64"):
        artifact = next(a for a in manifest["artifacts"] if a["lane"] == lane)
        summary[lane] = validate_native(artifacts / lane / artifact["files"][0]["path"], capture)
    return summary


def check_destinations(runner_temp, destination):
    runner_temp, destination = Path(runner_temp), Path(destination)
    require(runner_temp.is_absolute() and runner_temp.is_dir() and not runner_temp.is_symlink()
            and runner_temp.resolve() == runner_temp, "RUNNER_TEMP must be one canonical real directory")
    require(destination == runner_temp / "exochain-recovery-artifacts", "artifact destination must be the fixed RUNNER_TEMP child")
    evidence = runner_temp / "exochain-recovery-evidence"
    require(not os.path.lexists(destination) and not os.path.lexists(evidence), "fixed import destinations must be absent")
    return evidence


def current_receipt_context(custody, transport, capture, evidence, python, node, *, observer=None, checked_at=None):
    run_text, attempt_text = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[1-9][0-9]*", run_text) is not None
            and re.fullmatch(r"[1-9][0-9]*", attempt_text) is not None, "current numeric run and attempt required")
    run_id, attempt = int(run_text), int(attempt_text)
    sha, ref = os.environ["GITHUB_SHA"], os.environ["GITHUB_REF"]
    run_url = API + f"/runs/{run_id}/attempts/{attempt}"
    endpoints = {"run":run_url,"jobs":[run_url + f"/jobs?per_page=100&page={p}" for p in range(1,11)]}
    transport.authenticated.update([run_url, *endpoints["jobs"]])
    run, jobs_response = fetch_run_jobs(custody, transport, evidence / "current-producer", endpoints, None)
    custody.validate_run_identity(run, run_id, attempt, sha, ref.removeprefix("refs/tags/"), completed=False)
    jobs = custody.complete_jobs(jobs_response, run_id, attempt, sha, ref.removeprefix("refs/tags/"))
    producers = [job for job in jobs.values() if job.get("name") == custody.RECEIPT_JOB]
    require(len(producers) == 1 and producers[0].get("status") == "in_progress" and
            producers[0].get("conclusion") is None and producers[0].get("completed_at") is None,
            "current acceptance producer is not uniquely running")
    require(os.environ.get("GITHUB_JOB") == "retained-acceptance", "actual job key is not retained acceptance")
    if observer is not None:
        require(observer == {"run_id":run_id,"run_attempt":attempt,"controller_sha":sha,"controller_ref":ref,
            "controller_tag_object":os.environ["EXPECTED_TAG_OBJECT_SHA"],"job_id":producers[0]["id"],
            "job_name":custody.RECEIPT_JOB,"job_started_at":producers[0]["started_at"]},
            "captured observer differs from current producer")
        require(checked_at is not None, "final accepted check time is required")
        custody.timestamp(checked_at, "final accepted check time")
    else:
        require(checked_at is None, "v1 context cannot accept a caller check time")
    def version(argv, pattern):
        result = subprocess.run(argv, env=BASE_ENV, capture_output=True, timeout=30, check=False)
        require(result.returncode == 0 and len(result.stdout) < 4096, "runtime identity command failed")
        match = re.search(pattern, result.stdout.decode("ascii"))
        require(match is not None, "runtime identity is not exact")
        return match.group(1)
    tool_view = Path(os.environ["TRUSTED_RELEASE_PATH"].split(":")[0])
    context = {"controller_sha":sha,"controller_ref":ref,"controller_tag_object":os.environ["EXPECTED_TAG_OBJECT_SHA"],
        "run_id":run_id,"run_attempt":attempt,"producer_job_id":producers[0]["id"],"checked_at":checked_at or utc_now(),
        "checker_sha256":hashlib.sha256(custody.read_regular(capture / "verify_release_recovery_027.py", JSON_LIMIT, "captured checker")).hexdigest(),
        "runtime_versions":{
            "python":version([python,"-I","-B","-c","import sys; print('.'.join(map(str,sys.version_info[:3])))"],r"^([0-9]+\.[0-9]+\.[0-9]+)\n$"),
            "node":version([node,"--version"],r"^v([0-9]+\.[0-9]+\.[0-9]+)\n$"),
            "npm":version([node,str(tool_view / "npm"),"--version"],r"^([0-9]+\.[0-9]+\.[0-9]+)\n$"),
            "gh":version(["/usr/bin/gh","--version"],r"^gh version ([0-9]+\.[0-9]+\.[0-9]+) ")},
        "dry_run":os.environ["RELEASE_WORKFLOW_DRY_RUN"] == "true"}
    return context


def accept_publications(custody, publications, candidate, capture, evidence, runner_temp):
    """Execute the complete existing validators; only process exit zero permits results."""
    root = runner_temp / "exochain-recovery-receipts"
    require(not os.path.lexists(root), "current package receipt directory must be absent")
    environment = dict(os.environ, RELEASE_RECOVERY_DIRECTORY=str(candidate))
    # Child identity wrappers require GitHub read access. All public registry,
    # install and cryptographic checker subprocesses have env -i boundaries.
    outcomes = []
    for profile in ("wasm", "llm", "sdk"):
        publication, = [p for p in publications["publications"] if p["id"] == profile]
        child_output = evidence / f"npm-{profile}-diagnostic-output.txt"
        child_output.touch(mode=0o600, exist_ok=False)
        child_env = dict(environment, RELEASE_NPM_TARBALL=str(candidate / publication["lane"] / publication["file"]["path"]),
                         RELEASE_EXPECTED_TARBALL_SHA256=publication["file"]["sha256"], GITHUB_OUTPUT=str(child_output))
        command(["/bin/bash","--noprofile","--norc","-p",str(capture / "publish_release_npm_package.sh"),profile,"retained-accept"],
                evidence / f"npm-{profile}-acceptance.txt", child_env, timeout=1200, bounded=True)
        result = custody.load_json(root / f"npm-{profile}/result.json", "current npm acceptance result")
        expected = {"operation":os.environ["RELEASE_OPERATION"],"controller_commit":os.environ["GITHUB_SHA"],
            "controller_ref":os.environ["GITHUB_REF"],"package":publication["package"],"version":"0.2.7",
            "tarball_sha256":publication["file"]["sha256"],"provenance_commit":publication["source"]["commit"],
            "provenance_ref":publication["source"]["ref"],"exit_code":0,"acceptance_verified":True,
            "mutation_attempted":False,"upload_exit_code":None,"mutation_outcome":"verified","phase":"finished"}
        for key, value in expected.items():
            custody.exact(result.get(key), value, "current npm acceptance " + key)
        require(not (root / f"npm-{profile}/intent.json").exists()
                and not (root / f"npm-{profile}/outcome.json").exists(), "retained npm attempted an upload")
        for name in ("registry.json","audit.json"):
            custody.load_json(root / f"npm-{profile}" / name, "current complete npm readback")
        outcomes.append(publication_result(publication))
    command(["/bin/bash","--noprofile","--norc","-p",str(capture / "recover_release_python_027.sh"),"accept"],
            evidence / "python-acceptance.txt", environment, timeout=1200, bounded=True)
    result = custody.load_json(root / "python/result.json", "current Python acceptance")
    for key,value in {"schema":"exochain-python-retained-acceptance/v1","operation":os.environ["RELEASE_OPERATION"],
        "controller_commit":os.environ["GITHUB_SHA"],"controller_ref":os.environ["GITHUB_REF"],
        "exit_code":0,"acceptance_verified":True,"mutation_attempted":False}.items():
        custody.exact(result.get(key),value,"current Python " + key)
    require(type(result.get("files")) is list and len(result["files"]) == 2, "current Python inventory incomplete")
    for publication, checked in zip(publications["publications"][3:], result["files"]):
        for key,value in {"filename":Path(publication["file"]["path"]).name,"sha256":publication["file"]["sha256"],
            "source":publication["source"],"public_bytes_verified":True,"crypto_verified":True,
            "exit_code":0,"mutation_attempted":False}.items():
            custody.exact(checked.get(key),value,"current Python file " + key)
        outcomes.append(publication_result(publication))
    require(len(outcomes) == 5, "current mapped publication acceptance incomplete")
    return outcomes


def retained_github_preflight(capture, custody, manifest, publications, record, candidate, evidence, *, policy=None):
    github = load_module(capture, 'recover_github_release_027')
    receipt, expected = github.retained_release_metadata(manifest,publications,record,
        os.environ['GITHUB_SHA'],os.environ['GITHUB_REF'],policy=policy)
    assets = github.release_assets(custody,manifest,candidate,receipt)
    provider = github.GitHub(os.environ['RELEASE_GITHUB_TOKEN'],custody.parse_json)
    result = github.preflight(provider,expected,assets,lambda:custody.verify_files(manifest,candidate))
    dump(evidence/'github-preflight.json',result)


def publication_result(publication):
    return {**{key:publication[key] for key in ("id","package","version","file","source")},
            "public_bytes_verified":True,"crypto_verified":True}


def create_retained_receipts(custody, manifest, record, context, summary, checked_publications, evidence, *, policy=None):
    bindings = custody.retained_receipt_bindings(manifest, record, context, summary["origin"], policy=policy)
    require(summary["rust"] == {"version":"0.2.7","crates_verified":32}, "current Rust acceptance incomplete")
    transport = summary["retained_transport"]
    for key,value in {"retained_archives_verified":2,"payload_files_verified":40,"original_zip_envelopes_verified":0}.items():
        custody.exact(transport.get(key),value,"current retained transport " + key)
    custody.exact(summary["files"]["files_verified"],transport["payload_files_verified"],"final fixed file count")
    native = []
    for artifact in manifest["artifacts"]:
        if not artifact["lane"].startswith("native-"):
            continue
        checked, = [entry for entry in summary["native_attestations"] if entry["lane"] == artifact["lane"]]
        require(checked["verified_attestations"] > 0 and checked["original_invocation"] == manifest["origin"]["native_attestation_invocation"],
                "current native verification incomplete")
        require(summary["packages"][artifact["lane"]] == {"libraries":29,"executables":0}, "current native structure incomplete")
        native.append({"lane":artifact["lane"],"file":artifact["files"][0],"repository":"exochain/exochain",
            "source":{"commit":PRODUCT_SHA,"ref":"refs/tags/v0.2.7"},
            "signer_workflow":"exochain/exochain/.github/workflows/release.yml","signer_digest":PRODUCT_SHA,
            "invocation":checked["original_invocation"],"crypto_verified":True})
    identity = custody.load_json(evidence / "identity-after.json", "final signatures")
    for key in ("controller_signature_verified","product_signature_verified","retaining_signature_verified"):
        require(identity.get(key) is True, "current signatures incomplete")
    custody_result = {"payload_files_verified":summary["files"]["files_verified"],
        "retained_archives_verified":transport["retained_archives_verified"],
        "original_zip_envelopes_verified":transport["original_zip_envelopes_verified"],
        "native_attestations_verified":len(native),
        "native_libraries_per_archive":summary["packages"][native[0]["lane"]]["libraries"],"native_attestations":native,
        **{key:identity[key] for key in ("controller_signature_verified","product_signature_verified","retaining_signature_verified")}}
    acceptance_result = {"rust":{"crates_verified":summary["rust"]["crates_verified"],"checksum_verified":True,
        "version_verified":True,"unyanked_verified":True},"publications":checked_publications}
    receipt_directory = evidence / "current-receipts"
    receipt_directory.mkdir(mode=0o700)
    members = []
    for name, result in (("custody",custody_result),("acceptance",acceptance_result)):
        path = receipt_directory / (name + "-receipt.json")
        value = {"schema":"exochain-retained-"+name+"-receipt-027/"+("v2" if policy is not None else "v1"),
                 **bindings,"results":result}
        if policy is not None:
            value["original_observations"] = summary["origin"]["observations"]
        dump(path, value)
        path.chmod(0o600)
        data = custody.read_regular(path, 512 * 1024, "current receipt")
        members.append({"path":path.name,"size":len(data),"sha256":hashlib.sha256(data).hexdigest()})
    dump(evidence / "current-receipt-context.json", context)
    dump(evidence / "current-receipt-members.json", members)
    return members


def assert_captured_inputs(capture, custody, *, policy=None):
    paths = {"tools/"+name:name for name in (
        "verify_release_recovery_027.sh", "verify_release_recovery_027.py", "verify_npm_release_tarball.py",
        "verify_npm_release_package.mjs", "verify_python_release_package.py", "verify_release_sbom.py",
        "transport_release_build_output.py", "import_release_recovery_027.sh", "publish_release_npm_package.sh", "recover_release_python_027.sh", "recover_github_release_027.py")}
    paths.update({"governance/releases/v0.2.7/"+name:name for name in (
        "RECOVERY-MANIFEST.json", "PUBLICATION-IDENTITIES.json", "RETAINED-CUSTODY.json")})
    if policy is not None:
        paths["governance/releases/v0.2.7/RETAINED-METADATA-POLICY.json"] = "RETAINED-METADATA-POLICY.json"
    environment = dict(BASE_ENV,GIT_CONFIG_GLOBAL="/dev/null",GIT_CONFIG_NOSYSTEM="1",GIT_NO_REPLACE_OBJECTS="1")
    for source, name in paths.items():
        result = subprocess.run(["/usr/bin/git","--no-replace-objects","-c","core.fsmonitor=false",
            "-c","core.untrackedCache=false","-C",os.environ["GITHUB_WORKSPACE"],"show",os.environ["GITHUB_SHA"]+":"+source],
            env=environment,capture_output=True,timeout=30,check=False)
        require(result.returncode == 0 and len(result.stdout) <= JSON_LIMIT
                and result.stdout == custody.read_regular(capture / name, JSON_LIMIT, "captured input"),
                "captured controller helper or governance input changed")


def main():
    capture = Path(sys.argv[1])
    custody = load_module(capture, "verify_release_recovery_027")
    manifest_path = capture / "RECOVERY-MANIFEST.json"
    manifest = custody.load_manifest(manifest_path)
    runner_temp, destination = Path(os.environ["RUNNER_TEMP"]), Path(os.environ["RELEASE_RECOVERY_DIRECTORY"])
    final_evidence = check_destinations(runner_temp, destination)
    evidence = capture / "evidence"; evidence.mkdir(mode=0o700)
    candidate = capture / "artifacts"
    archives = capture / "archives"; archives.mkdir(mode=0o700)
    token = os.environ["RELEASE_GITHUB_TOKEN"]
    operation = os.environ.get("RELEASE_OPERATION")
    retained = operation in ("recover-0.2.7-retained", "recover-0.2.7-retained-404")
    record = custody.load_retained_record(manifest, capture / "RETAINED-CUSTODY.json") if retained else None
    policy = custody.load_retained_metadata_policy(manifest, record, capture / "RETAINED-METADATA-POLICY.json") \
        if operation == "recover-0.2.7-retained-404" else None
    transport = Transport(capture, token, manifest, record, policy=policy) if retained else Transport(capture, token, manifest)
    python, node = os.environ["RELEASE_PYTHON"], os.environ["RELEASE_NODE"]
    require(Path(node).is_absolute() and Path(node).resolve().is_file(), "invalid pinned Node executable")
    require(shutil.disk_usage(runner_temp).free >= 4 * 1024**3, "import requires at least four GiB free")
    before = custody.load_json(capture / "identity-before.json", "initial identity")
    if retained:
        assert_captured_inputs(capture, custody, policy=policy)
    summary = {"controller_sha":before["controller_sha"],"controller_ref":before["controller_ref"],
               "product":manifest["product"]}
    helper = [python, "-I", "-B", str(capture / "verify_release_recovery_027.py")]
    if retained:
        if policy is not None:
            observer = capture_observer(custody, transport, capture, evidence, "retained-acceptance")
        else:
            observer = None
        summary["origin"], summary["retained_transport"] = acquire_retained(manifest, record, custody, transport, evidence, archives,
                                              candidate, capture / "retaining-workflow.yml", policy=policy, observer=observer)
    else:
        summary["origin"] = fetch_origin(manifest, custody, transport, evidence)
        command(helper + ["origin", "--manifest", str(manifest_path), "--run", str(evidence / "run.json"),
                      "--jobs", str(evidence / "jobs.json"), "--artifact-metadata", str(evidence / "artifact-metadata")], evidence / "origin-check.json")
        for artifact in manifest["artifacts"]:
            transport.archive(artifact, archives / f"{artifact['id']}.zip")
        command(helper + ["artifacts", "--manifest", str(manifest_path), "--archives", str(archives),
                      "--destination", str(candidate)], evidence / "artifact-custody-check.json")
    summary["rust"] = fetch_rust(manifest, custody, transport, evidence)
    command(helper + ["rust-registry", "--manifest", str(manifest_path), "--responses", str(evidence / "rust-responses")],
            evidence / "rust-registry-check.json")
    summary["packages"] = validate_packages(manifest, candidate, capture, evidence, python, node)
    summary["native_attestations"] = []
    for artifact in manifest["artifacts"]:
        if artifact["lane"].startswith("native-"):
            summary["native_attestations"].append(verify_attestation(manifest, artifact,
                candidate / artifact["lane"] / artifact["files"][0]["path"], evidence, token, custody))
    if retained:
        publications = custody.load_publications(manifest, capture / "PUBLICATION-IDENTITIES.json")
        checked_publications = accept_publications(custody, publications, candidate, capture, evidence, runner_temp)
        retained_github_preflight(capture,custody,manifest,publications,record,candidate,evidence,policy=policy)
    command(helper + ["files", "--manifest", str(manifest_path), "--directory", str(candidate)], evidence / "final-file-check.json")
    # No package was executed. Recheck source, signatures and authoritative
    # remote tags immediately before exposing accepted data to later jobs.
    with (evidence / "identity-after.json").open("xb") as output:
        result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-p", str(capture / "verify_release_recovery_027.sh")],
                                env=dict(os.environ), stdout=output, timeout=240, check=False)
    require(result.returncode == 0, "final controller/product identity recheck failed")
    after = custody.load_json(evidence / "identity-after.json", "final identity")
    require(all(before.get(key) == after.get(key) for key in ("controller_sha", "controller_ref", "product_commit", "product_tag_object")),
            "identity changed during read-only import")
    if retained:
        if policy is not None:
            initial_input = custody.load_json(evidence / "acquisition-origin-input.json", "complete acquisition origin")
            final_input = finalize_retained_observations(manifest, record, policy, custody, transport, evidence,
                archives / f"{record['custody']['metadata']['id']}.zip", capture / "retaining-workflow.yml",
                observer=observer, initial_input=initial_input, phase="producer-final")
            summary["origin"] = custody.verify_retained_origin(manifest, record, final_input,
                archives / f"{record['custody']['metadata']['id']}.zip", capture / "retaining-workflow.yml", policy=policy)
        # Verify fixed files after the last identity checker, not just before it.
        summary["files"] = custody.verify_files(manifest, candidate)
        assert_captured_inputs(capture, custody, policy=policy)
        context = current_receipt_context(custody, transport, capture, evidence, python, node,
            observer=observer, checked_at=utc_now() if policy is not None else None)
        members = create_retained_receipts(custody, manifest, record, context, summary, checked_publications,
            evidence, policy=policy)
    shutil.copyfile(capture / "identity-before.json", evidence / "identity-before.json")
    dump(evidence / "import-receipt.json", summary)
    check_destinations(runner_temp, destination)
    # Everything executed before this point is a read or local private write.
    # Fresh-runner ownership and absent destinations are mandatory. No reuse or
    # merge of an earlier import tree is supported.
    output_path = Path(os.environ["GITHUB_OUTPUT"])
    descriptor = os.open(output_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    exposed = []
    staged_output = None
    staged_descriptor = None
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "GITHUB_OUTPUT must be one regular file")
        staged_descriptor, staged_name = tempfile.mkstemp(prefix="exochain-output-", dir=output_path.parent)
        staged_output = Path(staged_name)
        os.fchmod(staged_descriptor, stat.S_IMODE(metadata.st_mode))
        outputs = f"artifact_directory={destination}\nevidence_directory={final_evidence}\n"
        if retained:
            outputs += (f"receipt_directory={final_evidence / 'current-receipts'}\n"
                        f"producer_job_id={context['producer_job_id']}\n"
                        f"receipt_members={json.dumps(members,separators=(',',':'))}\n"
                        f"receipt_context={json.dumps(context,separators=(',',':'))}\n")
        copied = 0
        original_digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            copied += len(chunk)
            original_digest.update(chunk)
            require(os.write(staged_descriptor, chunk) == len(chunk), "staged controller output write was incomplete")
        require(copied == metadata.st_size, "GITHUB_OUTPUT changed during staging")
        evidence.rename(final_evidence)
        exposed.append((final_evidence, evidence))
        candidate.rename(destination)
        exposed.append((destination, candidate))
        encoded = outputs.encode()
        require(os.write(staged_descriptor, encoded) == len(encoded), "staged controller output write was incomplete")
        os.fsync(staged_descriptor)
        os.close(staged_descriptor)
        staged_descriptor = None
        os.lseek(descriptor, 0, os.SEEK_SET)
        current_digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            current_digest.update(chunk)
        current = os.lstat(output_path)
        require((current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_mode) ==
                (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_mode)
                and current_digest.digest() == original_digest.digest(),
                "GITHUB_OUTPUT changed before exposure")
        os.close(descriptor)
        descriptor = None
        # The atomic replacement is the final fallible exposure operation. A
        # failed write, sync or replace cannot publish partial acceptance keys.
        os.replace(staged_output, output_path)
        staged_output = None
    except BaseException:
        # The old output remains intact until replace succeeds. Each private
        # cleanup is independent so one failure cannot conceal another tree.
        for public, private in reversed(exposed):
            try:
                public.rename(private)
            except BaseException:
                print("release recovery import destination rollback failed", file=sys.stderr)
        if staged_output is not None:
            try:
                staged_output.unlink(missing_ok=True)
            except BaseException:
                print("release recovery import staged output cleanup failed", file=sys.stderr)
        raise
    finally:
        if staged_descriptor is not None:
            os.close(staged_descriptor)
        if descriptor is not None:
            os.close(descriptor)
    # GITHUB_OUTPUT is the handoff. A closed diagnostic stdout must not turn
    # an already committed atomic handoff into a reported failed operation.
    try:
        os.write(1, (json.dumps({"artifact_directory":str(destination),
                                 "evidence_directory":str(final_evidence)}, sort_keys=True) + "\n").encode())
    except OSError:
        pass


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Provider bodies, tokens and signed redirect URLs never become errors.
        print("release recovery import failed: " + (str(error) if isinstance(error, ImportFailure) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
# END RECOVERY_IMPORT_PYTHON
RECOVERY_IMPORT_PYTHON
