#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
# Fixed, read-only recovery import. The dispatcher captures this entry point
# from the actual controller GITHUB_SHA, before introducing any publication key.
set -euo pipefail
umask 077
fail() { printf 'release recovery import failed: %s\n' "$1" >&2; exit 1; }
[ "$#" -eq 0 ] || fail "this fixed import takes no arguments"
if /usr/bin/env | /usr/bin/grep -Eq '^BASH_FUNC_.*%%='; then
  fail "inherited shell functions are forbidden"
fi
for credential_name in CARGO_REGISTRY_TOKEN NPM_TOKEN NODE_AUTH_TOKEN \
    TWINE_PASSWORD PYPI_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL; do
  [ -z "${!credential_name:-}" ] || fail "publication credentials and OIDC must be absent"
done
[ "${RELEASE_OPERATION:-}" = recover-0.2.7 ] && [ "${RELEASE_VERSION:-}" = 0.2.7 ] \
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
# The wrapper verifies the pinned Python root/version, both signed tags and
# authoritative remote identities, keeping GITHUB_SHA bound to the controller.
/bin/bash --noprofile --norc -p "$capture/verify_release_recovery_027.sh" > "$capture/identity-before.json"
[ "$(/usr/bin/env -i "$RELEASE_NODE" --version)" = v24.15.0 ] || fail "Node must be exactly 24.15.0"

"$RELEASE_PYTHON" -I -B - "$capture" <<'RECOVERY_IMPORT_PYTHON'
# BEGIN RECOVERY_IMPORT_PYTHON
"""Fixed import orchestration. Network and subprocess boundaries are testable;
there are no runtime endpoint, command, manifest, or proof overrides."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
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
    def __init__(self, scratch, token, manifest):
        require(re.fullmatch(r"[A-Za-z0-9_]+", token or "") is not None, "malformed read-only GitHub credential")
        self.scratch, self.token = Path(scratch), token
        self.endpoints = fixed_endpoints(manifest)
        self.authenticated = {self.endpoints["run"], *self.endpoints["jobs"],
                              *(url for _, url in self.endpoints["metadata"]),
                              *(url for _, url in self.endpoints["archives"])}
        self.public = {url for _, url in self.endpoints["rust"]}

    def _get(self, url, destination, limit, authenticated):
        require(type(limit) is int and 0 < limit <= 96 * 1024 * 1024, "invalid response bound")
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
        try:
            result = subprocess.run(argv, input=config.encode(), capture_output=True, env=BASE_ENV, timeout=250, check=False)
            # Do not propagate curl diagnostics: a URL may contain a storage SAS.
            require(result.returncode == 0, "bounded provider GET failed")
            require(result.stdout in (b"200", b"302"), "unexpected provider HTTP status")
            require(destination.is_file() and not destination.is_symlink() and destination.stat().st_size <= limit,
                    "provider response exceeded its bound")
            require(header_path.stat().st_size <= 65536, "provider response headers exceeded their bound")
            headers = header_path.read_bytes().decode("latin-1")
            locations = [line.split(":", 1)[1].strip() for line in headers.splitlines() if line.lower().startswith("location:")]
            require(len(locations) <= 1, "duplicate provider redirect")
            return int(result.stdout), locations
        finally:
            header_path.unlink(missing_ok=True)

    def get(self, url, destination, limit):
        require(url in self.authenticated or url in self.public, "endpoint is outside fixed read-only inventory")
        status, locations = self._get(url, destination, limit, url in self.authenticated)
        require(status == 200 and not locations, "metadata and registry redirects are forbidden")

    def archive(self, artifact, destination):
        fixed = dict(self.endpoints["archives"])
        require(artifact["id"] in fixed, "archive is outside fixed artifact inventory")
        # GitHub normally returns 302, but a direct 200 is also checked later
        # against the exact original ZIP digest and size by the custody helper.
        status, locations = self._get(fixed[artifact["id"]], destination, artifact["zip_size"], True)
        if status == 302:
            require(len(locations) == 1, "artifact download lacks one storage redirect")
            url = validate_storage_url(locations[0])
            Path(destination).unlink()
            status, locations = self._get(url, destination, artifact["zip_size"], False)
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


def fetch_origin(manifest, custody, transport, evidence):
    endpoints = fixed_endpoints(manifest)
    transport.get(endpoints["run"], evidence / "run.json", JSON_LIMIT)
    run = custody.load_json(evidence / "run.json", "original run")
    jobs = []
    for page, url in enumerate(endpoints["jobs"], 1):
        path = evidence / f"jobs-page-{page}.json"
        transport.get(url, path, JSON_LIMIT)
        response = custody.load_json(path, "original attempt job page")
        require(type(response) is dict and type(response.get("jobs")) is list, "malformed job page")
        require(type(response.get("total_count")) is int and response["total_count"] == manifest["origin"]["jobs_total"],
                "attempt job count differs from the fixed original inventory")
        require(len(response["jobs"]) <= 100, "job page exceeds fixed pagination size")
        jobs.extend(response["jobs"])
        require(len(jobs) <= manifest["origin"]["jobs_total"], "attempt pagination exceeds fixed inventory")
        if len(response["jobs"]) < 100:
            require(len(jobs) == response["total_count"], "attempt job pagination is incomplete")
            break
    else:
        raise ImportFailure("attempt job pagination did not terminate")
    combined = {"total_count": len(jobs), "jobs": jobs}
    dump(evidence / "jobs.json", combined)
    metadata_directory = evidence / "artifact-metadata"
    metadata_directory.mkdir(mode=0o700)
    records = []
    for artifact_id, url in endpoints["metadata"]:
        path = metadata_directory / f"{artifact_id}.json"
        transport.get(url, path, JSON_LIMIT)
        records.append(custody.load_json(path, "original artifact metadata"))
    return custody.verify_origin(manifest, run, combined, records)


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


def command(argv, receipt, extra_env=None):
    environment = dict(BASE_ENV)
    environment.update(extra_env or {})
    with receipt.open("xb") as stream:
        result = subprocess.run(argv, env=environment, stdout=stream, stderr=subprocess.PIPE, timeout=240, check=False)
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
    transport = Transport(capture, token, manifest)
    python, node = os.environ["RELEASE_PYTHON"], os.environ["RELEASE_NODE"]
    require(Path(node).is_absolute() and Path(node).resolve().is_file(), "invalid pinned Node executable")
    require(shutil.disk_usage(runner_temp).free >= 4 * 1024**3, "import requires at least four GiB free")
    before = custody.load_json(capture / "identity-before.json", "initial identity")
    summary = {"controller_sha":before["controller_sha"],"controller_ref":before["controller_ref"],
               "product":manifest["product"],"origin":fetch_origin(manifest, custody, transport, evidence)}
    helper = [python, "-I", "-B", str(capture / "verify_release_recovery_027.py")]
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
    shutil.copyfile(capture / "identity-before.json", evidence / "identity-before.json")
    dump(evidence / "import-receipt.json", summary)
    check_destinations(runner_temp, destination)
    # Everything executed before this point is a read or local private write.
    # Fresh-runner ownership and absent destinations are mandatory. No reuse or
    # merge of an earlier import tree is supported.
    evidence.rename(final_evidence)
    candidate.rename(destination)
    descriptor = os.open(os.environ["GITHUB_OUTPUT"], os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "GITHUB_OUTPUT must be one regular file")
        os.write(descriptor, f"artifact_directory={destination}\nevidence_directory={final_evidence}\n".encode())
    finally:
        os.close(descriptor)
    print(json.dumps({"artifact_directory":str(destination), "evidence_directory":str(final_evidence)}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Provider bodies, tokens and signed redirect URLs never become errors.
        print("release recovery import failed: " + (str(error) if isinstance(error, ImportFailure) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
# END RECOVERY_IMPORT_PYTHON
RECOVERY_IMPORT_PYTHON
