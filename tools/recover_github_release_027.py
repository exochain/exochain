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
    final = provider.lookup()
    require(validate_release(final, expected) == identifier and final["draft"] is False, "release publication not confirmed")
    require(verified_assets(provider, identifier, assets) == set(assets), "published release asset inventory differs")
    rebind()
    if journal is not None:
        journal({"operation":"final_readback", "outcome":"accepted", "release_id":identifier, "asset_count":len(assets), "product_tag":"v0.2.7"})
    return {"tag":"v0.2.7", "release_id":identifier, "asset_count":len(assets), "published":True}


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


def main():
    env = os.environ
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
    for path in ("tools/verify_release_recovery_027.py", "tools/verify_release_recovery_027.sh", "governance/releases/v0.2.7/RECOVERY-MANIFEST.json"):
        data = subprocess.check_output(["/usr/bin/git", "--no-replace-objects", "-c", "core.fsmonitor=false", "-C", str(workspace), "show", sha + ":" + path], env=git_env)
        destination = capture / Path(path).name
        with destination.open("xb") as output: output.write(data)
        destination.chmod(0o400)
    spec = importlib.util.spec_from_file_location("fixed_recovery", capture / "verify_release_recovery_027.py")
    custody = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(custody)
    manifest = custody.load_manifest(capture / "RECOVERY-MANIFEST.json")
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
    assets = {}
    for lane in manifest["artifacts"]:
        if lane["lane"] not in ("native-x86_64", "native-aarch64", "sbom"):
            continue
        for file in lane["files"]:
            name = file["path"]
            require("/" not in name and name not in assets, "unexpected public asset name")
            data = custody.read_regular(directory / lane["lane"] / name, custody.MAX_ZIP_BYTES, "original release asset")
            require(len(data) == file["size"] and hashlib.sha256(data).hexdigest() == file["sha256"], "original release asset changed")
            assets[name] = data
    require(len(assets) == 34, "original release must have two native archives and 32 SBOMs")
    receipt = {"schema":"exochain-release-recovery-custody/v1", "product":manifest["product"], "origin":manifest["origin"], "controller":{"sha":sha, "ref":ref}, "artifacts":manifest["artifacts"], "rust_crates":manifest["rust_crates"], "native_archive_contents":"29 legacy libexo_*.rlib per archive; no server executables", "attestation_scope":"Original native archives have original build attestations. New npm/Python attestations identify this recovery controller; original payload custody is the fixed reviewed manifest and producer evidence."}
    assets["RECOVERY-CUSTODY.json"] = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
    expected = {"tag_name":"v0.2.7", "target_commitish":PRODUCT_SHA, "name":"EXOCHAIN v0.2.7", "body":f"Security remediation release 0.2.7. Original signed product tag and payload bytes are preserved.\n\nOriginal artifact source: `{PRODUCT_SHA}`. Recovery publisher: `{sha}` at `{ref}`. See RECOVERY-CUSTODY.json for the fixed original run, producer, artifact and checksum inventory.\n\nAll 32 Rust crates and the WASM, LYNK, TypeScript and Python packages passed their exact registry acceptance gates before this release job. Native archives contain 29 legacy libexo_*.rlib libraries each, not server executables. Only those native archives have original GitHub build attestations; newly published npm/Python attestations truthfully identify the recovery controller. No runtime deployment claim is made.\n"}
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
