#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

if /usr/bin/env | /usr/bin/grep -Eq '^BASH_FUNC_.*%%='; then
  /bin/echo "npm release publication failed: inherited shell functions are forbidden" >&2
  exit 1
fi
set -euo pipefail

fail() {
  printf 'npm release publication failed: %s\n' "$1" >&2
  exit 1
}

validate_npm_registry_response() {
  local response_file="$1"
  local expected_name="$2"
  local expected_version="$3"
  local expected_integrity="$4"
  local node_binary="$5"
  local expected_maintainer_name="$6"
  local expected_maintainer_email="$7"
  /usr/bin/env -i \
    EXPECTED_INTEGRITY="$expected_integrity" \
    EXPECTED_MAINTAINER_EMAIL="$expected_maintainer_email" \
    EXPECTED_MAINTAINER_NAME="$expected_maintainer_name" \
    EXPECTED_NAME="$expected_name" \
    EXPECTED_VERSION="$expected_version" \
    "$node_binary" - "$response_file" <<'NODE'
const fs = require('node:fs');
const MAX_BYTES = 1024 * 1024;
const MAX_DEPTH = 64;

function reject() { process.exit(2); }

class Scanner {
  constructor(text) { this.text = text; this.index = 0; }
  whitespace() { while (/\s/u.test(this.text[this.index] ?? '')) this.index += 1; }
  string() {
    const start = this.index;
    if (this.text[this.index] !== '"') reject();
    this.index += 1;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        try { return JSON.parse(this.text.slice(start, this.index)); } catch { reject(); }
      }
      if (code < 0x20) reject();
      if (code === 0x5c) {
        this.index += 1;
        const escape = this.text[this.index];
        if (escape === 'u') {
          if (!/^[0-9a-fA-F]{4}$/u.test(this.text.slice(this.index + 1, this.index + 5))) reject();
          this.index += 5;
          continue;
        }
        if (!['"', '\\', '/', 'b', 'f', 'n', 'r', 't'].includes(escape)) reject();
      }
      this.index += 1;
    }
    reject();
  }
  value(depth) {
    if (depth > MAX_DEPTH) reject();
    this.whitespace();
    const character = this.text[this.index];
    if (character === '{') return this.object(depth + 1);
    if (character === '[') return this.array(depth + 1);
    if (character === '"') { this.string(); return; }
    for (const literal of ['true', 'false', 'null']) {
      if (this.text.startsWith(literal, this.index)) { this.index += literal.length; return; }
    }
    const number = this.text.slice(this.index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u)?.[0];
    if (number !== undefined && Number.isFinite(Number(number))) { this.index += number.length; return; }
    reject();
  }
  object(depth) {
    this.index += 1; this.whitespace();
    const keys = new Set();
    if (this.text[this.index] === '}') { this.index += 1; return; }
    for (;;) {
      const key = this.string();
      if (keys.has(key)) reject();
      keys.add(key); this.whitespace();
      if (this.text[this.index] !== ':') reject();
      this.index += 1; this.value(depth); this.whitespace();
      if (this.text[this.index] === '}') { this.index += 1; return; }
      if (this.text[this.index] !== ',') reject();
      this.index += 1; this.whitespace();
    }
  }
  array(depth) {
    this.index += 1; this.whitespace();
    if (this.text[this.index] === ']') { this.index += 1; return; }
    for (;;) {
      this.value(depth); this.whitespace();
      if (this.text[this.index] === ']') { this.index += 1; return; }
      if (this.text[this.index] !== ',') reject();
      this.index += 1; this.whitespace();
    }
  }
  scan() { this.whitespace(); this.value(0); this.whitespace(); if (this.index !== this.text.length) reject(); }
}

if (typeof fs.constants.O_NOFOLLOW !== 'number' || typeof fs.constants.O_NONBLOCK !== 'number') reject();
let descriptor;
try {
  descriptor = fs.openSync(
    process.argv[2],
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
  );
  const before = fs.fstatSync(descriptor, { bigint: true });
  if (!before.isFile() || before.nlink !== 1n || before.size <= 0n || before.size > BigInt(MAX_BYTES)) reject();
  const bytes = Buffer.alloc(Number(before.size));
  let offset = 0;
  while (offset < bytes.length) {
    const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, null);
    if (count === 0) reject();
    offset += count;
  }
  const after = fs.fstatSync(descriptor, { bigint: true });
  const stable = (value) => [value.dev, value.ino, value.mode, value.nlink, value.size, value.mtimeNs, value.ctimeNs].join(':');
  if (stable(before) !== stable(after)) reject();
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  new Scanner(text).scan();
  const value = JSON.parse(text);
  if (value?.name !== process.env.EXPECTED_NAME
      || value?.version !== process.env.EXPECTED_VERSION
      || value?.dist?.integrity !== process.env.EXPECTED_INTEGRITY
      || JSON.stringify(value?.maintainers) !== JSON.stringify([{
        name: process.env.EXPECTED_MAINTAINER_NAME,
        email: process.env.EXPECTED_MAINTAINER_EMAIL,
      }])
      || JSON.stringify(value?._npmUser) !== JSON.stringify({
        name: process.env.EXPECTED_MAINTAINER_NAME,
        email: process.env.EXPECTED_MAINTAINER_EMAIL,
      })
      || !Array.isArray(value?.dist?.signatures)
      || value.dist.signatures.length === 0
      || value.dist.signatures.some((entry) => typeof entry?.keyid !== 'string' || typeof entry?.sig !== 'string')
      || value?.dist?.attestations?.provenance?.predicateType !== 'https://slsa.dev/provenance/v1'
      || typeof value?.dist?.attestations?.url !== 'string'
      || !value.dist.attestations.url.startsWith('https://registry.npmjs.org/-/npm/v1/attestations/')) reject();
} catch { reject(); }
finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
NODE
}

# A probe returns 1 only while the exact version is absent (HTTP 404).
# Any other failure is terminal. The callbacks are fixed by the publisher;
# tests replace only registry I/O and sleeping, never acceptance verification.
wait_for_npm_registry_visibility() {
  local probe="$1" pause="$2" attempt status
  for ((attempt = 1; attempt <= 25; attempt += 1)); do
    if "$probe"; then
      return 0
    else
      status=$?
    fi
    [ "$status" -eq 1 ] || return "$status"
    if [ "$attempt" -lt 25 ]; then
      "$pause" 15 || return "$?"
    fi
  done
  return 1
}

fetch_npm_registry_record() {
  /usr/bin/env -i \
    /usr/bin/curl -q --silent --show-error --output "$registry_response" \
      --write-out '%{http_code}' --proto '=https' --tlsv1.2 \
      --connect-timeout 15 --max-time 60 --max-filesize 1048576 \
      "$registry_url"
}

validate_npm_release_context() {
  RELEASE_OPERATION="${RELEASE_OPERATION:-release}"
  local name
  # Provenance is derived here, never accepted from an invocation override.
  for name in RELEASE_PROVENANCE_COMMIT_SHA RELEASE_PROVENANCE_REF \
    RELEASE_EXPECTED_PROVENANCE_SHA RELEASE_EXPECTED_PROVENANCE_REF; do
    [ -z "${!name+x}" ] || fail "caller provenance overrides are forbidden"
  done
  provenance_commit="$GITHUB_SHA"
  provenance_ref="$GITHUB_REF"
  acceptance_only=false
  case "$RELEASE_OPERATION" in
    release)
      [ "${RELEASE_NPM_MODE:-publish}" = publish ] || fail 'retained mode requires retained operation'
      [ -z "${RELEASE_WORKFLOW_DRY_RUN+x}" ] || fail 'workflow dry-run context requires retained operation'
      [[ "$GITHUB_REF" != refs/tags/v0.2.7-recover.* ]] \
        && [[ "$RELEASE_TAG" != v0.2.7-recover.* ]] \
        && [ -z "${RELEASE_RECOVERY_DIRECTORY+x}" ] \
        || fail "normal release cannot accept maintenance refs or recovery context"
      [ -n "${RELEASE_GITHUB_TOKEN:-}" ] || fail "RELEASE_GITHUB_TOKEN is required"
      ;;
    recover-0.2.7|recover-0.2.7-retained)
      if [ "$RELEASE_OPERATION" = recover-0.2.7-retained ]; then
        [ "${RELEASE_NPM_MODE:-}" = retained-accept ] || fail 'explicit retained-accept mode required'
        [[ "${RELEASE_WORKFLOW_DRY_RUN:-}" = true || "${RELEASE_WORKFLOW_DRY_RUN:-}" = false ]] \
          || fail 'explicit workflow dry-run boolean required'
      else
        [ "${RELEASE_NPM_MODE:-publish}" = publish ] || fail 'retained mode requires retained operation'
        [ -z "${RELEASE_WORKFLOW_DRY_RUN+x}" ] || fail 'workflow dry-run context requires retained operation'
      fi
      [ "$RELEASE_VERSION" = 0.2.7 ] || fail "recovery is restricted to version 0.2.7"
      [[ "$RELEASE_TAG" =~ ^v0\.2\.7-recover\.[1-9][0-9]*$ ]] \
        && [ "$GITHUB_REF" = "refs/tags/$RELEASE_TAG" ] \
        || fail "recovery requires the exact positive maintenance tag ref"
      [[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]] \
        && [ "$GITHUB_SHA" = "$EXPECTED_COMMIT_SHA" ] \
        && [ "$GITHUB_SHA" != 666c578f719d1e54fce95d6831a3af92ea80df93 ] \
        || fail "recovery requires the actual distinct controller source"
      for name in RUNNER_TEMP RELEASE_RECOVERY_DIRECTORY GNUPGHOME EXOCHAIN_RELEASE_SIGNING_FINGERPRINT GITHUB_OUTPUT; do
        [ -n "${!name:-}" ] || fail "$name is required for recovery"
      done
      if [ "$profile" = wasm ] || [ "$RELEASE_OPERATION" = recover-0.2.7-retained ]; then
        acceptance_only=true
        provenance_commit=666c578f719d1e54fce95d6831a3af92ea80df93
        provenance_ref=refs/tags/v0.2.7
        for name in NODE_AUTH_TOKEN NPM_TOKEN CARGO_REGISTRY_TOKEN TWINE_PASSWORD \
          PYPI_TOKEN PYPI_API_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL; do
          [ -z "${!name:-}" ] || fail "acceptance-only WASM or retained profile cannot receive publishing credentials or OIDC"
        done
      fi
      ;;
    *) fail "RELEASE_OPERATION must be release or recover-0.2.7" ;;
  esac
  if [ "$acceptance_only" = false ]; then
    [ -n "${NODE_AUTH_TOKEN:-}" ] || fail "NODE_AUTH_TOKEN is required"
  fi
  readonly RELEASE_OPERATION
}

run_public_npm() {
  local working_directory
  case "${1:-}" in
    install|audit) working_directory="$audit_root" ;;
    owner)
      [ "${2:-}" = ls ] || fail "public npm permits only install, audit and owner ls"
      working_directory="$public_home_root"
      ;;
    *) fail "public npm permits only install, audit and owner ls" ;;
  esac
  (
    # Never load a checkout's project .npmrc during a public owner readback.
    cd "$working_directory"
    /usr/bin/env -i \
      HOME="$public_home_root" \
      NPM_CONFIG_CACHE="$public_home_root/cache" \
      NPM_CONFIG_GLOBALCONFIG="$public_global_config" \
      NPM_CONFIG_IGNORE_SCRIPTS=true \
      NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ \
      NPM_CONFIG_USERCONFIG="$public_user_config" \
      PATH="$TRUSTED_RELEASE_PATH" \
      "$node_path" "$npm_cli_path" "$@"
  )
}

capture_npm_recovery_context() {
  [[ "$RELEASE_OPERATION" = recover-0.2.7 || "$RELEASE_OPERATION" = recover-0.2.7-retained ]] || return 0
  local source_path target
  for source_path in tools/verify_release_recovery_027.py tools/verify_release_recovery_027.sh \
    governance/releases/v0.2.7/RECOVERY-MANIFEST.json \
    governance/releases/v0.2.7/PUBLICATION-IDENTITIES.json; do
    target="$publish_root/${source_path##*/}"
    /usr/bin/env -i PATH=/usr/bin:/bin GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
      GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0 \
      /usr/bin/git --no-replace-objects -c core.fsmonitor=false -c core.untrackedCache=false \
        -c core.ignoreStat=false -C "$GITHUB_WORKSPACE" show "$GITHUB_SHA:$source_path" > "$target" \
      || fail "cannot capture immutable recovery helper or manifest"
    /bin/chmod 400 "$target"
  done
  recovery_manifest="$publish_root/RECOVERY-MANIFEST.json"
  recovery_verifier="$publish_root/verify_release_recovery_027.py"
  recovery_binding_verifier="$publish_root/verify_release_recovery_027.sh"
  recovery_publications="$publish_root/PUBLICATION-IDENTITIES.json"
  readonly recovery_manifest recovery_verifier recovery_binding_verifier recovery_publications
}

resolve_npm_publication_identity() {
  if [[ "$RELEASE_OPERATION" = recover-0.2.7 || "$RELEASE_OPERATION" = recover-0.2.7-retained ]]; then
    local record identity
    record="$(/usr/bin/env -i "$python_path" -I -B "$recovery_verifier" publication \
      --manifest "$recovery_manifest" --identities "$recovery_publications" --publication "$profile")" \
      || fail "publication identity is not the exact reviewed record"
    identity="$(/usr/bin/env -i "$python_path" -I -B -c '
import json,sys
r=json.loads(sys.argv[1]); assert r["id"] == sys.argv[2]
print(r["source"]["commit"], r["source"]["ref"], sep=chr(9))
' "$record" "$profile")" || fail "cannot decode validated publication identity"
    IFS=$'\t' read -r provenance_commit provenance_ref <<< "$identity"
    [[ "$provenance_commit" =~ ^[0-9a-f]{40}$ && "$provenance_ref" = refs/tags/* ]] \
      || fail "invalid selected publication identity"
    acceptance_only=true
  fi
  readonly provenance_commit provenance_ref acceptance_only
}

verify_recovery_npm_files() {
  [[ "$RELEASE_OPERATION" = recover-0.2.7 || "$RELEASE_OPERATION" = recover-0.2.7-retained ]] || return 0
  /usr/bin/env -i "$python_path" -I -B "$recovery_verifier" manifest \
    --manifest "$recovery_manifest" >/dev/null \
    || fail "recovery manifest is not the fixed reviewed manifest"
  /usr/bin/env -i "$python_path" -I -B - "$recovery_manifest" "npm-$profile" \
    "$RUNNER_TEMP" "$RELEASE_RECOVERY_DIRECTORY" "$RELEASE_NPM_TARBALL" \
    "$RELEASE_EXPECTED_TARBALL_SHA256" <<'PY' \
    || fail "recovery tarball selection differs from the exact manifest lane beneath RUNNER_TEMP"
import json
from pathlib import Path
import sys

manifest_path, lane, temporary, directory, tarball, digest = sys.argv[1:]
manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
artifact, = [entry for entry in manifest["artifacts"] if entry["lane"] == lane]
record, = artifact["files"]
scratch = Path(temporary)
root = Path(directory)
if (not scratch.is_absolute() or not root.is_absolute()
        or str(scratch.resolve(strict=True)) != temporary
        or str(root.resolve(strict=True)) != directory or root == scratch
        or not root.is_relative_to(scratch)
        or tarball != str(root / lane / record["path"])
        or digest != record["sha256"]):
    raise SystemExit(1)
PY
  /usr/bin/env -i "$python_path" -I -B "$recovery_verifier" files \
    --manifest "$recovery_manifest" --directory "$RELEASE_RECOVERY_DIRECTORY" \
    --lane "npm-$profile" >/dev/null \
    || fail "recovery lane bytes do not match the exact original file inventory"
}

initialize_npm_recovery_receipts() {
  recovery_receipt_root=''
  mutation_attempted=false
  mutation_exit_code=''
  acceptance_verified=false
  [[ "$RELEASE_OPERATION" = recover-0.2.7 || "$RELEASE_OPERATION" = recover-0.2.7-retained ]] || return 0
  /usr/bin/env -i "$python_path" -I -B - "$RUNNER_TEMP" "$profile" "$GITHUB_OUTPUT" <<'PY' \
    || fail "recovery receipt directory cannot be initialized exclusively"
import os
from pathlib import Path
import stat
import sys

scratch, profile, output = sys.argv[1:]
assert profile in ("wasm", "llm", "sdk")
assert Path(scratch).is_absolute() and str(Path(scratch).resolve(strict=True)) == scratch
assert Path(output).is_absolute() and Path(output).parent.resolve(strict=True).is_relative_to(Path(scratch))
fd = os.open(output, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    info = os.fstat(fd)
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
finally:
    os.close(fd)
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
root = os.open(scratch, flags)
try:
    try:
        os.mkdir("exochain-recovery-receipts", 0o700, dir_fd=root)
    except FileExistsError:
        pass
    parent = os.open("exochain-recovery-receipts", flags, dir_fd=root)
    try:
        info = os.fstat(parent)
        assert info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700
        os.mkdir("npm-" + profile, 0o700, dir_fd=parent)
        os.fsync(parent)
        os.fsync(root)
    finally:
        os.close(parent)
finally:
    os.close(root)
PY
  recovery_receipt_root="$RUNNER_TEMP/exochain-recovery-receipts/npm-$profile"
  readonly recovery_receipt_root
}

write_npm_recovery_receipt() {
  [[ "$RELEASE_OPERATION" = recover-0.2.7 || "$RELEASE_OPERATION" = recover-0.2.7-retained ]] || return 0
  /usr/bin/env -i "$python_path" -I -B - "$recovery_receipt_root" "$1" "${2:-}" \
    "$GITHUB_SHA" "$GITHUB_REF" "$package_name" "$RELEASE_VERSION" \
    "$RELEASE_EXPECTED_TARBALL_SHA256" "$provenance_commit" "$provenance_ref" \
    "$mutation_attempted" "$mutation_exit_code" "$acceptance_verified" "$RELEASE_OPERATION" <<'PY'
import json
import os
import sys

(root, phase, status, commit, ref, package, version, digest, provenance_commit,
 provenance_ref, attempted, upload_exit, accepted, operation) = sys.argv[1:]
assert phase in ("intent", "outcome", "result")
assert attempted in ("true", "false") and accepted in ("true", "false")
exit_code = int(status) if status else None
upload_code = int(upload_exit) if upload_exit else None
assert exit_code is None or 0 <= exit_code <= 255
assert upload_code is None or 0 <= upload_code <= 255
assert operation in ("recover-0.2.7", "recover-0.2.7-retained")
assert operation != "recover-0.2.7-retained" or (phase == "result" and attempted == "false" and upload_code is None)
value = {"schema":"exochain-npm-recovery-receipt/v1", "operation":operation,
         "controller_commit":commit, "controller_ref":ref, "package":package,
         "version":version, "tarball_sha256":digest,
         "provenance_commit":provenance_commit, "provenance_ref":provenance_ref,
         "mutation_attempted":attempted == "true", "upload_exit_code":upload_code,
         "acceptance_verified":accepted == "true" and exit_code == 0}
if phase == "intent":
    value.update(phase="upload-intent", mutation_outcome="unknown")
elif phase == "outcome":
    value.update(phase="upload-returned", mutation_outcome="unverified" if upload_code == 0 else "uncertain")
else:
    value.update(phase="finished", exit_code=exit_code,
                 mutation_outcome="verified" if value["acceptance_verified"] else
                 "uncertain" if value["mutation_attempted"] else "not-attempted")
data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
assert len(data) <= 8192
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    fd = os.open(phase + ".json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o400, dir_fd=directory)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.fsync(directory)
finally:
    os.close(directory)
PY
}

retain_npm_public_readbacks() {
  /usr/bin/env -i "$python_path" -I -B - "$recovery_receipt_root" \
    "$registry_response" "$audit_response" <<'PY'
import json
import os
import stat
import sys

root, registry, audit = sys.argv[1:]
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
failed = False
def pairs(values):
    result = {}
    for key, value in values:
        assert key not in result
        result[key] = value
    return result
def invalid_number(value):
    raise ValueError("nonstandard JSON number")
def stable(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)
try:
    # These are the only two public files eligible for retention. Configs,
    # caches, stdout/stderr and the private tool workspace are never copied.
    for path, name, limit in ((registry, "registry.json", 1024 * 1024),
                              (audit, "audit.json", 8 * 1024 * 1024)):
        created = False
        try:
            try:
                source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except FileNotFoundError:
                continue
            with os.fdopen(source_fd, "rb") as source:
                before = os.fstat(source.fileno())
                assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit
                data = source.read(limit + 1)
                assert len(data) == before.st_size and stable(before) == stable(os.fstat(source.fileno()))
            assert isinstance(json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_number), dict)
            output_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o400, dir_fd=directory)
            created = True
            with os.fdopen(output_fd, "wb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
        except (OSError, ValueError, AssertionError, RecursionError):
            if created:
                os.unlink(name, dir_fd=directory)
            failed = True
    os.fsync(directory)
finally:
    os.close(directory)
if failed:
    raise SystemExit(1)
PY
}

publish_npm_receipt_readiness() {
  /usr/bin/env -i "$python_path" -I -B - "$recovery_receipt_root" "$GITHUB_OUTPUT" \
    "$RUNNER_TEMP" "$GITHUB_SHA" "$GITHUB_REF" "$package_name" "$RELEASE_VERSION" \
    "$RELEASE_EXPECTED_TARBALL_SHA256" "$provenance_commit" "$provenance_ref" "$RELEASE_OPERATION" <<'PY'
import json
import os
from pathlib import Path
import stat
import sys

root, output, scratch, commit, ref, package, version, digest, provenance_commit, provenance_ref, operation = sys.argv[1:]
expected = {"schema":"exochain-npm-recovery-receipt/v1", "operation":operation,
            "controller_commit":commit, "controller_ref":ref, "package":package,
            "version":version, "tarball_sha256":digest,
            "provenance_commit":provenance_commit, "provenance_ref":provenance_ref}
limits = {"intent.json":8192, "outcome.json":8192, "result.json":8192,
          "registry.json":1024 * 1024, "audit.json":8 * 1024 * 1024}
def pairs(values):
    result = {}
    for key, value in values:
        assert key not in result
        result[key] = value
    return result
def invalid_number(value):
    raise ValueError("nonstandard JSON number")
def stable(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)
directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
values = {}
try:
    names = set(os.listdir(directory))
    assert "result.json" in names and names.issubset(limits)
    for name in sorted(names):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            assert (stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o400
                    and 0 < before.st_size <= limits[name])
            data = source.read(limits[name] + 1)
            assert len(data) == before.st_size and stable(before) == stable(os.fstat(source.fileno()))
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_number)
        assert isinstance(value, dict)
        values[name] = value
        if name in ("registry.json", "audit.json"):
            continue
        keys = set(expected) | {"phase", "mutation_attempted", "upload_exit_code", "acceptance_verified", "mutation_outcome"}
        if name == "result.json":
            keys.add("exit_code")
        assert set(value) == keys and all(value[key] == item for key, item in expected.items())
        assert type(value["mutation_attempted"]) is bool and type(value["acceptance_verified"]) is bool
        code = value["upload_exit_code"]
        assert code is None or (type(code) is int and 0 <= code <= 255)
        if name == "intent.json":
            assert value["phase"] == "upload-intent" and value["mutation_outcome"] == "unknown"
            assert not value["mutation_attempted"] and not value["acceptance_verified"] and code is None
        elif name == "outcome.json":
            assert value["phase"] == "upload-returned" and value["mutation_attempted"] and code is not None
            assert not value["acceptance_verified"]
            assert value["mutation_outcome"] == ("unverified" if code == 0 else "uncertain")
        else:
            assert value["phase"] == "finished" and type(value["exit_code"]) is int and 0 <= value["exit_code"] <= 255
            assert not value["acceptance_verified"] or value["exit_code"] == 0
            assert value["mutation_outcome"] == ("verified" if value["acceptance_verified"] else
                                                 "uncertain" if value["mutation_attempted"] else "not-attempted")
    assert not values["result.json"]["mutation_attempted"] or "intent.json" in names
    assert "outcome.json" not in names or "intent.json" in names
    assert Path(output).is_absolute() and Path(output).parent.resolve(strict=True).is_relative_to(Path(scratch))
    fd = os.open(output, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "w") as stream:
        info = os.fstat(stream.fileno())
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        stream.write("receipts_ready=true\n")
        stream.flush()
        os.fsync(stream.fileno())
finally:
    os.close(directory)
PY
}

finish_npm_publication() {
  local status="$1"
  trap - EXIT
  if [[ "$RELEASE_OPERATION" = recover-0.2.7 || "$RELEASE_OPERATION" = recover-0.2.7-retained ]] && [ -n "${recovery_receipt_root:-}" ]; then
    if ! retain_npm_public_readbacks; then
      printf 'npm recovery public readbacks could not be retained\n' >&2
      status=1
    fi
  fi
  /bin/rm -rf -- "$publish_root" || status=1
  if [[ "$RELEASE_OPERATION" = recover-0.2.7 || "$RELEASE_OPERATION" = recover-0.2.7-retained ]] && [ -n "${recovery_receipt_root:-}" ]; then
    if ! write_npm_recovery_receipt result "$status"; then
      printf 'npm recovery outcome receipt could not be persisted\n' >&2
      status=1
    elif ! publish_npm_receipt_readiness; then
      printf 'npm recovery receipts are not safe for artifact upload\n' >&2
      status=1
    fi
  fi
  exit "$status"
}

publish_or_accept_npm() {
  if [ "$acceptance_only" = false ]; then
    verify_credentialed_npm_actor
  fi
  verify_recovery_npm_files
  local publish_needed=true status
  if registry_has_exact_tarball; then
    publish_needed=false
  else
    status=$?
    [ "$status" -eq 1 ] || fail "npm registry probe failed"
  fi
  if [ "$publish_needed" = true ]; then
    [ "$acceptance_only" = false ] || fail "acceptance-only mapped npm version is absent"
    # Final source/tag, namespace authority and original bytes before mutation.
    verify_release_binding
    verify_prepublication_npm_authority
    verify_recovery_npm_files
    cd /
    write_npm_recovery_receipt intent
    mutation_attempted=true
    mutation_exit_code=0
    run_authenticated_npm publish "$RELEASE_NPM_TARBALL" \
      --access public --provenance --ignore-scripts --registry=https://registry.npmjs.org \
      || mutation_exit_code=$?
    write_npm_recovery_receipt outcome
    [ "$mutation_exit_code" -eq 0 ] || return "$mutation_exit_code"
    verify_recovery_npm_files
    wait_for_npm_registry_visibility registry_has_exact_tarball /bin/sleep \
      || fail "published npm version did not reach the registry with exact preflight integrity"
  fi
  # Existing and newly published versions require the same complete acceptance.
  verify_registry_acceptance
  verify_recovery_npm_files
  verify_release_binding
  acceptance_verified=true
}

for required_name in \
  EXPECTED_COMMIT_SHA \
  EXPECTED_TAG_COMMIT_SHA \
  EXPECTED_TAG_OBJECT_SHA \
  GITHUB_EVENT_NAME \
  GITHUB_REF \
  GITHUB_REPOSITORY \
  GITHUB_SERVER_URL \
  GITHUB_WORKFLOW_REF \
  GITHUB_SHA \
  GITHUB_WORKSPACE \
  RELEASE_EXPECTED_TARBALL_SHA256 \
  RELEASE_NPM_TARBALL \
  RELEASE_PYTHON \
  RELEASE_TAG \
  RELEASE_TEMP_ROOT \
  RELEASE_TRUSTED_NPM_VERSION \
  RELEASE_TRUSTED_PYTHON_ROOT \
  RELEASE_TRUSTED_PYTHON_VERSION \
  RELEASE_VERSION \
  RUNNER_ENVIRONMENT \
  TRUSTED_RELEASE_REF \
  TRUSTED_RELEASE_PATH \
  TRUSTED_RELEASE_TOOL_IDENTITY; do
  [ -n "${!required_name:-}" ] || fail "$required_name is required"
done

# An environment variable alone cannot select retained acceptance.
RELEASE_NPM_MODE="${2:-publish}"
[[ "$#" = 1 || ( "$#" = 2 && "$2" = retained-accept ) ]] || fail 'invalid npm operation arguments'
readonly RELEASE_NPM_MODE
profile="${1:-}"
case "$profile" in
  wasm) package_name='@exochain/exochain-wasm' ;;
  llm) package_name='@exochain/llm-proxy' ;;
  sdk) package_name='@exochain/sdk' ;;
  *) fail "profile must be wasm, llm, or sdk" ;;
esac
validate_npm_release_context
[[ "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "RELEASE_VERSION must be an exact semantic version"
[[ "$EXPECTED_COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]] \
  || fail "EXPECTED_COMMIT_SHA must be a full lowercase commit SHA"
[ "$EXPECTED_COMMIT_SHA" = "$GITHUB_SHA" ] \
  || fail "dispatch commit does not match the expected commit"
[ "$GITHUB_REPOSITORY" = exochain/exochain ] \
  || fail "npm publication is restricted to exochain/exochain"
[ "$GITHUB_SERVER_URL" = https://github.com ] \
  || fail "npm trusted publication requires github.com"
[ "$RUNNER_ENVIRONMENT" = github-hosted ] \
  || fail "npm trusted publication requires a GitHub-hosted runner"
[ "$GITHUB_EVENT_NAME" = workflow_dispatch ] \
  || fail "npm publication requires the reviewed workflow_dispatch trigger"
[[ "$GITHUB_REF" =~ ^refs/(heads|tags)/[0-9A-Za-z._/-]+$ ]] && [[ "$GITHUB_REF" != *..* ]] \
  || fail "GITHUB_REF must be an exact safe GitHub ref"
[ "$GITHUB_WORKFLOW_REF" = "exochain/exochain/.github/workflows/release.yml@$GITHUB_REF" ] \
  || fail "npm OIDC workflow identity must be exochain/exochain release.yml at GITHUB_REF"
[[ "$RELEASE_EXPECTED_TARBALL_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || fail "RELEASE_EXPECTED_TARBALL_SHA256 must be a lowercase SHA-256"

case "$RELEASE_NPM_TARBALL" in
  "$RELEASE_TEMP_ROOT"/*) ;;
  *) fail "release tarball must be beneath RUNNER_TEMP" ;;
esac
[ -f "$RELEASE_NPM_TARBALL" ] && [ ! -L "$RELEASE_NPM_TARBALL" ] \
  || fail "release tarball must be a regular non-symlink file"

tool_view="${TRUSTED_RELEASE_PATH%%:*}"
case "$tool_view" in
  "$RELEASE_TEMP_ROOT"/*) ;;
  *) fail "trusted tool view must be beneath RUNNER_TEMP" ;;
esac
[ -d "$tool_view" ] && [ ! -L "$tool_view" ] \
  || fail "trusted tool view must be a real directory"
[ "$(/bin/cat "$tool_view/.release-tool-identity")" = "$TRUSTED_RELEASE_TOOL_IDENTITY" ] \
  || fail "fresh tool-view identity does not match its trusted backing closure"
node_path="$(/usr/bin/realpath "$tool_view/node")"
npm_cli_path="$(/usr/bin/realpath "$tool_view/npm")"
[ -x "$node_path" ] && [ -f "$npm_cli_path" ] \
  || fail "fresh tool view does not contain usable Node.js and npm entries"
[ "$RELEASE_TRUSTED_NPM_VERSION" = 11.12.1 ] \
  || fail "release npm version must remain pinned to 11.12.1"
[ "$(/usr/bin/env -i PATH="$TRUSTED_RELEASE_PATH" \
    "$node_path" "$npm_cli_path" --version)" = "$RELEASE_TRUSTED_NPM_VERSION" ] \
  || fail "release npm executable version differs from the pinned runtime"
python_path="$(/usr/bin/realpath "$RELEASE_PYTHON")"
python_root="$(cd "$RELEASE_TRUSTED_PYTHON_ROOT" && pwd -P)"
case "$python_path" in
  "$python_root"/*) ;;
  *) fail "release Python is outside the trusted tool-cache root" ;;
esac
[ -f "$python_path" ] && [ -x "$python_path" ] && [ ! -L "$python_path" ] \
  || fail "release Python must be one executable regular file"
[ "$(/usr/bin/env -i "$python_path" -I -B -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')" = "$RELEASE_TRUSTED_PYTHON_VERSION" ] \
  || fail "release Python version differs from the pinned runtime"

actual_sha256="$(/usr/bin/sha256sum "$RELEASE_NPM_TARBALL" | /usr/bin/cut -d ' ' -f 1)"
[ "$actual_sha256" = "$RELEASE_EXPECTED_TARBALL_SHA256" ] \
  || fail "downloaded npm tarball does not match its token-free preflight digest"

publish_root="$(/usr/bin/mktemp -d "$RELEASE_TEMP_ROOT/exochain-npm-publish.XXXXXX")"
recovery_receipt_root=''
trap 'finish_npm_publication "$?"' EXIT
extract_root="$publish_root/extracted"
home_root="$publish_root/home"
audit_root="$publish_root/audit"
registry_response="$publish_root/registry.json"
package_registry_response="$publish_root/package-registry.json"
audit_response="$publish_root/audit.json"
registry_verifier="$publish_root/verify_npm_registry_attestation.mjs"
expected_npm_actor=bob-stewart
expected_maintainer_name=bob-stewart
expected_maintainer_email=stewart@exochain.com
/bin/mkdir -m 700 "$home_root"
publisher_user_config="$home_root/user.npmrc"
publisher_global_config="$home_root/global.npmrc"
public_home_root="$publish_root/public-home"
/bin/mkdir -m 700 "$public_home_root"
public_user_config="$public_home_root/user.npmrc"
public_global_config="$public_home_root/global.npmrc"
: > "$public_user_config"
: > "$public_global_config"
/bin/chmod 600 "$public_user_config" "$public_global_config"
[ "$public_user_config" != "$public_global_config" ] \
  || fail "public user and global npm config paths must differ"

capture_npm_recovery_context
resolve_npm_publication_identity
verify_recovery_npm_files
initialize_npm_recovery_receipts

for helper in verify_npm_release_tarball.py verify_npm_release_package.mjs verify_npm_registry_attestation.mjs; do
  /usr/bin/git --no-replace-objects -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false \
    -C "$GITHUB_WORKSPACE" show "${GITHUB_SHA}:tools/${helper}" > "$publish_root/$helper"
  /bin/chmod 500 "$publish_root/$helper"
done
/usr/bin/env -i "$python_path" -I -B "$publish_root/verify_npm_release_tarball.py" \
  "$RELEASE_NPM_TARBALL" "$extract_root"
/usr/bin/env -i \
  RELEASE_EXPECTED_VERSION="$RELEASE_VERSION" \
  "$node_path" "$publish_root/verify_npm_release_package.mjs" "$profile" "$extract_root/package"

expected_integrity="$($node_path - "$RELEASE_NPM_TARBALL" <<'NODE'
const fs = require('node:fs');
const crypto = require('node:crypto');
const bytes = fs.readFileSync(process.argv[2]);
process.stdout.write(`sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`);
NODE
)"
case "$profile" in
  wasm) registry_path='%40exochain%2Fexochain-wasm' ;;
  llm) registry_path='%40exochain%2Fllm-proxy' ;;
  sdk) registry_path='%40exochain%2Fsdk' ;;
esac
registry_url="https://registry.npmjs.org/${registry_path}/${RELEASE_VERSION}"
package_registry_url="https://registry.npmjs.org/${registry_path}"

printf '%s\n' \
  'registry=https://registry.npmjs.org/' \
  '//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}' \
  'ignore-scripts=true' \
  > "$publisher_user_config"
: > "$publisher_global_config"
/bin/chmod 600 "$publisher_user_config" "$publisher_global_config"
[ "$publisher_user_config" != "$publisher_global_config" ] \
  || fail "publisher user and global npm config paths must differ"

run_authenticated_npm() {
  [ "$acceptance_only" = false ] && [ "$RELEASE_OPERATION" != recover-0.2.7-retained ] \
    || fail 'authenticated npm is forbidden in acceptance-only mode'
  /usr/bin/env -i \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN="${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" \
    ACTIONS_ID_TOKEN_REQUEST_URL="${ACTIONS_ID_TOKEN_REQUEST_URL:-}" \
    GITHUB_ACTIONS="${GITHUB_ACTIONS:-true}" \
    GITHUB_EVENT_NAME="$GITHUB_EVENT_NAME" \
    GITHUB_REF="$GITHUB_REF" \
    GITHUB_REPOSITORY="$GITHUB_REPOSITORY" \
    GITHUB_REPOSITORY_ID="${GITHUB_REPOSITORY_ID:-}" \
    GITHUB_REPOSITORY_OWNER_ID="${GITHUB_REPOSITORY_OWNER_ID:-}" \
    GITHUB_RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-}" \
    GITHUB_RUN_ID="${GITHUB_RUN_ID:-}" \
    GITHUB_SERVER_URL="${GITHUB_SERVER_URL:-}" \
    GITHUB_SHA="$GITHUB_SHA" \
    GITHUB_WORKFLOW_REF="$GITHUB_WORKFLOW_REF" \
    HOME="$home_root" \
    NODE_AUTH_TOKEN="$NODE_AUTH_TOKEN" \
    NPM_CONFIG_CACHE="$home_root/cache" \
    NPM_CONFIG_GLOBALCONFIG="$publisher_global_config" \
    NPM_CONFIG_IGNORE_SCRIPTS=true \
    NPM_CONFIG_REGISTRY=https://registry.npmjs.org \
    NPM_CONFIG_USERCONFIG="$publisher_user_config" \
    PATH="$TRUSTED_RELEASE_PATH" \
    RUNNER_ENVIRONMENT="${RUNNER_ENVIRONMENT:-github-hosted}" \
    "$node_path" "$npm_cli_path" "$@"
}

verify_release_binding() {
  if [[ "$RELEASE_OPERATION" = recover-0.2.7 || "$RELEASE_OPERATION" = recover-0.2.7-retained ]]; then
    /bin/cat "$recovery_binding_verifier"
  else
    /usr/bin/git --no-replace-objects -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false \
      -C "$GITHUB_WORKSPACE" show "${GITHUB_SHA}:tools/verify_release_side_effect.sh"
  fi | \
    /usr/bin/env -i \
      BASH_ENV=/dev/null \
      DRY_RUN=false \
      EXPECTED_COMMIT_SHA="$EXPECTED_COMMIT_SHA" \
      EXPECTED_TAG_COMMIT_SHA="$EXPECTED_TAG_COMMIT_SHA" \
      EXPECTED_TAG_OBJECT_SHA="$EXPECTED_TAG_OBJECT_SHA" \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_NO_REPLACE_OBJECTS=1 \
      GITHUB_ACTIONS="${GITHUB_ACTIONS:-true}" \
      GITHUB_REF="$GITHUB_REF" \
      GITHUB_REPOSITORY="$GITHUB_REPOSITORY" \
      GITHUB_SERVER_URL="${GITHUB_SERVER_URL:-}" \
      GITHUB_SHA="$GITHUB_SHA" \
      GITHUB_WORKSPACE="$GITHUB_WORKSPACE" \
      GNUPGHOME="${GNUPGHOME:-}" \
      EXOCHAIN_RELEASE_SIGNING_FINGERPRINT="${EXOCHAIN_RELEASE_SIGNING_FINGERPRINT:-}" \
      RELEASE_GITHUB_TOKEN="${RELEASE_GITHUB_TOKEN:-}" \
      RELEASE_OPERATION="$RELEASE_OPERATION" \
      RELEASE_PYTHON="$python_path" \
      RELEASE_TRUSTED_PYTHON_ROOT="$python_root" \
      RELEASE_TRUSTED_PYTHON_VERSION="$RELEASE_TRUSTED_PYTHON_VERSION" \
      RELEASE_SOURCE_CLEAN_MODE=all \
      RELEASE_TAG="$RELEASE_TAG" \
      RUNNER_TEMP="${RUNNER_TEMP:-}" \
      TRUSTED_RELEASE_REF="$TRUSTED_RELEASE_REF" \
      /bin/bash --noprofile --norc -p
}

verify_credentialed_npm_actor() {
  local actual_actor
  actual_actor="$(run_authenticated_npm whoami --registry=https://registry.npmjs.org)" \
    || fail "npm whoami rejected the configured release credential"
  [ "$actual_actor" = "$expected_npm_actor" ] \
    || fail "npm release credential belongs to an unauthorized actor"
}

verify_exact_npm_owners() {
  local actual_owners
  actual_owners="$(run_public_npm owner ls "$package_name" --registry=https://registry.npmjs.org)" \
    || fail "npm owner ls could not prove package authority"
  [ "$actual_owners" = "$expected_maintainer_name <$expected_maintainer_email>" ] \
    || fail "npm package owners differ from the exact canonical maintainer policy"
}

verify_prepublication_npm_authority() {
  local actual_owners
  if actual_owners="$(run_public_npm owner ls "$package_name" --registry=https://registry.npmjs.org)"; then
    [ "$actual_owners" = "$expected_maintainer_name <$expected_maintainer_email>" ] \
      || fail "npm package owners differ from the exact canonical maintainer policy"
    return
  fi

  local status
  status="$(/usr/bin/env -i \
    /usr/bin/curl -q --silent --show-error --output "$package_registry_response" \
      --write-out '%{http_code}' --proto '=https' --tlsv1.2 \
      --connect-timeout 15 --max-time 60 --max-filesize 1048576 \
      "$package_registry_url")" || fail "npm package namespace lookup failed"
  case "$status" in
    404)
      [ "$profile" = sdk ] && [ "$package_name" = @exochain/sdk ] \
        || fail "npm first publication is approved only for the exact SDK package"
      ;;
    200) fail "npm owner ls could not prove authority over an existing package" ;;
    *) fail "npm package namespace returned unexpected HTTP status $status" ;;
  esac
}

registry_has_exact_tarball() {
  local status
  status="$(fetch_npm_registry_record)" || fail "npm registry lookup failed"
  case "$status" in
    404) return 1 ;;
    200) ;;
    *) fail "npm registry returned unexpected HTTP status $status" ;;
  esac
  validate_npm_registry_response \
    "$registry_response" "$package_name" "$RELEASE_VERSION" "$expected_integrity" \
    "$node_path" "$expected_maintainer_name" "$expected_maintainer_email" \
    || fail "published npm version does not match the exact release identity"
  /usr/bin/env -i "$node_path" "$registry_verifier" registry \
    "$registry_response" "$package_name" "$RELEASE_VERSION" "$expected_integrity" \
    "$expected_maintainer_name" "$expected_maintainer_email" \
    || fail "published npm registry record failed exact release verification"
}

fetch_public_npm_tarball() {
  /usr/bin/env -i /usr/bin/curl -q --silent --show-error --request GET \
    --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 60 \
    --max-filesize "$3" --output "$2" --write-out '%{http_code}' "$1"
}

verify_public_npm_tarball_bytes() {
  local url public_tarball size status
  case "$package_name" in
    @exochain/exochain-wasm|@exochain/llm-proxy|@exochain/sdk) ;;
    *) fail 'unexpected public npm package' ;;
  esac
  [[ "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'invalid public npm version'
  url="https://registry.npmjs.org/$package_name/-/${package_name#*/}-$RELEASE_VERSION.tgz"
  public_tarball="$publish_root/public-tarball.tgz"
  [ ! -e "$public_tarball" ] && [ ! -L "$public_tarball" ] || fail 'public tarball destination already exists'
  size="$(/usr/bin/env -i "$node_path" -e '
const fs=require("node:fs"); const s=fs.lstatSync(process.argv[1]);
if (!s.isFile() || s.nlink!==1 || s.size<=0 || s.size>96*1024*1024) process.exit(1);
process.stdout.write(String(s.size));' "$RELEASE_NPM_TARBALL")" || fail 'invalid original public tarball size'
  status="$(fetch_public_npm_tarball "$url" "$public_tarball" "$size")" || fail 'public npm tarball transport failed'
  [ "$status" = 200 ] || fail 'public npm tarball is absent'
  /usr/bin/cmp "$RELEASE_NPM_TARBALL" "$public_tarball" >/dev/null || fail 'public npm tarball bytes differ'
  /usr/bin/env -i "$node_path" - "$public_tarball" "$size" "$RELEASE_EXPECTED_TARBALL_SHA256" "$expected_integrity" <<'NODE' \
    || fail 'public npm tarball size, SHA256 or SRI differs'
const fs=require('node:fs'); const crypto=require('node:crypto');
const [path,size,digest,sri]=process.argv.slice(2);
const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
try {
  const before=fs.fstatSync(fd,{bigint:true});
  if (!before.isFile() || before.nlink!==1n || before.size!==BigInt(size)) process.exit(1);
  const bytes=Buffer.alloc(Number(size)); let read=0;
  while (read<bytes.length) {
    const count=fs.readSync(fd,bytes,read,bytes.length-read,null);
    if (count===0) process.exit(1);
    read+=count;
  }
  if (fs.readSync(fd,Buffer.alloc(1),0,1,null)!==0) process.exit(1);
  const after=fs.fstatSync(fd,{bigint:true});
  if (['dev','ino','mode','nlink','size','mtimeNs','ctimeNs'].some(k=>before[k]!==after[k])) process.exit(1);
  if (crypto.createHash('sha256').update(bytes).digest('hex')!==digest ||
      'sha512-'+crypto.createHash('sha512').update(bytes).digest('base64')!==sri) process.exit(1);
} finally {fs.closeSync(fd);}
NODE
}

install_public_npm_for_acceptance() {
  /bin/rm -rf -- "$audit_root"
  /bin/mkdir -m 700 "$audit_root"
  /usr/bin/env -i "$node_path" - "$audit_root/package.json" "$package_name" "$RELEASE_VERSION" <<'NODE'
const fs = require('node:fs');
const [output, name, version] = process.argv.slice(2);
fs.writeFileSync(output, JSON.stringify({
  name: 'exochain-release-registry-proof',
  version: '0.0.0',
  private: true,
  dependencies: { [name]: version },
}), { flag: 'wx', mode: 0o600 });
NODE
  (
    cd "$audit_root"
    run_public_npm install --ignore-scripts --no-audit --no-fund --save-exact \
      --registry=https://registry.npmjs.org >/dev/null || exit 1
  ) || return 1
}

verify_registry_signature_and_provenance() {
  install_public_npm_for_acceptance || return 1
  (
    cd "$audit_root"
    run_public_npm audit signatures --json --include-attestations > "$audit_response" \
      || exit 1
  ) || return 1
  local audit_sha256
  audit_sha256="$(/usr/bin/sha256sum "$audit_response" | /usr/bin/cut -d ' ' -f 1)"
  [[ "$audit_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  /usr/bin/env -i "$node_path" "$registry_verifier" audit \
    "$audit_response" "$package_name" "$RELEASE_VERSION" "$expected_integrity" \
    "$provenance_commit" "$provenance_ref" || return 1
  [ "$(/usr/bin/sha256sum "$audit_response" | /usr/bin/cut -d ' ' -f 1)" = "$audit_sha256" ] \
    || return 1
}

verify_registry_acceptance() {
  registry_has_exact_tarball \
    || fail "the exact npm version disappeared during acceptance verification"
  verify_public_npm_tarball_bytes
  verify_exact_npm_owners
  local provenance_verified=false
  for provenance_attempt in 1 2 3 4 5 6; do
    if verify_registry_signature_and_provenance; then
      provenance_verified=true
      break
    fi
    [ "$provenance_attempt" -lt 6 ] && /bin/sleep 10
  done
  [ "$provenance_verified" = true ] \
    || fail "npm audit signatures rejected the registry signature or exact release provenance"
}

publish_or_accept_npm
printf 'Verified %s@%s exact npm artifact, owners, signature, provenance, source, and tag.\n' \
  "$package_name" "$RELEASE_VERSION"
