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
  /usr/bin/env -i \
    EXPECTED_INTEGRITY="$expected_integrity" \
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
      || value?.dist?.integrity !== process.env.EXPECTED_INTEGRITY) reject();
} catch { reject(); }
finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
NODE
}

for required_name in \
  EXPECTED_COMMIT_SHA \
  EXPECTED_TAG_COMMIT_SHA \
  EXPECTED_TAG_OBJECT_SHA \
  GITHUB_SHA \
  GITHUB_WORKSPACE \
  NODE_AUTH_TOKEN \
  RELEASE_EXPECTED_TARBALL_SHA256 \
  RELEASE_GITHUB_TOKEN \
  RELEASE_NPM_TARBALL \
  RELEASE_PYTHON \
  RELEASE_TAG \
  RELEASE_TEMP_ROOT \
  RELEASE_TRUSTED_NPM_VERSION \
  RELEASE_TRUSTED_PYTHON_ROOT \
  RELEASE_TRUSTED_PYTHON_VERSION \
  RELEASE_VERSION \
  TRUSTED_RELEASE_REF \
  TRUSTED_RELEASE_PATH \
  TRUSTED_RELEASE_TOOL_IDENTITY; do
  [ -n "${!required_name:-}" ] || fail "$required_name is required"
done

profile="${1:-}"
case "$profile" in
  wasm) package_name='@exochain/exochain-wasm' ;;
  llm) package_name='@exochain/llm-proxy' ;;
  *) fail "profile must be wasm or llm" ;;
esac
[[ "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "RELEASE_VERSION must be an exact semantic version"
[[ "$EXPECTED_COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]] \
  || fail "EXPECTED_COMMIT_SHA must be a full lowercase commit SHA"
[ "$EXPECTED_COMMIT_SHA" = "$GITHUB_SHA" ] \
  || fail "dispatch commit does not match the expected commit"
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
[ "$RELEASE_TRUSTED_NPM_VERSION" = 10.9.2 ] \
  || fail "release npm version must remain pinned to 10.9.2"
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
trap '/bin/rm -rf -- "${publish_root:-}"' EXIT
extract_root="$publish_root/extracted"
home_root="$publish_root/home"
registry_response="$publish_root/registry.json"
/bin/mkdir -m 700 "$home_root"
publisher_user_config="$home_root/user.npmrc"
publisher_global_config="$home_root/global.npmrc"

/usr/bin/git --no-replace-objects -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false \
  -C "$GITHUB_WORKSPACE" show "${GITHUB_SHA}:tools/verify_npm_release_tarball.py" \
  > "$publish_root/verify_tarball.py"
/usr/bin/env -i "$python_path" -I -B "$publish_root/verify_tarball.py" \
  "$RELEASE_NPM_TARBALL" "$extract_root"
/usr/bin/git --no-replace-objects -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false \
  -C "$GITHUB_WORKSPACE" show "${GITHUB_SHA}:tools/verify_npm_release_package.mjs" \
  > "$publish_root/verify_package.mjs"
/usr/bin/env -i \
  RELEASE_EXPECTED_VERSION="$RELEASE_VERSION" \
  "$node_path" "$publish_root/verify_package.mjs" "$profile" "$extract_root/package"

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
esac
registry_url="https://registry.npmjs.org/${registry_path}/${RELEASE_VERSION}"

registry_has_exact_tarball() {
  local status
  status="$(/usr/bin/env -i \
    /usr/bin/curl -q --silent --show-error --output "$registry_response" \
      --write-out '%{http_code}' --proto '=https' --tlsv1.2 \
      --connect-timeout 15 --max-time 60 --max-filesize 1048576 \
      "$registry_url")" || fail "npm registry lookup failed"
  case "$status" in
    404) return 1 ;;
    200) ;;
    *) fail "npm registry returned unexpected HTTP status $status" ;;
  esac
  if validate_npm_registry_response \
      "$registry_response" "$package_name" "$RELEASE_VERSION" \
      "$expected_integrity" "$node_path"
  then
    return 0
  fi
  fail "published npm version does not match the exact preflight tarball"
}

if registry_has_exact_tarball; then
  printf '%s@%s already exists with the exact preflight integrity; skipping.\n' \
    "$package_name" "$RELEASE_VERSION"
  exit 0
fi

# Rebind and re-evaluate both immutable source and live remote-tag identity at
# the last safe point before the registry mutation. The guard itself, and its
# child guards, are loaded from the exact dispatch commit.
/usr/bin/git --no-replace-objects -c core.fsmonitor=false -c core.untrackedCache=false -c core.ignoreStat=false \
  -C "$GITHUB_WORKSPACE" show "${GITHUB_SHA}:tools/verify_release_side_effect.sh" | \
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
    GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}" \
    GITHUB_SERVER_URL="${GITHUB_SERVER_URL:-}" \
    GITHUB_SHA="$GITHUB_SHA" \
    GITHUB_WORKSPACE="$GITHUB_WORKSPACE" \
    RELEASE_GITHUB_TOKEN="$RELEASE_GITHUB_TOKEN" \
    RELEASE_SOURCE_CLEAN_MODE=all \
    RELEASE_TAG="$RELEASE_TAG" \
    TRUSTED_RELEASE_REF="$TRUSTED_RELEASE_REF" \
    /bin/bash --noprofile --norc -p

printf '%s\n' \
  'registry=https://registry.npmjs.org/' \
  '//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}' \
  'ignore-scripts=true' \
  > "$publisher_user_config"
: > "$publisher_global_config"
/bin/chmod 600 "$publisher_user_config" "$publisher_global_config"
[ "$publisher_user_config" != "$publisher_global_config" ] \
  || fail "publisher user and global npm config paths must differ"

cd /
/usr/bin/env -i \
  ACTIONS_ID_TOKEN_REQUEST_TOKEN="${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" \
  ACTIONS_ID_TOKEN_REQUEST_URL="${ACTIONS_ID_TOKEN_REQUEST_URL:-}" \
  GITHUB_ACTIONS="${GITHUB_ACTIONS:-true}" \
  GITHUB_EVENT_NAME="${GITHUB_EVENT_NAME:-workflow_dispatch}" \
  GITHUB_REF="${GITHUB_REF:-}" \
  GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}" \
  GITHUB_REPOSITORY_ID="${GITHUB_REPOSITORY_ID:-}" \
  GITHUB_REPOSITORY_OWNER_ID="${GITHUB_REPOSITORY_OWNER_ID:-}" \
  GITHUB_RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-}" \
  GITHUB_RUN_ID="${GITHUB_RUN_ID:-}" \
  GITHUB_SERVER_URL="${GITHUB_SERVER_URL:-}" \
  GITHUB_SHA="$GITHUB_SHA" \
  GITHUB_WORKFLOW_REF="${GITHUB_WORKFLOW_REF:-}" \
  HOME="$home_root" \
  NODE_AUTH_TOKEN="$NODE_AUTH_TOKEN" \
  NPM_CONFIG_CACHE="$home_root/cache" \
  NPM_CONFIG_GLOBALCONFIG="$publisher_global_config" \
  NPM_CONFIG_IGNORE_SCRIPTS=true \
  NPM_CONFIG_REGISTRY=https://registry.npmjs.org \
  NPM_CONFIG_USERCONFIG="$publisher_user_config" \
  PATH="$TRUSTED_RELEASE_PATH" \
  RUNNER_ENVIRONMENT="${RUNNER_ENVIRONMENT:-github-hosted}" \
  "$node_path" "$npm_cli_path" publish "$RELEASE_NPM_TARBALL" \
    --access public --provenance --ignore-scripts --registry=https://registry.npmjs.org

for registry_attempt in 1 2 3 4 5 6; do
  if registry_has_exact_tarball; then
    printf 'Verified %s@%s registry integrity after publication.\n' \
      "$package_name" "$RELEASE_VERSION"
    exit 0
  fi
  [ "$registry_attempt" -lt 6 ] && /bin/sleep 10
done
fail "published npm version did not reach the registry with exact preflight integrity"
