#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'npm visibility test failed: %s\n' "$1" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-npm-visibility.XXXXXX")"
trap '/bin/rm -rf -- "$test_root"' EXIT
# Load only function definitions, never the credentialed publisher entrypoint.
awk '/^for required_name in/ { found=1; exit } { print } END { if (!found) exit 42 }' \
  "$repo_root/tools/publish_release_npm_package.sh" > "$test_root/functions.sh"
source "$test_root/functions.sh"
declare -F wait_for_npm_registry_visibility >/dev/null \
  || fail "publisher must expose bounded visibility polling"
run_authenticated_npm() { fail "visibility polling attempted an authenticated registry operation"; }

check_count=0
sleep_count=0
visible_at=1
fatal_at=0
probe_registry() {
  check_count=$((check_count + 1))
  [ "$check_count" -ne "$fatal_at" ] || return 2
  [ "$check_count" -ge "$visible_at" ] && return 0
  return 1 # The production probe returns 1 only for HTTP 404.
}
record_sleep() {
  [ "$#" -eq 1 ] && [ "$1" = 15 ] || fail "visibility interval must be 15 seconds"
  sleep_count=$((sleep_count + 1))
}
run_case() {
  local label="$1" expected_status="$2" expected_checks="$3" expected_sleeps="$4"
  check_count=0
  sleep_count=0
  local status=0
  wait_for_npm_registry_visibility probe_registry record_sleep || status=$?
  [ "$status" -eq "$expected_status" ] || fail "$label returned $status"
  [ "$check_count" -eq "$expected_checks" ] || fail "$label made $check_count registry requests"
  [ "$sleep_count" -eq "$expected_sleeps" ] || fail "$label slept $sleep_count times"
}
run_case immediate 0 1 0
visible_at=4
run_case delayed 0 4 3
visible_at=25
run_case final-attempt 0 25 24
visible_at=26
run_case exhausted 1 25 24
fatal_at=1
run_case malformed-or-unexpected 2 1 0
fatal_at=4
run_case fatal-after-delay 2 4 3
# A failed clock/scheduler must also prevent further polling.
fatal_at=0
sleep_fails() { return 3; }
check_count=0
status=0
wait_for_npm_registry_visibility probe_registry sleep_fails || status=$?
[ "$status" -eq 3 ] && [ "$check_count" -eq 1 ] \
  || fail "failed sleep did not stop visibility polling"
# Exercise the real HTTP disposition and exact registry validators too. Only
# the external fetch and wall-clock delay are replaced with deterministic I/O.
declare -F fetch_npm_registry_record >/dev/null \
  || fail "registry fetch must be separable from exact response validation"
awk '/^registry_has_exact_tarball\(\) \{/ { found=1; copying=1 } copying { print } copying && /^}/ { exit } END { if (!found) exit 42 }' \
  "$repo_root/tools/publish_release_npm_package.sh" > "$test_root/registry-probe.sh"
source "$test_root/registry-probe.sh"
node_path="$(command -v node)"
registry_verifier="$repo_root/tools/verify_npm_registry_attestation.mjs"
registry_response="$test_root/response.json"
package_name='@exochain/exochain-wasm'
RELEASE_VERSION=0.2.7
expected_integrity='sha512-8x96qZwE16F8Gdd0JZ6G4VXaNM2mvETW+czF4xN1lURoMGaEtH7VPT9VwnlOJOlmd0bjh6pBh/zPN78PLN3sRw=='
expected_maintainer_name=bob-stewart
expected_maintainer_email=stewart@exochain.com
"$node_path" - "$test_root" "$expected_integrity" <<'NODE'
const fs = require('node:fs');
const [root, integrity] = process.argv.slice(2);
const record = {
  name: '@exochain/exochain-wasm', version: '0.2.7',
  maintainers: [{ name: 'bob-stewart', email: 'stewart@exochain.com' }],
  _npmUser: { name: 'bob-stewart', email: 'stewart@exochain.com' },
  dist: {
    integrity,
    tarball: 'https://registry.npmjs.org/@exochain/exochain-wasm/-/exochain-wasm-0.2.7.tgz',
    signatures: [{ keyid: 'registry-fixture-key', sig: 'registry-fixture-signature' }],
    attestations: {
      url: 'https://registry.npmjs.org/-/npm/v1/attestations/%40exochain%2Fexochain-wasm@0.2.7',
      provenance: { predicateType: 'https://slsa.dev/provenance/v1' },
    },
  },
};
fs.writeFileSync(`${root}/valid.json`, JSON.stringify(record));
record.dist.tarball = 'https://attacker.invalid/other.tgz';
fs.writeFileSync(`${root}/wrong-tarball.json`, JSON.stringify(record));
record.dist.integrity = 'sha512-wrong';
fs.writeFileSync(`${root}/wrong-integrity.json`, JSON.stringify(record));
fs.writeFileSync(`${root}/malformed.json`, '{');
NODE
fetch_npm_registry_record() {
  printf 'request\n' >> "$test_root/requests"
  [ "$transport_status" -eq 0 ] || return "$transport_status"
  cp "$http_fixture" "$registry_response"
  printf '%s' "$http_status"
}
record_http_sleep() {
  [ "$1" = 15 ] || fail "wrong HTTP visibility sleep interval"
  printf 'sleep\n' >> "$test_root/sleeps"
}
run_http_case() {
  local label="$1" expected_status="$2" expected_requests="$3" expected_delays="$4"
  : > "$test_root/requests"
  : > "$test_root/sleeps"
  local result=0
  (wait_for_npm_registry_visibility registry_has_exact_tarball record_http_sleep) \
    > "$test_root/probe.stdout" 2> "$test_root/probe.stderr" || result=$?
  [ "$result" -eq "$expected_status" ] || fail "$label returned $result"
  [ "$(wc -l < "$test_root/requests" | tr -d ' ')" -eq "$expected_requests" ] \
    || fail "$label retried a terminal response"
  [ "$(wc -l < "$test_root/sleeps" | tr -d ' ')" -eq "$expected_delays" ] \
    || fail "$label slept after a terminal response"
}
http_fixture="$test_root/valid.json"
transport_status=0
http_status=200
run_http_case exact-record 0 1 0
http_fixture="$test_root/wrong-tarball.json"
run_http_case wrong-tarball 1 1 0
http_fixture="$test_root/wrong-integrity.json"
run_http_case wrong-integrity 1 1 0
http_fixture="$test_root/malformed.json"
run_http_case malformed-record 1 1 0
http_fixture="$test_root/valid.json"
for http_status in 400 401 403 429 500 503; do
  run_http_case "http-$http_status" 1 1 0
done
http_status=404
run_http_case absent-record 1 25 24
transport_status=7
run_http_case network-failure 1 1 0
printf 'npm visibility behavior tests passed, including real response validation and terminal HTTP failures.\n'
