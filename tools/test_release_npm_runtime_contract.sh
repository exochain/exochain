#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'npm runtime contract test failed: %s\n' "$1" >&2
  exit 1
}

case "${1:-}" in
  '') expected_node=v24.15.0; expected_npm=11.12.1; legacy=false ;;
  --expect-legacy-rejection) expected_node=v22.14.0; expected_npm=10.9.2; legacy=true ;;
  *) fail "usage: $0 [--expect-legacy-rejection]" ;;
esac
[ "$#" -le 1 ] || fail "usage: $0 [--expect-legacy-rejection]"
node_path="${RELEASE_TEST_NODE:-}"
npm_cli="${RELEASE_TEST_NPM:-}"
[[ "$node_path" = /* && -f "$node_path" && -x "$node_path" ]] \
  || fail "RELEASE_TEST_NODE must name an explicit absolute executable"
[[ "$npm_cli" = /* && -f "$npm_cli" ]] \
  || fail "RELEASE_TEST_NPM must name an explicit absolute npm CLI file"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-npm-runtime-contract.XXXXXX")"
printf 'npm runtime contract evidence: %s\n' "$test_root"
/bin/mkdir -m 700 "$test_root/project" "$test_root/cache"
user_config="$test_root/user.npmrc"
global_config="$test_root/global.npmrc"
: > "$user_config"
: > "$global_config"
/bin/chmod 600 "$user_config" "$global_config"
[ "$user_config" != "$global_config" ] || fail "npm config files must differ"
cd "$test_root/project"

run_npm() {
  /usr/bin/env -i \
    PATH="$(dirname "$node_path"):/usr/bin:/bin" \
    NPM_CONFIG_USERCONFIG="$user_config" \
    NPM_CONFIG_GLOBALCONFIG="$global_config" \
    NPM_CONFIG_CACHE="$test_root/cache" \
    NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ \
    NPM_CONFIG_IGNORE_SCRIPTS=true \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    "$node_path" "$npm_cli" "$@"
}

# Reject the wrong tool pair before the first network operation. Both npm
# configuration layers are private empty files; no caller credentials survive.
/usr/bin/env -i "$node_path" --version > "$test_root/node-version.txt"
[ "$(<"$test_root/node-version.txt")" = "$expected_node" ] \
  || fail "expected Node $expected_node"
run_npm --version > "$test_root/npm-version.txt"
[ "$(<"$test_root/npm-version.txt")" = "$expected_npm" ] \
  || fail "expected npm $expected_npm"

printf '%s\n' '{"name":"exochain-public-runtime-contract","version":"1.0.0","private":true}' > package.json
run_npm install --ignore-scripts --no-audit --no-fund --save-exact \
  '@exochain/exochain-wasm@0.2.7' > "$test_root/install.stdout" 2> "$test_root/install.stderr"
integrity='sha512-8x96qZwE16F8Gdd0JZ6G4VXaNM2mvETW+czF4xN1lURoMGaEtH7VPT9VwnlOJOlmd0bjh6pBh/zPN78PLN3sRw=='
/usr/bin/env -i "$node_path" - "$integrity" <<'NODE'
const fs = require('node:fs');
const lock = JSON.parse(fs.readFileSync('package-lock.json'));
const entry = lock.packages?.['node_modules/@exochain/exochain-wasm'];
if (entry?.version !== '0.2.7' || entry?.integrity !== process.argv[2]
    || entry?.resolved !== 'https://registry.npmjs.org/@exochain/exochain-wasm/-/exochain-wasm-0.2.7.tgz'
    || Object.keys(lock.packages).length !== 2) {
  throw new Error('installed tree differs from the exact published WASM artifact');
}
NODE
run_npm audit signatures --json --include-attestations \
  > "$test_root/audit.json" 2> "$test_root/audit.stderr"
verifier_status=0
/usr/bin/env -i "$node_path" "$repo_root/tools/verify_npm_registry_attestation.mjs" \
  audit "$test_root/audit.json" '@exochain/exochain-wasm' 0.2.7 "$integrity" \
  666c578f719d1e54fce95d6831a3af92ea80df93 refs/tags/v0.2.7 \
  > "$test_root/verifier.stdout" 2> "$test_root/verifier.stderr" || verifier_status=$?
printf '%s\n' "$verifier_status" > "$test_root/verifier-status.txt"

if [ "$legacy" = true ]; then
  /usr/bin/env -i "$node_path" - "$test_root/audit.json" <<'NODE'
const fs = require('node:fs');
const audit = JSON.parse(fs.readFileSync(process.argv[2]));
if (!Array.isArray(audit.invalid) || audit.invalid.length !== 0
    || !Array.isArray(audit.missing) || audit.missing.length !== 0
    || Object.hasOwn(audit, 'verified')) {
  throw new Error('legacy regression requires real successful npm 10 output without verified bundles');
}
NODE
  [ "$verifier_status" -eq 1 ] || fail "legacy npm audit output was not rejected"
  grep -F 'npm audit result contains invalid or missing signatures' "$test_root/verifier.stderr" >/dev/null \
    || fail "legacy output failed for an unexpected reason"
  printf 'Real npm %s audit succeeded; unchanged verifier rejected its missing verified bundles as expected.\n' "$expected_npm"
else
  [ "$verifier_status" -eq 0 ] || fail "real npm audit output failed exact release verification"
  printf 'Real Node %s / npm %s audit passed the unchanged exact release verifier.\n' "$expected_node" "$expected_npm"
fi
