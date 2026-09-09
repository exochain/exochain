#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'release npm config boundary test failed: %s\n' "$1" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
workflow="$repo_root/.github/workflows/release.yml"
publisher="$repo_root/tools/publish_release_npm_package.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-npm-config-test.XXXXXX")"
trap '/bin/rm -rf -- "$test_root"' EXIT

[[ -f "$workflow" ]] || fail "release workflow is missing"
[[ -f "$publisher" ]] || fail "npm publisher is missing"

if grep -E 'NPM_CONFIG_(USERCONFIG|GLOBALCONFIG):[[:space:]]*/dev/null' \
    "$workflow" >/dev/null; then
  fail "release lifecycle jobs must not bind both npm config layers to /dev/null"
fi
[ "$(grep -cF '[ "$RELEASE_NPM_USER_CONFIG" != "$RELEASE_NPM_GLOBAL_CONFIG" ]' "$workflow" || true)" -eq 3 ] \
  || fail "all three token-free npm lanes must prove their user/global config paths differ"
[ "$(grep -cF '/bin/chmod 600 "$RELEASE_NPM_USER_CONFIG" "$RELEASE_NPM_GLOBAL_CONFIG"' "$workflow" || true)" -eq 3 ] \
  || fail "all three token-free npm lanes must protect both empty config files"
[ "$(grep -cF '"$npm_path" --version)" = 10.9.2 ]' "$workflow" || true)" -eq 3 ] \
  || fail "all three token-free npm lanes must execute the exact bundled npm 10.9.2 runtime"
grep -F '[ "$RELEASE_TRUSTED_NPM_VERSION" = 10.9.2 ]' "$publisher" >/dev/null \
  && grep -F '"$node_path" "$npm_cli_path" --version' "$publisher" >/dev/null \
  || fail "credentialed npm publication must verify the exact bundled npm 10.9.2 runtime"
grep -F 'publisher_user_config="$home_root/user.npmrc"' "$publisher" >/dev/null \
  && grep -F 'publisher_global_config="$home_root/global.npmrc"' "$publisher" >/dev/null \
  && grep -F '/bin/chmod 600 "$publisher_user_config" "$publisher_global_config"' "$publisher" >/dev/null \
  && grep -F '[ "$publisher_user_config" != "$publisher_global_config" ]' "$publisher" >/dev/null \
  && grep -F 'NPM_CONFIG_USERCONFIG="$publisher_user_config"' "$publisher" >/dev/null \
  && grep -F 'NPM_CONFIG_GLOBALCONFIG="$publisher_global_config"' "$publisher" >/dev/null \
  || fail "credentialed npm publication must use distinct protected private config files"

node_path="$(command -v node)"
npm_path="$(command -v npm)"
[ -x "$node_path" ] && [ -x "$npm_path" ] \
  || fail "Node.js and npm are required for the pinned npm regression"
runtime_root="$test_root/npm-runtime"
bootstrap_home="$test_root/bootstrap-home"
/bin/mkdir -m 700 -p "$runtime_root" "$bootstrap_home"
bootstrap_user_config="$bootstrap_home/user.npmrc"
bootstrap_global_config="$bootstrap_home/global.npmrc"
: > "$bootstrap_user_config"
: > "$bootstrap_global_config"
/bin/chmod 600 "$bootstrap_user_config" "$bootstrap_global_config"

# Install the exact npm release bundled by actions/setup-node 22.14.0. This is
# a test dependency only; production uses the commit-pinned setup-node action
# and verifies the same runtime before any package lifecycle or publication.
/usr/bin/env -i \
  PATH="$(dirname "$node_path"):$(dirname "$npm_path"):/usr/bin:/bin" \
  HOME="$bootstrap_home" \
  NPM_CONFIG_CACHE="$bootstrap_home/cache" \
  NPM_CONFIG_USERCONFIG="$bootstrap_user_config" \
  NPM_CONFIG_GLOBALCONFIG="$bootstrap_global_config" \
  "$npm_path" install --prefix "$runtime_root" --no-save --package-lock=false \
    --ignore-scripts --fund=false --audit=false --registry=https://registry.npmjs.org \
    npm@10.9.2 >/dev/null

pinned_npm="$runtime_root/node_modules/npm/bin/npm-cli.js"
[ -f "$pinned_npm" ] && [ ! -L "$pinned_npm" ] \
  || fail "exact npm 10.9.2 test runtime was not installed as a regular file"
[ "$(/usr/bin/env -i "$node_path" "$pinned_npm" --version)" = 10.9.2 ] \
  || fail "installed npm test runtime is not exactly 10.9.2"

runtime_home="$test_root/runtime-home"
/bin/mkdir -m 700 "$runtime_home"
same_config="$runtime_home/same.npmrc"
: > "$same_config"
/bin/chmod 600 "$same_config"
collision_output="$test_root/collision.out"
if /usr/bin/env -i \
    HOME="$runtime_home" \
    NPM_CONFIG_USERCONFIG="$same_config" \
    NPM_CONFIG_GLOBALCONFIG="$same_config" \
    "$node_path" "$pinned_npm" --version >"$collision_output" 2>&1; then
  fail "npm 10.9.2 accepted one path for both user and global configuration"
fi
grep -E 'config.*loaded twice|double.*config' "$collision_output" >/dev/null \
  || fail "npm 10.9.2 did not report the expected duplicate-config boundary"

runtime_user_config="$runtime_home/user.npmrc"
runtime_global_config="$runtime_home/global.npmrc"
: > "$runtime_user_config"
: > "$runtime_global_config"
/bin/chmod 600 "$runtime_user_config" "$runtime_global_config"
[ "$runtime_user_config" != "$runtime_global_config" ] \
  || fail "control fixture did not create distinct config paths"
[ "$(/usr/bin/env -i \
    HOME="$runtime_home" \
    NPM_CONFIG_USERCONFIG="$runtime_user_config" \
    NPM_CONFIG_GLOBALCONFIG="$runtime_global_config" \
    "$node_path" "$pinned_npm" --version)" = 10.9.2 ] \
  || fail "npm 10.9.2 failed with distinct empty user/global config files"

printf 'release npm config boundary test passed\n'
