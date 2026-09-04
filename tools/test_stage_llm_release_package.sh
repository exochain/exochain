#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'LYNK release staging test failed: %s\n' "$1" >&2
  exit 1
}

repo_root="$(pwd -P)"
stage_helper="$repo_root/tools/stage_llm_release_package.sh"
[ -x "$stage_helper" ] || fail "$stage_helper is missing or not executable"
release_python="${PYTHON:-$(command -v python3)}"
release_python="$($release_python -c 'import os,sys; print(os.path.realpath(sys.executable))')"
[ -f "$release_python" ] && [ -x "$release_python" ] && [ ! -L "$release_python" ] \
  || fail "a real Python interpreter is required"

fixture_root="$(mktemp -d)"
fixture_checkout="$fixture_root/checkout"
build_tree="$fixture_root/build-tree"
stage_root="$fixture_root/stage"
trap '/bin/rm -rf -- "$fixture_root"' EXIT

git init -q "$fixture_checkout"
git -C "$fixture_checkout" config user.name EXOCHAIN
git -C "$fixture_checkout" config user.email release-test@example.invalid
mkdir -p "$fixture_checkout/packages/exochain-llm-proxy/dist"
printf 'committed readme\n' > "$fixture_checkout/packages/exochain-llm-proxy/README.md"
printf 'committed package\n' > "$fixture_checkout/packages/exochain-llm-proxy/package.json"
printf 'committed dist\n' > "$fixture_checkout/packages/exochain-llm-proxy/dist/index.js"
printf '#!/bin/sh\nexit 0\n' > "$fixture_checkout/packages/exochain-llm-proxy/dist/cli.js"
chmod +x "$fixture_checkout/packages/exochain-llm-proxy/dist/cli.js"
git -C "$fixture_checkout" add packages
git -C "$fixture_checkout" commit -qm fixture
fixture_sha="$(git -C "$fixture_checkout" rev-parse HEAD)"

/bin/cp -R "$fixture_checkout/packages/exochain-llm-proxy" "$build_tree"
printf 'ATTACKER-LIFECYCLE-MUTATION\n' >> "$build_tree/README.md"

GITHUB_WORKSPACE="$fixture_checkout" \
GITHUB_SHA="$fixture_sha" \
RUNNER_TEMP="$fixture_root" \
RELEASE_LLM_BUILD_DIR="$build_tree" \
RELEASE_PYTHON="$release_python" \
RELEASE_LLM_STAGE_ROOT="$stage_root" \
  /bin/bash --noprofile --norc -p "$stage_helper" >/dev/null

stage_package="$stage_root/packages/exochain-llm-proxy"
/usr/bin/cmp -s \
  "$fixture_checkout/packages/exochain-llm-proxy/README.md" \
  "$stage_package/README.md" \
  || fail "staged README must come from the immutable commit, not lifecycle-mutated source"
if /usr/bin/grep -F 'ATTACKER-LIFECYCLE-MUTATION' "$stage_package/README.md" >/dev/null; then
  fail "lifecycle-mutated README reached the staged release package"
fi
[ -x "$stage_package/dist/cli.js" ] \
  || fail "staging must preserve the committed executable mode"

/bin/rm -rf -- "$stage_root"
GITHUB_WORKSPACE="$fixture_checkout" \
GITHUB_SHA="$fixture_sha" \
RUNNER_TEMP="$fixture_root" \
RELEASE_LLM_STAGE_ROOT="$stage_root" \
  /bin/bash --noprofile --norc -p "$stage_helper" >/dev/null
/usr/bin/cmp -s \
  "$fixture_checkout/packages/exochain-llm-proxy/README.md" \
  "$stage_package/README.md" \
  || fail "fresh packaging mode must reconstruct all LYNK bytes from the immutable commit"
[ -x "$stage_package/dist/cli.js" ] \
  || fail "fresh packaging mode must preserve the committed executable mode"

/bin/rm -rf -- "$stage_root"
printf 'mutated dist\n' > "$build_tree/dist/index.js"
if GITHUB_WORKSPACE="$fixture_checkout" \
  GITHUB_SHA="$fixture_sha" \
  RUNNER_TEMP="$fixture_root" \
  RELEASE_LLM_BUILD_DIR="$build_tree" \
  RELEASE_PYTHON="$release_python" \
  RELEASE_LLM_STAGE_ROOT="$stage_root" \
    /bin/bash --noprofile --norc -p "$stage_helper" >/dev/null 2>&1; then
  fail "staging must reject build output that differs from committed dist bytes"
fi

/bin/cp \
  "$fixture_checkout/packages/exochain-llm-proxy/dist/index.js" \
  "$build_tree/dist/index.js"
/bin/rm -rf -- "$stage_root"
replacement_index="$fixture_root/replacement.index"
GIT_INDEX_FILE="$replacement_index" git -C "$fixture_checkout" read-tree "$fixture_sha"
attacker_blob="$(printf 'replacement readme\n' | git -C "$fixture_checkout" hash-object -w --stdin)"
GIT_INDEX_FILE="$replacement_index" git -C "$fixture_checkout" update-index \
  --cacheinfo "100644,$attacker_blob,packages/exochain-llm-proxy/README.md"
replacement_tree="$(GIT_INDEX_FILE="$replacement_index" git -C "$fixture_checkout" write-tree)"
replacement_commit="$(printf 'replacement fixture\n' | git -C "$fixture_checkout" commit-tree "$replacement_tree" -p "$fixture_sha")"
git -C "$fixture_checkout" replace "$fixture_sha" "$replacement_commit"
GITHUB_WORKSPACE="$fixture_checkout" \
GITHUB_SHA="$fixture_sha" \
RUNNER_TEMP="$fixture_root" \
RELEASE_LLM_BUILD_DIR="$build_tree" \
RELEASE_PYTHON="$release_python" \
RELEASE_LLM_STAGE_ROOT="$stage_root" \
  /bin/bash --noprofile --norc -p "$stage_helper" >/dev/null
if /usr/bin/grep -F 'replacement readme' "$stage_package/README.md" >/dev/null; then
  fail "Git replacement objects must not alter immutable staged package bytes"
fi

printf 'LYNK release staging test passed\n'
