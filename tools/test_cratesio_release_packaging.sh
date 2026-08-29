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

set -euo pipefail

fail() {
  printf 'crates.io release packaging test failed: %s\n' "$1" >&2
  exit 1
}

workflow=".github/workflows/release.yml"
ci_workflow=".github/workflows/ci.yml"

[[ -f "$workflow" ]] || fail "$workflow is missing"
[[ -f "$ci_workflow" ]] || fail "$ci_workflow is missing"
[[ -f tools/check_cratesio_namespace_ownership.mjs ]] \
  || fail "tools/check_cratesio_namespace_ownership.mjs is missing"
[[ -f tools/verify_cratesio_release_packaging.mjs ]] \
  || fail "tools/verify_cratesio_release_packaging.mjs is missing"

node tools/verify_cratesio_release_packaging.mjs

fixture_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir"' EXIT
owner_guard_output="$fixture_dir/owner-guard.out"
printf '{"users":[{"login":"unapproved-owner"}]}\n' > "$fixture_dir/exochain-core.json"
if EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
  EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
  node tools/check_cratesio_namespace_ownership.mjs >"$owner_guard_output" 2>&1; then
  fail "crates.io namespace guard must reject packages owned by non-EXOCHAIN accounts"
fi
grep -F 'not an approved EXOCHAIN owner' "$owner_guard_output" >/dev/null \
  || fail "crates.io namespace guard rejection must explain the non-EXOCHAIN owner"

printf '{"users":[{"login":"exochain"}]}\n' > "$fixture_dir/exochain-core.json"
EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
  EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
  node tools/check_cratesio_namespace_ownership.mjs >/dev/null

grep -F 'node tools/check_cratesio_namespace_ownership.mjs' "$workflow" >/dev/null \
  || fail "release workflow must run the crates.io namespace ownership guard before publishing"
grep -F '/owners' tools/check_cratesio_namespace_ownership.mjs >/dev/null \
  || fail "crates.io namespace guard must inspect crates.io owner records, not only crate metadata"
grep -F 'cargo publish -p "$crate" --dry-run --locked' "$workflow" >/dev/null \
  || fail "release workflow must dry-run every crate without refreshing the lockfile"
if grep -F -- '--allow-dirty' "$workflow" >/dev/null; then
  fail "release workflow must not bypass Cargo's dirty-source rejection"
fi
grep -F 'bash tools/test_cratesio_release_packaging.sh' "$ci_workflow" >/dev/null \
  || fail "CI repo hygiene must run the crates.io release packaging guard"

if grep -E '^[[:space:]]+exo-(core|node|identity|consent|authority|dag|proofs|gatekeeper|governance|escalation|legal|tenant|api|gateway)[[:space:]]*$' "$workflow" >/dev/null; then
  fail "release publish loop must use final exochain-* package names, not legacy exo-* names"
fi

stale_cargo_selectors="$fixture_dir/stale-cargo-selectors.out"
if rg -n -- 'cargo [^\n]*(^|[[:space:]])(-p|--packages)[[:space:]]+(exo-[A-Za-z0-9_-]+|decision-forum)([[:space:]]|$)' .github tools crates Dockerfile deploy >"$stale_cargo_selectors"; then
  cat "$stale_cargo_selectors" >&2
  fail "Cargo package selectors in CI/tools must use final exochain-* package names"
fi

stale_feature_selectors="$fixture_dir/stale-feature-selectors.out"
if rg -n -- '--features[[:space:]]+exo-[A-Za-z0-9_-]+/' .github tools crates Dockerfile deploy >"$stale_feature_selectors"; then
  cat "$stale_feature_selectors" >&2
  fail "Cargo feature selectors in CI/tools must use final exochain-* package names"
fi

printf 'crates.io release packaging test passed\n'
