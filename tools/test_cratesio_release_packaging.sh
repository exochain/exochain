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
[[ -f tools/publish_sealed_crate.py ]] \
  || fail "tools/publish_sealed_crate.py is missing"
[[ -f tools/test_publish_sealed_crate.py ]] \
  || fail "tools/test_publish_sealed_crate.py is missing"
[[ -f tools/test_publish_sealed_crate_cargo_parity.py ]] \
  || fail "tools/test_publish_sealed_crate_cargo_parity.py is missing"
[[ -f tools/test_verify_crate_release_archive.py ]] \
  || fail "tools/test_verify_crate_release_archive.py is missing"

fixture_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir"' EXIT
owner_guard_output="$fixture_dir/owner-guard.out"
node_path="$(command -v node)"
[ -x "$node_path" ] || fail "Node.js is unavailable"

expect_owner_guard_failure() {
  local case_name="$1"
  local expected_message="$2"
  shift 2
  if "$@" >"$owner_guard_output" 2>&1; then
    fail "crates.io namespace guard accepted $case_name"
  fi
  grep -F "$expected_message" "$owner_guard_output" >/dev/null \
    || fail "crates.io namespace guard did not explain $case_name"
}

printf '{"users":[{"login":"exochain"}]}\n' > "$fixture_dir/exochain-core.json"
expect_owner_guard_failure \
  "a missing repository owner allowlist" \
  "EXOCHAIN_CRATES_IO_ALLOWED_OWNERS must be explicitly configured" \
  env -u EXOCHAIN_CRATES_IO_ALLOWED_OWNERS \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    node tools/check_cratesio_namespace_ownership.mjs
expect_owner_guard_failure \
  "an empty repository owner allowlist" \
  "EXOCHAIN_CRATES_IO_ALLOWED_OWNERS must be explicitly configured" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS= \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    node tools/check_cratesio_namespace_ownership.mjs

printf '{"users":[{"login":"unapproved-owner"}]}\n' > "$fixture_dir/exochain-core.json"
expect_owner_guard_failure \
  "a package owned only by an unapproved account" \
  "unapproved crates.io owner" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    node tools/check_cratesio_namespace_ownership.mjs

printf '{"users":[{"login":"exochain"},{"login":"attacker"}]}\n' \
  > "$fixture_dir/exochain-core.json"
expect_owner_guard_failure \
  "mixed approved and unapproved owners" \
  "unapproved crates.io owner" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    node tools/check_cratesio_namespace_ownership.mjs

printf '{}\n' > "$fixture_dir/exochain-core.json"
expect_owner_guard_failure \
  "an owner response without a users array" \
  "malformed crates.io owner response" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    node tools/check_cratesio_namespace_ownership.mjs

printf '{"users":[]}\n' > "$fixture_dir/exochain-core.json"
expect_owner_guard_failure \
  "an empty owner response" \
  "empty crates.io owner response" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    node tools/check_cratesio_namespace_ownership.mjs

printf '{"users":[{"login":""}]}\n' > "$fixture_dir/exochain-core.json"
expect_owner_guard_failure \
  "a malformed owner record" \
  "malformed crates.io owner record" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    node tools/check_cratesio_namespace_ownership.mjs

printf '{"users":[{"login":"exochain"},{"login":"exochain-foundation"}]}\n' \
  > "$fixture_dir/exochain-core.json"
EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain,exochain-foundation \
  EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
  node tools/check_cratesio_namespace_ownership.mjs >/dev/null

printf '{"users":[{"login":"attacker"}],"users":[{"login":"exochain"}]}\n' \
  > "$fixture_dir/exochain-core.json"
expect_owner_guard_failure \
  "duplicate users keys hiding an unapproved owner" \
  "duplicate object key" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    EXOCHAIN_CRATES_IO_EXACT_TARGET=exochain-core \
    "$node_path" tools/check_cratesio_namespace_ownership.mjs

printf '{"u\\u0073ers":[{"login":"attacker"}],"users":[{"login":"exochain"}]}\n' \
  > "$fixture_dir/exochain-core.json"
expect_owner_guard_failure \
  "escaped duplicate users keys hiding an unapproved owner" \
  "duplicate object key" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    EXOCHAIN_CRATES_IO_EXACT_TARGET=exochain-core \
    "$node_path" tools/check_cratesio_namespace_ownership.mjs

/bin/rm -f "$fixture_dir/exochain-core.json"
/usr/bin/mkfifo "$fixture_dir/exochain-core.json"
expect_owner_guard_failure \
  "a FIFO owner fixture" \
  "must be one regular" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    EXOCHAIN_CRATES_IO_EXACT_TARGET=exochain-core \
    "$node_path" tools/check_cratesio_namespace_ownership.mjs
/bin/rm -f "$fixture_dir/exochain-core.json"

printf '{"users":[{"login":"exochain"}]}\n' > "$fixture_dir/owner-target.json"
/bin/ln -s "$fixture_dir/owner-target.json" "$fixture_dir/exochain-core.json"
expect_owner_guard_failure \
  "a symbolic-link owner fixture" \
  "cannot be securely opened" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    EXOCHAIN_CRATES_IO_EXACT_TARGET=exochain-core \
    "$node_path" tools/check_cratesio_namespace_ownership.mjs
/bin/rm -f "$fixture_dir/exochain-core.json"

/bin/ln "$fixture_dir/owner-target.json" "$fixture_dir/exochain-core.json"
expect_owner_guard_failure \
  "a hard-linked owner fixture" \
  "non-hardlinked" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    EXOCHAIN_CRATES_IO_EXACT_TARGET=exochain-core \
    "$node_path" tools/check_cratesio_namespace_ownership.mjs
/bin/rm -f "$fixture_dir/exochain-core.json" "$fixture_dir/owner-target.json"

/usr/bin/python3 - "$fixture_dir/exochain-core.json" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).write_bytes(b" " * (1024 * 1024 + 1))
PY
expect_owner_guard_failure \
  "an oversized owner fixture" \
  "size is outside the accepted range" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    EXOCHAIN_CRATES_IO_EXACT_TARGET=exochain-core \
    "$node_path" tools/check_cratesio_namespace_ownership.mjs

# Exercise the descriptor-level before/after stability check with a valid,
# near-limit JSON document whose trailing whitespace is changed continuously.
active_writer_fixture="$fixture_dir/exochain-core.json"
/usr/bin/python3 - "$active_writer_fixture" <<'PY'
from pathlib import Path
import sys

payload = b'{"users":[{"login":"exochain"}]}\n'
target = 1024 * 1024 - 1
Path(sys.argv[1]).write_bytes(payload + b" " * (target - len(payload)))
PY
writer_ready="$fixture_dir/owner-writer-ready"
writer_stop="$fixture_dir/owner-writer-stop"
/usr/bin/python3 - "$active_writer_fixture" "$writer_ready" "$writer_stop" <<'PY' &
from pathlib import Path
import sys

path, ready, stop = map(Path, sys.argv[1:])
with path.open("r+b", buffering=0) as handle:
    offset = path.stat().st_size - 1
    ready.touch()
    toggle = False
    while not stop.exists():
        handle.seek(offset)
        handle.write(b"\t" if toggle else b" ")
        toggle = not toggle
PY
writer_pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -e "$writer_ready" ] && break
  /bin/sleep 0.1
done
[ -e "$writer_ready" ] || fail "active owner-fixture writer did not start"
if env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    EXOCHAIN_CRATES_IO_EXACT_TARGET=exochain-core \
    "$node_path" tools/check_cratesio_namespace_ownership.mjs \
    >"$owner_guard_output" 2>&1; then
  : > "$writer_stop"
  wait "$writer_pid" || true
  fail "crates.io namespace guard accepted an actively modified owner fixture"
fi
: > "$writer_stop"
wait "$writer_pid" || true
grep -F 'changed while it was read' "$owner_guard_output" >/dev/null \
  || fail "active owner-fixture rejection did not come from the stable-read boundary"
/bin/rm -f -- "$writer_ready" "$writer_stop"

printf '{"users":[{"login":"exochain"}]}\n' > "$fixture_dir/exochain-core.json"
EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
  EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
  EXOCHAIN_CRATES_IO_EXACT_TARGET=exochain-core \
  PATH=/nonexistent \
  "$node_path" tools/check_cratesio_namespace_ownership.mjs >/dev/null \
  || fail "exact-target owner validation unexpectedly invoked Cargo"
expect_owner_guard_failure \
  "a target outside the exact release inventory" \
  "not one of the exact 32 release crates" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    EXOCHAIN_CRATES_IO_EXACT_TARGET=attacker-crate \
    "$node_path" tools/check_cratesio_namespace_ownership.mjs

/bin/rm -f "$fixture_dir/exochain-core.json"
EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
  EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
  EXOCHAIN_CRATES_IO_EXACT_TARGET=exochain-core \
  "$node_path" tools/check_cratesio_namespace_ownership.mjs >/dev/null \
  || fail "pre-publication ownership validation must permit an unclaimed namespace"
expect_owner_guard_failure \
  "an unclaimed namespace after an exact checksum observation" \
  "must already be claimed by an approved crates.io owner" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    EXOCHAIN_CRATES_IO_EXACT_TARGET=exochain-core \
    EXOCHAIN_CRATES_IO_REQUIRE_CLAIMED=true \
    "$node_path" tools/check_cratesio_namespace_ownership.mjs
expect_owner_guard_failure \
  "a malformed require-claimed mode" \
  "must be exactly true when set" \
  env EXOCHAIN_CRATES_IO_ALLOWED_OWNERS=exochain \
    EXOCHAIN_CRATES_IO_FIXTURE_DIR="$fixture_dir" \
    EXOCHAIN_CRATES_IO_EXACT_TARGET=exochain-core \
    EXOCHAIN_CRATES_IO_REQUIRE_CLAIMED=false \
    "$node_path" tools/check_cratesio_namespace_ownership.mjs

grep -F 'redirect: "error"' tools/check_cratesio_namespace_ownership.mjs >/dev/null \
  && grep -F 'AbortSignal.timeout(FETCH_TIMEOUT_MS)' tools/check_cratesio_namespace_ownership.mjs >/dev/null \
  && grep -F 'total > MAX_RESPONSE_BYTES' tools/check_cratesio_namespace_ownership.mjs >/dev/null \
  || fail "live crates.io owner requests must reject redirects, time out, and cap streamed bytes"

node tools/verify_cratesio_release_packaging.mjs

grep -F '${GITHUB_SHA}:tools/check_cratesio_namespace_ownership.mjs' "$workflow" >/dev/null \
  || fail "release workflow must load the crates.io namespace ownership guard from the immutable commit"
grep -F '/owners' tools/check_cratesio_namespace_ownership.mjs >/dev/null \
  || fail "crates.io namespace guard must inspect crates.io owner records, not only crate metadata"
grep -F 'EXOCHAIN_CRATES_IO_ALLOWED_OWNERS: ${{ vars.EXOCHAIN_CRATES_IO_ALLOWED_OWNERS }}' "$workflow" >/dev/null \
  || fail "release workflow must bind the crates.io owner allowlist to an explicit repository variable"
grep -F 'release_cargo package' tools/preflight_release_crates.sh >/dev/null \
  && grep -F -- '--workspace' tools/preflight_release_crates.sh >/dev/null \
  && grep -F -- '--no-verify' tools/preflight_release_crates.sh >/dev/null \
  && grep -F -- '--locked' tools/preflight_release_crates.sh >/dev/null \
  || fail "token-free preflight must package the exact locked workspace without running build scripts"
grep -F 'release_sealed_crate_publish "$crate" "$expected_checksum"' \
    tools/publish_release_crates.sh >/dev/null \
  && grep -F 'RELEASE_CRATE_ARCHIVE_DIR' tools/publish_release_crates.sh >/dev/null \
  && grep -F 'sealed_crate_publisher_program' tools/publish_release_crates.sh >/dev/null \
  || fail "live publisher must upload only the independently reproduced sealed archives"
if grep -F '"$trusted_cargo" publish' tools/publish_release_crates.sh >/dev/null; then
  fail "live publisher must not repackage mutable workspace source with Cargo"
fi
if grep -F -- '--allow-dirty' "$workflow" tools/preflight_release_crates.sh tools/publish_release_crates.sh >/dev/null; then
  fail "release workflow must not bypass Cargo's dirty-source rejection"
fi
grep -F 'bash tools/test_cratesio_release_packaging.sh' "$ci_workflow" >/dev/null \
  || fail "CI repo hygiene must run the crates.io release packaging guard"
grep -F 'python3 tools/test_publish_sealed_crate.py' "$ci_workflow" >/dev/null \
  || fail "CI repo hygiene must run the sealed crate uploader regression tests"
grep -F 'tools/test_publish_sealed_crate_cargo_parity.py' "$ci_workflow" >/dev/null \
  && grep -F 'tools/test_verify_crate_release_archive.py' "$ci_workflow" >/dev/null \
  && grep -F 'toolchain: 1.97.1' "$ci_workflow" >/dev/null \
  || fail "exact Cargo parity and archive snapshot regressions must run under pinned CI"
[ "$(grep -cF 'package/*.crate' "$workflow" || true)" -eq 2 ] \
  && [ "$(grep -cF 'compression-level: 0' "$workflow" || true)" -ge 2 ] \
  || fail "both token-free crate reproductions must transport exact uncompressed archives"
grep -F 'capture_release_helper tools/publish_sealed_crate.py sealed_crate_publisher_program' \
    "$workflow" >/dev/null \
  && grep -F 'RELEASE_CRATE_ARCHIVE_DIR="$RELEASE_CRATE_ARCHIVE_DIR"' \
    "$workflow" >/dev/null \
  && grep -F 'RELEASE_SEALED_CRATE_PUBLISHER_PROGRAM="$sealed_crate_publisher_program"' \
    "$workflow" >/dev/null \
  || fail "credentialed crate publication must consume the captured sealed uploader and archive set"

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
