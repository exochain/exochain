#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'npm registry validation test failed: %s\n' "$1" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
publisher="$repo_root/tools/publish_release_npm_package.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-npm-registry-test.XXXXXX")"
trap '/bin/rm -rf -- "$test_root"' EXIT
prefix="$test_root/publisher-prefix.sh"
/usr/bin/awk '
  /^for required_name in/ { found = 1; exit }
  { print }
  END { if (!found) exit 42 }
' "$publisher" > "$prefix" || fail "publisher validation boundary is missing"
# shellcheck source=/dev/null
source "$prefix"
declare -F validate_npm_registry_response >/dev/null \
  || fail "strict npm registry response validator is missing"

node_path="$(command -v node)"
[ -x "$node_path" ] || fail "Node.js is unavailable"
package_name='@exochain/exochain-wasm'
version=0.2.6
integrity='sha512-Zml4dHVyZQ=='

expect_rejected() {
  local label="$1"
  local response="$2"
  if validate_npm_registry_response \
      "$response" "$package_name" "$version" "$integrity" "$node_path" \
      >/dev/null 2>&1; then
    fail "$label was accepted"
  fi
}

valid="$test_root/valid.json"
printf '{"name":"%s","version":"%s","dist":{"integrity":"%s"}}\n' \
  "$package_name" "$version" "$integrity" > "$valid"
validate_npm_registry_response \
  "$valid" "$package_name" "$version" "$integrity" "$node_path" \
  || fail "exact registry response was rejected"

duplicate="$test_root/duplicate.json"
printf '{"name":"@attacker/pkg","name":"%s","version":"%s","dist":{"integrity":"%s"}}\n' \
  "$package_name" "$version" "$integrity" > "$duplicate"
expect_rejected "duplicate npm identity key" "$duplicate"

escaped_duplicate="$test_root/escaped-duplicate.json"
printf '{"name":"@attacker/pkg","na\\u006de":"%s","version":"%s","dist":{"integrity":"%s"}}\n' \
  "$package_name" "$version" "$integrity" > "$escaped_duplicate"
expect_rejected "escaped duplicate npm identity key" "$escaped_duplicate"

wrong_integrity="$test_root/wrong-integrity.json"
printf '{"name":"%s","version":"%s","dist":{"integrity":"sha512-attacker"}}\n' \
  "$package_name" "$version" > "$wrong_integrity"
expect_rejected "wrong npm tarball integrity" "$wrong_integrity"

oversized="$test_root/oversized.json"
/usr/bin/python3 - "$oversized" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).write_bytes(b" " * (1024 * 1024 + 1))
PY
expect_rejected "oversized npm registry response" "$oversized"

symlink_response="$test_root/symlink.json"
/bin/ln -s "$valid" "$symlink_response"
expect_rejected "symlinked npm registry response" "$symlink_response"

hardlink_response="$test_root/hardlink.json"
/bin/ln "$valid" "$hardlink_response"
expect_rejected "hard-linked npm registry response" "$hardlink_response"

grep -F -- '--connect-timeout 15 --max-time 60 --max-filesize 1048576' "$publisher" >/dev/null \
  || fail "npm registry curl must have explicit connection, total-time, and byte limits"

printf 'npm registry validation test passed\n'
