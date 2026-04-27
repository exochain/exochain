#!/usr/bin/env bash
# Guard GAP-REGISTRY.md and closed GAP ULTRAPLANs against stale closure claims.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "GAP registry truth test failed: $*" >&2
  exit 1
}

assert_contains() {
  local file=$1
  local pattern=$2
  if ! grep -Eq "$pattern" "$file"; then
    fail "$file missing required pattern: $pattern"
  fi
}

assert_lacks() {
  local file=$1
  local pattern=$2
  if grep -nE "$pattern" "$file"; then
    fail "$file contains forbidden pattern: $pattern"
  fi
}

ultraplan_count=$(find gap -maxdepth 1 -name 'ULTRAPLAN-*.md' | wc -l | tr -d ' ')

assert_contains GAP-REGISTRY.md "\\*\\*Current ULTRAPLAN files:\\*\\* $ultraplan_count"
assert_contains GAP-REGISTRY.md "Basalt reconciliation"
assert_contains GAP-REGISTRY.md "GAP-004.*Onyx-4 remediation PRs #117-#124"
assert_contains GAP-REGISTRY.md "GAP-011.*feature-gated unaudited axes"

assert_contains gap/ULTRAPLAN-GAP-002-EVIDENCE-BUNDLE.md "verify_with_signer_keys"
assert_lacks gap/ULTRAPLAN-GAP-002-EVIDENCE-BUNDLE.md \
  "placeholder for full cryptographic verification|Production systems will resolve signer DIDs|signature is non-empty"

assert_lacks GAP-REGISTRY.md "GAP-002:[^\\n]*16 tests|GAP-002:[^\\n]*offline-verifiable signatures"

echo "GAP registry truth test passed"
