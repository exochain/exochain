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
#
# Drives the real HPC-001 self-validator (tools/hpc001_self_validate.sh).
# Proves: canonical control path is GREEN; a mutated control missing a required
# needle is rejected (non-zero, no GREEN token).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "hpc001 self-validate test failed: $*" >&2
  exit 1
}

VALIDATOR="$ROOT/tools/hpc001_self_validate.sh"
CTRL="$ROOT/docs/superpowers/specs/2026-07-26-exochain-holographic-perfecting-control.md"
DELIVERY="$ROOT/docs/superpowers/plans/2026-07-16-df-protocol-001-delivery-map.md"
PROGRESS="$ROOT/.superpowers/sdd/progress.md"

[[ -x "$VALIDATOR" || -f "$VALIDATOR" ]] || fail "missing validator $VALIDATOR"
[[ -f "$CTRL" ]] || fail "missing control $CTRL"
[[ -f "$DELIVERY" ]] || fail "missing delivery map $DELIVERY"
[[ -f "$PROGRESS" ]] || fail "missing progress ledger $PROGRESS"

# --- Positive path: real control must GREEN ---
out="$(bash "$VALIDATOR" 2>&1)" || fail "validator exited non-zero on canonical control"
echo "$out" | rg -q 'hpc001_control_self_validation=GREEN' \
  || fail "canonical control did not print GREEN token"
echo "$out" | rg -q '^[0-9a-f]{64}  ' \
  || fail "canonical control output missing sha256 line"

# --- Binding: delivery map and ledger must reference HPC-001 ---
rg -q --fixed-strings 'HPC-001' "$DELIVERY" \
  || fail "delivery map does not bind HPC-001"
rg -q --fixed-strings 'exo.governance.holographic_perfecting_control.v1' "$DELIVERY" \
  || fail "delivery map missing domain string"
rg -q --fixed-strings 'ArtifactDelta' "$PROGRESS" \
  || fail "progress ledger missing ArtifactDelta"
rg -q --fixed-strings 'ControlDelta' "$PROGRESS" \
  || fail "progress ledger missing ControlDelta"
rg -q --fixed-strings 'NonClaimSet' "$PROGRESS" \
  || fail "progress ledger missing NonClaimSet"
rg -q --fixed-strings 'proof_of_ratchet' "$PROGRESS" \
  || fail "progress ledger missing proof_of_ratchet"

# --- Negative path: drive the same validator against a broken copy ---
tmp="$(mktemp "${TMPDIR:-/tmp}/hpc001-broken.XXXXXX.md")"
trap 'rm -f "$tmp"' EXIT
# Remove a required needle without re-implementing validation logic
python3 - "$CTRL" "$tmp" <<'PY'
from pathlib import Path
import sys
src = Path(sys.argv[1]).read_text()
# Drop one required identifier so the real validator must fail
src = src.replace("HPC-INV-1", "HPC-INV-REMOVED")
Path(sys.argv[2]).write_text(src)
PY

set +e
bad_out="$(bash "$VALIDATOR" "$tmp" 2>&1)"
bad_rc=$?
set -e
[[ "$bad_rc" -ne 0 ]] || fail "validator accepted control missing HPC-INV-1"
echo "$bad_out" | rg -q 'hpc001_control_self_validation=GREEN' \
  && fail "validator printed GREEN for broken control" || true

echo "test_hpc001_self_validate: ok"
