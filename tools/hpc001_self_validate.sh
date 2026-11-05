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
# Deterministic self-validation for HPC-001
# (exo.governance.holographic_perfecting_control.v1).
# Optional arg: path to control document (default: repo canonical path).

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${ROOT}" ]]; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi
cd "$ROOT"

CTRL="${1:-$ROOT/docs/superpowers/specs/2026-07-26-exochain-holographic-perfecting-control.md}"

if [[ ! -f "$CTRL" ]]; then
  echo "missing control document: $CTRL" >&2
  exit 1
fi

for needle in \
  HPC-001 \
  exo.governance.holographic_perfecting_control.v1 \
  ArtifactDelta \
  ControlDelta \
  NonClaimSet \
  HPC-INV-1 \
  HPC-INV-2 \
  HPC-INV-3 \
  HPC-INV-4 \
  HPC-INV-5 \
  constitutional_ratification_truth \
  publication_truth \
  max_iterations \
  proof_of_ratchet
do
  if ! rg -q --fixed-strings "$needle" "$CTRL"; then
    echo "missing $needle" >&2
    exit 1
  fi
done

if rg -n 'destination perfectionism is the goal|stop improving after GREEN' "$CTRL"; then
  echo "forbidden destination-perfection claim" >&2
  exit 1
fi

python3 - "$CTRL" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text()
markers = sum(1 for line in text.splitlines() if line.strip().startswith("`" * 3))
if markers % 2 != 0:
    raise SystemExit(f"unbalanced fences markers={markers}")
print("fences_ok")
PY

echo "hpc001_control_self_validation=GREEN"
shasum -a 256 "$CTRL"
