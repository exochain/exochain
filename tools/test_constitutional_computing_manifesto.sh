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

cd "$(dirname "$0")/.."

manifesto="docs/constitutional-computing/README.md"
index="docs/INDEX.md"

fail() {
  echo "constitutional computing manifesto test failed: $*" >&2
  exit 1
}

[ -f "$manifesto" ] || fail "manifesto document is required"

grep -q "Truth is not imported. Truth is adjudicated." "$manifesto" || {
  fail "manifesto must carry the core truth doctrine"
}

grep -q "constitutional synapse" "$manifesto" || {
  fail "manifesto must define the constitutional synapse"
}

grep -q "A signal is evidence, not authority." "$manifesto" || {
  fail "manifesto must reject signal-as-authority"
}

grep -q "signal -> classification -> reproduction -> failing test -> remediation -> verification -> review -> merge" "$manifesto" || {
  fail "manifesto must preserve the adjudication pipeline"
}

grep -q "No trust by proximity" "$manifesto" || {
  fail "manifesto must preserve the adjacent-surface boundary"
}

grep -q "bounded autonomy" "$manifesto" || {
  fail "manifesto must require bounded autonomous systems"
}

grep -q "separation of powers" "$manifesto" || {
  fail "manifesto must preserve separation of powers"
}

grep -q "consent before access" "$manifesto" || {
  fail "manifesto must require consent before access"
}

grep -q "provenance before trust" "$manifesto" || {
  fail "manifesto must require provenance before trust"
}

grep -q "Constitutional Computing" "$index" || {
  fail "docs index must link the Constitutional Computing movement artifact"
}

echo "constitutional computing manifesto test passed"
