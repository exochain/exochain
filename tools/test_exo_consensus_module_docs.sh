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

readme="crates/exo-consensus/README.md"
lib="crates/exo-consensus/src/lib.rs"

fail() {
  echo "exo-consensus module docs test failed: $*" >&2
  exit 1
}

[ -f "$readme" ] || fail "crate README is required"

grep -q "^//!" "$lib" || fail "crate root must contain module-level Rust docs"
grep -q "Panel Confidence Index" "$lib" || fail "crate root docs must name the Panel Confidence Index"
grep -q "basis points" "$lib" || fail "crate root docs must document basis-point arithmetic"
grep -q "not BFT finality" "$lib" || fail "crate root docs must state the trust boundary"

grep -q "Panel Confidence Index" "$readme" || fail "README must document the Panel Confidence Index"
grep -q "50% model agreement" "$readme" || fail "README must document the agreement weight"
grep -q "30% convergence speed" "$readme" || fail "README must document the speed weight"
grep -q "20% devil's advocate" "$readme" || fail "README must document the advocate weight"
grep -q "basis points" "$readme" || fail "README must document basis-point scoring"
grep -q "minority reports reduce the agreement component" "$readme" || fail "README must document minority-report PCI treatment"
grep -q "no floating-point arithmetic" "$readme" || fail "README must document deterministic arithmetic constraints"
grep -q "not BFT finality" "$readme" || fail "README must state the trust boundary"

echo "exo-consensus module docs test passed"
