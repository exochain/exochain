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

consensus="crates/exo-dag/src/consensus.rs"

fail() {
  echo "consensus quorum formula docs test failed: $*" >&2
  exit 1
}

grep -q "quorum_size(n) = n - floor((n - 1) / 3)" "$consensus" || {
  fail "quorum_size docs must state the implemented formula"
}

grep -q "floor(2n / 3) + 1" "$consensus" || {
  fail "quorum_size docs must state equivalence to the strict >2/3 threshold"
}

grep -q "strictly greater than two thirds" "$consensus" || {
  fail "quorum_size docs must spell out the >2/3 threshold in words"
}

grep -q "n = 3k" "$consensus" || {
  fail "quorum_size docs must prove the n = 3k case"
}

grep -q "n = 3k + 1" "$consensus" || {
  fail "quorum_size docs must prove the n = 3k + 1 case"
}

grep -q "n = 3k + 2" "$consensus" || {
  fail "quorum_size docs must prove the n = 3k + 2 case"
}

grep -q "quorum_size_matches_strict_two_thirds_threshold_for_representative_validator_sets" "$consensus" || {
  fail "consensus tests must prove the formula across representative validator-set sizes"
}

echo "consensus quorum formula docs test passed"
