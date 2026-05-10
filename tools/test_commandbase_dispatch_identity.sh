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

# Guard CommandBase's adjacent agent fleet against anonymous auto-spawned
# terminals. Each dispatched terminal must carry a stable identity envelope so
# agent actions remain attributable without expanding EXOCHAIN core trust.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "commandbase dispatch identity test failed: $*" >&2
  exit 1
}

assert_contains() {
  local file="$1"
  local expected="$2"

  grep -Fq -- "$expected" "$file" || fail "$file must contain: $expected"
}

assert_contains command-base/CLAUDE.md "per-dispatch identity assertion"
assert_contains command-base/CLAUDE.md "dispatch_id"
assert_contains command-base/CLAUDE.md "team_member_id"
assert_contains command-base/CLAUDE.md "task_assignment_id"
assert_contains command-base/CLAUDE.md "agent_passport_id"
assert_contains command-base/CLAUDE.md "actor_did"
assert_contains command-base/CLAUDE.md "spawn must fail closed"
assert_contains command-base/CLAUDE.md "shared Board, executive, or team identity"
assert_contains command-base/CLAUDE.md "does not make the adjacent CommandBase agent an EXOCHAIN core actor"

echo "commandbase dispatch identity test passed"
