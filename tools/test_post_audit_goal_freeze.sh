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

cd "$(git rev-parse --show-toplevel)"

goal_record="docs/audit/POST-AUDIT-FROZEN-GOAL-2026-07-08.md"
plan_record="docs/audit/POST-AUDIT-IMPLEMENTATION-PLAN-2026-07-08.md"
audit_record="docs/audit/WHOLE-SYSTEM-AUDIT-2026-07-08.md"

fail() {
  printf 'post-audit goal freeze test failed: %s\n' "$1" >&2
  exit 1
}

require_file() {
  local path="$1"
  [ -f "$path" ] || fail "missing required file: $path"
}

require_pattern() {
  local path="$1"
  local pattern="$2"
  local description="$3"
  grep -Eq "$pattern" "$path" || fail "$path missing $description"
}

require_file "$audit_record"
require_file "$plan_record"
require_file "$goal_record"

require_pattern "$goal_record" '^# Post-Audit Frozen System Goal - 2026-07-08$' "canonical title"
require_pattern "$goal_record" '^## System-Level Goal$' "system-level goal section"
require_pattern "$goal_record" '^## Non-Negotiable Acceptance Criteria$' "non-negotiable acceptance criteria section"
require_pattern "$goal_record" '^## Surface Classification Boundary$' "surface classification boundary section"
require_pattern "$goal_record" '^## Claim Boundaries$' "claim boundaries section"
require_pattern "$goal_record" '^## Evidence Required Before Success Claims$' "evidence requirements section"
require_pattern "$goal_record" '^## Requirement Change Process$' "requirement change process section"

require_pattern "$goal_record" 'EXOCHAIN core' "EXOCHAIN core classification"
require_pattern "$goal_record" 'Core runtime adapter' "core runtime adapter classification"
require_pattern "$goal_record" 'Adjacent surface' "adjacent surface classification"
require_pattern "$goal_record" 'Imported evidence' "imported evidence classification"
require_pattern "$goal_record" 'Third-party/vendor' "third-party/vendor classification"

require_pattern "$goal_record" 'must not claim.*production-ready|must not claim.*goal-ready|must not claim.*end-to-end achieved' "explicit forbidden success claim boundary"
require_pattern "$goal_record" 'tests, command output, release artifacts, deployment evidence, or reviewer evidence' "direct evidence requirement"
require_pattern "$goal_record" 'requirement-change proposal' "requirement-change proposal rule"

require_pattern "$plan_record" 'Slice 1: Goal Freeze and Surface Classification' "Slice 1 plan reference"
require_pattern "$plan_record" "$goal_record" "goal record path reference"
require_pattern "$audit_record" 'Strict inferred system-level goal' "audit goal source"

printf 'post-audit goal freeze test passed\n'
