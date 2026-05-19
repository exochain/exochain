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
  printf 'agent workflow bound test failed: %s\n' "$1" >&2
  exit 1
}

require_file() {
  local path="$1"
  [ -f "$path" ] || fail "required file missing: $path"
}

require_pattern() {
  local path="$1"
  local pattern="$2"
  local description="$3"
  grep -Eq "$pattern" "$path" || fail "$path missing $description"
}

extract_positive_bound() {
  local path="$1"
  local bound
  bound="$(awk '
    /^[[:space:]]*max_iterations:[[:space:]]*[0-9]+[[:space:]]*$/ {
      value = $0
      sub(/^[^:]*:[[:space:]]*/, "", value)
      sub(/[[:space:]]*$/, "", value)
      print value
      exit
    }
  ' "$path")"

  [ -n "$bound" ] || fail "$path missing numeric max_iterations"
  [ "$bound" -ge 1 ] || fail "$path max_iterations must be at least 1"
  [ "$bound" -le 25 ] || fail "$path max_iterations must be 25 or lower"
}

require_file "AGENTS.md"
require_pattern "AGENTS.md" '^### Agent Workflow Loop Bounds$' "agent workflow loop-bound section"
require_pattern "AGENTS.md" 'max_iterations' "max_iterations rule"
require_pattern "AGENTS.md" 'stop condition' "stop-condition rule"
require_pattern "AGENTS.md" 'escalation path' "escalation-path rule"

for workflow in .archon/workflows/*.yaml; do
  require_file "$workflow"

  if grep -Eiq 'self-improvement|perpetual|continuous governance loop|recursive|autonomous' "$workflow"; then
    require_pattern "$workflow" '^[[:space:]]*loop:[[:space:]]*$' "loop block for recursive workflow"
    require_pattern "$workflow" '^[[:space:]]*enabled:[[:space:]]*true[[:space:]]*$' "enabled loop declaration"
    require_pattern "$workflow" '^[[:space:]]*max_iterations:[[:space:]]*[0-9]+[[:space:]]*$' "numeric max_iterations"
    require_pattern "$workflow" '^[[:space:]]*exit_condition:' "exit condition"
    require_pattern "$workflow" 'stop_conditions:' "stop_conditions list"
    require_pattern "$workflow" 'escalat' "escalation path"
    require_pattern "$workflow" 'same .*failure fingerprint.*twice' "repeated validation/remediation failure stop condition"
    extract_positive_bound "$workflow"
  fi
done

require_file ".github/workflows/ci.yml"
require_pattern ".github/workflows/ci.yml" 'bash tools/test_agent_prompt_boundaries\.sh' "agent prompt boundary CI gate"
require_pattern ".github/workflows/ci.yml" 'bash tools/test_agent_workflow_bounds\.sh' "agent workflow bound CI gate"

fix_issue_workflow=".archon/workflows/exochain-fix-issue-dag.yaml"
require_file "$fix_issue_workflow"
require_pattern "$fix_issue_workflow" "when: \"\\\$council_review\\.output\\.aggregate_disposition == 'Approved'\"" "approved-only council gate before fix node"
if grep -Fq "aggregate_disposition != 'Rejected'" "$fix_issue_workflow"; then
  fail "$fix_issue_workflow must not route Deferred or Requires-Amendment council outputs to code-writing nodes"
fi

printf 'agent workflow bound test passed\n'
