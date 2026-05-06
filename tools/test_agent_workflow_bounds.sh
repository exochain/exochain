#!/usr/bin/env bash
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
    extract_positive_bound "$workflow"
  fi
done

require_file ".github/workflows/ci.yml"
require_pattern ".github/workflows/ci.yml" 'bash tools/test_agent_prompt_boundaries\.sh' "agent prompt boundary CI gate"
require_pattern ".github/workflows/ci.yml" 'bash tools/test_agent_workflow_bounds\.sh' "agent workflow bound CI gate"

printf 'agent workflow bound test passed\n'
