#!/usr/bin/env bash
# EXOCHAIN Repository Truth Generator
# Produces machine-verifiable facts about the repository state.
# Used to validate public claims in README.md and docs.
#
# Usage: bash tools/repo_truth.sh [--json] [--skip-tests|--list-tests|--run-tests]

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

JSON_MODE=false
TEST_MODE="list"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)
      JSON_MODE=true
      ;;
    --skip-tests)
      TEST_MODE="skip"
      ;;
    --list-tests)
      TEST_MODE="list"
      ;;
    --run-tests)
      TEST_MODE="run"
      ;;
    --help|-h)
      sed -n '1,12p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

# ── Counts ──
CRATE_COUNT=$(cargo metadata --no-deps --format-version 1 | jq '.packages | length')
RS_FILE_COUNT=$(git ls-files 'crates/**/*.rs' | wc -l | tr -d ' ')
RS_LOC=$(git ls-files 'crates/**/*.rs' | xargs wc -l | tail -1 | awk '{print $1}')
TLA_COUNT=$(git ls-files | grep -E '^tla/.*\.tla$' | wc -l | tr -d ' ')
CI_GATE_COUNT=$(grep -E 'name: "Gate [0-9]+' .github/workflows/ci.yml \
  | sed -E 's/.*Gate ([0-9]+).*/\1/' \
  | sort -n \
  | uniq \
  | wc -l \
  | tr -d ' ')

# ── Test inventory / result count ──
TESTS_LISTED=null
TESTS_PASSED=null
TESTS_FAILED=null
TEST_EXIT=0
TEST_MODE_LABEL=$TEST_MODE

case "$TEST_MODE" in
  skip)
    TEST_MODE_LABEL="skipped"
    ;;
  list)
    TEST_OUTPUT=$(cargo test --workspace -- --list 2>&1)
    TESTS_LISTED=$(printf '%s\n' "$TEST_OUTPUT" | grep -c ': test$' | tr -d ' ')
    ;;
  run)
    set +e
    TEST_OUTPUT=$(cargo test --workspace 2>&1)
    TEST_EXIT=$?
    set -e
    TESTS_PASSED=$(printf '%s\n' "$TEST_OUTPUT" | awk '/^test result:/ {sum+=$4} END {print sum+0}')
    TESTS_FAILED=$(printf '%s\n' "$TEST_OUTPUT" | awk '/^test result:/ {sum+=$6} END {print sum+0}')
    ;;
esac

count_status_rows() {
  local file=$1
  local marker=$2
  awk -F'|' -v marker="$marker" '
    /^\|/ {
      label = $2
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", label)
      if (label ~ /^(---|Spec|Req|Category)$/) {
        next
      }
      status = $(NF - 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", status)
      if (index(status, marker) == 1) {
        count += 1
      }
    }
    END { print count + 0 }
  ' "$file"
}

# ── Traceability ──
TRACE_GREEN=$(count_status_rows governance/traceability_matrix.md '🟢')
TRACE_YELLOW=$(count_status_rows governance/traceability_matrix.md '🟡')
TRACE_RED=$(count_status_rows governance/traceability_matrix.md '🔴')
TRACE_TOTAL=$((TRACE_GREEN + TRACE_YELLOW + TRACE_RED))

# ── Threat model ──
THREAT_GREEN=$(count_status_rows governance/threat_matrix.md '🟢')
THREAT_YELLOW=$(count_status_rows governance/threat_matrix.md '🟡')
THREAT_RED=$(count_status_rows governance/threat_matrix.md '🔴')
THREAT_TOTAL=$((THREAT_GREEN + THREAT_YELLOW + THREAT_RED))

# ── License ──
CARGO_LICENSE=$(grep '^license' Cargo.toml | head -1 | sed 's/license = "//;s/"//')
LICENSE_FILE=$(head -1 LICENSE 2>/dev/null || echo "MISSING")
README_LICENSE=$(grep -Eo 'Apache-2\.0|AGPL-3\.0|MIT' README.md | head -1 || true)
README_LICENSE=${README_LICENSE:-NONE}

# ── Release state ──
TAG_COUNT=$(git tag -l | wc -l | tr -d ' ')
HAS_CHANGELOG=$([[ -f CHANGELOG.md ]] && echo "true" || echo "false")
HAS_SECURITY=$([[ -f SECURITY.md ]] && echo "true" || echo "false")

# ── Supply chain integrity ──
HAS_SBOM_GATE=$(grep -c 'cargo-cyclonedx\|cargo cyclonedx' .github/workflows/ci.yml 2>/dev/null || echo 0)
HAS_SLSA_ATTEST=$(grep -c 'attest-build-provenance' .github/workflows/release.yml 2>/dev/null || echo 0)
HAS_DENY_CONFIG=$([[ -f deny.toml ]] && echo "true" || echo "false")

# ── Governance artifacts ──
RESOLUTION_COUNT=$(ls governance/resolutions/*.md 2>/dev/null | grep -v INDEX | wc -l | tr -d ' ')
GOVERNANCE_DOCS=$(ls governance/*.md 2>/dev/null | wc -l | tr -d ' ')

# ── Build checks (quick, no full rebuild) ──
FMT_OK=$(cargo +nightly fmt --all -- --check >/dev/null 2>&1 && echo "true" || echo "false")

# ── Output ──
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT=$(git rev-parse --short HEAD)

if $JSON_MODE; then
cat <<JEOF
{
  "timestamp": "$TIMESTAMP",
  "commit": "$COMMIT",
  "crates": $CRATE_COUNT,
  "rust_source_files": $RS_FILE_COUNT,
  "rust_loc": $RS_LOC,
  "tla_specs": $TLA_COUNT,
  "tests": { "mode": "$TEST_MODE_LABEL", "listed": $TESTS_LISTED, "passed": $TESTS_PASSED, "failed": $TESTS_FAILED, "exit_code": $TEST_EXIT },
  "tests_listed": $TESTS_LISTED,
  "tests_passed": $TESTS_PASSED,
  "tests_failed": $TESTS_FAILED,
  "ci_gates": { "numbered": $CI_GATE_COUNT, "required_aggregator": "All Constitutional Gates" },
  "traceability": { "implemented": $TRACE_GREEN, "partial": $TRACE_YELLOW, "planned": $TRACE_RED, "total": $TRACE_TOTAL },
  "threats": { "mitigated": $THREAT_GREEN, "partial": $THREAT_YELLOW, "planned": $THREAT_RED, "total": $THREAT_TOTAL },
  "license": { "cargo_toml": "$CARGO_LICENSE", "license_file": "$LICENSE_FILE", "readme": "$README_LICENSE" },
  "releases": { "tag_count": $TAG_COUNT, "has_changelog": $HAS_CHANGELOG, "has_security_md": $HAS_SECURITY },
  "governance": { "resolutions": $RESOLUTION_COUNT, "governance_docs": $GOVERNANCE_DOCS },
  "supply_chain": { "sbom_gate_configured": $HAS_SBOM_GATE, "slsa_attestation_configured": $HAS_SLSA_ATTEST, "deny_config_present": $HAS_DENY_CONFIG },
  "fmt_clean": $FMT_OK
}
JEOF
else
cat <<TEOF
EXOCHAIN Repository Truth — $TIMESTAMP (commit $COMMIT)
═══════════════════════════════════════════════════════

Crates:              $CRATE_COUNT
Rust source files:   $RS_FILE_COUNT
Rust LOC:            $RS_LOC
TLA+ specs:          $TLA_COUNT

Test mode:           $TEST_MODE_LABEL
Tests listed:        $TESTS_LISTED
Tests passed:        $TESTS_PASSED
Tests failed:        $TESTS_FAILED

CI gates:            $CI_GATE_COUNT numbered gate jobs + All Constitutional Gates aggregator

Traceability:        $TRACE_GREEN implemented / $TRACE_YELLOW partial / $TRACE_RED planned (of $TRACE_TOTAL)
Threats:             $THREAT_GREEN mitigated / $THREAT_YELLOW partial / $THREAT_RED planned (of $THREAT_TOTAL)

License (Cargo.toml):  $CARGO_LICENSE
License (LICENSE file): $LICENSE_FILE
License (README):       $README_LICENSE

Git tags:            $TAG_COUNT
CHANGELOG.md:        $HAS_CHANGELOG
SECURITY.md:         $HAS_SECURITY

Supply chain:
  SBOM gate (Gate 10):    $HAS_SBOM_GATE reference(s) in ci.yml
  SLSA attestation:       $HAS_SLSA_ATTEST reference(s) in release.yml
  deny.toml present:      $HAS_DENY_CONFIG

Resolutions:         $RESOLUTION_COUNT
Governance docs:     $GOVERNANCE_DOCS

Format clean:        $FMT_OK
TEOF
fi
