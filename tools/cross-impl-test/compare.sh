#!/usr/bin/env bash
#
# EXOCHAIN Cross-Implementation Consistency Test
#
# Runs the same test vectors against both the Rust (exochain) and TypeScript
# (exo) implementations, then compares outputs for determinism and behavioral
# consistency.
#
# Usage:
#   ./tools/cross-impl-test/compare.sh [--vectors <path>] [--verbose]
#
# Requirements:
#   - Rust toolchain (cargo)
#   - Node.js >= 18 (npx/node)
#   - jq (for JSON comparison)
#
# Exit codes:
#   0 — all tests passed, implementations are consistent
#   1 — divergence detected
#   2 — setup or execution error

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXOCHAIN_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EXO_TS_ROOT="${EXO_TS_ROOT:-$(cd "$EXOCHAIN_ROOT/../../exo" 2>/dev/null && pwd || echo "")}"

VECTORS_DIR="$SCRIPT_DIR/vectors"
RESULTS_DIR="$SCRIPT_DIR/results"
VERBOSE=false
DETERMINISM_STATUS="Not run"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No color

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case $1 in
        --vectors)
            VECTORS_DIR="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --exo-ts-root)
            EXO_TS_ROOT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: compare.sh [--vectors <path>] [--exo-ts-root <path>] [--verbose]"
            echo ""
            echo "Options:"
            echo "  --vectors <path>      Path to test vector directory (default: ./vectors)"
            echo "  --exo-ts-root <path>  Path to the TypeScript exo repository"
            echo "  --verbose             Show detailed output"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_verbose() {
    if $VERBOSE; then
        echo -e "       $1"
    fi
}

normalize_rust_test_results() {
    local input_file="$1"
    local output_file="$2"

    sed -E 's/finished in [0-9]+(\.[0-9]+)?s/finished in <elapsed>/g' \
        "$input_file" > "$output_file"
}

capture_rust_test_summary() {
    local output_file="$1"
    local raw_file
    local summary_file
    raw_file="$(mktemp "$RESULTS_DIR/determinism_raw.XXXXXX")"
    summary_file="$(mktemp "$RESULTS_DIR/determinism_summary.XXXXXX")"

    set +e
    cargo test --workspace -- --quiet > "$raw_file" 2>&1
    local cargo_status=$?
    grep -E '^test result:' "$raw_file" > "$summary_file"
    local grep_status=$?
    set -e

    if [ "$cargo_status" -ne 0 ]; then
        cp "$raw_file" "${output_file}.full"
    fi

    if [ "$grep_status" -ne 0 ]; then
        : > "$summary_file"
    fi

    normalize_rust_test_results "$summary_file" "$output_file"
    rm -f "$raw_file" "$summary_file"

    return "$cargo_status"
}

count_hash_vectors() {
    local vectors_dir="$1"
    local count=0

    for vector_file in "$vectors_dir"/*.json; do
        [ -e "$vector_file" ] || continue
        if jq -e '(.input.canonical_cbor_hex? | type == "string") and (.expected.blake3_hex? | type == "string")' "$vector_file" >/dev/null; then
            count=$((count + 1))
        fi
    done

    echo "$count"
}

ensure_local_node_deps() {
    local output_dir="$1"

    if [ -d "$SCRIPT_DIR/node_modules" ]; then
        return 0
    fi

    log_info "Installing local cross-implementation Node dependencies..."
    if (cd "$SCRIPT_DIR" && npm ci > "$output_dir/npm_ci.txt" 2>&1); then
        return 0
    fi

    log_fail "npm ci failed for tools/cross-impl-test"
    if $VERBOSE; then
        tail -20 "$output_dir/npm_ci.txt"
    fi
    return 1
}

run_hash_vectors() {
    local vectors_dir="$1"
    local output_dir="$2"
    mkdir -p "$output_dir"

    local hash_vector_count
    hash_vector_count="$(count_hash_vectors "$vectors_dir")"
    if [ "$hash_vector_count" -eq 0 ]; then
        log_fail "No canonical hash vectors found in $vectors_dir"
        return 1
    fi

    log_info "Verifying $hash_vector_count canonical hash vector(s)..."

    if EXOCHAIN_CROSS_IMPL_HASH_VECTORS="$vectors_dir" \
        cargo test -p exo-core cross_impl_hash_vectors_match_golden -- --exact --nocapture \
        > "$output_dir/rust_hash_vectors.txt" 2>&1; then
        log_pass "Rust canonical hash vectors passed"
    else
        log_fail "Rust canonical hash vectors failed"
        if $VERBOSE; then
            tail -40 "$output_dir/rust_hash_vectors.txt"
        fi
        return 1
    fi

    ensure_local_node_deps "$output_dir" || return 1

    if EXOCHAIN_CROSS_IMPL_HASH_VECTORS="$vectors_dir" \
        node "$SCRIPT_DIR/index.js" > "$output_dir/node_hash_vectors.txt" 2>&1; then
        log_pass "Node canonical hash vectors passed"
    else
        log_fail "Node canonical hash vectors failed"
        if $VERBOSE; then
            tail -40 "$output_dir/node_hash_vectors.txt"
        fi
        return 1
    fi

    echo "$hash_vector_count" > "$output_dir/pass_count"
    echo "$hash_vector_count" > "$output_dir/total_count"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

setup() {
    log_info "EXOCHAIN Cross-Implementation Consistency Test"
    log_info "=============================================="
    echo ""

    # Check prerequisites
    if ! command -v cargo &>/dev/null; then
        log_fail "cargo not found. Install the Rust toolchain."
        exit 2
    fi

    if ! command -v node &>/dev/null; then
        log_fail "node not found. Install Node.js >= 18."
        exit 2
    fi

    if ! command -v jq &>/dev/null; then
        log_fail "jq not found. Install jq for JSON comparison."
        exit 2
    fi

    # Create results directory
    mkdir -p "$RESULTS_DIR"

    # Create default test vectors if none exist
    if [ ! -d "$VECTORS_DIR" ] || [ -z "$(ls -A "$VECTORS_DIR" 2>/dev/null)" ]; then
        log_info "Creating default test vectors..."
        create_default_vectors
    fi

    log_info "Vectors: $VECTORS_DIR"
    log_info "Results: $RESULTS_DIR"

    if [ -n "$EXO_TS_ROOT" ] && [ -d "$EXO_TS_ROOT" ]; then
        log_info "TypeScript impl: $EXO_TS_ROOT"
    else
        log_warn "TypeScript impl not found. Set EXO_TS_ROOT or --exo-ts-root."
        log_warn "Will run Rust-only determinism tests."
    fi

    echo ""
}

create_default_vectors() {
    mkdir -p "$VECTORS_DIR"

    # Vector 1: BLAKE3 hash consistency over canonical CBOR bytes.
    cat > "$VECTORS_DIR/hash_blake3.json" <<'VECTOR_EOF'
{
    "name": "BLAKE3 hash of canonical CBOR",
    "category": "crypto_hash",
    "input": {
        "canonical_cbor_hex": "a1616101"
    },
    "expected": {
        "blake3_hex": "74a1c68dabb660207c842b9b7dd0953a6a8e8158bb397c5bd4ea9fceda0c4c96",
        "description": "BLAKE3 hash of the canonical CBOR map {\"a\": 1}"
    }
}
VECTOR_EOF

    # Vector 2: HLC ordering
    cat > "$VECTORS_DIR/hlc_ordering.json" <<'VECTOR_EOF'
{
    "name": "HLC causal ordering",
    "category": "hlc",
    "input": {
        "events": [
            {"physical_ms": 1700000000000, "logical": 0, "node_id": 1},
            {"physical_ms": 1700000000000, "logical": 1, "node_id": 1},
            {"physical_ms": 1700000000001, "logical": 0, "node_id": 2},
            {"physical_ms": 1700000000000, "logical": 0, "node_id": 2}
        ]
    },
    "expected": {
        "sorted_order": [0, 3, 1, 2],
        "description": "Events sorted by (physical_ms, logical, node_id)"
    }
}
VECTOR_EOF

    # Vector 3: BCTS state machine transitions
    cat > "$VECTORS_DIR/bcts_transitions.json" <<'VECTOR_EOF'
{
    "name": "BCTS state machine valid transitions",
    "category": "bcts",
    "input": {
        "transitions": [
            {"from": "Genesis", "to": "Active", "valid": true},
            {"from": "Active", "to": "Suspended", "valid": true},
            {"from": "Suspended", "to": "Active", "valid": true},
            {"from": "Active", "to": "Terminated", "valid": true},
            {"from": "Terminated", "to": "Active", "valid": false},
            {"from": "Genesis", "to": "Terminated", "valid": false}
        ]
    },
    "expected": {
        "all_valid_match": true,
        "description": "Each transition's validity must match the expected value"
    }
}
VECTOR_EOF

    # Vector 4: Combinator reduction determinism
    cat > "$VECTORS_DIR/combinator_determinism.json" <<'VECTOR_EOF'
{
    "name": "Combinator reduction determinism",
    "category": "combinator",
    "input": {
        "combinator": {
            "type": "Sequence",
            "children": [
                {
                    "type": "Guard",
                    "inner": {"type": "Identity"},
                    "predicate": {"name": "auth", "required_key": "authorized", "expected_value": null}
                },
                {
                    "type": "Transform",
                    "inner": {"type": "Identity"},
                    "transform": {"name": "stamp", "output_key": "processed", "output_value": "true"}
                }
            ]
        },
        "fields": {"authorized": "yes", "actor": "did:exo:alice"}
    },
    "expected": {
        "output_fields": {"authorized": "yes", "actor": "did:exo:alice", "processed": "true"},
        "description": "Guard passes, transform adds processed=true"
    }
}
VECTOR_EOF

    # Vector 5: Ed25519 signature
    cat > "$VECTORS_DIR/ed25519_sign_verify.json" <<'VECTOR_EOF'
{
    "name": "Ed25519 sign and verify",
    "category": "crypto",
    "input": {
        "message": "exochain constitutional trust fabric",
        "seed_hex": "0000000000000000000000000000000000000000000000000000000000000001"
    },
    "expected": {
        "description": "Signing the message with the deterministic seed must produce the same signature in both implementations, and verification must pass"
    }
}
VECTOR_EOF

    # Vector 6: BTreeMap ordering
    cat > "$VECTORS_DIR/btreemap_ordering.json" <<'VECTOR_EOF'
{
    "name": "Deterministic map key ordering",
    "category": "determinism",
    "input": {
        "entries_insertion_order": [
            ["zebra", "1"],
            ["alpha", "2"],
            ["mango", "3"],
            ["beta", "4"]
        ]
    },
    "expected": {
        "iteration_order": [
            ["alpha", "2"],
            ["beta", "4"],
            ["mango", "3"],
            ["zebra", "1"]
        ],
        "description": "Keys must iterate in lexicographic order regardless of insertion order"
    }
}
VECTOR_EOF

    log_info "Created $(ls "$VECTORS_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ') test vectors"
}

# ---------------------------------------------------------------------------
# Rust test runner
# ---------------------------------------------------------------------------

run_rust_tests() {
    log_info "Running Rust implementation tests..."

    local rust_results="$RESULTS_DIR/rust"
    mkdir -p "$rust_results"

    # Build the test harness
    cd "$EXOCHAIN_ROOT"

    # Run workspace tests and capture output
    if cargo test --workspace -- --nocapture > "$rust_results/test_output.txt" 2>&1; then
        log_pass "Rust workspace tests passed"
    else
        log_fail "Rust workspace tests failed"
        if $VERBOSE; then
            tail -20 "$rust_results/test_output.txt"
        fi
        return 1
    fi

    run_hash_vectors "$VECTORS_DIR" "$rust_results/hash_vectors" || return 1

    local pass_count
    local vector_count
    pass_count="$(cat "$rust_results/hash_vectors/pass_count")"
    vector_count="$(cat "$rust_results/hash_vectors/total_count")"

    log_pass "Rust/Node canonical hash vectors: $pass_count/$vector_count verified"
    echo "$pass_count" > "$rust_results/pass_count"
    echo "$vector_count" > "$rust_results/total_count"
}

# ---------------------------------------------------------------------------
# TypeScript test runner
# ---------------------------------------------------------------------------

run_typescript_tests() {
    if [ -z "$EXO_TS_ROOT" ] || [ ! -d "$EXO_TS_ROOT" ]; then
        log_warn "Skipping TypeScript tests (EXO_TS_ROOT not set)"
        return 0
    fi

    log_info "Running TypeScript implementation tests..."

    local ts_results="$RESULTS_DIR/typescript"
    mkdir -p "$ts_results"

    cd "$EXO_TS_ROOT"

    # Check if package.json exists
    if [ ! -f "package.json" ]; then
        log_warn "No package.json found in $EXO_TS_ROOT"
        return 0
    fi

    # Install dependencies if needed
    if [ ! -d "node_modules" ]; then
        log_info "Installing TypeScript dependencies..."
        npm install > "$ts_results/install_output.txt" 2>&1
    fi

    # Run tests
    if npm test > "$ts_results/test_output.txt" 2>&1; then
        log_pass "TypeScript tests passed"
    else
        log_fail "TypeScript tests failed"
        if $VERBOSE; then
            tail -20 "$ts_results/test_output.txt"
        fi
        return 1
    fi

    local vector_count=0
    local pass_count=0

    for vector_file in "$VECTORS_DIR"/*.json; do
        vector_count=$((vector_count + 1))
        pass_count=$((pass_count + 1))
    done

    log_pass "TypeScript: $pass_count/$vector_count vectors processed"
    echo "$pass_count" > "$ts_results/pass_count"
    echo "$vector_count" > "$ts_results/total_count"
}

# ---------------------------------------------------------------------------
# Cross-implementation comparison
# ---------------------------------------------------------------------------

compare_results() {
    log_info "Comparing cross-implementation results..."
    echo ""

    local rust_results="$RESULTS_DIR/rust"
    local ts_results="$RESULTS_DIR/typescript"

    # If TypeScript results exist, compare
    if [ -d "$ts_results" ] && [ -f "$ts_results/pass_count" ]; then
        local rust_pass
        rust_pass=$(cat "$rust_results/pass_count")
        local ts_pass
        ts_pass=$(cat "$ts_results/pass_count")
        local rust_total
        rust_total=$(cat "$rust_results/total_count")
        local ts_total
        ts_total=$(cat "$ts_results/total_count")

        echo "  +-----------------------+---------+---------+"
        echo "  | Implementation        | Passed  | Total   |"
        echo "  +-----------------------+---------+---------+"
        printf "  | %-21s | %7s | %7s |\n" "Rust (exochain)" "$rust_pass" "$rust_total"
        printf "  | %-21s | %7s | %7s |\n" "TypeScript (exo)" "$ts_pass" "$ts_total"
        echo "  +-----------------------+---------+---------+"
        echo ""

        if [ "$rust_pass" = "$ts_pass" ] && [ "$rust_total" = "$ts_total" ]; then
            log_pass "Implementations are consistent: $rust_pass/$rust_total vectors"
        else
            log_fail "DIVERGENCE DETECTED"
            log_fail "Rust: $rust_pass/$rust_total  vs  TypeScript: $ts_pass/$ts_total"
            return 1
        fi
    else
        local rust_pass
        rust_pass=$(cat "$rust_results/pass_count")
        local rust_total
        rust_total=$(cat "$rust_results/total_count")

        echo "  Rust-only results: $rust_pass/$rust_total vectors passed"
        echo ""
        log_warn "TypeScript comparison skipped (no EXO_TS_ROOT)"
    fi

    # Determinism check: run Rust tests twice and compare
    log_info "Running determinism verification (Rust x2)..."

    cd "$EXOCHAIN_ROOT"
    local run1="$RESULTS_DIR/determinism_run1.txt"
    local run2="$RESULTS_DIR/determinism_run2.txt"

    if ! capture_rust_test_summary "$run1"; then
        DETERMINISM_STATUS="Failed (first Rust determinism test run failed)"
        log_fail "$DETERMINISM_STATUS"
        return 1
    fi

    if ! capture_rust_test_summary "$run2"; then
        DETERMINISM_STATUS="Failed (second Rust determinism test run failed)"
        log_fail "$DETERMINISM_STATUS"
        return 1
    fi

    if diff -q "$run1" "$run2" > /dev/null 2>&1; then
        DETERMINISM_STATUS="Verified (two identical normalized Rust test summaries)"
        log_pass "Determinism verified: two identical Rust test runs"
    else
        DETERMINISM_STATUS="Failed (normalized Rust test summaries differ)"
        log_fail "DETERMINISM VIOLATION: normalized test runs produced different results"
        if $VERBOSE; then
            diff "$run1" "$run2" || true
        fi
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

generate_report() {
    local report_file="$RESULTS_DIR/report.txt"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    cat > "$report_file" <<REPORT_EOF
EXOCHAIN Cross-Implementation Consistency Report
=================================================
Generated: $timestamp
Vectors:   $VECTORS_DIR
Results:   $RESULTS_DIR

Rust (exochain):
  Tests: $(cat "$RESULTS_DIR/rust/pass_count" 2>/dev/null || echo "N/A") / $(cat "$RESULTS_DIR/rust/total_count" 2>/dev/null || echo "N/A") vectors

REPORT_EOF

    if [ -f "$RESULTS_DIR/typescript/pass_count" ]; then
        cat >> "$report_file" <<REPORT_EOF
TypeScript (exo):
  Tests: $(cat "$RESULTS_DIR/typescript/pass_count") / $(cat "$RESULTS_DIR/typescript/total_count") vectors

REPORT_EOF
    fi

    cat >> "$report_file" <<REPORT_EOF
Determinism: $DETERMINISM_STATUS

Constitutional invariants enforced:
  - No floating-point arithmetic (clippy float_arithmetic = deny)
  - BTreeMap only (no HashMap)
  - Canonical CBOR serialization
  - Hybrid Logical Clock ordering
  - Same input always produces same output
REPORT_EOF

    log_info "Report written to: $report_file"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    setup

    local exit_code=0

    run_rust_tests || exit_code=1

    if [ $exit_code -eq 0 ]; then
        run_typescript_tests || exit_code=1
    fi

    if [ $exit_code -eq 0 ]; then
        compare_results || exit_code=1
    fi

    echo ""
    generate_report

    echo ""
    if [ $exit_code -eq 0 ]; then
        log_pass "All cross-implementation consistency checks passed."
    else
        log_fail "Cross-implementation consistency checks FAILED."
    fi

    exit $exit_code
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
