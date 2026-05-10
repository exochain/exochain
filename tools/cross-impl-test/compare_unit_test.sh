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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/compare.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cat > "$TMP_DIR/run1.txt" <<'EOF'
test result: ok. 45 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.36s
test result: ok. 149 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 63.51s
EOF

cat > "$TMP_DIR/run2.txt" <<'EOF'
test result: ok. 45 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.35s
test result: ok. 149 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 62.62s
EOF

normalize_rust_test_results "$TMP_DIR/run1.txt" "$TMP_DIR/run1.normalized"
normalize_rust_test_results "$TMP_DIR/run2.txt" "$TMP_DIR/run2.normalized"
diff -u "$TMP_DIR/run1.normalized" "$TMP_DIR/run2.normalized"

cat > "$TMP_DIR/run3.txt" <<'EOF'
test result: ok. 44 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.35s
test result: ok. 149 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 62.62s
EOF

normalize_rust_test_results "$TMP_DIR/run3.txt" "$TMP_DIR/run3.normalized"
if diff -q "$TMP_DIR/run1.normalized" "$TMP_DIR/run3.normalized" > /dev/null; then
    echo "normalization masked a substantive test-count difference" >&2
    exit 1
fi

RESULTS_DIR="$TMP_DIR/results"
VECTORS_DIR="$TMP_DIR/vectors"
DETERMINISM_STATUS="Failed (normalized Rust test summaries differ)"
mkdir -p "$RESULTS_DIR/rust" "$VECTORS_DIR"
printf '6\n' > "$RESULTS_DIR/rust/pass_count"
printf '6\n' > "$RESULTS_DIR/rust/total_count"

generate_report
grep -F "Determinism: Failed (normalized Rust test summaries differ)" \
    "$RESULTS_DIR/report.txt" > /dev/null

declare -F run_hash_vectors > /dev/null || {
    echo "run_hash_vectors function missing" >&2
    exit 1
}

HASH_RESULTS="$TMP_DIR/hash-results"
GOOD_VECTORS="$TMP_DIR/good-hash-vectors"
BAD_VECTORS="$TMP_DIR/bad-hash-vectors"
mkdir -p "$HASH_RESULTS" "$GOOD_VECTORS" "$BAD_VECTORS"

cat > "$GOOD_VECTORS/hash_blake3.json" <<'EOF'
{
  "name": "BLAKE3 hash of canonical CBOR",
  "category": "crypto_hash",
  "input": {
    "canonical_cbor_hex": "a1616101"
  },
  "expected": {
    "blake3_hex": "74a1c68dabb660207c842b9b7dd0953a6a8e8158bb397c5bd4ea9fceda0c4c96"
  }
}
EOF

run_hash_vectors "$GOOD_VECTORS" "$HASH_RESULTS/good"

cat > "$BAD_VECTORS/hash_blake3.json" <<'EOF'
{
  "name": "BLAKE3 hash rejects incorrect expected output",
  "category": "crypto_hash",
  "input": {
    "canonical_cbor_hex": "a1616101"
  },
  "expected": {
    "blake3_hex": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
EOF

set +e
run_hash_vectors "$BAD_VECTORS" "$HASH_RESULTS/bad"
bad_status=$?
set -e

if [ "$bad_status" -eq 0 ]; then
    echo "bad canonical hash vector unexpectedly passed" >&2
    exit 1
fi

if grep -nE 'for now|would invoke|placeholder' "$SCRIPT_DIR/compare.sh"; then
    echo "cross-implementation harness must not describe unimplemented vector runners as passing" >&2
    exit 1
fi
