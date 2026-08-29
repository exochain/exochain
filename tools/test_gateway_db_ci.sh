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

fail() {
  printf 'gateway DB CI test failed: %s\n' "$1" >&2
  exit 1
}

workflow=".github/workflows/ci.yml"
[[ -f "$workflow" ]] || fail "$workflow is missing"

node_store="crates/exo-node/src/store/store_postgres.rs"
[[ -f "$node_store" ]] || fail "$node_store is missing"

job_block() {
  local job_name="$1"
  awk -v job_name="$job_name" '
    $0 == "  " job_name ":" {
      in_job = 1
    }
    in_job && $0 ~ /^  [[:alnum:]_-]+:$/ && $0 != "  " job_name ":" {
      exit
    }
    in_job {
      print
    }
  ' "$workflow"
}

test_job="$(job_block test)"
db_job="$(job_block integration-tests-db)"

[[ -n "$test_job" ]] || fail "Gate 2 test job is missing"
[[ -n "$db_job" ]] || fail "Gate 13 integration-tests-db job is missing"

if grep -F 'DATABASE_URL' <<<"$test_job" >/dev/null; then
  fail "Gate 2 must remain environment-free; live PostgreSQL belongs in Gate 13"
fi

grep -F '#[ignore = "requires live PostgreSQL; mandatory in CI Gate 13"]' "$node_store" >/dev/null \
  || fail "malformed-row regression must be explicitly isolated from environment-free suites"

grep -F 'async fn postgres_malformed_rows_return_typed_errors()' "$node_store" >/dev/null \
  || fail "malformed-row regression test is missing"

grep -F '.expect("DATABASE_URL is required for postgres_malformed_rows_return_typed_errors")' "$node_store" >/dev/null \
  || fail "malformed-row regression must fail closed when DATABASE_URL is absent"

grep -F -- 'cargo test -p exochain-node --bin exochain' <<<"$db_job" >/dev/null \
  || fail "Gate 13 must target the exochain binary test harness"

grep -F 'store::store_postgres::tests::postgres_malformed_rows_return_typed_errors' <<<"$db_job" >/dev/null \
  || fail "Gate 13 must name the fully qualified malformed-row regression"

grep -F -- '-- --exact --ignored --nocapture --test-threads=1' <<<"$db_job" >/dev/null \
  || fail "Gate 13 must run exactly the ignored malformed-row regression serially"

grep -F "test result: ok. 1 passed; 0 failed; 0 ignored;" <<<"$db_job" >/dev/null \
  || fail "Gate 13 must assert that exactly one malformed-row regression executed"

grep -F 'DATABASE_URL: postgres://exochain:test@localhost:5432/exochain_test' <<<"$db_job" >/dev/null \
  || fail "Gate 13 must run with an explicit live PostgreSQL DATABASE_URL"

grep -F 'cargo test -p exochain-gateway --lib --features production-db' <<<"$db_job" >/dev/null \
  || fail "Gate 13 must run exo-gateway DB-backed library tests"

grep -F 'EXO_DAGDB_TEST_DATABASE_URL: ${{ env.DATABASE_URL }}' <<<"$db_job" >/dev/null \
  || fail "Gate 13 must pass its live PostgreSQL URL to DAG DB migration regressions"

grep -F 'cargo test -p exochain-dag-db-postgres --features postgres --test migration_contract pr708_migrator_upgrades_from_last_successful_deployed_ledger' <<<"$db_job" >/dev/null \
  || fail "Gate 13 must run the DAG DB PR #708 upgrade regression"

grep -F -- '--test-threads=1' <<<"$db_job" >/dev/null \
  || fail "DB-backed gateway library tests must run serially against the shared CI database"

grep -F "cargo test --workspace --test '*' --features exochain-gateway/production-db" <<<"$db_job" >/dev/null \
  || fail "Gate 13 must retain workspace DB-backed integration tests"

printf 'gateway DB CI test passed\n'
