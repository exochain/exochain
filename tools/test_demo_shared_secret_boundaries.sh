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
  printf 'demo shared secret boundary test failed: %s\n' "$1" >&2
  exit 1
}

source_file="demo/packages/shared/src/index.js"
test_file="demo/packages/shared/src/index.test.js"

[[ -f "$source_file" ]] || fail "missing $source_file"
[[ -f "$test_file" ]] || fail "missing $test_file"

if grep -En 'postgres://[^[:space:]"'\'']+' "$source_file"; then
  fail "$source_file must not embed a PostgreSQL connection string fallback"
fi

if grep -En 'process\.env\.DATABASE_URL[[:space:]]*\|\|' "$source_file"; then
  fail "$source_file must fail closed instead of using an OR fallback for DATABASE_URL"
fi

node --test "$test_file"

printf 'demo shared secret boundary test passed\n'
