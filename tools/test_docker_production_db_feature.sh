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

# Guard production container builds so deployed gateway paths compile with
# DB-backed adjudication instead of the default WO-009 deny-all scaffold.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "docker production-db feature test failed: $*" >&2
  exit 1
}

assert_file_contains() {
  local file="$1"
  local expected="$2"

  grep -Fq -- "$expected" "$file" || fail "$file must contain: $expected"
}

assert_exochain_build_enables_production_db() {
  local file="$1"

  if ! awk '
    /^RUN[[:space:]]+cargo build/ {
      command = $0
      while (command ~ /\\$/ && getline continuation) {
        sub(/\\$/, "", command)
        command = command " " continuation
      }
      if (command ~ /--bin[[:space:]]+exochain/) {
        found = 1
        if (command !~ /--features[[:space:]][^\\n]*exo-gateway\/production-db/) {
          bad = 1
        }
      }
    }
    END {
      if (!found || bad) {
        exit 1
      }
    }
  ' "$file"; then
    fail "$file must build exochain with --features exo-gateway/production-db"
  fi
}

assert_exochain_build_enables_production_db Dockerfile
assert_exochain_build_enables_production_db deploy/Dockerfile.node
assert_file_contains Dockerfile "--bin exo-gateway"

echo "docker production-db feature test passed"
