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

# Guard deployment contracts against probing the liveness-only /health route.
# Production rollout checks must use /ready so dependency failures stop deploys.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "deployment readiness probe test failed: $*" >&2
  exit 1
}

assert_file_contains() {
  local file="$1"
  local expected="$2"

  grep -Fq -- "$expected" "$file" || fail "$file must contain: $expected"
}

assert_healthcheck_uses_ready() {
  local file="$1"

  assert_file_contains "$file" "HEALTHCHECK"
  assert_file_contains "$file" "/ready"

  if awk '
    /HEALTHCHECK/ { in_healthcheck = 1 }
    in_healthcheck && /\/health/ { found = 1 }
    in_healthcheck && !/\\$/ && /exit 1/ { in_healthcheck = 0 }
    END { exit found ? 0 : 1 }
  ' "$file"; then
    fail "$file HEALTHCHECK must not probe /health"
  fi
}

assert_healthcheck_uses_ready Dockerfile
assert_healthcheck_uses_ready deploy/Dockerfile.node
assert_file_contains railway.json '"healthcheckPath": "/ready"'
assert_file_contains deploy/fly.toml 'path = "/ready"'

echo "deployment readiness probe test passed"
