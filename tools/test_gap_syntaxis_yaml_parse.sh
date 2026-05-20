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
  printf 'GAP Syntaxis YAML parse test failed: %s\n' "$1" >&2
  exit 1
}

protocols=(gap/syntaxis/protocols/*.yaml)

if grep -nE '(^|[[:space:],[])\*[A-Za-z0-9_-]+' "${protocols[@]}"; then
  fail "Syntaxis protocols must not use unquoted YAML alias tokens as wildcard inputs"
fi

if command -v ruby >/dev/null 2>&1; then
  ruby -ryaml -e 'ARGV.each { |path| YAML.load_file(path) }' "${protocols[@]}"
else
  printf 'ruby unavailable; alias-token source guard completed\n'
fi

printf 'GAP Syntaxis YAML parse test passed\n'
