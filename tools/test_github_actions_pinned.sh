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
  printf 'github actions pinning test failed: %s\n' "$1" >&2
  exit 1
}

shopt -s nullglob

violations=()
for workflow in .github/workflows/*.yml .github/workflows/*.yaml; do
  while IFS= read -r match; do
    line_no=${match%%:*}
    uses_ref=${match#*:}
    uses_ref=${uses_ref#*uses:}
    uses_ref=${uses_ref%%#*}
    uses_ref=$(printf '%s' "$uses_ref" | sed -E "s/^[[:space:]]+//;s/[[:space:]]+$//;s/^['\\\"]//;s/['\\\"]$//")

    [[ -z "$uses_ref" ]] && continue
    [[ "$uses_ref" == ./* ]] && continue

    ref=${uses_ref##*@}
    if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
      violations+=("${workflow}:${line_no}: ${uses_ref}")
    fi
  done < <(grep -nE 'uses:[[:space:]]+[^[:space:]#]+@[^[:space:]#]+' "$workflow" || true)
done

if ((${#violations[@]} > 0)); then
  printf '%s\n' "${violations[@]}" >&2
  fail "external actions must be pinned to immutable commit SHAs"
fi

printf 'github actions pinning test passed\n'
