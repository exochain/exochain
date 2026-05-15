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

cd "$(dirname "$0")/.."

policy="docs/policy/CANONICAL-ORIGIN-SIGNALS.md"
index="docs/INDEX.md"
security="SECURITY.md"

fail() {
  echo "canonical origin spoof guard failed: $*" >&2
  exit 1
}

[ -f "$policy" ] || fail "canonical origin policy is required"

grep -q "EXOCHAIN.AI" "$policy" || {
  fail "policy must name EXOCHAIN.AI as the canonical public identity signal"
}

grep -q "EX0CHAIN is a spoofing watchword" "$policy" || {
  fail "policy must classify the zero-form token as a spoofing watchword"
}

grep -q "O is origin. 0 is evidence. Adjudicate before trust." "$policy" || {
  fail "policy must preserve the origin/evidence/adjudication rule"
}

grep -q "Do not let the zero divide the community" "$policy" || {
  fail "policy must preserve the non-divisive response rule"
}

grep -q "constitutional synapse" "$policy" || {
  fail "policy must route spoofing signals through the constitutional synapse"
}

grep -q "Canonical Origin Signals" "$index" || {
  fail "docs index must link the canonical origin policy"
}

grep -q "Canonical origin signals" "$security" || {
  fail "SECURITY.md must expose canonical origin guidance"
}

violations=()
while IFS= read -r hit; do
  path=${hit%%:*}
  path=${path#./}
  case "$path" in
    "$policy" | "tools/test_canonical_origin_spoof_guard.sh")
      ;;
    *)
      violations+=("$hit")
      ;;
  esac
done < <(rg -n -i "ex0chain" --glob '!target/**' --glob '!.git/**' --glob '!docs/superpowers/**' --glob '!docs.zip' . || true)

if [ "${#violations[@]}" -ne 0 ]; then
  printf '%s\n' "${violations[@]}" >&2
  fail "zero-form EX0CHAIN token may appear only in the canonical policy and guard"
fi

echo "canonical origin spoof guard passed"
