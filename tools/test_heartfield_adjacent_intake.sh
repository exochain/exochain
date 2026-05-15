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

readme="docs/heartfield/README.md"
intake="docs/heartfield/INTAKE.md"
kinships="docs/heartfield/KINSHIPS.md"
whitepaper="docs/heartfield/WHITEPAPER.md"
index="docs/INDEX.md"

fail() {
  echo "HeartField adjacent intake test failed: $*" >&2
  exit 1
}

[ -f "$readme" ] || fail "HeartField README is required"
[ -f "$intake" ] || fail "HeartField intake record is required"
[ -f "$kinships" ] || fail "HeartField kinship map is required"
[ -f "$whitepaper" ] || fail "HeartField whitepaper is required"

grep -q "Adjacent surface" "$readme" || fail "README must classify HeartField as adjacent"
grep -q "must not claim EXOCHAIN constitutional enforcement" "$readme" || {
  fail "README must prevent unproven EXOCHAIN trust claims"
}
grep -q "Uplifting self-governance" "$readme" || {
  fail "README must preserve the HeartField mission"
}

required_intake_fields=(
  "Owner and accountable maintainer"
  "Deployment status"
  "Allowed EXOCHAIN constitutional trust claims"
  "Core state read/write access"
  "Exact trust boundary"
  "Surface-specific test command and CI gate"
  "Secrets inventory and runtime configuration source"
  "Rollback or disablement path"
)

for field in "${required_intake_fields[@]}"; do
  grep -q "$field" "$intake" || fail "intake missing field: $field"
done

grep -q "prototype" "$intake" || fail "intake must mark initial deployment status"
grep -q "None until a tested runtime adapter exists" "$intake" || {
  fail "intake must deny inherited constitutional trust claims"
}
grep -q "No direct read or write access to EXOCHAIN core state" "$intake" || {
  fail "intake must deny direct core-state access"
}

grep -q "Kinships do not expand the trusted computing base" "$kinships" || {
  fail "kinship map must preserve the trust-boundary rule"
}
grep -q "EXOCHAIN.AI" "$kinships" || fail "kinship map must include EXOCHAIN.AI"
grep -q "Constitutional Computing" "$kinships" || {
  fail "kinship map must include Constitutional Computing"
}

grep -q "HeartField.ai Whitepaper" "$whitepaper" || {
  fail "whitepaper must have a canonical title"
}
grep -q "Uplifting self-governance" "$whitepaper" || {
  fail "whitepaper must preserve the HeartField thesis"
}
grep -q "not EXOCHAIN constitutional enforcement" "$whitepaper" || {
  fail "whitepaper must deny unproven EXOCHAIN enforcement"
}
grep -q "No runtime adapter is introduced by this whitepaper" "$whitepaper" || {
  fail "whitepaper must preserve the runtime trust boundary"
}
grep -q "truth, consent, repair, memory, dissent, restraint, and wise evolution" "$whitepaper" || {
  fail "whitepaper must preserve the practice vocabulary"
}

grep -q "HeartField.ai" "$index" || fail "docs index must link HeartField"

echo "HeartField adjacent intake test passed"
