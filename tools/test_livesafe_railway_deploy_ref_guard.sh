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
  printf 'LiveSafe Railway deploy ref guard failed: %s\n' "$1" >&2
  exit 1
}

workflow=".github/workflows/livesafe-railway-deploy.yml"
ci_workflow=".github/workflows/ci.yml"

[[ -f "$workflow" ]] || fail "$workflow is missing"
[[ -f "$ci_workflow" ]] || fail "$ci_workflow is missing"

if grep -nF 'ref: ${{ inputs.commit_sha || github.sha }}' "$workflow"; then
  fail "secret-bearing deploy jobs must not check out raw workflow_dispatch commit_sha"
fi

safe_ref_count=$(grep -cF 'id: safe-ref' "$workflow")
[[ "$safe_ref_count" -eq 2 ]] \
  || fail "staging and production jobs must each resolve a safe ref before checkout"

grep -F 'REQUESTED_COMMIT_SHA: ${{ inputs.commit_sha || github.sha }}' "$workflow" >/dev/null \
  || fail "safe-ref gate must validate the requested workflow commit SHA"

grep -F '[[ ! "$REQUESTED_COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]]' "$workflow" >/dev/null \
  || fail "safe-ref gate must require a full lowercase commit SHA"

grep -F 'merge-base --is-ancestor "$REQUESTED_COMMIT_SHA" refs/remotes/origin/main' "$workflow" >/dev/null \
  || fail "safe-ref gate must prove requested SHA is reachable from origin/main"

checkout_safe_ref_count=$(grep -cF 'ref: ${{ steps.safe-ref.outputs.sha }}' "$workflow")
[[ "$checkout_safe_ref_count" -eq 2 ]] \
  || fail "staging and production checkouts must use the resolved safe ref"

deploy_sha_count=$(grep -cF 'SAFE_DEPLOY_SHA: ${{ steps.safe-ref.outputs.sha }}' "$workflow")
[[ "$deploy_sha_count" -eq 4 ]] \
  || fail "both services in staging and production must deploy the resolved safe SHA"

grep -F 'tools/test_livesafe_railway_deploy_ref_guard.sh' "$ci_workflow" >/dev/null \
  || fail "CI must run the LiveSafe Railway deploy ref guard"

printf 'LiveSafe Railway deploy ref guard passed\n'
