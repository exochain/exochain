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
  printf 'release source verification failed: %s\n' "$1" >&2
  exit 1
}

expected_commit_sha="${EXPECTED_COMMIT_SHA:-}"
dispatch_sha="${GITHUB_SHA:-}"
trusted_release_ref="${TRUSTED_RELEASE_REF:-}"
source_clean_mode="${RELEASE_SOURCE_CLEAN_MODE:-all}"

for entry in \
  "EXPECTED_COMMIT_SHA:$expected_commit_sha" \
  "GITHUB_SHA:$dispatch_sha" \
  "TRUSTED_RELEASE_REF:$trusted_release_ref"; do
  name="${entry%%:*}"
  value="${entry#*:}"
  [[ "$value" =~ ^[0-9a-f]{40}$ ]] \
    || fail "$name must be a full lowercase 40-character commit SHA"
done

head_sha="$(git rev-parse --verify 'HEAD^{commit}')"
if [ "$head_sha" != "$expected_commit_sha" ] \
  || [ "$head_sha" != "$dispatch_sha" ] \
  || [ "$trusted_release_ref" != "$expected_commit_sha" ]; then
  fail "identity mismatch: HEAD=${head_sha}, expected=${expected_commit_sha}, dispatch=${dispatch_sha}, trusted_ref=${trusted_release_ref}"
fi

case "$source_clean_mode" in
  all)
    if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
      fail "checkout must be clean, including untracked files"
    fi
    ;;
  tracked)
    if [ -n "$(git status --porcelain=v1 --untracked-files=no)" ]; then
      fail "tracked release source must be clean"
    fi
    ;;
  *)
    fail "RELEASE_SOURCE_CLEAN_MODE must be all or tracked"
    ;;
esac

printf 'Verified immutable release source %s with %s cleanliness\n' "$head_sha" "$source_clean_mode"
