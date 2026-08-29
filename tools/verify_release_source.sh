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

release_workspace="${GITHUB_WORKSPACE:-}"
if [[ "$release_workspace" != /* ]] || [ ! -d "$release_workspace" ]; then
  fail "GITHUB_WORKSPACE must name the absolute release checkout directory"
fi
release_workspace="$(cd "$release_workspace" && pwd -P)"

# Git's repository, index, object, replacement, and config environment is
# process-global. A previous lifecycle step can persist these names through
# GITHUB_ENV, so remove them before resolving or inspecting the checkout.
scrub_git_environment() {
  unset \
    GIT_DIR \
    GIT_WORK_TREE \
    GIT_INDEX_FILE \
    GIT_COMMON_DIR \
    GIT_OBJECT_DIRECTORY \
    GIT_ALTERNATE_OBJECT_DIRECTORIES \
    GIT_CONFIG \
    GIT_CONFIG_GLOBAL \
    GIT_CONFIG_SYSTEM \
    GIT_CONFIG_NOSYSTEM \
    GIT_CONFIG_COUNT \
    GIT_CONFIG_PARAMETERS \
    GIT_CEILING_DIRECTORIES \
    GIT_DISCOVERY_ACROSS_FILESYSTEM \
    GIT_IMPLICIT_WORK_TREE \
    GIT_PREFIX \
    GIT_INTERNAL_SUPER_PREFIX \
    GIT_NAMESPACE \
    GIT_REPLACE_REF_BASE \
    GIT_NO_REPLACE_OBJECTS \
    GIT_SHALLOW_FILE \
    GIT_GRAFT_FILE \
    GIT_QUARANTINE_PATH \
    GIT_EXEC_PATH \
    GIT_EXTERNAL_DIFF \
    GIT_DIFF_OPTS \
    GIT_ATTR_SOURCE
}

scrub_git_environment
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1

trusted_git() (
  scrub_git_environment
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1
  command -p git \
    -c core.fsmonitor=false \
    -c core.untrackedCache=false \
    -c core.ignoreStat=false \
    -C "$release_workspace" \
    "$@"
)

git_toplevel="$(trusted_git rev-parse --show-toplevel)"
git_toplevel="$(cd "$git_toplevel" && pwd -P)"
if [ "$git_toplevel" != "$release_workspace" ]; then
  fail "GITHUB_WORKSPACE must be the root of the inspected Git checkout"
fi

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

head_sha="$(trusted_git rev-parse --verify 'HEAD^{commit}')"
if [ "$head_sha" != "$expected_commit_sha" ] \
  || [ "$head_sha" != "$dispatch_sha" ] \
  || [ "$trusted_release_ref" != "$expected_commit_sha" ]; then
  fail "identity mismatch: HEAD=${head_sha}, expected=${expected_commit_sha}, dispatch=${dispatch_sha}, trusted_ref=${trusted_release_ref}"
fi

# `git status` deliberately honors assume-unchanged and skip-worktree index
# flags. Release jobs never need either optimization, so reject them before
# assessing cleanliness; otherwise a lifecycle script could hide a tracked
# mutation from the final source boundary.
hidden_index_paths="$(trusted_git ls-files -v | command -p awk '$1 ~ /^[a-zS]$/ { print substr($0, 3) }')"
if [ -n "$hidden_index_paths" ]; then
  fail "tracked paths must not use assume-unchanged or skip-worktree flags: ${hidden_index_paths//$'\n'/, }"
fi

case "$source_clean_mode" in
  all)
    if [ -n "$(trusted_git status --porcelain=v1 --untracked-files=all)" ]; then
      fail "checkout must be clean, including untracked files"
    fi
    ;;
  tracked)
    if [ -n "$(trusted_git status --porcelain=v1 --untracked-files=no)" ]; then
      fail "tracked release source must be clean"
    fi
    ;;
  *)
    fail "RELEASE_SOURCE_CLEAN_MODE must be all or tracked"
    ;;
esac

printf 'Verified immutable release source %s with %s cleanliness\n' "$head_sha" "$source_clean_mode"
