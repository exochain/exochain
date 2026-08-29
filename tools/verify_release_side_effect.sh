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
  printf 'release side-effect verification failed: %s\n' "$1" >&2
  exit 1
}

release_workspace="${GITHUB_WORKSPACE:-}"
if [[ "$release_workspace" != /* ]] || [ ! -d "$release_workspace" ]; then
  fail "GITHUB_WORKSPACE must name the absolute release checkout directory"
fi
release_workspace="$(cd "$release_workspace" && pwd -P)"

scrub_git_environment() {
  unset \
    GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR \
    GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES \
    GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM \
    GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS \
    GIT_CEILING_DIRECTORIES GIT_DISCOVERY_ACROSS_FILESYSTEM \
    GIT_IMPLICIT_WORK_TREE GIT_PREFIX GIT_INTERNAL_SUPER_PREFIX \
    GIT_NAMESPACE GIT_REPLACE_REF_BASE GIT_NO_REPLACE_OBJECTS \
    GIT_SHALLOW_FILE GIT_GRAFT_FILE GIT_QUARANTINE_PATH GIT_EXEC_PATH \
    GIT_EXTERNAL_DIFF GIT_DIFF_OPTS GIT_ATTR_SOURCE
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

github_sha="${GITHUB_SHA:-}"
if ! [[ "$github_sha" =~ ^[0-9a-f]{40}$ ]]; then
  fail "GITHUB_SHA must be a full lowercase 40-character commit SHA"
fi

# This wrapper and both child guards are loaded from the immutable workflow
# dispatch commit. A build tool or npm lifecycle script may mutate checkout
# files, but it cannot replace the guard code executed at a release boundary.
trusted_git show "${GITHUB_SHA}:tools/verify_release_source.sh" | \
  BASH_ENV=/dev/null command -p bash
trusted_git show "${GITHUB_SHA}:tools/verify_release_tag.sh" | \
  BASH_ENV=/dev/null command -p bash
