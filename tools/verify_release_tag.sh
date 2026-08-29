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
  printf 'release tag verification failed: %s\n' "$1" >&2
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

dry_run="${DRY_RUN:-}"
release_tag="${RELEASE_TAG:-}"
expected_tag_object_sha="${EXPECTED_TAG_OBJECT_SHA:-}"
expected_tag_commit_sha="${EXPECTED_TAG_COMMIT_SHA:-}"
expected_commit_sha="${EXPECTED_COMMIT_SHA:-}"
dispatch_sha="${GITHUB_SHA:-}"

case "$dry_run" in
  true)
    if [ -n "$expected_tag_object_sha" ] || [ -n "$expected_tag_commit_sha" ]; then
      fail "dry run must not consume a signed-tag identity"
    fi
    printf 'Dry run: remote release tag verification is skipped.\n'
    exit 0
    ;;
  false) ;;
  *) fail "DRY_RUN must be exactly true or false" ;;
esac

[[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z-]*(\.[0-9A-Za-z][0-9A-Za-z-]*)*)?$ ]] \
  || fail "RELEASE_TAG must be a sanitized v-prefixed semantic version"

for entry in \
  "EXPECTED_TAG_OBJECT_SHA:$expected_tag_object_sha" \
  "EXPECTED_TAG_COMMIT_SHA:$expected_tag_commit_sha" \
  "EXPECTED_COMMIT_SHA:$expected_commit_sha" \
  "GITHUB_SHA:$dispatch_sha"; do
  name="${entry%%:*}"
  value="${entry#*:}"
  [[ "$value" =~ ^[0-9a-f]{40}$ ]] \
    || fail "$name must be a full lowercase 40-character object ID"
done

if [ "$expected_tag_commit_sha" != "$expected_commit_sha" ] \
  || [ "$expected_tag_commit_sha" != "$dispatch_sha" ]; then
  fail "verified tag commit must equal the validated and workflow-dispatch commits"
fi

# Fetch the named remote ref itself on every live job. Fetching only an object
# ID would prove object availability, not that the release tag still names it.
if ! trusted_git fetch --force --no-tags origin \
  "+refs/tags/${release_tag}:refs/tags/${release_tag}"; then
  fail "remote release tag ${release_tag} is absent or could not be fetched"
fi

tag_type="$(trusted_git cat-file -t "refs/tags/${release_tag}")"
if [ "$tag_type" != "tag" ]; then
  fail "remote release tag ${release_tag} is no longer an annotated tag"
fi

actual_tag_object_sha="$(trusted_git rev-parse "refs/tags/${release_tag}")"
actual_tag_commit_sha="$(trusted_git rev-parse "refs/tags/${release_tag}^{commit}")"
if [ "$actual_tag_object_sha" != "$expected_tag_object_sha" ]; then
  fail "remote release tag object changed: got ${actual_tag_object_sha}, expected ${expected_tag_object_sha}"
fi
if [ "$actual_tag_commit_sha" != "$expected_tag_commit_sha" ] \
  || [ "$actual_tag_commit_sha" != "$expected_commit_sha" ] \
  || [ "$actual_tag_commit_sha" != "$dispatch_sha" ]; then
  fail "remote release tag commit changed: got ${actual_tag_commit_sha}, expected ${expected_tag_commit_sha}"
fi

printf 'Verified current remote signed-tag object %s at commit %s\n' \
  "$actual_tag_object_sha" "$actual_tag_commit_sha"
