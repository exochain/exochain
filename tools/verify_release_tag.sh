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

if /usr/bin/env | /usr/bin/grep -Eq '^BASH_FUNC_.*%%='; then
  /bin/echo "release tag verification failed: inherited shell functions are forbidden" >&2
  exit 1
fi
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
  /usr/bin/git --no-replace-objects \
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

github_actions="${GITHUB_ACTIONS:-}"
github_server_url="${GITHUB_SERVER_URL:-}"
github_repository="${GITHUB_REPOSITORY:-}"
release_github_token="${RELEASE_GITHUB_TOKEN:-}"

case "$github_actions" in
  true)
    [[ "$github_server_url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] \
      || fail "GITHUB_SERVER_URL must be a credential-free HTTPS origin"
    [[ "$github_repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
      || fail "GITHUB_REPOSITORY must identify one owner and repository"
    [ -n "$release_github_token" ] \
      || fail "RELEASE_GITHUB_TOKEN is required for authoritative tag lookup"
    [[ "$release_github_token" != *$'\n'* && "$release_github_token" != *$'\r'* ]] \
      || fail "RELEASE_GITHUB_TOKEN must not contain line breaks"
    ;;
  false|"")
    # Local regression fixtures use a file transport. GitHub Actions cannot
    # enter this branch because its GITHUB_* defaults are runner-protected.
    if ! [[ "$github_server_url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] \
      && ! [[ "$github_server_url" =~ ^file:///[-/A-Za-z0-9._]+$ ]]; then
      fail "local GITHUB_SERVER_URL must be a credential-free HTTPS or absolute file origin"
    fi
    [[ "$github_repository" =~ ^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?$ ]] \
      || fail "local GITHUB_REPOSITORY is malformed"
    ;;
  *) fail "GITHUB_ACTIONS must be exactly true, false, or empty" ;;
esac

authoritative_remote_url="${github_server_url%/}/${github_repository}.git"
tag_probe_dir="$(/usr/bin/mktemp -d)"
tag_probe_dir="$(cd "$tag_probe_dir" && pwd -P)"
case "${tag_probe_dir}/" in
  "${release_workspace}/"*) fail "authoritative tag probe must be outside GITHUB_WORKSPACE" ;;
esac
cleanup_tag_probe() {
  /bin/rm -rf -- "$tag_probe_dir"
}
trap cleanup_tag_probe EXIT

trusted_remote_git() (
  # Start the authoritative lookup with an empty environment. This makes
  # checkout-local configuration, GITHUB_ENV Git/cURL controls, proxies,
  # credential helpers, and tracing hooks structurally unavailable to Git.
  /usr/bin/env -i \
    GIT_CEILING_DIRECTORIES="$tag_probe_dir" \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_TERMINAL_PROMPT=0 \
    PATH=/usr/bin:/bin \
    RELEASE_GIT_AUTH_HEADER="${release_git_auth_header:-}" \
    /usr/bin/git \
    -c core.fsmonitor=false \
    -c core.untrackedCache=false \
    -c core.ignoreStat=false \
    -C "$tag_probe_dir" \
    "$@"
)

remote_refs=""
release_git_auth_header=""
if [ "$github_actions" = "true" ]; then
  release_git_auth_header="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$release_github_token" | /usr/bin/base64 | /usr/bin/tr -d '\r\n')"
  if ! remote_refs="$(trusted_remote_git \
    --config-env="http.${github_server_url}/.extraheader=RELEASE_GIT_AUTH_HEADER" \
    ls-remote "$authoritative_remote_url" \
    "refs/tags/${release_tag}" "refs/tags/${release_tag}^{}")"; then
    fail "authoritative release tag ${release_tag} is absent or could not be queried"
  fi
else
  if ! remote_refs="$(trusted_remote_git ls-remote "$authoritative_remote_url" \
    "refs/tags/${release_tag}" "refs/tags/${release_tag}^{}")"; then
    fail "authoritative release tag ${release_tag} is absent or could not be queried"
  fi
fi

actual_tag_object_sha=""
actual_tag_commit_sha=""
remote_ref_count=0
while IFS=$'\t' read -r object_id ref_name unexpected; do
  [ -n "$object_id" ] || continue
  [ -z "$unexpected" ] || fail "authoritative tag lookup returned malformed output"
  [[ "$object_id" =~ ^[0-9a-f]{40}$ ]] \
    || fail "authoritative tag lookup returned a malformed object ID"
  case "$ref_name" in
    "refs/tags/${release_tag}")
      [ -z "$actual_tag_object_sha" ] || fail "authoritative tag lookup returned a duplicate tag object"
      actual_tag_object_sha="$object_id"
      ;;
    "refs/tags/${release_tag}^{}")
      [ -z "$actual_tag_commit_sha" ] || fail "authoritative tag lookup returned a duplicate peeled commit"
      actual_tag_commit_sha="$object_id"
      ;;
    *) fail "authoritative tag lookup returned an unexpected ref ${ref_name}" ;;
  esac
  remote_ref_count=$((remote_ref_count + 1))
done <<<"$remote_refs"

if [ "$remote_ref_count" -ne 2 ] \
  || [ -z "$actual_tag_object_sha" ] \
  || [ -z "$actual_tag_commit_sha" ]; then
  fail "authoritative release tag ${release_tag} must be one annotated tag with one peeled commit"
fi

if [ "$actual_tag_object_sha" != "$expected_tag_object_sha" ]; then
  fail "authoritative release tag object changed: got ${actual_tag_object_sha}, expected ${expected_tag_object_sha}"
fi
if [ "$actual_tag_commit_sha" != "$expected_tag_commit_sha" ] \
  || [ "$actual_tag_commit_sha" != "$expected_commit_sha" ] \
  || [ "$actual_tag_commit_sha" != "$dispatch_sha" ]; then
  fail "authoritative release tag commit changed: got ${actual_tag_commit_sha}, expected ${expected_tag_commit_sha}"
fi

printf 'Verified authoritative remote signed-tag object %s at commit %s\n' \
  "$actual_tag_object_sha" "$actual_tag_commit_sha"
