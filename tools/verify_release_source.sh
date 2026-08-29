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
  /bin/echo "release source verification failed: inherited shell functions are forbidden" >&2
  exit 1
fi
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
  /usr/bin/git \
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

# Release jobs never need assume-unchanged or skip-worktree index
# optimizations. Reject them before assessing the index; otherwise a lifecycle
# script could make subsequent path classification ambiguous.
hidden_index_paths="$(trusted_git ls-files -v | /usr/bin/awk '$1 ~ /^[a-zS]$/ { print substr($0, 3) }')"
if [ -n "$hidden_index_paths" ]; then
  fail "tracked paths must not use assume-unchanged or skip-worktree flags: ${hidden_index_paths//$'\n'/, }"
fi

case "$source_clean_mode" in
  all|tracked) ;;
  *) fail "RELEASE_SOURCE_CLEAN_MODE must be all or tracked" ;;
esac

# Do not use `git status`, `diff`, or an index refresh to validate tracked
# release source. Those porcelain paths trust cached stat data and repository
# configuration such as core.trustctime and core.checkStat. Instead, walk the
# immutable commit tree, hash raw worktree bytes with filters disabled, and
# compare every Git-representable file type and executable mode directly.
manifest_parent="${RUNNER_TEMP:-/tmp}"
if [[ "$manifest_parent" != /* ]] || [ ! -d "$manifest_parent" ]; then
  fail "RUNNER_TEMP must name an absolute existing directory"
fi
manifest_parent="$(cd "$manifest_parent" && pwd -P)"
case "$manifest_parent/" in
  "$release_workspace/"|"$release_workspace/"*)
    fail "release source manifest must be created outside GITHUB_WORKSPACE"
    ;;
esac

source_manifest="$(/usr/bin/mktemp "$manifest_parent/exochain-release-source.XXXXXX")"
untracked_manifest=""
cleanup_source_manifests() {
  if [ -n "$source_manifest" ]; then
    /bin/rm -f -- "$source_manifest"
  fi
  if [ -n "$untracked_manifest" ]; then
    /bin/rm -f -- "$untracked_manifest"
  fi
}
trap cleanup_source_manifests EXIT

trusted_git ls-tree -r -t -z --full-tree "$expected_commit_sha" > "$source_manifest"
manifest_entry_count=0
while IFS= read -r -d '' manifest_entry; do
  manifest_entry_count=$((manifest_entry_count + 1))
  if [[ "$manifest_entry" != *$'\t'* ]]; then
    fail "commit tree contains an unparsable manifest entry"
  fi

  manifest_metadata="${manifest_entry%%$'\t'*}"
  tracked_path="${manifest_entry#*$'\t'}"
  IFS=' ' read -r tracked_mode tracked_type tracked_object unexpected_metadata <<< "$manifest_metadata"
  if [ -z "$tracked_mode" ] || [ -z "$tracked_type" ] || [ -z "$tracked_object" ] \
    || [ -n "${unexpected_metadata:-}" ] \
    || ! [[ "$tracked_object" =~ ^[0-9a-f]{40}$ ]]; then
    fail "commit tree contains invalid metadata for ${tracked_path:-an unnamed path}"
  fi
  case "/$tracked_path/" in
    //*|*/./*|*/../*) fail "commit tree contains an unsafe path" ;;
  esac
  if [ -z "$tracked_path" ] || [[ "$tracked_path" == /* ]]; then
    fail "commit tree contains an unsafe path"
  fi

  worktree_path="$release_workspace/$tracked_path"
  case "$tracked_mode:$tracked_type" in
    040000:tree)
      if [ ! -d "$worktree_path" ] || [ -L "$worktree_path" ]; then
        fail "tracked directory type mismatch: $tracked_path"
      fi
      ;;
    100644:blob|100755:blob)
      if [ ! -f "$worktree_path" ] || [ -L "$worktree_path" ]; then
        fail "tracked regular-file type mismatch: $tracked_path"
      fi
      actual_object="$(trusted_git hash-object --no-filters -- "$tracked_path")"
      if [ "$actual_object" != "$tracked_object" ]; then
        fail "tracked file bytes differ from immutable commit: $tracked_path"
      fi

      if actual_permissions="$(/usr/bin/stat -c '%a' -- "$worktree_path" 2>/dev/null)"; then
        :
      else
        actual_permissions="$(/usr/bin/stat -f '%Lp' -- "$worktree_path")"
      fi
      if ! [[ "$actual_permissions" =~ ^[0-7]{3,4}$ ]]; then
        fail "could not determine tracked file mode: $tracked_path"
      fi
      actual_execute_bits=$((8#$actual_permissions & 0111))
      if [ "$tracked_mode" = "100644" ] && [ "$actual_execute_bits" -ne 0 ]; then
        fail "tracked file unexpectedly executable: $tracked_path"
      fi
      if [ "$tracked_mode" = "100755" ] && [ "$actual_execute_bits" -ne 73 ]; then
        fail "tracked executable mode differs from immutable commit: $tracked_path"
      fi
      ;;
    120000:blob)
      if [ ! -L "$worktree_path" ]; then
        fail "tracked symlink type mismatch: $tracked_path"
      fi
      actual_object="$(/usr/bin/readlink -n -- "$worktree_path" | trusted_git hash-object --stdin)"
      if [ "$actual_object" != "$tracked_object" ]; then
        fail "tracked symlink target differs from immutable commit: $tracked_path"
      fi
      ;;
    160000:commit)
      fail "release source cannot contain Git submodules: $tracked_path"
      ;;
    *)
      fail "unsupported tracked object ${tracked_mode}:${tracked_type}: $tracked_path"
      ;;
  esac
done < "$source_manifest"

if [ "$manifest_entry_count" -eq 0 ]; then
  fail "immutable release commit tree must not be empty"
fi

# The raw worktree comparison above is independent of the index. Compare the
# index tree separately, without refreshing it from stat data, so staged path
# additions, removals, and content changes also fail closed.
expected_tree="$(trusted_git rev-parse --verify "${expected_commit_sha}^{tree}")"
index_tree="$(trusted_git write-tree)"
if [ "$index_tree" != "$expected_tree" ]; then
  fail "release index must exactly match the immutable commit tree"
fi

if [ "$source_clean_mode" = "all" ]; then
  untracked_manifest="$(/usr/bin/mktemp "$manifest_parent/exochain-release-untracked.XXXXXX")"
  # Honor only committed, per-directory .gitignore files. Do not allow
  # .git/info/exclude or core.excludesFile from local configuration to hide a
  # lifecycle-created input from the all-source boundary.
  trusted_git ls-files --others --exclude-per-directory=.gitignore -z > "$untracked_manifest"
  if [ -s "$untracked_manifest" ]; then
    fail "checkout must be clean, including nonignored untracked files"
  fi
fi

printf 'Verified immutable release source %s with %s cleanliness\n' "$head_sha" "$source_clean_mode"
