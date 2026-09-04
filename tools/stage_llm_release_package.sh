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
  /bin/echo "LYNK release staging failed: inherited shell functions are forbidden" >&2
  exit 1
fi
set -euo pipefail

fail() {
  printf 'LYNK release staging failed: %s\n' "$1" >&2
  exit 1
}

release_workspace="${GITHUB_WORKSPACE:-}"
release_commit="${GITHUB_SHA:-}"
runner_temp="${RUNNER_TEMP:-}"
build_package="${RELEASE_LLM_BUILD_DIR:-}"
stage_root="${RELEASE_LLM_STAGE_ROOT:-}"
release_python="${RELEASE_PYTHON:-}"

for directory_name in release_workspace runner_temp; do
  directory_value="${!directory_name}"
  if [[ "$directory_value" != /* ]] || [ ! -d "$directory_value" ] || [ -L "$directory_value" ]; then
    fail "$directory_name must name an absolute real directory"
  fi
done
release_workspace="$(cd "$release_workspace" && pwd -P)"
runner_temp="$(cd "$runner_temp" && pwd -P)"
if [ -n "$build_package" ]; then
  if [[ "$build_package" != /* ]] || [ ! -d "$build_package" ] || [ -L "$build_package" ]; then
    fail "RELEASE_LLM_BUILD_DIR must name an absolute real directory when provided"
  fi
  build_package="$(cd "$build_package" && pwd -P)"
  if [[ "$release_python" != /* ]] || [ ! -f "$release_python" ] \
    || [ ! -x "$release_python" ] || [ -L "$release_python" ]; then
    fail "RELEASE_PYTHON must name an absolute real executable when build output is provided"
  fi
fi
if ! [[ "$release_commit" =~ ^[0-9a-f]{40}$ ]]; then
  fail "GITHUB_SHA must be a full lowercase commit SHA"
fi
stage_parent="$(/usr/bin/dirname "$stage_root")"
stage_name="$(/usr/bin/basename "$stage_root")"
if [[ "$stage_root" != /* ]] || [[ "$stage_root" == *$'\n'* ]] \
  || [[ "$stage_name" == '.' || "$stage_name" == '..' ]] \
  || [ ! -d "$stage_parent" ] || [ -L "$stage_parent" ] \
  || [ -e "$stage_root" ] || [ -L "$stage_root" ]; then
  fail "RELEASE_LLM_STAGE_ROOT must be a fresh absolute path beneath RUNNER_TEMP"
fi
stage_parent="$(cd "$stage_parent" && pwd -P)"
stage_root="$stage_parent/$stage_name"
case "$stage_root" in
  "$runner_temp"/*) ;;
  *) fail "RELEASE_LLM_STAGE_ROOT must be beneath RUNNER_TEMP" ;;
esac
if [ -n "$build_package" ]; then
  case "$build_package/" in
    "$runner_temp/"*) ;;
    *) fail "RELEASE_LLM_BUILD_DIR must be beneath RUNNER_TEMP" ;;
  esac
fi

unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG GIT_CONFIG_GLOBAL \
  GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM GIT_CONFIG_COUNT \
  GIT_CONFIG_PARAMETERS GIT_CEILING_DIRECTORIES \
  GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_NAMESPACE GIT_REPLACE_REF_BASE \
  GIT_NO_REPLACE_OBJECTS GIT_SHALLOW_FILE GIT_GRAFT_FILE GIT_EXEC_PATH \
  GIT_EXTERNAL_DIFF GIT_DIFF_OPTS GIT_ATTR_SOURCE
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1

trusted_git() {
  /usr/bin/git --no-replace-objects \
    -c core.fsmonitor=false \
    -c core.untrackedCache=false \
    -c core.ignoreStat=false \
    -C "$release_workspace" \
    "$@"
}

head_commit="$(trusted_git rev-parse --verify 'HEAD^{commit}')"
[ "$head_commit" = "$release_commit" ] \
  || fail "checked-out HEAD does not match GITHUB_SHA"

readonly package_prefix='packages/exochain-llm-proxy/'
stage_package="$stage_root/packages/exochain-llm-proxy"
/bin/mkdir -m 700 -p "$stage_package"
entry_count=0
while IFS= read -r -d '' tree_entry; do
  entry_count=$((entry_count + 1))
  [[ "$tree_entry" == *$'\t'* ]] || fail "immutable package tree entry is malformed"
  tree_metadata="${tree_entry%%$'\t'*}"
  source_path="${tree_entry#*$'\t'}"
  IFS=' ' read -r source_mode source_type source_object unexpected_metadata <<< "$tree_metadata"
  [ -z "${unexpected_metadata:-}" ] \
    || fail "immutable package tree metadata is malformed"
  [[ "$source_object" =~ ^[0-9a-f]{40}$ ]] \
    || fail "immutable package tree object ID is invalid"
  case "$source_path" in
    "$package_prefix"*) ;;
    *) fail "immutable package tree escaped the LYNK package prefix" ;;
  esac
  relative_path="${source_path#"$package_prefix"}"
  if [ -z "$relative_path" ] || [[ "$relative_path" == /* ]] \
    || [[ "$relative_path" == *$'\n'* ]] || [[ "$relative_path" == *$'\r'* ]]; then
    fail "immutable package tree contains an unsafe path"
  fi
  case "/$relative_path/" in
    //*|*/./*|*/../*) fail "immutable package tree contains traversal" ;;
  esac
  destination="$stage_package/$relative_path"
  /bin/mkdir -m 755 -p "$(/usr/bin/dirname "$destination")"
  [ ! -e "$destination" ] && [ ! -L "$destination" ] \
    || fail "immutable package tree contains a duplicate path"
  case "$source_mode:$source_type" in
    100644:blob)
      trusted_git cat-file blob "$source_object" > "$destination"
      /bin/chmod 644 "$destination"
      ;;
    100755:blob)
      trusted_git cat-file blob "$source_object" > "$destination"
      /bin/chmod 755 "$destination"
      ;;
    120000:blob)
      fail "npm release package source must not contain symbolic links: $relative_path"
      ;;
    160000:commit)
      fail "npm release package source must not contain submodules: $relative_path"
      ;;
    *)
      fail "unsupported immutable package entry $source_mode:$source_type"
      ;;
  esac
done < <(trusted_git ls-tree -r -z --full-tree "$release_commit" -- "${package_prefix%/}")

[ "$entry_count" -gt 0 ] || fail "immutable LYNK package tree is empty"
[ -d "$stage_package/dist" ] && [ ! -L "$stage_package/dist" ] \
  || fail "immutable LYNK package has no committed dist directory"

# Only compiler output is admitted from the lifecycle tree, and even that must
# already equal the signed commit byte-for-byte, type-for-type, and mode-for-mode.
if [ -n "$build_package" ]; then
  [ -d "$build_package/dist" ] && [ ! -L "$build_package/dist" ] \
    || fail "tested LYNK build has no real dist directory"
  /usr/bin/env -i "$release_python" -I -B - "$build_package/dist" "$stage_package/dist" <<'PY'
from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path


def reject(message: str) -> None:
    raise SystemExit(f"LYNK release staging failed: {message}")


def manifest(root_text: str) -> list[tuple[str, str, int, str]]:
    root = Path(root_text)
    try:
        root_stat = root.lstat()
    except OSError as error:
        reject(f"cannot inspect generated dist root: {error}")
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        reject("generated dist root must be a real directory")

    records: list[tuple[str, str, int, str]] = []
    for candidate in sorted(root.rglob("*"), key=lambda path: path.as_posix()):
        relative = candidate.relative_to(root).as_posix()
        if not relative or "\n" in relative or "\r" in relative:
            reject("generated dist contains an unsafe path")
        metadata = candidate.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            records.append((relative, "d", mode, ""))
        elif stat.S_ISREG(metadata.st_mode):
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            records.append((relative, "f", mode, digest))
        else:
            reject(f"generated dist contains a symlink or special file: {relative}")
    if not records:
        reject("generated dist must not be empty")
    return records


if manifest(sys.argv[1]) != manifest(sys.argv[2]):
    reject("tested generated dist differs from the immutable committed dist tree")
PY
fi

printf '%s\n' "$stage_package"
