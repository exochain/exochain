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
  /bin/echo "release Cargo configuration verification failed: inherited shell functions are forbidden" >&2
  exit 1
fi
set -euo pipefail

fail() {
  printf 'release Cargo configuration verification failed: %s\n' "$1" >&2
  exit 1
}

release_workspace="${GITHUB_WORKSPACE:-}"
if [[ "$release_workspace" != /* ]] || [ ! -d "$release_workspace" ] || [ -L "$release_workspace" ]; then
  fail "GITHUB_WORKSPACE must name the absolute real release checkout directory"
fi
release_workspace="$(cd "$release_workspace" && pwd -P)"

# Cargo merges .cargo/config{,.toml} while walking from its project directory
# to the filesystem root. The immutable source guard covers every location in
# GITHUB_WORKSPACE; reject every location above it so a lifecycle step cannot
# inject a compiler wrapper, registry, linker, or credential provider outside
# the checked release source.
ancestor_directory="$(/usr/bin/dirname "$release_workspace")"
while :; do
  cargo_config_directory="$ancestor_directory/.cargo"
  if [ -L "$cargo_config_directory" ]; then
    fail "Cargo configuration directory above GITHUB_WORKSPACE must not be a symlink: $cargo_config_directory"
  fi
  for cargo_config_name in config config.toml; do
    cargo_config_path="$cargo_config_directory/$cargo_config_name"
    if [ -e "$cargo_config_path" ] || [ -L "$cargo_config_path" ]; then
      fail "Cargo configuration above GITHUB_WORKSPACE is forbidden: $cargo_config_path"
    fi
  done

  [ "$ancestor_directory" = / ] && break
  next_ancestor="$(/usr/bin/dirname "$ancestor_directory")"
  [ "$next_ancestor" != "$ancestor_directory" ] \
    || fail "could not complete Cargo ancestor traversal"
  ancestor_directory="$next_ancestor"
done

printf 'Release Cargo configuration is confined to immutable source and the caller-provided clean CARGO_HOME\n'
