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
  /bin/echo "release tool resolution failed: inherited shell functions are forbidden" >&2
  exit 1
fi
set -euo pipefail

fail() {
  printf 'release tool resolution failed: %s\n' "$1" >&2
  exit 1
}

output_mode=materialize
tool_view=""
case "${1:-}" in
  --identity)
    output_mode=identity
    shift
    ;;
  --materialize)
    output_mode=materialize
    tool_view="${2:-}"
    shift 2
    ;;
  *) ;;
esac

if [ "$#" -eq 0 ]; then
  fail "at least one required release tool must be named"
fi

trusted_cargo_home="${RELEASE_TRUSTED_CARGO_HOME:-}"
trusted_rustup_home="${RELEASE_TRUSTED_RUSTUP_HOME:-}"
trusted_rust_toolchain="${RELEASE_TRUSTED_RUST_TOOLCHAIN:-}"
trusted_cargo_tool_home="${RELEASE_TRUSTED_CARGO_TOOL_HOME:-}"
trusted_node_root="${RELEASE_TRUSTED_NODE_ROOT:-}"
trusted_node_version="${RELEASE_TRUSTED_NODE_VERSION:-}"
manifest_parent="${RUNNER_TEMP:-/tmp}"
trusted_tool_records=()
tool_link_names=()
tool_link_targets=()
hashed_roots=()
if [ -x /usr/bin/realpath ]; then
  realpath_command=/usr/bin/realpath
elif [ -x /bin/realpath ]; then
  realpath_command=/bin/realpath
else
  fail "a system realpath utility is required"
fi

sha256_file() {
  local source_file="$1"
  if [ -x /usr/bin/sha256sum ]; then
    /usr/bin/sha256sum "$source_file" | /usr/bin/cut -d ' ' -f 1
  elif [ -x /usr/bin/shasum ]; then
    /usr/bin/shasum -a 256 "$source_file" | /usr/bin/awk '{ print $1 }'
  else
    fail "a system SHA-256 utility is required"
  fi
}

validate_directory() {
  local label="$1"
  local directory="$2"

  if [[ "$directory" != /* ]] || [[ "$directory" == *:* ]] || [[ "$directory" == *$'\n'* ]] \
    || [ ! -d "$directory" ] || [ -L "$directory" ]; then
    fail "$label must name an absolute real directory without PATH separators"
  fi
}

require_executable() {
  local label="$1"
  local executable="$2"
  local trusted_root="$3"
  local link_name="$4"
  local resolved_executable
  local resolved_root
  local executable_sha256

  if [ ! -e "$executable" ] || [ ! -x "$executable" ]; then
    fail "$label must be executable at $executable"
  fi
  resolved_executable="$("$realpath_command" "$executable")"
  resolved_root="$(cd "$trusted_root" && pwd -P)"
  if [ ! -f "$resolved_executable" ]; then
    fail "$label must resolve to a regular file"
  fi
  case "$resolved_executable" in
    "$resolved_root"|"$resolved_root"/*) ;;
    *) fail "$label resolves outside its trusted tool root" ;;
  esac
  if [ ! -x "$resolved_executable" ]; then
    fail "$label must resolve to an executable file"
  fi

  executable_sha256="$(sha256_file "$resolved_executable")"
  [[ "$executable_sha256" =~ ^[0-9a-f]{64}$ ]] \
    || fail "$label did not produce a valid SHA-256 identity"
  trusted_tool_records+=("${label}"$'\t'"${resolved_executable}"$'\t'"${executable_sha256}")
  tool_link_names+=("$link_name")
  tool_link_targets+=("$resolved_executable")
}

hash_tool_root() {
  local label="$1"
  local requested_root="$2"
  local resolved_root
  local existing_root
  local unsupported_object
  local root_sha256

  resolved_root="$(cd "$requested_root" && pwd -P)"
  for existing_root in "${hashed_roots[@]:-}"; do
    if [ "$existing_root" = "$resolved_root" ]; then
      return
    fi
  done
  hashed_roots+=("$resolved_root")

  validate_directory "$label root" "$resolved_root"
  unsupported_object="$(/usr/bin/find -P "$resolved_root" -mindepth 1 \
    ! -type f ! -type d ! -type l -print -quit)"
  [ -z "$unsupported_object" ] \
    || fail "$label contains an unsupported filesystem object"

  # A single archive stream binds every runtime byte, path, mode, and symlink
  # target without spawning one hashing process per Rust library or npm
  # module. The digest is compared only inside one fresh runner job, so stable
  # archive traversal is sufficient and keeps full-closure revalidation fast.
  if [ -x /usr/bin/sha256sum ]; then
    root_sha256="$(
      /usr/bin/env -i TAR_OPTIONS= /usr/bin/tar -cf - -C "$resolved_root" . \
        | /usr/bin/sha256sum | /usr/bin/cut -d ' ' -f 1
    )"
  elif [ -x /usr/bin/shasum ]; then
    root_sha256="$(
      /usr/bin/env -i TAR_OPTIONS= /usr/bin/tar -cf - -C "$resolved_root" . \
        | /usr/bin/shasum -a 256 | /usr/bin/awk '{ print $1 }'
    )"
  else
    fail "a system SHA-256 utility is required"
  fi
  trusted_tool_records+=("${label}-tree"$'\t'"${resolved_root}"$'\t'"${root_sha256}")
}

add_rust_toolchain() {
  validate_directory RELEASE_TRUSTED_CARGO_HOME "$trusted_cargo_home"
  validate_directory RELEASE_TRUSTED_RUSTUP_HOME "$trusted_rustup_home"
  [[ "$trusted_rust_toolchain" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || fail "RELEASE_TRUSTED_RUST_TOOLCHAIN must be an exact numeric Rust release"
  local rustup="$trusted_cargo_home/bin/rustup"
  local actual_cargo
  local actual_rustc
  local actual_rustdoc
  local sysroot
  require_executable rustup "$rustup" "$trusted_cargo_home" rustup

  actual_cargo="$(/usr/bin/env -i \
    CARGO_HOME="$trusted_cargo_home" \
    RUSTUP_HOME="$trusted_rustup_home" \
    RUSTUP_TOOLCHAIN="$trusted_rust_toolchain" \
    "$rustup" which --toolchain "$trusted_rust_toolchain" cargo)"
  actual_rustc="$(/usr/bin/env -i \
    CARGO_HOME="$trusted_cargo_home" \
    RUSTUP_HOME="$trusted_rustup_home" \
    RUSTUP_TOOLCHAIN="$trusted_rust_toolchain" \
    "$rustup" which --toolchain "$trusted_rust_toolchain" rustc)"
  actual_rustdoc="$(/usr/bin/env -i \
    CARGO_HOME="$trusted_cargo_home" \
    RUSTUP_HOME="$trusted_rustup_home" \
    RUSTUP_TOOLCHAIN="$trusted_rust_toolchain" \
    "$rustup" which --toolchain "$trusted_rust_toolchain" rustdoc)"
  sysroot="$(/usr/bin/env -i \
    RUSTUP_HOME="$trusted_rustup_home" \
    RUSTUP_TOOLCHAIN="$trusted_rust_toolchain" \
    "$actual_rustc" --print sysroot)"
  validate_directory "resolved Rust sysroot" "$sysroot"
  case "$(cd "$sysroot" && pwd -P)" in
    "$(cd "$trusted_rustup_home" && pwd -P)"/toolchains/*) ;;
    *) fail "resolved Rust sysroot is outside RELEASE_TRUSTED_RUSTUP_HOME/toolchains" ;;
  esac
  require_executable cargo "$actual_cargo" "$sysroot" cargo
  require_executable rustc "$actual_rustc" "$sysroot" rustc
  require_executable rustdoc "$actual_rustdoc" "$sysroot" rustdoc
  hash_tool_root rust-toolchain "$sysroot"
}

rust_toolchain_added=false
node_toolchain_added=false
for required_tool in "$@"; do
  case "$required_tool" in
    cargo)
      if [ "$rust_toolchain_added" = false ]; then
        add_rust_toolchain
        rust_toolchain_added=true
      fi
      ;;
    cargo-cyclonedx|wasm-pack)
      cargo_tool_home="${trusted_cargo_tool_home:-$trusted_cargo_home}"
      validate_directory RELEASE_TRUSTED_CARGO_TOOL_HOME "$cargo_tool_home"
      require_executable "$required_tool" "$cargo_tool_home/bin/$required_tool" "$cargo_tool_home" "$required_tool"
      ;;
    node|npm)
      if [ "$node_toolchain_added" = false ]; then
        validate_directory RELEASE_TRUSTED_NODE_ROOT "$trusted_node_root"
        if ! [[ "$trusted_node_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
          fail "RELEASE_TRUSTED_NODE_VERSION must be an exact numeric Node.js version"
        fi
        node_distribution="$trusted_node_root/$trusted_node_version/x64"
        validate_directory "release Node.js distribution" "$node_distribution"
        require_executable node "$node_distribution/bin/node" "$node_distribution" node
        require_executable npm "$node_distribution/bin/npm" "$node_distribution" npm
        actual_node_version="$(/usr/bin/env -i "$node_distribution/bin/node" --version)"
        [ "$actual_node_version" = "v$trusted_node_version" ] \
          || fail "trusted Node.js executable version does not match RELEASE_TRUSTED_NODE_VERSION"
        hash_tool_root node-distribution "$node_distribution"
        node_toolchain_added=true
      fi
      ;;
    bash)
      require_executable bash /bin/bash /bin bash
      ;;
    tar)
      require_executable tar /usr/bin/tar /usr/bin tar
      ;;
    git)
      require_executable git /usr/bin/git /usr/bin git
      ;;
    curl)
      require_executable curl /usr/bin/curl /usr/bin curl
      ;;
    *)
      fail "unsupported release tool: $required_tool"
      ;;
  esac
done

identity_manifest="$(/usr/bin/mktemp "$manifest_parent/exochain-release-tool-identity.XXXXXX")"
trap '/bin/rm -f -- "${identity_manifest:-}"' EXIT
printf '%s\n' "${trusted_tool_records[@]}" > "$identity_manifest"
trusted_identity="$(sha256_file "$identity_manifest")"
[[ "$trusted_identity" =~ ^[0-9a-f]{64}$ ]] \
  || fail "trusted release tools did not produce a valid aggregate identity"

if [ "$output_mode" = identity ]; then
  printf '%s\n' "$trusted_identity"
  exit 0
fi

validate_directory "RUNNER_TEMP" "$manifest_parent"
if [ -z "$tool_view" ]; then
  tool_view_parent="$(/usr/bin/mktemp -d "$manifest_parent/exochain-release-tool-view.XXXXXX")"
  tool_view="$tool_view_parent/bin"
fi
if [[ "$tool_view" != "$manifest_parent/"* ]] || [[ "$tool_view" == *:* ]] \
  || [[ "$tool_view" == *$'\n'* ]] || [ -e "$tool_view" ] || [ -L "$tool_view" ]; then
  fail "tool view must be a fresh absolute directory beneath RUNNER_TEMP"
fi
/bin/mkdir -m 700 -- "$tool_view"
for tool_index in "${!tool_link_names[@]}"; do
  link_name="${tool_link_names[$tool_index]}"
  link_target="${tool_link_targets[$tool_index]}"
  case "$link_name" in
    *[!A-Za-z0-9._+-]*|'') fail "tool view contains an unsafe executable name" ;;
  esac
  [ ! -e "$tool_view/$link_name" ] && [ ! -L "$tool_view/$link_name" ] \
    || fail "tool view contains a duplicate executable name: $link_name"
  /bin/ln -s -- "$link_target" "$tool_view/$link_name"
done
printf '%s\n' "$trusted_identity" > "$tool_view/.release-tool-identity"
printf '%s:/usr/bin:/bin\n' "$tool_view"
