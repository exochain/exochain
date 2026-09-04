#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

# Source this file only after verify_release_source.sh has accepted the checkout
# and before any package lifecycle or repository build begins. Captured bytes
# remain shell variables in that same process; they are never reloaded from the
# checkout or Git object database after untrusted code has executed.

capture_release_helper_fail() {
  printf 'release helper capture failed: %s\n' "$1" >&2
  return 1
}

capture_release_helper() {
  local helper_path="${1:-}"
  local destination_name="${2:-}"
  local release_workspace="${GITHUB_WORKSPACE:-}"
  local dispatch_sha="${GITHUB_SHA:-}"
  local expected_blob
  local captured_bytes
  local actual_blob

  if [[ "$release_workspace" != /* ]] || [ ! -d "$release_workspace" ]; then
    capture_release_helper_fail "GITHUB_WORKSPACE must name an absolute existing directory"
    return 1
  fi
  if ! [[ "$dispatch_sha" =~ ^[0-9a-f]{40}$ ]]; then
    capture_release_helper_fail "GITHUB_SHA must be a full lowercase commit SHA"
    return 1
  fi
  case "/$helper_path/" in
    //*|*/./*|*/../*|*:*|*$'\n'*)
      capture_release_helper_fail "helper path is unsafe"
      return 1
      ;;
  esac
  if [ -z "$helper_path" ] || [[ "$helper_path" == /* ]]; then
    capture_release_helper_fail "helper path must be repository relative"
    return 1
  fi
  if ! [[ "$destination_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    capture_release_helper_fail "destination must be a shell variable name"
    return 1
  fi

  expected_blob="$(
    /usr/bin/env -i \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_NO_REPLACE_OBJECTS=1 \
      /usr/bin/git --no-replace-objects \
        -c core.fsmonitor=false \
        -c core.untrackedCache=false \
        -c core.ignoreStat=false \
        -C "$release_workspace" \
        rev-parse --verify "${dispatch_sha}:${helper_path}"
  )" || return 1
  if ! [[ "$expected_blob" =~ ^[0-9a-f]{40}$ ]]; then
    capture_release_helper_fail "helper path does not resolve to one Git object"
    return 1
  fi

  captured_bytes="$(
    /usr/bin/env -i \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_NO_REPLACE_OBJECTS=1 \
      /usr/bin/git --no-replace-objects \
        -c core.fsmonitor=false \
        -c core.untrackedCache=false \
        -c core.ignoreStat=false \
        -C "$release_workspace" \
        show "${dispatch_sha}:${helper_path}"
    printf '\036'
  )" || return 1
  if [[ "$captured_bytes" != *$'\036' ]]; then
    capture_release_helper_fail "could not preserve the complete helper bytes"
    return 1
  fi
  captured_bytes="${captured_bytes%$'\036'}"
  actual_blob="$(
    printf '%s' "$captured_bytes" | \
      /usr/bin/env -i /usr/bin/git hash-object --stdin
  )" || return 1
  if [ "$actual_blob" != "$expected_blob" ]; then
    capture_release_helper_fail "Git returned helper bytes that do not match the commit object ID"
    return 1
  fi

  printf -v "$destination_name" '%s' "$captured_bytes"
}
