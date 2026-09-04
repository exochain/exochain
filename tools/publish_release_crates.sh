#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly MAX_CRATES_IO_RETRY_SLEEP_SECONDS=900
crates_io_retry_seconds_slept=0
trusted_cargo=
trusted_rustc=
trusted_rustdoc=
trusted_node=
trusted_python=
owner_checker_program=
expected_checksum_crates=()
expected_checksum_values=()

fail() {
  printf 'crate publication failed: %s\n' "$1" >&2
  exit 1
}

initialize_release_publication() {
  if /usr/bin/env | /usr/bin/grep -Eq '^BASH_FUNC_.*%%='; then
    fail "inherited shell functions are forbidden"
  fi
  [ -n "${CARGO_REGISTRY_TOKEN:-}" ] \
    || fail "CARGO_REGISTRY_TOKEN is required only for live crate publication"
  cargo_registry_token="$CARGO_REGISTRY_TOKEN"
  unset CARGO_REGISTRY_TOKEN

  for required_name in \
    GITHUB_WORKSPACE GITHUB_SHA RUNNER_TEMP TRUSTED_RELEASE_PATH \
    RELEASE_TRUSTED_CARGO_HOME RELEASE_TRUSTED_RUSTUP_HOME \
    RELEASE_TRUSTED_RUST_TOOLCHAIN \
    RELEASE_CARGO_HOME RELEASE_TOOL_HOME RELEASE_TARGET_DIR \
    RELEASE_PREFLIGHT_MANIFEST RELEASE_REPRODUCED_MANIFEST RELEASE_VERSION \
    EXPECTED_COMMIT_SHA TRUSTED_RELEASE_REF RELEASE_TAG \
    EXPECTED_TAG_OBJECT_SHA EXPECTED_TAG_COMMIT_SHA RELEASE_GITHUB_TOKEN \
    RELEASE_PYTHON RELEASE_TRUSTED_PYTHON_ROOT RELEASE_TRUSTED_PYTHON_VERSION \
    RELEASE_TRUSTED_NODE_ROOT RELEASE_TRUSTED_NODE_VERSION \
    EXOCHAIN_CRATES_IO_ALLOWED_OWNERS RELEASE_SOURCE_GUARD_PROGRAM \
    RELEASE_TAG_GUARD_PROGRAM RELEASE_CARGO_CONFIG_GUARD_PROGRAM \
    RELEASE_OWNER_CHECK_PROGRAM GITHUB_ACTIONS GITHUB_SERVER_URL \
    GITHUB_REPOSITORY; do
    [ -n "${!required_name:-}" ] || fail "$required_name is required"
  done
  for generated_path in \
    "$RELEASE_CARGO_HOME" "$RELEASE_TOOL_HOME" "$RELEASE_TARGET_DIR" \
    "$RELEASE_PREFLIGHT_MANIFEST" "$RELEASE_REPRODUCED_MANIFEST"; do
    case "$generated_path" in
      "$RUNNER_TEMP"/*) ;;
      *) fail "generated and downloaded release paths must be beneath RUNNER_TEMP" ;;
    esac
  done
  for clean_directory in \
    "$RELEASE_CARGO_HOME" "$RELEASE_TOOL_HOME" "$RELEASE_TARGET_DIR"; do
    /bin/rm -rf -- "$clean_directory"
    /bin/mkdir -m 700 -p -- "$clean_directory"
  done

  trusted_tool_view="${TRUSTED_RELEASE_PATH%%:*}"
  case "$trusted_tool_view" in
    "$RUNNER_TEMP"/*) ;;
    *) fail "trusted release tool view must be beneath RUNNER_TEMP" ;;
  esac
  trusted_cargo="$(/usr/bin/realpath "$trusted_tool_view/cargo")"
  trusted_rustc="$(/usr/bin/realpath "$trusted_tool_view/rustc")"
  trusted_rustdoc="$(/usr/bin/realpath "$trusted_tool_view/rustdoc")"
  [ -x "$trusted_cargo" ] && [ -x "$trusted_rustc" ] && [ -x "$trusted_rustdoc" ] \
    || fail "trusted release tool view lacks Cargo, rustc, or rustdoc"

  trusted_python="$(/usr/bin/realpath "$RELEASE_PYTHON")"
  trusted_python_root="$(cd "$RELEASE_TRUSTED_PYTHON_ROOT" && pwd -P)"
  case "$trusted_python" in
    "$trusted_python_root"/*) ;;
    *) fail "release Python is outside the trusted tool-cache root" ;;
  esac
  [ -f "$trusted_python" ] && [ -x "$trusted_python" ] && [ ! -L "$trusted_python" ] \
    || fail "release Python must be one executable regular file"
  [ "$(/usr/bin/env -i "$trusted_python" -I -B -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')" = "$RELEASE_TRUSTED_PYTHON_VERSION" ] \
    || fail "release Python version differs from the pinned runtime"

  trusted_node="$(/usr/bin/realpath "$trusted_tool_view/node")"
  trusted_node_root="$(cd "$RELEASE_TRUSTED_NODE_ROOT" && pwd -P)"
  case "$trusted_node" in
    "$trusted_node_root"/*) ;;
    *) fail "release Node.js is outside the trusted tool-cache root" ;;
  esac
  [ -f "$trusted_node" ] && [ -x "$trusted_node" ] && [ ! -L "$trusted_node" ] \
    || fail "release Node.js must be one executable regular file"
  [ "$(/usr/bin/env -i "$trusted_node" --version)" = "v${RELEASE_TRUSTED_NODE_VERSION}" ] \
    || fail "release Node.js version differs from the pinned runtime"

  owner_checker_program="$RELEASE_OWNER_CHECK_PROGRAM"
  printf '%s' "$RELEASE_SOURCE_GUARD_PROGRAM" | /usr/bin/env -i \
    EXPECTED_COMMIT_SHA="$EXPECTED_COMMIT_SHA" \
    GITHUB_SHA="$GITHUB_SHA" GITHUB_WORKSPACE="$GITHUB_WORKSPACE" \
    RUNNER_TEMP="$RUNNER_TEMP" \
    TRUSTED_RELEASE_REF="$TRUSTED_RELEASE_REF" \
    /bin/bash --noprofile --norc -p
  printf '%s' "$RELEASE_TAG_GUARD_PROGRAM" | /usr/bin/env -i \
    DRY_RUN=false RELEASE_TAG="$RELEASE_TAG" \
    EXPECTED_TAG_OBJECT_SHA="$EXPECTED_TAG_OBJECT_SHA" \
    EXPECTED_TAG_COMMIT_SHA="$EXPECTED_TAG_COMMIT_SHA" \
    EXPECTED_COMMIT_SHA="$EXPECTED_COMMIT_SHA" \
    GITHUB_SHA="$GITHUB_SHA" GITHUB_WORKSPACE="$GITHUB_WORKSPACE" \
    GITHUB_ACTIONS="$GITHUB_ACTIONS" \
    GITHUB_SERVER_URL="$GITHUB_SERVER_URL" \
    GITHUB_REPOSITORY="$GITHUB_REPOSITORY" \
    RELEASE_GITHUB_TOKEN="$RELEASE_GITHUB_TOKEN" \
    /bin/bash --noprofile --norc -p
  printf '%s' "$RELEASE_CARGO_CONFIG_GUARD_PROGRAM" | /usr/bin/env -i \
    GITHUB_WORKSPACE="$GITHUB_WORKSPACE" /bin/bash --noprofile --norc -p
  unset RELEASE_SOURCE_GUARD_PROGRAM RELEASE_TAG_GUARD_PROGRAM \
    RELEASE_CARGO_CONFIG_GUARD_PROGRAM RELEASE_OWNER_CHECK_PROGRAM \
    RELEASE_GITHUB_TOKEN

  validate_release_manifests \
    "$RELEASE_PREFLIGHT_MANIFEST" \
    "$RELEASE_REPRODUCED_MANIFEST" \
    "$RELEASE_VERSION"

  # Capture every already-validated checksum in parent-shell memory before the
  # first irreversible registry operation. Later attempts never reopen a
  # downloaded manifest that a detached process could replace.
  local captured_crate
  local captured_version
  local captured_archive_checksum
  local captured_member_checksum
  while IFS=$'\t' read -r captured_crate captured_version \
      captured_archive_checksum captured_member_checksum; do
    [ -n "$captured_crate" ] \
      || fail "publisher checksum capture contains an empty crate"
    case " ${expected_checksum_crates[*]} " in
      *" $captured_crate "*) fail "publisher checksum capture contains a duplicate crate" ;;
    esac
    [ "$captured_version" = "$RELEASE_VERSION" ] \
      && [[ "$captured_archive_checksum" =~ ^[0-9a-f]{64}$ ]] \
      && [[ "$captured_member_checksum" =~ ^[0-9a-f]{64}$ ]] \
      || fail "publisher checksum capture differs from the validated release"
    expected_checksum_crates+=("$captured_crate")
    expected_checksum_values+=("$captured_archive_checksum")
  done < "$RELEASE_PREFLIGHT_MANIFEST"
  [ "${#expected_checksum_crates[@]}" -eq "${#CRATES[@]}" ] \
    || fail "publisher checksum capture is incomplete"
  readonly -a expected_checksum_crates expected_checksum_values
  unset RELEASE_PREFLIGHT_MANIFEST RELEASE_REPRODUCED_MANIFEST

  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR \
    GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG \
    GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM GIT_CONFIG_COUNT \
    GIT_CONFIG_PARAMETERS GIT_CEILING_DIRECTORIES \
    GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_NAMESPACE GIT_REPLACE_REF_BASE \
    GIT_NO_REPLACE_OBJECTS GIT_SHALLOW_FILE GIT_GRAFT_FILE GIT_EXEC_PATH \
    GIT_EXTERNAL_DIFF GIT_DIFF_OPTS GIT_ATTR_SOURCE
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    GIT_NO_REPLACE_OBJECTS=1
}

validate_release_manifests() {
  local preflight_manifest="$1"
  local reproduced_manifest="$2"
  local expected_version="$3"
  /usr/bin/env -i "$trusted_python" -I -B - \
    "$preflight_manifest" "$reproduced_manifest" "$expected_version" \
    "${CRATES[@]}" <<'PY'
import os
import re
import stat
import sys


def reject(message: str) -> None:
    raise SystemExit(f"crate publication failed: {message}")


preflight_path, reproduced_path, expected_version, *expected_crates = sys.argv[1:]
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected_version):
    reject("release version must contain exactly three numeric components")
if len(expected_crates) != 32 or len(set(expected_crates)) != 32:
    reject("publisher must declare exactly 32 unique release crates")


def read_manifest(path: str, label: str) -> bytes:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        reject(f"{label} manifest is unavailable: {error}")
    if not stat.S_ISREG(metadata.st_mode):
        reject(f"{label} manifest must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > 16 * 1024:
        reject(f"{label} manifest has an invalid size")
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        reject(f"{label} manifest is unreadable: {error}")
    if not data.endswith(b"\n") or b"\r" in data:
        reject(f"{label} manifest must end with one complete row")
    lines = data[:-1].split(b"\n")
    if len(lines) != 32:
        reject(f"{label} manifest must contain exactly 32 rows")
    for index, (line, expected_crate) in enumerate(zip(lines, expected_crates)):
        fields = line.split(b"\t")
        if len(fields) != 4:
            reject(f"{label} manifest row {index + 1} must contain four fields")
        try:
            crate, version, archive_hash, member_hash = (
                field.decode("ascii") for field in fields
            )
        except UnicodeDecodeError:
            reject(f"{label} manifest row {index + 1} must be ASCII")
        if crate != expected_crate:
            reject(f"{label} manifest crate order or set is invalid")
        if version != expected_version:
            reject(f"{label} manifest contains a wrong crate version")
        if re.fullmatch(r"[0-9a-f]{64}", archive_hash) is None:
            reject(f"{label} manifest contains an invalid archive checksum")
        if re.fullmatch(r"[0-9a-f]{64}", member_hash) is None:
            reject(f"{label} manifest contains an invalid member checksum")
    return data


preflight = read_manifest(preflight_path, "token-free preflight")
reproduced = read_manifest(reproduced_path, "publisher reproduction")
if preflight != reproduced:
    reject("fresh publisher packages differ from token-free preflight archives")
PY
}

expected_archive_checksum() {
  local crate="$1"
  local checksum=
  local index
  for ((index = 0; index < ${#expected_checksum_crates[@]}; index += 1)); do
    if [ "${expected_checksum_crates[$index]}" = "$crate" ]; then
      checksum="${expected_checksum_values[$index]}"
      break
    fi
  done
  [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] \
    || fail "preflight manifest has no exact archive checksum for $crate"
  printf '%s\n' "$checksum"
}

validate_crates_io_response() {
  local response_file="$1"
  local expected_crate="$2"
  local expected_version="$3"
  local expected_checksum="$4"
  /usr/bin/env -i "$trusted_python" -I -B - \
    "$response_file" "$expected_crate" "$expected_version" \
    "$expected_checksum" <<'PY'
import json
import os
import re
import stat
import sys


def reject(message: str) -> None:
    raise SystemExit(f"crate publication failed: {message}")


response_path, expected_crate, expected_version, expected_checksum = sys.argv[1:]
if re.fullmatch(r"[a-z0-9_-]+", expected_crate) is None:
    reject("expected crate name is invalid")
if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected_version) is None:
    reject("expected crate version is invalid")
if re.fullmatch(r"[0-9a-f]{64}", expected_checksum) is None:
    reject("expected archive checksum is invalid")
try:
    metadata = os.lstat(response_path)
except OSError as error:
    reject(f"crates.io response is unavailable: {error}")
if not stat.S_ISREG(metadata.st_mode):
    reject("crates.io response must be a regular non-symlink file")
if metadata.st_size <= 0 or metadata.st_size > 1024 * 1024:
    reject("crates.io response has an invalid size")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject(f"crates.io response contains duplicate JSON key {key!r}")
        result[key] = value
    return result


def invalid_constant(value: str):
    reject(f"crates.io response contains invalid JSON constant {value!r}")


try:
    with open(response_path, "r", encoding="utf-8") as handle:
        response = json.load(
            handle,
            object_pairs_hook=unique_object,
            parse_constant=invalid_constant,
        )
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    reject(f"crates.io response is malformed: {error}")
if not isinstance(response, dict) or not isinstance(response.get("version"), dict):
    reject("crates.io response lacks one version object")
version = response["version"]
if version.get("crate") != expected_crate:
    reject("crates.io response crate identity does not match the release crate")
if version.get("num") != expected_version:
    reject("crates.io response version does not match the release version")
if version.get("yanked") is not False:
    reject("crates.io response must identify an unyanked release version")
checksum = version.get("checksum")
if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
    reject("crates.io response contains an invalid archive checksum")
if checksum != expected_checksum:
    reject("crates.io archive checksum does not match the preflight candidate")
PY
}

perform_crates_io_request() {
  local curl_binary="$1"
  local response_file="$2"
  local crate="$3"
  local version="$4"
  /usr/bin/env -i "$curl_binary" \
    -q \
    --proto '=https' \
    --tlsv1.2 \
    --silent \
    --show-error \
    --connect-timeout 15 \
    --max-time 60 \
    --max-filesize 1048576 \
    --retry 3 \
    --retry-delay 2 \
    --retry-max-time 30 \
    --retry-all-errors \
    --header 'User-Agent: exochain-release-workflow (https://github.com/exochain/exochain)' \
    --output "$response_file" \
    --write-out '%{http_code}' \
    "https://crates.io/api/v1/crates/${crate}/${version}"
}

query_crate_version() {
  local crate="$1"
  local expected_checksum="$2"
  local response_file
  local http_code
  local request_status
  response_file="$(/usr/bin/mktemp "$RUNNER_TEMP/exochain-crates-response.XXXXXX")"
  if http_code="$(
    perform_crates_io_request \
      /usr/bin/curl "$response_file" "$crate" "$RELEASE_VERSION"
  )"; then
    request_status=0
  else
    request_status=$?
  fi
  if [ "$request_status" -ne 0 ]; then
    /bin/rm -f -- "$response_file"
    echo "Secure crates.io request failed for ${crate}: curl status ${request_status}." >&2
    return 2
  fi
  case "$http_code" in
    200)
      if validate_crates_io_response \
          "$response_file" "$crate" "$RELEASE_VERSION" "$expected_checksum"; then
        /bin/rm -f -- "$response_file"
        return 0
      fi
      /bin/rm -f -- "$response_file"
      return 2
      ;;
    404)
      /bin/rm -f -- "$response_file"
      return 1
      ;;
    *)
      echo "Unexpected crates.io response for ${crate} ${RELEASE_VERSION}: HTTP ${http_code}" >&2
      /bin/rm -f -- "$response_file"
      return 2
      ;;
  esac
}

poll_for_expected_checksum() {
  local crate="$1"
  local expected_checksum="$2"
  local max_attempts="${3:-20}"
  local delay_seconds="${4:-15}"
  local attempt=1
  local query_status
  case "$max_attempts" in
    ''|*[!0-9]*) fail "checksum poll attempts must be numeric" ;;
  esac
  case "$delay_seconds" in
    ''|*[!0-9]*) fail "checksum poll delay must be numeric" ;;
  esac
  [ "$max_attempts" -ge 1 ] && [ "$max_attempts" -le 25 ] \
    || fail "checksum poll attempts must be between 1 and 25"
  [ "$delay_seconds" -le 300 ] \
    || fail "checksum poll delay must not exceed 300 seconds"

  while [ "$attempt" -le "$max_attempts" ]; do
    if query_crate_version "$crate" "$expected_checksum"; then
      verify_crate_ownership "$crate" require-claimed \
        || fail "crates.io ownership changed after observing $crate"
      return 0
    else
      query_status=$?
    fi
    [ "$query_status" -eq 1 ] || return "$query_status"
    if [ "$attempt" -lt "$max_attempts" ]; then
      /bin/sleep "$delay_seconds"
    fi
    attempt=$((attempt + 1))
  done
  echo "Exact crates.io checksum for ${crate} ${RELEASE_VERSION} was not visible after ${max_attempts} attempts." >&2
  return 1
}

verify_crate_ownership() {
  local crate="$1"
  local ownership_mode="${2:-allow-unclaimed}"
  local fixture_arguments=()
  local claimed_arguments=()
  case "$ownership_mode" in
    allow-unclaimed) ;;
    require-claimed)
      claimed_arguments=(EXOCHAIN_CRATES_IO_REQUIRE_CLAIMED=true)
      ;;
    *) fail "invalid crates.io ownership verification mode" ;;
  esac
  if [ -n "${EXOCHAIN_CRATES_IO_FIXTURE_DIR:-}" ]; then
    fixture_arguments=(EXOCHAIN_CRATES_IO_FIXTURE_DIR="$EXOCHAIN_CRATES_IO_FIXTURE_DIR")
  fi
  printf '%s' "$owner_checker_program" | /usr/bin/env -i \
    PATH="$TRUSTED_RELEASE_PATH" \
    HOME="$RELEASE_TOOL_HOME" \
    EXOCHAIN_CRATES_IO_ALLOWED_OWNERS="$EXOCHAIN_CRATES_IO_ALLOWED_OWNERS" \
    EXOCHAIN_CRATES_IO_EXACT_TARGET="$crate" \
    "${claimed_arguments[@]}" \
    "${fixture_arguments[@]}" \
    "$trusted_node" --input-type=module - >/dev/null
}

release_cargo_publish() (
  # An absolute manifest path does not prevent Cargo from discovering project
  # configuration relative to its invocation directory. Run from the verified
  # config-free filesystem root and name every compiler entry point explicitly.
  cd /
  /usr/bin/env -i \
    PATH="$TRUSTED_RELEASE_PATH" \
    HOME="$RELEASE_TOOL_HOME" \
    CARGO_HOME="$RELEASE_CARGO_HOME" \
    RUSTUP_HOME="$RELEASE_TRUSTED_RUSTUP_HOME" \
    RUSTUP_TOOLCHAIN="$RELEASE_TRUSTED_RUST_TOOLCHAIN" \
    RUSTC="$trusted_rustc" \
    RUSTDOC="$trusted_rustdoc" \
    RUSTC_WRAPPER= \
    RUSTC_WORKSPACE_WRAPPER= \
    CARGO_TARGET_DIR="$RELEASE_TARGET_DIR" \
    CARGO_TERM_COLOR=always \
    CARGO_NET_RETRY=10 \
    CARGO_HTTP_TIMEOUT=120 \
    CARGO_HTTP_MULTIPLEXING=false \
    CARGO_REGISTRY_TOKEN="$cargo_registry_token" \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_REGISTRY_DEFAULT=crates-io \
    TZ=UTC LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    "$trusted_cargo" publish \
      --manifest-path "$GITHUB_WORKSPACE/Cargo.toml" \
      -p "$1" \
      --no-verify \
      --locked \
      --registry crates-io
)

bounded_retry_seconds() {
  local candidate="$1"

  [[ "$candidate" =~ ^-?[0-9]+$ ]] \
    || fail "crates.io retry delay is not an integer"
  if [ "$candidate" -lt 60 ]; then
    candidate=60
  elif [ "$candidate" -gt 300 ]; then
    candidate=300
  fi
  printf '%s\n' "$candidate"
}

retry_seconds_until_epoch() {
  local retry_epoch="$1"
  local now_epoch="$2"

  [[ "$retry_epoch" =~ ^-?[0-9]+$ ]] \
    || fail "crates.io Retry-After epoch is not an integer"
  [[ "$now_epoch" =~ ^-?[0-9]+$ ]] \
    || fail "current epoch is not an integer"
  bounded_retry_seconds "$((retry_epoch - now_epoch + 15))"
}

retry_seconds_within_budget() {
  local candidate="$1"
  local seconds_already_slept="$2"
  local bounded
  local remaining

  [[ "$seconds_already_slept" =~ ^[0-9]+$ ]] \
    || fail "cumulative crates.io retry delay is not a non-negative integer"
  bounded="$(bounded_retry_seconds "$candidate")"
  remaining=$((MAX_CRATES_IO_RETRY_SLEEP_SECONDS - seconds_already_slept))
  [ "$remaining" -gt 0 ] || return 1
  if [ "$bounded" -gt "$remaining" ]; then
    bounded="$remaining"
  fi
  printf '%s\n' "$bounded"
}

publish_crate_with_retry() {
  local crate="$1"
  local expected_checksum="$2"
  local attempt=1
  local max_attempts=6
  local output
  local status
  local retry_after
  local retry_epoch
  local now_epoch
  local retry_seconds
  local published_status

  while [ "$attempt" -le "$max_attempts" ]; do
    # This captured, self-contained checker receives neither registry token.
    # It is repeated immediately before every irreversible attempt, including
    # the first attempt after a bounded rate-limit sleep.
    verify_crate_ownership "$crate" \
      || fail "crates.io ownership changed before publishing $crate"
    if output="$(release_cargo_publish "$crate" 2>&1)"; then
      status=0
    else
      status=$?
    fi
    printf '%s\n' "$output"
    if [ "$status" -eq 0 ]; then
      poll_for_expected_checksum "$crate" "$expected_checksum"
      return
    fi

    if query_crate_version "$crate" "$expected_checksum"; then
      verify_crate_ownership "$crate" require-claimed \
        || fail "crates.io ownership changed after recovering published $crate"
      echo "${crate} ${RELEASE_VERSION} has the exact preflight checksum; continuing after status ${status}."
      return 0
    else
      published_status=$?
      [ "$published_status" -eq 1 ] || return "$published_status"
    fi
    if /usr/bin/grep -F 'status 429 Too Many Requests' <<<"$output" >/dev/null; then
      [ "$attempt" -lt "$max_attempts" ] \
        || fail "failed to publish ${crate} after ${max_attempts} attempts"
      retry_after="$(
        /usr/bin/sed -nE 's/.*try again after (.* GMT) and see.*/\1/p' <<<"$output" \
          | /usr/bin/tail -n 1
      )"
      if [ -n "$retry_after" ]; then
        retry_epoch="$(/usr/bin/date -u -d "$retry_after" +%s)"
        now_epoch="$(/usr/bin/date -u +%s)"
        retry_seconds="$(retry_seconds_until_epoch "$retry_epoch" "$now_epoch")"
      else
        retry_seconds=$((attempt * 120))
      fi
      if ! retry_seconds="$(
        retry_seconds_within_budget \
          "$retry_seconds" "$crates_io_retry_seconds_slept"
      )"; then
        fail "crates.io retry sleep budget exhausted for ${crate}"
      fi
      crates_io_retry_seconds_slept=$((
        crates_io_retry_seconds_slept + retry_seconds
      ))
      echo "crates.io rate limit for ${crate}; sleeping ${retry_seconds}s."
      /bin/sleep "$retry_seconds"
      attempt=$((attempt + 1))
      continue
    fi
    return "$status"
  done
  fail "failed to publish ${crate} after ${max_attempts} attempts"
}

CRATES=(
  exochain-core
  exochain-dag-db-api
  exochain-identity
  exochain-api
  exochain-authority
  exochain-pdp
  exochain-avc
  exochain-consent
  exochain-dag-db-core
  exochain-dag-db-graph
  exochain-dag-db-domain
  exochain-dag-db-retrieval
  exochain-dag-db-exchange
  exochain-dag
  exochain-dag-db-postgres
  exochain-gatekeeper
  exochain-proofs
  exochain-governance
  exochain-escalation
  exochain-tenant
  exochain-catapult
  exochain-legal
  exochain-decision-forum
  exochain-consensus
  exochain-dag-db-lab
  exochain-economy
  exochain-gateway
  exochain-messaging
  exochain-root
  exochain-sdk
  exochain-node
  exochain-wasm
)

main() {
  local crate
  local expected_checksum
  local published_status
  initialize_release_publication
  for crate in "${CRATES[@]}"; do
    expected_checksum="$(expected_archive_checksum "$crate")"
    verify_crate_ownership "$crate" \
      || fail "crates.io ownership changed before deciding whether to publish $crate"
    if query_crate_version "$crate" "$expected_checksum"; then
      verify_crate_ownership "$crate" require-claimed \
        || fail "crates.io ownership changed after observing published $crate"
      echo "${crate} ${RELEASE_VERSION} is already published with the exact preflight checksum; skipping."
      continue
    else
      published_status=$?
      [ "$published_status" -eq 1 ] || exit "$published_status"
    fi
    publish_crate_with_retry "$crate" "$expected_checksum"
  done
  printf 'Published or verified %s dependency-ordered crates\n' "${#CRATES[@]}"
}

main "$@"
