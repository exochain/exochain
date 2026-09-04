#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly MAX_CRATES_IO_RETRY_SLEEP_SECONDS=900
crates_io_retry_seconds_slept=0
trusted_node=
trusted_python=
owner_checker_program=
source_guard_program=
tag_guard_program=
sealed_crate_publisher_program=
release_github_token=
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
    RELEASE_TOOL_HOME RELEASE_CRATE_ARCHIVE_DIR \
    RELEASE_PREFLIGHT_MANIFEST RELEASE_REPRODUCED_MANIFEST RELEASE_VERSION \
    EXPECTED_COMMIT_SHA TRUSTED_RELEASE_REF RELEASE_TAG \
    EXPECTED_TAG_OBJECT_SHA EXPECTED_TAG_COMMIT_SHA RELEASE_GITHUB_TOKEN \
    RELEASE_PYTHON RELEASE_TRUSTED_PYTHON_ROOT RELEASE_TRUSTED_PYTHON_VERSION \
    RELEASE_TRUSTED_NODE_ROOT RELEASE_TRUSTED_NODE_VERSION \
    EXOCHAIN_CRATES_IO_ALLOWED_OWNERS RELEASE_SOURCE_GUARD_PROGRAM \
    RELEASE_TAG_GUARD_PROGRAM RELEASE_OWNER_CHECK_PROGRAM \
    RELEASE_SEALED_CRATE_PUBLISHER_PROGRAM GITHUB_ACTIONS GITHUB_SERVER_URL \
    GITHUB_REPOSITORY; do
    [ -n "${!required_name:-}" ] || fail "$required_name is required"
  done
  for generated_path in \
    "$RELEASE_TOOL_HOME" "$RELEASE_CRATE_ARCHIVE_DIR" \
    "$RELEASE_PREFLIGHT_MANIFEST" "$RELEASE_REPRODUCED_MANIFEST"; do
    case "$generated_path" in
      "$RUNNER_TEMP"/*) ;;
      *) fail "generated and downloaded release paths must be beneath RUNNER_TEMP" ;;
    esac
  done
  /bin/rm -rf -- "$RELEASE_TOOL_HOME"
  /bin/mkdir -m 700 -p -- "$RELEASE_TOOL_HOME"
  [ -d "$RELEASE_CRATE_ARCHIVE_DIR" ] && [ ! -L "$RELEASE_CRATE_ARCHIVE_DIR" ] \
    || fail "sealed crate archive directory must be one real directory"

  trusted_tool_view="${TRUSTED_RELEASE_PATH%%:*}"
  case "$trusted_tool_view" in
    "$RUNNER_TEMP"/*) ;;
    *) fail "trusted release tool view must be beneath RUNNER_TEMP" ;;
  esac
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
  source_guard_program="$RELEASE_SOURCE_GUARD_PROGRAM"
  tag_guard_program="$RELEASE_TAG_GUARD_PROGRAM"
  sealed_crate_publisher_program="$RELEASE_SEALED_CRATE_PUBLISHER_PROGRAM"
  release_github_token="$RELEASE_GITHUB_TOKEN"
  verify_live_release_binding
  unset RELEASE_SOURCE_GUARD_PROGRAM RELEASE_TAG_GUARD_PROGRAM \
    RELEASE_OWNER_CHECK_PROGRAM RELEASE_SEALED_CRATE_PUBLISHER_PROGRAM \
    RELEASE_GITHUB_TOKEN

  # Capture every validated checksum in parent-shell memory before the first
  # irreversible registry operation. Later attempts never reopen a downloaded
  # manifest that a detached process could replace.
  local captured_crate
  local captured_version
  local captured_archive_checksum
  local captured_member_checksum
  local captured_manifest_rows
  if ! captured_manifest_rows="$(
    validate_release_manifests \
      "$RELEASE_PREFLIGHT_MANIFEST" \
      "$RELEASE_REPRODUCED_MANIFEST" \
      "$RELEASE_VERSION"
  )"; then
    fail "release manifests could not be securely captured"
  fi

  # The validator emits the exact bytes it securely opened and compared. Do
  # not reopen either downloaded path after validation: a detached process
  # could otherwise replace both the manifest and its paired archive between
  # the check and this in-memory capture.
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
  done <<< "$captured_manifest_rows"
  [ "${#expected_checksum_crates[@]}" -eq "${#CRATES[@]}" ] \
    || fail "publisher checksum capture is incomplete"
  readonly -a expected_checksum_crates expected_checksum_values
  validate_sealed_archive_inventory \
    "$RELEASE_CRATE_ARCHIVE_DIR" "$RELEASE_VERSION" "${CRATES[@]}"
  captured_manifest_rows=
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

verify_live_release_binding() {
  [ -n "$source_guard_program" ] && [ -n "$tag_guard_program" ] \
    && [ -n "$release_github_token" ] \
    || fail "captured release binding inputs are unavailable"
  printf '%s' "$source_guard_program" | /usr/bin/env -i \
    EXPECTED_COMMIT_SHA="$EXPECTED_COMMIT_SHA" \
    GITHUB_SHA="$GITHUB_SHA" GITHUB_WORKSPACE="$GITHUB_WORKSPACE" \
    RUNNER_TEMP="$RUNNER_TEMP" \
    TRUSTED_RELEASE_REF="$TRUSTED_RELEASE_REF" \
    /bin/bash --noprofile --norc -p
  printf '%s' "$tag_guard_program" | /usr/bin/env -i \
    DRY_RUN=false RELEASE_TAG="$RELEASE_TAG" \
    EXPECTED_TAG_OBJECT_SHA="$EXPECTED_TAG_OBJECT_SHA" \
    EXPECTED_TAG_COMMIT_SHA="$EXPECTED_TAG_COMMIT_SHA" \
    EXPECTED_COMMIT_SHA="$EXPECTED_COMMIT_SHA" \
    GITHUB_SHA="$GITHUB_SHA" GITHUB_WORKSPACE="$GITHUB_WORKSPACE" \
    GITHUB_ACTIONS="$GITHUB_ACTIONS" \
    GITHUB_SERVER_URL="$GITHUB_SERVER_URL" \
    GITHUB_REPOSITORY="$GITHUB_REPOSITORY" \
    RELEASE_GITHUB_TOKEN="$release_github_token" \
    /bin/bash --noprofile --norc -p
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
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        reject(f"{label} manifest cannot be opened without symlink protection")
    flags |= nofollow
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        reject(f"{label} manifest is unavailable: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            reject(f"{label} manifest must be one regular file")
        if before.st_nlink != 1:
            reject(f"{label} manifest must be non-hardlinked")
        if before.st_size <= 0 or before.st_size > 16 * 1024:
            reject(f"{label} manifest has an invalid size")
        remaining = before.st_size
        chunks = []
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                reject(f"{label} manifest was truncated while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            reject(f"{label} manifest grew while it was read")
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev", "st_ino", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            reject(f"{label} manifest changed while it was read")
        data = b"".join(chunks)
    finally:
        os.close(descriptor)
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
sys.stdout.buffer.write(preflight)
PY
}

validate_sealed_archive_inventory() {
  local archive_directory="$1"
  local expected_version="$2"
  shift 2
  /usr/bin/env -i "$trusted_python" -I -B - \
    "$archive_directory" "$expected_version" "$@" <<'PY'
import os
import stat
import sys


def reject(message: str) -> None:
    raise SystemExit(f"crate publication failed: {message}")


directory, version, *crates = sys.argv[1:]
expected = sorted(f"{crate}-{version}.crate" for crate in crates)
try:
    directory_metadata = os.lstat(directory)
except OSError as error:
    reject(f"sealed crate archive directory is unavailable: {error}")
if not stat.S_ISDIR(directory_metadata.st_mode):
    reject("sealed crate archive path must be one non-symlink directory")
try:
    entries = list(os.scandir(directory))
except OSError as error:
    reject(f"sealed crate archive directory is unreadable: {error}")
actual = sorted(entry.name for entry in entries)
if actual != expected:
    reject("sealed crate archive inventory is missing or contains an unexpected entry")
for entry in entries:
    try:
        metadata = entry.stat(follow_symlinks=False)
    except OSError as error:
        reject(f"sealed crate archive entry is unavailable: {error}")
    if not stat.S_ISREG(metadata.st_mode) or entry.is_symlink():
        reject(f"sealed crate archive entry must be regular: {entry.name!r}")
    if metadata.st_nlink != 1:
        reject(f"sealed crate archive entry must be non-hardlinked: {entry.name!r}")
    if metadata.st_size <= 0 or metadata.st_size > 10 * 1024 * 1024:
        reject(f"sealed crate archive entry has an invalid size: {entry.name!r}")
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
nofollow = getattr(os, "O_NOFOLLOW", 0)
if not isinstance(nofollow, int) or nofollow == 0:
    reject("crates.io response cannot be opened safely because O_NOFOLLOW is unavailable")
flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow
try:
    descriptor = os.open(response_path, flags)
except OSError as error:
    reject(f"crates.io response cannot be securely opened: {error}")
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        reject("crates.io response must be one regular file")
    if before.st_nlink != 1:
        reject("crates.io response must be non-hardlinked")
    if before.st_size <= 0 or before.st_size > 1024 * 1024:
        reject("crates.io response has an invalid size")
    chunks = []
    remaining = before.st_size
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            reject("crates.io response was truncated while it was read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        reject("crates.io response grew while it was read")
    after = os.fstat(descriptor)
    stable_fields = ("st_dev", "st_ino", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if tuple(getattr(before, field) for field in stable_fields) != tuple(
        getattr(after, field) for field in stable_fields
    ):
        reject("crates.io response changed while it was read")
    response_bytes = b"".join(chunks)
finally:
    os.close(descriptor)


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
    response = json.loads(
        response_bytes,
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
      verify_live_release_binding
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

release_sealed_crate_publish() (
  local crate="$1"
  local expected_checksum="$2"
  local archive="$RELEASE_CRATE_ARCHIVE_DIR/${crate}-${RELEASE_VERSION}.crate"

  # The captured helper reads and validates the sealed archive completely into
  # memory before it opens a TLS connection. The irreversible path never reads
  # GITHUB_WORKSPACE and therefore cannot repackage post-guard mutations.
  printf '%s' "$sealed_crate_publisher_program" | /usr/bin/env -i \
    CARGO_REGISTRY_TOKEN="$cargo_registry_token" \
    LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONHASHSEED=0 TZ=UTC \
    "$trusted_python" -I -B - \
      "$archive" "$crate" "$RELEASE_VERSION" \
      "$expected_checksum" "$EXPECTED_COMMIT_SHA"
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

release_retry_sleep() {
  /bin/sleep "$1"
}

publish_crate_with_retry() {
  local crate="$1"
  local expected_checksum="$2"
  local attempt=1
  local max_attempts=6
  local output
  local status
  local retry_seconds
  local published_status

  while [ "$attempt" -le "$max_attempts" ]; do
    # This captured, self-contained checker receives neither registry token.
    # It is repeated immediately before every irreversible attempt, including
    # the first attempt after a bounded rate-limit sleep.
    verify_crate_ownership "$crate" \
      || fail "crates.io ownership changed before publishing $crate"
    # Revalidate the exact checked-out source and immutable signed remote tag
    # after all retry delays and immediately before handing the registry token
    # to the sealed-archive uploader. The guard bodies were captured from the
    # approved commit.
    verify_live_release_binding
    if output="$(release_sealed_crate_publish "$crate" "$expected_checksum" 2>&1)"; then
      status=0
    else
      status=$?
    fi
    printf '%s\n' "$output"
    if [ "$status" -eq 0 ]; then
      poll_for_expected_checksum "$crate" "$expected_checksum"
      return
    fi

    if [ "$status" -eq 75 ] \
        && /usr/bin/grep -F 'status 429 ' <<<"$output" >/dev/null; then
      if query_crate_version "$crate" "$expected_checksum"; then
        verify_crate_ownership "$crate" require-claimed \
          || fail "crates.io ownership changed after recovering published $crate"
        verify_live_release_binding
        echo "${crate} ${RELEASE_VERSION} has the exact preflight checksum; continuing after status ${status}."
        return 0
      else
        published_status=$?
        [ "$published_status" -eq 1 ] || return "$published_status"
      fi
      [ "$attempt" -lt "$max_attempts" ] \
        || fail "failed to publish ${crate} after ${max_attempts} attempts"
      retry_seconds=$((attempt * 120))
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
      release_retry_sleep "$retry_seconds"
      attempt=$((attempt + 1))
      continue
    fi

    # Once the uploader begins its PUT, a lost TLS response, registry 5xx, or
    # malformed success response cannot prove whether crates.io committed the
    # immutable version. Poll the exact checksum to convergence and never send
    # a second PUT for an outcome-unknown attempt. A later workflow rerun is
    # safely resumable through the same checksum check.
    if poll_for_expected_checksum "$crate" "$expected_checksum"; then
      echo "${crate} ${RELEASE_VERSION} has the exact preflight checksum; continuing after status ${status}."
      return 0
    else
      published_status=$?
      [ "$published_status" -eq 1 ] || return "$published_status"
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
      verify_live_release_binding
      echo "${crate} ${RELEASE_VERSION} is already published with the exact preflight checksum; skipping."
      continue
    else
      published_status=$?
      [ "$published_status" -eq 1 ] || exit "$published_status"
    fi
    publish_crate_with_retry "$crate" "$expected_checksum"
  done
  source_guard_program=
  tag_guard_program=
  sealed_crate_publisher_program=
  release_github_token=
  owner_checker_program=
  cargo_registry_token=
  printf 'Published or verified %s dependency-ordered crates\n' "${#CRATES[@]}"
}

main "$@"
