#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
publisher="$repo_root/tools/publish_release_crates.sh"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-crate-registry-test.XXXXXX")"
trap '/bin/rm -rf -- "$test_root"' EXIT

fail() {
  printf 'crate registry validation test failed: %s\n' "$1" >&2
  exit 1
}

publisher_prefix="$test_root/publisher-functions.sh"
/usr/bin/awk '
  /^main "\$@"$/ { found = 1; exit }
  { print }
  END { if (!found) exit 42 }
' "$publisher" > "$publisher_prefix" \
  || fail "publisher main boundary is missing"
# shellcheck source=/dev/null
source "$publisher_prefix"

if /usr/bin/grep -F 'done < "$RELEASE_PREFLIGHT_MANIFEST"' "$publisher" >/dev/null; then
  fail "publisher reopens the preflight manifest after validation"
fi
if /usr/bin/grep -F 'metadata = os.lstat(response_path)' "$publisher" >/dev/null \
    || /usr/bin/grep -F 'with open(response_path' "$publisher" >/dev/null; then
  fail "crates.io response validator separates pathname metadata from the opened bytes"
fi

trusted_python="${PYTHON:-$(command -v python3)}"
trusted_python="$($trusted_python -c 'import os,sys; print(os.path.realpath(sys.executable))')"
[ -f "$trusted_python" ] && [ -x "$trusted_python" ] && [ ! -L "$trusted_python" ] \
  || fail "a real Python interpreter is required"
"$trusted_python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
  || fail "Python 3.11 or newer is required"

declare -F validate_release_manifests >/dev/null \
  || fail "manifest validator is missing"
declare -F validate_sealed_archive_inventory >/dev/null \
  || fail "sealed archive inventory validator is missing"
declare -F validate_crates_io_response >/dev/null \
  || fail "crates.io response validator is missing"
declare -F poll_for_expected_checksum >/dev/null \
  || fail "post-upload checksum poller is missing"
declare -F perform_crates_io_request >/dev/null \
  || fail "secure crates.io request boundary is missing"
declare -F bounded_retry_seconds >/dev/null \
  || fail "bounded crates.io retry delay is missing"
declare -F retry_seconds_until_epoch >/dev/null \
  || fail "crates.io Retry-After calculation is missing"
declare -F retry_seconds_within_budget >/dev/null \
  || fail "cumulative crates.io retry budget is missing"
declare -F verify_live_release_binding >/dev/null \
  || fail "per-attempt release source and tag binding guard is missing"
declare -F release_retry_sleep >/dev/null \
  || fail "testable bounded retry sleep boundary is missing"
declare -F release_sealed_crate_publish >/dev/null \
  || fail "sealed archive publication boundary is missing"

release_version=0.2.6
RELEASE_VERSION="$release_version"
archive_hash="$(printf '%064d' 1)"
member_hash="$(printf '%064d' 2)"

[ "$(bounded_retry_seconds 1)" -eq 60 ] \
  || fail "retry delay did not enforce its minimum"
[ "$(bounded_retry_seconds 120)" -eq 120 ] \
  || fail "ordinary retry delay was changed"
[ "$(bounded_retry_seconds 999999999)" -eq 300 ] \
  || fail "far-future retry delay was not capped"
[ "$(retry_seconds_until_epoch 4102444800 1787976000)" -eq 300 ] \
  || fail "far-future Retry-After date was not capped"
[ "$(retry_seconds_within_budget 300 850)" -eq 50 ] \
  || fail "retry delay was not truncated to the cumulative budget"
if retry_seconds_within_budget 60 900 >/dev/null; then
  fail "exhausted cumulative retry budget permitted another delay"
fi

write_manifest() {
  local destination="$1"
  local mode="${2:-valid}"
  local index=0
  local crate
  local emitted_crate
  local emitted_version
  local emitted_archive_hash
  local emitted_member_hash
  : > "$destination"
  for crate in "${CRATES[@]}"; do
    emitted_crate="$crate"
    emitted_version="$release_version"
    emitted_archive_hash="$(printf '%064x' "$((index + 1))")"
    emitted_member_hash="$(printf '%064x' "$((index + 101))")"
    case "$mode:$index" in
      wrong-order:0) emitted_crate="${CRATES[1]}" ;;
      wrong-order:1) emitted_crate="${CRATES[0]}" ;;
      duplicate:1) emitted_crate="${CRATES[0]}" ;;
      wrong-version:0) emitted_version=0.2.5 ;;
      bad-archive-hash:0) emitted_archive_hash=ABCDEF ;;
      bad-member-hash:0) emitted_member_hash=xyz ;;
    esac
    if [ "$mode" = extra-field ] && [ "$index" -eq 0 ]; then
      printf '%s\t%s\t%s\t%s\textra\n' \
        "$emitted_crate" "$emitted_version" \
        "$emitted_archive_hash" "$emitted_member_hash" >> "$destination"
    else
      printf '%s\t%s\t%s\t%s\n' \
        "$emitted_crate" "$emitted_version" \
        "$emitted_archive_hash" "$emitted_member_hash" >> "$destination"
    fi
    index=$((index + 1))
  done
  if [ "$mode" = missing-row ]; then
    "$trusted_python" - "$destination" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
lines = path.read_bytes().splitlines(keepends=True)
path.write_bytes(b"".join(lines[:-1]))
PY
  elif [ "$mode" = no-final-newline ]; then
    "$trusted_python" - "$destination" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
path.write_bytes(path.read_bytes().removesuffix(b"\n"))
PY
  fi
}

valid_preflight="$test_root/valid-preflight.tsv"
valid_reproduced="$test_root/valid-reproduced.tsv"
write_manifest "$valid_preflight"
/bin/cp "$valid_preflight" "$valid_reproduced"
validate_release_manifests \
  "$valid_preflight" "$valid_reproduced" "$release_version" \
  > "$test_root/captured-valid-manifest.tsv"
/usr/bin/cmp -s "$valid_preflight" "$test_root/captured-valid-manifest.tsv" \
  || fail "manifest validator did not emit the exact securely-read rows"

# The publisher must consume only the validator's in-memory output. Replacing
# either downloaded path after validation cannot change the checksums that will
# be handed to the irreversible uploader.
captured_manifest_rows="$(
  validate_release_manifests \
    "$valid_preflight" "$valid_reproduced" "$release_version"
)"
write_manifest "$valid_preflight" bad-archive-hash
write_manifest "$valid_reproduced" bad-archive-hash
captured_first_hash="$(
  printf '%s\n' "$captured_manifest_rows" | /usr/bin/awk -F '\t' 'NR == 1 { print $3 }'
)"
[ "$captured_first_hash" = "$(printf '%064x' 1)" ] \
  || fail "post-validation manifest replacement changed captured publisher checksums"
write_manifest "$valid_preflight"
/bin/cp "$valid_preflight" "$valid_reproduced"

for invalid_mode in \
  wrong-order duplicate wrong-version bad-archive-hash bad-member-hash \
  extra-field missing-row no-final-newline; do
  invalid_manifest="$test_root/${invalid_mode}.tsv"
  write_manifest "$invalid_manifest" "$invalid_mode"
  if validate_release_manifests \
      "$invalid_manifest" "$invalid_manifest" "$release_version" \
      >/dev/null 2>&1; then
    fail "manifest mode $invalid_mode was accepted"
  fi
done

mismatched_manifest="$test_root/mismatched.tsv"
/bin/cp "$valid_preflight" "$mismatched_manifest"
"$trusted_python" - "$mismatched_manifest" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = path.read_bytes()
path.write_bytes(data.replace(b"0000000000000000000000000000000000000000000000000000000000000065", b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 1))
PY
if validate_release_manifests \
    "$valid_preflight" "$mismatched_manifest" "$release_version" \
    >/dev/null 2>&1; then
  fail "different preflight and reproduced manifests were accepted"
fi

symlink_manifest="$test_root/symlink-manifest.tsv"
/bin/ln -s "$valid_preflight" "$symlink_manifest"
if validate_release_manifests \
    "$symlink_manifest" "$symlink_manifest" "$release_version" \
    >/dev/null 2>&1; then
  fail "symbolic-link manifests were accepted"
fi

valid_archive_directory="$test_root/sealed-archives"
/bin/mkdir "$valid_archive_directory"
for crate in "${CRATES[@]}"; do
  printf 'sealed fixture\n' > "$valid_archive_directory/${crate}-${release_version}.crate"
done
validate_sealed_archive_inventory \
  "$valid_archive_directory" "$release_version" "${CRATES[@]}"
printf 'unexpected\n' > "$valid_archive_directory/unexpected.crate"
if validate_sealed_archive_inventory \
    "$valid_archive_directory" "$release_version" "${CRATES[@]}" \
    >/dev/null 2>&1; then
  fail "an unexpected sealed archive was accepted"
fi
/bin/rm "$valid_archive_directory/unexpected.crate"
/bin/rm "$valid_archive_directory/exochain-core-${release_version}.crate"
/bin/ln -s "exochain-api-${release_version}.crate" \
  "$valid_archive_directory/exochain-core-${release_version}.crate"
if validate_sealed_archive_inventory \
    "$valid_archive_directory" "$release_version" "${CRATES[@]}" \
    >/dev/null 2>&1; then
  fail "a symbolic-link sealed archive was accepted"
fi

RELEASE_PREFLIGHT_MANIFEST="$valid_preflight"
expected_checksum_crates=(exochain-core)
expected_checksum_values=("$archive_hash")
[ "$(expected_archive_checksum exochain-core)" = "$archive_hash" ] \
  || fail "publisher did not select the preflight archive checksum"

write_response() {
  local destination="$1"
  local json="$2"
  printf '%s\n' "$json" > "$destination"
}

valid_response="$test_root/valid-response.json"
write_response "$valid_response" \
  "{\"version\":{\"crate\":\"exochain-core\",\"num\":\"$release_version\",\"checksum\":\"$archive_hash\",\"yanked\":false}}"
validate_crates_io_response \
  "$valid_response" exochain-core "$release_version" "$archive_hash"

invalid_responses=(
  '{'
  '{}'
  '{"version":[]}'
  "{\"version\":{\"crate\":\"wrong-crate\",\"num\":\"$release_version\",\"checksum\":\"$archive_hash\"}}"
  "{\"version\":{\"crate\":\"exochain-core\",\"num\":\"0.2.5\",\"checksum\":\"$archive_hash\"}}"
  "{\"version\":{\"crate\":\"exochain-core\",\"num\":\"$release_version\",\"checksum\":\"$member_hash\"}}"
  "{\"version\":{\"crate\":\"exochain-core\",\"num\":\"$release_version\",\"checksum\":1}}"
  "{\"version\":{\"crate\":\"exochain-core\",\"num\":\"$release_version\",\"checksum\":\"$archive_hash\",\"checksum\":\"$archive_hash\"}}"
  "{\"version\":{\"crate\":\"exochain-core\",\"num\":\"$release_version\",\"checksum\":\"$archive_hash\"}}"
  "{\"version\":{\"crate\":\"exochain-core\",\"num\":\"$release_version\",\"checksum\":\"$archive_hash\",\"yanked\":true}}"
  "{\"version\":{\"crate\":\"exochain-core\",\"num\":\"$release_version\",\"checksum\":\"$archive_hash\",\"yanked\":\"false\"}}"
)
response_index=0
for invalid_json in "${invalid_responses[@]}"; do
  invalid_response="$test_root/invalid-response-${response_index}.json"
  write_response "$invalid_response" "$invalid_json"
  if validate_crates_io_response \
      "$invalid_response" exochain-core "$release_version" "$archive_hash" \
      >/dev/null 2>&1; then
    fail "invalid crates.io response $response_index was accepted"
  fi
  response_index=$((response_index + 1))
done

RUNNER_TEMP="$test_root"
original_request_definition="$(declare -f perform_crates_io_request)"
query_fixture="$valid_response"
query_http_code=200
perform_crates_io_request() {
  /bin/cp "$query_fixture" "$2"
  printf '%s' "$query_http_code"
}
query_crate_version exochain-core "$archive_hash" \
  || fail "exact HTTP 200 response was not accepted"

query_fixture="$test_root/query-wrong-checksum.json"
write_response "$query_fixture" \
  "{\"version\":{\"crate\":\"exochain-core\",\"num\":\"$release_version\",\"checksum\":\"$member_hash\"}}"
if query_crate_version exochain-core "$archive_hash" >/dev/null 2>&1; then
  fail "HTTP 200 with a wrong archive checksum was accepted"
else
  query_status=$?
fi
[ "$query_status" -eq 2 ] \
  || fail "wrong archive checksum did not return the fatal status"

query_fixture="$test_root/query-malformed.json"
write_response "$query_fixture" '{'
if query_crate_version exochain-core "$archive_hash" >/dev/null 2>&1; then
  fail "HTTP 200 with malformed JSON was accepted"
else
  query_status=$?
fi
[ "$query_status" -eq 2 ] \
  || fail "malformed JSON did not return the fatal status"

query_http_code=404
if query_crate_version exochain-core "$archive_hash" >/dev/null 2>&1; then
  fail "HTTP 404 was accepted as an exact published crate"
else
  query_status=$?
fi
[ "$query_status" -eq 1 ] || fail "HTTP 404 did not return the retryable status"
eval "$original_request_definition"

original_query_definition="$(declare -f query_crate_version)"
poll_owner_definition="$(declare -f verify_crate_ownership)"
poll_binding_definition="$(declare -f verify_live_release_binding)"
verify_crate_ownership() { return 0; }
verify_live_release_binding() { return 0; }
query_attempts=0
query_crate_version() {
  query_attempts=$((query_attempts + 1))
  [ "$query_attempts" -ge 3 ] && return 0
  return 1
}
poll_for_expected_checksum exochain-core "$archive_hash" 3 0
[ "$query_attempts" -eq 3 ] \
  || fail "checksum polling did not stop on the third exact response"

query_attempts=0
query_crate_version() {
  query_attempts=$((query_attempts + 1))
  return 1
}
if poll_for_expected_checksum exochain-core "$archive_hash" 3 0 \
    >/dev/null 2>&1; then
  fail "checksum polling accepted bounded 404 exhaustion"
fi
[ "$query_attempts" -eq 3 ] \
  || fail "checksum polling exceeded or shortened its bound"

query_attempts=0
query_crate_version() {
  query_attempts=$((query_attempts + 1))
  return 2
}
if poll_for_expected_checksum exochain-core "$archive_hash" 3 0 \
    >/dev/null 2>&1; then
  fail "checksum polling accepted a fatal malformed or mismatched response"
fi
[ "$query_attempts" -eq 1 ] \
  || fail "checksum polling retried a fatal response"
eval "$original_query_definition"
eval "$poll_owner_definition"
eval "$poll_binding_definition"

original_publish_definition="$(declare -f release_sealed_crate_publish)"
original_poll_definition="$(declare -f poll_for_expected_checksum)"
original_query_definition="$(declare -f query_crate_version)"
original_owner_definition="$(declare -f verify_crate_ownership)"
original_binding_definition="$(declare -f verify_live_release_binding)"
verify_live_release_binding() { return 0; }
verify_crate_ownership() { return 0; }
release_sealed_crate_publish() { return 0; }
publish_poll_calls=0
poll_for_expected_checksum() {
  publish_poll_calls=$((publish_poll_calls + 1))
  [ "$1" = exochain-core ] && [ "$2" = "$archive_hash" ]
}
publish_crate_with_retry exochain-core "$archive_hash"
[ "$publish_poll_calls" -eq 1 ] \
  || fail "successful upload did not require exact-checksum visibility"

release_sealed_crate_publish() { return 7; }
recovery_query_calls=0
query_crate_version() {
  [ "$1" = exochain-core ] && [ "$2" = "$archive_hash" ] || return 2
  recovery_query_calls=$((recovery_query_calls + 1))
  [ "$recovery_query_calls" -ge 3 ] && return 0
  return 1
}
recovery_poll_calls=0
poll_for_expected_checksum() {
  recovery_poll_calls=$((recovery_poll_calls + 1))
  query_crate_version "$1" "$2" || query_crate_version "$1" "$2" \
    || query_crate_version "$1" "$2"
}
publish_crate_with_retry exochain-core "$archive_hash" >/dev/null
[ "$recovery_poll_calls" -eq 1 ] && [ "$recovery_query_calls" -eq 3 ] \
  || fail "failed upload recovery did not poll to the delayed exact preflight checksum"
eval "$original_publish_definition"
eval "$original_poll_definition"
eval "$original_query_definition"
eval "$original_owner_definition"

# A token-free preflight can be approved and then ownership can drift before
# the credentialed publisher runs. The live, per-attempt check must stop the
# operation before the sealed archive uploader is invoked at all.
publish_marker="$test_root/cargo-publish-ran"
verify_crate_ownership() { return 9; }
release_sealed_crate_publish() {
  : > "$publish_marker"
  return 0
}
if (publish_crate_with_retry exochain-core "$archive_hash") >/dev/null 2>&1; then
  fail "publisher-time owner drift was accepted"
fi
[ ! -e "$publish_marker" ] \
  || fail "sealed archive uploader ran after publisher-time owner drift"
eval "$original_publish_definition"
eval "$original_owner_definition"

original_initialize_definition="$(declare -f initialize_release_publication)"
original_checksum_definition="$(declare -f expected_archive_checksum)"
original_publish_retry_definition="$(declare -f publish_crate_with_retry)"
original_crates=("${CRATES[@]}")
initialize_release_publication() { return 0; }
expected_archive_checksum() { printf '%s\n' "$archive_hash"; }
skip_query_calls=0
query_crate_version() {
  [ "$1" = exochain-core ] && [ "$2" = "$archive_hash" ] || return 2
  skip_query_calls=$((skip_query_calls + 1))
  return 0
}
publish_crate_with_retry() {
  fail "publisher attempted to upload an exact already-published crate"
}
verify_crate_ownership() { return 0; }
CRATES=(exochain-core)
main >/dev/null
[ "$skip_query_calls" -eq 1 ] \
  || fail "initial skip did not require the exact preflight checksum"
CRATES=("${original_crates[@]}")
eval "$original_initialize_definition"
eval "$original_checksum_definition"
eval "$original_query_definition"
eval "$original_publish_retry_definition"
eval "$original_owner_definition"

# An attacker can claim an initially unowned namespace with the reviewed bytes
# between the pre-query owner check and the exact-checksum observation. The
# post-observation owner check must reject that takeover before it is treated as
# a completed partial release.
initialize_release_publication() { return 0; }
expected_archive_checksum() { printf '%s\n' "$archive_hash"; }
ownership_count_file="$test_root/initial-skip-ownership-count"
: > "$ownership_count_file"
verify_crate_ownership() {
  local count=0
  [ ! -s "$ownership_count_file" ] || read -r count < "$ownership_count_file"
  count=$((count + 1))
  printf '%s\n' "$count" > "$ownership_count_file"
  if [ "$count" -eq 1 ]; then
    [ "${2:-allow-unclaimed}" = allow-unclaimed ]
    return
  fi
  [ "${2:-}" = require-claimed ] || return 8
  return 9 # Simulated 404/unclaimed result after an exact checksum response.
}
query_crate_version() { return 0; }
takeover_publish_marker="$test_root/initial-skip-publish-ran"
publish_crate_with_retry() {
  : > "$takeover_publish_marker"
  return 0
}
CRATES=(exochain-core)
if (main) >/dev/null 2>&1; then
  fail "exact-checksum observation accepted a namespace takeover"
fi
[ "$(/bin/cat "$ownership_count_file")" -eq 2 ] \
  || fail "initial exact-checksum path did not recheck ownership after its query"
[ ! -e "$takeover_publish_marker" ] \
  || fail "initial exact-checksum takeover reached sealed archive publication"
CRATES=("${original_crates[@]}")
eval "$original_initialize_definition"
eval "$original_checksum_definition"
eval "$original_query_definition"
eval "$original_publish_retry_definition"
eval "$original_owner_definition"

# The failed-upload recovery path also observes an exact public checksum. A
# namespace takeover between the pre-attempt owner check and that observation
# must not be accepted as successful recovery.
ownership_count_file="$test_root/recovery-ownership-count"
: > "$ownership_count_file"
verify_crate_ownership() {
  local count=0
  [ ! -s "$ownership_count_file" ] || read -r count < "$ownership_count_file"
  count=$((count + 1))
  printf '%s\n' "$count" > "$ownership_count_file"
  if [ "$count" -eq 1 ]; then
    [ "${2:-allow-unclaimed}" = allow-unclaimed ]
    return
  fi
  [ "${2:-}" = require-claimed ] || return 8
  return 9 # Simulated 404/unclaimed result after recovery sees exact bytes.
}
recovery_publish_marker="$test_root/recovery-cargo-publish-ran"
release_sealed_crate_publish() {
  : > "$recovery_publish_marker"
  return 7
}
recovery_query_marker="$test_root/recovery-query-ran"
query_crate_version() {
  : > "$recovery_query_marker"
  return 0
}
if (publish_crate_with_retry exochain-core "$archive_hash") >/dev/null 2>&1; then
  fail "failed-upload recovery accepted a namespace takeover"
fi
[ -e "$recovery_publish_marker" ] && [ -e "$recovery_query_marker" ] \
  || fail "failed-upload takeover fixture did not reach its exact-checksum observation"
[ "$(/bin/cat "$ownership_count_file")" -eq 2 ] \
  || fail "failed-upload recovery did not recheck ownership after its exact query"
eval "$original_publish_definition"
eval "$original_query_definition"
eval "$original_owner_definition"

# Every irreversible sealed archive upload must be immediately preceded by the
# captured source and signed-tag guards. This remains true after a bounded 429
# retry delay, when either the checkout or the remote tag could have changed.
original_retry_sleep_definition="$(declare -f release_retry_sleep)"
release_event_log="$test_root/release-attempt-events"
: > "$release_event_log"
verify_crate_ownership() {
  printf 'owner\n' >> "$release_event_log"
}
verify_live_release_binding() {
  printf 'binding\n' >> "$release_event_log"
}
retry_publish_count_file="$test_root/retry-publish-count"
printf '0\n' > "$retry_publish_count_file"
release_sealed_crate_publish() {
  local retry_publish_attempts
  read -r retry_publish_attempts < "$retry_publish_count_file"
  retry_publish_attempts=$((retry_publish_attempts + 1))
  printf '%s\n' "$retry_publish_attempts" > "$retry_publish_count_file"
  printf 'publish\n' >> "$release_event_log"
  if [ "$retry_publish_attempts" -eq 1 ]; then
    printf 'status 429 Too Many Requests\n'
    return 75
  fi
  return 0
}
query_crate_version() { return 1; }
poll_for_expected_checksum() { return 0; }
release_retry_sleep() { return 0; }
crates_io_retry_seconds_slept=0
publish_crate_with_retry exochain-core "$archive_hash" >/dev/null
[ "$(/bin/cat "$retry_publish_count_file")" -eq 2 ] \
  || fail "429 retry fixture did not execute exactly two publication attempts"
[ "$(tr '\n' ' ' < "$release_event_log")" = \
    "owner binding publish owner binding publish " ] \
  || fail "source and tag binding did not immediately guard every publication attempt"
eval "$original_publish_definition"
eval "$original_poll_definition"
eval "$original_query_definition"
eval "$original_owner_definition"
eval "$original_binding_definition"
eval "$original_retry_sleep_definition"

# A successful publish is not complete until the exact checksum is visible.
# The visibility poll must bind that observation to the then-current owners.
ownership_count_file="$test_root/poll-ownership-count"
: > "$ownership_count_file"
verify_crate_ownership() {
  local count=0
  [ ! -s "$ownership_count_file" ] || read -r count < "$ownership_count_file"
  count=$((count + 1))
  printf '%s\n' "$count" > "$ownership_count_file"
  [ "${2:-}" = require-claimed ] || return 8
  return 9 # Simulated 404/unclaimed result after the poll sees exact bytes.
}
poll_query_marker="$test_root/poll-query-ran"
query_crate_version() {
  : > "$poll_query_marker"
  return 0
}
if (poll_for_expected_checksum exochain-core "$archive_hash" 1 0) \
    >/dev/null 2>&1; then
  fail "post-publish checksum poll accepted a namespace takeover"
fi
[ -e "$poll_query_marker" ] \
  || fail "post-publish takeover fixture did not reach an exact-checksum observation"
[ "$(/bin/cat "$ownership_count_file")" -eq 1 ] \
  || fail "post-publish checksum poll did not recheck ownership after its exact query"
eval "$original_query_definition"
eval "$original_owner_definition"

curl_log="$test_root/curl-arguments.bin"
fake_curl="$test_root/curl"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  "printf '%s\\0' \"\$@\" > '$curl_log'" \
  "printf '200'" > "$fake_curl"
/bin/chmod 500 "$fake_curl"
http_code="$(perform_crates_io_request \
  "$fake_curl" "$test_root/fetched-response.json" \
  exochain-core "$release_version")"
[ "$http_code" = 200 ] || fail "secure curl boundary did not return HTTP 200"
"$trusted_python" - "$curl_log" "$test_root/fetched-response.json" <<'PY'
from pathlib import Path
import sys

arguments = Path(sys.argv[1]).read_bytes().split(b"\0")[:-1]
expected = [
    b"-q",
    b"--proto", b"=https",
    b"--tlsv1.2",
    b"--silent",
    b"--show-error",
    b"--connect-timeout", b"15",
    b"--max-time", b"60",
    b"--max-filesize", b"1048576",
    b"--retry", b"3",
    b"--retry-delay", b"2",
    b"--retry-max-time", b"30",
    b"--retry-all-errors",
    b"--header", b"User-Agent: exochain-release-workflow (https://github.com/exochain/exochain)",
    b"--output", sys.argv[2].encode(),
    b"--write-out", b"%{http_code}",
    b"https://crates.io/api/v1/crates/exochain-core/0.2.6",
]
if arguments != expected:
    raise SystemExit(f"unsafe or drifted curl arguments: {arguments!r}")
PY

printf 'crate registry validation test passed\n'
