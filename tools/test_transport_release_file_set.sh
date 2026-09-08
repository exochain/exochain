#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'release file-set transport test failed: %s\n' "$1" >&2
  exit 1
}

case "${1:-}" in
  '') benign_only=false ;;
  --benign-only) benign_only=true ;;
  *) fail "usage: $0 [--benign-only]" ;;
esac
[ "$#" -le 1 ] || fail "usage: $0 [--benign-only]"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
transport="$repo_root/tools/transport_release_file_set.py"
python_path="${PYTHON:-$(command -v python3)}"
[ -x "$python_path" ] || fail "Python is unavailable"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-file-set-test.XXXXXX")"
trap '/bin/rm -rf -- "$test_root"' EXIT

run_transport() {
  /usr/bin/env -i "$python_path" -I -B "$transport" "$@"
}

expect_rejected() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    fail "$label was accepted"
  fi
}

llm_input="$test_root/llm-input"
/bin/mkdir "$llm_input"
# Exercise the actual shipped package, independently of the transport allowlist.
run_transport_source="$repo_root/packages/exochain-llm-proxy/dist"
/usr/bin/env -i "$python_path" -I -B - "$run_transport_source" "$llm_input" <<'PY'
from pathlib import Path
import shutil
import stat
import sys

source, destination = map(Path, sys.argv[1:])
entries = sorted(source.iterdir())
if len(entries) != 44:
    raise SystemExit("current LYNK package must contain exactly 44 build outputs")
for entry in entries:
    if not stat.S_ISREG(entry.lstat().st_mode):
        raise SystemExit(f"current LYNK output is not a regular file: {entry.name}")
    shutil.copyfile(entry, destination / entry.name)
    (destination / entry.name).chmod(0o644)
PY
archive="$test_root/llm.tar"
inventory="$test_root/llm.inventory"
digest="$(run_transport create --profile llm-dist --version 0.2.6 \
  --input-dir "$llm_input" --archive "$archive" --inventory "$inventory")"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "create did not emit one SHA-256"
run_transport extract --profile llm-dist --version 0.2.6 \
  --archive "$archive" --inventory "$inventory" --expected-sha256 "$digest" \
  --output-dir "$test_root/llm-output"
/usr/bin/diff -r "$llm_input" "$test_root/llm-output" >/dev/null \
  || fail "LYNK dist round trip changed bytes"

second_archive="$test_root/llm-second.tar"
second_inventory="$test_root/llm-second.inventory"
second_digest="$(run_transport create --profile llm-dist --version 0.2.6 \
  --input-dir "$llm_input" --archive "$second_archive" --inventory "$second_inventory")"
[ "$digest" = "$second_digest" ] \
  && /usr/bin/cmp -s "$archive" "$second_archive" \
  && /usr/bin/cmp -s "$inventory" "$second_inventory" \
  || fail "identical inputs did not produce deterministic transport bytes"

if [ "$benign_only" = true ]; then
  printf 'release file-set benign current-package round-trip test passed (44 files)\n'
  exit 0
fi

expect_rejected wrong-independent-digest run_transport extract \
  --profile llm-dist --version 0.2.6 --archive "$archive" --inventory "$inventory" \
  --expected-sha256 "$(printf '%064d' 0)" --output-dir "$test_root/wrong-digest-output"

extra_input="$test_root/extra-input"
/bin/cp -R "$llm_input" "$extra_input"
printf 'extra\n' > "$extra_input/attacker.js"
expect_rejected extra-input run_transport create --profile llm-dist --version 0.2.6 \
  --input-dir "$extra_input" --archive "$test_root/extra.tar" \
  --inventory "$test_root/extra.inventory"

empty_input="$test_root/empty-input"
/bin/cp -R "$llm_input" "$empty_input"
: > "$empty_input/index.js"
expect_rejected zero-byte-input run_transport create --profile llm-dist --version 0.2.6 \
  --input-dir "$empty_input" --archive "$test_root/empty.tar" \
  --inventory "$test_root/empty.inventory"

symlink_input="$test_root/symlink-input"
/bin/cp -R "$llm_input" "$symlink_input"
/bin/rm "$symlink_input/index.js"
/bin/ln -s cli.js "$symlink_input/index.js"
expect_rejected symlink-input run_transport create --profile llm-dist --version 0.2.6 \
  --input-dir "$symlink_input" --archive "$test_root/symlink.tar" \
  --inventory "$test_root/symlink.inventory"

hardlink_input="$test_root/hardlink-input"
/bin/cp -R "$llm_input" "$hardlink_input"
/bin/rm "$hardlink_input/index.js"
/bin/ln "$hardlink_input/cli.js" "$hardlink_input/index.js"
expect_rejected hardlink-input run_transport create --profile llm-dist --version 0.2.6 \
  --input-dir "$hardlink_input" --archive "$test_root/hardlink.tar" \
  --inventory "$test_root/hardlink.inventory"

fifo_input="$test_root/fifo-input"
/bin/cp -R "$llm_input" "$fifo_input"
/bin/rm "$fifo_input/index.js"
/usr/bin/mkfifo "$fifo_input/index.js"
expect_rejected fifo-input run_transport create --profile llm-dist --version 0.2.6 \
  --input-dir "$fifo_input" --archive "$test_root/fifo.tar" \
  --inventory "$test_root/fifo.inventory"

archive_hardlink="$test_root/archive-hardlink.tar"
/bin/ln "$archive" "$archive_hardlink"
expect_rejected hardlinked-archive run_transport extract --profile llm-dist --version 0.2.6 \
  --archive "$archive_hardlink" --inventory "$inventory" --expected-sha256 "$digest" \
  --output-dir "$test_root/archive-hardlink-output"
inventory_hardlink="$test_root/inventory-hardlink"
/bin/ln "$inventory" "$inventory_hardlink"
expect_rejected hardlinked-inventory run_transport extract --profile llm-dist --version 0.2.6 \
  --archive "$archive" --inventory "$inventory_hardlink" --expected-sha256 "$digest" \
  --output-dir "$test_root/inventory-hardlink-output"

attacker_input="$test_root/attacker-input"
/bin/cp -R "$llm_input" "$attacker_input"
printf 'attacker replacement\n' > "$attacker_input/index.js"
attacker_archive="$test_root/attacker.tar"
attacker_inventory="$test_root/attacker.inventory"
attacker_digest="$(run_transport create --profile llm-dist --version 0.2.6 \
  --input-dir "$attacker_input" --archive "$attacker_archive" --inventory "$attacker_inventory")"
run_transport extract --profile llm-dist --version 0.2.6 \
  --archive "$attacker_archive" --inventory "$attacker_inventory" \
  --expected-sha256 "$attacker_digest" --output-dir "$test_root/attacker-control"
expect_rejected consistent-triple-substitution run_transport extract \
  --profile llm-dist --version 0.2.6 --archive "$attacker_archive" \
  --inventory "$attacker_inventory" --expected-sha256 "$digest" \
  --output-dir "$test_root/attacker-rejected"

tool_input="$test_root/tool-input"
/bin/mkdir "$tool_input"
printf '#!/bin/sh\nexit 0\n' > "$tool_input/cargo-cyclonedx"
/bin/chmod 755 "$tool_input/cargo-cyclonedx"
tool_digest="$(run_transport create --profile cargo-cyclonedx --version 0.5.9 \
  --input-dir "$tool_input" --archive "$test_root/tool.tar" \
  --inventory "$test_root/tool.inventory")"
run_transport extract --profile cargo-cyclonedx --version 0.5.9 \
  --archive "$test_root/tool.tar" --inventory "$test_root/tool.inventory" \
  --expected-sha256 "$tool_digest" --output-dir "$test_root/tool-output"
[ -x "$test_root/tool-output/cargo-cyclonedx" ] \
  || fail "tool transport did not restore canonical executable mode"

sbom_input="$test_root/sbom-input"
/bin/mkdir "$sbom_input"
for index in $(seq -w 1 32); do
  printf '{"index":"%s"}\n' "$index" > "$sbom_input/exochain-fixture-$index.cdx.json"
done
sbom_digest="$(run_transport create --profile raw-sbom --version 0.2.6 \
  --input-dir "$sbom_input" --archive "$test_root/sbom.tar" \
  --inventory "$test_root/sbom.inventory")"
run_transport extract --profile raw-sbom --version 0.2.6 \
  --archive "$test_root/sbom.tar" --inventory "$test_root/sbom.inventory" \
  --expected-sha256 "$sbom_digest" --output-dir "$test_root/sbom-output"
[ "$(find "$test_root/sbom-output" -type f | wc -l | tr -d ' ')" -eq 32 ] \
  || fail "raw SBOM transport did not preserve exactly 32 files"

printf 'release file-set transport test passed\n'
