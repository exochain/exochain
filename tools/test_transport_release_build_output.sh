#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'release build transport test failed: %s\n' "$1" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | /usr/bin/cut -d ' ' -f 1
  else
    /usr/bin/shasum -a 256 "$1" | /usr/bin/cut -d ' ' -f 1
  fi
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper="$repo_root/tools/transport_release_build_output.py"
[ -f "$helper" ] || fail "transport helper is missing"

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-release-transport.XXXXXX")"
trap '/bin/rm -rf -- "$fixture_root"' EXIT
input_dir="$fixture_root/input"
archive="$fixture_root/release-output.tar"
inventory="$fixture_root/release-output.inventory"
output_dir="$fixture_root/output"
/bin/mkdir -m 700 -p "$input_dir"
expected_libraries=(
  libexo_api.rlib
  libexo_authority.rlib
  libexo_avc.rlib
  libexo_catapult.rlib
  libexo_consensus.rlib
  libexo_consent.rlib
  libexo_core.rlib
  libexo_dag.rlib
  libexo_dag_db_api.rlib
  libexo_dag_db_core.rlib
  libexo_dag_db_domain.rlib
  libexo_dag_db_exchange.rlib
  libexo_dag_db_graph.rlib
  libexo_dag_db_lab.rlib
  libexo_dag_db_postgres.rlib
  libexo_dag_db_retrieval.rlib
  libexo_economy.rlib
  libexo_escalation.rlib
  libexo_gatekeeper.rlib
  libexo_gateway.rlib
  libexo_governance.rlib
  libexo_identity.rlib
  libexo_legal.rlib
  libexo_messaging.rlib
  libexo_node.rlib
  libexo_pdp.rlib
  libexo_proofs.rlib
  libexo_root.rlib
  libexo_tenant.rlib
)
for library in "${expected_libraries[@]}"; do
  printf '%s bytes\n' "$library" > "$input_dir/$library"
  /bin/chmod 644 "$input_dir/$library"
done

/usr/bin/python3 -I -B "$helper" create \
  --input-dir "$input_dir" --archive "$archive" --inventory "$inventory"
archive_sha="$(sha256_file "$archive")"
/usr/bin/python3 -I -B "$helper" extract \
  --archive "$archive" --expected-sha256 "$archive_sha" \
  --inventory "$inventory" --output-dir "$output_dir"
/usr/bin/cmp -s "$input_dir/libexo_core.rlib" "$output_dir/libexo_core.rlib" \
  || fail "round-trip changed rlib bytes"
[ "$(find "$output_dir" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')" -eq 29 ] \
  || fail "round-trip did not preserve the exact 29-library inventory"

backdoor_dir="$fixture_root/backdoor-input"
/bin/cp -R "$input_dir" "$backdoor_dir"
printf 'attacker bytes\n' > "$backdoor_dir/libexo_backdoor.so"
if /usr/bin/python3 -I -B "$helper" create \
    --input-dir "$backdoor_dir" --archive "$fixture_root/backdoor.tar" \
    --inventory "$fixture_root/backdoor.inventory" >/dev/null 2>&1; then
  fail "create accepted the expected libraries plus an attacker-named extra library"
fi

if /usr/bin/python3 -I -B "$helper" extract \
    --archive "$archive" --expected-sha256 "$(printf '%064d' 0)" \
    --inventory "$inventory" --output-dir "$fixture_root/hash-mismatch" \
    >/dev/null 2>&1; then
  fail "extract accepted a mismatched expected transport digest"
fi

/bin/cp "$archive" "$fixture_root/watcher-mutated.tar"
printf 'detached-watcher-mutation' >> "$fixture_root/watcher-mutated.tar"
if /usr/bin/python3 -I -B "$helper" extract \
    --archive "$fixture_root/watcher-mutated.tar" --expected-sha256 "$archive_sha" \
    --inventory "$inventory" --output-dir "$fixture_root/watcher-output" \
    >/dev/null 2>&1; then
  fail "extract accepted a transport changed after its digest was recorded"
fi

invalid_index=0
for invalid_name in README.md libexo_backdoor.rlib libexo_backdoor.so subdir/libexo_bad.rlib $'libexo_bad\n.rlib'; do
  invalid_dir="$fixture_root/invalid-$invalid_index"
  invalid_index=$((invalid_index + 1))
  /bin/mkdir -m 700 -p "$invalid_dir"
  /bin/cp "$input_dir/libexo_core.rlib" "$invalid_dir/$invalid_name" 2>/dev/null || true
  if /usr/bin/python3 -I -B "$helper" create \
      --input-dir "$invalid_dir" --archive "$fixture_root/invalid.tar" \
      --inventory "$fixture_root/invalid.inventory" >/dev/null 2>&1; then
    fail "create accepted invalid release-library path $invalid_name"
  fi
done

symlink_dir="$fixture_root/symlink-input"
/bin/cp -R "$input_dir" "$symlink_dir"
/bin/rm "$symlink_dir/libexo_api.rlib"
/bin/ln -s "$input_dir/libexo_core.rlib" "$symlink_dir/libexo_api.rlib"
if /usr/bin/python3 -I -B "$helper" create \
    --input-dir "$symlink_dir" --archive "$fixture_root/symlink.tar" \
    --inventory "$fixture_root/symlink.inventory" >/dev/null 2>&1; then
  fail "create accepted a symbolic-link library"
fi

hardlink_dir="$fixture_root/hardlink-input"
/bin/cp -R "$input_dir" "$hardlink_dir"
/bin/rm "$hardlink_dir/libexo_api.rlib"
/bin/ln "$hardlink_dir/libexo_core.rlib" "$hardlink_dir/libexo_api.rlib"
if /usr/bin/python3 -I -B "$helper" create \
    --input-dir "$hardlink_dir" --archive "$fixture_root/hardlink.tar" \
    --inventory "$fixture_root/hardlink.inventory" >/dev/null 2>&1; then
  fail "create accepted a hard-linked library"
fi

missing_dir="$fixture_root/missing-input"
/bin/cp -R "$input_dir" "$missing_dir"
/bin/rm "$missing_dir/libexo_api.rlib"
if /usr/bin/python3 -I -B "$helper" create \
    --input-dir "$missing_dir" --archive "$fixture_root/missing.tar" \
    --inventory "$fixture_root/missing.inventory" >/dev/null 2>&1; then
  fail "create accepted a missing expected library"
fi

empty_dir="$fixture_root/empty-input"
/bin/cp -R "$input_dir" "$empty_dir"
: > "$empty_dir/libexo_api.rlib"
if /usr/bin/python3 -I -B "$helper" create \
    --input-dir "$empty_dir" --archive "$fixture_root/empty.tar" \
    --inventory "$fixture_root/empty.inventory" >/dev/null 2>&1; then
  fail "create accepted a zero-byte expected release library"
fi

mode_dir="$fixture_root/mode-input"
/bin/cp -R "$input_dir" "$mode_dir"
/bin/chmod 755 "$mode_dir/libexo_api.rlib"
if /usr/bin/python3 -I -B "$helper" create \
    --input-dir "$mode_dir" --archive "$fixture_root/mode.tar" \
    --inventory "$fixture_root/mode.inventory" >/dev/null 2>&1; then
  fail "create accepted a drifted library mode"
fi

aggregate_dir="$fixture_root/aggregate-input"
/bin/cp -R "$input_dir" "$aggregate_dir"
for library in "${expected_libraries[@]}"; do
  /usr/bin/python3 -I -B - "$aggregate_dir/$library" <<'PY'
from pathlib import Path
import sys

with Path(sys.argv[1]).open("wb") as output:
    output.truncate(20 * 1024 * 1024)
PY
done
if /usr/bin/python3 -I -B "$helper" create \
    --input-dir "$aggregate_dir" --archive "$fixture_root/aggregate.tar" \
    --inventory "$fixture_root/aggregate.inventory" >/dev/null 2>&1; then
  fail "create accepted release libraries above the aggregate payload cap"
fi

if /usr/bin/python3 -I -B "$helper" create \
    --input-dir "$input_dir" --archive "$input_dir/nested.tar" \
    --inventory "$fixture_root/nested.inventory" >/dev/null 2>&1; then
  fail "create accepted an archive path inside its input tree"
fi

/bin/mkdir -m 700 -p "$fixture_root/nonempty-output"
printf 'existing\n' > "$fixture_root/nonempty-output/existing"
if /usr/bin/python3 -I -B "$helper" extract \
    --archive "$archive" --expected-sha256 "$archive_sha" \
    --inventory "$inventory" --output-dir "$fixture_root/nonempty-output" \
    >/dev/null 2>&1; then
  fail "extract accepted a non-empty output directory"
fi

malicious_tar="$fixture_root/traversal.tar"
/usr/bin/python3 -I -B - "$malicious_tar" <<'PY'
import io
import tarfile
import sys

with tarfile.open(sys.argv[1], "w", format=tarfile.USTAR_FORMAT) as archive:
    item = tarfile.TarInfo("../libexo_escape.rlib")
    item.size = 1
    archive.addfile(item, io.BytesIO(b"x"))
PY
malicious_sha="$(sha256_file "$malicious_tar")"
if /usr/bin/python3 -I -B "$helper" extract \
    --archive "$malicious_tar" --expected-sha256 "$malicious_sha" \
    --inventory "$inventory" --output-dir "$fixture_root/traversal-output" \
    >/dev/null 2>&1; then
  fail "extract accepted an archive containing traversal"
fi

canonical_mutation="$fixture_root/canonical-mutation.tar"
/bin/cp "$archive" "$canonical_mutation"
printf 'attacker-trailing-bytes' >> "$canonical_mutation"
canonical_mutation_sha="$(sha256_file "$canonical_mutation")"
/usr/bin/python3 -I -B - "$inventory" "$fixture_root/canonical-mutation.inventory" "$canonical_mutation_sha" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_bytes().split(b"\0")
source[2] = sys.argv[3].encode("ascii")
Path(sys.argv[2]).write_bytes(b"\0".join(source))
PY
if /usr/bin/python3 -I -B "$helper" extract \
    --archive "$canonical_mutation" --expected-sha256 "$canonical_mutation_sha" \
    --inventory "$fixture_root/canonical-mutation.inventory" \
    --output-dir "$fixture_root/canonical-mutation-output" >/dev/null 2>&1; then
  fail "extract accepted noncanonical trailing archive bytes after all digests were updated"
fi

/bin/cp "$inventory" "$fixture_root/trailing.inventory"
printf 'trailing-garbage' >> "$fixture_root/trailing.inventory"
if /usr/bin/python3 -I -B "$helper" extract \
    --archive "$archive" --expected-sha256 "$archive_sha" \
    --inventory "$fixture_root/trailing.inventory" \
    --output-dir "$fixture_root/trailing-output" >/dev/null 2>&1; then
  fail "extract accepted inventory trailing garbage"
fi

archive_hardlink="$fixture_root/archive-hardlink.tar"
/bin/ln "$archive" "$archive_hardlink"
if /usr/bin/python3 -I -B "$helper" extract \
    --archive "$archive_hardlink" --expected-sha256 "$archive_sha" \
    --inventory "$inventory" --output-dir "$fixture_root/archive-hardlink-output" \
    >/dev/null 2>&1; then
  fail "extract accepted a hard-linked archive"
fi

inventory_hardlink="$fixture_root/inventory-hardlink"
/bin/ln "$inventory" "$inventory_hardlink"
if /usr/bin/python3 -I -B "$helper" extract \
    --archive "$archive" --expected-sha256 "$archive_sha" \
    --inventory "$inventory_hardlink" --output-dir "$fixture_root/inventory-hardlink-output" \
    >/dev/null 2>&1; then
  fail "extract accepted a hard-linked inventory"
fi

attacker_input="$fixture_root/attacker-input"
/bin/cp -R "$input_dir" "$attacker_input"
printf 'attacker replacement bytes\n' > "$attacker_input/libexo_core.rlib"
attacker_archive="$fixture_root/attacker-canonical.tar"
attacker_inventory="$fixture_root/attacker-canonical.inventory"
/usr/bin/python3 -I -B "$helper" create \
  --input-dir "$attacker_input" --archive "$attacker_archive" \
  --inventory "$attacker_inventory"
attacker_sha="$(sha256_file "$attacker_archive")"
/usr/bin/python3 -I -B "$helper" extract \
  --archive "$attacker_archive" --expected-sha256 "$attacker_sha" \
  --inventory "$attacker_inventory" --output-dir "$fixture_root/attacker-control-output"
if /usr/bin/python3 -I -B "$helper" extract \
    --archive "$attacker_archive" --expected-sha256 "$archive_sha" \
    --inventory "$attacker_inventory" --output-dir "$fixture_root/consistent-triple-output" \
    >/dev/null 2>&1; then
  fail "consumer accepted a consistently replaced archive and inventory against its independent producer digest"
fi

printf 'release build transport test passed\n'
