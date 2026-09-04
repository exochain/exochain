#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'WASM release transport test failed: %s\n' "$1" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
transport="$repo_root/tools/transport_wasm_release_output.py"
python3_binary="$(command -v python3)"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-wasm-transport-test.XXXXXX")"
trap '/bin/rm -rf -- "$fixture_root"' EXIT

[ -f "$transport" ] || fail "transport implementation is missing"

run_transport() {
  /usr/bin/env -i "$python3_binary" -I -B "$transport" "$@"
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >"$fixture_root/$label.stdout" 2>"$fixture_root/$label.stderr"; then
    fail "$label was accepted"
  fi
}

sha256_file() {
  /usr/bin/env -i "$python3_binary" -I -B - "$1" <<'PY'
import hashlib
import sys

with open(sys.argv[1], "rb") as source:
    print(hashlib.file_digest(source, "sha256").hexdigest())
PY
}

make_valid_input() {
  local destination="$1"
  /bin/mkdir -p "$destination"
  printf '*\n' >"$destination/.gitignore"
  printf 'export function adjudicate(): void;\n' \
    >"$destination/exochain_wasm.d.ts"
  printf 'export function adjudicate() { return true; }\n' \
    >"$destination/exochain_wasm.js"
  printf '\000asm\001\000\000\000fixture' \
    >"$destination/exochain_wasm_bg.wasm"
  printf 'export const memory: WebAssembly.Memory;\n' \
    >"$destination/exochain_wasm_bg.wasm.d.ts"
  printf '{"name":"exochain-wasm","version":"0.2.6"}\n' \
    >"$destination/package.json"
}

valid_input="$fixture_root/valid-input"
archive_one="$fixture_root/wasm-output-one.tar"
archive_two="$fixture_root/wasm-output-two.tar"
inventory_one="$fixture_root/wasm-output-one.inventory"
inventory_two="$fixture_root/wasm-output-two.inventory"
make_valid_input "$valid_input"

create_sha_one="$(run_transport create \
  --input-dir "$valid_input" \
  --archive "$archive_one" \
  --inventory "$inventory_one")"
create_sha_two="$(run_transport create \
  --input-dir "$valid_input" \
  --archive "$archive_two" \
  --inventory "$inventory_two")"
/usr/bin/cmp -s "$archive_one" "$archive_two" \
  || fail "identical inputs did not produce one deterministic archive"
/usr/bin/cmp -s "$inventory_one" "$inventory_two" \
  || fail "identical inputs did not produce deterministic inventory metadata"

archive_sha256="$(sha256_file "$archive_one")"
[[ "$archive_sha256" =~ ^[0-9a-f]{64}$ ]] \
  || fail "archive SHA-256 was not lowercase hexadecimal"
[ "$create_sha_one" = "$archive_sha256" ] \
  || fail "create mode did not report the archive SHA-256"
[ "$create_sha_two" = "$archive_sha256" ] \
  || fail "deterministic create mode reported a different archive SHA-256"

/usr/bin/env -i "$python3_binary" -I -B - \
  "$inventory_one" "$archive_one" "$valid_input" <<'PY'
import hashlib
import pathlib
import sys

expected_names = (
    ".gitignore",
    "exochain_wasm.d.ts",
    "exochain_wasm.js",
    "exochain_wasm_bg.wasm",
    "exochain_wasm_bg.wasm.d.ts",
    "package.json",
)
inventory = pathlib.Path(sys.argv[1]).read_bytes()
archive = pathlib.Path(sys.argv[2])
source = pathlib.Path(sys.argv[3])
tokens = [
    b"EXOCHAIN-WASM-TRANSPORT-V1",
    b"archive-sha256",
    hashlib.sha256(archive.read_bytes()).hexdigest().encode("ascii"),
    b"archive-size",
    str(archive.stat().st_size).encode("ascii"),
]
for name in expected_names:
    payload = (source / name).read_bytes()
    tokens.extend(
        (
            b"file",
            name.encode("ascii"),
            str(len(payload)).encode("ascii"),
            hashlib.sha256(payload).hexdigest().encode("ascii"),
        )
    )
tokens.append(b"end")
expected = b"\0".join(tokens) + b"\0"
if inventory != expected:
    raise SystemExit("inventory is not the strict deterministic NUL format")
if b"\n" in inventory or not inventory.endswith(b"end\0"):
    raise SystemExit("inventory is not NUL-safe or has trailing bytes")
PY

valid_output="$fixture_root/valid-output"
/bin/mkdir "$valid_output"
run_transport extract \
  --archive "$archive_one" \
  --expected-sha256 "$archive_sha256" \
  --inventory "$inventory_one" \
  --output-dir "$valid_output"
for expected_name in \
  .gitignore \
  exochain_wasm.d.ts \
  exochain_wasm.js \
  exochain_wasm_bg.wasm \
  exochain_wasm_bg.wasm.d.ts \
  package.json; do
  [ -f "$valid_output/$expected_name" ] \
    || fail "valid extraction omitted $expected_name"
  [ ! -L "$valid_output/$expected_name" ] \
    || fail "valid extraction materialized a link for $expected_name"
  /usr/bin/cmp -s "$valid_input/$expected_name" "$valid_output/$expected_name" \
    || fail "valid extraction changed bytes for $expected_name"
done
[ "$(find "$valid_output" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" -eq 6 ] \
  || fail "valid extraction did not materialize the exact six-file inventory"

extra_input="$fixture_root/extra-input"
/bin/cp -R "$valid_input" "$extra_input"
printf 'unexpected\n' >"$extra_input/unexpected.txt"
expect_failure create-extra run_transport create \
  --input-dir "$extra_input" \
  --archive "$fixture_root/create-extra.tar" \
  --inventory "$fixture_root/create-extra.inventory"

missing_input="$fixture_root/missing-input"
/bin/cp -R "$valid_input" "$missing_input"
/bin/rm "$missing_input/package.json"
expect_failure create-missing run_transport create \
  --input-dir "$missing_input" \
  --archive "$fixture_root/create-missing.tar" \
  --inventory "$fixture_root/create-missing.inventory"

empty_input="$fixture_root/empty-input"
/bin/cp -R "$valid_input" "$empty_input"
: > "$empty_input/exochain_wasm_bg.wasm"
expect_failure create-empty run_transport create \
  --input-dir "$empty_input" \
  --archive "$fixture_root/create-empty.tar" \
  --inventory "$fixture_root/create-empty.inventory"

symlink_input="$fixture_root/symlink-input"
/bin/cp -R "$valid_input" "$symlink_input"
/bin/rm "$symlink_input/exochain_wasm.js"
/bin/ln -s package.json "$symlink_input/exochain_wasm.js"
expect_failure create-symlink run_transport create \
  --input-dir "$symlink_input" \
  --archive "$fixture_root/create-symlink.tar" \
  --inventory "$fixture_root/create-symlink.inventory"

hardlink_input="$fixture_root/hardlink-input"
/bin/cp -R "$valid_input" "$hardlink_input"
/bin/rm "$hardlink_input/exochain_wasm.js"
/bin/ln "$hardlink_input/package.json" "$hardlink_input/exochain_wasm.js"
expect_failure create-hardlink run_transport create \
  --input-dir "$hardlink_input" \
  --archive "$fixture_root/create-hardlink.tar" \
  --inventory "$fixture_root/create-hardlink.inventory"

fifo_input="$fixture_root/fifo-input"
/bin/cp -R "$valid_input" "$fifo_input"
/bin/rm "$fifo_input/exochain_wasm.js"
mkfifo "$fifo_input/exochain_wasm.js"
run_transport create \
  --input-dir "$fifo_input" \
  --archive "$fixture_root/create-fifo.tar" \
  --inventory "$fixture_root/create-fifo.inventory" \
  >"$fixture_root/create-fifo.stdout" \
  2>"$fixture_root/create-fifo.stderr" &
fifo_pid=$!
fifo_finished=false
fifo_status=0
for _ in {1..50}; do
  if ! kill -0 "$fifo_pid" 2>/dev/null; then
    if wait "$fifo_pid"; then
      fifo_status=0
    else
      fifo_status=$?
    fi
    fifo_finished=true
    break
  fi
  /bin/sleep 0.02
done
if [ "$fifo_finished" != true ]; then
  kill "$fifo_pid" 2>/dev/null || true
  wait "$fifo_pid" 2>/dev/null || true
  fail "create mode blocked while inspecting a FIFO input"
fi
[ "$fifo_status" -ne 0 ] || fail "create mode accepted a FIFO input"

oversize_input="$fixture_root/oversize-input"
/bin/cp -R "$valid_input" "$oversize_input"
/usr/bin/env -i "$python3_binary" -I -B - \
  "$oversize_input/.gitignore" <<'PY'
import pathlib
import sys

with pathlib.Path(sys.argv[1]).open("wb") as oversized:
    oversized.truncate(16 * 1024 + 1)
PY
expect_failure create-oversize run_transport create \
  --input-dir "$oversize_input" \
  --archive "$fixture_root/create-oversize.tar" \
  --inventory "$fixture_root/create-oversize.inventory"

expect_failure create-nested-archive run_transport create \
  --input-dir "$valid_input" \
  --archive "$valid_input/nested.tar" \
  --inventory "$fixture_root/nested-archive.inventory"
expect_failure create-nested-inventory run_transport create \
  --input-dir "$valid_input" \
  --archive "$fixture_root/nested-inventory.tar" \
  --inventory "$valid_input/nested.inventory"

malicious_root="$fixture_root/malicious"
/bin/mkdir "$malicious_root"
/usr/bin/env -i "$python3_binary" -I -B - "$malicious_root" <<'PY'
import hashlib
import io
import pathlib
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
files = {
    ".gitignore": b"*\n",
    "exochain_wasm.d.ts": b"export function adjudicate(): void;\n",
    "exochain_wasm.js": b"export function adjudicate() { return true; }\n",
    "exochain_wasm_bg.wasm": b"\0asm\1\0\0\0fixture",
    "exochain_wasm_bg.wasm.d.ts": b"export const memory: WebAssembly.Memory;\n",
    "package.json": b'{"name":"exochain-wasm","version":"0.2.6"}\n',
}


def add_regular(bundle, name, payload):
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = 0o644
    member.mtime = 0
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""
    bundle.addfile(member, io.BytesIO(payload))


def write_inventory(case, archive, records=None, trailing=b""):
    if records is None:
        records = tuple(files.items())
    archive_bytes = archive.read_bytes()
    tokens = [
        b"EXOCHAIN-WASM-TRANSPORT-V1",
        b"archive-sha256",
        hashlib.sha256(archive_bytes).hexdigest().encode("ascii"),
        b"archive-size",
        str(len(archive_bytes)).encode("ascii"),
    ]
    for name, payload in records:
        tokens.extend(
            (
                b"file",
                name.encode("ascii"),
                str(len(payload)).encode("ascii"),
                hashlib.sha256(payload).hexdigest().encode("ascii"),
            )
        )
    tokens.append(b"end")
    (root / f"{case}.inventory").write_bytes(
        b"\0".join(tokens) + b"\0" + trailing
    )
    (root / f"{case}.sha256").write_text(
        hashlib.sha256(archive_bytes).hexdigest(), encoding="ascii"
    )


def write_case(case, entries):
    archive = root / f"{case}.tar"
    with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as bundle:
        for entry in entries:
            kind, name, payload = entry
            if kind == "regular":
                add_regular(bundle, name, payload)
                continue
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.mtime = 0
            member.uid = 0
            member.gid = 0
            if kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = "package.json"
            elif kind == "hardlink":
                member.type = tarfile.LNKTYPE
                member.linkname = "package.json"
            elif kind == "special":
                member.type = tarfile.FIFOTYPE
            else:
                raise AssertionError(kind)
            bundle.addfile(member)
    write_inventory(case, archive)


regular = [("regular", name, payload) for name, payload in files.items()]
write_case("traversal", [("regular", "../escape", b"escape\n"), *regular[1:]])
write_case("duplicate", [*regular, regular[0]])
write_case("extra", [*regular, ("regular", "unexpected.txt", b"unexpected\n")])
write_case("missing", regular[:-1])
write_case("symlink", [("symlink", ".gitignore", b""), *regular[1:]])
write_case("hardlink", [("hardlink", ".gitignore", b""), *regular[1:]])
write_case("special", [("special", ".gitignore", b""), *regular[1:]])
oversized = dict(files)
oversized[".gitignore"] = b"x" * (16 * 1024 + 1)
oversize_entries = [
    ("regular", name, payload) for name, payload in oversized.items()
]
archive = root / "oversize.tar"
with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as bundle:
    for _, name, payload in oversize_entries:
        add_regular(bundle, name, payload)
write_inventory("oversize", archive, tuple(oversized.items()))

valid_archive = root.parent / "wasm-output-one.tar"
duplicate_records = list(files.items())
duplicate_records[1] = duplicate_records[0]
write_inventory("inventory-duplicate", valid_archive, duplicate_records)
write_inventory("inventory-trailing", valid_archive, trailing=b"garbage")
PY

for attack in traversal duplicate extra missing symlink hardlink special oversize; do
  attack_archive="$malicious_root/$attack.tar"
  attack_inventory="$malicious_root/$attack.inventory"
  attack_sha="$(<"$malicious_root/$attack.sha256")"
  attack_output="$fixture_root/$attack-output"
  /bin/mkdir "$attack_output"
  expect_failure "extract-$attack" run_transport extract \
    --archive "$attack_archive" \
    --expected-sha256 "$attack_sha" \
    --inventory "$attack_inventory" \
    --output-dir "$attack_output"
  [ "$(find "$attack_output" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" -eq 0 ] \
    || fail "rejected $attack archive partially materialized output"
done
[ ! -e "$fixture_root/escape" ] \
  || fail "traversal archive escaped the extraction directory"

hash_mismatch_output="$fixture_root/hash-mismatch-output"
/bin/mkdir "$hash_mismatch_output"
expect_failure extract-hash-mismatch run_transport extract \
  --archive "$archive_one" \
  --expected-sha256 0000000000000000000000000000000000000000000000000000000000000000 \
  --inventory "$inventory_one" \
  --output-dir "$hash_mismatch_output"
[ "$(find "$hash_mismatch_output" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" -eq 0 ] \
  || fail "hash-mismatched archive partially materialized output"

for inventory_attack in inventory-duplicate inventory-trailing; do
  inventory_output="$fixture_root/$inventory_attack-output"
  /bin/mkdir "$inventory_output"
  expect_failure "extract-$inventory_attack" run_transport extract \
    --archive "$archive_one" \
    --expected-sha256 "$archive_sha256" \
    --inventory "$malicious_root/$inventory_attack.inventory" \
    --output-dir "$inventory_output"
  [ "$(find "$inventory_output" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" -eq 0 ] \
    || fail "rejected $inventory_attack metadata partially materialized output"
done

nonempty_output="$fixture_root/nonempty-output"
/bin/mkdir "$nonempty_output"
printf 'preserve\n' >"$nonempty_output/sentinel"
expect_failure extract-nonempty-output run_transport extract \
  --archive "$archive_one" \
  --expected-sha256 "$archive_sha256" \
  --inventory "$inventory_one" \
  --output-dir "$nonempty_output"
[ "$(<"$nonempty_output/sentinel")" = preserve ] \
  || fail "non-empty rejected output was modified"
[ "$(find "$nonempty_output" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" -eq 1 ] \
  || fail "non-empty rejected output received extracted files"

archive_symlink="$fixture_root/archive-symlink.tar"
/bin/ln -s "$archive_one" "$archive_symlink"
archive_symlink_output="$fixture_root/archive-symlink-output"
/bin/mkdir "$archive_symlink_output"
expect_failure extract-archive-symlink run_transport extract \
  --archive "$archive_symlink" \
  --expected-sha256 "$archive_sha256" \
  --inventory "$inventory_one" \
  --output-dir "$archive_symlink_output"

inventory_symlink="$fixture_root/inventory-symlink"
/bin/ln -s "$inventory_one" "$inventory_symlink"
inventory_symlink_output="$fixture_root/inventory-symlink-output"
/bin/mkdir "$inventory_symlink_output"
expect_failure extract-inventory-symlink run_transport extract \
  --archive "$archive_one" \
  --expected-sha256 "$archive_sha256" \
  --inventory "$inventory_symlink" \
  --output-dir "$inventory_symlink_output"

archive_hardlink="$fixture_root/archive-hardlink.tar"
/bin/ln "$archive_one" "$archive_hardlink"
archive_hardlink_output="$fixture_root/archive-hardlink-output"
/bin/mkdir "$archive_hardlink_output"
expect_failure extract-archive-hardlink run_transport extract \
  --archive "$archive_hardlink" \
  --expected-sha256 "$archive_sha256" \
  --inventory "$inventory_one" \
  --output-dir "$archive_hardlink_output"

inventory_hardlink="$fixture_root/inventory-hardlink"
/bin/ln "$inventory_one" "$inventory_hardlink"
inventory_hardlink_output="$fixture_root/inventory-hardlink-output"
/bin/mkdir "$inventory_hardlink_output"
expect_failure extract-inventory-hardlink run_transport extract \
  --archive "$archive_one" \
  --expected-sha256 "$archive_sha256" \
  --inventory "$inventory_hardlink" \
  --output-dir "$inventory_hardlink_output"

shadow_dir="$fixture_root/shadow"
/bin/mkdir "$shadow_dir"
/bin/cp "$transport" "$shadow_dir/transport.py"
for shadow_module in argparse hashlib io os pathlib stat sys tarfile; do
  printf 'raise RuntimeError("attacker module imported")\n' \
    >"$shadow_dir/$shadow_module.py"
done
shadow_archive="$fixture_root/shadow.tar"
shadow_inventory="$fixture_root/shadow.inventory"
shadow_sha="$(
  cd "$shadow_dir"
  /usr/bin/env -i "$python3_binary" -I -B "$shadow_dir/transport.py" create \
    --input-dir "$valid_input" \
    --archive "$shadow_archive" \
    --inventory "$shadow_inventory"
)"
[ "$shadow_sha" = "$archive_sha256" ] \
  || fail "isolated execution reported a different archive SHA-256"
/usr/bin/cmp -s "$archive_one" "$shadow_archive" \
  || fail "isolated execution changed the deterministic archive"
/usr/bin/cmp -s "$inventory_one" "$shadow_inventory" \
  || fail "isolated execution changed deterministic inventory metadata"

printf 'WASM release transport test passed\n'
