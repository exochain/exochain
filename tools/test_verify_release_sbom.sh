#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'release SBOM validator test failed: %s\n' "$1" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
validator="$repo_root/tools/verify_release_sbom.py"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/exochain-sbom-validator-test.XXXXXX")"
trap '/bin/rm -rf -- "$test_root"' EXIT

[[ -f "$validator" ]] || fail "SBOM validator is missing"
python_path="${PYTHON:-$(command -v python3)}"
python_path="$($python_path -c 'import os,sys; print(os.path.realpath(sys.executable))')"
[ -f "$python_path" ] && [ -x "$python_path" ] && [ ! -L "$python_path" ] \
  || fail "a real Python interpreter is required"
"$python_path" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
  || fail "Python 3.11 or newer is required"

cargo_path="$(command -v cargo)"
[ -x "$cargo_path" ] || fail "Cargo is unavailable"
[ "$("$cargo_path" cyclonedx --version)" = "cargo-cyclonedx-cyclonedx 0.5.9" ] \
  || fail "cargo-cyclonedx must be exactly 0.5.9"

source_root="$test_root/source-one"
raw_root="$test_root/raw-one"
metadata_file="$test_root/metadata-one.json"
lock_file="$test_root/Cargo-one.lock"
/bin/mkdir -m 700 -p "$source_root" "$raw_root"
/usr/bin/git -C "$repo_root" archive --format=tar HEAD | \
  /usr/bin/env -i TAR_OPTIONS= /usr/bin/tar -xf - -C "$source_root"

(cd "$source_root" && \
  SOURCE_DATE_EPOCH=0 "$cargo_path" cyclonedx \
    --manifest-path "$source_root/Cargo.toml" \
    -f json --all --target all --spec-version 1.5)
"$cargo_path" metadata --manifest-path "$source_root/Cargo.toml" \
  --format-version 1 --locked > "$metadata_file"
/bin/cp -- "$source_root/Cargo.lock" "$lock_file"

while IFS= read -r -d '' raw_file; do
  raw_name="$(/usr/bin/basename "$raw_file")"
  [ ! -e "$raw_root/$raw_name" ] && [ ! -L "$raw_root/$raw_name" ] \
    || fail "cargo-cyclonedx produced duplicate flat SBOM names"
  /bin/cp -- "$raw_file" "$raw_root/$raw_name"
done < <(/usr/bin/find "$source_root/crates" -type f -name '*.cdx.json' -print0 | /usr/bin/sort -z)
[ "$(/usr/bin/find "$raw_root" -mindepth 1 -maxdepth 1 -type f | /usr/bin/wc -l | /usr/bin/tr -d ' ')" -eq 32 ] \
  || fail "cargo-cyclonedx did not produce exactly 32 flat raw SBOMs"

run_validator() {
  local input_dir="$1"
  local metadata="$2"
  local lock="$3"
  local output_dir="$4"
  shift 4
  "$python_path" -I -B "$validator" \
    --input-dir "$input_dir" \
    --cargo-metadata "$metadata" \
    --cargo-lock "$lock" \
    --output-dir "$output_dir" \
    --version 0.2.6 \
    --forbid-prefix "$test_root" \
    "$@"
}

canonical_one="$test_root/canonical-one"
canonical_two="$test_root/canonical-two"
digest_one="$(run_validator "$raw_root" "$metadata_file" "$lock_file" "$canonical_one")"
digest_two="$(run_validator "$raw_root" "$metadata_file" "$lock_file" "$canonical_two")"
expected_digest=4625d65eee8bb844f4dfb87cc97da797afdbc8c41a4ee0a892d3b83325d2e32c
[ "$digest_one" = "$expected_digest" ] && [ "$digest_two" = "$expected_digest" ] \
  || fail "exact cargo-cyclonedx 0.5.9 corpus did not produce the reviewed canonical digest"
/usr/bin/diff -ru "$canonical_one" "$canonical_two" >/dev/null \
  || fail "repeated validation did not produce byte-identical canonical SBOMs"

"$python_path" -I -B - "$canonical_one" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
files = sorted(root.iterdir())
if len(files) != 32:
    raise SystemExit("canonical inventory is not exactly 32 files")
for path in files:
    payload = path.read_bytes()
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise SystemExit(f"{path.name} is not compact canonical JSON plus LF")
    value = json.loads(payload)
    if value.get("$schema") != "http://cyclonedx.org/schema/bom-1.5.schema.json":
        raise SystemExit(f"{path.name} does not bind the official CycloneDX 1.5 schema URI")
    if value.get("bomFormat") != "CycloneDX" or value.get("specVersion") != "1.5":
        raise SystemExit(f"{path.name} is not a CycloneDX 1.5 document")
    if json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n" != payload:
        raise SystemExit(f"{path.name} is not idempotently canonical")
PY

primary_raw="$raw_root/exochain-core.cdx.json"
target_raw="$raw_root/exochain-node.cdx.json"
primary_backup="$test_root/exochain-core.backup"
target_backup="$test_root/exochain-node.backup"
/bin/cp -- "$primary_raw" "$primary_backup"
/bin/cp -- "$target_raw" "$target_backup"
negative_index=0

restore_raw_files() {
  /bin/rm -f -- "$primary_raw" "$target_raw"
  /bin/cp -- "$primary_backup" "$primary_raw"
  /bin/cp -- "$target_backup" "$target_raw"
}

expect_rejected() {
  local label="$1"
  local output_dir="$test_root/rejected-$negative_index"
  negative_index=$((negative_index + 1))
  if run_validator "$raw_root" "$metadata_file" "$lock_file" "$output_dir" \
      >"$test_root/rejected.out" 2>&1; then
    fail "$label was accepted"
  fi
  restore_raw_files
}

mutate_json() {
  local operation="$1"
  local path="${2:-$primary_raw}"
  "$python_path" -I -B - "$path" "$operation" "$test_root" <<'PY'
import copy
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
operation = sys.argv[2]
test_root = sys.argv[3]
document = json.loads(path.read_bytes())
if operation == "top-level-claim":
    document["vulnerabilities"] = [{"id": "forged"}]
elif operation == "root-description":
    document["metadata"]["component"]["description"] = "attacker supplied claim"
elif operation == "absolute-path":
    document["metadata"]["component"]["description"] = test_root + "/secret"
elif operation == "extra-property":
    document["metadata"]["properties"].append({"name": "exochain:forged", "value": "true"})
elif operation == "scope-flip":
    component = next(item for item in document["components"] if item["scope"] == "excluded")
    component["scope"] = "required"
elif operation == "wrong-checksum":
    component = next(item for item in document["components"] if "hashes" in item)
    component["hashes"][0]["content"] = "0" * 64
elif operation == "wrong-tool":
    document["metadata"]["tools"][0]["version"] = "0.5.8"
elif operation == "wrong-timestamp":
    document["metadata"]["timestamp"] = "2026-09-03T00:00:00Z"
elif operation == "omit-leaf":
    edges = {item["ref"]: item.get("dependsOn", []) for item in document["dependencies"]}
    incoming = {target for targets in edges.values() for target in targets}
    leaf = next(item["bom-ref"] for item in document["components"] if not edges[item["bom-ref"]] and item["bom-ref"] in incoming)
    document["components"] = [item for item in document["components"] if item["bom-ref"] != leaf]
    document["dependencies"] = [item for item in document["dependencies"] if item["ref"] != leaf]
    for item in document["dependencies"]:
        if "dependsOn" in item:
            item["dependsOn"] = [target for target in item["dependsOn"] if target != leaf]
elif operation == "alter-edge":
    entry = next(item for item in document["dependencies"] if item.get("dependsOn"))
    entry["dependsOn"] = entry["dependsOn"][1:]
elif operation == "missing-dependency-record":
    document["dependencies"].pop()
elif operation == "reverse-targets":
    document["metadata"]["component"]["components"].reverse()
elif operation == "duplicate-target":
    targets = document["metadata"]["component"]["components"]
    duplicate = copy.deepcopy(targets[0])
    duplicate["bom-ref"] = duplicate["bom-ref"].rsplit("-", 1)[0] + "-9999"
    targets.append(duplicate)
else:
    raise SystemExit(f"unknown mutation {operation}")
path.write_text(json.dumps(document, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

for mutation in \
  top-level-claim root-description absolute-path extra-property scope-flip \
  wrong-checksum wrong-tool wrong-timestamp omit-leaf alter-edge \
  missing-dependency-record; do
  mutate_json "$mutation"
  expect_rejected "$mutation mutation"
done

mutate_json duplicate-target "$target_raw"
expect_rejected "duplicate nested target identity"

mutate_json reverse-targets "$target_raw"
permuted_output="$test_root/canonical-permuted-targets"
permuted_digest="$(run_validator "$raw_root" "$metadata_file" "$lock_file" "$permuted_output")"
[ "$permuted_digest" = "$digest_one" ] \
  && /usr/bin/diff -ru "$canonical_one" "$permuted_output" >/dev/null \
  || fail "equivalent nested-target permutation changed canonical bytes"
restore_raw_files

"$python_path" -I -B - "$primary_raw" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
payload = path.read_bytes()
path.write_bytes(payload.replace(b"{", b'{"version":1,', 1))
PY
expect_rejected "duplicate JSON key"

"$python_path" -I -B - "$primary_raw" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
payload = path.read_bytes()
path.write_bytes(payload.replace(b"{", b'{"unexpected":NaN,', 1))
PY
expect_rejected "non-finite JSON value"

"$python_path" -I -B - "$primary_raw" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
document = json.loads(path.read_bytes())
value = "leaf"
for _ in range(100):
    value = [value]
document["unexpected"] = value
path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
PY
expect_rejected "excessive JSON depth"

"$python_path" -I -B - "$primary_raw" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).write_bytes(b" " * (8 * 1024 * 1024 + 1))
PY
expect_rejected "oversized raw SBOM"

/bin/mv -- "$primary_raw" "$test_root/missing-raw"
expect_rejected "missing raw SBOM inventory member"
/bin/cp -- "$primary_backup" "$primary_raw"
: > "$raw_root/attacker.cdx.json"
expect_rejected "extra raw SBOM inventory member"
/bin/rm -f -- "$raw_root/attacker.cdx.json"
/bin/rm -f -- "$primary_raw"
/bin/ln -s "$primary_backup" "$primary_raw"
expect_rejected "symlinked raw SBOM"
/bin/rm -f -- "$primary_raw"
/bin/ln "$primary_backup" "$primary_raw"
expect_rejected "hard-linked raw SBOM"

# Keep a valid document just below the byte cap while another process changes
# its trailing JSON whitespace. The single-descriptor stability check must
# reject the active writer rather than canonicalizing racing bytes.
"$python_path" -I -B - "$primary_raw" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
payload = path.read_bytes().rstrip() + b"\n"
target = 8 * 1024 * 1024 - 1
path.write_bytes(payload + b" " * (target - len(payload)))
PY
writer_ready="$test_root/writer-ready"
writer_stop="$test_root/writer-stop"
"$python_path" -I -B - "$primary_raw" "$writer_ready" "$writer_stop" <<'PY' &
import os
from pathlib import Path
import sys

path, ready, stop = map(Path, sys.argv[1:])
with path.open("r+b", buffering=0) as handle:
    offset = path.stat().st_size - 1
    ready.touch()
    toggle = False
    while not stop.exists():
        handle.seek(offset)
        handle.write(b"\t" if toggle else b" ")
        toggle = not toggle
PY
writer_pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -e "$writer_ready" ] && break
  /bin/sleep 0.1
done
[ -e "$writer_ready" ] || fail "active-writer fixture did not start"
active_writer_output="$test_root/active-writer-output"
if run_validator "$raw_root" "$metadata_file" "$lock_file" "$active_writer_output" \
    >"$test_root/active-writer.out" 2>&1; then
  : > "$writer_stop"
  wait "$writer_pid" || true
  fail "actively modified raw SBOM was accepted"
fi
: > "$writer_stop"
wait "$writer_pid" || true
grep -F 'changed while it was read' "$test_root/active-writer.out" >/dev/null \
  || fail "active-writer rejection did not come from the stable-read boundary"
restore_raw_files

# Relocate every absolute workspace identity in both producer output and Cargo
# metadata. Canonical bytes must depend only on validated package semantics.
second_raw="$test_root/raw-two"
second_metadata="$test_root/metadata-two.json"
/bin/cp -R "$raw_root" "$second_raw"
/bin/cp -- "$metadata_file" "$second_metadata"
synthetic_root=/opt/exochain-independent-checkout
"$python_path" -I -B - "$second_raw" "$second_metadata" "$source_root" "$synthetic_root" <<'PY'
import json
from pathlib import Path
import sys

raw_root, metadata_path = Path(sys.argv[1]), Path(sys.argv[2])
old, new = sys.argv[3], sys.argv[4]

def relocate(value):
    if isinstance(value, dict):
        return {key: relocate(item) for key, item in value.items()}
    if isinstance(value, list):
        return [relocate(item) for item in value]
    if isinstance(value, str):
        return value.replace(old, new)
    return value

for path in sorted(raw_root.iterdir()):
    document = relocate(json.loads(path.read_bytes()))
    path.write_text(json.dumps(document, separators=(",", ":")) + "\n")
metadata = relocate(json.loads(metadata_path.read_bytes()))
metadata_path.write_text(json.dumps(metadata, separators=(",", ":")) + "\n")
PY
canonical_relocated="$test_root/canonical-relocated"
relocated_digest="$(run_validator \
  "$second_raw" "$second_metadata" "$lock_file" "$canonical_relocated" \
  --forbid-prefix "$synthetic_root")"
[ "$relocated_digest" = "$digest_one" ] \
  && /usr/bin/diff -ru "$canonical_one" "$canonical_relocated" >/dev/null \
  || fail "equivalent second checkout root changed canonical SBOM bytes"

printf 'release SBOM validator test passed\n'
