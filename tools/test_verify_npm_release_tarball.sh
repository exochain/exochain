#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'npm tarball guard test failed: %s\n' "$1" >&2
  exit 1
}

repo_root="$(pwd -P)"
guard_source="$repo_root/tools/verify_npm_release_tarball.py"
[ -f "$guard_source" ] || fail "$guard_source is missing"

fixture_root="$(mktemp -d)"
helper_dir="$fixture_root/helper"
package_root="$fixture_root/source/package"
valid_archive="$fixture_root/valid.tgz"
symlink_archive="$fixture_root/symlink.tgz"
traversal_archive="$fixture_root/traversal.tgz"
raw_trailer_archive="$fixture_root/raw-trailer.tgz"
concatenated_archive="$fixture_root/concatenated.tgz"
compressed_bomb_archive="$fixture_root/compressed-bomb.tgz"
many_members_archive="$fixture_root/many-members.tgz"
python_shadow_marker="$fixture_root/python-shadow-ran"
trap '/bin/rm -rf -- "$fixture_root"' EXIT
mkdir -p "$helper_dir" "$package_root"
cp "$guard_source" "$helper_dir/guard.py"
printf 'fixture\n' > "$package_root/package.json"
/usr/bin/env -i COPYFILE_DISABLE=1 TAR_OPTIONS= GZIP= /usr/bin/tar -czf "$valid_archive" \
  -C "$fixture_root/source" package

cat > "$helper_dir/tarfile.py" <<'PYTHON_SHADOW'
import os
with open(os.environ["PYTHON_SHADOW_MARKER"], "w", encoding="utf-8") as marker:
    marker.write("shadowed")
raise RuntimeError("attacker tarfile module imported")
PYTHON_SHADOW
cat > "$helper_dir/hashlib.py" <<'PYTHON_SHADOW'
import os
with open(os.environ["PYTHON_SHADOW_MARKER"], "w", encoding="utf-8") as marker:
    marker.write("shadowed")
raise RuntimeError("attacker hashlib module imported")
PYTHON_SHADOW
(
  cd "$helper_dir"
  /usr/bin/env -i \
    PYTHON_SHADOW_MARKER="$python_shadow_marker" \
    /usr/bin/python3 -I -B "$helper_dir/guard.py" \
      "$valid_archive" "$fixture_root/valid-output"
)
[ ! -e "$python_shadow_marker" ] \
  || fail "isolated Python must not import attacker modules from cwd or helper directory"
/usr/bin/cmp -s \
  "$package_root/package.json" \
  "$fixture_root/valid-output/package/package.json" \
  || fail "valid npm tarball must extract exact regular-file bytes"

/bin/cp "$valid_archive" "$raw_trailer_archive"
printf 'attacker-raw-trailer' >> "$raw_trailer_archive"
if /usr/bin/env -i /usr/bin/python3 -I -B "$helper_dir/guard.py" \
  "$raw_trailer_archive" "$fixture_root/raw-trailer-output" >/dev/null 2>&1; then
  fail "npm tarball guard must reject bytes after the one gzip member"
fi

/bin/cat "$valid_archive" "$valid_archive" > "$concatenated_archive"
if /usr/bin/env -i /usr/bin/python3 -I -B "$helper_dir/guard.py" \
  "$concatenated_archive" "$fixture_root/concatenated-output" >/dev/null 2>&1; then
  fail "npm tarball guard must reject a concatenated second gzip member"
fi

# Exercise resource cutoffs at a small test-only value by importing the exact
# production helper and overriding only its constants in this isolated process.
/usr/bin/env -i /usr/bin/python3 -I -B - "$helper_dir/guard.py" "$compressed_bomb_archive" <<'PY'
import gzip
import importlib.util
import pathlib
import sys

guard_path = pathlib.Path(sys.argv[1])
bomb_path = pathlib.Path(sys.argv[2])
bomb_path.write_bytes(gzip.compress(b"A" * 1_000_000, mtime=0))
spec = importlib.util.spec_from_file_location("release_tar_guard", guard_path)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
guard.MAX_TAR_STREAM_SIZE = 10
try:
    guard.read_one_gzip_member(bomb_path)
except SystemExit:
    pass
else:
    raise SystemExit("gzip expansion beyond the bound was accepted")
PY

/usr/bin/env -i /usr/bin/python3 -I -B - "$many_members_archive" <<'PY'
import io
import sys
import tarfile

with tarfile.open(sys.argv[1], "w:gz") as archive:
    for index in range(9):
        member = tarfile.TarInfo(f"package/empty-{index}")
        member.size = 0
        archive.addfile(member, io.BytesIO())
PY
if /usr/bin/env -i /usr/bin/python3 -I -B - \
  "$helper_dir/guard.py" "$many_members_archive" "$fixture_root/many-members-output" <<'PY'
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("release_tar_guard", pathlib.Path(sys.argv[1]))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
guard.MAX_MEMBERS = 8
sys.argv = [str(sys.argv[1]), str(sys.argv[2]), str(sys.argv[3])]
guard.main()
PY
then
  fail "npm tarball guard must stop parsing at the member-count bound"
fi

ln -s package.json "$package_root/link"
/usr/bin/env -i COPYFILE_DISABLE=1 TAR_OPTIONS= GZIP= /usr/bin/tar -czf "$symlink_archive" \
  -C "$fixture_root/source" package
if /usr/bin/env -i /usr/bin/python3 -I -B "$helper_dir/guard.py" \
  "$symlink_archive" "$fixture_root/symlink-output" >/dev/null 2>&1; then
  fail "npm tarball guard must reject symbolic-link members"
fi
rm "$package_root/link"

/usr/bin/env -i /usr/bin/python3 -I -B - "$traversal_archive" <<'PY'
import io
import sys
import tarfile

with tarfile.open(sys.argv[1], "w:gz") as archive:
    payload = b"escape\n"
    member = tarfile.TarInfo("package/../escape")
    member.size = len(payload)
    archive.addfile(member, io.BytesIO(payload))
PY
if /usr/bin/env -i /usr/bin/python3 -I -B "$helper_dir/guard.py" \
  "$traversal_archive" "$fixture_root/traversal-output" >/dev/null 2>&1; then
  fail "npm tarball guard must reject traversal members"
fi
[ ! -e "$fixture_root/traversal-output/escape" ] \
  || fail "rejected traversal member must not escape the extraction root"

open_count="$(grep -cF 'with tarfile.open(fileobj=io.BytesIO(tar_stream), mode="r:") as bundle:' "$guard_source")"
[ "$open_count" -eq 1 ] \
  || fail "tarball guard must inspect and extract the one validated gzip member through one tar handle"
if grep -E 'tar[[:space:]]+-(t|x)|subprocess' "$guard_source" >/dev/null; then
  fail "tarball guard must not use a check-then-extract subprocess path"
fi
if grep -F 'bundle.getmembers()' "$guard_source" >/dev/null; then
  fail "tarball guard must enforce its member bound while iterating"
fi

printf 'npm tarball guard test passed\n'
