#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'release helper capture test failed: %s\n' "$1" >&2
  exit 1
}

repo_root="$(pwd -P)"
capture_helper="$repo_root/tools/capture_release_helper.sh"
source_guard="$repo_root/tools/verify_release_source.sh"
[[ -f "$capture_helper" ]] || fail "$capture_helper is missing"
[[ -f "$source_guard" ]] || fail "$source_guard is missing"

fixture_root="$(mktemp -d)"
fixture_checkout="$fixture_root/checkout"
trusted_marker="$fixture_root/trusted-helper-ran"
attacker_marker="$fixture_root/attacker-helper-ran"
trap '/bin/rm -rf -- "$fixture_root"' EXIT

/usr/bin/git init -q "$fixture_checkout"
/usr/bin/git -C "$fixture_checkout" config user.name EXOCHAIN
/usr/bin/git -C "$fixture_checkout" config user.email release-test@example.invalid
/bin/mkdir -p "$fixture_checkout/tools"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  ': > "$TRUSTED_HELPER_MARKER"' \
  > "$fixture_checkout/tools/lifecycle-helper.sh"
/bin/chmod 755 "$fixture_checkout/tools/lifecycle-helper.sh"
/bin/cp -- "$source_guard" "$fixture_checkout/tools/verify_release_source.sh"
/usr/bin/git -C "$fixture_checkout" add tools
/usr/bin/git -C "$fixture_checkout" commit -qm fixture
fixture_sha="$(/usr/bin/git -C "$fixture_checkout" rev-parse HEAD)"
helper_blob="$(/usr/bin/git -C "$fixture_checkout" rev-parse "$fixture_sha:tools/lifecycle-helper.sh")"

# Force the trusted helper into a pack, then unpack that reviewed pack before
# replacing the expected loose-object pathname. Keeping the old pack visible is
# not a reliable reproducer because Git may prefer it over a corrupt loose
# shadow. This sequence models a lifecycle process repacking/unpacking objects
# and then overwriting the resulting loose file.
/usr/bin/git -C "$fixture_checkout" gc --prune=now --quiet
loose_object="$fixture_checkout/.git/objects/${helper_blob:0:2}/${helper_blob:2}"
[ ! -e "$loose_object" ] || fail "fixture helper blob must begin packed-only"
hidden_pack_dir="$fixture_checkout/.git/objects/pack.reviewed"
/bin/mv -- "$fixture_checkout/.git/objects/pack" "$hidden_pack_dir"
/bin/mkdir -p "$fixture_checkout/.git/objects/pack"
reviewed_pack="$(/usr/bin/find "$hidden_pack_dir" -maxdepth 1 -type f -name 'pack-*.pack' -print)"
[ -n "$reviewed_pack" ] && [ "$(printf '%s\n' "$reviewed_pack" | /usr/bin/wc -l | /usr/bin/tr -d ' ')" -eq 1 ] \
  || fail "fixture must contain exactly one reviewed pack"
/usr/bin/git -C "$fixture_checkout" unpack-objects < "$reviewed_pack"
[ -f "$loose_object" ] || fail "fixture helper blob must become a valid loose object"

EXPECTED_COMMIT_SHA="$fixture_sha" \
  GITHUB_SHA="$fixture_sha" \
  GITHUB_WORKSPACE="$fixture_checkout" \
  RUNNER_TEMP="$fixture_root" \
  TRUSTED_RELEASE_REF="$fixture_sha" \
  /bin/bash --noprofile --norc -p "$source_guard" >/dev/null \
  || fail "source verification must accept the intact unpacked-object control"

GITHUB_WORKSPACE="$fixture_checkout"
GITHUB_SHA="$fixture_sha"
# shellcheck source=tools/capture_release_helper.sh
source "$capture_helper"
capture_release_helper tools/lifecycle-helper.sh captured_helper

malicious_helper="$fixture_root/malicious-helper.sh"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  ': > "$ATTACKER_HELPER_MARKER"' \
  > "$malicious_helper"
/bin/mkdir -p "$(/usr/bin/dirname "$loose_object")"
/bin/chmod u+w "$loose_object"
/usr/bin/python3 -I -B - "$malicious_helper" "$loose_object" <<'PY'
import pathlib
import sys
import zlib

source_path = pathlib.Path(sys.argv[1])
object_path = pathlib.Path(sys.argv[2])
payload = source_path.read_bytes()
object_path.write_bytes(zlib.compress(b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload))
PY

late_helper="$(/usr/bin/git -C "$fixture_checkout" show "$fixture_sha:tools/lifecycle-helper.sh")"
grep -F 'ATTACKER_HELPER_MARKER' <<<"$late_helper" >/dev/null \
  || fail "ordinary Git show must reproduce the packed-to-loose object substitution"
if grep -F 'TRUSTED_HELPER_MARKER' <<<"$late_helper" >/dev/null; then
  fail "ordinary Git show unexpectedly retained the packed helper bytes"
fi

printf '%s' "$late_helper" | \
  /usr/bin/env -i ATTACKER_HELPER_MARKER="$attacker_marker" \
    /bin/bash --noprofile --norc -p
[ -e "$attacker_marker" ] \
  || fail "late Git helper load must demonstrate attacker-code execution"

printf '%s' "$captured_helper" | \
  /usr/bin/env -i TRUSTED_HELPER_MARKER="$trusted_marker" \
    /bin/bash --noprofile --norc -p
[ -e "$trusted_marker" ] \
  || fail "pre-lifecycle in-memory helper bytes must preserve legitimate execution"

if EXPECTED_COMMIT_SHA="$fixture_sha" \
  GITHUB_SHA="$fixture_sha" \
  GITHUB_WORKSPACE="$fixture_checkout" \
  RUNNER_TEMP="$fixture_root" \
  TRUSTED_RELEASE_REF="$fixture_sha" \
  /bin/bash --noprofile --norc -p "$source_guard" >/dev/null 2>&1; then
  fail "source verification must reject the corrupt loose object before lifecycle execution"
fi

printf 'release helper capture test passed\n'
