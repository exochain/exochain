#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

fail() {
  printf 'release signed-tag trust boundary test failed: %s\n' "$1" >&2
  exit 1
}

workflow=".github/workflows/release.yml"
ci_workflow=".github/workflows/ci.yml"
signer_guard="tools/verify_release_tag_signer.sh"

[[ -f "$workflow" ]] || fail "$workflow is missing"
[[ -f "$ci_workflow" ]] || fail "$ci_workflow is missing"
[[ -f "$signer_guard" ]] || fail "$signer_guard is missing"

verify_block=$(
  awk '
    $0 == "  verify-signed-tag:" { capture = 1; print; next }
    capture && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
    capture { print }
  ' "$workflow"
)
[[ -n "$verify_block" ]] || fail "verify-signed-tag job is missing"

grep -F 'tag_object_sha: ${{ steps.verify-tag.outputs.tag_object_sha }}' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must expose the cryptographically verified annotated-tag object ID"
grep -F 'tag_commit_sha: ${{ steps.verify-tag.outputs.tag_commit_sha }}' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must expose the verified tag's peeled commit"
grep -F 'id: verify-tag' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must use a stable output-producing verification step"
grep -F 'EXOCHAIN_RELEASE_SIGNING_PUBLIC_KEY_ASC: ${{ vars.EXOCHAIN_RELEASE_SIGNING_PUBLIC_KEY_ASC }}' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must receive the approved release public key from repository variables"
grep -F 'EXOCHAIN_RELEASE_SIGNING_FINGERPRINT: ${{ vars.EXOCHAIN_RELEASE_SIGNING_FINGERPRINT }}' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must receive the approved release signing fingerprint from repository variables"
grep -F 'BASH_ENV: /dev/null' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must neutralize BASH_ENV before invoking its immutable signer guard"
grep -F 'GNUPGHOME="$(mktemp -d)"' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must isolate the release verification keyring"
grep -F 'gpg --batch --import' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must import the approved release public key before verification"
grep -F '^[0-9A-F]{40}$' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must enforce a full 40-hex-character OpenPGP fingerprint"
grep -F 'ref: ${{ needs.validate-release-inputs.outputs.trusted_ref }}' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must check out the validated immutable trusted ref"
grep -F 'EXPECTED_COMMIT_SHA: ${{ needs.validate-release-inputs.outputs.commit_sha }}' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must consume the validated commit SHA"
grep -F 'TRUSTED_RELEASE_REF: ${{ needs.validate-release-inputs.outputs.trusted_ref }}' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must consume the validated trusted ref"
grep -F 'run: /bin/bash --noprofile --norc -p tools/verify_release_source.sh' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must execute the shared source-identity guard"
grep -F 'tag_type="$(git cat-file -t "refs/tags/${RELEASE_TAG}")"' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must inspect the release ref object type"
grep -F '"$tag_type" != "tag"' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must reject lightweight release tags"
grep -F 'unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must scrub persisted Git controls before loading its immutable signer guard"
grep -F '/usr/bin/env -i GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 /usr/bin/git --no-replace-objects -C "$GITHUB_WORKSPACE" show "${GITHUB_SHA}:tools/verify_release_tag_signer.sh" | BASH_ENV=/dev/null /bin/bash --noprofile --norc -p' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must execute signer verification from the immutable dispatch commit"
if grep -F 'git tag -v "${RELEASE_TAG}"' <<<"$verify_block" >/dev/null; then
  fail "verify-signed-tag must not accept any signer merely because git tag -v trusts an imported bundle"
fi
grep -F 'tag_object_sha="$(git rev-parse "refs/tags/${RELEASE_TAG}")"' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must capture the exact signed annotated-tag object ID"
grep -F 'peeled_commit="$(git rev-parse "refs/tags/${RELEASE_TAG}^{commit}")"' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must peel the verified release tag to a commit"
grep -F '"$peeled_commit" != "$EXPECTED_COMMIT_SHA"' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must bind the signed tag commit to the validated commit SHA"
grep -F '"$peeled_commit" != "$GITHUB_SHA"' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must bind the signed tag commit to the dispatch SHA"
grep -F 'printf '\''tag_object_sha=%s\n'\'' "$tag_object_sha" >> "$GITHUB_OUTPUT"' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must emit the verified tag-object ID"
grep -F 'printf '\''tag_commit_sha=%s\n'\'' "$peeled_commit" >> "$GITHUB_OUTPUT"' <<<"$verify_block" >/dev/null \
  || fail "verify-signed-tag must emit the verified peeled commit"

grep -F 'bash tools/test_release_signed_tag_trust_boundary.sh' "$ci_workflow" >/dev/null \
  || fail "CI repo hygiene must run the release signed-tag trust boundary guard"

repo_root="$(pwd -P)"
fixture_root="$(mktemp -d)"
# Keep GNUPGHOME paths short enough for gpg-agent Unix-domain sockets on macOS.
signing_home="$fixture_root/s"
verify_home="$fixture_root/v"
two_key_verify_home="$fixture_root/w"
fixture_repo="$fixture_root/r"
trap 'rm -rf "$fixture_root"' EXIT
mkdir -m 700 "$signing_home" "$verify_home" "$two_key_verify_home"

GNUPGHOME="$signing_home" gpg --batch --passphrase '' --quick-generate-key \
  'Approved Release Test <approved-release@example.invalid>' ed25519 cert 0 >/dev/null 2>&1
approved_primary="$({ GNUPGHOME="$signing_home" gpg --batch --with-colons --list-keys 2>/dev/null; } | awk -F: '/^fpr:/ { print toupper($10); exit }')"
[[ "$approved_primary" =~ ^[0-9A-F]{40}$ ]] || fail "could not create approved primary-key fixture"
GNUPGHOME="$signing_home" gpg --batch --passphrase '' --quick-add-key \
  "$approved_primary" ed25519 sign 0 >/dev/null 2>&1
approved_signing_subkey="$({ GNUPGHOME="$signing_home" gpg --batch --with-colons --list-keys "$approved_primary" 2>/dev/null; } | awk -F: '/^sub:/ { want = 1; next } /^fpr:/ && want { print toupper($10); exit }')"
[[ "$approved_signing_subkey" =~ ^[0-9A-F]{40}$ ]] || fail "could not create approved signing-subkey fixture"

GNUPGHOME="$signing_home" gpg --batch --passphrase '' --quick-generate-key \
  'Unapproved Release Test <unapproved-release@example.invalid>' ed25519 cert 0 >/dev/null 2>&1
second_primary="$({ GNUPGHOME="$signing_home" gpg --batch --with-colons --list-keys 2>/dev/null; } | awk -F: -v approved="$approved_primary" '
  /^pub:/ { want_primary_fingerprint = 1; next }
  /^fpr:/ && want_primary_fingerprint {
    candidate = toupper($10)
    want_primary_fingerprint = 0
    if (candidate != approved) { print candidate; exit }
  }
')"
[[ "$second_primary" =~ ^[0-9A-F]{40}$ ]] || fail "could not create second primary-key fixture"
GNUPGHOME="$signing_home" gpg --batch --passphrase '' --quick-add-key \
  "$second_primary" ed25519 sign 0 >/dev/null 2>&1

git init -q "$fixture_repo"
git -C "$fixture_repo" config user.name 'EXOCHAIN Release Test'
git -C "$fixture_repo" config user.email release-test@example.invalid
git -C "$fixture_repo" config commit.gpgSign false
git -C "$fixture_repo" config gpg.program gpg
printf 'signed source\n' > "$fixture_repo/source.txt"
git -C "$fixture_repo" add source.txt
git -C "$fixture_repo" commit -qm fixture
release_tag="v0.2.6"

# A cert-only approved primary must delegate signing to its legitimate signing
# subkey. The configured trust anchor remains the approved primary fingerprint.
git -C "$fixture_repo" config user.signingkey "$approved_primary"
GNUPGHOME="$signing_home" git -C "$fixture_repo" tag -s "$release_tag" -m 'approved subkey signature'
GNUPGHOME="$signing_home" gpg --batch --armor --export "$approved_primary" > "$fixture_root/approved.asc"
GNUPGHOME="$verify_home" gpg --batch --import "$fixture_root/approved.asc" >/dev/null 2>&1
(
  cd "$fixture_repo"
  GNUPGHOME="$verify_home" \
    RELEASE_TAG="$release_tag" \
    EXOCHAIN_RELEASE_SIGNING_FINGERPRINT="$approved_primary" \
    GITHUB_WORKSPACE="$fixture_repo" \
    BASH_ENV=/dev/null \
    bash "$repo_root/$signer_guard"
) >/dev/null || fail "signer guard must accept the approved primary's legitimate signing subkey"

# Importing an arbitrary bundle must not expand the trust boundary. A tag made
# by a second bundled primary signer must still be rejected when the configured
# trust anchor is the approved primary.
git -C "$fixture_repo" tag -d "$release_tag" >/dev/null
git -C "$fixture_repo" config user.signingkey "$second_primary"
GNUPGHOME="$signing_home" git -C "$fixture_repo" tag -s "$release_tag" -m 'second bundled signer'
GNUPGHOME="$signing_home" gpg --batch --armor --export "$approved_primary" "$second_primary" > "$fixture_root/two-key-bundle.asc"
GNUPGHOME="$two_key_verify_home" gpg --batch --import "$fixture_root/two-key-bundle.asc" >/dev/null 2>&1
if (
  cd "$fixture_repo"
  GNUPGHOME="$two_key_verify_home" \
    RELEASE_TAG="$release_tag" \
    EXOCHAIN_RELEASE_SIGNING_FINGERPRINT="$approved_primary" \
    GITHUB_WORKSPACE="$fixture_repo" \
    BASH_ENV=/dev/null \
    bash "$repo_root/$signer_guard"
) >/dev/null 2>&1; then
  fail "signer guard must reject a tag made by a second primary included in the imported bundle"
fi

printf 'release signed-tag trust boundary test passed\n'
