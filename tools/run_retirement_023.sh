#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

if /usr/bin/env | /usr/bin/grep -Eq '^BASH_FUNC_.*%%='; then
  /bin/echo 'retirement rejected: inherited shell functions are forbidden' >&2
  exit 1
fi
set -euo pipefail
umask 077

fail() { printf 'retirement rejected: %s\n' "$1" >&2; exit 1; }

[ "${GITHUB_ACTIONS:-}" = true ] \
  && [ "${GITHUB_REPOSITORY:-}" = exochain/exochain ] \
  && [ "${GITHUB_SERVER_URL:-}" = https://github.com ] \
  && [ "${GITHUB_EVENT_NAME:-}" = workflow_dispatch ] \
  || fail 'requires the canonical workflow-dispatch context'
[[ "${RETIREMENT_TAG:-}" =~ ^v0\.2\.7-retire-0\.2\.3\.[1-9][0-9]*$ ]] \
  || fail 'invalid maintenance tag'
[ "${GITHUB_REF:-}" = "refs/tags/$RETIREMENT_TAG" ] \
  || fail 'dispatch must use the exact maintenance tag'
[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]] \
  || fail 'dispatch SHA must be a full commit identity'
case "${DRY_RUN:-}" in true|false) ;; *) fail 'DRY_RUN must be exactly true or false' ;; esac
[[ "${GITHUB_WORKSPACE:-}" = /* ]] && [ -d "$GITHUB_WORKSPACE" ] \
  || fail 'workspace must be an absolute directory'
[[ "${RUNNER_TEMP:-}" = /* ]] && [ -d "$RUNNER_TEMP" ] \
  || fail 'runner temporary directory is required'
retirement_workspace="$(cd "$GITHUB_WORKSPACE" && pwd -P)"
retirement_temp="$(cd "$RUNNER_TEMP" && pwd -P)"
case "$retirement_temp/" in "$retirement_workspace/"*) fail 'temporary directory must be outside source' ;; esac
[ -n "${RELEASE_GITHUB_TOKEN:-}" ] || fail 'authoritative tag lookup token is required'
[ -n "${EXOCHAIN_RELEASE_SIGNING_PUBLIC_KEY_ASC:-}" ] || fail 'release verification key is required'
[ -n "${EXOCHAIN_CRATES_IO_ALLOWED_OWNERS:-}" ] || fail 'approved crates.io owners must be configured'
if [ "$DRY_RUN" = false ]; then
  [ -n "${CARGO_REGISTRY_TOKEN:-}" ] || fail 'protected Cargo token is required for apply'
fi

# Never pass registry credentials, caller Git configuration or executable hooks
# to source inspection. Verify object integrity before reading helpers.
retirement_git() {
  /usr/bin/env -i PATH=/usr/bin:/bin GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git --no-replace-objects -c core.fsmonitor=false \
      -c core.untrackedCache=false -c core.ignoreStat=false \
      -C "$retirement_workspace" "$@"
}
retirement_git fsck --strict --no-reflogs --no-progress --no-dangling "$GITHUB_SHA" >/dev/null
source_program="$(retirement_git show "$GITHUB_SHA:tools/verify_release_source.sh")"
printf '%s' "$source_program" | /usr/bin/env -i PATH=/usr/bin:/bin \
  GITHUB_WORKSPACE="$retirement_workspace" RUNNER_TEMP="$retirement_temp" \
  GITHUB_SHA="$GITHUB_SHA" EXPECTED_COMMIT_SHA="$GITHUB_SHA" TRUSTED_RELEASE_REF="$GITHUB_SHA" \
  /bin/bash --noprofile --norc -p

signer_program="$(retirement_git show "$GITHUB_SHA:tools/verify_release_tag_signer.sh")"
tag_program="$(retirement_git show "$GITHUB_SHA:tools/verify_release_tag.sh")"
owner_program="$(retirement_git show "$GITHUB_SHA:tools/check_cratesio_namespace_ownership.mjs")"
registry_program="$(retirement_git show "$GITHUB_SHA:tools/retire_crates_023.py")"

retirement_tag_object="$(retirement_git rev-parse "refs/tags/$RETIREMENT_TAG")"
retirement_tag_commit="$(retirement_git rev-parse "refs/tags/$RETIREMENT_TAG^{commit}")"
[ "$(retirement_git cat-file -t "$retirement_tag_object")" = tag ] \
  || fail 'maintenance tag must be annotated and signed'
[ "$retirement_tag_commit" = "$GITHUB_SHA" ] || fail 'maintenance tag commit differs from dispatch'
retirement_git fsck --strict --no-reflogs --no-progress --no-dangling "$retirement_tag_object" >/dev/null
retirement_gpg="$(/usr/bin/mktemp -d "$retirement_temp/retirement-gpg.XXXXXX")"
trap '/bin/rm -rf -- "$retirement_gpg"' EXIT
printf '%s\n' "$EXOCHAIN_RELEASE_SIGNING_PUBLIC_KEY_ASC" | \
  /usr/bin/env -i PATH=/usr/bin:/bin GNUPGHOME="$retirement_gpg" /usr/bin/gpg --batch --import
printf '%s' "$signer_program" | /usr/bin/env -i PATH=/usr/bin:/bin \
  GITHUB_WORKSPACE="$retirement_workspace" GITHUB_ACTIONS=true GNUPGHOME="$retirement_gpg" \
  RELEASE_TAG="$RETIREMENT_TAG" EXOCHAIN_RELEASE_SIGNING_FINGERPRINT="${EXOCHAIN_RELEASE_SIGNING_FINGERPRINT:-}" \
  /bin/bash --noprofile --norc -p
printf '%s' "$tag_program" | /usr/bin/env -i PATH=/usr/bin:/bin \
  GITHUB_WORKSPACE="$retirement_workspace" GITHUB_ACTIONS=true \
  GITHUB_SERVER_URL=https://github.com GITHUB_REPOSITORY=exochain/exochain \
  GITHUB_SHA="$GITHUB_SHA" EXPECTED_COMMIT_SHA="$GITHUB_SHA" DRY_RUN=false \
  RELEASE_TAG="$RETIREMENT_TAG" EXPECTED_TAG_OBJECT_SHA="$retirement_tag_object" \
  EXPECTED_TAG_COMMIT_SHA="$retirement_tag_commit" RELEASE_GITHUB_TOKEN="$RELEASE_GITHUB_TOKEN" \
  /bin/bash --noprofile --norc -p

# Interpreter setup ran in separate, token-free steps. Resolve immutable native
# paths and require the reviewed versions; never import from repository paths.
[[ "${RETIREMENT_PYTHON:-}" = /* ]] && [ -x "$RETIREMENT_PYTHON" ] \
  || fail 'pinned Python interpreter is required'
retirement_python="$(/usr/bin/realpath "$RETIREMENT_PYTHON")"
retirement_node="$(/usr/bin/realpath "$(command -v node)")"
[ "$(/usr/bin/env -i "$retirement_python" -I -B -c 'import platform; print(platform.python_version())')" = 3.13.7 ] \
  || fail 'Python must be exactly 3.13.7'
[ "$(/usr/bin/env -i "$retirement_node" --version)" = v22.14.0 ] \
  || fail 'Node must be exactly 22.14.0'
inventory="$(printf '%s' "$registry_program" | /usr/bin/env -i \
  "$retirement_python" -I -B - --inventory)"
inventory_count=0
while IFS= read -r crate; do
  [[ "$crate" =~ ^exochain-[a-z0-9-]+$ ]] && [ "$crate" != exochain-pdp ] \
    || fail 'fixed retirement inventory is malformed'
  inventory_count=$((inventory_count + 1))
  printf '%s' "$owner_program" | /usr/bin/env -i \
    EXOCHAIN_CRATES_IO_ALLOWED_OWNERS="$EXOCHAIN_CRATES_IO_ALLOWED_OWNERS" \
    EXOCHAIN_CRATES_IO_REQUIRE_CLAIMED=true EXOCHAIN_CRATES_IO_EXACT_TARGET="$crate" \
    "$retirement_node" --input-type=module -
done <<< "$inventory"
[ "$inventory_count" -eq 31 ] || fail 'fixed retirement inventory must contain exactly 31 crates'

receipt_path="$retirement_temp/retirement-023-receipts.jsonl"
[ ! -e "$receipt_path" ] && [ ! -L "$receipt_path" ] || fail 'receipt destination already exists'
if [ "$DRY_RUN" = true ]; then
  printf '%s' "$registry_program" | /usr/bin/env -i \
    "$retirement_python" -I -B - > "$receipt_path"
else
  printf '%s' "$registry_program" | /usr/bin/env -i \
    CARGO_REGISTRY_TOKEN="$CARGO_REGISTRY_TOKEN" \
    "$retirement_python" -I -B - --apply > "$receipt_path"
fi
printf 'Retirement operation completed; structured receipts: %s\n' "$receipt_path"
