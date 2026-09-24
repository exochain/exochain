#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

# This identity-only wrapper is invoked before import and immediately before
# publication, with publishing credentials/OIDC omitted from its environment.
# The Actions caller must load this entry point from the real dispatch commit.
set -euo pipefail

fail() {
  printf 'release recovery identity failed: %s\n' "$1" >&2
  exit 1
}

[ "$#" -eq 0 ] || fail "this fixed recovery wrapper takes no arguments"
if /usr/bin/env | /usr/bin/grep -Eq '^BASH_FUNC_.*%%='; then
  fail "inherited shell functions are forbidden"
fi
for credential_name in CARGO_REGISTRY_TOKEN NPM_TOKEN NODE_AUTH_TOKEN \
    TWINE_PASSWORD PYPI_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL; do
  [ -z "${!credential_name:-}" ] || fail "publication credentials and OIDC must be absent during helper capture"
done

controller_sha="${GITHUB_SHA:-}"
controller_tag="${RELEASE_TAG:-}"
[[ "$controller_sha" =~ ^[0-9a-f]{40}$ ]] \
  && [ "$controller_sha" != 666c578f719d1e54fce95d6831a3af92ea80df93 ] \
  || fail "controller must use its distinct real dispatch commit"
[[ "$controller_tag" =~ ^v0\.2\.7-recover\.[1-9][0-9]*$ ]] \
  || fail "controller maintenance tag must be v0.2.7-recover.N with positive N"
[ "${GITHUB_REF:-}" = "refs/tags/$controller_tag" ] \
  || fail "controller dispatch ref must equal its maintenance tag"
[ "${EXPECTED_COMMIT_SHA:-}" = "$controller_sha" ] \
  && [ "${TRUSTED_RELEASE_REF:-}" = "$controller_sha" ] \
  && [ "${EXPECTED_TAG_COMMIT_SHA:-}" = "$controller_sha" ] \
  || fail "controller source/tag inputs must equal real GITHUB_SHA"
[[ "${EXPECTED_TAG_OBJECT_SHA:-}" =~ ^[0-9a-f]{40}$ ]] \
  || fail "controller tag object must be one full object ID"
[ "${GITHUB_ACTIONS:-}" = true ] \
  && [ "${GITHUB_SERVER_URL:-}" = https://github.com ] \
  && [ "${GITHUB_REPOSITORY:-}" = exochain/exochain ] \
  || fail "recovery is restricted to the fixed GitHub Actions repository"
[ "${DRY_RUN:-false}" = false ] || fail "recovery identity cannot use a dry-run signature bypass"

workspace="${GITHUB_WORKSPACE:-}"
scratch_parent="${RUNNER_TEMP:-}"
[[ "$workspace" = /* && "$scratch_parent" = /* ]] \
  && [ -d "$workspace" ] && [ ! -L "$workspace" ] \
  && [ -d "$scratch_parent" ] && [ ! -L "$scratch_parent" ] \
  || fail "workspace and RUNNER_TEMP must be absolute real directories"
workspace="$(cd "$workspace" && pwd -P)"
scratch_parent="$(cd "$scratch_parent" && pwd -P)"
case "$scratch_parent/" in "$workspace/"*) fail "helper capture must be outside the checkout" ;; esac

trusted_git() {
  /usr/bin/env -i PATH=/usr/bin:/bin GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0 \
    /usr/bin/git --no-replace-objects -c core.fsmonitor=false \
      -c core.untrackedCache=false -c core.ignoreStat=false -C "$workspace" "$@"
}

# Verify the dispatch object graph before trusting even the source guard blob.
trusted_git fsck --strict --no-reflogs --no-progress --no-dangling "$controller_sha" >/dev/null
[ "$(trusted_git rev-parse --verify 'HEAD^{commit}')" = "$controller_sha" ] \
  || fail "checkout HEAD differs from real controller dispatch"
capture="$(/usr/bin/mktemp -d "$scratch_parent/exochain-recovery-027.XXXXXX")"
/bin/chmod 700 "$capture"
for helper in verify_release_source.sh verify_release_tag.sh \
    verify_release_tag_signer.sh verify_release_recovery_027.py; do
  trusted_git show "$controller_sha:tools/$helper" > "$capture/$helper"
  /bin/chmod 400 "$capture/$helper"
done
trusted_git show "$controller_sha:governance/releases/v0.2.7/RECOVERY-MANIFEST.json" \
  > "$capture/RECOVERY-MANIFEST.json"
/bin/chmod 400 "$capture/RECOVERY-MANIFEST.json"
trusted_git show "$controller_sha:governance/releases/v0.2.7/PUBLICATION-IDENTITIES.json" \
  > "$capture/PUBLICATION-IDENTITIES.json"
/bin/chmod 400 "$capture/PUBLICATION-IDENTITIES.json"

[ -n "${RELEASE_PYTHON:-}" ] && [ -n "${RELEASE_TRUSTED_PYTHON_ROOT:-}" ] \
  && [ "${RELEASE_TRUSTED_PYTHON_VERSION:-}" = 3.13.7 ] \
  || fail "pinned Python 3.13.7 identity is required"
python_path="$(/usr/bin/realpath "$RELEASE_PYTHON")"
python_root="$(cd "$RELEASE_TRUSTED_PYTHON_ROOT" && pwd -P)"
case "$python_path" in "$python_root"/*) ;; *) fail "Python is outside the trusted tool-cache root" ;; esac
[ -f "$python_path" ] && [ -x "$python_path" ] && [ ! -L "$python_path" ] \
  || fail "Python must be one trusted executable regular file"
[ "$(/usr/bin/env -i "$python_path" -I -B -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')" = 3.13.7 ] \
  || fail "Python differs from the pinned runtime"

identity_env=(
  "PATH=/usr/bin:/bin" "GITHUB_WORKSPACE=$workspace" "RUNNER_TEMP=$scratch_parent"
  "GITHUB_SHA=$controller_sha" "GITHUB_REF=$GITHUB_REF"
  "EXPECTED_COMMIT_SHA=$controller_sha" "TRUSTED_RELEASE_REF=$controller_sha"
  "EXPECTED_TAG_OBJECT_SHA=$EXPECTED_TAG_OBJECT_SHA" "EXPECTED_TAG_COMMIT_SHA=$controller_sha"
  "DRY_RUN=false" "RELEASE_TAG=$controller_tag"
  "GITHUB_ACTIONS=true" "GITHUB_SERVER_URL=https://github.com" "GITHUB_REPOSITORY=exochain/exochain"
  "RELEASE_GITHUB_TOKEN=${RELEASE_GITHUB_TOKEN:-}"
  "GNUPGHOME=${GNUPGHOME:-}" "EXOCHAIN_RELEASE_SIGNING_FINGERPRINT=${EXOCHAIN_RELEASE_SIGNING_FINGERPRINT:-}"
  "RELEASE_SOURCE_CLEAN_MODE=all" "RELEASE_ALLOWED_UNTRACKED_PATHS="
)
/usr/bin/env -i "$python_path" -I -B "$capture/verify_release_recovery_027.py" \
  manifest --manifest "$capture/RECOVERY-MANIFEST.json" >/dev/null
/usr/bin/env -i "$python_path" -I -B "$capture/verify_release_recovery_027.py" \
  publication --manifest "$capture/RECOVERY-MANIFEST.json" \
  --identities "$capture/PUBLICATION-IDENTITIES.json" >/dev/null

# The pinned PyPI action uses a Docker-mounted workspace stage and generates a
# local Docker trampoline. Only this exact validated phase may exempt its exact
# data files; callers cannot supply paths or relax tracked/index validation.
case "${RELEASE_RECOVERY_PYTHON_PHASE:-}" in
  '') ;;
  staged|readback)
    trusted_git show "$controller_sha:tools/verify_release_recovery_python_stage.py" \
      > "$capture/verify_release_recovery_python_stage.py"
    /bin/chmod 400 "$capture/verify_release_recovery_python_stage.py"
    /usr/bin/env -i "$python_path" -I -B "$capture/verify_release_recovery_python_stage.py" \
      --manifest "$capture/RECOVERY-MANIFEST.json" --workspace "$workspace" \
      --state "$scratch_parent/exochain-recovery-python-state.json" \
      --phase "$RELEASE_RECOVERY_PYTHON_PHASE" --sha "$controller_sha" --ref "$GITHUB_REF" \
      > "$capture/python-workspace.json"
    allowed_paths="$(/usr/bin/env -i "$python_path" -I -B -c \
      'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["allowed_paths"]))' \
      "$capture/python-workspace.json")"
    identity_env+=("RELEASE_SOURCE_CLEAN_MODE=tracked" "RELEASE_ALLOWED_UNTRACKED_PATHS=$allowed_paths")
    ;;
  *) fail "unknown Python recovery workspace phase" ;;
esac
/usr/bin/env -i "${identity_env[@]}" /bin/bash --noprofile --norc -p "$capture/verify_release_source.sh" >&2

[ "$(trusted_git rev-parse --verify "refs/tags/$controller_tag")" = "$EXPECTED_TAG_OBJECT_SHA" ] \
  || fail "local controller maintenance tag object differs"
/usr/bin/env -i "${identity_env[@]}" /bin/bash --noprofile --norc -p "$capture/verify_release_tag_signer.sh" >&2
/usr/bin/env -i "${identity_env[@]}" /bin/bash --noprofile --norc -p "$capture/verify_release_tag.sh" >&2

# The signer guard does not bind a dispatch SHA. Only its RELEASE_TAG changes;
# GITHUB_SHA and all controller source/tag equality guards remain unchanged.
/usr/bin/env -i "${identity_env[@]}" RELEASE_TAG=v0.2.7 \
  /bin/bash --noprofile --norc -p "$capture/verify_release_tag_signer.sh" >&2
original_object="$(trusted_git rev-parse --verify refs/tags/v0.2.7)"
original_commit="$(trusted_git rev-parse --verify 'refs/tags/v0.2.7^{commit}')"
/usr/bin/env -i PATH=/usr/bin:/bin GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0 \
  GIT_CEILING_DIRECTORIES="$capture" \
  /usr/bin/git -C "$capture" ls-remote https://github.com/exochain/exochain.git \
    refs/tags/v0.2.7 'refs/tags/v0.2.7^{}' > "$capture/original-remote-refs.txt"
/bin/chmod 400 "$capture/original-remote-refs.txt"
/usr/bin/env -i "$python_path" -I -B "$capture/verify_release_recovery_027.py" \
  product-tag --manifest "$capture/RECOVERY-MANIFEST.json" \
  --local-tag-object "$original_object" --local-peeled-commit "$original_commit" \
  --remote-refs "$capture/original-remote-refs.txt" >/dev/null

/usr/bin/env -i "$python_path" -I -B -c '
import json,sys
sha,ref,capture=sys.argv[1:]
print(json.dumps({"controller_sha":sha,"controller_ref":ref,
    "product_commit":"666c578f719d1e54fce95d6831a3af92ea80df93",
    "product_tag_object":"be47589ec7dbefe821ada35ed0a89dedc9751953",
    "controller_signature_verified":True,"product_signature_verified":True,
    "captured_directory":capture,"helper":capture+"/verify_release_recovery_027.py",
    "manifest":capture+"/RECOVERY-MANIFEST.json"},sort_keys=True,separators=(",",":")))
' "$controller_sha" "$GITHUB_REF" "$capture"
