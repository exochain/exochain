#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0
# Load this fixed dispatcher with git show from the genuine workflow SHA.
set -euo pipefail
fail() { printf 'release recovery runner failed: %s\n' "$1" >&2; exit 1; }
[ "$#" -eq 1 ] || fail 'exactly one fixed operation is required'
operation="$1"
case "$operation" in
  retained-acceptance|retained-github)
    [[ "${RELEASE_OPERATION:-}" = recover-0.2.7-retained || "${RELEASE_OPERATION:-}" = recover-0.2.7-retained-404 ]] \
      || fail 'operation and release mode differ'
    for credential in NODE_AUTH_TOKEN NPM_TOKEN CARGO_REGISTRY_TOKEN TWINE_PASSWORD PYPI_TOKEN PYPI_API_TOKEN \
        ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL; do
      [ -z "${!credential:-}" ] || fail 'retained acceptance forbids publication credentials and OIDC'
    done
    [[ "${RELEASE_WORKFLOW_DRY_RUN:-}" = true || "${RELEASE_WORKFLOW_DRY_RUN:-}" = false ]] \
      || fail 'explicit workflow dry-run boolean required'
    [ -z "${RELEASE_RECOVERY_PYTHON_PHASE:-}" ] || fail 'retained acceptance forbids stage exemptions'
    if [ "$operation" = retained-github ]; then
      [ "$RELEASE_WORKFLOW_DRY_RUN" = false ] && [ "${GITHUB_JOB:-}" = retained-github ] \
        || fail 'live current receipt handoff required'
      for output in ARTIFACT_ID ARTIFACT_DIGEST PRODUCER_JOB_ID RECEIPT_MEMBERS RECEIPT_CONTEXT; do
        name="RELEASE_RECEIPT_$output"
        [ -n "${!name:-}" ] || fail 'live current receipt handoff required'
      done
    fi
    ;;
  import|npm-wasm|npm-llm|npm-sdk|python-preflight|python-readback|github) ;;
  *) fail 'unknown fixed recovery operation' ;;
esac
if [[ "$operation" != retained-acceptance && "$operation" != retained-github ]]; then
  [ "${RELEASE_OPERATION:-recover-0.2.7}" = recover-0.2.7 ] \
    && [ -z "${RELEASE_WORKFLOW_DRY_RUN+x}" ] || fail 'operation and release mode differ'
fi
release_operation="${RELEASE_OPERATION:-recover-0.2.7}"
if /usr/bin/env | /usr/bin/grep -Eq '^BASH_FUNC_.*%%='; then
  fail 'inherited shell functions are forbidden'
fi
for required in GITHUB_SHA GITHUB_WORKSPACE GITHUB_REF GITHUB_REPOSITORY \
    GITHUB_SERVER_URL RUNNER_TEMP RELEASE_PYTHON RELEASE_TRUSTED_PYTHON_ROOT \
    EXPECTED_COMMIT_SHA TRUSTED_RELEASE_REF EXPECTED_TAG_OBJECT_SHA \
    EXPECTED_TAG_COMMIT_SHA RELEASE_TAG EXOCHAIN_RELEASE_SIGNING_FINGERPRINT \
    EXOCHAIN_RELEASE_SIGNING_PUBLIC_KEY_ASC; do
  [ -n "${!required:-}" ] || fail "$required is required"
done
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]] || fail 'invalid actual dispatch commit'
[[ "$RELEASE_TAG" =~ ^v0\.2\.7-recover\.[1-9][0-9]*$ ]] || fail 'invalid maintenance tag'
[ "$GITHUB_REF" = "refs/tags/$RELEASE_TAG" ] || fail 'maintenance ref differs'
[ "$EXPECTED_COMMIT_SHA" = "$GITHUB_SHA" ] && [ "$TRUSTED_RELEASE_REF" = "$GITHUB_SHA" ] \
  || fail 'controller identity differs from genuine dispatch'
[ "$GITHUB_REPOSITORY" = exochain/exochain ] && [ "$GITHUB_SERVER_URL" = https://github.com ] \
  || fail 'wrong repository or provider'
[ "${GITHUB_ACTIONS:-}" = true ] && [ "${GITHUB_EVENT_NAME:-}" = workflow_dispatch ] \
  && [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] \
  && [ "${GITHUB_WORKFLOW_REF:-}" = "exochain/exochain/.github/workflows/release.yml@$GITHUB_REF" ] \
  || fail 'recovery must run in its actual hosted workflow dispatch'
[[ "$RUNNER_TEMP" = /* ]] && [ -d "$RUNNER_TEMP" ] && [ ! -L "$RUNNER_TEMP" ] \
  || fail 'RUNNER_TEMP must be an absolute real directory'
case "$operation" in
  npm-llm|npm-sdk) [ -n "${NODE_AUTH_TOKEN:-}" ] || fail 'npm publication credential missing' ;;
  *) [ -z "${NODE_AUTH_TOKEN:-}" ] && [ -z "${NPM_TOKEN:-}" ] \
       || fail 'npm publishing credentials forbidden for this operation' ;;
esac
[ -z "${CARGO_REGISTRY_TOKEN:-}" ] && [ -z "${PYPI_TOKEN:-}" ] && [ -z "${PYPI_API_TOKEN:-}" ] && [ -z "${TWINE_PASSWORD:-}" ] \
  || fail 'unneeded publishing credentials are forbidden'

capture="$(/usr/bin/mktemp -d "$RUNNER_TEMP/exochain-recovery-runner.XXXXXX")"
/bin/chmod 700 "$capture"
capture_helper() {
  /usr/bin/env -i GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git --no-replace-objects -c core.fsmonitor=false -c core.untrackedCache=false \
      -C "$GITHUB_WORKSPACE" show "${GITHUB_SHA}:tools/$1" > "$capture/$1"
  /bin/chmod 400 "$capture/$1"
}
capture_helper verify_release_recovery_027.sh
if [ "$release_operation" = recover-0.2.7-retained-404 ]; then
  capture_helper verify_release_recovery_027.py
  /usr/bin/env -i GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git --no-replace-objects -c core.fsmonitor=false -c core.untrackedCache=false \
      -C "$GITHUB_WORKSPACE" show "$GITHUB_SHA:governance/releases/v0.2.7/RETAINED-METADATA-POLICY.json" \
      > "$capture/RETAINED-METADATA-POLICY.json"
  /bin/chmod 400 "$capture/RETAINED-METADATA-POLICY.json"
fi
key_home="$capture/signing-keys"
/bin/mkdir -m 700 "$key_home"
printf '%s\n' "$EXOCHAIN_RELEASE_SIGNING_PUBLIC_KEY_ASC" | \
  /usr/bin/env -i PATH=/usr/bin:/bin GNUPGHOME="$key_home" /usr/bin/gpg --batch --import

# No inherited loader, Git, npm, Python, OIDC or shell startup configuration
# crosses this boundary. Public helpers get only read-only GitHub authority.
common=(
  PATH=/usr/bin:/bin BASH_ENV=/dev/null ENV=/dev/null
  "GITHUB_SHA=$GITHUB_SHA" "GITHUB_REF=$GITHUB_REF" "GITHUB_WORKSPACE=$GITHUB_WORKSPACE"
  "GITHUB_REPOSITORY=$GITHUB_REPOSITORY" "GITHUB_SERVER_URL=$GITHUB_SERVER_URL"
  "GITHUB_ACTIONS=true" "GITHUB_EVENT_NAME=${GITHUB_EVENT_NAME:-}"
  "GITHUB_WORKFLOW_REF=${GITHUB_WORKFLOW_REF:-}" "GITHUB_RUN_ID=${GITHUB_RUN_ID:-}"
  "GITHUB_RUN_ATTEMPT=${GITHUB_RUN_ATTEMPT:-}" "GITHUB_OUTPUT=${GITHUB_OUTPUT:-}"
  "GITHUB_REPOSITORY_ID=${GITHUB_REPOSITORY_ID:-}"
  "GITHUB_REPOSITORY_OWNER_ID=${GITHUB_REPOSITORY_OWNER_ID:-}"
  "RUNNER_ENVIRONMENT=${RUNNER_ENVIRONMENT:-}" "RUNNER_TEMP=$RUNNER_TEMP"
  "EXPECTED_COMMIT_SHA=$EXPECTED_COMMIT_SHA" "TRUSTED_RELEASE_REF=$TRUSTED_RELEASE_REF"
  "EXPECTED_TAG_OBJECT_SHA=$EXPECTED_TAG_OBJECT_SHA" "EXPECTED_TAG_COMMIT_SHA=$EXPECTED_TAG_COMMIT_SHA"
  "RELEASE_TAG=$RELEASE_TAG" "RELEASE_VERSION=0.2.7" "RELEASE_OPERATION=$release_operation"
  "RELEASE_GITHUB_TOKEN=${RELEASE_GITHUB_TOKEN:-}" "GNUPGHOME=$key_home"
  "EXOCHAIN_RELEASE_SIGNING_FINGERPRINT=$EXOCHAIN_RELEASE_SIGNING_FINGERPRINT"
  "RELEASE_PYTHON=$RELEASE_PYTHON" "RELEASE_TRUSTED_PYTHON_ROOT=$RELEASE_TRUSTED_PYTHON_ROOT"
  "RELEASE_TRUSTED_PYTHON_VERSION=3.13.7" "RELEASE_TEMP_ROOT=$RUNNER_TEMP"
  "RELEASE_RECOVERY_DIRECTORY=$RUNNER_TEMP/exochain-recovery-artifacts" "DRY_RUN=false"
)
if [[ "$operation" = retained-acceptance || "$operation" = retained-github ]]; then
  common+=("RELEASE_WORKFLOW_DRY_RUN=$RELEASE_WORKFLOW_DRY_RUN" "GITHUB_JOB=${GITHUB_JOB:-}")
fi
if [ "$operation" = retained-github ]; then
  for output in ARTIFACT_ID ARTIFACT_DIGEST PRODUCER_JOB_ID RECEIPT_MEMBERS RECEIPT_CONTEXT; do
    name="RELEASE_RECEIPT_$output"
    common+=("$name=${!name}")
  done
fi
if [ "$operation" = python-readback ]; then
  common+=("RELEASE_RECOVERY_PYTHON_PHASE=readback")
fi
/usr/bin/env -i "${common[@]}" /bin/bash --noprofile --norc -p \
  "$capture/verify_release_recovery_027.sh" > "$capture/identity.json"
if [ "$release_operation" = recover-0.2.7-retained-404 ]; then
  /usr/bin/env -i GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git --no-replace-objects -c core.fsmonitor=false -c core.untrackedCache=false \
      -C "$GITHUB_WORKSPACE" show "$GITHUB_SHA:governance/releases/v0.2.7/RETAINED-METADATA-POLICY.json" \
      | /usr/bin/cmp - "$capture/RETAINED-METADATA-POLICY.json" \
      || fail 'captured retained metadata policy changed'
fi

case "$operation" in
  import|retained-acceptance|retained-github|npm-*)
    capture_helper resolve_release_tool_path.sh
    [ -n "${RELEASE_TRUSTED_NODE_ROOT:-}" ] || fail 'trusted Node root missing'
    node_env=("RUNNER_TEMP=$RUNNER_TEMP" "RELEASE_TRUSTED_NODE_ROOT=$RELEASE_TRUSTED_NODE_ROOT" "RELEASE_TRUSTED_NODE_VERSION=24.15.0")
    identity="$(/usr/bin/env -i "${node_env[@]}" /bin/bash --noprofile --norc -p \
      "$capture/resolve_release_tool_path.sh" --identity node npm bash tar git curl)"
    tool_path="$(/usr/bin/env -i "${node_env[@]}" /bin/bash --noprofile --norc -p \
      "$capture/resolve_release_tool_path.sh" node npm bash tar git curl)"
    [ "$(/bin/cat "${tool_path%%:*}/.release-tool-identity")" = "$identity" ] || fail 'tool closure changed'
    common+=("RELEASE_NODE=${tool_path%%:*}/node" "TRUSTED_RELEASE_PATH=$tool_path"
      "TRUSTED_RELEASE_TOOL_IDENTITY=$identity" "RELEASE_TRUSTED_NPM_VERSION=11.12.1")
    ;;
esac
case "$operation" in
  import|retained-acceptance)
    capture_helper import_release_recovery_027.sh
    if [ "$operation" = retained-acceptance ]; then
      /usr/bin/env -i "${common[@]}" /bin/bash --noprofile --norc -p "$capture/import_release_recovery_027.sh" retained-acceptance
    else
      /usr/bin/env -i "${common[@]}" /bin/bash --noprofile --norc -p "$capture/import_release_recovery_027.sh"
    fi
    ;;
  npm-*)
    profile="${operation#npm-}"
    case "$profile" in
      wasm) filename=exochain-exochain-wasm-0.2.7.tgz; digest=a9660cbf0241e8adde6be92cd7a13beea00c0fe258ea6c79ea527750f182d023 ;;
      llm) filename=exochain-llm-proxy-0.2.7.tgz; digest=22d60086f12aca9a46bab6cf70325e4f38ed73dd046f5438b8d9b984fd54f2e4 ;;
      sdk) filename=exochain-sdk-0.2.7.tgz; digest=a0b616e5af6a61dc96c12c2166b20e05f71a61f03b257b370aacc02ceebaa003 ;;
    esac
    capture_helper publish_release_npm_package.sh
    common+=("RELEASE_NPM_TARBALL=$RUNNER_TEMP/exochain-recovery-artifacts/npm-$profile/$filename" "RELEASE_EXPECTED_TARBALL_SHA256=$digest")
    if [ "$profile" != wasm ]; then
      common+=("NODE_AUTH_TOKEN=$NODE_AUTH_TOKEN"
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN=${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}"
        "ACTIONS_ID_TOKEN_REQUEST_URL=${ACTIONS_ID_TOKEN_REQUEST_URL:-}")
    fi
    /usr/bin/env -i "${common[@]}" /bin/bash --noprofile --norc -p "$capture/publish_release_npm_package.sh" "$profile"
    ;;
  python-*)
    capture_helper recover_release_python_027.sh
    /usr/bin/env -i "${common[@]}" /bin/bash --noprofile --norc -p "$capture/recover_release_python_027.sh" "${operation#python-}"
    ;;
  github)
    capture_helper recover_github_release_027.py
    /usr/bin/env -i "${common[@]}" "$RELEASE_PYTHON" -I -B "$capture/recover_github_release_027.py"
    ;;
  retained-github)
    capture_helper recover_github_release_027.py
    /usr/bin/env -i "${common[@]}" "$RELEASE_PYTHON" -I -B "$capture/recover_github_release_027.py" retained-github
    ;;
esac
