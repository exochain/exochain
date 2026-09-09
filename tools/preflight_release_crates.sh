#!/usr/bin/env bash
# Copyright 2026 Exochain Foundation
# SPDX-License-Identifier: Apache-2.0

if /usr/bin/env | /usr/bin/grep -Eq '^BASH_FUNC_.*%%='; then
  /bin/echo "crate preflight failed: inherited shell functions are forbidden" >&2
  exit 1
fi
set -euo pipefail

fail() {
  printf 'crate preflight failed: %s\n' "$1" >&2
  exit 1
}

for cargo_token_name in CARGO_REGISTRY_TOKEN CARGO_REGISTRIES_CRATES_IO_TOKEN; do
  if [ "${!cargo_token_name+x}" = x ]; then
    fail "$cargo_token_name must be absent from the token-free crate preflight"
  fi
done

for required_name in \
  GITHUB_WORKSPACE GITHUB_SHA RUNNER_TEMP TRUSTED_RELEASE_PATH \
  RELEASE_TRUSTED_CARGO_HOME RELEASE_TRUSTED_RUSTUP_HOME \
  RELEASE_TRUSTED_RUST_TOOLCHAIN \
  RELEASE_CARGO_HOME RELEASE_TOOL_HOME RELEASE_TARGET_DIR \
  RELEASE_CRATE_MANIFEST RELEASE_VERSION EXPECTED_COMMIT_SHA \
  TRUSTED_RELEASE_REF RELEASE_PYTHON RELEASE_TRUSTED_PYTHON_ROOT \
  RELEASE_TRUSTED_PYTHON_VERSION; do
  [ -n "${!required_name:-}" ] || fail "$required_name is required"
done
for required_directory in \
  "$GITHUB_WORKSPACE" "$RUNNER_TEMP" "$RELEASE_TRUSTED_CARGO_HOME" \
  "$RELEASE_TRUSTED_RUSTUP_HOME"; do
  [[ "$required_directory" == /* ]] && [ -d "$required_directory" ] \
    || fail "release directories must exist and be absolute"
done
for generated_path in \
  "$RELEASE_CARGO_HOME" "$RELEASE_TOOL_HOME" "$RELEASE_TARGET_DIR" \
  "$RELEASE_CRATE_MANIFEST"; do
  case "$generated_path" in
    "$RUNNER_TEMP"/*) ;;
    *) fail "generated release paths must be beneath RUNNER_TEMP" ;;
  esac
done
[[ "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "RELEASE_VERSION must be numeric semantic version text"

unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG GIT_CONFIG_GLOBAL \
  GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM GIT_CONFIG_COUNT \
  GIT_CONFIG_PARAMETERS GIT_CEILING_DIRECTORIES \
  GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_NAMESPACE GIT_REPLACE_REF_BASE \
  GIT_NO_REPLACE_OBJECTS GIT_SHALLOW_FILE GIT_GRAFT_FILE GIT_EXEC_PATH \
  GIT_EXTERNAL_DIFF GIT_DIFF_OPTS GIT_ATTR_SOURCE
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1

trusted_git() {
  /usr/bin/git --no-replace-objects -c core.fsmonitor=false -c core.untrackedCache=false \
    -c core.ignoreStat=false -C "$GITHUB_WORKSPACE" "$@"
}

run_exact_guard() {
  trusted_git show "${GITHUB_SHA}:tools/verify_release_side_effect.sh" \
    | /usr/bin/env -i \
        BASH_ENV=/dev/null \
        RELEASE_SOURCE_CLEAN_MODE=all \
        RELEASE_ALLOWED_UNTRACKED_PATHS= \
        DRY_RUN="${DRY_RUN:-false}" \
        RELEASE_TAG="${RELEASE_TAG:-}" \
        EXPECTED_TAG_OBJECT_SHA="${EXPECTED_TAG_OBJECT_SHA:-}" \
        EXPECTED_TAG_COMMIT_SHA="${EXPECTED_TAG_COMMIT_SHA:-}" \
        EXPECTED_COMMIT_SHA="$EXPECTED_COMMIT_SHA" \
        GITHUB_SHA="$GITHUB_SHA" \
        GITHUB_WORKSPACE="$GITHUB_WORKSPACE" \
        RUNNER_TEMP="$RUNNER_TEMP" \
        TRUSTED_RELEASE_REF="$TRUSTED_RELEASE_REF" \
        RELEASE_GITHUB_TOKEN="${RELEASE_GITHUB_TOKEN:-}" \
        GITHUB_SERVER_URL="${GITHUB_SERVER_URL:-https://github.com}" \
        GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-exochain/exochain}" \
        /bin/bash --noprofile --norc -p
}

verify_cargo_config() {
  trusted_git show "${GITHUB_SHA}:tools/verify_release_cargo_config.sh" \
    | /usr/bin/env -i \
        GITHUB_WORKSPACE="$GITHUB_WORKSPACE" \
        /bin/bash --noprofile --norc -p
}

for clean_directory in "$RELEASE_CARGO_HOME" "$RELEASE_TOOL_HOME" "$RELEASE_TARGET_DIR"; do
  /bin/rm -rf -- "$clean_directory"
  /bin/mkdir -m 700 -p -- "$clean_directory"
done
[ ! -e "$RELEASE_CRATE_MANIFEST" ] && [ ! -L "$RELEASE_CRATE_MANIFEST" ] \
  || fail "crate manifest output must start absent"

trusted_tool_view="${TRUSTED_RELEASE_PATH%%:*}"
trusted_cargo="$(/usr/bin/realpath "$trusted_tool_view/cargo")"
trusted_rustc="$(/usr/bin/realpath "$trusted_tool_view/rustc")"
trusted_rustdoc="$(/usr/bin/realpath "$trusted_tool_view/rustdoc")"
[ -x "$trusted_cargo" ] && [ -x "$trusted_rustc" ] && [ -x "$trusted_rustdoc" ] \
  || fail "trusted release tool view lacks Cargo, rustc, or rustdoc"
trusted_python="$(/usr/bin/realpath "$RELEASE_PYTHON")"
trusted_python_root="$(cd "$RELEASE_TRUSTED_PYTHON_ROOT" && pwd -P)"
case "$trusted_python" in
  "$trusted_python_root"/*) ;;
  *) fail "release Python is outside the trusted tool-cache root" ;;
esac
[ -f "$trusted_python" ] && [ -x "$trusted_python" ] && [ ! -L "$trusted_python" ] \
  || fail "release Python must be one executable regular file"
[ "$(/usr/bin/env -i "$trusted_python" -I -B -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')" = "$RELEASE_TRUSTED_PYTHON_VERSION" ] \
  || fail "release Python version differs from the pinned runtime"

release_cargo() (
  # Cargo discovers .cargo/config from the invocation directory, not the
  # absolute manifest path. A config-free cwd prevents committed or generated
  # workspace wrappers and credential providers from influencing packaging.
  cd /
  /usr/bin/env -i \
    PATH="$TRUSTED_RELEASE_PATH" \
    HOME="$RELEASE_TOOL_HOME" \
    CARGO_HOME="$RELEASE_CARGO_HOME" \
    RUSTUP_HOME="$RELEASE_TRUSTED_RUSTUP_HOME" \
    RUSTUP_TOOLCHAIN="$RELEASE_TRUSTED_RUST_TOOLCHAIN" \
    RUSTC="$trusted_rustc" \
    RUSTDOC="$trusted_rustdoc" \
    RUSTC_WRAPPER= \
    RUSTC_WORKSPACE_WRAPPER= \
    CARGO_TARGET_DIR="$RELEASE_TARGET_DIR" \
    CARGO_TERM_COLOR=always \
    CARGO_NET_RETRY=10 \
    CARGO_HTTP_TIMEOUT=120 \
    CARGO_HTTP_MULTIPLEXING=false \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_REGISTRY_DEFAULT=crates-io \
    RUSTFLAGS='-D warnings' \
    TZ=UTC LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    "$trusted_cargo" "$@"
)

CRATES=(
  exochain-core
  exochain-dag-db-api
  exochain-identity
  exochain-api
  exochain-authority
  exochain-pdp
  exochain-avc
  exochain-consent
  exochain-dag-db-core
  exochain-dag-db-graph
  exochain-dag-db-domain
  exochain-dag-db-retrieval
  exochain-dag-db-exchange
  exochain-dag
  exochain-dag-db-postgres
  exochain-gatekeeper
  exochain-proofs
  exochain-governance
  exochain-escalation
  exochain-tenant
  exochain-catapult
  exochain-legal
  exochain-decision-forum
  exochain-consensus
  exochain-dag-db-lab
  exochain-economy
  exochain-gateway
  exochain-messaging
  exochain-root
  exochain-sdk
  exochain-node
  exochain-wasm
)

expected_inventory="$RUNNER_TEMP/exochain-expected-crate-inventory"
actual_inventory="$RUNNER_TEMP/exochain-actual-crate-inventory"
printf '%s\n' "${CRATES[@]}" | /usr/bin/sort > "$expected_inventory"
release_cargo metadata --manifest-path "$GITHUB_WORKSPACE/Cargo.toml" \
  --no-deps --format-version 1 --locked \
  | /usr/bin/env -i "$trusted_python" -I -B -c '
import json
import sys
metadata = json.load(sys.stdin)
names = sorted(
    package["name"]
    for package in metadata["packages"]
    if package.get("publish") != []
)
sys.stdout.write("".join(f"{name}\n" for name in names))
' > "$actual_inventory"
/usr/bin/cmp -s "$expected_inventory" "$actual_inventory" \
  || fail "hard-coded release crates differ from publishable Cargo metadata"

run_exact_guard
verify_cargo_config
archive_guard_program="$(
  trusted_git show "${GITHUB_SHA}:tools/verify_crate_release_archive.py"
  printf '\036'
)"
[[ "$archive_guard_program" == *$'\036' ]] \
  || fail "could not preserve complete crate archive guard bytes"
archive_guard_program="${archive_guard_program%$'\036'}"
unset RELEASE_GITHUB_TOKEN
release_cargo package \
  --manifest-path "$GITHUB_WORKSPACE/Cargo.toml" \
  --workspace \
  --no-verify \
  --locked \
  --registry crates-io

for crate in "${CRATES[@]}"; do
  archive="$RELEASE_TARGET_DIR/package/${crate}-${RELEASE_VERSION}.crate"
  printf '%s' "$archive_guard_program" | /usr/bin/env -i "$trusted_python" -I -B - \
    "$archive" "$crate" "$RELEASE_VERSION" "$GITHUB_SHA" >> "$RELEASE_CRATE_MANIFEST"
done

actual_archive_inventory="$RUNNER_TEMP/exochain-actual-crate-archives"
/usr/bin/find "$RELEASE_TARGET_DIR/package" -maxdepth 1 -type f -name '*.crate' -print \
  | /usr/bin/sed 's!.*/!!' | /usr/bin/sort > "$actual_archive_inventory"
expected_archive_inventory="$RUNNER_TEMP/exochain-expected-crate-archives"
for crate in "${CRATES[@]}"; do
  printf '%s-%s.crate\n' "$crate" "$RELEASE_VERSION"
done | /usr/bin/sort > "$expected_archive_inventory"
/usr/bin/cmp -s "$expected_archive_inventory" "$actual_archive_inventory" \
  || fail "Cargo produced a missing or unexpected release archive"

[ "$(/usr/bin/wc -l < "$RELEASE_CRATE_MANIFEST" | /usr/bin/tr -d ' ')" -eq "${#CRATES[@]}" ] \
  || fail "crate package manifest has the wrong number of entries"
printf 'Preflighted %s exact crate archives without registry credentials\n' "${#CRATES[@]}"
