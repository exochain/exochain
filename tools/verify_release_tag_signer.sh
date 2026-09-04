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

if /usr/bin/env | /usr/bin/grep -Eq '^BASH_FUNC_.*%%='; then
  /bin/echo "release tag signer verification failed: inherited shell functions are forbidden" >&2
  exit 1
fi
set -euo pipefail

fail() {
  printf 'release tag signer verification failed: %s\n' "$1" >&2
  exit 1
}

release_workspace="${GITHUB_WORKSPACE:-}"
if [[ "$release_workspace" != /* ]] || [ ! -d "$release_workspace" ]; then
  fail "GITHUB_WORKSPACE must name the absolute release checkout directory"
fi
release_workspace="$(cd "$release_workspace" && pwd -P)"

scrub_git_environment() {
  unset \
    GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR \
    GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES \
    GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM \
    GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS \
    GIT_CEILING_DIRECTORIES GIT_DISCOVERY_ACROSS_FILESYSTEM \
    GIT_IMPLICIT_WORK_TREE GIT_PREFIX GIT_INTERNAL_SUPER_PREFIX \
    GIT_NAMESPACE GIT_REPLACE_REF_BASE GIT_NO_REPLACE_OBJECTS \
    GIT_SHALLOW_FILE GIT_GRAFT_FILE GIT_QUARANTINE_PATH GIT_EXEC_PATH \
    GIT_EXTERNAL_DIFF GIT_DIFF_OPTS GIT_ATTR_SOURCE
}

scrub_git_environment
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1

trusted_git() (
  scrub_git_environment
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1
  /usr/bin/git --no-replace-objects \
    -c core.fsmonitor=false \
    -c core.untrackedCache=false \
    -c core.ignoreStat=false \
    -C "$release_workspace" \
    "$@"
)

git_toplevel="$(trusted_git rev-parse --show-toplevel)"
git_toplevel="$(cd "$git_toplevel" && pwd -P)"
if [ "$git_toplevel" != "$release_workspace" ]; then
  fail "GITHUB_WORKSPACE must be the root of the inspected Git checkout"
fi

release_tag="${RELEASE_TAG:-}"
configured_primary="$(printf '%s' "${EXOCHAIN_RELEASE_SIGNING_FINGERPRINT:-}" | /usr/bin/tr -d '[:space:]' | /usr/bin/tr '[:lower:]' '[:upper:]')"

if ! [[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z-]*(\.[0-9A-Za-z][0-9A-Za-z-]*)*)?$ ]]; then
  echo "RELEASE_TAG must be a validated v-prefixed semantic version." >&2
  exit 1
fi
if ! [[ "$configured_primary" =~ ^[0-9A-F]{40}$ ]]; then
  echo "EXOCHAIN_RELEASE_SIGNING_FINGERPRINT must be a 40-character OpenPGP fingerprint." >&2
  exit 1
fi
if [ -z "${GNUPGHOME:-}" ] || [ ! -d "$GNUPGHOME" ]; then
  echo "GNUPGHOME must name the isolated release-verification keyring." >&2
  exit 1
fi
if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
  gpg_path="/usr/bin/gpg"
elif [ -x /opt/homebrew/bin/gpg ]; then
  gpg_path="/opt/homebrew/bin/gpg"
elif [ -x /usr/local/bin/gpg ]; then
  gpg_path="/usr/local/bin/gpg"
elif [ -x /usr/bin/gpg ]; then
  gpg_path="/usr/bin/gpg"
else
  gpg_path=""
fi
if [[ "$gpg_path" != /* ]] || [ ! -x "$gpg_path" ]; then
  fail "a trusted absolute GPG executable is required"
fi

primary_fingerprints="$(
  "$gpg_path" --batch --with-colons --fingerprint --list-keys | /usr/bin/awk -F: '
    /^pub:/ { want_primary_fingerprint = 1; next }
    /^fpr:/ && want_primary_fingerprint {
      print toupper($10)
      want_primary_fingerprint = 0
    }
  '
)"
primary_count="$(printf '%s\n' "$primary_fingerprints" | /usr/bin/awk 'NF { count += 1 } END { print count + 0 }')"
if [ "$primary_count" -ne 1 ]; then
  echo "Release verification keyring must contain exactly one primary key; found ${primary_count}." >&2
  exit 1
fi
if [ "$primary_fingerprints" != "$configured_primary" ]; then
  echo "Imported release signing primary key does not match EXOCHAIN_RELEASE_SIGNING_FINGERPRINT." >&2
  exit 1
fi

verification_output=""
if ! verification_output="$(trusted_git -c "gpg.program=${gpg_path}" verify-tag --raw "$release_tag" 2>&1)"; then
  printf '%s\n' "$verification_output" >&2
  echo "Release tag ${release_tag} does not have a valid OpenPGP signature." >&2
  exit 1
fi
printf '%s\n' "$verification_output"

validsig_count="$(/usr/bin/grep -c '^\[GNUPG:\] VALIDSIG ' <<<"$verification_output" || true)"
if [ "$validsig_count" -ne 1 ]; then
  echo "Release tag verification must produce exactly one VALIDSIG status; found ${validsig_count}." >&2
  exit 1
fi

read -r signing_fingerprint signer_primary_fingerprint < <(
  /usr/bin/awk '
    /^\[GNUPG:\] VALIDSIG / {
      signing = toupper($3)
      candidate = toupper($NF)
      if (candidate ~ /^[0-9A-F]{40}$/) {
        primary = candidate
      } else {
        primary = signing
      }
      print signing, primary
    }
  ' <<<"$verification_output"
)
if ! [[ "$signing_fingerprint" =~ ^[0-9A-F]{40}$ ]]; then
  echo "Release tag VALIDSIG did not identify a full signing-key fingerprint." >&2
  exit 1
fi
if [ "$signer_primary_fingerprint" != "$configured_primary" ]; then
  echo "Release tag signer primary ${signer_primary_fingerprint} does not match configured primary ${configured_primary}." >&2
  exit 1
fi

echo "Release tag ${release_tag} signature chains to configured primary ${configured_primary}."
