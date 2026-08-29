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

release_tag="${RELEASE_TAG:-}"
configured_primary="$(printf '%s' "${EXOCHAIN_RELEASE_SIGNING_FINGERPRINT:-}" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"

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

primary_fingerprints="$(
  gpg --batch --with-colons --fingerprint --list-keys | awk -F: '
    /^pub:/ { want_primary_fingerprint = 1; next }
    /^fpr:/ && want_primary_fingerprint {
      print toupper($10)
      want_primary_fingerprint = 0
    }
  '
)"
primary_count="$(printf '%s\n' "$primary_fingerprints" | awk 'NF { count += 1 } END { print count + 0 }')"
if [ "$primary_count" -ne 1 ]; then
  echo "Release verification keyring must contain exactly one primary key; found ${primary_count}." >&2
  exit 1
fi
if [ "$primary_fingerprints" != "$configured_primary" ]; then
  echo "Imported release signing primary key does not match EXOCHAIN_RELEASE_SIGNING_FINGERPRINT." >&2
  exit 1
fi

verification_output=""
if ! verification_output="$(git verify-tag --raw "$release_tag" 2>&1)"; then
  printf '%s\n' "$verification_output" >&2
  echo "Release tag ${release_tag} does not have a valid OpenPGP signature." >&2
  exit 1
fi
printf '%s\n' "$verification_output"

validsig_count="$(grep -c '^\[GNUPG:\] VALIDSIG ' <<<"$verification_output" || true)"
if [ "$validsig_count" -ne 1 ]; then
  echo "Release tag verification must produce exactly one VALIDSIG status; found ${validsig_count}." >&2
  exit 1
fi

read -r signing_fingerprint signer_primary_fingerprint < <(
  awk '
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
