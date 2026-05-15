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

cd "$(dirname "$0")/.."

types="crates/exo-core/src/types.rs"
crypto="crates/exo-core/src/crypto.rs"

fail() {
  echo "Signature::Empty boundary docs test failed: $*" >&2
  exit 1
}

grep -q "Signature::Empty is an unsigned construction sentinel" "$types" || {
  fail "types.rs must define Signature::Empty as an unsigned construction sentinel"
}

grep -q "permitted only while building" "$types" || {
  fail "types.rs must document the acceptable pre-boundary use"
}

grep -q "not reached a trust" "$types" || {
  fail "types.rs must document the acceptable pre-boundary use"
}

grep -q "boundary. It must be rejected" "$types" || {
  fail "types.rs must document the acceptable pre-boundary use"
}

grep -q "must be rejected before persistence" "$types" || {
  fail "types.rs must document the security boundary"
}

grep -q "trust-record finalization" "$types" || {
  fail "types.rs must document the security boundary"
}

grep -q "Do not use is_empty() as proof that a non-empty signature is valid" "$types" || {
  fail "types.rs must warn against structural-only signature validation"
}

grep -q "Signature::Empty => return false" "$crypto" || {
  fail "crypto verification must explicitly reject Signature::Empty"
}

grep -q "signature_as_bytes_panics_for_empty_instead_of_returning_zero_sentinel" "$types" || {
  fail "types.rs tests must keep as_bytes from returning a zero sentinel for Signature::Empty"
}

echo "Signature::Empty boundary docs test passed"
