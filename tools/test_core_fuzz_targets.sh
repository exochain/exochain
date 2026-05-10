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

# Regression guard for F-145: core parser fuzz targets must exist and compile.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail() {
  echo "core fuzz target test failed: $*" >&2
  exit 1
}

[ -f fuzz/Cargo.toml ] || fail "fuzz/Cargo.toml is missing"
[ -f fuzz/Cargo.lock ] || fail "fuzz/Cargo.lock is missing"

for target in did_parse signature_cbor clearance_policy_json; do
  [ -f "fuzz/fuzz_targets/${target}.rs" ] || fail "missing fuzz target: ${target}"
  grep -F 'fuzz_target!' "fuzz/fuzz_targets/${target}.rs" >/dev/null \
    || fail "${target} does not define a cargo-fuzz fuzz_target"
done

cargo check --manifest-path fuzz/Cargo.toml --bins --locked

echo "core fuzz target test passed"
