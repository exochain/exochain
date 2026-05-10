#!/bin/bash
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

# Build ExoChain Rust crates → WASM → Node.js
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${REPO_ROOT}/demo/packages/exochain-wasm/wasm"

echo "Building ExoChain WASM from ${REPO_ROOT}/crates/exochain-wasm..."
echo "Output: ${OUT_DIR}"

cd "${REPO_ROOT}"
wasm-pack build crates/exochain-wasm --target nodejs --release --out-dir "${OUT_DIR}"

echo ""
echo "WASM binary size: $(wc -c < "${OUT_DIR}/exochain_wasm_bg.wasm") bytes"
echo "Running tests..."
cd "${REPO_ROOT}/demo"
node packages/exochain-wasm/test.mjs
