// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

const fs = require('fs');
const path = require('path');
const blake3 = require('blake3');

const DEFAULT_HASH_VECTOR = {
  name: 'BLAKE3 hash of canonical CBOR',
  input: {
    canonical_cbor_hex: 'a1616101',
  },
  expected: {
    blake3_hex: '74a1c68dabb660207c842b9b7dd0953a6a8e8158bb397c5bd4ea9fceda0c4c96',
  },
};

function isHashVector(vector) {
  return (
    vector &&
    vector.input &&
    typeof vector.input.canonical_cbor_hex === 'string' &&
    vector.expected &&
    typeof vector.expected.blake3_hex === 'string'
  );
}

function decodeHex(hex, filePath) {
  if (hex.length % 2 !== 0 || /[^0-9a-f]/i.test(hex)) {
    throw new Error(`${filePath}: canonical_cbor_hex must be even-length hex`);
  }
  return Buffer.from(hex, 'hex');
}

function verifyHashVector(vector, label) {
  if (!isHashVector(vector)) {
    return false;
  }

  const input = decodeHex(vector.input.canonical_cbor_hex, label);
  const actual = blake3.hash(input).toString('hex');
  const expected = vector.expected.blake3_hex.toLowerCase();

  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }

  console.log(`PASS ${path.basename(label)} ${actual}`);
  return true;
}

function readVectorFile(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function main() {
  const vectorsDir =
    process.env.EXOCHAIN_CROSS_IMPL_HASH_VECTORS || path.join(__dirname, 'vectors');

  let verified = 0;
  if (fs.existsSync(vectorsDir)) {
    const files = fs
      .readdirSync(vectorsDir)
      .filter((file) => file.endsWith('.json'))
      .sort()
      .map((file) => path.join(vectorsDir, file));

    for (const filePath of files) {
      if (verifyHashVector(readVectorFile(filePath), filePath)) {
        verified += 1;
      }
    }
  } else if (!process.env.EXOCHAIN_CROSS_IMPL_HASH_VECTORS) {
    if (verifyHashVector(DEFAULT_HASH_VECTOR, 'builtin:hash_blake3.json')) {
      verified += 1;
    }
  }

  if (verified === 0) {
    throw new Error(`no canonical hash vectors found in ${vectorsDir}`);
  }

  console.log(`Verified ${verified} canonical hash vector(s)`);
}

if (require.main === module) {
  main();
}
