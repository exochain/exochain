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
const crypto = require('crypto');
const blake3 = require('blake3');
const cbor = require('cbor');

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

function verifyAuthorityGovernanceFixture() {
  const fixturePath = path.join(
    __dirname,
    'fixtures',
    'crosschecked_anchor_authority_governance_v1.json',
  );
  const fixture = readVectorFile(fixturePath);
  const packageBytes = decodeHex(fixture.provisioning_package_cbor_hex, fixturePath);
  const policyPreimage = decodeHex(fixture.node_policy_preimage_cbor_hex, fixturePath);
  const authorizationPreimage = decodeHex(
    fixture.authorization_signing_preimage_cbor_hex,
    fixturePath,
  );
  const signature = decodeHex(fixture.authorization_signature_hex, fixturePath);
  const artifact = decodeHex(fixture.authorization_artifact_cbor_hex, fixturePath);
  const groupPublicKey = decodeHex(fixture.governance_group_public_key_hex, fixturePath);

  const exactKeys = [
    'authorization_artifact_blake3_hex',
    'authorization_artifact_cbor_hex',
    'authorization_artifact_sha256_hex',
    'authorization_signature_hex',
    'authorization_signing_preimage_cbor_hex',
    'fixture_version',
    'governance_group_public_key_hex',
    'governance_key_epoch',
    'node_policy_blake3_hex',
    'node_policy_preimage_cbor_hex',
    'participant_count',
    'protocol_version',
    'provisioning_package_blake3_hex',
    'provisioning_package_cbor_hex',
    'signature_algorithm',
    'signer_ids',
    'threshold',
  ];
  if (JSON.stringify(Object.keys(fixture).sort()) !== JSON.stringify(exactKeys.sort())) {
    throw new Error(`${fixturePath}: unknown or missing governance fixture fields`);
  }
  if (
    fixture.fixture_version !== 'crosschecked_anchor_authority_governance_v1' ||
    fixture.protocol_version !== 1 ||
    fixture.signature_algorithm !== 'frost-ed25519-sha512-rfc9591' ||
    fixture.governance_key_epoch !== 7 ||
    fixture.threshold !== 7 ||
    fixture.participant_count !== 13 ||
    JSON.stringify(fixture.signer_ids) !== JSON.stringify([1, 2, 3, 4, 5, 6, 7])
  ) {
    throw new Error(`${fixturePath}: governance profile mismatch`);
  }
  const checks = [
    [blake3.hash(packageBytes).toString('hex'), fixture.provisioning_package_blake3_hex],
    [blake3.hash(policyPreimage).toString('hex'), fixture.node_policy_blake3_hex],
    [blake3.hash(artifact).toString('hex'), fixture.authorization_artifact_blake3_hex],
    [crypto.createHash('sha256').update(artifact).digest('hex'), fixture.authorization_artifact_sha256_hex],
  ];
  for (const [actual, expected] of checks) {
    if (actual !== expected) {
      throw new Error(`${fixturePath}: governance digest mismatch`);
    }
  }
  const artifactValues = cbor.decodeAllSync(artifact);
  if (
    artifactValues.length !== 1 ||
    !Array.isArray(artifactValues[0]) ||
    artifactValues[0].length !== 2 ||
    !artifactValues[0][0].equals(authorizationPreimage) ||
    !artifactValues[0][1].equals(signature)
  ) {
    throw new Error(`${fixturePath}: authorization artifact encoding mismatch`);
  }
  const preimageValues = cbor.decodeAllSync(authorizationPreimage);
  if (
    preimageValues.length !== 1 ||
    !Array.isArray(preimageValues[0]) ||
    preimageValues[0].length !== 20 ||
    !preimageValues[0][13].equals(Buffer.from(fixture.provisioning_package_blake3_hex, 'hex')) ||
    !preimageValues[0][14].equals(Buffer.from(fixture.node_policy_blake3_hex, 'hex'))
  ) {
    throw new Error(`${fixturePath}: authorization target binding mismatch`);
  }
  const spki = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    groupPublicKey,
  ]);
  const publicKey = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  if (!crypto.verify(null, authorizationPreimage, publicKey, signature)) {
    throw new Error(`${fixturePath}: RFC 9591 FROST signature rejected`);
  }
  console.log(`PASS ${path.basename(fixturePath)} ${fixture.authorization_artifact_blake3_hex}`);
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

  verifyAuthorityGovernanceFixture();

  console.log(`Verified ${verified} canonical hash vector(s)`);
}

if (require.main === module) {
  main();
}
