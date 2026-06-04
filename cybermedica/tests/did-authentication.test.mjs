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

import assert from 'node:assert/strict';
import { test } from 'node:test';

async function loadDidAuthentication() {
  try {
    return await import('../src/did-authentication.mjs');
  } catch (error) {
    assert.fail(`CyberMedica DID authentication module must exist and load: ${error.message}`);
  }
}

const digestA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const digestB = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const digestC = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const digestD = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const publicKeyPem = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAiOJ3h9qEWcd58P7tc7XSnAcjNkOH/7J0rOKLrBRdwDo=\n-----END PUBLIC KEY-----\n';
const wrongPublicKeyPem = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAKej2mqY+k93TjIkMaCZ5cD33ol8mITbVNkMSqQZNka0=\n-----END PUBLIC KEY-----\n';
const validSignature = 'UsCDSGXit1ENDZAzd2JuvPc3dci7q7FsX6tbQBaQ3XXWA2YqshcXhFSt361HI09k9NrswRUaGNHrVOPi0kDoAQ==';
const staleSignature = 'eL5NzDUVABDV6kegdqdBWHW5TQ5APl8maycE6yQcN8JRg+bebZiTRlfEU2JgJkoeoPMCC5E97+WJd+Nlb/7RBg==';

function didAuthInput(overrides = {}) {
  return {
    tenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:principal-investigator-alpha', kind: 'human' },
    registryRecord: {
      did: 'did:exo:principal-investigator-alpha',
      source: 'exochain_did_registry',
      status: 'verified',
      keyRef: 'did:exo:principal-investigator-alpha#key-1',
      algorithm: 'Ed25519',
      publicKeyPem,
      registryEvidenceHash: digestA,
      custodyDigest: digestB,
      allowedTenantIds: ['tenant-network-beta', 'tenant-site-alpha'],
    },
    challenge: {
      purpose: 'qms_request_authentication',
      requestHash: digestD,
      nonceHash: digestC,
      issuedAtHlc: { physicalMs: 1790003000000, logical: 1 },
      expiresAtHlc: { physicalMs: 1790003300000, logical: 0 },
    },
    verification: {
      checkedAtHlc: { physicalMs: 1790003060000, logical: 0 },
      maxChallengeAgeMs: 300000,
      gatewayAuthRequired: true,
    },
    signature: validSignature,
    ...overrides,
  };
}

test('DID authentication verifies an Ed25519 challenge and creates deterministic inactive metadata evidence', async () => {
  const { buildDidAuthenticationChallenge, evaluateDidAuthentication } = await loadDidAuthentication();

  const resultA = evaluateDidAuthentication(didAuthInput());
  const resultB = evaluateDidAuthentication(
    didAuthInput({
      registryRecord: {
        ...didAuthInput().registryRecord,
        allowedTenantIds: [...didAuthInput().registryRecord.allowedTenantIds].reverse(),
      },
    }),
  );

  assert.equal(resultA.verified, true);
  assert.equal(resultA.state, 'verified');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.blockedBy, []);
  assert.equal(resultA.exochainProductionClaim, false);
  assert.equal(resultA.authentication.actorDid, 'did:exo:principal-investigator-alpha');
  assert.equal(resultA.authentication.keyRef, 'did:exo:principal-investigator-alpha#key-1');
  assert.equal(resultA.authentication.registrySource, 'exochain_did_registry');
  assert.equal(resultA.authentication.signatureVerified, true);
  assert.equal(resultA.authentication.challengeHash.length, 64);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'did_authentication_evidence');
  assert.equal(resultA.receipt.anchorPayload.custodyDigest, digestB);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.authentication.challengeHash, resultB.authentication.challengeHash);
  assert.deepEqual(resultA.allowedTenantIds, ['tenant-network-beta', 'tenant-site-alpha']);
  assert.equal(JSON.stringify(resultA.receipt).includes(validSignature), false);
  assert.equal(JSON.stringify(resultA.receipt).includes('BEGIN PUBLIC KEY'), false);

  assert.equal(
    buildDidAuthenticationChallenge(didAuthInput()),
    '{"actorDid":"did:exo:principal-investigator-alpha","audience":"cybermedica.did-auth.v1","expiresAtHlc":{"logical":0,"physicalMs":1790003300000},"issuedAtHlc":{"logical":1,"physicalMs":1790003000000},"keyRef":"did:exo:principal-investigator-alpha#key-1","nonceHash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","purpose":"qms_request_authentication","requestHash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","tenantId":"tenant-site-alpha"}',
  );
});

test('DID authentication fails closed for malformed DID stale challenge and wrong registry key', async () => {
  const { evaluateDidAuthentication } = await loadDidAuthentication();

  const malformedDid = evaluateDidAuthentication(
    didAuthInput({
      actor: { did: 'did:exo:Principal Investigator Alpha', kind: 'human' },
      registryRecord: {
        ...didAuthInput().registryRecord,
        did: 'did:exo:Principal Investigator Alpha',
        keyRef: 'did:exo:Principal Investigator Alpha#key-1',
      },
    }),
  );

  assert.equal(malformedDid.verified, false);
  assert.equal(malformedDid.state, 'denied');
  assert.equal(malformedDid.receipt, null);
  assert.ok(malformedDid.blockedBy.includes('did_format_invalid'));

  const staleChallenge = evaluateDidAuthentication(
    didAuthInput({
      challenge: {
        purpose: 'qms_request_authentication',
        requestHash: digestD,
        nonceHash: digestC,
        issuedAtHlc: { physicalMs: 1789990000000, logical: 0 },
        expiresAtHlc: { physicalMs: 1790003200000, logical: 0 },
      },
      signature: staleSignature,
    }),
  );

  assert.equal(staleChallenge.verified, false);
  assert.equal(staleChallenge.state, 'denied');
  assert.ok(staleChallenge.blockedBy.includes('did_auth_challenge_stale'));
  assert.equal(staleChallenge.receipt, null);

  const wrongKey = evaluateDidAuthentication(
    didAuthInput({
      registryRecord: {
        ...didAuthInput().registryRecord,
        publicKeyPem: wrongPublicKeyPem,
      },
    }),
  );

  assert.equal(wrongKey.verified, false);
  assert.equal(wrongKey.state, 'denied');
  assert.ok(wrongKey.blockedBy.includes('did_signature_invalid'));
  assert.equal(wrongKey.receipt, null);
});

test('DID authentication distinguishes absent pending and mismatched registry evidence', async () => {
  const { evaluateDidAuthentication } = await loadDidAuthentication();

  const absentRegistry = evaluateDidAuthentication(didAuthInput({ registryRecord: null }));
  assert.equal(absentRegistry.verified, false);
  assert.equal(absentRegistry.state, 'inactive');
  assert.ok(absentRegistry.blockedBy.includes('did_registry_record_absent'));

  const pendingRegistry = evaluateDidAuthentication(
    didAuthInput({
      registryRecord: {
        ...didAuthInput().registryRecord,
        status: 'pending',
      },
    }),
  );
  assert.equal(pendingRegistry.verified, false);
  assert.equal(pendingRegistry.state, 'pending');
  assert.deepEqual(pendingRegistry.blockedBy, ['did_registry_pending']);

  const mismatchedRegistry = evaluateDidAuthentication(
    didAuthInput({
      registryRecord: {
        ...didAuthInput().registryRecord,
        did: 'did:exo:quality-manager-alpha',
      },
    }),
  );
  assert.equal(mismatchedRegistry.verified, false);
  assert.equal(mismatchedRegistry.state, 'denied');
  assert.ok(mismatchedRegistry.blockedBy.includes('did_registry_did_mismatch'));
});

test('DID authentication rejects protected content and raw key material before receipts', async () => {
  const { evaluateDidAuthentication } = await loadDidAuthentication();

  assert.throws(
    () =>
      evaluateDidAuthentication(
        didAuthInput({
          registryRecord: {
            ...didAuthInput().registryRecord,
            rawContent: 'Participant Alice Example identity worksheet must not be anchored.',
          },
        }),
      ),
    /protected content/i,
  );

  assert.throws(
    () =>
      evaluateDidAuthentication(
        didAuthInput({
          registryRecord: {
            ...didAuthInput().registryRecord,
            privateKey: 'fixture key material must never be accepted',
          },
        }),
      ),
    /protected content/i,
  );
});

test('DID authentication reports malformed registry challenge and gateway auth defects', async () => {
  const { evaluateDidAuthentication } = await loadDidAuthentication();

  const malformed = evaluateDidAuthentication(
    didAuthInput({
      registryRecord: {
        did: 'did:exo:principal-investigator-alpha',
        source: 'local_identity_cache',
        status: 'revoked',
        keyRef: '',
        algorithm: 'RSA-PSS',
        publicKeyPem: 'not a public key',
        registryEvidenceHash: '0000000000000000000000000000000000000000000000000000000000000000',
        custodyDigest: 'not-a-digest',
      },
      challenge: {
        purpose: '',
        requestHash: 'not-a-digest',
        nonceHash: '0000000000000000000000000000000000000000000000000000000000000000',
        issuedAtHlc: { physicalMs: 1790003000000, logical: 3 },
        expiresAtHlc: { physicalMs: 1790003000000, logical: 1 },
      },
      verification: {
        checkedAtHlc: { physicalMs: 1790003000000, logical: 2 },
        gatewayAuthRequired: false,
      },
      signature: '',
    }),
  );

  assert.equal(malformed.verified, false);
  assert.equal(malformed.state, 'denied');
  assert.equal(malformed.receipt, null);
  assert.ok(malformed.blockedBy.includes('did_registry_source_unverified'));
  assert.ok(malformed.blockedBy.includes('did_registry_unverified'));
  assert.ok(malformed.blockedBy.includes('did_algorithm_unsupported'));
  assert.ok(malformed.blockedBy.includes('did_key_ref_absent'));
  assert.ok(malformed.blockedBy.includes('did_public_key_invalid'));
  assert.ok(malformed.blockedBy.includes('did_registry_evidence_hash_invalid'));
  assert.ok(malformed.blockedBy.includes('did_registry_custody_digest_invalid'));
  assert.ok(malformed.blockedBy.includes('did_tenant_not_allowed_by_registry'));
  assert.ok(malformed.blockedBy.includes('did_auth_purpose_absent'));
  assert.ok(malformed.blockedBy.includes('did_auth_request_hash_invalid'));
  assert.ok(malformed.blockedBy.includes('did_auth_nonce_hash_invalid'));
  assert.ok(malformed.blockedBy.includes('did_auth_challenge_window_invalid'));
  assert.ok(malformed.blockedBy.includes('did_auth_issued_after_verification'));
  assert.ok(malformed.blockedBy.includes('did_auth_challenge_expired'));
  assert.ok(malformed.blockedBy.includes('gateway_auth_requirement_absent'));
  assert.ok(malformed.blockedBy.includes('did_signature_absent'));
  assert.ok(malformed.blockedBy.includes('did_signature_invalid'));
});
