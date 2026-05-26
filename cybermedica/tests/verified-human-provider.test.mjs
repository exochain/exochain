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

async function loadVerifiedHumanProvider() {
  try {
    return await import('../src/verified-human-provider.mjs');
  } catch (error) {
    assert.fail(`CyberMedica verified human provider module must exist and load: ${error.message}`);
  }
}

const digestA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const digestB = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const digestC = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';

function verifiedHumanInput(overrides = {}) {
  return {
    tenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:principal-investigator-alpha', kind: 'human' },
    provider: {
      providerId: 'external-human-proofing-provider-alpha',
      status: 'verified',
      checkedBy: 'did:exo:human-proofing-service-alpha',
      checkedAtHlc: { physicalMs: 1790003000000, logical: 8 },
      evidenceRef: 'cm-human-proofing/pi-alpha-attestation-v1',
      attestationHash: digestA,
      custodyDigest: digestB,
      allowedHumanDids: [
        'did:exo:quality-manager-alpha',
        'did:exo:principal-investigator-alpha',
      ],
    },
    ...overrides,
  };
}

test('verified human provider creates deterministic inactive human-gate evidence', async () => {
  const { evaluateVerifiedHumanProvider } = await loadVerifiedHumanProvider();

  const resultA = evaluateVerifiedHumanProvider(verifiedHumanInput());
  const resultB = evaluateVerifiedHumanProvider(
    verifiedHumanInput({
      provider: {
        ...verifiedHumanInput().provider,
        allowedHumanDids: [...verifiedHumanInput().provider.allowedHumanDids].reverse(),
      },
    }),
  );

  assert.equal(resultA.verified, true);
  assert.equal(resultA.state, 'verified');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.blockedBy, []);
  assert.equal(resultA.exochainProductionClaim, false);
  assert.equal(resultA.humanGate.verified, true);
  assert.equal(resultA.humanGate.actorDid, 'did:exo:principal-investigator-alpha');
  assert.equal(resultA.humanGate.providerId, 'external-human-proofing-provider-alpha');
  assert.equal(resultA.humanGate.evidenceReceiptId, resultA.receipt.receiptId);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'verified_human_provider_evidence');
  assert.equal(resultA.receipt.anchorPayload.custodyDigest, digestB);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.providerEvidenceHash, resultB.providerEvidenceHash);
  assert.deepEqual(resultA.providerAllowedHumanDids, [
    'did:exo:principal-investigator-alpha',
    'did:exo:quality-manager-alpha',
  ]);
});

test('verified human provider fails closed without external provider evidence or for AI actors', async () => {
  const { evaluateVerifiedHumanProvider } = await loadVerifiedHumanProvider();

  const absentProvider = evaluateVerifiedHumanProvider({
    tenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:principal-investigator-alpha', kind: 'human', selfDeclaredHuman: true },
  });

  assert.equal(absentProvider.verified, false);
  assert.equal(absentProvider.state, 'inactive');
  assert.equal(absentProvider.failClosed, true);
  assert.equal(absentProvider.receipt, null);
  assert.equal(absentProvider.humanGate.verified, false);
  assert.ok(absentProvider.blockedBy.includes('verified_human_provider_absent'));
  assert.ok(absentProvider.blockedBy.includes('self_declared_human_insufficient'));

  const aiActor = evaluateVerifiedHumanProvider(
    verifiedHumanInput({
      actor: { did: 'did:exo:ai-quality-reviewer-alpha', kind: 'ai_agent' },
      provider: {
        ...verifiedHumanInput().provider,
        allowedHumanDids: ['did:exo:ai-quality-reviewer-alpha'],
      },
    }),
  );

  assert.equal(aiActor.verified, false);
  assert.equal(aiActor.state, 'denied');
  assert.equal(aiActor.failClosed, true);
  assert.equal(aiActor.receipt, null);
  assert.ok(aiActor.blockedBy.includes('ai_actor_cannot_satisfy_human_gate'));
});

test('verified human provider denies unlisted pending malformed or protected inputs', async () => {
  const { evaluateVerifiedHumanProvider } = await loadVerifiedHumanProvider();

  const unlisted = evaluateVerifiedHumanProvider(
    verifiedHumanInput({
      actor: { did: 'did:exo:sub-investigator-beta', kind: 'human' },
    }),
  );

  assert.equal(unlisted.verified, false);
  assert.equal(unlisted.state, 'denied');
  assert.ok(unlisted.blockedBy.includes('human_did_not_allowed_by_provider'));

  const pending = evaluateVerifiedHumanProvider(
    verifiedHumanInput({
      provider: {
        ...verifiedHumanInput().provider,
        status: 'pending',
      },
    }),
  );

  assert.equal(pending.verified, false);
  assert.equal(pending.state, 'pending');
  assert.deepEqual(pending.blockedBy, ['verified_human_provider_pending']);
  assert.equal(pending.receipt, null);

  const malformed = evaluateVerifiedHumanProvider(
    verifiedHumanInput({
      provider: {
        ...verifiedHumanInput().provider,
        checkedAtHlc: { physicalMs: 1790003000000 },
        attestationHash: 'not-a-digest',
        custodyDigest: digestC,
        allowedHumanDids: [],
      },
    }),
  );

  assert.equal(malformed.verified, false);
  assert.equal(malformed.state, 'denied');
  assert.ok(malformed.blockedBy.includes('verified_human_checked_at_invalid'));
  assert.ok(malformed.blockedBy.includes('verified_human_attestation_hash_invalid'));
  assert.ok(malformed.blockedBy.includes('verified_human_allowlist_absent'));

  assert.throws(
    () =>
      evaluateVerifiedHumanProvider(
        verifiedHumanInput({
          provider: {
            ...verifiedHumanInput().provider,
            rawContent: 'Participant Alice Example identity proofing worksheet must not be anchored.',
          },
        }),
      ),
    /protected content/i,
  );
});
