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

const DIGEST_A = '3d6f0a96f7c972d4f5b66a1c6b5177fe5a32cc0cbd27f7c67be4c11a4f7ce70a';
const DIGEST_B = '8cf4dfd546b712c3b21f0d61fd7c6b744dfc6d9c7d0c8758fb6c6db6e782a7f3';
const DIGEST_C = '54f6e9e53f0e6d9a6ce64b2d67b79d44a927f276e8916d34a2d3b942f575f1b7';

async function loadEvidenceCustody() {
  try {
    return await import('../src/evidence-custody.mjs');
  } catch (error) {
    assert.fail(`CyberMedica evidence custody module must exist and load: ${error.message}`);
  }
}

function custodyTransferInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:evidence-custodian-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['write', 'custody_transfer'],
      authorityChainHash: DIGEST_C,
    },
    evidence: {
      evidenceId: 'CM-EVD-0007',
      evidenceType: 'monitoring_visit_artifact',
      artifactHash: DIGEST_A,
      currentCustodianDid: 'did:exo:evidence-custodian-alpha',
      currentCustodyDigest: DIGEST_B,
      custodySequence: 11,
      classification: 'confidential_metadata_only',
    },
    transfer: {
      fromCustodianDid: 'did:exo:evidence-custodian-alpha',
      toCustodianDid: 'did:exo:quality-archive-beta',
      transferType: 'archive_handoff',
      reasonCode: 'monitoring_package_complete',
      previousTransferAtHlc: { physicalMs: 1790000000800, logical: 2 },
      transferAtHlc: { physicalMs: 1790000000810, logical: 0 },
      evidenceRefIds: ['control-evidence-ref-2', 'control-evidence-ref-1'],
    },
    custodyDigest: DIGEST_B,
  };
}

test('evidence custody transfers require the current custodian and create deterministic inactive receipts', async () => {
  const { evaluateEvidenceCustodyTransfer } = await loadEvidenceCustody();

  const transferA = evaluateEvidenceCustodyTransfer(custodyTransferInput());
  const transferB = evaluateEvidenceCustodyTransfer({
    ...custodyTransferInput(),
    authority: {
      permissions: ['custody_transfer', 'write'],
      expired: false,
      revoked: false,
      valid: true,
      authorityChainHash: DIGEST_C,
    },
    transfer: {
      evidenceRefIds: ['control-evidence-ref-1', 'control-evidence-ref-2'],
      transferAtHlc: { logical: 0, physicalMs: 1790000000810 },
      previousTransferAtHlc: { logical: 2, physicalMs: 1790000000800 },
      reasonCode: 'monitoring_package_complete',
      transferType: 'archive_handoff',
      toCustodianDid: 'did:exo:quality-archive-beta',
      fromCustodianDid: 'did:exo:evidence-custodian-alpha',
    },
  });

  assert.equal(transferA.decision, 'permitted');
  assert.equal(transferA.failClosed, false);
  assert.equal(transferA.custodyTransfer.sequence, 12);
  assert.equal(transferA.custodyTransfer.fromCustodianDid, 'did:exo:evidence-custodian-alpha');
  assert.equal(transferA.custodyTransfer.toCustodianDid, 'did:exo:quality-archive-beta');
  assert.equal(transferA.custodyTransfer.previousCustodyDigest, DIGEST_B);
  assert.match(transferA.custodyTransfer.newCustodyDigest, /^[0-9a-f]{64}$/u);
  assert.notEqual(transferA.custodyTransfer.newCustodyDigest, DIGEST_B);
  assert.equal(transferA.custodyTransfer.newCustodyDigest, transferB.custodyTransfer.newCustodyDigest);
  assert.equal(transferA.receipt.receiptId, transferB.receipt.receiptId);
  assert.equal(transferA.receipt.anchorPayload.artifactType, 'evidence_custody_transfer');
  assert.equal(transferA.receipt.anchorPayload.custodyDigest, transferA.custodyTransfer.newCustodyDigest);
  assert.equal(transferA.receipt.trustState, 'inactive');
  assert.equal(transferA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(transferA), /source document|clinical note|participant alice/iu);
});

test('evidence custody transfers fail closed for wrong custodian and non-monotonic HLC time', async () => {
  const { evaluateEvidenceCustodyTransfer } = await loadEvidenceCustody();

  const denied = evaluateEvidenceCustodyTransfer({
    ...custodyTransferInput(),
    actor: { did: 'did:exo:unassigned-quality-user', kind: 'human' },
    transfer: {
      ...custodyTransferInput().transfer,
      fromCustodianDid: 'did:exo:unassigned-quality-user',
      previousTransferAtHlc: { physicalMs: 1790000000810, logical: 0 },
      transferAtHlc: { physicalMs: 1790000000810, logical: 0 },
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('current_custodian_mismatch'));
  assert.ok(denied.reasons.includes('transfer_time_not_monotonic'));
  assert.equal(denied.custodyTransfer, null);
  assert.equal(denied.receipt, null);
});

test('evidence custody transfers deny broken authority sequence metadata and protected content', async () => {
  const { evaluateEvidenceCustodyTransfer } = await loadEvidenceCustody();

  const denied = evaluateEvidenceCustodyTransfer({
    ...custodyTransferInput(),
    authority: { valid: true, revoked: true, expired: true, permissions: ['read'] },
    evidence: {
      ...custodyTransferInput().evidence,
      custodySequence: 0,
      currentCustodyDigest: null,
    },
    custodyDigest: null,
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('current_custody_digest_invalid'));
  assert.ok(denied.reasons.includes('custody_sequence_invalid'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));

  assert.throws(
    () =>
      evaluateEvidenceCustodyTransfer({
        ...custodyTransferInput(),
        sourceDocumentBody: 'Participant Alice Example source document must not be anchored.',
      }),
    /protected content/i,
  );
});
