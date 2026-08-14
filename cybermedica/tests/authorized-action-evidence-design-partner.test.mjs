// Copyright (c) 2026 Exochain Foundation. All rights reserved.
// Proprietary and confidential. See cybermedica/LICENSE.
// SPDX-License-Identifier: LicenseRef-Exochain-Proprietary

import assert from 'node:assert/strict';
import { test } from 'node:test';

const PACK_HASH = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ACTION_HASH = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

async function loadModule() {
  return import('../src/authorized-action-evidence-design-partner.mjs');
}

function validInput(overrides = {}) {
  return {
    partnerRef: 'cybermedica-design-partner',
    tenantId: 'tenant-cm-001',
    actorDid: 'did:exo:quality-officer',
    evidencePackHash: PACK_HASH,
    actionCommitmentHash: ACTION_HASH,
    purpose: 'regulated_proof',
    metadataOnly: true,
    protectedContentExcluded: true,
    exochainProductionClaim: false,
    insuranceRiskTransfer: false,
    gmvTakeRateClaim: false,
    hlcTimestamp: { physicalMs: 1_800_000_000_000, logical: 0 },
    ...overrides,
  };
}

test('consumes metadata-only evidence pack hashes as an inactive design-partner proof', async () => {
  const { consumeAuthorizedActionEvidencePack } = await loadModule();
  const result = consumeAuthorizedActionEvidencePack(validInput());
  assert.equal(result.schema, 'cybermedica.authorized_action_evidence_design_partner.v1');
  assert.equal(result.accepted, true);
  assert.equal(result.insuranceRiskTransfer, false);
  assert.equal(result.insuranceReadinessOnly, true);
  assert.equal(result.gmvTakeRateClaim, false);
  assert.equal(result.exochainProductionClaim, false);
  assert.equal(result.trustState, 'inactive');
  assert.equal(result.evidencePackHash, PACK_HASH);
  assert.equal(result.receipt.trustState, 'inactive');
});

test('is deterministic for the same hash-only input', async () => {
  const { consumeAuthorizedActionEvidencePack } = await loadModule();
  const left = consumeAuthorizedActionEvidencePack(validInput());
  const right = consumeAuthorizedActionEvidencePack(validInput());
  assert.deepEqual(left, right);
});

test('refuses insurance risk-transfer and GMV take-rate claims', async () => {
  const { consumeAuthorizedActionEvidencePack, ProtectedContentError } = await loadModule();
  assert.throws(
    () => consumeAuthorizedActionEvidencePack(validInput({ insuranceRiskTransfer: true })),
    ProtectedContentError,
  );
  assert.throws(
    () => consumeAuthorizedActionEvidencePack(validInput({ gmvTakeRateClaim: true })),
    ProtectedContentError,
  );
});

test('refuses PHI and secret fields', async () => {
  const { consumeAuthorizedActionEvidencePack, ProtectedContentError } = await loadModule();
  assert.throws(
    () => consumeAuthorizedActionEvidencePack(validInput({ rawPhi: 'hidden' })),
    ProtectedContentError,
  );
  assert.throws(
    () => consumeAuthorizedActionEvidencePack(validInput({ apiKey: 'secret' })),
    ProtectedContentError,
  );
});

test('refuses production trust claims and missing pack hashes', async () => {
  const { consumeAuthorizedActionEvidencePack, ProtectedContentError } = await loadModule();
  assert.throws(
    () => consumeAuthorizedActionEvidencePack(validInput({ exochainProductionClaim: true })),
    ProtectedContentError,
  );
  assert.throws(
    () => consumeAuthorizedActionEvidencePack(validInput({ evidencePackHash: '0'.repeat(64) })),
    ProtectedContentError,
  );
});
