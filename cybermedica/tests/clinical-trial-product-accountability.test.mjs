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

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

const REQUIRED_ACCOUNTABILITY_DOMAINS = Object.freeze([
  'access_control',
  'blinding_control',
  'dispensing',
  'disposal',
  'expiration_control',
  'receipt',
  'reconciliation',
  'return',
  'stock_control',
  'storage',
]);

async function loadProductAccountability() {
  try {
    return await import('../src/clinical-trial-product-accountability.mjs');
  } catch (error) {
    assert.fail(`CyberMedica clinical-trial-product-accountability module must exist and load: ${error.message}`);
  }
}

function mergeDeep(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      mergeDeep(base[key], overrides[key]),
    ]),
  );
}

function domainEvidence(domainRef, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    domainRef,
    status: 'verified',
    evidenceHash: hashes[index % hashes.length],
    reviewedAtHlc: { physicalMs: 1802000020000 + index, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function productLot(overrides = {}) {
  return {
    productRef: 'ip-cardiac-alpha-001',
    protocolRef: 'protocol-cardiac-alpha',
    siteRef: 'site-alpha',
    sponsorRef: 'sponsor-alpha',
    productType: 'investigational_product',
    lotRef: 'lot-alpha-001',
    batchSerialHash: DIGEST_A,
    receiptRecordHash: DIGEST_B,
    storageControlHash: DIGEST_C,
    temperatureControlHash: DIGEST_D,
    accessControlHash: DIGEST_E,
    blindingControlHash: DIGEST_F,
    expirationAtHlc: { physicalMs: 1812000000000, logical: 0 },
    receivedAtHlc: { physicalMs: 1802000000000, logical: 0 },
    quantityReceived: 120,
    quantityDispensed: 24,
    quantityReturnedToSponsor: 6,
    quantityDisposed: 0,
    quantityOnHand: 90,
    nonconformityRef: null,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function dispensingRecord(overrides = {}) {
  return {
    dispensingRef: 'dispense-alpha-001',
    productRef: 'ip-cardiac-alpha-001',
    participantCodeHash: DIGEST_F,
    quantityDispensed: 4,
    dispensedAtHlc: { physicalMs: 1802000010000, logical: 0 },
    dispensedByDid: 'did:exo:ip-manager-alpha',
    witnessDid: 'did:exo:pharmacy-witness-alpha',
    prescriptionOrderHash: DIGEST_C,
    visitRef: 'visit-week-01',
    blindingStatus: 'blinded',
    unblindedActorDid: 'did:exo:unblinded-pharmacist-alpha',
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function returnOrDisposalRecord(recordType, overrides = {}) {
  return {
    recordRef: `${recordType}-alpha-001`,
    recordType,
    productRef: 'ip-cardiac-alpha-001',
    quantity: recordType === 'return_to_sponsor' ? 6 : 0,
    recordedAtHlc: { physicalMs: 1802000040000, logical: recordType === 'return_to_sponsor' ? 0 : 1 },
    recordedByDid: 'did:exo:ip-manager-alpha',
    evidenceHash: recordType === 'return_to_sponsor' ? DIGEST_D : DIGEST_E,
    custodyDigest: recordType === 'return_to_sponsor' ? DIGEST_E : DIGEST_F,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function accountabilityInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:ip-manager-alpha',
      kind: 'human',
      roleRefs: ['pharmacy_investigational_product_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_product_accountability', 'write'],
      authorityChainHash: DIGEST_A,
    },
    accountabilityPlan: {
      planRef: 'product-accountability-plan-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      status: 'active',
      requiredDomains: REQUIRED_ACCOUNTABILITY_DOMAINS,
      productAccountabilitySopHash: DIGEST_B,
      randomizationPlanHash: DIGEST_C,
      blindingPlanHash: DIGEST_D,
      accessPolicyHash: DIGEST_E,
      storageProcedureHash: DIGEST_F,
      reconciliationProcedureHash: DIGEST_A,
      assessedAtHlc: { physicalMs: 1802000060000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    productLots: [productLot()],
    dispensingRecords: [dispensingRecord()],
    returnDisposalRecords: [returnOrDisposalRecord('return_to_sponsor'), returnOrDisposalRecord('destruction')],
    accountabilityControls: {
      domainEvidence: REQUIRED_ACCOUNTABILITY_DOMAINS.map((domainRef, index) => domainEvidence(domainRef, index)),
      openVarianceCount: 0,
      openNonconformityCount: 0,
      allDispensingRecordsWitnessed: true,
      allParticipantIdentifiersSuppressed: true,
      stockReconciliationHash: DIGEST_B,
      accessReviewHash: DIGEST_C,
      blindingReviewHash: DIGEST_D,
      returnDisposalReconciliationHash: DIGEST_E,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:principal-investigator-alpha',
      productManagerDid: 'did:exo:ip-manager-alpha',
      qualityReviewerDid: 'did:exo:quality-manager-alpha',
      decision: 'product_accountability_reconciled',
      reviewedAtHlc: { physicalMs: 1802000070000, logical: 0 },
      finalAuthority: 'human',
      aiFinalAuthority: false,
      evidenceBundleHash: DIGEST_F,
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-product-accountability-alpha',
        workflowReceiptId: 'df-workflow-product-accountability-alpha',
      },
    },
    custodyDigest: DIGEST_E,
  };
  return mergeDeep(base, overrides);
}

test('clinical trial product accountability creates deterministic inactive reconciliation receipts', async () => {
  const { evaluateClinicalTrialProductAccountability } = await loadProductAccountability();

  const resultA = evaluateClinicalTrialProductAccountability(accountabilityInput());
  const inputB = accountabilityInput();
  inputB.accountabilityPlan.requiredDomains = [...inputB.accountabilityPlan.requiredDomains].reverse();
  inputB.accountabilityControls.domainEvidence = [...inputB.accountabilityControls.domainEvidence].reverse();
  inputB.returnDisposalRecords = [...inputB.returnDisposalRecords].reverse();
  const resultB = evaluateClinicalTrialProductAccountability(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.accountability.reconciliationStatus, 'reconciled');
  assert.equal(resultA.accountability.productLotCount, 1);
  assert.equal(resultA.accountability.dispensingRecordCount, 1);
  assert.equal(resultA.accountability.returnDisposalRecordCount, 2);
  assert.deepEqual(resultA.accountability.requiredDomains, REQUIRED_ACCOUNTABILITY_DOMAINS);
  assert.deepEqual(resultA.accountability.coveredDomains, REQUIRED_ACCOUNTABILITY_DOMAINS);
  assert.equal(resultA.accountability.aiFinalAuthority, false);
  assert.equal(resultA.accountability.exochainProductionClaim, false);
  assert.equal(resultA.accountability.containsProtectedContent, false);
  assert.equal(resultA.accountability.accountabilityId, resultB.accountability.accountabilityId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'clinical_trial_product_accountability');
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|serial number 123|raw product/iu);
});

test('clinical trial product accountability denies missing domains and broken stock reconciliation', async () => {
  const { evaluateClinicalTrialProductAccountability } = await loadProductAccountability();

  const result = evaluateClinicalTrialProductAccountability(
    accountabilityInput({
      accountabilityPlan: {
        requiredDomains: REQUIRED_ACCOUNTABILITY_DOMAINS.filter((domainRef) => domainRef !== 'disposal'),
      },
      productLots: [productLot({ quantityOnHand: 91, nonconformityRef: '' })],
      accountabilityControls: {
        domainEvidence: REQUIRED_ACCOUNTABILITY_DOMAINS.filter((domainRef) => domainRef !== 'stock_control').map(
          (domainRef, index) => domainEvidence(domainRef, index),
        ),
        openVarianceCount: 1,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.accountability.reconciliationStatus, 'blocked');
  assert.match(result.denialReasons.join('|'), /required_domain_missing:disposal/);
  assert.match(result.denialReasons.join('|'), /domain_evidence_missing:stock_control/);
  assert.match(result.denialReasons.join('|'), /product_stock_reconciliation_mismatch:ip-cardiac-alpha-001/);
  assert.match(result.denialReasons.join('|'), /product_nonconformity_linkage_absent:ip-cardiac-alpha-001/);
  assert.match(result.denialReasons.join('|'), /open_variance_count_present/);
});

test('clinical trial product accountability denies unsafe dispensing and blinding governance', async () => {
  const { evaluateClinicalTrialProductAccountability } = await loadProductAccountability();

  const result = evaluateClinicalTrialProductAccountability(
    accountabilityInput({
      dispensingRecords: [
        dispensingRecord({
          participantCodeHash: 'subject-alpha-raw',
          witnessDid: '',
          blindingStatus: 'emergency_unblinded',
          unblindedActorDid: '',
        }),
      ],
      accountabilityControls: {
        allDispensingRecordsWitnessed: false,
        allParticipantIdentifiersSuppressed: false,
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.denialReasons.join('|'), /dispensing_participant_code_hash_invalid:dispense-alpha-001/);
  assert.match(result.denialReasons.join('|'), /dispensing_witness_absent:dispense-alpha-001/);
  assert.match(result.denialReasons.join('|'), /emergency_unblinding_actor_absent:dispense-alpha-001/);
  assert.match(result.denialReasons.join('|'), /dispensing_witness_control_incomplete/);
  assert.match(result.denialReasons.join('|'), /participant_identifier_boundary_incomplete/);
  assert.match(result.denialReasons.join('|'), /ai_final_authority_forbidden/);
});

test('clinical trial product accountability denies expired stock and non-monotonic HLC evidence', async () => {
  const { evaluateClinicalTrialProductAccountability } = await loadProductAccountability();

  const result = evaluateClinicalTrialProductAccountability(
    accountabilityInput({
      productLots: [
        productLot({
          expirationAtHlc: { physicalMs: 1802000050000, logical: 0 },
          nonconformityRef: '',
        }),
      ],
      dispensingRecords: [
        dispensingRecord({
          dispensedAtHlc: { physicalMs: 1801000000000, logical: 0 },
        }),
      ],
      returnDisposalRecords: [
        returnOrDisposalRecord('return_to_sponsor', {
          recordedAtHlc: { physicalMs: 1801000000000, logical: 0 },
        }),
      ],
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.denialReasons.join('|'), /product_expired_or_expiration_time_invalid:ip-cardiac-alpha-001/);
  assert.match(result.denialReasons.join('|'), /product_nonconformity_linkage_absent:ip-cardiac-alpha-001/);
  assert.match(result.denialReasons.join('|'), /dispensing_time_not_after_receipt:dispense-alpha-001/);
  assert.match(result.denialReasons.join('|'), /return_disposal_time_not_after_receipt:return_to_sponsor-alpha-001/);
});

test('clinical trial product accountability rejects raw product content and secrets before receipts are created', async () => {
  const { ProtectedContentError, evaluateClinicalTrialProductAccountability } = await loadProductAccountability();

  assert.throws(
    () =>
      evaluateClinicalTrialProductAccountability({
        ...accountabilityInput(),
        productAccountabilityNarrative: 'raw product accountability for Participant Alice serial number 123',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateClinicalTrialProductAccountability({
        ...accountabilityInput(),
        pharmacySecret: 'prod-secret',
      }),
    ProtectedContentError,
  );
});
