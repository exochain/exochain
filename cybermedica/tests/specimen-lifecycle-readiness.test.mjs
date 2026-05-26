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

const REQUIRED_SPECIMEN_FAMILIES = [
  'biomarker_blood',
  'pharmacokinetic_sample',
  'safety_laboratory',
  'urine_sample',
];

const REQUIRED_HANDLING_DOMAINS = [
  'central_lab_receipt',
  'collection_identity_separation',
  'courier_chain_of_custody',
  'processing_time_window',
  'result_reconciliation',
  'temperature_monitoring',
];

async function loadSpecimenLifecycleReadiness() {
  try {
    return await import('../src/specimen-lifecycle-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica specimen-lifecycle-readiness module must exist and load: ${error.message}`);
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

function collectionKit(specimenFamily, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    kitRef: `kit-${specimenFamily}`,
    specimenFamily,
    status: 'ready',
    kitInventoryHash: hashes[index],
    kitInstructionHash: hashes[(index + 1) % hashes.length],
    consentBoundaryHash: hashes[(index + 2) % hashes.length],
    collectionWindowHash: hashes[(index + 3) % hashes.length],
    aliquotPlanHash: hashes[(index + 4) % hashes.length],
    ownerDid: `did:exo:specimen-owner-${index}`,
    expiresAtHlc: { physicalMs: 1810000000000 + index, logical: 0 },
    lastReviewedAtHlc: { physicalMs: 1797000000000 + index, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function collectionKits() {
  return REQUIRED_SPECIMEN_FAMILIES.map((family, index) => collectionKit(family, index));
}

function handlingControl(domainRef, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  return {
    domainRef,
    status: 'verified',
    evidenceHash: hashes[index],
    custodyDigest: hashes[(index + 1) % hashes.length],
    ownerDid: `did:exo:handling-owner-${index}`,
    reviewedAtHlc: { physicalMs: 1798000000000 + index, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function handlingControls() {
  return REQUIRED_HANDLING_DOMAINS.map((domainRef, index) => handlingControl(domainRef, index));
}

function readinessInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:lab-operations-lead-alpha',
      kind: 'human',
      roleRefs: ['clinical_research_coordinator', 'lab_operations_lead'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_specimen_lifecycle', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    specimenPlan: {
      planRef: 'specimen-plan-cardiac-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      siteRef: 'site-alpha',
      status: 'active',
      requiredSpecimenFamilies: REQUIRED_SPECIMEN_FAMILIES,
      collectionManualHash: DIGEST_B,
      labManualHash: DIGEST_C,
      processingProcedureHash: DIGEST_D,
      shippingProcedureHash: DIGEST_E,
      resultReviewProcedureHash: DIGEST_F,
      consentMaterialRef: 'consent-materials-cardiac-alpha',
      reviewedAtHlc: { physicalMs: 1799000000000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    collectionKits: collectionKits(),
    handlingControls: handlingControls(),
    logistics: {
      centralLabVendorReadinessRef: 'vendor-central-lab-ready-alpha',
      logisticsVendorReadinessRef: 'vendor-logistics-ready-alpha',
      pharmacyReadinessRef: 'facility-product-ready-alpha',
      governedIntegrationRefs: ['integration-lab-alpha', 'integration-edc-alpha'],
      specimenManifestHash: DIGEST_A,
      shipmentTrackingHash: DIGEST_B,
      temperatureExcursionRegisterHash: DIGEST_C,
      transferOfCustodyHash: DIGEST_D,
      externalLabResultBoundaryHash: DIGEST_E,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    resultReview: {
      reviewRef: 'result-review-cardiac-alpha',
      reviewerDid: 'did:exo:principal-investigator-alpha',
      reviewedAtHlc: { physicalMs: 1800000000000, logical: 0 },
      abnormalResultEscalationProcedureHash: DIGEST_F,
      safetyEventLinkageHash: DIGEST_A,
      sourceDataReconciliationHash: DIGEST_B,
      unresolvedCriticalAbnormalCount: 0,
      pendingResultCount: 0,
      repeatCollectionDecisionHash: DIGEST_C,
      participantIdentifierSuppressed: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    dependencyEvidence: {
      protocolFeasibilityRef: 'protocol-feasibility-alpha',
      facilityProductReadinessRef: 'facility-product-ready-alpha',
      vendorSubcontractorReadinessRef: 'vendor-subcontractor-ready-alpha',
      consentMaterialsRef: 'consent-materials-cardiac-alpha',
      evidenceHashes: [DIGEST_A, DIGEST_B, DIGEST_C],
      metadataOnly: true,
    },
    review: {
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-specimen-lifecycle-alpha',
        workflowReceiptId: 'df-workflow-specimen-lifecycle-alpha',
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      finalAuthority: 'human',
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_D,
  };
  return mergeDeep(base, overrides);
}

test('specimen lifecycle readiness creates deterministic inactive metadata receipts', async () => {
  const { evaluateSpecimenLifecycleReadiness } = await loadSpecimenLifecycleReadiness();

  const resultA = evaluateSpecimenLifecycleReadiness(readinessInput());
  const resultB = evaluateSpecimenLifecycleReadiness({
    ...readinessInput(),
    specimenPlan: {
      ...readinessInput().specimenPlan,
      requiredSpecimenFamilies: [...REQUIRED_SPECIMEN_FAMILIES].reverse(),
    },
    collectionKits: [...readinessInput().collectionKits].reverse(),
    handlingControls: [...readinessInput().handlingControls].reverse(),
    logistics: {
      ...readinessInput().logistics,
      governedIntegrationRefs: [...readinessInput().logistics.governedIntegrationRefs].reverse(),
    },
    dependencyEvidence: {
      ...readinessInput().dependencyEvidence,
      evidenceHashes: [...readinessInput().dependencyEvidence.evidenceHashes].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.specimenLifecycle.readinessStatus, 'ready_for_specimen_operations');
  assert.equal(resultA.specimenLifecycle.trustState, 'inactive');
  assert.equal(resultA.specimenLifecycle.exochainProductionClaim, false);
  assert.deepEqual(resultA.specimenLifecycle.specimenFamiliesCovered, REQUIRED_SPECIMEN_FAMILIES);
  assert.deepEqual(resultA.specimenLifecycle.handlingDomainsCovered, REQUIRED_HANDLING_DOMAINS);
  assert.equal(resultA.specimenLifecycle.kitCount, 4);
  assert.equal(resultA.specimenLifecycle.unresolvedCriticalAbnormalCount, 0);
  assert.equal(resultA.specimenLifecycle.pendingResultCount, 0);
  assert.equal(resultA.specimenLifecycle.readinessId, resultB.specimenLifecycle.readinessId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'specimen_lifecycle_readiness');
  assert.doesNotMatch(JSON.stringify(resultA), /participant alice|lab value|specimen label|source document|raw result/iu);
});

test('specimen lifecycle readiness fails closed for missing families expired kits and unresolved results', async () => {
  const { evaluateSpecimenLifecycleReadiness } = await loadSpecimenLifecycleReadiness();

  const result = evaluateSpecimenLifecycleReadiness(
    readinessInput({
      specimenPlan: {
        requiredSpecimenFamilies: REQUIRED_SPECIMEN_FAMILIES.filter((family) => family !== 'pharmacokinetic_sample'),
      },
      collectionKits: collectionKits()
        .filter((kit) => kit.specimenFamily !== 'pharmacokinetic_sample')
        .map((kit) =>
          kit.specimenFamily === 'biomarker_blood'
            ? {
                ...kit,
                status: 'pending',
                expiresAtHlc: { physicalMs: 1790000000000, logical: 0 },
                kitInventoryHash: '',
              }
            : kit,
        ),
      resultReview: {
        unresolvedCriticalAbnormalCount: 1,
        pendingResultCount: 2,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.specimenLifecycle.readinessStatus, 'not_ready');
  assert.ok(result.reasons.includes('required_specimen_family_missing:pharmacokinetic_sample'));
  assert.ok(result.reasons.includes('kit_not_ready:kit-biomarker_blood'));
  assert.ok(result.reasons.includes('kit_expired_or_invalid:kit-biomarker_blood'));
  assert.ok(result.reasons.includes('kit_inventory_hash_invalid:kit-biomarker_blood'));
  assert.ok(result.reasons.includes('unresolved_critical_abnormal_results'));
  assert.ok(result.reasons.includes('pending_lab_results_present'));
  assert.equal(result.receipt, null);
});

test('specimen lifecycle readiness requires verified handling custody logistics and result reconciliation', async () => {
  const { evaluateSpecimenLifecycleReadiness } = await loadSpecimenLifecycleReadiness();

  const result = evaluateSpecimenLifecycleReadiness(
    readinessInput({
      handlingControls: handlingControls()
        .filter((control) => control.domainRef !== 'temperature_monitoring')
        .map((control) =>
          control.domainRef === 'central_lab_receipt'
            ? {
                ...control,
                status: 'pending',
                custodyDigest: '',
              }
            : control,
        ),
      logistics: {
        centralLabVendorReadinessRef: '',
        specimenManifestHash: '',
        transferOfCustodyHash: '',
      },
      resultReview: {
        sourceDataReconciliationHash: '',
        participantIdentifierSuppressed: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.specimenLifecycle.handlingStatus, 'blocked');
  assert.equal(result.specimenLifecycle.logisticsStatus, 'blocked');
  assert.equal(result.specimenLifecycle.resultReviewStatus, 'blocked');
  assert.ok(result.reasons.includes('handling_domain_missing:temperature_monitoring'));
  assert.ok(result.reasons.includes('handling_control_not_verified:central_lab_receipt'));
  assert.ok(result.reasons.includes('handling_control_custody_digest_invalid:central_lab_receipt'));
  assert.ok(result.reasons.includes('central_lab_vendor_readiness_ref_absent'));
  assert.ok(result.reasons.includes('specimen_manifest_hash_invalid'));
  assert.ok(result.reasons.includes('transfer_of_custody_hash_invalid'));
  assert.ok(result.reasons.includes('source_data_reconciliation_hash_invalid'));
  assert.ok(result.reasons.includes('participant_identifier_suppression_absent'));
});

test('specimen lifecycle readiness enforces human governance and HLC ordering', async () => {
  const { evaluateSpecimenLifecycleReadiness } = await loadSpecimenLifecycleReadiness();

  const result = evaluateSpecimenLifecycleReadiness(
    readinessInput({
      actor: { kind: 'ai_agent' },
      authority: { authorityChainHash: 'not-a-digest' },
      specimenPlan: {
        reviewedAtHlc: { physicalMs: 1799000000000, logical: 0 },
      },
      resultReview: {
        reviewedAtHlc: { physicalMs: 1798000000000, logical: 0 },
      },
      review: {
        decisionForum: {
          verified: false,
          openChallenge: true,
        },
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_actor_required'));
  assert.ok(result.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(result.reasons.includes('result_review_before_plan_review'));
  assert.ok(result.reasons.includes('decision_forum_unverified'));
  assert.ok(result.reasons.includes('challenge_open'));
  assert.ok(result.reasons.includes('human_final_authority_required'));
});

test('specimen lifecycle readiness refuses raw specimen content and secret material', async () => {
  const { ProtectedContentError, evaluateSpecimenLifecycleReadiness } = await loadSpecimenLifecycleReadiness();

  assert.throws(
    () =>
      evaluateSpecimenLifecycleReadiness(
        readinessInput({
          collectionKits: [
            {
              ...collectionKits()[0],
              rawSpecimenLabel: 'Participant Alice specimen label',
            },
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateSpecimenLifecycleReadiness(
        readinessInput({
          logistics: {
            accessToken: 'secret-lab-system-token',
          },
        }),
      ),
    ProtectedContentError,
  );
});
