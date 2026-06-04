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

const REQUIRED_RANDOMIZATION_DOMAINS = Object.freeze([
  'allocation_concealment',
  'assignment_code_list',
  'blinding_role_separation',
  'emergency_unblinding_control',
  'participant_identifier_suppression',
  'product_linkage',
  'protocol_version_alignment',
  'randomization_system_validation',
  'sponsor_ethics_notification',
]);

async function loadRandomizationBlindingManagement() {
  try {
    return await import('../src/randomization-blinding-management.mjs');
  } catch (error) {
    assert.fail(`CyberMedica randomization-blinding-management module must exist and load: ${error.message}`);
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
    reviewedAtHlc: { physicalMs: 1804000020000 + index, logical: 0 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function assignment(overrides = {}) {
  return {
    assignmentRef: 'rand-assign-alpha-001',
    participantCodeHash: DIGEST_A,
    protocolRef: 'protocol-cardiac-alpha',
    protocolVersionRef: 'protocol-version-3',
    siteRef: 'site-alpha',
    productLotRef: 'lot-alpha-001',
    assignmentArmHash: DIGEST_B,
    randomizationCodeHash: DIGEST_C,
    allocationVersionHash: DIGEST_D,
    assignedAtHlc: { physicalMs: 1804000010000, logical: 0 },
    assignedByDid: 'did:exo:randomization-system-alpha',
    assignmentReceiptHash: DIGEST_E,
    blindedRoleRefs: ['clinical_research_coordinator', 'principal_investigator'],
    unblindedCustodianDid: 'did:exo:unblinded-pharmacist-alpha',
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function unblindingEvent(overrides = {}) {
  return {
    eventRef: 'unblind-event-alpha-001',
    assignmentRef: 'rand-assign-alpha-001',
    participantCodeHash: DIGEST_A,
    requestedAtHlc: { physicalMs: 1804000030000, logical: 0 },
    authorizedAtHlc: { physicalMs: 1804000031000, logical: 0 },
    reviewedAtHlc: { physicalMs: 1804000040000, logical: 0 },
    authorized: true,
    authorizedByDid: 'did:exo:principal-investigator-alpha',
    medicalMonitorDid: 'did:exo:medical-monitor-alpha',
    safetyJustificationHash: DIGEST_B,
    codeBreakLogHash: DIGEST_C,
    sponsorNotificationHash: DIGEST_D,
    ethicsNotificationHash: DIGEST_E,
    postReviewReceiptHash: DIGEST_F,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function randomizationInput(overrides = {}) {
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
      permissions: ['manage_randomization_blinding', 'manage_product_accountability'],
      authorityChainHash: DIGEST_A,
    },
    randomizationPlan: {
      planRef: 'randomization-blinding-plan-alpha',
      protocolRef: 'protocol-cardiac-alpha',
      protocolVersionRef: 'protocol-version-3',
      siteRef: 'site-alpha',
      sponsorRef: 'sponsor-alpha',
      status: 'active',
      requiredDomains: REQUIRED_RANDOMIZATION_DOMAINS,
      randomizationMethodHash: DIGEST_B,
      allocationRatioHash: DIGEST_C,
      seedCustodyHash: DIGEST_D,
      blindingPlanHash: DIGEST_E,
      codeListHash: DIGEST_F,
      emergencyUnblindingSopHash: DIGEST_A,
      assessedAtHlc: { physicalMs: 1804000050000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    assignments: [assignment()],
    emergencyUnblindingEvents: [unblindingEvent()],
    blindingControls: {
      domainEvidence: REQUIRED_RANDOMIZATION_DOMAINS.map((domainRef, index) => domainEvidence(domainRef, index)),
      allocationConcealmentMaintained: true,
      unblindedRolesSeparated: true,
      participantIdentifiersSuppressed: true,
      openCodeBreakCount: 0,
      codeListAccessPolicyHash: DIGEST_B,
      randomizationSystemValidationHash: DIGEST_C,
      blindingAccessReviewHash: DIGEST_D,
      productAccountabilityRef: 'product-accountability-alpha',
      productAccountabilityHash: DIGEST_E,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      principalInvestigatorDid: 'did:exo:principal-investigator-alpha',
      unblindedCustodianDid: 'did:exo:unblinded-pharmacist-alpha',
      decision: 'randomization_blinding_ready',
      reviewedAtHlc: { physicalMs: 1804000060000, logical: 0 },
      finalAuthority: 'human',
      aiFinalAuthority: false,
      evidenceBundleHash: DIGEST_F,
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-randomization-blinding-alpha',
        workflowReceiptId: 'df-workflow-randomization-blinding-alpha',
      },
    },
    custodyDigest: DIGEST_D,
  };
  return mergeDeep(base, overrides);
}

test('randomization blinding management creates deterministic inactive assignment receipts', async () => {
  const { evaluateRandomizationBlindingManagement } = await loadRandomizationBlindingManagement();

  const resultA = evaluateRandomizationBlindingManagement(randomizationInput());
  const inputB = randomizationInput();
  inputB.randomizationPlan.requiredDomains = [...inputB.randomizationPlan.requiredDomains].reverse();
  inputB.blindingControls.domainEvidence = [...inputB.blindingControls.domainEvidence].reverse();
  inputB.assignments = [...inputB.assignments].reverse();
  const resultB = evaluateRandomizationBlindingManagement(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.randomizationBlinding.readinessStatus, 'ready');
  assert.equal(resultA.randomizationBlinding.assignmentCount, 1);
  assert.equal(resultA.randomizationBlinding.emergencyUnblindingEventCount, 1);
  assert.equal(resultA.randomizationBlinding.openCodeBreakCount, 0);
  assert.deepEqual(resultA.randomizationBlinding.requiredDomains, REQUIRED_RANDOMIZATION_DOMAINS);
  assert.deepEqual(resultA.randomizationBlinding.coveredDomains, REQUIRED_RANDOMIZATION_DOMAINS);
  assert.equal(resultA.randomizationBlinding.aiFinalAuthority, false);
  assert.equal(resultA.randomizationBlinding.exochainProductionClaim, false);
  assert.equal(resultA.randomizationBlinding.containsProtectedContent, false);
  assert.equal(resultA.randomizationBlinding.randomizationBlindingId, resultB.randomizationBlinding.randomizationBlindingId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'randomization_blinding_management');
  assert.doesNotMatch(JSON.stringify(resultA), /Participant Alice|randomization list body|code break note|medical record/iu);
});

test('randomization blinding management fails closed for missing domains and duplicate assignments', async () => {
  const { evaluateRandomizationBlindingManagement } = await loadRandomizationBlindingManagement();

  const result = evaluateRandomizationBlindingManagement(
    randomizationInput({
      randomizationPlan: {
        requiredDomains: REQUIRED_RANDOMIZATION_DOMAINS.filter((domainRef) => domainRef !== 'allocation_concealment'),
      },
      blindingControls: {
        domainEvidence: REQUIRED_RANDOMIZATION_DOMAINS.filter((domainRef) => domainRef !== 'product_linkage').map(
          (domainRef, index) => domainEvidence(domainRef, index),
        ),
      },
      assignments: [
        assignment(),
        assignment({
          assignmentRef: 'rand-assign-alpha-002',
          randomizationCodeHash: DIGEST_C,
          participantCodeHash: DIGEST_A,
        }),
      ],
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.randomizationBlinding.readinessStatus, 'blocked');
  assert.ok(result.reasons.includes('required_domain_missing:allocation_concealment'));
  assert.ok(result.reasons.includes('domain_evidence_missing:product_linkage'));
  assert.ok(result.reasons.includes('participant_assignment_duplicate'));
  assert.ok(result.reasons.includes('randomization_code_duplicate'));
});

test('randomization blinding management denies unsafe unblinding and role-separation defects', async () => {
  const { evaluateRandomizationBlindingManagement } = await loadRandomizationBlindingManagement();

  const result = evaluateRandomizationBlindingManagement(
    randomizationInput({
      blindingControls: {
        allocationConcealmentMaintained: false,
        unblindedRolesSeparated: false,
        participantIdentifiersSuppressed: false,
        openCodeBreakCount: 1,
      },
      emergencyUnblindingEvents: [
        unblindingEvent({
          authorized: false,
          authorizedByDid: '',
          safetyJustificationHash: '',
          sponsorNotificationHash: '',
          ethicsNotificationHash: '',
          reviewedAtHlc: { physicalMs: 1804000020000, logical: 0 },
        }),
      ],
      humanReview: {
        decision: 'hold_randomization_blinding_gap',
        decisionForum: { openChallenge: true },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('allocation_concealment_not_maintained'));
  assert.ok(result.reasons.includes('unblinded_roles_not_separated'));
  assert.ok(result.reasons.includes('participant_identifier_suppression_absent'));
  assert.ok(result.reasons.includes('open_code_breaks_present'));
  assert.ok(result.reasons.includes('unblinding_not_authorized:unblind-event-alpha-001'));
  assert.ok(result.reasons.includes('unblinding_review_before_authorization:unblind-event-alpha-001'));
  assert.ok(result.reasons.includes('decision_forum_challenge_open'));
});

test('randomization blinding management rejects raw assignment content protected content and secrets', async () => {
  const { evaluateRandomizationBlindingManagement, ProtectedContentError } =
    await loadRandomizationBlindingManagement();

  assert.throws(
    () =>
      evaluateRandomizationBlindingManagement(
        randomizationInput({
          assignments: [
            assignment({
              rawRandomizationListBody: 'Participant Alice Example randomization list body with medical record: MRN-123',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRandomizationBlindingManagement(
        randomizationInput({
          randomizationPlan: {
            codeListSecret: 'prod-secret',
          },
        }),
      ),
    ProtectedContentError,
  );
});
