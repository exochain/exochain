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
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';

const REQUIRED_MATERIAL_FAMILIES = [
  'amendment_package',
  'consent_form',
  'participant_information',
  'protocol_document',
  'recruitment_material',
];

const REQUIRED_NOTIFICATION_AUDIENCES = [
  'cro',
  'investigator',
  'site_quality',
  'sponsor',
  'study_staff',
];

async function loadIndependentEthicsReview() {
  try {
    return await import('../src/independent-ethics-review.mjs');
  } catch (error) {
    assert.fail(`CyberMedica independent ethics review module must exist and load: ${error.message}`);
  }
}

function material(family, index, overrides = {}) {
  const notApplicable = family === 'amendment_package';
  return {
    materialRef: `${family}-alpha-${index}`,
    family,
    versionRef: `${family}:v${index + 1}`,
    status: notApplicable ? 'not_applicable' : 'approved',
    artifactHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E][index % 5],
    approvalEvidenceHash: notApplicable ? null : [DIGEST_E, DIGEST_D, DIGEST_C, DIGEST_B, DIGEST_A][index % 5],
    notApplicableRationaleHash: notApplicable ? DIGEST_F : null,
    approvedAtHlc: notApplicable ? null : { physicalMs: 1810000001000 + index, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function notification(audience, index, overrides = {}) {
  return {
    notificationRef: `ethics-notice-${audience}-alpha`,
    audience,
    notificationHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E][index % 5],
    deliveredAtHlc: { physicalMs: 1810000009000 + index, logical: index },
    disclosureLogged: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function ethicsReviewInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:regulatory-coordinator-alpha',
      kind: 'human',
      roleRefs: ['regulatory_coordinator', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['independent_ethics_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    ethicsReview: {
      reviewRef: 'irb-review-cardio-alpha',
      protocolRef: 'protocol-cm-alpha',
      protocolVersionRef: 'protocol-cm-alpha:v3',
      siteRef: 'site-alpha',
      studyRef: 'study-alpha',
      committeeRef: 'central-irb-alpha',
      committeeType: 'irb',
      status: 'approved',
      independentCommitteeAttested: true,
      aiRepresentedAsEthicsApproval: false,
      approvalEvidenceHash: DIGEST_B,
      approvalLetterHash: DIGEST_C,
      approvedAtHlc: { physicalMs: 1810000000000, logical: 0 },
      effectiveAtHlc: { physicalMs: 1810000005000, logical: 0 },
      expiresAtHlc: { physicalMs: 1815000000000, logical: 0 },
      evaluatedAtHlc: { physicalMs: 1811000000000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    approvedMaterials: REQUIRED_MATERIAL_FAMILIES.map((family, index) => material(family, index)),
    continuingReview: {
      required: true,
      status: 'current',
      lastCompletedAtHlc: { physicalMs: 1810500000000, logical: 0 },
      nextDueAtHlc: { physicalMs: 1814000000000, logical: 0 },
      reviewEvidenceHash: DIGEST_D,
      dependencyHash: DIGEST_E,
    },
    requiredNotifications: REQUIRED_NOTIFICATION_AUDIENCES.map((audience, index) => notification(audience, index)),
    protocolDependencies: {
      protocolIntakeRef: 'protocol-intake-packet-alpha',
      protocolIntakeHash: DIGEST_F,
      consentMaterialRefs: ['ICF-CARDIO-ALPHA-v3.1'],
      launchGateRef: 'launch-gate-alpha',
      launchGateHash: DIGEST_1,
    },
    reviewGovernance: {
      humanReviewerDid: 'did:exo:quality-manager-alpha',
      decisionForum: {
        required: true,
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-irb-tracking-alpha',
        workflowReceiptId: 'df-irb-workflow-alpha',
      },
      aiAssisted: true,
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_1,
  };
  return {
    ...base,
    ...overrides,
  };
}

test('independent ethics review module loads', async () => {
  const mod = await loadIndependentEthicsReview();
  assert.equal(typeof mod.evaluateIndependentEthicsReview, 'function');
});

test('independent ethics review creates deterministic inactive Policy 5 receipts', async () => {
  const { evaluateIndependentEthicsReview } = await loadIndependentEthicsReview();

  const first = evaluateIndependentEthicsReview(ethicsReviewInput());
  const second = evaluateIndependentEthicsReview({
    ...ethicsReviewInput(),
    approvedMaterials: [...ethicsReviewInput().approvedMaterials].reverse(),
    requiredNotifications: [...ethicsReviewInput().requiredNotifications].reverse(),
    protocolDependencies: {
      ...ethicsReviewInput().protocolDependencies,
      consentMaterialRefs: [...ethicsReviewInput().protocolDependencies.consentMaterialRefs].reverse(),
    },
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.ethicsReview.reviewReady, true);
  assert.equal(first.ethicsReview.approvalStatus, 'approved');
  assert.equal(first.ethicsReview.independentCommitteeAttested, true);
  assert.equal(first.ethicsReview.aiReviewNotEthicsApproval, true);
  assert.equal(first.ethicsReview.continuingReviewState, 'current');
  assert.equal(first.ethicsReview.materialCoverageBasisPoints, 10000);
  assert.deepEqual(first.ethicsReview.approvedMaterialFamilies, REQUIRED_MATERIAL_FAMILIES);
  assert.deepEqual(first.ethicsReview.notifiedAudiences, REQUIRED_NOTIFICATION_AUDIENCES);
  assert.equal(first.ethicsReview.reviewHash, second.ethicsReview.reviewHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.anchorPayload.artifactType, 'independent_ethics_review');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(first), /source document|raw irb|participant alice|patient|medical record/iu);
});

test('independent ethics review fails closed for missing approval dependencies and AI authority', async () => {
  const { evaluateIndependentEthicsReview } = await loadIndependentEthicsReview();
  const input = ethicsReviewInput({
    actor: { did: 'did:exo:ai-irb-agent-alpha', kind: 'ai_agent' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: DIGEST_A,
    },
    ethicsReview: {
      ...ethicsReviewInput().ethicsReview,
      status: 'pending',
      independentCommitteeAttested: false,
      aiRepresentedAsEthicsApproval: true,
      approvalEvidenceHash: '',
      expiresAtHlc: { physicalMs: 1810500000000, logical: 0 },
    },
    approvedMaterials: ethicsReviewInput().approvedMaterials
      .filter((item) => item.family !== 'consent_form')
      .map((item) =>
        item.family === 'protocol_document'
          ? { ...item, status: 'pending', approvalEvidenceHash: '' }
          : item,
      ),
    continuingReview: {
      ...ethicsReviewInput().continuingReview,
      status: 'overdue',
      nextDueAtHlc: { physicalMs: 1810500000000, logical: 0 },
      reviewEvidenceHash: '',
    },
    requiredNotifications: ethicsReviewInput().requiredNotifications.filter((item) => item.audience !== 'sponsor'),
    reviewGovernance: {
      ...ethicsReviewInput().reviewGovernance,
      humanReviewerDid: '',
      aiFinalAuthority: true,
      decisionForum: {
        required: true,
        verified: false,
        state: 'pending',
        humanGate: { verified: false },
        quorum: { status: 'not_met' },
        openChallenge: true,
        decisionId: '',
        workflowReceiptId: '',
      },
    },
  });

  const denied = evaluateIndependentEthicsReview(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.ethicsReview.reviewReady, false);
  assert.equal(denied.ethicsReview.approvalStatus, 'blocked');
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_actor_required'));
  assert.ok(denied.reasons.includes('independent_ethics_review_authority_missing'));
  assert.ok(denied.reasons.includes('ethics_review_not_approved'));
  assert.ok(denied.reasons.includes('committee_independence_absent'));
  assert.ok(denied.reasons.includes('ai_irb_confusion_forbidden'));
  assert.ok(denied.reasons.includes('approval_expires_before_evaluation'));
  assert.ok(denied.reasons.includes('approved_material_family_missing:consent_form'));
  assert.ok(denied.reasons.includes('material_not_approved:protocol_document'));
  assert.ok(denied.reasons.includes('continuing_review_not_current'));
  assert.ok(denied.reasons.includes('continuing_review_due_before_evaluation'));
  assert.ok(denied.reasons.includes('notification_audience_missing:sponsor'));
  assert.ok(denied.reasons.includes('decision_forum_not_verified'));
  assert.equal(denied.receipt, null);
});

test('independent ethics review validates HLC ordering notification boundaries and no-AI operation', async () => {
  const { evaluateIndependentEthicsReview } = await loadIndependentEthicsReview();
  const sameTickReady = evaluateIndependentEthicsReview({
    ...ethicsReviewInput(),
    ethicsReview: {
      ...ethicsReviewInput().ethicsReview,
      approvedAtHlc: { physicalMs: 1810000000000, logical: 0 },
      effectiveAtHlc: { physicalMs: 1810000000000, logical: 1 },
    },
    approvedMaterials: ethicsReviewInput().approvedMaterials.map((item) =>
      item.status === 'approved'
        ? { ...item, approvedAtHlc: { physicalMs: 1810000000000, logical: 0 } }
        : item,
    ),
    reviewGovernance: {
      ...ethicsReviewInput().reviewGovernance,
      aiAssisted: false,
      aiFinalAuthority: false,
    },
  });

  assert.equal(sameTickReady.decision, 'permitted');
  assert.equal(sameTickReady.ethicsReview.aiAssisted, false);

  const malformed = evaluateIndependentEthicsReview({
    ...ethicsReviewInput(),
    ethicsReview: {
      ...ethicsReviewInput().ethicsReview,
      effectiveAtHlc: { physicalMs: 1809000000000, logical: 0 },
    },
    requiredNotifications: ethicsReviewInput().requiredNotifications.map((item) =>
      item.audience === 'cro'
        ? { ...item, deliveredAtHlc: { physicalMs: 1808999999999, logical: 0 }, metadataOnly: false }
        : item,
    ),
  });

  assert.equal(malformed.decision, 'denied');
  assert.ok(malformed.reasons.includes('effective_before_approval'));
  assert.ok(malformed.reasons.includes('notification_before_effective:cro'));
  assert.ok(malformed.reasons.includes('notification_metadata_boundary_invalid:cro'));
});

test('independent ethics review rejects raw review content protected data and secrets before receipts', async () => {
  const { evaluateIndependentEthicsReview, ProtectedContentError } = await loadIndependentEthicsReview();

  assert.throws(
    () =>
      evaluateIndependentEthicsReview({
        ...ethicsReviewInput(),
        rawIrbLetter: 'source document body must not be stored in the receipt',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateIndependentEthicsReview({
        ...ethicsReviewInput(),
        reviewerContactEmail: 'reviewer@example.invalid',
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateIndependentEthicsReview({
        ...ethicsReviewInput(),
        integrationSecret: 'ethics-portal-token',
      }),
    ProtectedContentError,
  );
});
