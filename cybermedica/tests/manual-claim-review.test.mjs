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
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_3 = '3333333333333333333333333333333333333333333333333333333333333333';
const DIGEST_4 = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_5 = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_6 = '6666666666666666666666666666666666666666666666666666666666666666';
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';

const REQUIRED_CLAIM_FAMILIES = ['accreditation', 'clinical', 'compliance', 'regulatory'];
const REQUIRED_REVIEWER_ROLES = ['legal', 'quality', 'regulatory'];

async function loadManualClaimReview() {
  try {
    return await import('../src/manual-claim-review.mjs');
  } catch (error) {
    assert.fail(`CyberMedica manual claim review module must exist and load: ${error.message}`);
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

function claimFor(family, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D];
  return {
    claimRef: `claim-${family}`,
    family,
    sectionRef: `manual-section-${family}`,
    claimHash: hashes[index],
    evidenceHash: [DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2][index],
    riskLevel: 'high',
    publicationDisposition: 'approved_for_publication',
    requiresClaimReview: true,
    classifiedAtHlc: { physicalMs: 1800020000000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function claimRegister(overrides = {}) {
  const claims = REQUIRED_CLAIM_FAMILIES.map((family, index) => claimFor(family, index));
  return {
    registerRef: 'manual-claim-register-alpha',
    manualSetHash: DIGEST_3,
    manualIndexHash: DIGEST_4,
    documentationPublicationReceiptHash: DIGEST_5,
    documentationRunbookReceiptHash: DIGEST_6,
    noRawClaimText: true,
    classifiedAtHlc: { physicalMs: 1800019900000, logical: 0 },
    claims,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function reviewFor(claim, reviewerRole, index, overrides = {}) {
  return {
    reviewRef: `review-${claim.family}-${reviewerRole}`,
    claimRef: claim.claimRef,
    reviewerRole,
    reviewerDid: `did:exo:${reviewerRole}-manual-reviewer-alpha`,
    decision: 'approved',
    reviewHash: [DIGEST_7, DIGEST_8, DIGEST_9][index],
    reviewedAtHlc: { physicalMs: 1800020100000 + index, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function reviewsForClaims(claims = claimRegister().claims) {
  return claims.flatMap((claim) => REQUIRED_REVIEWER_ROLES.map((role, index) => reviewFor(claim, role, index)));
}

function reviewInput(overrides = {}) {
  const register = claimRegister();
  return mergeDeep(
    {
      tenantId: 'tenant-site-alpha',
      targetTenantId: 'tenant-site-alpha',
      actor: {
        did: 'did:exo:manual-claims-owner-alpha',
        kind: 'human',
        roleRefs: ['quality_manager', 'documentation_owner'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['manual_claim_review', 'govern'],
        authorityChainHash: DIGEST_A,
      },
      claimReviewPolicy: {
        policyRef: 'manual-claim-review-policy-alpha',
        policyHash: DIGEST_B,
        status: 'active',
        requiredClaimFamilies: REQUIRED_CLAIM_FAMILIES,
        requiredReviewerRoles: REQUIRED_REVIEWER_ROLES,
        highRiskReviewRequired: true,
        qualityReviewRequired: true,
        legalReviewRequired: true,
        regulatoryReviewRequired: true,
        aiAssistanceAdvisoryOnly: true,
        metadataOnly: true,
        protectedContentExcluded: true,
        evaluatedAtHlc: { physicalMs: 1800019800000, logical: 0 },
      },
      claimRegister: register,
      reviews: reviewsForClaims(register.claims),
      publicationGate: {
        gateRef: 'manual-publication-gate-alpha',
        documentationPublicationReceiptHash: DIGEST_5,
        manualExportBoundaryHash: DIGEST_C,
        approvedClaimRegisterHash: DIGEST_D,
        publicationPackageRef: 'documentation-publication-package-alpha',
        highRiskSectionsHeld: false,
        productionTrustClaim: false,
        gatedAtHlc: { physicalMs: 1800020300000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      aiAssistant: {
        used: true,
        assistantRef: 'manual-claim-review-ai-alpha',
        recommendationHash: DIGEST_E,
        limitationHashes: [DIGEST_F],
        advisoryOnly: true,
        finalAuthority: false,
        humanReviewed: true,
        reviewedAtHlc: { physicalMs: 1800020200000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      humanReview: {
        reviewerDid: 'did:exo:quality-owner-alpha',
        reviewerRoleRefs: ['legal', 'quality', 'regulatory'],
        decision: 'manual_claims_approved_for_publication',
        decisionHash: DIGEST_1,
        finalAuthority: 'human',
        aiFinalAuthority: false,
        noProductionTrustClaim: true,
        reviewedAtHlc: { physicalMs: 1800020250000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      validationEvidence: {
        commandRefs: ['node --test tests/manual-claim-review.test.mjs', 'npm run quality'],
        commandsPassed: true,
        sourceGuardPassed: true,
        noExochainSourceModified: true,
        recordedAtHlc: { physicalMs: 1800020400000, logical: 0 },
        metadataOnly: true,
      },
      custodyDigest: DIGEST_2,
    },
    overrides,
  );
}

test('manual claim review creates deterministic inactive DOC-009 publication receipts', async () => {
  const { evaluateManualClaimReview } = await loadManualClaimReview();
  const input = reviewInput();

  const first = evaluateManualClaimReview(input);
  const second = evaluateManualClaimReview(input);

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first, second);
  assert.equal(first.manualClaimReview.trustState, 'inactive');
  assert.equal(first.manualClaimReview.exochainProductionClaim, false);
  assert.equal(first.manualClaimReview.metadataOnly, true);
  assert.equal(first.manualClaimReview.containsProtectedContent, false);
  assert.equal(first.manualClaimReview.doc009Satisfied, true);
  assert.equal(first.manualClaimReview.publicationEligible, true);
  assert.deepEqual(first.manualClaimReview.claimFamilies, REQUIRED_CLAIM_FAMILIES);
  assert.deepEqual(first.manualClaimReview.requiredReviewerRoles, REQUIRED_REVIEWER_ROLES);
  assert.deepEqual(first.manualClaimReview.reviewRoles, REQUIRED_REVIEWER_ROLES);
  assert.equal(first.manualClaimReview.claimCount, 4);
  assert.deepEqual(first.manualClaimReview.approvedClaimRefs, [
    'claim-accreditation',
    'claim-clinical',
    'claim-compliance',
    'claim-regulatory',
  ]);
  assert.deepEqual(first.manualClaimReview.heldClaimRefs, []);
  assert.equal(first.receipt.anchorPayload.artifactType, 'manual_claim_review');
  assert.equal(first.receipt.anchorPayload.classification, 'metadata_only_manual_claim_review');
});

test('manual claim review fails closed for missing claim families and required reviewers', async () => {
  const { evaluateManualClaimReview } = await loadManualClaimReview();
  const claims = claimRegister().claims.filter((claim) => claim.family !== 'clinical');
  const reviews = reviewsForClaims(claims).filter(
    (review) => !(review.claimRef === 'claim-regulatory' && review.reviewerRole === 'legal'),
  );

  const result = evaluateManualClaimReview(
    reviewInput({
      claimRegister: { claims },
      reviews,
      publicationGate: { highRiskSectionsHeld: true },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.match(result.reasons.join('\n'), /claim_family_missing:clinical/u);
  assert.match(result.reasons.join('\n'), /claim_required_review_missing:claim-regulatory:legal/u);
  assert.match(result.reasons.join('\n'), /high_risk_sections_held/u);
});

test('manual claim review denies AI authority unapproved claims and unsafe trust claims', async () => {
  const { evaluateManualClaimReview } = await loadManualClaimReview();
  const claims = claimRegister().claims.map((claim) =>
    claim.family === 'compliance' ? { ...claim, publicationDisposition: 'hold_for_revision' } : claim,
  );
  const reviews = reviewsForClaims(claims).map((review) =>
    review.claimRef === 'claim-compliance' && review.reviewerRole === 'regulatory'
      ? { ...review, decision: 'requires_revision' }
      : review,
  );

  const result = evaluateManualClaimReview(
    reviewInput({
      actor: { kind: 'ai_agent' },
      claimRegister: { claims },
      reviews,
      publicationGate: { productionTrustClaim: true },
      aiAssistant: {
        advisoryOnly: false,
        finalAuthority: true,
        humanReviewed: false,
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('\n'), /ai_final_authority_forbidden/u);
  assert.match(result.reasons.join('\n'), /claim_not_approved_for_publication:claim-compliance/u);
  assert.match(result.reasons.join('\n'), /claim_review_not_approved:claim-compliance:regulatory/u);
  assert.match(result.reasons.join('\n'), /production_trust_claim_forbidden/u);
  assert.match(result.reasons.join('\n'), /ai_assistant_not_advisory_only/u);
  assert.match(result.reasons.join('\n'), /human_final_authority_missing/u);
});

test('manual claim review validates HLC ordering and supports no AI operation', async () => {
  const { evaluateManualClaimReview } = await loadManualClaimReview();

  const noAi = evaluateManualClaimReview(reviewInput({ aiAssistant: { used: false } }));
  assert.equal(noAi.decision, 'permitted');
  assert.equal(noAi.manualClaimReview.aiAssistanceUsed, false);

  const inertRawMarkers = evaluateManualClaimReview(
    reviewInput({
      claimRegister: {
        rawManualClaimContent: {},
        rawRegulatoryClaimText: false,
      },
    }),
  );
  assert.equal(inertRawMarkers.decision, 'permitted');

  const result = evaluateManualClaimReview(
    reviewInput({
      claimReviewPolicy: { evaluatedAtHlc: { physicalMs: 1800020000001, logical: 0 } },
      reviews: reviewsForClaims().map((review) =>
        review.claimRef === 'claim-accreditation' && review.reviewerRole === 'quality'
          ? { ...review, reviewedAtHlc: { physicalMs: 1800019999999, logical: 0 } }
          : review,
      ),
      aiAssistant: { reviewedAtHlc: { physicalMs: 1800020299999, logical: 0 } },
      humanReview: { reviewedAtHlc: { physicalMs: 1800020199999, logical: 0 } },
      validationEvidence: { recordedAtHlc: { physicalMs: 1800020399999, logical: -1 } },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('\n'), /policy_review_after_claim_classification/u);
  assert.match(result.reasons.join('\n'), /claim_review_before_classification:claim-accreditation:quality/u);
  assert.match(result.reasons.join('\n'), /ai_review_not_before_human_review/u);
  assert.match(result.reasons.join('\n'), /human_review_before_ai_review/u);
  assert.match(result.reasons.join('\n'), /validation_record_time_invalid/u);
});

test('manual claim review handles absent inputs as denial states', async () => {
  const { evaluateManualClaimReview } = await loadManualClaimReview();
  const result = evaluateManualClaimReview({});

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('\n'), /tenant_absent/u);
  assert.match(result.reasons.join('\n'), /claim_review_policy_ref_absent/u);
  assert.match(result.reasons.join('\n'), /claim_register_ref_absent/u);
  assert.match(result.reasons.join('\n'), /publication_gate_ref_absent/u);
  assert.match(result.reasons.join('\n'), /human_review_reviewer_absent/u);
});

test('manual claim review rejects raw claim content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateManualClaimReview } = await loadManualClaimReview();

  assert.throws(
    () => evaluateManualClaimReview(reviewInput({ claimRegister: { rawRegulatoryClaimText: 'FDA compliant copy' } })),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateManualClaimReview(reviewInput({ claimRegister: { claims: [{ ...claimFor('clinical', 1), reviewerEmail: 'qa@example.com' }] } })),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateManualClaimReview(reviewInput({ aiAssistant: { apiKey: DIGEST_A } })),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateManualClaimReview(reviewInput({ aiAssistant: { apiKey: 7 } })),
    ProtectedContentError,
  );
});
