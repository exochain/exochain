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

const REQUIRED_CONTESTATION_FAMILIES = [
  'advisory_label',
  'evidence_basis',
  'human_reviewer',
  'limitation_record',
  'reason_code',
  'standing_policy',
  'timely_filing',
];

async function loadAiRecommendationContestation() {
  try {
    return await import('../src/ai-recommendation-contestation.mjs');
  } catch (error) {
    assert.fail(`CyberMedica AI recommendation contestation module must exist and load: ${error.message}`);
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

function contestationInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'ai_recommendation_reviewer'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['contest_ai_recommendation', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    recommendation: {
      recommendationRef: 'ai-rec-launch-gap-alpha',
      sourceWorkflowRef: 'ai-gap-recommendation-queue',
      sourceWorkflowReceiptHash: DIGEST_B,
      recommendationHash: DIGEST_C,
      modelRef: 'cm-advisory-quality-reviewer',
      modelVersionHash: DIGEST_D,
      evidenceBundleHash: DIGEST_E,
      reasoningSummaryHash: DIGEST_F,
      limitationHashes: [DIGEST_A, DIGEST_B],
      confidenceBasisPoints: 7600,
      advisoryOnly: true,
      finalAuthority: false,
      humanDispositionRequired: true,
      contestable: true,
      generatedAtHlc: { physicalMs: 1810000000000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    standingPolicy: {
      policyRef: 'ai-recommendation-contestation-policy-alpha',
      policyHash: DIGEST_D,
      status: 'active',
      allowedFilerRoles: [
        'clinical_research_coordinator',
        'decision_forum_member',
        'principal_investigator',
        'quality_manager',
        'site_leader',
        'sponsor_monitor',
      ],
      allowedReasonCodes: [
        'conflict_or_recusal_gap',
        'data_integrity_concern',
        'evidence_gap',
        'participant_safety_concern',
        'privacy_boundary_concern',
      ],
      requiredContestabilityFamilies: REQUIRED_CONTESTATION_FAMILIES,
      challengeWindowClosesAtHlc: { physicalMs: 1810086400000, logical: 0 },
      independentReviewRequired: true,
      decisionForumRequiredForMaterial: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    contestation: {
      contestRef: 'ai-contest-launch-gap-alpha',
      filerDid: 'did:exo:principal-investigator-alpha',
      filerRoleRef: 'principal_investigator',
      reasonCode: 'evidence_gap',
      reasonHash: DIGEST_E,
      requestedOutcome: 'decision_forum_review',
      materialImpact: true,
      affectsParticipantSafety: true,
      affectsDataIntegrity: false,
      affectsPrivacy: false,
      filedAtHlc: { physicalMs: 1810003600000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    independentReview: {
      reviewerDid: 'did:exo:independent-quality-reviewer-alpha',
      reviewerRoleRef: 'independent_quality_reviewer',
      independentFromAiOwner: true,
      reviewEvidenceHash: DIGEST_F,
      decision: 'routed_to_decision_forum',
      decisionRationaleHash: DIGEST_A,
      reviewedAtHlc: { physicalMs: 1810007200000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    decisionForum: {
      requiredForMaterial: true,
      matterRef: 'df-ai-recommendation-contest-alpha',
      routingReceiptHash: DIGEST_B,
      state: 'routed',
      humanGate: { verified: true },
      quorum: { status: 'not_required_until_review' },
      openChallenge: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanDisposition: {
      finalAuthority: 'human',
      aiFinalAuthorityRejected: true,
      disposition: 'human_governance_review_pending',
      dispositionHash: DIGEST_C,
      recordedAtHlc: { physicalMs: 1810010800000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    custodyDigest: DIGEST_F,
  };
  return mergeDeep(base, overrides);
}

test('AI recommendation contestation creates deterministic inactive metadata receipts', async () => {
  const { evaluateAiRecommendationContestation } = await loadAiRecommendationContestation();

  const first = evaluateAiRecommendationContestation(contestationInput());
  const second = evaluateAiRecommendationContestation(
    contestationInput({
      recommendation: {
        limitationHashes: [DIGEST_B, DIGEST_A],
      },
      standingPolicy: {
        allowedFilerRoles: [
          'sponsor_monitor',
          'site_leader',
          'quality_manager',
          'principal_investigator',
          'decision_forum_member',
          'clinical_research_coordinator',
        ],
        allowedReasonCodes: [
          'privacy_boundary_concern',
          'participant_safety_concern',
          'evidence_gap',
          'data_integrity_concern',
          'conflict_or_recusal_gap',
        ],
        requiredContestabilityFamilies: [...REQUIRED_CONTESTATION_FAMILIES].reverse(),
      },
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.contestationRecord.status, 'routed_to_decision_forum');
  assert.equal(first.contestationRecord.trustState, 'inactive');
  assert.equal(first.contestationRecord.exochainProductionClaim, false);
  assert.equal(first.contestationRecord.aiFinalAuthorityRejected, true);
  assert.equal(first.contestationRecord.materialImpact, true);
  assert.deepEqual(first.contestationRecord.contestabilityFamilies, REQUIRED_CONTESTATION_FAMILIES);
  assert.deepEqual(first.contestationRecord.allowedReasonCodes, [
    'conflict_or_recusal_gap',
    'data_integrity_concern',
    'evidence_gap',
    'participant_safety_concern',
    'privacy_boundary_concern',
  ]);
  assert.equal(first.contestationRecord.recordHash, second.contestationRecord.recordHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.anchorPayload.artifactType, 'ai_recommendation_contestation');
  assert.doesNotMatch(JSON.stringify(first), /raw recommendation|hidden conclusion|participant alice|source document/iu);
});

test('AI recommendation contestation fails closed for non-contestable AI output and material routing defects', async () => {
  const { evaluateAiRecommendationContestation } = await loadAiRecommendationContestation();

  const result = evaluateAiRecommendationContestation(
    contestationInput({
      recommendation: {
        advisoryOnly: false,
        finalAuthority: true,
        humanDispositionRequired: false,
        contestable: false,
        productionTrustClaim: true,
      },
      standingPolicy: {
        status: 'inactive',
        allowedReasonCodes: ['evidence_gap'],
        requiredContestabilityFamilies: REQUIRED_CONTESTATION_FAMILIES.filter((family) => family !== 'human_reviewer'),
        independentReviewRequired: false,
        decisionForumRequiredForMaterial: false,
      },
      contestation: {
        reasonCode: 'unsupported_reason',
        materialImpact: true,
        affectsParticipantSafety: true,
      },
      independentReview: {
        independentFromAiOwner: false,
        decision: 'accepted_for_review',
        reviewEvidenceHash: '',
      },
      decisionForum: {
        matterRef: '',
        routingReceiptHash: '',
        state: 'not_routed',
        humanGate: { verified: false },
        metadataOnly: false,
      },
      humanDisposition: {
        finalAuthority: 'ai',
        aiFinalAuthorityRejected: false,
        dispositionHash: '',
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.contestationRecord, null);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('recommendation_must_be_advisory'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('recommendation_contestability_absent'));
  assert.ok(result.reasons.includes('recommendation_production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('standing_policy_not_active'));
  assert.ok(result.reasons.includes('contestability_family_missing:human_reviewer'));
  assert.ok(result.reasons.includes('contest_reason_not_allowed'));
  assert.ok(result.reasons.includes('independent_review_policy_absent'));
  assert.ok(result.reasons.includes('independent_review_conflict'));
  assert.ok(result.reasons.includes('independent_review_evidence_hash_invalid'));
  assert.ok(result.reasons.includes('material_contestation_decision_forum_policy_absent'));
  assert.ok(result.reasons.includes('material_contestation_decision_forum_matter_absent'));
  assert.ok(result.reasons.includes('material_contestation_human_gate_unverified'));
  assert.ok(result.reasons.includes('human_disposition_ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_disposition_hash_invalid'));
});

test('AI recommendation contestation validates standing HLC order and authority', async () => {
  const { evaluateAiRecommendationContestation } = await loadAiRecommendationContestation();

  const result = evaluateAiRecommendationContestation(
    contestationInput({
      actor: { kind: 'ai_agent' },
      authority: {
        valid: false,
        permissions: ['read'],
        authorityChainHash: 'not-a-digest',
      },
      standingPolicy: {
        allowedFilerRoles: ['quality_manager'],
        challengeWindowClosesAtHlc: { physicalMs: 1810001000000, logical: 0 },
      },
      contestation: {
        filerRoleRef: 'principal_investigator',
        filedAtHlc: { physicalMs: 1810003600000, logical: 0 },
      },
      independentReview: {
        reviewedAtHlc: { physicalMs: 1810000100000, logical: 0 },
      },
      humanDisposition: {
        recordedAtHlc: { physicalMs: 1810000050000, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.match(result.reasons.join('|'), /ai_final_authority_forbidden/);
  assert.match(result.reasons.join('|'), /ai_contestation_authority_missing/);
  assert.match(result.reasons.join('|'), /authority_chain_hash_invalid/);
  assert.match(result.reasons.join('|'), /filer_role_not_allowed/);
  assert.match(result.reasons.join('|'), /contest_filed_after_challenge_window/);
  assert.match(result.reasons.join('|'), /independent_review_before_contestation/);
  assert.match(result.reasons.join('|'), /human_disposition_before_independent_review/);
});

test('AI recommendation contestation rejects raw recommendation content protected content and secrets before receipts', async () => {
  const { evaluateAiRecommendationContestation, ProtectedContentError } = await loadAiRecommendationContestation();

  assert.throws(
    () =>
      evaluateAiRecommendationContestation(
        contestationInput({
          recommendation: {
            rawRecommendation: 'Hidden conclusion about Participant Alice from source document text.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateAiRecommendationContestation(
        contestationInput({
          independentReview: {
            apiKey: 'cm-ai-contest-secret',
          },
        }),
      ),
    ProtectedContentError,
  );
});

test('AI recommendation contestation exports required families as immutable contract metadata', async () => {
  const { REQUIRED_AI_RECOMMENDATION_CONTESTATION_FAMILIES } = await loadAiRecommendationContestation();

  assert.deepEqual(REQUIRED_AI_RECOMMENDATION_CONTESTATION_FAMILIES, REQUIRED_CONTESTATION_FAMILIES);
  assert.throws(() => REQUIRED_AI_RECOMMENDATION_CONTESTATION_FAMILIES.push('late_mutation'), TypeError);
});
