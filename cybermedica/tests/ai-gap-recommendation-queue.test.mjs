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

const REQUIRED_GAP_FAMILIES = [
  'consent_version_gap',
  'control_gap',
  'data_integrity_gap',
  'documentation_gap',
  'evidence_aging',
  'policy_procedure_gap',
  'protocol_amendment_gap',
  'safety_signal',
  'sponsor_expectation',
  'training_gap',
];

const ROUTE_TYPES = [
  'capa',
  'cqi',
  'decision_forum',
  'documentation_update',
  'drift_signal',
  'training_update',
];

async function loadAiGapQueue() {
  try {
    return await import('../src/ai-gap-recommendation-queue.mjs');
  } catch (error) {
    assert.fail(`CyberMedica AI gap recommendation queue module must exist and load: ${error.message}`);
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

function recommendationFor(gapFamily, index, overrides = {}) {
  const materialFamilies = new Set([
    'consent_version_gap',
    'data_integrity_gap',
    'protocol_amendment_gap',
    'safety_signal',
    'sponsor_expectation',
  ]);
  return {
    recommendationRef: `ai-gap-${gapFamily}`,
    gapFamily,
    sourceReviewRef: `ai-review-${gapFamily}`,
    sourceEvidenceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    controlRefs: [`control-${gapFamily}`],
    confidenceBasisPoints: materialFamilies.has(gapFamily) ? 8900 : 6100,
    riskLevel: materialFamilies.has(gapFamily) ? 'critical' : 'major',
    urgency: materialFamilies.has(gapFamily) ? 'urgent' : 'standard',
    participantSafetyImpact: ['consent_version_gap', 'protocol_amendment_gap', 'safety_signal'].includes(gapFamily),
    dataIntegrityImpact: gapFamily === 'data_integrity_gap',
    sponsorCroImpact: ['protocol_amendment_gap', 'sponsor_expectation'].includes(gapFamily),
    reviewable: true,
    advisoryOnly: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    detectedAtHlc: { physicalMs: 1801000100000, logical: index },
    ...overrides,
  };
}

function queueItemFor(recommendation, index, overrides = {}) {
  const material = recommendation.riskLevel === 'critical';
  const routeTypeByFamily = {
    consent_version_gap: 'decision_forum',
    control_gap: 'cqi',
    data_integrity_gap: 'capa',
    documentation_gap: 'documentation_update',
    evidence_aging: 'drift_signal',
    policy_procedure_gap: 'cqi',
    protocol_amendment_gap: 'decision_forum',
    safety_signal: 'capa',
    sponsor_expectation: 'decision_forum',
    training_gap: 'training_update',
  };
  return {
    queueItemRef: `queue-${recommendation.gapFamily}`,
    recommendationRef: recommendation.recommendationRef,
    ownerRoleRef: material ? 'quality_manager' : 'site_leader',
    priority: material ? 'critical' : 'standard',
    routeType: routeTypeByFamily[recommendation.gapFamily],
    requiredReviewRoleRefs: material
      ? ['quality_manager', 'principal_investigator']
      : ['quality_manager'],
    evidenceReviewHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6][index % 6],
    rationaleHash: [DIGEST_7, DIGEST_8, DIGEST_9, DIGEST_A, DIGEST_B, DIGEST_C][index % 6],
    triagedAtHlc: { physicalMs: 1801000200000, logical: index },
    dueAtHlc: { physicalMs: 1801100000000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function aiGapInput(overrides = {}) {
  const recommendations = REQUIRED_GAP_FAMILIES.map((gapFamily, index) =>
    recommendationFor(gapFamily, index),
  );
  const queueItems = recommendations.map((recommendation, index) =>
    queueItemFor(recommendation, index),
  );
  return mergeDeep(
    {
      tenantId: 'tenant-site-alpha',
      targetTenantId: 'tenant-site-alpha',
      actor: {
        did: 'did:exo:quality-manager-alpha',
        kind: 'human',
        roleRefs: ['quality_manager'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['ai_gap_triage', 'drift_manage'],
        authorityChainHash: DIGEST_A,
      },
      queuePolicy: {
        policyRef: 'ai-gap-policy-alpha',
        policyHash: DIGEST_B,
        status: 'active',
        requiredGapFamilies: REQUIRED_GAP_FAMILIES,
        allowedRouteTypes: ROUTE_TYPES,
        materialDecisionForumRequired: true,
        humanReviewRequired: true,
        metadataOnly: true,
        protectedContentExcluded: true,
        evaluatedAtHlc: { physicalMs: 1801000000000, logical: 0 },
      },
      queueCycle: {
        cycleRef: 'ai-gap-cycle-alpha',
        openedAtHlc: { physicalMs: 1801000050000, logical: 0 },
        recommendationsCapturedAtHlc: { physicalMs: 1801000100000, logical: 0 },
        triagedAtHlc: { physicalMs: 1801000200000, logical: 0 },
        routedAtHlc: { physicalMs: 1801000300000, logical: 0 },
        humanReviewedAtHlc: { physicalMs: 1801000400000, logical: 0 },
        auditRecordedAtHlc: { physicalMs: 1801000500000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
        exochainProductionClaim: false,
      },
      aiReviewManifest: {
        manifestRef: 'ai-gap-manifest-alpha',
        modelRefHash: DIGEST_C,
        promptHash: DIGEST_D,
        inputManifestHash: DIGEST_E,
        outputManifestHash: DIGEST_F,
        noRawPromptOrOutput: true,
        advisoryOnly: true,
        finalAuthority: false,
        metadataOnly: true,
        protectedContentExcluded: true,
        reviewedAtHlc: { physicalMs: 1801000090000, logical: 0 },
      },
      recommendations,
      queueItems,
      downstreamRouting: {
        routingRef: 'ai-gap-routing-alpha',
        routeTypes: ROUTE_TYPES,
        cqiQueueHash: DIGEST_1,
        capaRefs: ['capa-ai-gap-safety'],
        documentationUpdateRefs: ['doc-ai-gap-manual'],
        driftSignalRefs: recommendations.map((recommendation) => `drift-${recommendation.recommendationRef}`),
        trainingUpdateRefs: ['training-ai-gap-alpha'],
        decisionForumMatterRefs: [
          'df-ai-gap-consent',
          'df-ai-gap-protocol',
          'df-ai-gap-sponsor',
        ],
        routedAtHlc: { physicalMs: 1801000300000, logical: 1 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      humanReview: {
        reviewerDid: 'did:exo:quality-reviewer-alpha',
        reviewerRoleRefs: ['quality_manager', 'principal_investigator'],
        decision: 'ai_gap_queue_ready',
        decisionHash: DIGEST_2,
        finalAuthority: 'human',
        aiFinalAuthority: false,
        noProductionTrustClaim: true,
        reviewedAtHlc: { physicalMs: 1801000400000, logical: 1 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      auditRecord: {
        auditRecordRef: 'ai-gap-audit-alpha',
        auditRecordHash: DIGEST_3,
        receiptRecordedAtHlc: { physicalMs: 1801000500000, logical: 0 },
        metadataOnly: true,
        includesProtectedContent: false,
      },
      custodyDigest: DIGEST_4,
    },
    overrides,
  );
}

test('AI gap recommendation queue creates deterministic inactive reviewable actions', async () => {
  const { evaluateAiGapRecommendationQueue } = await loadAiGapQueue();
  const input = aiGapInput();

  const first = evaluateAiGapRecommendationQueue(input);
  const second = evaluateAiGapRecommendationQueue(input);

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first, second);
  assert.equal(first.aiGapQueue.trustState, 'inactive');
  assert.equal(first.aiGapQueue.exochainProductionClaim, false);
  assert.equal(first.aiGapQueue.metadataOnly, true);
  assert.equal(first.aiGapQueue.containsProtectedContent, false);
  assert.deepEqual(first.aiGapQueue.gapFamilies, REQUIRED_GAP_FAMILIES);
  assert.deepEqual(first.aiGapQueue.routeTypes, ROUTE_TYPES);
  assert.equal(first.aiGapQueue.recommendationCount, REQUIRED_GAP_FAMILIES.length);
  assert.equal(first.aiGapQueue.queueItemCount, REQUIRED_GAP_FAMILIES.length);
  assert.deepEqual(first.aiGapQueue.materialRecommendationRefs, [
    'ai-gap-consent_version_gap',
    'ai-gap-data_integrity_gap',
    'ai-gap-protocol_amendment_gap',
    'ai-gap-safety_signal',
    'ai-gap-sponsor_expectation',
  ]);
  assert.equal(first.aiGapQueue.decisionForumRequired, true);
  assert.equal(first.aiGapQueue.decisionForumInvoked, true);
  assert.equal(first.aiGapQueue.aiFinalAuthority, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'ai_gap_recommendation_queue');
});

test('AI gap recommendation queue fails closed for missing family coverage and routing gaps', async () => {
  const { evaluateAiGapRecommendationQueue } = await loadAiGapQueue();
  const recommendations = aiGapInput().recommendations.filter(
    (recommendation) => recommendation.gapFamily !== 'training_gap',
  );
  const queueItems = aiGapInput().queueItems.filter(
    (item) => item.recommendationRef !== 'ai-gap-documentation_gap',
  );

  const result = evaluateAiGapRecommendationQueue(
    aiGapInput({
      queueCycle: { exochainProductionClaim: true },
      recommendations,
      queueItems,
      downstreamRouting: {
        decisionForumMatterRefs: [],
        routeTypes: ['cqi'],
        driftSignalRefs: [],
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.aiGapQueue, null);
  assert.equal(result.receipt, null);
  assert.match(result.reasons.join('\n'), /gap_family_missing:training_gap/);
  assert.match(result.reasons.join('\n'), /queue_item_absent:ai-gap-documentation_gap/);
  assert.match(result.reasons.join('\n'), /material_decision_forum_absent/);
  assert.match(result.reasons.join('\n'), /route_type_missing:decision_forum/);
  assert.match(result.reasons.join('\n'), /drift_signal_route_absent/);
  assert.match(result.reasons.join('\n'), /production_trust_claim_forbidden/);
});

test('AI gap recommendation queue keeps AI advisory and requires human review', async () => {
  const { evaluateAiGapRecommendationQueue } = await loadAiGapQueue();

  const result = evaluateAiGapRecommendationQueue(
    aiGapInput({
      aiReviewManifest: {
        finalAuthority: true,
        advisoryOnly: false,
      },
      recommendations: [
        recommendationFor('control_gap', 0, {
          confidenceBasisPoints: 10001,
          advisoryOnly: false,
          reviewable: false,
        }),
      ],
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        reviewerRoleRefs: [],
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('\n'), /ai_final_authority_forbidden/);
  assert.match(result.reasons.join('\n'), /ai_review_manifest_advisory_boundary_invalid/);
  assert.match(result.reasons.join('\n'), /recommendation_confidence_invalid:ai-gap-control_gap/);
  assert.match(result.reasons.join('\n'), /recommendation_advisory_boundary_invalid:ai-gap-control_gap/);
  assert.match(result.reasons.join('\n'), /recommendation_reviewable_absent:ai-gap-control_gap/);
  assert.match(result.reasons.join('\n'), /human_review_roles_absent/);
  assert.match(result.reasons.join('\n'), /human_final_authority_absent/);
});

test('AI gap recommendation queue validates HLC ordering and same-tick logical clocks', async () => {
  const { evaluateAiGapRecommendationQueue } = await loadAiGapQueue();

  const sameTick = evaluateAiGapRecommendationQueue(
    aiGapInput({
      queueCycle: {
        openedAtHlc: { physicalMs: 1801000050000, logical: 0 },
        recommendationsCapturedAtHlc: { physicalMs: 1801000050000, logical: 1 },
        triagedAtHlc: { physicalMs: 1801000050000, logical: 2 },
        routedAtHlc: { physicalMs: 1801000050000, logical: 3 },
        humanReviewedAtHlc: { physicalMs: 1801000050000, logical: 4 },
        auditRecordedAtHlc: { physicalMs: 1801000050000, logical: 5 },
      },
      aiReviewManifest: {
        reviewedAtHlc: { physicalMs: 1801000050000, logical: 0 },
      },
      recommendations: REQUIRED_GAP_FAMILIES.map((gapFamily, index) =>
        recommendationFor(gapFamily, index, {
          detectedAtHlc: { physicalMs: 1801000050000, logical: index + 1 },
        }),
      ),
      queueItems: REQUIRED_GAP_FAMILIES.map((gapFamily, index) =>
        queueItemFor(recommendationFor(gapFamily, index), index, {
          triagedAtHlc: { physicalMs: 1801000050000, logical: 2 + index },
          dueAtHlc: { physicalMs: 1801000050000, logical: 30 + index },
        }),
      ),
      downstreamRouting: {
        routedAtHlc: { physicalMs: 1801000050000, logical: 3 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1801000050000, logical: 4 },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1801000050000, logical: 5 },
      },
    }),
  );

  assert.equal(sameTick.decision, 'permitted');

  const invalid = evaluateAiGapRecommendationQueue(
    aiGapInput({
      queueCycle: {
        triagedAtHlc: { physicalMs: 1801000040000, logical: 0 },
      },
      downstreamRouting: {
        routedAtHlc: { physicalMs: 1801000190000, logical: 0 },
      },
    }),
  );

  assert.equal(invalid.decision, 'denied');
  assert.match(invalid.reasons.join('\n'), /queue_cycle_triagedAtHlc_before_recommendationsCapturedAtHlc/);
  assert.match(invalid.reasons.join('\n'), /routing_before_cycle_routing_step/);
});

test('AI gap recommendation queue handles absent collections as denial states', async () => {
  const { evaluateAiGapRecommendationQueue } = await loadAiGapQueue();

  const result = evaluateAiGapRecommendationQueue(
    aiGapInput({
      queueCycle: {
        openedAtHlc: { physicalMs: 1801000050000, logical: -1 },
      },
      recommendations: null,
      queueItems: null,
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('\n'), /queue_cycle_openedAtHlc_invalid/);
  assert.match(result.reasons.join('\n'), /recommendations_absent/);
  assert.match(result.reasons.join('\n'), /queue_items_absent/);
});

test('AI gap recommendation queue rejects raw recommendations protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateAiGapRecommendationQueue } = await loadAiGapQueue();

  const inert = evaluateAiGapRecommendationQueue(
    aiGapInput({
      nested: [{ rawRecommendation: false }, { apiKey: null }, { rawAiOutput: [null, false] }],
    }),
  );
  assert.equal(inert.decision, 'permitted');

  assert.throws(
    () =>
      evaluateAiGapRecommendationQueue(
        aiGapInput({
          recommendations: [
            recommendationFor('evidence_aging', 0, {
              rawRecommendation: 'source review content must stay outside receipts',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateAiGapRecommendationQueue(
        aiGapInput({
          aiReviewManifest: {
            rawAiOutput: {
              outputHash: DIGEST_A,
            },
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateAiGapRecommendationQueue(
        aiGapInput({
          downstreamRouting: {
            apiKey: DIGEST_B,
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateAiGapRecommendationQueue(
        aiGapInput({
          nested: [{ token: 7 }],
        }),
      ),
    ProtectedContentError,
  );
});
