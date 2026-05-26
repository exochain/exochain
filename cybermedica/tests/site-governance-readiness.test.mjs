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

async function loadSiteGovernanceReadiness() {
  try {
    return await import('../src/site-governance-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica site-governance-readiness module must exist and load: ${error.message}`);
  }
}

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
const CUSTODY_DIGEST = 'abababababababababababababababababababababababababababababababab';
const AUTHORITY_HASH = 'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0';

function baseInput() {
  return {
    requestId: 'site-governance-readiness-alpha',
    tenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    checkedAtHlc: { physicalMs: 1790500000000, logical: 15 },
    actor: { did: 'did:exo:site-leader-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['site_governance_review', 'govern'],
      authorityChainHash: AUTHORITY_HASH,
    },
    qualityPolicy: {
      policyRef: 'QPOL-SITE-ALPHA-2026',
      version: 'v3',
      status: 'approved',
      policyHash: DIGEST_A,
      leadershipApproval: {
        approvedByDid: 'did:exo:site-executive-alpha',
        approvedAtHlc: { physicalMs: 1789000000000, logical: 0 },
        approvalEvidenceHash: DIGEST_B,
      },
      annualReview: {
        status: 'current',
        reviewedAtHlc: { physicalMs: 1789600000000, logical: 0 },
        nextReviewDueHlc: { physicalMs: 1800000000000, logical: 0 },
        evidenceHash: DIGEST_C,
      },
      staffCommunicationEvidenceHash: DIGEST_D,
      strategyLinkHash: DIGEST_E,
      evidenceHash: DIGEST_F,
    },
    missionVisionValues: {
      statementRef: 'MVV-SITE-ALPHA-2026',
      version: 'v2',
      status: 'approved',
      missionHash: DIGEST_B,
      visionHash: DIGEST_C,
      valuesHash: DIGEST_D,
      stakeholderConsultationHash: DIGEST_E,
      leadershipApproval: {
        approvedByDid: 'did:exo:site-executive-alpha',
        approvedAtHlc: { physicalMs: 1789100000000, logical: 0 },
        approvalEvidenceHash: DIGEST_F,
      },
      reviewCadence: {
        status: 'current',
        reviewedAtHlc: { physicalMs: 1789700000000, logical: 0 },
        nextReviewDueHlc: { physicalMs: 1800100000000, logical: 0 },
        evidenceHash: DIGEST_1,
      },
      valueDomains: ['innovation_improvement', 'ethical', 'quality_oriented', 'people_centered'],
      communicationEvidenceHash: DIGEST_2,
    },
    siteStrategy: {
      strategyRef: 'STRAT-SITE-ALPHA-2026',
      version: 'v4',
      status: 'approved',
      strategyHash: DIGEST_3,
      coveredDomains: [
        'budgets',
        'mission_vision_values_realization',
        'organizational_structure',
        'quality_management_scope',
        'resource_needs',
        'stakeholder_expectations',
        'supporting_policies',
        'technology_needs',
      ],
      annualReview: {
        status: 'current',
        reviewedAtHlc: { physicalMs: 1789800000000, logical: 0 },
        nextReviewDueHlc: { physicalMs: 1800200000000, logical: 0 },
        evidenceHash: DIGEST_4,
      },
      lessonsLearnedHash: DIGEST_A,
      resourcePlanningHash: DIGEST_B,
      qualityObjectiveRefs: ['QOBJ-SITE-ALPHA-001', 'QOBJ-SITE-ALPHA-002'],
      supportingPolicyRefs: ['QPOL-SITE-ALPHA-2026', 'ETH-SITE-ALPHA-2026'],
    },
    communicationGovernance: {
      planRef: 'COMM-SITE-ALPHA-2026',
      version: 'v5',
      status: 'approved',
      planHash: DIGEST_C,
      internalAudienceRefs: ['staff', 'site_leadership', 'quality_team', 'investigators'],
      externalAudienceRefs: ['auditors', 'cro', 'iec_irb', 'monitors', 'regulators', 'sponsors', 'stakeholders'],
      topicRefs: [
        'ae_sae_lessons_learned',
        'deviations',
        'feedback',
        'protocol_requirements',
        'quality_improvement_results',
        'regulatory_changes',
        'safety_governance_updates',
        'strategy_updates',
      ],
      channelPolicyRefs: ['CHAN-POL-SECURE-PORTAL', 'CHAN-POL-MEETING-MINUTES'],
      escalationOwnerDid: 'did:exo:quality-manager-alpha',
      escalationPathHash: DIGEST_D,
      stakeholderFeedbackHash: DIGEST_E,
      reviewedByHuman: true,
      reviewedAtHlc: { physicalMs: 1789900000000, logical: 0 },
      nextReviewDueHlc: { physicalMs: 1800300000000, logical: 0 },
    },
    humanGovernance: {
      verified: true,
      approvedByDid: 'did:exo:site-executive-alpha',
      decisionForumReceiptId: 'df-site-governance-alpha',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    aiAssistance: { used: true, finalAuthority: false, recommendationHash: DIGEST_F },
    custodyDigest: CUSTODY_DIGEST,
  };
}

test('site governance readiness creates deterministic inactive policy strategy and communication receipts', async () => {
  const { evaluateSiteGovernanceReadiness } = await loadSiteGovernanceReadiness();
  const input = baseInput();

  const readyA = evaluateSiteGovernanceReadiness(input);
  const readyB = evaluateSiteGovernanceReadiness({
    ...input,
    missionVisionValues: {
      ...input.missionVisionValues,
      valueDomains: [...input.missionVisionValues.valueDomains].reverse(),
    },
    siteStrategy: {
      ...input.siteStrategy,
      coveredDomains: [...input.siteStrategy.coveredDomains].reverse(),
      qualityObjectiveRefs: [...input.siteStrategy.qualityObjectiveRefs].reverse(),
      supportingPolicyRefs: [...input.siteStrategy.supportingPolicyRefs].reverse(),
    },
    communicationGovernance: {
      ...input.communicationGovernance,
      internalAudienceRefs: [...input.communicationGovernance.internalAudienceRefs].reverse(),
      externalAudienceRefs: [...input.communicationGovernance.externalAudienceRefs].reverse(),
      topicRefs: [...input.communicationGovernance.topicRefs].reverse(),
      channelPolicyRefs: [...input.communicationGovernance.channelPolicyRefs].reverse(),
    },
  });

  assert.equal(readyA.decision, 'permitted');
  assert.equal(readyA.failClosed, false);
  assert.deepEqual(readyA.reasons, []);
  assert.deepEqual(readyA.gaps, []);
  assert.equal(readyA.trustState, 'inactive');
  assert.equal(readyA.exochainProductionClaim, false);
  assert.equal(readyA.siteGovernance.governanceHash, readyB.siteGovernance.governanceHash);
  assert.equal(readyA.receipt.receiptId, readyB.receipt.receiptId);
  assert.equal(readyA.receipt.anchorPayload.artifactType, 'site_governance_readiness');
  assert.equal(readyA.receipt.trustState, 'inactive');
  assert.deepEqual(readyA.siteGovernance.readinessDomains, [
    'communication_governance',
    'mission_vision_values',
    'quality_policy',
    'site_strategy',
  ]);
  assert.deepEqual(readyA.siteGovernance.communicationAudiences.external, [
    'auditors',
    'cro',
    'iec_irb',
    'monitors',
    'regulators',
    'sponsors',
    'stakeholders',
  ]);
  assert.deepEqual(Object.keys(readyA.siteGovernance), [
    'schema',
    'readinessId',
    'governanceHash',
    'tenantId',
    'siteId',
    'checkedAtHlc',
    'readinessDomains',
    'qualityPolicyRef',
    'missionVisionValuesRef',
    'strategyRef',
    'communicationPlanRef',
    'strategyDomains',
    'valueDomains',
    'communicationAudiences',
    'communicationTopics',
    'evidenceHashes',
    'authorityChainHash',
    'receiptId',
  ]);
  assert.doesNotMatch(JSON.stringify(readyA), /root-backed production authority/i);
});

test('site governance readiness fails closed for leadership strategy communication and authority defects', async () => {
  const { evaluateSiteGovernanceReadiness } = await loadSiteGovernanceReadiness();
  const input = baseInput();

  const denied = evaluateSiteGovernanceReadiness({
    ...input,
    actor: { did: 'did:exo:site-governance-ai-alpha', kind: 'ai_agent' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: AUTHORITY_HASH,
    },
    qualityPolicy: {
      ...input.qualityPolicy,
      status: 'draft',
      staffCommunicationEvidenceHash: '',
      strategyLinkHash: '',
    },
    missionVisionValues: {
      ...input.missionVisionValues,
      status: 'draft',
      stakeholderConsultationHash: '',
      valueDomains: ['ethical'],
      leadershipApproval: {
        ...input.missionVisionValues.leadershipApproval,
        approvedByDid: '',
      },
    },
    siteStrategy: {
      ...input.siteStrategy,
      status: 'retired',
      coveredDomains: ['budgets'],
      qualityObjectiveRefs: [],
      lessonsLearnedHash: '',
      resourcePlanningHash: '',
    },
    communicationGovernance: {
      ...input.communicationGovernance,
      status: 'draft',
      internalAudienceRefs: ['staff'],
      externalAudienceRefs: ['sponsors'],
      topicRefs: ['strategy_updates'],
      reviewedByHuman: false,
      escalationOwnerDid: '',
    },
    humanGovernance: {
      verified: false,
      approvedByDid: '',
      decisionForumReceiptId: '',
      humanGate: { verified: false },
      quorum: { status: 'not_met' },
      openChallenge: true,
    },
    aiAssistance: { used: true, finalAuthority: true, recommendationHash: DIGEST_F },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.siteGovernance, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('quality_policy_not_approved'));
  assert.ok(denied.reasons.includes('quality_policy_staff_communication_absent'));
  assert.ok(denied.reasons.includes('quality_policy_strategy_link_absent'));
  assert.ok(denied.reasons.includes('mission_vision_values_not_approved'));
  assert.ok(denied.reasons.includes('mvv_stakeholder_consultation_absent'));
  assert.ok(denied.reasons.includes('mvv_leadership_approver_absent'));
  assert.ok(denied.reasons.includes('strategy_not_approved'));
  assert.ok(denied.reasons.includes('strategy_quality_objectives_absent'));
  assert.ok(denied.reasons.includes('communication_governance_not_approved'));
  assert.ok(denied.reasons.includes('communication_human_review_absent'));
  assert.ok(denied.reasons.includes('communication_escalation_owner_absent'));
  assert.ok(denied.reasons.includes('human_governance_unverified'));
  assert.ok(denied.gaps.some((gap) => gap.reason === 'strategy_domain_missing:resource_needs'));
  assert.ok(denied.gaps.some((gap) => gap.reason === 'communication_external_audience_missing:regulators'));
  assert.ok(denied.gaps.some((gap) => gap.reason === 'communication_topic_missing:deviations'));
});

test('site governance readiness rejects overdue reviews future approvals and malformed evidence', async () => {
  const { evaluateSiteGovernanceReadiness } = await loadSiteGovernanceReadiness();
  const input = baseInput();

  const denied = evaluateSiteGovernanceReadiness({
    ...input,
    qualityPolicy: {
      ...input.qualityPolicy,
      leadershipApproval: {
        ...input.qualityPolicy.leadershipApproval,
        approvedAtHlc: { physicalMs: 1790600000000, logical: 0 },
        approvalEvidenceHash: 'not-a-digest',
      },
      annualReview: {
        ...input.qualityPolicy.annualReview,
        reviewedAtHlc: { physicalMs: 1790600000000, logical: 0 },
        nextReviewDueHlc: { physicalMs: 1790000000000, logical: 0 },
      },
    },
    missionVisionValues: {
      ...input.missionVisionValues,
      reviewCadence: {
        ...input.missionVisionValues.reviewCadence,
        nextReviewDueHlc: { physicalMs: 1790100000000, logical: 0 },
      },
    },
    siteStrategy: {
      ...input.siteStrategy,
      annualReview: {
        ...input.siteStrategy.annualReview,
        reviewedAtHlc: { physicalMs: 1790700000000, logical: 0 },
      },
    },
    communicationGovernance: {
      ...input.communicationGovernance,
      reviewedAtHlc: { physicalMs: 1790800000000, logical: 0 },
      nextReviewDueHlc: { physicalMs: 1790100000000, logical: 0 },
      planHash: '',
    },
    custodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('quality_policy_approval_after_check'));
  assert.ok(denied.reasons.includes('quality_policy_approval_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('quality_policy_review_after_check'));
  assert.ok(denied.reasons.includes('quality_policy_review_overdue'));
  assert.ok(denied.reasons.includes('mvv_review_overdue'));
  assert.ok(denied.reasons.includes('strategy_review_after_check'));
  assert.ok(denied.reasons.includes('communication_review_after_check'));
  assert.ok(denied.reasons.includes('communication_review_overdue'));
  assert.ok(denied.reasons.includes('communication_plan_hash_invalid'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
});

test('site governance readiness rejects raw site narratives protected content and secrets before receipts', async () => {
  const { evaluateSiteGovernanceReadiness, ProtectedContentError } = await loadSiteGovernanceReadiness();

  assert.throws(
    () => evaluateSiteGovernanceReadiness({ ...baseInput(), rawMissionStatement: 'Patient Alice attends site alpha.' }),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateSiteGovernanceReadiness({ ...baseInput(), communicationBody: 'Direct sponsor confidential update.' }),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateSiteGovernanceReadiness({ ...baseInput(), adapterSecret: 'sk-production-secret' }),
    ProtectedContentError,
  );
});

test('site governance readiness handles absent objects as fail-closed denial states', async () => {
  const { evaluateSiteGovernanceReadiness } = await loadSiteGovernanceReadiness();

  const denied = evaluateSiteGovernanceReadiness({
    requestId: 'site-governance-absent-objects',
    tenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    checkedAtHlc: { physicalMs: 1790500000000, logical: 15 },
    actor: { did: 'did:exo:site-leader-alpha', kind: 'human' },
    authority: { valid: false, revoked: false, expired: false, permissions: [] },
    custodyDigest: CUSTODY_DIGEST,
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('quality_policy_absent'));
  assert.ok(denied.reasons.includes('mission_vision_values_absent'));
  assert.ok(denied.reasons.includes('site_strategy_absent'));
  assert.ok(denied.reasons.includes('communication_governance_absent'));
  assert.ok(denied.reasons.includes('human_governance_unverified'));
});
