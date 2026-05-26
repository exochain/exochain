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

async function loadWorkforceProfileReadiness() {
  try {
    return await import('../src/workforce-profile-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica workforce-profile-readiness module must exist and load: ${error.message}`);
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
const CUSTODY_DIGEST = 'abababababababababababababababababababababababababababababababab';
const AUTHORITY_HASH = 'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0';

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function baseInput() {
  return {
    requestId: 'workforce-profile-readiness-alpha',
    tenantId: 'tenant-site-alpha',
    siteId: 'site-alpha',
    checkedAtHlc: { physicalMs: 1790500000000, logical: 12 },
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['workforce_profile_review', 'govern'],
      authorityChainHash: AUTHORITY_HASH,
    },
    staffProfile: {
      profileId: 'staff-profile-crc-alpha',
      staffIdHash: DIGEST_A,
      actorDid: 'did:exo:crc-alpha',
      tenantId: 'tenant-site-alpha',
      siteId: 'site-alpha',
      role: 'clinical_research_coordinator',
      titleHash: DIGEST_B,
      departmentHash: DIGEST_C,
      employmentStatus: 'active',
      contractStatus: 'active',
      startAtHlc: { physicalMs: 1786000000000, logical: 0 },
      endAtHlc: null,
      accessRightRefs: ['access-consent-docs', 'access-source-metadata'],
      systemPrivilegeRefs: ['priv-econsent-metadata-write'],
      conflictDisclosureStatus: 'clear',
      recusalStatus: 'not_recused',
      exochainIdentityRefHash: DIGEST_D,
    },
    skillMixReview: {
      status: 'approved',
      staffingAdequate: true,
      reviewedByHuman: true,
      requiredRoles: ['clinical_research_coordinator', 'principal_investigator', 'quality_manager'],
      assignedRoleCounts: [
        { role: 'clinical_research_coordinator', requiredCount: 2, assignedCount: 2 },
        { role: 'principal_investigator', requiredCount: 1, assignedCount: 1 },
        { role: 'quality_manager', requiredCount: 1, assignedCount: 1 },
      ],
      evidenceHash: DIGEST_E,
      reviewedAtHlc: { physicalMs: 1790400000000, logical: 0 },
    },
    orientationIntegration: {
      status: 'complete',
      verifiedByHuman: true,
      completedAtHlc: { physicalMs: 1790100000000, logical: 0 },
      evidenceHash: DIGEST_F,
      topics: [
        'access_methods',
        'concern_reporting',
        'innovation_participation',
        'policies',
        'procedures',
        'rights',
        'role_expectations',
      ],
    },
    performanceReview: {
      status: 'current',
      reviewedByHuman: true,
      lastReviewAtHlc: { physicalMs: 1790200000000, logical: 0 },
      nextReviewDueHlc: { physicalMs: 1794000000000, logical: 0 },
      evidenceHash: DIGEST_1,
      developmentPlanHash: DIGEST_2,
      qualityCultureReviewed: true,
    },
    leadershipDevelopment: {
      required: true,
      status: 'complete',
      reviewedByHuman: true,
      evidenceHash: DIGEST_3,
      successionPlanHash: DIGEST_B,
      riskCqiCommunicationCovered: true,
    },
    wellbeingSafeguards: {
      status: 'active',
      reviewedByHuman: true,
      riskAssessmentHash: DIGEST_C,
      noBlameMechanismHash: DIGEST_D,
      complaintMechanismHash: DIGEST_E,
      communicationEvidenceHash: DIGEST_F,
      confidentialConcernRouteActive: true,
      reviewedAtHlc: { physicalMs: 1790300000000, logical: 0 },
    },
    peopleCenteredCulture: {
      reviewedByHuman: true,
      evidenceHash: DIGEST_1,
      domains: [
        'ethics',
        'inclusivity',
        'knowledge_sharing',
        'problem_solving',
        'societal_responsibility',
        'teamwork',
      ],
    },
    humanGovernance: {
      verified: true,
      approvedByDid: 'did:exo:site-executive-alpha',
      decisionForumReceiptId: 'df-workforce-profile-alpha',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
    },
    aiAssistance: { used: true, finalAuthority: false, recommendationHash: DIGEST_2 },
    custodyDigest: CUSTODY_DIGEST,
  };
}

test('workforce profile readiness creates deterministic inactive metadata receipts', async () => {
  const { evaluateWorkforceProfileReadiness } = await loadWorkforceProfileReadiness();
  const input = baseInput();

  const readyA = evaluateWorkforceProfileReadiness(input);
  const readyB = evaluateWorkforceProfileReadiness({
    ...input,
    staffProfile: {
      ...input.staffProfile,
      accessRightRefs: [...input.staffProfile.accessRightRefs].reverse(),
      systemPrivilegeRefs: [...input.staffProfile.systemPrivilegeRefs].reverse(),
    },
    skillMixReview: {
      ...input.skillMixReview,
      requiredRoles: [...input.skillMixReview.requiredRoles].reverse(),
      assignedRoleCounts: [...input.skillMixReview.assignedRoleCounts].reverse(),
    },
    orientationIntegration: {
      ...input.orientationIntegration,
      topics: [...input.orientationIntegration.topics].reverse(),
    },
    peopleCenteredCulture: {
      ...input.peopleCenteredCulture,
      domains: [...input.peopleCenteredCulture.domains].reverse(),
    },
  });

  assert.equal(readyA.decision, 'permitted');
  assert.equal(readyA.failClosed, false);
  assert.deepEqual(readyA.reasons, []);
  assert.deepEqual(readyA.gaps, []);
  assert.equal(readyA.trustState, 'inactive');
  assert.equal(readyA.exochainProductionClaim, false);
  assert.equal(readyA.workforceProfile.profileHash, readyB.workforceProfile.profileHash);
  assert.equal(readyA.receipt.receiptId, readyB.receipt.receiptId);
  assert.equal(readyA.receipt.anchorPayload.artifactType, 'workforce_profile_readiness');
  assert.equal(readyA.receipt.trustState, 'inactive');
  assert.deepEqual(readyA.workforceProfile.profileDomains, [
    'leadership_development',
    'orientation_integration',
    'people_centered_culture',
    'performance_review',
    'skill_mix',
    'wellbeing_safeguards',
  ]);
  assert.deepEqual(readyA.workforceProfile.requiredRoleCoverage, [
    'clinical_research_coordinator',
    'principal_investigator',
    'quality_manager',
  ]);
  assert.deepEqual(Object.keys(readyA.workforceProfile), [
    'schema',
    'profileReadinessId',
    'profileHash',
    'tenantId',
    'siteId',
    'profileId',
    'staffIdHash',
    'actorDid',
    'role',
    'employmentStatus',
    'checkedAtHlc',
    'profileDomains',
    'requiredRoleCoverage',
    'orientationTopics',
    'cultureDomains',
    'evidenceHashes',
    'authorityChainHash',
    'receiptId',
  ]);
  assert.doesNotMatch(JSON.stringify(readyA), /root-backed production authority/i);
});

test('workforce profile readiness fails closed for governance skill mix orientation performance and wellbeing gaps', async () => {
  const { evaluateWorkforceProfileReadiness } = await loadWorkforceProfileReadiness();
  const input = baseInput();

  const denied = evaluateWorkforceProfileReadiness({
    ...input,
    actor: { did: 'did:exo:quality-ai-alpha', kind: 'ai_agent' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read'],
      authorityChainHash: AUTHORITY_HASH,
    },
    staffProfile: {
      ...input.staffProfile,
      tenantId: 'tenant-site-beta',
      employmentStatus: 'terminated',
      recusalStatus: 'recused',
    },
    skillMixReview: {
      ...input.skillMixReview,
      status: 'draft',
      staffingAdequate: false,
      reviewedByHuman: false,
      requiredRoles: ['clinical_research_coordinator'],
      assignedRoleCounts: [{ role: 'clinical_research_coordinator', requiredCount: 2, assignedCount: 1 }],
      evidenceHash: '',
    },
    orientationIntegration: {
      ...input.orientationIntegration,
      status: 'incomplete',
      verifiedByHuman: false,
      topics: ['policies'],
    },
    performanceReview: {
      ...input.performanceReview,
      status: 'overdue',
      reviewedByHuman: false,
      nextReviewDueHlc: { physicalMs: 1790000000000, logical: 0 },
      evidenceHash: '',
      qualityCultureReviewed: false,
    },
    leadershipDevelopment: {
      required: true,
      status: 'not_started',
      reviewedByHuman: false,
      evidenceHash: '',
      successionPlanHash: '',
      riskCqiCommunicationCovered: false,
    },
    wellbeingSafeguards: {
      ...input.wellbeingSafeguards,
      status: 'inactive',
      reviewedByHuman: false,
      confidentialConcernRouteActive: false,
      riskAssessmentHash: '',
      noBlameMechanismHash: '',
      complaintMechanismHash: '',
      communicationEvidenceHash: '',
    },
    peopleCenteredCulture: {
      reviewedByHuman: false,
      evidenceHash: '',
      domains: ['ethics'],
    },
    humanGovernance: {
      verified: false,
      approvedByDid: '',
      decisionForumReceiptId: '',
      humanGate: { verified: false },
      quorum: { status: 'not_met' },
      openChallenge: true,
    },
    aiAssistance: { used: true, finalAuthority: true, recommendationHash: '' },
  });

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.workforceProfile, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('staff_profile_tenant_mismatch'));
  assert.ok(denied.reasons.includes('staff_profile_not_active'));
  assert.ok(denied.reasons.includes('staff_profile_recused'));
  assert.ok(denied.reasons.includes('skill_mix_review_not_approved'));
  assert.ok(denied.reasons.includes('skill_mix_human_review_absent'));
  assert.ok(denied.reasons.includes('skill_mix_staffing_inadequate'));
  assert.ok(denied.reasons.includes('skill_mix_role_shortfall:clinical_research_coordinator'));
  assert.ok(denied.reasons.includes('orientation_topic_missing:concern_reporting'));
  assert.ok(denied.reasons.includes('orientation_not_complete'));
  assert.ok(denied.reasons.includes('performance_review_overdue'));
  assert.ok(denied.reasons.includes('performance_quality_culture_absent'));
  assert.ok(denied.reasons.includes('leadership_development_incomplete'));
  assert.ok(denied.reasons.includes('leadership_succession_plan_absent'));
  assert.ok(denied.reasons.includes('wellbeing_confidential_route_absent'));
  assert.ok(denied.reasons.includes('wellbeing_no_blame_mechanism_absent'));
  assert.ok(denied.reasons.includes('culture_domain_missing:teamwork'));
  assert.ok(denied.reasons.includes('human_governance_unverified'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
  assert.deepEqual(
    denied.gaps.filter((gap) => gap.domain === 'orientation').map((gap) => gap.reason),
    [
      'orientation_topic_missing:access_methods',
      'orientation_topic_missing:concern_reporting',
      'orientation_topic_missing:innovation_participation',
      'orientation_topic_missing:procedures',
      'orientation_topic_missing:rights',
      'orientation_topic_missing:role_expectations',
    ],
  );
});

test('workforce profile readiness rejects direct staff identifiers protected content and unsafe clocks', async () => {
  const { evaluateWorkforceProfileReadiness } = await loadWorkforceProfileReadiness();
  const input = baseInput();

  assert.throws(
    () =>
      evaluateWorkforceProfileReadiness({
        ...input,
        staffProfile: {
          ...input.staffProfile,
          staffName: 'Alice Example',
        },
      }),
    /protected content/i,
  );

  assert.throws(
    () =>
      evaluateWorkforceProfileReadiness({
        ...input,
        wellbeingSafeguards: {
          ...input.wellbeingSafeguards,
          sourceDocumentBody: 'Participant Alice Example described a workplace concern',
        },
      }),
    /protected content/i,
  );

  const denied = evaluateWorkforceProfileReadiness({
    ...input,
    checkedAtHlc: { physicalMs: 1790000000000, logical: 0 },
    skillMixReview: {
      ...input.skillMixReview,
      reviewedAtHlc: { physicalMs: 1790500000000, logical: 13 },
    },
    orientationIntegration: {
      ...input.orientationIntegration,
      completedAtHlc: { physicalMs: 1790500000000, logical: 14 },
    },
    performanceReview: {
      ...input.performanceReview,
      lastReviewAtHlc: { physicalMs: 1790500000000, logical: 15 },
      nextReviewDueHlc: { physicalMs: 1790500000000, logical: 15 },
    },
    custodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('skill_mix_review_after_check'));
  assert.ok(denied.reasons.includes('orientation_completed_after_check'));
  assert.ok(denied.reasons.includes('performance_review_after_check'));
  assert.ok(denied.reasons.includes('performance_next_review_not_after_last'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
});

test('workforce profile readiness handles absent objects as fail closed denial states', async () => {
  const { evaluateWorkforceProfileReadiness } = await loadWorkforceProfileReadiness();

  const denied = evaluateWorkforceProfileReadiness({
    requestId: '',
    tenantId: '',
    siteId: '',
    checkedAtHlc: null,
    actor: { did: '', kind: 'human' },
    authority: null,
    staffProfile: null,
    skillMixReview: null,
    orientationIntegration: null,
    performanceReview: null,
    leadershipDevelopment: null,
    wellbeingSafeguards: null,
    peopleCenteredCulture: null,
    humanGovernance: null,
    aiAssistance: { used: false },
    custodyDigest: '',
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('request_id_absent'));
  assert.ok(denied.reasons.includes('tenant_absent'));
  assert.ok(denied.reasons.includes('site_absent'));
  assert.ok(denied.reasons.includes('actor_did_absent'));
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('staff_profile_absent'));
  assert.ok(denied.reasons.includes('skill_mix_review_absent'));
  assert.ok(denied.reasons.includes('orientation_absent'));
  assert.ok(denied.reasons.includes('performance_review_absent'));
  assert.ok(denied.reasons.includes('leadership_development_absent'));
  assert.ok(denied.reasons.includes('wellbeing_safeguards_absent'));
  assert.ok(denied.reasons.includes('people_centered_culture_absent'));
  assert.ok(denied.reasons.includes('human_governance_unverified'));
  assert.equal(denied.trustState, 'inactive');
  assert.equal(denied.exochainProductionClaim, false);
});
