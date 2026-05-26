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

async function loadProtocolFeasibility() {
  try {
    return await import('../src/protocol-feasibility.mjs');
  } catch (error) {
    assert.fail(`CyberMedica protocol feasibility module must exist and load: ${error.message}`);
  }
}

function domainReviews() {
  return [
    'participant_population',
    'recruitment',
    'staffing',
    'training',
    'facility',
    'equipment',
    'product_handling',
    'vendor',
    'financial',
    'insurance',
    'privacy_data',
    'reporting',
  ].map((domain, index) => ({
    domain,
    status: index === 1 || index === 7 ? 'feasible_with_conditions' : 'feasible',
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner-alpha`,
    evidenceHashes: [index % 2 === 0 ? DIGEST_A : DIGEST_B],
    controlRefs: [`CTRL-${domain.toUpperCase()}-001`],
    gapRefs: index === 1 ? ['GAP-RECRUITMENT-001'] : [],
    decisionRationaleHash: index % 2 === 0 ? DIGEST_C : DIGEST_D,
  }));
}

function protocolFeasibilityInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:site-quality-lead-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    feasibilityReview: {
      reviewRef: 'FEAS-PROTOCOL-2026-0003',
      protocolRef: 'protocol-cm-001',
      siteRef: 'site-alpha',
      sponsorRef: 'sponsor-alpha',
      croRef: 'cro-alpha',
      reviewType: 'protocol_feasibility',
      status: 'accepted_with_conditions',
      createdAtHlc: { physicalMs: 1791000000000, logical: 4 },
      qualityReviewRef: 'QR-PROTOCOL-FIT-0003',
      policyRefs: ['protocol-feasibility-procedure-v1', 'site-acceptance-governance-v1'],
    },
    intake: {
      protocolHash: DIGEST_A,
      investigatorBrochureHash: DIGEST_B,
      productInformationHash: DIGEST_C,
      sponsorQuestionnaireHash: DIGEST_D,
      clinicalTrialAgreementHash: DIGEST_E,
      regulatoryRequirementHashes: [DIGEST_A, DIGEST_E],
    },
    domainReviews: domainReviews(),
    aiFitReview: {
      completed: true,
      advisoryOnly: true,
      finalAuthority: false,
      reviewerRole: 'quality_manager',
      outputHash: DIGEST_B,
      evidenceUsedHashes: [DIGEST_A, DIGEST_C],
      unresolvedAssumptions: ['final_enrollment_cadence_pending_sponsor_confirmation'],
    },
    startupRiskAssessment: {
      assessmentRef: 'RISK-STARTUP-2026-0007',
      status: 'approved_with_conditions',
      artifactHash: DIGEST_D,
      receiptId: 'cmr_startup_risk_0007',
    },
    gaps: [
      {
        gapRef: 'GAP-RECRUITMENT-001',
        severity: 'major',
        status: 'accepted',
        ownerDid: 'did:exo:recruitment-lead-alpha',
        mitigationHash: DIGEST_E,
        targetResolutionHlc: { physicalMs: 1791200000000, logical: 1 },
      },
      {
        gapRef: 'GAP-VENDOR-001',
        severity: 'minor',
        status: 'closed',
        ownerDid: 'did:exo:vendor-manager-alpha',
        mitigationHash: DIGEST_A,
      },
    ],
    leadershipDecision: {
      decision: 'accept_with_conditions',
      decisionMakerDid: 'did:exo:principal-investigator-alpha',
      rationaleHash: DIGEST_C,
      acceptedConditionRefs: ['GAP-RECRUITMENT-001'],
      signedAtHlc: { physicalMs: 1791000005000, logical: 1 },
    },
    review: {
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-protocol-feasibility-0003',
        workflowReceiptId: 'df-workflow-protocol-feasibility-0003',
      },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      qualityReviewerDid: 'did:exo:quality-reviewer-alpha',
    },
    custodyDigest: DIGEST_E,
  };
}

test('protocol feasibility review creates deterministic inactive metadata receipt', async () => {
  const { evaluateProtocolFeasibilityReview } = await loadProtocolFeasibility();

  const resultA = evaluateProtocolFeasibilityReview(protocolFeasibilityInput());
  const resultB = evaluateProtocolFeasibilityReview({
    ...protocolFeasibilityInput(),
    intake: {
      ...protocolFeasibilityInput().intake,
      regulatoryRequirementHashes: [...protocolFeasibilityInput().intake.regulatoryRequirementHashes].reverse(),
    },
    domainReviews: [...protocolFeasibilityInput().domainReviews].reverse(),
    gaps: [...protocolFeasibilityInput().gaps].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.feasibilityReview.acceptanceStatus, 'accepted_with_conditions');
  assert.equal(resultA.feasibilityReview.exochainProductionClaim, false);
  assert.equal(resultA.feasibilityReview.trustState, 'inactive');
  assert.equal(resultA.feasibilityReview.aiFinalAuthority, false);
  assert.equal(resultA.feasibilityReview.domainReadinessBasisPoints, 10000);
  assert.deepEqual(resultA.feasibilityReview.coveredDomains, [
    'equipment',
    'facility',
    'financial',
    'insurance',
    'participant_population',
    'privacy_data',
    'product_handling',
    'recruitment',
    'reporting',
    'staffing',
    'training',
    'vendor',
  ]);
  assert.equal(resultA.feasibilityReview.openGapSummary.major, 1);
  assert.deepEqual(resultA.feasibilityReview.requiredEscalationRoles, [
    'decision_forum',
    'principal_investigator',
    'site_quality_lead',
  ]);
  assert.equal(resultA.feasibilityReview.reviewId, resultB.feasibilityReview.reviewId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'protocol_feasibility_review');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /source document|raw protocol|participant alice|patient/iu);
});

test('protocol feasibility fails closed for unresolved critical gaps and advisory AI defects', async () => {
  const { evaluateProtocolFeasibilityReview } = await loadProtocolFeasibility();
  const input = protocolFeasibilityInput();
  input.actor = { did: 'did:exo:ai-quality-reviewer-alpha', kind: 'ai_agent' };
  input.aiFitReview = {
    completed: false,
    advisoryOnly: false,
    finalAuthority: true,
    reviewerRole: '',
    outputHash: '',
    evidenceUsedHashes: ['not-a-hash'],
    unresolvedAssumptions: [],
  };
  input.domainReviews = input.domainReviews.filter((review) => review.domain !== 'privacy_data');
  input.gaps = [
    {
      gapRef: 'GAP-SAFETY-CRITICAL-001',
      severity: 'critical',
      status: 'open',
      ownerDid: '',
      mitigationHash: '',
    },
  ];

  const denied = evaluateProtocolFeasibilityReview(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_fit_review_incomplete'));
  assert.ok(denied.reasons.includes('ai_fit_review_must_be_advisory'));
  assert.ok(denied.reasons.includes('ai_fit_review_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('required_feasibility_domain_missing:privacy_data'));
  assert.ok(denied.reasons.includes('critical_gap_unresolved:GAP-SAFETY-CRITICAL-001'));
  assert.ok(denied.reasons.includes('gap_owner_absent:GAP-SAFETY-CRITICAL-001'));
  assert.ok(denied.reasons.includes('gap_mitigation_invalid:GAP-SAFETY-CRITICAL-001'));
  assert.equal(denied.feasibilityReview.acceptanceStatus, 'blocked');
  assert.equal(denied.feasibilityReview.openGapSummary.critical, 1);
});

test('protocol feasibility denies missing intake risk governance and human approval evidence', async () => {
  const { evaluateProtocolFeasibilityReview } = await loadProtocolFeasibility();
  const input = protocolFeasibilityInput();
  input.targetTenantId = 'tenant-site-beta';
  input.authority = { valid: true, revoked: false, expired: false, permissions: ['read'] };
  input.intake = {
    ...input.intake,
    protocolHash: 'bad',
    sponsorQuestionnaireHash: '',
    regulatoryRequirementHashes: [],
  };
  input.startupRiskAssessment = {
    assessmentRef: 'RISK-STARTUP-2026-0007',
    status: 'deferred',
    artifactHash: 'bad',
    receiptId: '',
  };
  input.leadershipDecision = {
    decision: 'defer',
    decisionMakerDid: '',
    rationaleHash: '',
    acceptedConditionRefs: [],
    signedAtHlc: { physicalMs: 1791000005000, logical: 1 },
  };
  input.review.decisionForum = {
    verified: false,
    state: 'pending',
    humanGate: { verified: false },
    quorum: { status: 'not_met' },
    openChallenge: true,
    decisionId: '',
    workflowReceiptId: '',
  };
  input.review.evidenceBundle = { complete: false, phiBoundaryAttested: false };

  const denied = evaluateProtocolFeasibilityReview(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('protocol_hash_invalid'));
  assert.ok(denied.reasons.includes('sponsor_questionnaire_hash_invalid'));
  assert.ok(denied.reasons.includes('regulatory_requirements_absent'));
  assert.ok(denied.reasons.includes('startup_risk_assessment_not_approved'));
  assert.ok(denied.reasons.includes('startup_risk_receipt_absent'));
  assert.ok(denied.reasons.includes('startup_risk_artifact_hash_invalid'));
  assert.ok(denied.reasons.includes('protocol_feasibility_deferred'));
  assert.ok(denied.reasons.includes('leadership_decision_maker_absent'));
  assert.ok(denied.reasons.includes('leadership_rationale_invalid'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
  assert.ok(denied.reasons.includes('evidence_bundle_incomplete'));
  assert.ok(denied.reasons.includes('phi_boundary_unattested'));
});

test('protocol feasibility rejects raw protocol text and protected content before receipt creation', async () => {
  const { evaluateProtocolFeasibilityReview } = await loadProtocolFeasibility();

  assert.throws(
    () =>
      evaluateProtocolFeasibilityReview({
        ...protocolFeasibilityInput(),
        intake: {
          ...protocolFeasibilityInput().intake,
          rawProtocolBody: 'Participant Alice Example source document text must not enter feasibility review.',
        },
      }),
    /protected content|raw protocol/i,
  );
});
