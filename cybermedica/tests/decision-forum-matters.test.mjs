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

async function loadDecisionForumMatters() {
  try {
    return await import('../src/decision-forum-matters.mjs');
  } catch (error) {
    assert.fail(`CyberMedica Decision Forum matter module must exist and load: ${error.message}`);
  }
}

function decisionForumMatterInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:decision-forum-chair-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['govern', 'write'],
      authorityChainHash: DIGEST_A,
    },
    matter: {
      matterRef: 'DF-PROTOCOL-LAUNCH-CM-001',
      titleHash: DIGEST_B,
      decisionType: 'protocol_launch',
      decisionClass: 'strategic',
      material: true,
      siteRef: 'site-alpha',
      protocolRef: 'protocol-cm-001',
      createdAtHlc: { physicalMs: 1791600000000, logical: 0 },
      reviewOpenedAtHlc: { physicalMs: 1791600100000, logical: 0 },
      deliberationOpenedAtHlc: { physicalMs: 1791600200000, logical: 0 },
      voteOpenedAtHlc: { physicalMs: 1791600300000, logical: 0 },
      closedAtHlc: { physicalMs: 1791600400000, logical: 0 },
      expirationAtHlc: { physicalMs: 1794200000000, logical: 0 },
    },
    evidenceBundle: {
      complete: true,
      phiBoundaryAttested: true,
      bundleHash: DIGEST_C,
      sourceArtifactHashes: [DIGEST_A, DIGEST_B, DIGEST_C],
      controlRefs: ['CM-QMS-CTRL-001', 'CM-QMS-CTRL-017'],
      authorityChainHash: DIGEST_A,
      consentRefs: ['consent-policy-alpha-v1'],
      riskAssessmentRef: 'risk-assessment-cm-001',
      alternativesHash: DIGEST_D,
      noActionRationaleHash: DIGEST_E,
      humanReviewEvidenceHash: DIGEST_F,
    },
    aiAnalysis: {
      attached: true,
      advisoryOnly: true,
      finalAuthority: false,
      promptHash: DIGEST_B,
      outputHash: DIGEST_C,
      evidenceUsedHashes: [DIGEST_A, DIGEST_D],
      confidenceBasisPoints: 7600,
      limitsHash: DIGEST_E,
      unresolvedAssumptionHashes: [DIGEST_F],
      recommendedHumanReviewerRole: 'quality_governance',
    },
    participants: [
      {
        did: 'did:exo:principal-investigator-alpha',
        role: 'principal_investigator',
        votingEligible: true,
        disclosureStatus: 'clear',
        recused: false,
      },
      {
        did: 'did:exo:site-quality-manager-alpha',
        role: 'quality_manager',
        votingEligible: true,
        disclosureStatus: 'managed',
        recused: false,
      },
      {
        did: 'did:exo:sponsor-liaison-alpha',
        role: 'sponsor_liaison',
        votingEligible: false,
        disclosureStatus: 'active',
        recused: true,
        recusalRef: 'REC-SPONSOR-0001',
      },
    ],
    conflictReview: {
      verified: true,
      reviewRef: 'COI-REVIEW-0001',
      coverageBasisPoints: 10000,
      activeConflictDids: ['did:exo:sponsor-liaison-alpha'],
      recusedParticipantDids: ['did:exo:sponsor-liaison-alpha'],
      unresolvedConflictDids: [],
      evidenceHash: DIGEST_D,
    },
    quorum: {
      verified: true,
      status: 'met',
      policyHash: DIGEST_E,
      requiredVotingRoles: ['principal_investigator', 'quality_manager'],
      approvalsNeeded: 2,
    },
    votes: [
      {
        voterDid: 'did:exo:principal-investigator-alpha',
        role: 'principal_investigator',
        vote: 'approve',
        rationaleHash: DIGEST_A,
        signatureHash: DIGEST_B,
        castAtHlc: { physicalMs: 1791600310000, logical: 0 },
      },
      {
        voterDid: 'did:exo:site-quality-manager-alpha',
        role: 'quality_manager',
        vote: 'approve_with_conditions',
        rationaleHash: DIGEST_C,
        signatureHash: DIGEST_D,
        castAtHlc: { physicalMs: 1791600320000, logical: 0 },
      },
      {
        voterDid: 'did:exo:sponsor-liaison-alpha',
        role: 'sponsor_liaison',
        vote: 'abstain',
        rationaleHash: DIGEST_E,
        signatureHash: DIGEST_F,
        castAtHlc: { physicalMs: 1791600330000, logical: 0 },
      },
    ],
    disposition: {
      outcome: 'approve_with_conditions',
      rationaleHash: DIGEST_A,
      minorityViewHashes: [DIGEST_B],
      dissentHashes: [DIGEST_C],
      conditionHashes: [DIGEST_D],
      followUpActions: [
        {
          actionRef: 'FOLLOWUP-LAUNCH-CONDITION-001',
          ownerDid: 'did:exo:site-quality-manager-alpha',
          dueAtHlc: { physicalMs: 1792200000000, logical: 0 },
          evidenceHash: DIGEST_E,
        },
      ],
      capaRef: 'CAPA-READINESS-0001',
      sponsorNotificationRequired: true,
      sponsorNotificationEvidenceHash: DIGEST_F,
      irbIecNotificationRequired: true,
      irbIecNotificationEvidenceHash: DIGEST_A,
      regulatoryNotificationRequired: false,
      regulatoryNotificationRationaleHash: DIGEST_B,
    },
    contestation: { open: false, status: 'none', contestRefs: [] },
    receipts: {
      workflowReceiptId: 'df-workflow-protocol-launch-0001',
      auditEntryHash: DIGEST_C,
    },
    custodyDigest: DIGEST_F,
  };
}

test('Decision Forum matter lifecycle creates deterministic inactive closure receipt', async () => {
  const { evaluateDecisionForumMatter } = await loadDecisionForumMatters();

  const resultA = evaluateDecisionForumMatter(decisionForumMatterInput());
  const resultB = evaluateDecisionForumMatter({
    ...decisionForumMatterInput(),
    evidenceBundle: {
      ...decisionForumMatterInput().evidenceBundle,
      sourceArtifactHashes: [...decisionForumMatterInput().evidenceBundle.sourceArtifactHashes].reverse(),
      controlRefs: [...decisionForumMatterInput().evidenceBundle.controlRefs].reverse(),
    },
    aiAnalysis: {
      ...decisionForumMatterInput().aiAnalysis,
      evidenceUsedHashes: [...decisionForumMatterInput().aiAnalysis.evidenceUsedHashes].reverse(),
      unresolvedAssumptionHashes: [...decisionForumMatterInput().aiAnalysis.unresolvedAssumptionHashes].reverse(),
    },
    participants: [...decisionForumMatterInput().participants].reverse(),
    votes: [...decisionForumMatterInput().votes].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.matterRecord.status, 'closed');
  assert.equal(resultA.matterRecord.trustState, 'inactive');
  assert.equal(resultA.matterRecord.exochainProductionClaim, false);
  assert.equal(resultA.matterRecord.aiFinalAuthority, false);
  assert.deepEqual(resultA.matterRecord.lifecycleSteps, [
    'created',
    'reviewed',
    'deliberated',
    'voted',
    'closed',
    'receipt_prepared',
  ]);
  assert.deepEqual(resultA.matterRecord.requiredVotingRoles, ['principal_investigator', 'quality_manager']);
  assert.deepEqual(resultA.matterRecord.voteSummary, {
    abstain: 1,
    approve: 1,
    approve_with_conditions: 1,
    defer: 0,
    emergency_authorize: 0,
    escalate: 0,
    reject: 0,
    revoke: 0,
  });
  assert.equal(resultA.matterRecord.followUpActionCount, 1);
  assert.equal(resultA.matterRecord.notificationRequirementCount, 2);
  assert.equal(resultA.matterRecord.matterId, resultB.matterRecord.matterId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'decision_forum_matter');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.dashboardItem.requiredQuorumStatus, 'met');
  assert.equal(resultA.dashboardItem.openChallenge, false);
  assert.deepEqual(resultA.dashboardItem.conditions, [DIGEST_D]);
  assert.doesNotMatch(JSON.stringify(resultA), /participant alice|raw deliberation|patient|source document/iu);
});

test('Decision Forum matter fails closed for missing review deliberation vote rationale and governance evidence', async () => {
  const { evaluateDecisionForumMatter } = await loadDecisionForumMatters();
  const input = decisionForumMatterInput();
  input.actor = { did: 'did:exo:ai-forum-agent-alpha', kind: 'ai_agent' };
  input.authority = {
    valid: true,
    revoked: false,
    expired: false,
    permissions: ['read'],
    authorityChainHash: 'bad',
  };
  input.evidenceBundle = {
    complete: false,
    phiBoundaryAttested: false,
    bundleHash: '',
    sourceArtifactHashes: [],
    controlRefs: [],
  };
  input.aiAnalysis = {
    attached: true,
    advisoryOnly: false,
    finalAuthority: true,
    promptHash: 'bad',
    outputHash: '',
    evidenceUsedHashes: ['bad'],
    confidenceBasisPoints: 10001,
  };
  input.participants = input.participants.filter(
    (participant) => participant.did !== 'did:exo:site-quality-manager-alpha',
  );
  input.conflictReview = {
    verified: false,
    coverageBasisPoints: 7500,
    activeConflictDids: ['did:exo:sponsor-liaison-alpha'],
    recusedParticipantDids: [],
    unresolvedConflictDids: ['did:exo:sponsor-liaison-alpha'],
    evidenceHash: 'bad',
  };
  input.quorum = {
    verified: false,
    status: 'not_met',
    policyHash: '',
    requiredVotingRoles: ['principal_investigator', 'quality_manager'],
    approvalsNeeded: 2,
  };
  input.votes = [input.votes[0]];
  input.disposition = {
    outcome: 'approve_with_conditions',
    rationaleHash: '',
    minorityViewHashes: ['bad'],
    dissentHashes: ['bad'],
    conditionHashes: [],
    followUpActions: [],
    capaRef: '',
    sponsorNotificationRequired: true,
    sponsorNotificationEvidenceHash: '',
    irbIecNotificationRequired: true,
    irbIecNotificationEvidenceHash: '',
    regulatoryNotificationRequired: true,
    regulatoryNotificationEvidenceHash: '',
  };
  input.receipts = { workflowReceiptId: '', auditEntryHash: 'bad' };

  const denied = evaluateDecisionForumMatter(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.matterRecord.status, 'blocked');
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('decision_forum_authority_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('evidence_bundle_incomplete'));
  assert.ok(denied.reasons.includes('phi_boundary_unattested'));
  assert.ok(denied.reasons.includes('evidence_bundle_hash_invalid'));
  assert.ok(denied.reasons.includes('control_refs_absent'));
  assert.ok(denied.reasons.includes('ai_analysis_must_be_advisory'));
  assert.ok(denied.reasons.includes('ai_analysis_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_analysis_confidence_invalid'));
  assert.ok(denied.reasons.includes('conflict_review_unverified'));
  assert.ok(denied.reasons.includes('conflict_review_incomplete'));
  assert.ok(denied.reasons.includes('unresolved_conflict:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('quorum_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('vote_missing_for_role:quality_manager'));
  assert.ok(denied.reasons.includes('approval_threshold_not_met'));
  assert.ok(denied.reasons.includes('decision_rationale_hash_invalid'));
  assert.ok(denied.reasons.includes('conditions_required_for_outcome'));
  assert.ok(denied.reasons.includes('follow_up_required_for_conditions'));
  assert.ok(denied.reasons.includes('sponsor_notification_evidence_missing'));
  assert.ok(denied.reasons.includes('irb_iec_notification_evidence_missing'));
  assert.ok(denied.reasons.includes('regulatory_notification_evidence_missing'));
  assert.ok(denied.reasons.includes('workflow_receipt_absent'));
  assert.ok(denied.reasons.includes('audit_entry_hash_invalid'));
});

test('Decision Forum matter supports contestation receipts without claiming final closure', async () => {
  const { evaluateDecisionForumMatter } = await loadDecisionForumMatters();
  const input = decisionForumMatterInput();
  input.disposition = {
    outcome: 'contest',
    rationaleHash: DIGEST_A,
    minorityViewHashes: [],
    dissentHashes: [DIGEST_B],
    conditionHashes: [],
    followUpActions: [],
    sponsorNotificationRequired: false,
    sponsorNotificationRationaleHash: DIGEST_C,
    irbIecNotificationRequired: false,
    irbIecNotificationRationaleHash: DIGEST_D,
    regulatoryNotificationRequired: false,
    regulatoryNotificationRationaleHash: DIGEST_E,
  };
  input.contestation = {
    open: true,
    status: 'filed',
    contestRefs: ['CONTEST-DF-0001'],
    filedByDid: 'did:exo:principal-investigator-alpha',
    standingRole: 'affected_site_governance',
    reasonHash: DIGEST_F,
    filedAtHlc: { physicalMs: 1791600410000, logical: 0 },
    independentReviewerDid: 'did:exo:independent-governance-reviewer-alpha',
  };

  const contested = evaluateDecisionForumMatter(input);

  assert.equal(contested.decision, 'permitted');
  assert.equal(contested.matterRecord.status, 'contested');
  assert.equal(contested.matterRecord.finalClosure, false);
  assert.equal(contested.matterRecord.openChallenge, true);
  assert.deepEqual(contested.matterRecord.lifecycleSteps, [
    'created',
    'reviewed',
    'deliberated',
    'voted',
    'contested',
    'receipt_prepared',
  ]);
  assert.equal(contested.receipt.anchorPayload.artifactVersion, 'DF-PROTOCOL-LAUNCH-CM-001@contested');
  assert.equal(contested.dashboardItem.openChallenge, true);
});

test('Decision Forum matter validates HLC ordering outcomes and required abstention rationale', async () => {
  const { evaluateDecisionForumMatter } = await loadDecisionForumMatters();

  const malformed = decisionForumMatterInput();
  malformed.matter.reviewOpenedAtHlc = { physicalMs: 1791600000000, logical: -1 };
  malformed.votes = malformed.votes.map((vote) =>
    vote.voterDid === 'did:exo:principal-investigator-alpha'
      ? { ...vote, castAtHlc: { physicalMs: 1791600290000, logical: 0 }, rationaleHash: '' }
      : vote,
  );

  const malformedDenied = evaluateDecisionForumMatter(malformed);
  assert.equal(malformedDenied.decision, 'denied');
  assert.ok(malformedDenied.reasons.includes('review_time_invalid'));
  assert.ok(malformedDenied.reasons.includes('vote_before_vote_opened:did:exo:principal-investigator-alpha'));
  assert.ok(malformedDenied.reasons.includes('vote_rationale_hash_invalid:did:exo:principal-investigator-alpha'));

  const sameTick = decisionForumMatterInput();
  sameTick.matter.voteOpenedAtHlc = { physicalMs: 1791600300000, logical: 1 };
  sameTick.votes = sameTick.votes.map((vote) =>
    vote.voterDid === 'did:exo:principal-investigator-alpha'
      ? { ...vote, castAtHlc: { physicalMs: 1791600300000, logical: 0 } }
      : vote,
  );

  const sameTickDenied = evaluateDecisionForumMatter(sameTick);
  assert.equal(sameTickDenied.decision, 'denied');
  assert.ok(sameTickDenied.reasons.includes('vote_before_vote_opened:did:exo:principal-investigator-alpha'));

  const logicalAfterPermitted = decisionForumMatterInput();
  logicalAfterPermitted.matter.voteOpenedAtHlc = { physicalMs: 1791600300000, logical: 1 };
  logicalAfterPermitted.matter.expirationAtHlc = logicalAfterPermitted.matter.closedAtHlc;
  logicalAfterPermitted.votes = logicalAfterPermitted.votes.map((vote) =>
    vote.voterDid === 'did:exo:principal-investigator-alpha'
      ? { ...vote, castAtHlc: { physicalMs: 1791600300000, logical: 2 } }
      : vote,
  );

  const logicalAfter = evaluateDecisionForumMatter(logicalAfterPermitted);
  assert.equal(logicalAfter.decision, 'permitted');

  const invalidOutcome = decisionForumMatterInput();
  invalidOutcome.disposition.outcome = 'approve';
  invalidOutcome.disposition.conditionHashes = [DIGEST_D];
  invalidOutcome.votes = invalidOutcome.votes.map((vote) =>
    vote.voterDid === 'did:exo:sponsor-liaison-alpha' ? { ...vote, rationaleHash: '' } : vote,
  );

  const outcomeDenied = evaluateDecisionForumMatter(invalidOutcome);
  assert.equal(outcomeDenied.decision, 'denied');
  assert.ok(outcomeDenied.reasons.includes('conditions_not_allowed_for_outcome'));
  assert.ok(outcomeDenied.reasons.includes('abstention_rationale_hash_invalid:did:exo:sponsor-liaison-alpha'));
});

test('Decision Forum matter rejects raw deliberation vote and decision text before receipt creation', async () => {
  const { evaluateDecisionForumMatter } = await loadDecisionForumMatters();

  assert.throws(
    () =>
      evaluateDecisionForumMatter({
        ...decisionForumMatterInput(),
        rawDeliberationNotes: 'Participant Alice Example source document text must never be anchored.',
      }),
    /protected content|raw decision forum/i,
  );
});
