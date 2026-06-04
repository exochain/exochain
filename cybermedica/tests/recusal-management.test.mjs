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

async function loadRecusalManagement() {
  try {
    return await import('../src/recusal-management.mjs');
  } catch (error) {
    assert.fail(`CyberMedica recusal management module must exist and load: ${error.message}`);
  }
}

function recusalInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:ethics-governance-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_recusals', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    decisionMatter: {
      matterRef: 'DF-LAUNCH-RECUSAL-001',
      decisionType: 'protocol_launch',
      material: true,
      siteRef: 'site-alpha',
      protocolRef: 'protocol-cm-001',
      status: 'pending_deliberation',
      scheduledAtHlc: { physicalMs: 1800100000000, logical: 0 },
    },
    recusalPolicy: {
      policyRef: 'recusal-management-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredScopes: ['decision', 'review'],
      requireReplacementForVoting: true,
      requireReplacementForReview: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800099000000, logical: 0 },
    },
    participants: [
      {
        did: 'did:exo:principal-investigator-alpha',
        role: 'principal_investigator',
        decisionRole: 'voter',
        votingEligible: true,
        reviewer: false,
        activeOnMatter: true,
      },
      {
        did: 'did:exo:quality-reviewer-alpha',
        role: 'quality_reviewer',
        decisionRole: 'reviewer',
        votingEligible: false,
        reviewer: true,
        activeOnMatter: true,
      },
      {
        did: 'did:exo:sponsor-liaison-alpha',
        role: 'sponsor_liaison',
        decisionRole: 'observer',
        votingEligible: true,
        reviewer: true,
        activeOnMatter: false,
      },
    ],
    conflictFindings: [
      {
        findingRef: 'COI-PI-CLEAR-001',
        participantDid: 'did:exo:principal-investigator-alpha',
        status: 'clear',
        requiresRecusal: false,
        evidenceHash: DIGEST_B,
        assessedAtHlc: { physicalMs: 1800099100000, logical: 0 },
      },
      {
        findingRef: 'COI-QUALITY-MANAGED-001',
        participantDid: 'did:exo:quality-reviewer-alpha',
        status: 'managed',
        requiresRecusal: false,
        evidenceHash: DIGEST_C,
        managementPlanHash: DIGEST_D,
        assessedAtHlc: { physicalMs: 1800099200000, logical: 0 },
      },
      {
        findingRef: 'COI-SPONSOR-ACTIVE-001',
        participantDid: 'did:exo:sponsor-liaison-alpha',
        status: 'active',
        requiresRecusal: true,
        requiredScope: 'decision_and_review',
        evidenceHash: DIGEST_D,
        managementPlanHash: DIGEST_E,
        assessedAtHlc: { physicalMs: 1800099300000, logical: 0 },
      },
    ],
    recusalActions: [
      {
        recusalRef: 'REC-SPONSOR-001',
        participantDid: 'did:exo:sponsor-liaison-alpha',
        matterRef: 'DF-LAUNCH-RECUSAL-001',
        conflictFindingRef: 'COI-SPONSOR-ACTIVE-001',
        status: 'active',
        scope: 'decision_and_review',
        reasonHash: DIGEST_A,
        acknowledgementHash: DIGEST_B,
        notificationHash: DIGEST_C,
        replacementDid: 'did:exo:sponsor-independent-reviewer-alpha',
        acceptedByDid: 'did:exo:ethics-governance-alpha',
        effectiveAtHlc: { physicalMs: 1800099400000, logical: 0 },
      },
    ],
    replacementEvidence: [
      {
        replacedParticipantDid: 'did:exo:sponsor-liaison-alpha',
        replacementDid: 'did:exo:sponsor-independent-reviewer-alpha',
        role: 'independent_sponsor_reviewer',
        authorityHash: DIGEST_D,
        disclosureClearanceHash: DIGEST_E,
        acceptedAtHlc: { physicalMs: 1800099500000, logical: 0 },
      },
    ],
    matterRoster: {
      activeVotingDids: ['did:exo:principal-investigator-alpha'],
      activeReviewDids: ['did:exo:quality-reviewer-alpha'],
      excludedVotingDids: ['did:exo:sponsor-liaison-alpha'],
      excludedReviewDids: ['did:exo:sponsor-liaison-alpha'],
    },
    humanReview: {
      reviewerDid: 'did:exo:ethics-governance-alpha',
      decision: 'recusal_plan_accepted_inactive_trust',
      decisionHash: DIGEST_F,
      humanGateVerified: true,
      quorumStatus: 'met',
      openChallenge: false,
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800099600000, logical: 0 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_F,
  };

  return { ...base, ...overrides };
}

test('recusal management creates deterministic inactive FR-028 recusal plan receipts', async () => {
  const { evaluateRecusalManagement } = await loadRecusalManagement();

  const resultA = evaluateRecusalManagement(recusalInput());
  const inputB = recusalInput({
    participants: [...recusalInput().participants].reverse(),
    conflictFindings: [...recusalInput().conflictFindings].reverse(),
    recusalActions: [...recusalInput().recusalActions].reverse(),
    replacementEvidence: [...recusalInput().replacementEvidence].reverse(),
    matterRoster: {
      activeVotingDids: ['did:exo:principal-investigator-alpha'],
      activeReviewDids: ['did:exo:quality-reviewer-alpha'],
      excludedVotingDids: ['did:exo:sponsor-liaison-alpha'],
      excludedReviewDids: ['did:exo:sponsor-liaison-alpha'],
    },
  });
  const resultB = evaluateRecusalManagement(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.recusalPlan.status, 'ready_for_matter');
  assert.equal(resultA.recusalPlan.trustState, 'inactive');
  assert.equal(resultA.recusalPlan.exochainProductionClaim, false);
  assert.equal(resultA.recusalPlan.recusalCoverageBasisPoints, 10000);
  assert.deepEqual(resultA.recusalPlan.recusedParticipantDids, ['did:exo:sponsor-liaison-alpha']);
  assert.deepEqual(resultA.recusalPlan.clearedParticipantDids, [
    'did:exo:principal-investigator-alpha',
    'did:exo:quality-reviewer-alpha',
  ]);
  assert.deepEqual(resultA.recusalPlan.replacementDids, ['did:exo:sponsor-independent-reviewer-alpha']);
  assert.deepEqual(resultA.recusalPlan.excludedVotingDids, ['did:exo:sponsor-liaison-alpha']);
  assert.deepEqual(resultA.recusalPlan.excludedReviewDids, ['did:exo:sponsor-liaison-alpha']);
  assert.equal(resultA.recusalPlan.planId, resultB.recusalPlan.planId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'recusal_management_plan');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /raw conflict|relationship details|participant alice|patient bob/iu);
});

test('recusal management fails closed for uncovered conflicts active rosters and AI authority', async () => {
  const { evaluateRecusalManagement } = await loadRecusalManagement();
  const input = recusalInput({
    actor: { did: 'did:exo:ai-governance-alpha', kind: 'ai_agent' },
    recusalActions: [],
    replacementEvidence: [],
    matterRoster: {
      activeVotingDids: ['did:exo:principal-investigator-alpha', 'did:exo:sponsor-liaison-alpha'],
      activeReviewDids: ['did:exo:quality-reviewer-alpha', 'did:exo:sponsor-liaison-alpha'],
      excludedVotingDids: [],
      excludedReviewDids: [],
    },
    humanReview: {
      ...recusalInput().humanReview,
      humanGateVerified: false,
      quorumStatus: 'not_met',
      openChallenge: true,
      aiFinalAuthority: true,
      decision: 'hold_for_recusal_gap',
    },
  });

  const denied = evaluateRecusalManagement(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.recusalPlan.status, 'blocked');
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_actor_required'));
  assert.ok(denied.reasons.includes('required_recusal_missing:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recused_participant_active_voter:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recused_participant_active_reviewer:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recused_participant_not_excluded_from_vote:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recused_participant_not_excluded_from_review:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
});

test('recusal management validates action evidence replacement scope and HLC timing', async () => {
  const { evaluateRecusalManagement } = await loadRecusalManagement();
  const input = recusalInput({
    recusalActions: [
      {
        recusalRef: 'REC-SPONSOR-001',
        participantDid: 'did:exo:sponsor-liaison-alpha',
        matterRef: 'DF-WRONG-MATTER',
        conflictFindingRef: 'COI-SPONSOR-ACTIVE-001',
        status: 'withdrawn',
        scope: 'review',
        reasonHash: 'bad',
        acknowledgementHash: '',
        notificationHash: 'bad',
        replacementDid: '',
        acceptedByDid: '',
        effectiveAtHlc: { physicalMs: 1800100100000, logical: 0 },
      },
    ],
    replacementEvidence: [
      {
        replacedParticipantDid: 'did:exo:sponsor-liaison-alpha',
        replacementDid: 'did:exo:sponsor-independent-reviewer-alpha',
        role: '',
        authorityHash: 'bad',
        disclosureClearanceHash: '',
        acceptedAtHlc: { physicalMs: 1800099300000, logical: 0 },
      },
    ],
  });

  const denied = evaluateRecusalManagement(input);

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('recusal_matter_mismatch:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recusal_status_invalid:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recusal_scope_insufficient:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recusal_reason_hash_invalid:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recusal_acknowledgement_hash_invalid:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recusal_notification_hash_invalid:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recusal_replacement_absent:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recusal_acceptance_absent:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recusal_after_matter_start:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('replacement_role_absent:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('replacement_authority_hash_invalid:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('replacement_disclosure_clearance_hash_invalid:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('replacement_accepted_before_recusal:did:exo:sponsor-liaison-alpha'));
});

test('recusal management handles absent inputs as fail-closed denial states', async () => {
  const { evaluateRecusalManagement } = await loadRecusalManagement();

  const denied = evaluateRecusalManagement({});

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.recusalPlan.status, 'blocked');
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('tenant_absent'));
  assert.ok(denied.reasons.includes('decision_participants_absent'));
  assert.ok(denied.reasons.includes('recusal_policy_missing'));
  assert.ok(denied.reasons.includes('human_review_decision_invalid'));
});

test('recusal management rejects raw recusal content protected content and secrets', async () => {
  const { ProtectedContentError, evaluateRecusalManagement } = await loadRecusalManagement();

  assert.throws(
    () =>
      evaluateRecusalManagement({
        ...recusalInput(),
        recusalActions: [
          {
            ...recusalInput().recusalActions[0],
            rawRecusalReason: 'relationship details with participant Alice',
          },
        ],
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRecusalManagement({
        ...recusalInput(),
        replacementEvidence: [
          {
            ...recusalInput().replacementEvidence[0],
            rootSigningKey: 'secret-key-material',
          },
        ],
      }),
    ProtectedContentError,
  );
});
