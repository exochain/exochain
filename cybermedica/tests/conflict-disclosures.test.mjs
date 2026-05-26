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

async function loadConflictDisclosures() {
  try {
    return await import('../src/conflict-disclosures.mjs');
  } catch (error) {
    assert.fail(`CyberMedica conflict disclosure module must exist and load: ${error.message}`);
  }
}

function conflictDisclosureInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:ethics-governance-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['manage_conflicts', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    decisionMatter: {
      matterRef: 'DF-PROTOCOL-LAUNCH-CM-001',
      decisionType: 'protocol_launch',
      material: true,
      siteRef: 'site-alpha',
      protocolRef: 'protocol-cm-001',
      status: 'pending_deliberation',
      scheduledAtHlc: { physicalMs: 1791500000000, logical: 4 },
    },
    participants: [
      {
        did: 'did:exo:principal-investigator-alpha',
        role: 'principal_investigator',
        decisionRole: 'voter',
        votingEligible: true,
        reviewer: false,
      },
      {
        did: 'did:exo:quality-reviewer-alpha',
        role: 'quality_reviewer',
        decisionRole: 'reviewer',
        votingEligible: false,
        reviewer: true,
      },
      {
        did: 'did:exo:sponsor-liaison-alpha',
        role: 'sponsor_liaison',
        decisionRole: 'observer',
        votingEligible: false,
        reviewer: true,
      },
    ],
    disclosures: [
      {
        disclosureRef: 'COI-PI-0001',
        participantDid: 'did:exo:principal-investigator-alpha',
        status: 'clear',
        current: true,
        appliesToMatter: true,
        evidenceHash: DIGEST_B,
        disclosedAtHlc: { physicalMs: 1791400000000, logical: 0 },
        reviewedByDid: 'did:exo:ethics-governance-alpha',
        reviewedAtHlc: { physicalMs: 1791400100000, logical: 0 },
      },
      {
        disclosureRef: 'COI-QUALITY-0001',
        participantDid: 'did:exo:quality-reviewer-alpha',
        status: 'managed',
        current: true,
        appliesToMatter: true,
        evidenceHash: DIGEST_C,
        managementPlanHash: DIGEST_D,
        disclosedAtHlc: { physicalMs: 1791400200000, logical: 0 },
        reviewedByDid: 'did:exo:ethics-governance-alpha',
        reviewedAtHlc: { physicalMs: 1791400300000, logical: 0 },
      },
      {
        disclosureRef: 'COI-SPONSOR-0001',
        participantDid: 'did:exo:sponsor-liaison-alpha',
        status: 'active',
        current: true,
        appliesToMatter: true,
        evidenceHash: DIGEST_D,
        managementPlanHash: DIGEST_E,
        disclosedAtHlc: { physicalMs: 1791400400000, logical: 0 },
        reviewedByDid: 'did:exo:ethics-governance-alpha',
        reviewedAtHlc: { physicalMs: 1791400500000, logical: 0 },
      },
    ],
    recusals: [
      {
        recusalRef: 'REC-SPONSOR-0001',
        participantDid: 'did:exo:sponsor-liaison-alpha',
        matterRef: 'DF-PROTOCOL-LAUNCH-CM-001',
        status: 'active',
        scope: 'decision_and_review',
        reasonHash: DIGEST_A,
        replacementDid: 'did:exo:sponsor-independent-reviewer-alpha',
        acceptedByDid: 'did:exo:ethics-governance-alpha',
        effectiveAtHlc: { physicalMs: 1791400600000, logical: 0 },
      },
    ],
    aiReview: {
      completed: true,
      advisoryOnly: true,
      finalAuthority: false,
      outputHash: DIGEST_E,
      evidenceUsedHashes: [DIGEST_A, DIGEST_B],
      flaggedParticipantDids: ['did:exo:sponsor-liaison-alpha'],
    },
    governance: {
      verified: true,
      state: 'approved',
      humanGate: { verified: true },
      quorum: { status: 'met' },
      openChallenge: false,
      decisionId: 'df-conflict-disclosure-0001',
      workflowReceiptId: 'df-workflow-conflict-disclosure-0001',
    },
    evidenceBundle: { complete: true, phiBoundaryAttested: true },
    custodyDigest: DIGEST_E,
  };
}

test('conflict disclosure review creates deterministic inactive participation receipt with recusal evidence', async () => {
  const { evaluateConflictDisclosureReview } = await loadConflictDisclosures();

  const resultA = evaluateConflictDisclosureReview(conflictDisclosureInput());
  const resultB = evaluateConflictDisclosureReview({
    ...conflictDisclosureInput(),
    participants: [...conflictDisclosureInput().participants].reverse(),
    disclosures: [...conflictDisclosureInput().disclosures].reverse(),
    recusals: [...conflictDisclosureInput().recusals].reverse(),
    aiReview: {
      ...conflictDisclosureInput().aiReview,
      evidenceUsedHashes: [...conflictDisclosureInput().aiReview.evidenceUsedHashes].reverse(),
      flaggedParticipantDids: [...conflictDisclosureInput().aiReview.flaggedParticipantDids].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.conflictReview.status, 'cleared_for_participation');
  assert.equal(resultA.conflictReview.trustState, 'inactive');
  assert.equal(resultA.conflictReview.exochainProductionClaim, false);
  assert.equal(resultA.conflictReview.aiFinalAuthority, false);
  assert.equal(resultA.conflictReview.disclosureCoverageBasisPoints, 10000);
  assert.deepEqual(resultA.conflictReview.clearedParticipantDids, [
    'did:exo:principal-investigator-alpha',
    'did:exo:quality-reviewer-alpha',
  ]);
  assert.deepEqual(resultA.conflictReview.recusedParticipantDids, ['did:exo:sponsor-liaison-alpha']);
  assert.deepEqual(resultA.conflictReview.managedConflictDids, ['did:exo:quality-reviewer-alpha']);
  assert.deepEqual(resultA.conflictReview.aiFlaggedParticipantDids, ['did:exo:sponsor-liaison-alpha']);
  assert.equal(resultA.conflictReview.reviewId, resultB.conflictReview.reviewId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'conflict_disclosure_review');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /raw conflict|relationship details|patient|participant alice/iu);
});

test('conflict disclosure review fails closed for missing disclosures active conflicts and AI authority', async () => {
  const { evaluateConflictDisclosureReview } = await loadConflictDisclosures();
  const input = conflictDisclosureInput();
  input.actor = { did: 'did:exo:ai-governance-alpha', kind: 'ai_agent' };
  input.disclosures = input.disclosures.filter(
    (disclosure) => disclosure.participantDid !== 'did:exo:quality-reviewer-alpha',
  );
  input.recusals = [];
  input.aiReview = {
    completed: false,
    advisoryOnly: false,
    finalAuthority: true,
    outputHash: '',
    evidenceUsedHashes: ['bad'],
    flaggedParticipantDids: ['did:exo:sponsor-liaison-alpha'],
  };

  const denied = evaluateConflictDisclosureReview(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.conflictReview.status, 'blocked');
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_review_incomplete'));
  assert.ok(denied.reasons.includes('ai_review_must_be_advisory'));
  assert.ok(denied.reasons.includes('ai_review_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('conflict_disclosure_missing:did:exo:quality-reviewer-alpha'));
  assert.ok(denied.reasons.includes('active_conflict_without_recusal:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.conflictReview.blockedParticipantDids.includes('did:exo:sponsor-liaison-alpha'));
});

test('conflict disclosure review denies recused participants who remain in decision or review roles', async () => {
  const { evaluateConflictDisclosureReview } = await loadConflictDisclosures();
  const input = conflictDisclosureInput();
  input.participants = input.participants.map((participant) =>
    participant.did === 'did:exo:sponsor-liaison-alpha'
      ? { ...participant, votingEligible: true, reviewer: true, decisionRole: 'voter' }
      : participant,
  );
  input.recusals = [
    {
      ...input.recusals[0],
      replacementDid: '',
      acceptedByDid: '',
      reasonHash: 'bad',
      effectiveAtHlc: { physicalMs: 1791510000000, logical: 0 },
    },
  ];
  input.governance = {
    verified: false,
    state: 'pending',
    humanGate: { verified: false },
    quorum: { status: 'not_met' },
    openChallenge: true,
    decisionId: '',
    workflowReceiptId: '',
  };
  input.evidenceBundle = { complete: false, phiBoundaryAttested: false };

  const denied = evaluateConflictDisclosureReview(input);

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('recused_participant_still_active:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recusal_replacement_absent:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recusal_acceptance_absent:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recusal_reason_hash_invalid:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('recusal_after_matter_start:did:exo:sponsor-liaison-alpha'));
  assert.ok(denied.reasons.includes('decision_forum_unverified'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('quorum_not_met'));
  assert.ok(denied.reasons.includes('challenge_open'));
  assert.ok(denied.reasons.includes('evidence_bundle_incomplete'));
  assert.ok(denied.reasons.includes('phi_boundary_unattested'));
});

test('conflict disclosure review validates tenant authority disclosure timing and metadata hashes', async () => {
  const { evaluateConflictDisclosureReview } = await loadConflictDisclosures();
  const input = conflictDisclosureInput();
  input.targetTenantId = 'tenant-site-beta';
  input.authority = {
    valid: true,
    revoked: false,
    expired: false,
    permissions: ['read'],
    authorityChainHash: 'bad',
  };
  input.decisionMatter.scheduledAtHlc = { physicalMs: 1791380000000, logical: 0 };
  input.disclosures = input.disclosures.map((disclosure) => ({
    ...disclosure,
    current: false,
    evidenceHash: '',
    reviewedByDid: '',
    reviewedAtHlc: { physicalMs: 1791390000000, logical: 0 },
  }));
  input.custodyDigest = 'bad';

  const denied = evaluateConflictDisclosureReview(input);

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('conflict_disclosure_authority_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.ok(denied.reasons.includes('disclosure_not_current:did:exo:principal-investigator-alpha'));
  assert.ok(denied.reasons.includes('disclosure_evidence_hash_invalid:did:exo:principal-investigator-alpha'));
  assert.ok(denied.reasons.includes('disclosure_reviewer_absent:did:exo:principal-investigator-alpha'));
  assert.ok(denied.reasons.includes('disclosure_review_before_disclosure:did:exo:principal-investigator-alpha'));
  assert.ok(denied.reasons.includes('disclosure_review_after_matter_start:did:exo:principal-investigator-alpha'));
});

test('conflict disclosure review rejects raw conflict and recusal text before receipt creation', async () => {
  const { evaluateConflictDisclosureReview } = await loadConflictDisclosures();

  assert.throws(
    () =>
      evaluateConflictDisclosureReview({
        ...conflictDisclosureInput(),
        disclosures: [
          {
            ...conflictDisclosureInput().disclosures[0],
            rawConflictNarrative: 'Participant Alice Example relationship details must not be anchored.',
          },
        ],
      }),
    /protected content|raw conflict/i,
  );
});

test('conflict disclosure review handles empty rosters malformed HLC and scoped recusal branches', async () => {
  const { evaluateConflictDisclosureReview } = await loadConflictDisclosures();

  const emptyRoster = evaluateConflictDisclosureReview({
    ...conflictDisclosureInput(),
    decisionMatter: {
      ...conflictDisclosureInput().decisionMatter,
      scheduledAtHlc: { physicalMs: 1791500000000, logical: -1 },
    },
    participants: [],
    disclosures: null,
    recusals: null,
  });

  assert.equal(emptyRoster.decision, 'denied');
  assert.ok(emptyRoster.reasons.includes('decision_participants_absent'));
  assert.ok(emptyRoster.reasons.includes('decision_matter_time_invalid'));
  assert.equal(emptyRoster.conflictReview.disclosureCoverageBasisPoints, 0);

  const logicalOrdering = conflictDisclosureInput();
  logicalOrdering.decisionMatter.scheduledAtHlc = { physicalMs: 1791400500000, logical: 1 };
  logicalOrdering.disclosures = logicalOrdering.disclosures.map((disclosure) => {
    if (disclosure.participantDid === 'did:exo:principal-investigator-alpha') {
      return {
        ...disclosure,
        disclosedAtHlc: { physicalMs: 1791400500000, logical: 2 },
        reviewedAtHlc: { physicalMs: 1791400500000, logical: 0 },
      };
    }
    if (disclosure.participantDid === 'did:exo:quality-reviewer-alpha') {
      return {
        ...disclosure,
        disclosedAtHlc: { physicalMs: 1791400500000, logical: 1 },
        reviewedAtHlc: { physicalMs: 1791400500000, logical: 2 },
      };
    }
    return disclosure;
  });

  const logicalDenied = evaluateConflictDisclosureReview(logicalOrdering);
  assert.equal(logicalDenied.decision, 'denied');
  assert.ok(logicalDenied.reasons.includes('disclosure_review_before_disclosure:did:exo:principal-investigator-alpha'));
  assert.ok(logicalDenied.reasons.includes('disclosure_review_after_matter_start:did:exo:quality-reviewer-alpha'));

  const decisionScope = conflictDisclosureInput();
  decisionScope.participants = decisionScope.participants.map((participant) =>
    participant.did === 'did:exo:sponsor-liaison-alpha'
      ? { ...participant, votingEligible: true, reviewer: false, decisionRole: 'voter' }
      : participant,
  );
  decisionScope.recusals = [{ ...decisionScope.recusals[0], scope: 'decision' }];

  const decisionScopeDenied = evaluateConflictDisclosureReview(decisionScope);
  assert.equal(decisionScopeDenied.decision, 'denied');
  assert.equal(
    decisionScopeDenied.reasons.includes('active_conflict_without_recusal:did:exo:sponsor-liaison-alpha'),
    false,
  );
  assert.ok(decisionScopeDenied.reasons.includes('recused_participant_still_active:did:exo:sponsor-liaison-alpha'));

  const reviewScope = conflictDisclosureInput();
  reviewScope.recusals = [{ ...reviewScope.recusals[0], scope: 'review' }];
  reviewScope.disclosures = reviewScope.disclosures.map((disclosure) =>
    disclosure.participantDid === 'did:exo:principal-investigator-alpha'
      ? { ...disclosure, reviewedAtHlc: disclosure.disclosedAtHlc }
      : disclosure,
  );

  const reviewScopePermitted = evaluateConflictDisclosureReview(reviewScope);
  assert.equal(reviewScopePermitted.decision, 'permitted');
});
