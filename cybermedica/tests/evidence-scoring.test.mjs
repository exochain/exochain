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

const REQUIRED_SCOPES = Object.freeze(['control', 'diligence_packet', 'protocol', 'site', 'study']);

async function loadEvidenceScoring() {
  try {
    return await import('../src/evidence-scoring.mjs');
  } catch (error) {
    assert.fail(`CyberMedica evidence scoring module must exist and load: ${error.message}`);
  }
}

function requirement(scope, family, index) {
  return {
    scope,
    ownerRef: `${scope}-alpha`,
    requiredFamily: family,
    controlRef: scope === 'control' ? `CTRL-${String(index).padStart(3, '0')}` : null,
    criticality: index % 2 === 0 ? 'critical' : 'major',
  };
}

function evidenceItem(scope, family, index) {
  return {
    evidenceRef: `EVD-${scope.toUpperCase()}-${String(index).padStart(3, '0')}`,
    scope,
    ownerRef: `${scope}-alpha`,
    family,
    status: 'approved',
    artifactHash: index % 2 === 0 ? DIGEST_A : DIGEST_B,
    custodyDigest: index % 2 === 0 ? DIGEST_C : DIGEST_D,
    observedAtHlc: { physicalMs: 1793000000000 + index, logical: 0 },
    freshnessWindowMs: 86_400_000,
    reviewReceiptHash: index % 2 === 0 ? DIGEST_E : DIGEST_F,
    metadataOnly: true,
    protectedContentExcluded: true,
  };
}

function scoringRequirements() {
  return [
    requirement('control', 'control_evidence', 1),
    requirement('control', 'control_owner_review', 2),
    requirement('site', 'site_training_matrix', 3),
    requirement('site', 'site_quality_review', 4),
    requirement('study', 'study_delegation_log', 5),
    requirement('study', 'study_risk_review', 6),
    requirement('protocol', 'protocol_approval', 7),
    requirement('protocol', 'protocol_amendment', 8),
    requirement('diligence_packet', 'diligence_manifest', 9),
    requirement('diligence_packet', 'diligence_export_review', 10),
  ];
}

function completeEvidenceItems() {
  return scoringRequirements().map((item, index) => evidenceItem(item.scope, item.requiredFamily, index + 1));
}

function evidenceScoringInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:evidence-score-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['evidence_scoring', 'read'],
      authorityChainHash: DIGEST_F,
    },
    scoringPolicy: {
      policyRef: 'FR-006-FR-007-EVIDENCE-SCORING-POLICY-ALPHA',
      requiredScopes: REQUIRED_SCOPES,
      policyHash: DIGEST_A,
      reviewedAtHlc: { physicalMs: 1792999999000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    scoreSet: {
      scoreSetRef: 'EVIDENCE-SCORE-CARDIAC-ALPHA-001',
      siteRef: 'site-alpha',
      studyRef: 'study-alpha',
      protocolRef: 'protocol-alpha',
      diligencePacketRef: 'diligence-packet-alpha',
      evaluatedAtHlc: { physicalMs: 1793000005000, logical: 0 },
      requirements: scoringRequirements(),
      evidenceItems: completeEvidenceItems(),
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-reviewer-alpha',
      reviewDecision: 'score_approved',
      reviewedAtHlc: { physicalMs: 1793000006000, logical: 0 },
      evidenceBundleHash: DIGEST_B,
      rationaleHash: DIGEST_C,
      decisionForum: {
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-evidence-scoring-alpha-001',
        workflowReceiptId: 'df-workflow-evidence-scoring-alpha-001',
      },
    },
    custodyDigest: DIGEST_D,
  };
}

test('evidence scoring computes deterministic FR-006 and FR-007 readiness across required scopes', async () => {
  const { evaluateEvidenceScoring } = await loadEvidenceScoring();

  const resultA = evaluateEvidenceScoring(evidenceScoringInput());
  const inputB = evidenceScoringInput();
  inputB.scoringPolicy.requiredScopes = [...inputB.scoringPolicy.requiredScopes].reverse();
  inputB.scoreSet.requirements = [...inputB.scoreSet.requirements].reverse();
  inputB.scoreSet.evidenceItems = [...inputB.scoreSet.evidenceItems].reverse();
  const resultB = evaluateEvidenceScoring(inputB);

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.evidenceScore.scoreStatus, 'ready');
  assert.equal(resultA.evidenceScore.completenessBasisPoints, 10000);
  assert.equal(resultA.evidenceScore.freshnessBasisPoints, 10000);
  assert.equal(resultA.evidenceScore.trustState, 'inactive');
  assert.equal(resultA.evidenceScore.exochainProductionClaim, false);
  assert.deepEqual(
    resultA.evidenceScore.scopeScores.map((scope) => scope.scope),
    ['control', 'diligence_packet', 'protocol', 'site', 'study'],
  );
  assert.ok(resultA.evidenceScore.scopeScores.every((scope) => scope.completenessBasisPoints === 10000));
  assert.ok(resultA.evidenceScore.scopeScores.every((scope) => scope.freshnessBasisPoints === 10000));
  assert.equal(resultA.evidenceScore.scoreSetHash, resultB.evidenceScore.scoreSetHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'evidence_scoring');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(resultA), /source document body|participant alice|raw evidence|root-backed production authority/iu);
});

test('evidence scoring flags incomplete and stale evidence without claiming readiness', async () => {
  const { evaluateEvidenceScoring } = await loadEvidenceScoring();
  const input = evidenceScoringInput();

  input.scoreSet.evidenceItems = input.scoreSet.evidenceItems
    .filter((item) => item.family !== 'protocol_amendment')
    .map((item) =>
      item.family === 'site_training_matrix'
        ? {
            ...item,
            observedAtHlc: { physicalMs: 1792000000000, logical: 0 },
            freshnessWindowMs: 1,
          }
        : item,
    )
    .map((item) =>
      item.family === 'study_delegation_log'
        ? {
            ...item,
            status: 'pending',
          }
        : item,
    );

  const result = evaluateEvidenceScoring(input);

  assert.equal(result.decision, 'permitted');
  assert.equal(result.failClosed, false);
  assert.equal(result.evidenceScore.scoreStatus, 'attention_required');
  assert.equal(result.evidenceScore.completenessBasisPoints, 8000);
  assert.equal(result.evidenceScore.freshnessBasisPoints, 7000);
  assert.ok(result.evidenceScore.defects.includes('required_evidence_missing:protocol:protocol_amendment'));
  assert.ok(result.evidenceScore.defects.includes('evidence_stale:site:site_training_matrix'));
  assert.ok(result.evidenceScore.defects.includes('evidence_not_approved:study:study_delegation_log'));
  assert.deepEqual(result.evidenceScore.requiredFollowUpRoles, [
    'principal_investigator',
    'site_quality_lead',
    'study_owner',
  ]);
  assert.equal(result.evidenceScore.readyForReadinessGate, false);
  assert.equal(result.receipt.anchorPayload.artifactType, 'evidence_scoring');
});

test('evidence scoring fails closed for boundary authority governance and timing defects', async () => {
  const { evaluateEvidenceScoring } = await loadEvidenceScoring();
  const input = evidenceScoringInput();

  input.targetTenantId = 'tenant-site-beta';
  input.actor = { did: 'did:exo:ai-evidence-scorer-alpha', kind: 'ai_agent' };
  input.authority = {
    valid: true,
    revoked: true,
    expired: true,
    permissions: ['read'],
    authorityChainHash: 'bad',
  };
  input.scoringPolicy.requiredScopes = ['control', 'site'];
  input.scoringPolicy.metadataOnly = false;
  input.scoringPolicy.protectedContentExcluded = false;
  input.scoreSet.evaluatedAtHlc = { physicalMs: 1792999998000, logical: 0 };
  input.humanReview.reviewDecision = 'ai_finalized';
  input.humanReview.decisionForum.humanGate.verified = false;

  const denied = evaluateEvidenceScoring(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_chain_revoked'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('authority_chain_hash_invalid'));
  assert.ok(denied.reasons.includes('required_scope_absent:diligence_packet'));
  assert.ok(denied.reasons.includes('required_scope_absent:protocol'));
  assert.ok(denied.reasons.includes('required_scope_absent:study'));
  assert.ok(denied.reasons.includes('policy_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('evaluation_time_before_policy_review'));
  assert.ok(denied.reasons.includes('human_gate_unverified'));
  assert.ok(denied.reasons.includes('human_review_decision_invalid'));
  assert.equal(denied.evidenceScore, null);
  assert.equal(denied.receipt, null);
});

test('evidence scoring validates same-tick HLC order and rejects protected content', async () => {
  const { evaluateEvidenceScoring } = await loadEvidenceScoring();

  const sameTick = evidenceScoringInput();
  sameTick.scoringPolicy.reviewedAtHlc = { physicalMs: 1793000005000, logical: 0 };
  sameTick.scoreSet.evaluatedAtHlc = { physicalMs: 1793000005000, logical: 1 };
  sameTick.humanReview.reviewedAtHlc = { physicalMs: 1793000005000, logical: 2 };
  const sameTickResult = evaluateEvidenceScoring(sameTick);
  assert.equal(sameTickResult.decision, 'permitted');

  const malformed = evidenceScoringInput();
  malformed.scoreSet.evaluatedAtHlc = { physicalMs: 1793000005000, logical: -1 };
  malformed.humanReview.reviewedAtHlc = null;
  const denied = evaluateEvidenceScoring(malformed);
  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('evaluation_time_invalid'));
  assert.ok(denied.reasons.includes('human_review_time_invalid'));

  assert.throws(
    () =>
      evaluateEvidenceScoring({
        ...evidenceScoringInput(),
        sourceDocumentBody: 'Participant Alice Example source document body must not enter evidence scoring.',
      }),
    /protected content/i,
  );
});
