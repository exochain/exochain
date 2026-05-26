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

const DIGEST_A = '3d6f0a96f7c972d4f5b66a1c6b5177fe5a32cc0cbd27f7c67be4c11a4f7ce70a';
const DIGEST_B = '8cf4dfd546b712c3b21f0d61fd7c6b744dfc6d9c7d0c8758fb6c6db6e782a7f3';
const DIGEST_C = '54f6e9e53f0e6d9a6ce64b2d67b79d44a927f276e8916d34a2d3b942f575f1b7';
const DIGEST_D = 'd9470f1f6f89a8836e46c21ffcf84f544f8b70a54156f8380dfd5bdf8c5f9693';
const DIGEST_E = 'f50b82f55e509c9fb872d064d8e513ba60b74a5925c16f70b96c41d727fcb2cc';
const DIGEST_F = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

async function loadAiControlReview() {
  try {
    return await import('../src/ai-control-review.mjs');
  } catch (error) {
    assert.fail(`CyberMedica AI control review module must exist and load: ${error.message}`);
  }
}

function aiControlReviewInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['read', 'write', 'ai_control_review'],
      authorityChainHash: DIGEST_A,
    },
    aiAgent: {
      did: 'did:exo:ai-quality-reviewer-alpha',
      kind: 'ai_agent',
      authorizedScope: 'control_evidence_review',
      policyRef: 'AI-QMS-REVIEW-POLICY-2026-05',
    },
    review: {
      reviewId: 'AI-CTRL-REVIEW-SITE-ALPHA-0001',
      reviewClass: 'control_evidence_completeness',
      modelRefHash: DIGEST_B,
      promptHash: DIGEST_C,
      inputManifestHash: DIGEST_D,
      outputHash: DIGEST_E,
      startedAtHlc: { physicalMs: 1793500000000, logical: 0 },
      completedAtHlc: { physicalMs: 1793500000000, logical: 2 },
      advisoryOnly: true,
      finalAuthority: false,
      logged: true,
      promptOutputRetained: true,
      tenantPolicyRef: 'TENANT-AI-POLICY-ALPHA',
      scopePermissions: ['read_metadata_evidence', 'generate_advisory_findings'],
    },
    controls: [
      {
        controlId: 'CM-QMS-CONSENT-001',
        versionId: 'v3',
        riskCriticality: 'critical',
        ownerRole: 'principal_investigator',
        objectiveHash: DIGEST_A,
        requiredEvidenceTypes: ['delegation_log', 'site_consent_sop'],
        applicable: true,
        controlApprovalRef: 'cmqa-consent-001-v3',
      },
      {
        controlId: 'CM-QMS-DOC-001',
        versionId: 'v2',
        riskCriticality: 'major',
        ownerRole: 'quality_manager',
        objectiveHash: DIGEST_B,
        requiredEvidenceTypes: ['approved_sop'],
        applicable: true,
        controlApprovalRef: 'cmqa-doc-001-v2',
      },
      {
        controlId: 'CM-QMS-PRODUCT-001',
        versionId: 'v1',
        riskCriticality: 'critical',
        ownerRole: 'pharmacy_lead',
        objectiveHash: DIGEST_C,
        requiredEvidenceTypes: ['temperature_log'],
        applicable: true,
        controlApprovalRef: 'cmqa-product-001-v1',
      },
    ],
    evidenceLinks: [
      {
        controlId: 'CM-QMS-CONSENT-001',
        evidenceRef: 'EVD-CONSENT-SOP-001',
        evidenceType: 'site_consent_sop',
        artifactHash: DIGEST_B,
        custodyDigest: DIGEST_C,
        status: 'approved',
        fresh: true,
        classification: 'qms_metadata_only',
        reviewedByHuman: true,
        phiBoundaryAttested: true,
      },
      {
        controlId: 'CM-QMS-DOC-001',
        evidenceRef: 'EVD-DOC-SOP-001',
        evidenceType: 'approved_sop',
        artifactHash: DIGEST_C,
        custodyDigest: DIGEST_D,
        status: 'approved',
        fresh: true,
        classification: 'qms_metadata_only',
        reviewedByHuman: true,
        phiBoundaryAttested: true,
      },
      {
        controlId: 'CM-QMS-PRODUCT-001',
        evidenceRef: 'EVD-PRODUCT-TEMP-001',
        evidenceType: 'temperature_log',
        artifactHash: DIGEST_D,
        custodyDigest: DIGEST_E,
        status: 'approved',
        fresh: false,
        classification: 'sponsor_confidential_metadata_only',
        reviewedByHuman: true,
        phiBoundaryAttested: true,
      },
    ],
    findings: [
      {
        findingRef: 'FIND-AI-CONSENT-001',
        controlId: 'CM-QMS-CONSENT-001',
        findingType: 'missing_evidence',
        severity: 'major',
        confidenceBasisPoints: 8600,
        humanReadableFindingHash: DIGEST_A,
        evidenceRefs: ['EVD-CONSENT-SOP-001'],
        reasoningSummaryHash: DIGEST_B,
        limitationsHash: DIGEST_C,
        unresolvedAssumptionHashes: [DIGEST_D],
        potentialConflictRefs: [],
        recommendedHumanReviewerRole: 'quality_manager',
        requiresHumanReview: true,
        escalationRequired: true,
        capaRecommended: true,
        participantSafetyRisk: false,
        dataIntegrityRisk: true,
        privacyRisk: true,
      },
      {
        findingRef: 'FIND-AI-PRODUCT-001',
        controlId: 'CM-QMS-PRODUCT-001',
        findingType: 'stale_evidence',
        severity: 'critical',
        confidenceBasisPoints: 9300,
        humanReadableFindingHash: DIGEST_D,
        evidenceRefs: ['EVD-PRODUCT-TEMP-001'],
        reasoningSummaryHash: DIGEST_E,
        limitationsHash: DIGEST_A,
        unresolvedAssumptionHashes: [],
        potentialConflictRefs: ['conflict-review-product-001'],
        recommendedHumanReviewerRole: 'principal_investigator',
        requiresHumanReview: true,
        escalationRequired: true,
        capaRecommended: true,
        participantSafetyRisk: true,
        dataIntegrityRisk: false,
        privacyRisk: false,
      },
      {
        findingRef: 'FIND-AI-DOC-001',
        controlId: 'CM-QMS-DOC-001',
        findingType: 'evidence_complete',
        severity: 'observation',
        confidenceBasisPoints: 9900,
        humanReadableFindingHash: DIGEST_F,
        evidenceRefs: ['EVD-DOC-SOP-001'],
        reasoningSummaryHash: DIGEST_A,
        limitationsHash: DIGEST_B,
        unresolvedAssumptionHashes: [],
        potentialConflictRefs: [],
        recommendedHumanReviewerRole: 'document_owner',
        requiresHumanReview: true,
        escalationRequired: false,
        capaRecommended: false,
        participantSafetyRisk: false,
        dataIntegrityRisk: false,
        privacyRisk: false,
      },
    ],
    humanReviewPolicy: {
      required: true,
      reviewerRoles: ['quality_manager', 'principal_investigator', 'site_quality_lead'],
      contestable: true,
      allowAiFinalAuthority: false,
    },
    custodyDigest: DIGEST_E,
  };
}

test('AI control review maps evidence to controls and creates deterministic inactive review findings', async () => {
  const { runAiControlReview } = await loadAiControlReview();

  const resultA = runAiControlReview(aiControlReviewInput());
  const resultB = runAiControlReview({
    ...aiControlReviewInput(),
    controls: [...aiControlReviewInput().controls].reverse(),
    evidenceLinks: [...aiControlReviewInput().evidenceLinks].reverse(),
    findings: [...aiControlReviewInput().findings].reverse(),
    humanReviewPolicy: {
      ...aiControlReviewInput().humanReviewPolicy,
      reviewerRoles: [...aiControlReviewInput().humanReviewPolicy.reviewerRoles].reverse(),
    },
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.aiControlReview.assistanceOnly, true);
  assert.equal(resultA.aiControlReview.aiFinalAuthority, false);
  assert.equal(resultA.aiControlReview.exochainProductionClaim, false);
  assert.equal(resultA.aiControlReview.trustState, 'inactive');
  assert.equal(resultA.aiControlReview.evidenceCompletenessBasisPoints, 7500);
  assert.equal(resultA.aiControlReview.evidenceFreshnessBasisPoints, 7500);
  assert.deepEqual(resultA.aiControlReview.findingSummary, { critical: 1, major: 1, minor: 0, observation: 1 });
  assert.deepEqual(resultA.aiControlReview.controlIds, [
    'CM-QMS-CONSENT-001',
    'CM-QMS-DOC-001',
    'CM-QMS-PRODUCT-001',
  ]);
  assert.deepEqual(resultA.aiControlReview.requiredEscalationRoles, [
    'capa_owner',
    'data_integrity_owner',
    'decision_forum_chair',
    'principal_investigator',
    'privacy_officer',
    'site_quality_lead',
  ]);
  assert.deepEqual(resultA.aiControlReview.humanReviewQueue, [
    'document_owner:FIND-AI-DOC-001',
    'principal_investigator:FIND-AI-PRODUCT-001',
    'quality_manager:FIND-AI-CONSENT-001',
  ]);
  assert.deepEqual(resultA.aiControlReview.capaRecommendedFindingRefs, [
    'FIND-AI-CONSENT-001',
    'FIND-AI-PRODUCT-001',
  ]);
  assert.equal(resultA.aiControlReview.reviewId, resultB.aiControlReview.reviewId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'ai_control_review_findings');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /source document body|raw ai output|participant alice|finding narrative/iu);
});

test('AI control review fails closed for final authority incomplete evidence and missing human review policy', async () => {
  const { runAiControlReview } = await loadAiControlReview();
  const input = aiControlReviewInput();
  input.review = {
    ...input.review,
    modelRefHash: '',
    promptHash: 'not-a-digest',
    outputHash: null,
    finalAuthority: true,
    advisoryOnly: false,
    logged: false,
    promptOutputRetained: false,
    completedAtHlc: { physicalMs: 1793499999000, logical: 0 },
    scopePermissions: ['write_raw_payload'],
  };
  input.humanReviewPolicy = {
    required: false,
    reviewerRoles: [],
    contestable: false,
    allowAiFinalAuthority: true,
  };
  input.evidenceLinks[0] = {
    ...input.evidenceLinks[0],
    artifactHash: '',
    status: 'pending',
    reviewedByHuman: false,
    phiBoundaryAttested: false,
  };
  input.findings[0] = {
    ...input.findings[0],
    confidenceBasisPoints: 10001,
    evidenceRefs: [],
    humanReadableFindingHash: '',
    recommendedHumanReviewerRole: '',
    requiresHumanReview: false,
  };

  const denied = runAiControlReview(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_advisory_disposition_invalid'));
  assert.ok(denied.reasons.includes('ai_review_not_logged'));
  assert.ok(denied.reasons.includes('ai_prompt_output_retention_absent'));
  assert.ok(denied.reasons.includes('ai_model_ref_hash_invalid'));
  assert.ok(denied.reasons.includes('ai_prompt_hash_invalid'));
  assert.ok(denied.reasons.includes('ai_output_hash_invalid'));
  assert.ok(denied.reasons.includes('ai_review_completed_before_start'));
  assert.ok(denied.reasons.includes('ai_scope_permission_invalid:write_raw_payload'));
  assert.ok(denied.reasons.includes('human_review_policy_absent'));
  assert.ok(denied.reasons.includes('human_review_roles_absent'));
  assert.ok(denied.reasons.includes('human_contestation_absent'));
  assert.ok(denied.reasons.includes('human_review_policy_allows_ai_final_authority'));
  assert.ok(denied.reasons.includes('evidence_artifact_hash_invalid:EVD-CONSENT-SOP-001'));
  assert.ok(denied.reasons.includes('evidence_not_approved:EVD-CONSENT-SOP-001'));
  assert.ok(denied.reasons.includes('evidence_human_review_absent:EVD-CONSENT-SOP-001'));
  assert.ok(denied.reasons.includes('evidence_phi_boundary_unattested:EVD-CONSENT-SOP-001'));
  assert.ok(denied.reasons.includes('finding_confidence_invalid:FIND-AI-CONSENT-001'));
  assert.ok(denied.reasons.includes('finding_evidence_refs_absent:FIND-AI-CONSENT-001'));
  assert.ok(denied.reasons.includes('finding_human_readable_hash_invalid:FIND-AI-CONSENT-001'));
  assert.ok(denied.reasons.includes('finding_reviewer_role_absent:FIND-AI-CONSENT-001'));
  assert.ok(denied.reasons.includes('finding_human_review_absent:FIND-AI-CONSENT-001'));
  assert.equal(denied.aiControlReview, null);
  assert.equal(denied.receipt, null);
});

test('AI control review rejects raw AI output finding text and protected source content', async () => {
  const { runAiControlReview } = await loadAiControlReview();

  assert.throws(
    () =>
      runAiControlReview({
        ...aiControlReviewInput(),
        review: { ...aiControlReviewInput().review, rawAiOutput: 'plain language output is not anchored' },
      }),
    /raw AI control review content field is not allowed/i,
  );

  assert.throws(
    () =>
      runAiControlReview({
        ...aiControlReviewInput(),
        findings: [{ ...aiControlReviewInput().findings[0], findingText: 'finding narrative is not anchored' }],
      }),
    /raw AI control review content field is not allowed/i,
  );

  assert.throws(
    () =>
      runAiControlReview({
        ...aiControlReviewInput(),
        evidenceLinks: [
          {
            ...aiControlReviewInput().evidenceLinks[0],
            sourceDocumentBody: 'Patient Alice Example consent source document body',
          },
        ],
      }),
    /protected content|raw AI control review content/i,
  );
});
