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

async function loadSiteSelfAssessments() {
  try {
    return await import('../src/site-self-assessments.mjs');
  } catch (error) {
    assert.fail(`CyberMedica site self-assessments module must exist and load: ${error.message}`);
  }
}

function controlEvidence(controlId, index) {
  return {
    evidenceRef: `EVD-${controlId}-${index}`,
    artifactHash: index % 2 === 0 ? DIGEST_A : DIGEST_B,
    custodyDigest: index % 2 === 0 ? DIGEST_C : DIGEST_D,
    status: 'approved',
    fresh: true,
    classification: 'confidential_metadata_only',
    receiptRef: `cmr-${controlId.toLowerCase()}-${index}`,
  };
}

function controlEvaluation(controlId, index) {
  return {
    controlId,
    applicability: 'applicable',
    evidenceRefs: [`EVD-${controlId}-${index}`],
    ownerDid: `did:exo:${controlId.toLowerCase()}-owner`,
    reviewerDid: `did:exo:${controlId.toLowerCase()}-reviewer`,
    reviewerDecision: index === 1 ? 'accept_with_findings' : 'accept',
    commentHash: index % 2 === 0 ? DIGEST_D : DIGEST_E,
    recommendationHash: index % 2 === 0 ? DIGEST_E : DIGEST_A,
    evidenceComplete: true,
    phiBoundaryAttested: true,
    reviewedAtHlc: { physicalMs: 1793000002000 + index, logical: index },
  };
}

function siteAssessmentInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:assessment-manager-alpha', kind: 'human' },
    authority: { valid: true, revoked: false, expired: false, permissions: ['govern'] },
    assessment: {
      assessmentId: 'ASSESS-SITE-ALPHA-2026-0001',
      assessmentType: 'self_assessment',
      siteRef: 'site-alpha',
      controlSetRef: 'CONTROL-SET-QMS-ISO-ICHS6-2026-01',
      workspaceRef: 'assessment-workspace-site-alpha-0001',
      selectedAtHlc: { physicalMs: 1793000000000, logical: 1 },
      generatedAtHlc: { physicalMs: 1793000001000, logical: 1 },
      closedAtHlc: { physicalMs: 1793000010000, logical: 2 },
    },
    controlOwners: [
      { controlId: 'CM-QMS-DOC-001', ownerDid: 'did:exo:cm-qms-doc-001-owner', assignedAtHlc: { physicalMs: 1793000001100, logical: 0 } },
      {
        controlId: 'CM-QMS-CONSENT-001',
        ownerDid: 'did:exo:cm-qms-consent-001-owner',
        assignedAtHlc: { physicalMs: 1793000001200, logical: 0 },
      },
      {
        controlId: 'CM-QMS-CALIBRATION-001',
        ownerDid: 'did:exo:cm-qms-calibration-001-owner',
        assignedAtHlc: { physicalMs: 1793000001300, logical: 0 },
      },
    ],
    reviewers: [
      { controlId: 'CM-QMS-DOC-001', reviewerDid: 'did:exo:cm-qms-doc-001-reviewer', role: 'control_reviewer' },
      { controlId: 'CM-QMS-CONSENT-001', reviewerDid: 'did:exo:cm-qms-consent-001-reviewer', role: 'control_reviewer' },
      { controlId: 'CM-QMS-CALIBRATION-001', reviewerDid: 'did:exo:cm-qms-calibration-001-reviewer', role: 'control_reviewer' },
      { controlId: '*', reviewerDid: 'did:exo:assessment-manager-alpha', role: 'assessment_manager' },
    ],
    controlEvaluations: [
      controlEvaluation('CM-QMS-DOC-001', 0),
      controlEvaluation('CM-QMS-CONSENT-001', 1),
      {
        ...controlEvaluation('CM-QMS-CALIBRATION-001', 2),
        applicability: 'not_applicable',
        notApplicableRationaleHash: DIGEST_B,
        reviewerDecision: 'not_applicable',
      },
    ],
    evidenceInventory: [
      controlEvidence('CM-QMS-DOC-001', 0),
      controlEvidence('CM-QMS-CONSENT-001', 1),
      controlEvidence('CM-QMS-CALIBRATION-001', 2),
    ],
    aiEvidenceReview: {
      completed: true,
      advisoryOnly: true,
      finalAuthority: false,
      outputHash: DIGEST_A,
      reviewedControlIds: ['CM-QMS-DOC-001', 'CM-QMS-CONSENT-001', 'CM-QMS-CALIBRATION-001'],
      unresolvedMissingEvidence: [],
    },
    findings: [
      {
        findingRef: 'FIND-ASSESS-001',
        controlId: 'CM-QMS-CONSENT-001',
        severity: 'major',
        status: 'accepted',
        findingHash: DIGEST_C,
        ownerDid: 'did:exo:quality-manager-alpha',
        capaRequired: true,
        capaRef: 'CAPA-ASSESS-001',
      },
      {
        findingRef: 'FIND-ASSESS-002',
        controlId: 'CM-QMS-DOC-001',
        severity: 'observation',
        status: 'closed',
        findingHash: DIGEST_D,
        ownerDid: 'did:exo:document-owner-alpha',
        capaRequired: false,
      },
    ],
    assessmentManagerClose: {
      decision: 'close_with_conditions',
      managerDid: 'did:exo:assessment-manager-alpha',
      humanVerified: true,
      rationaleHash: DIGEST_E,
      closedAtHlc: { physicalMs: 1793000010000, logical: 2 },
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
    },
    lockedReport: {
      locked: true,
      reportHash: DIGEST_B,
      lockedByDid: 'did:exo:assessment-manager-alpha',
      lockedAtHlc: { physicalMs: 1793000011000, logical: 0 },
      reportVersion: 'v1',
    },
    sitePassportUpdate: {
      passportRef: 'QMS-PASSPORT-SITE-ALPHA-2026-0001',
      status: 'applied',
      updateHash: DIGEST_A,
      updateReceiptRef: 'cmr-site-passport-update-assess-0001',
    },
    custodyDigest: DIGEST_E,
  };
}

test('site self-assessment closes review locks report updates passport and creates deterministic inactive receipt', async () => {
  const { closeSiteAssessment } = await loadSiteSelfAssessments();

  const resultA = closeSiteAssessment(siteAssessmentInput());
  const resultB = closeSiteAssessment({
    ...siteAssessmentInput(),
    controlOwners: [...siteAssessmentInput().controlOwners].reverse(),
    reviewers: [...siteAssessmentInput().reviewers].reverse(),
    controlEvaluations: [...siteAssessmentInput().controlEvaluations].reverse(),
    evidenceInventory: [...siteAssessmentInput().evidenceInventory].reverse(),
    findings: [...siteAssessmentInput().findings].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.assessmentReport.assessmentClosed, true);
  assert.equal(resultA.assessmentReport.lockedReport, true);
  assert.equal(resultA.assessmentReport.sitePassportUpdated, true);
  assert.equal(resultA.assessmentReport.assessmentType, 'self_assessment');
  assert.equal(resultA.assessmentReport.aiFinalAuthority, false);
  assert.equal(resultA.assessmentReport.exochainProductionClaim, false);
  assert.equal(resultA.assessmentReport.trustState, 'inactive');
  assert.equal(resultA.assessmentReport.evidenceCompletenessBasisPoints, 10000);
  assert.equal(resultA.assessmentReport.evidenceFreshnessBasisPoints, 10000);
  assert.deepEqual(resultA.assessmentReport.findingSummary, { critical: 0, major: 1, minor: 0, observation: 0 });
  assert.deepEqual(resultA.assessmentReport.requiredEscalationRoles, ['site_quality_lead']);
  assert.deepEqual(resultA.assessmentReport.controlIds, ['CM-QMS-CALIBRATION-001', 'CM-QMS-CONSENT-001', 'CM-QMS-DOC-001']);
  assert.equal(resultA.assessmentReport.reportId, resultB.assessmentReport.reportId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'site_self_assessment_report');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /participant name|source document body|raw assessment|review narrative|direct identifier/iu);
});

test('external assessments require an external reviewer assignment before report lock', async () => {
  const { closeSiteAssessment } = await loadSiteSelfAssessments();
  const input = siteAssessmentInput();
  input.assessment = {
    ...input.assessment,
    assessmentId: 'ASSESS-SITE-ALPHA-EXTERNAL-2026-0001',
    assessmentType: 'external_assessment',
  };
  input.reviewers = [
    ...input.reviewers,
    { controlId: '*', reviewerDid: 'did:exo:sponsor-auditor-alpha', role: 'external_reviewer' },
  ];
  input.lockedReport.reportHash = DIGEST_C;

  const result = closeSiteAssessment(input);

  assert.equal(result.decision, 'permitted');
  assert.equal(result.assessmentReport.assessmentType, 'external_assessment');
  assert.equal(result.assessmentReport.externalReviewerDids[0], 'did:exo:sponsor-auditor-alpha');
  assert.equal(result.assessmentReport.lockedReport, true);
});

test('site self-assessment fails closed for missing evidence not-applicable rationale reviewers and CAPA defects', async () => {
  const { closeSiteAssessment } = await loadSiteSelfAssessments();
  const input = siteAssessmentInput();
  input.evidenceInventory[0] = {
    ...input.evidenceInventory[0],
    status: 'pending',
    fresh: false,
    artifactHash: 'not-a-digest',
  };
  input.controlEvaluations[1] = {
    ...input.controlEvaluations[1],
    reviewerDid: '',
    evidenceRefs: ['EVD-MISSING-001'],
    evidenceComplete: false,
    phiBoundaryAttested: false,
  };
  input.controlEvaluations[2] = {
    ...input.controlEvaluations[2],
    notApplicableRationaleHash: '',
  };
  input.findings = [
    {
      findingRef: 'FIND-ASSESS-CRITICAL-001',
      controlId: 'CM-QMS-CONSENT-001',
      severity: 'critical',
      status: 'open',
      findingHash: '',
      ownerDid: '',
      capaRequired: true,
      capaRef: '',
    },
  ];

  const denied = closeSiteAssessment(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.assessmentReport.assessmentClosed, false);
  assert.equal(denied.assessmentReport.lockedReport, false);
  assert.ok(denied.reasons.includes('evidence_not_approved:EVD-CM-QMS-DOC-001-0'));
  assert.ok(denied.reasons.includes('evidence_stale:EVD-CM-QMS-DOC-001-0'));
  assert.ok(denied.reasons.includes('evidence_hash_invalid:EVD-CM-QMS-DOC-001-0'));
  assert.ok(denied.reasons.includes('control_evidence_missing:CM-QMS-CONSENT-001:EVD-MISSING-001'));
  assert.ok(denied.reasons.includes('control_reviewer_absent:CM-QMS-CONSENT-001'));
  assert.ok(denied.reasons.includes('control_evidence_incomplete:CM-QMS-CONSENT-001'));
  assert.ok(denied.reasons.includes('control_phi_boundary_unattested:CM-QMS-CONSENT-001'));
  assert.ok(denied.reasons.includes('not_applicable_rationale_absent:CM-QMS-CALIBRATION-001'));
  assert.ok(denied.reasons.includes('critical_finding_unresolved:FIND-ASSESS-CRITICAL-001'));
  assert.ok(denied.reasons.includes('finding_hash_invalid:FIND-ASSESS-CRITICAL-001'));
  assert.ok(denied.reasons.includes('finding_owner_absent:FIND-ASSESS-CRITICAL-001'));
  assert.ok(denied.reasons.includes('finding_capa_ref_absent:FIND-ASSESS-CRITICAL-001'));
  assert.equal(denied.receipt, undefined);
});

test('site self-assessment denies tenant authority AI closure lock and passport update defects', async () => {
  const { closeSiteAssessment } = await loadSiteSelfAssessments();
  const input = siteAssessmentInput();
  input.targetTenantId = 'tenant-site-beta';
  input.actor = { did: 'did:exo:ai-assessment-reviewer-alpha', kind: 'ai_agent' };
  input.authority = { valid: true, revoked: false, expired: false, permissions: ['read'] };
  input.aiEvidenceReview = {
    completed: false,
    advisoryOnly: false,
    finalAuthority: true,
    outputHash: 'bad',
    reviewedControlIds: ['CM-QMS-DOC-001'],
    unresolvedMissingEvidence: ['CM-QMS-CONSENT-001'],
  };
  input.assessmentManagerClose = {
    decision: 'reject',
    managerDid: '',
    humanVerified: false,
    rationaleHash: '',
    closedAtHlc: { physicalMs: 1792999999999, logical: 1 },
    evidenceBundle: { complete: false, phiBoundaryAttested: false },
  };
  input.lockedReport = {
    locked: false,
    reportHash: 'bad',
    lockedByDid: '',
    lockedAtHlc: { physicalMs: 1792999999999, logical: 0 },
    reportVersion: '',
  };
  input.sitePassportUpdate = {
    passportRef: '',
    status: 'queued',
    updateHash: '',
    updateReceiptRef: '',
  };

  const denied = closeSiteAssessment(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_evidence_review_incomplete'));
  assert.ok(denied.reasons.includes('ai_evidence_review_must_be_advisory'));
  assert.ok(denied.reasons.includes('ai_evidence_review_output_invalid'));
  assert.ok(denied.reasons.includes('ai_unresolved_missing_evidence_present'));
  assert.ok(denied.reasons.includes('assessment_close_rejected'));
  assert.ok(denied.reasons.includes('assessment_manager_absent'));
  assert.ok(denied.reasons.includes('assessment_manager_human_unverified'));
  assert.ok(denied.reasons.includes('assessment_close_before_workspace_generation'));
  assert.ok(denied.reasons.includes('evidence_bundle_incomplete'));
  assert.ok(denied.reasons.includes('phi_boundary_unattested'));
  assert.ok(denied.reasons.includes('assessment_report_not_locked'));
  assert.ok(denied.reasons.includes('locked_report_hash_invalid'));
  assert.ok(denied.reasons.includes('locked_report_actor_absent'));
  assert.ok(denied.reasons.includes('locked_report_before_close'));
  assert.ok(denied.reasons.includes('locked_report_version_absent'));
  assert.ok(denied.reasons.includes('site_passport_ref_absent'));
  assert.ok(denied.reasons.includes('site_passport_update_not_applied'));
  assert.ok(denied.reasons.includes('site_passport_update_hash_invalid'));
  assert.ok(denied.reasons.includes('site_passport_update_receipt_absent'));
});

test('site self-assessment rejects raw reviewer text and protected source content before receipt creation', async () => {
  const { closeSiteAssessment } = await loadSiteSelfAssessments();

  assert.throws(
    () =>
      closeSiteAssessment({
        ...siteAssessmentInput(),
        controlEvaluations: [
          {
            ...siteAssessmentInput().controlEvaluations[0],
            reviewerCommentText: 'Raw review narrative and source document body must stay out of the assessment receipt.',
          },
        ],
      }),
    /protected content|raw assessment/i,
  );
});

test('site self-assessment fails closed instead of throwing when required objects are absent', async () => {
  const { closeSiteAssessment } = await loadSiteSelfAssessments();

  const denied = closeSiteAssessment({});

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.assessmentReport.assessmentClosed, false);
  assert.equal(denied.assessmentReport.lockedReport, false);
  assert.equal(denied.assessmentReport.sitePassportUpdated, false);
  assert.equal(denied.assessmentReport.evidenceCompletenessBasisPoints, 0);
  assert.equal(denied.assessmentReport.evidenceFreshnessBasisPoints, 0);
  assert.ok(denied.reasons.includes('tenant_absent'));
  assert.ok(denied.reasons.includes('actor_did_absent'));
  assert.ok(denied.reasons.includes('assessment_id_absent'));
  assert.ok(denied.reasons.includes('control_evaluations_absent'));
  assert.ok(denied.reasons.includes('evidence_inventory_absent'));
  assert.ok(denied.reasons.includes('assessment_close_decision_invalid'));
  assert.ok(denied.reasons.includes('assessment_report_not_locked'));
  assert.ok(denied.reasons.includes('site_passport_update_not_applied'));
  assert.equal(denied.receipt, undefined);
});
