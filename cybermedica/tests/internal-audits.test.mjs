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

const DIGEST_A = '0a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef';
const DIGEST_B = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_C = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_D = '3333333333333333333333333333333333333333333333333333333333333333';
const DIGEST_E = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_F = '5555555555555555555555555555555555555555555555555555555555555555';

async function loadInternalAudits() {
  try {
    return await import('../src/internal-audits.mjs');
  } catch (error) {
    assert.fail(`CyberMedica internal audits module must exist and load: ${error.message}`);
  }
}

function evidence(controlId, evidenceRef, artifactHash, custodyDigest) {
  return {
    controlId,
    evidenceRef,
    artifactHash,
    custodyDigest,
    classification: 'audit_metadata_only',
    receiptRef: `cmr-${evidenceRef.toLowerCase()}`,
    reviewedByAuditor: true,
    phiBoundaryAttested: true,
  };
}

function finding(findingRef, controlId, severity, overrides = {}) {
  return {
    findingRef,
    controlId,
    severity,
    status: 'closed',
    riskRating: severity === 'critical' ? 'high' : 'medium',
    findingHash: DIGEST_C,
    ownerDid: 'did:exo:site-quality-owner-alpha',
    assignedAtHlc: { physicalMs: 1794100006000, logical: 1 },
    dueAtHlc: { physicalMs: 1794105000000, logical: 0 },
    correctedAtHlc: { physicalMs: 1794109000000, logical: 0 },
    closureEvidenceHash: DIGEST_D,
    trendCategoryHash: DIGEST_E,
    capaRequired: severity === 'critical' || severity === 'major',
    capaRef: severity === 'observation' ? null : `CAPA-${findingRef}`,
    managementResponseRef: `MGMT-${findingRef}`,
    ...overrides,
  };
}

function internalAuditInput() {
  return {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['govern', 'internal_audit'],
      authorityChainHash: DIGEST_A,
    },
    audit: {
      auditId: 'IA-SITE-ALPHA-2026-0001',
      auditType: 'internal',
      scopeRef: 'site-quality-system-annual-internal-audit',
      siteRef: 'site-alpha',
      protocolRef: 'protocol-cm-001',
      controlSetRef: 'CONTROL-SET-QMS-ISO-ICHS6-2026-01',
      objectiveHash: DIGEST_B,
      plannedAtHlc: { physicalMs: 1794100000000, logical: 0 },
      scheduledForHlc: { physicalMs: 1794100001000, logical: 0 },
      controlsSelected: ['CM-QMS-CONSENT-001', 'CM-QMS-DOC-001', 'CM-QMS-PRODUCT-001'],
    },
    auditorAssignment: {
      auditorDid: 'did:exo:independent-auditor-alpha',
      independenceStatus: 'independent',
      independenceEvidenceHash: DIGEST_C,
      assignedAtHlc: { physicalMs: 1794100000500, logical: 0 },
    },
    execution: {
      startedAtHlc: { physicalMs: 1794100002000, logical: 0 },
      completedAtHlc: { physicalMs: 1794100005000, logical: 0 },
      evidenceReviewed: [
        evidence('CM-QMS-CONSENT-001', 'EVD-IA-CONSENT-001', DIGEST_A, DIGEST_B),
        evidence('CM-QMS-DOC-001', 'EVD-IA-DOC-001', DIGEST_B, DIGEST_C),
        evidence('CM-QMS-PRODUCT-001', 'EVD-IA-PRODUCT-001', DIGEST_C, DIGEST_D),
      ],
      documentReviewRefs: ['DOC-SOP-CONSENT-V3', 'DOC-SOP-PRODUCT-V2'],
      recordReviewRefs: ['REC-DELEGATION-LOG-Q2', 'REC-TEMP-LOG-Q2'],
      interviewRequired: true,
      interviewRecords: [
        {
          interviewRef: 'INT-IA-PI-001',
          role: 'principal_investigator',
          interviewHash: DIGEST_E,
          conductedAtHlc: { physicalMs: 1794100004000, logical: 0 },
        },
        {
          interviewRef: 'INT-IA-QM-001',
          role: 'quality_manager',
          interviewHash: DIGEST_D,
          conductedAtHlc: { physicalMs: 1794100003000, logical: 0 },
        },
      ],
    },
    findings: [
      finding('FIND-IA-CONSENT-001', 'CM-QMS-CONSENT-001', 'major'),
      finding('FIND-IA-PRODUCT-001', 'CM-QMS-PRODUCT-001', 'critical', {
        riskRating: 'critical',
        findingHash: DIGEST_F,
        capaRef: 'CAPA-IA-PRODUCT-001',
      }),
      finding('FIND-IA-DOC-001', 'CM-QMS-DOC-001', 'observation', {
        riskRating: 'low',
        findingHash: DIGEST_A,
        capaRequired: false,
        capaRef: null,
      }),
    ],
    report: {
      draftReportHash: DIGEST_A,
      draftedAtHlc: { physicalMs: 1794110000000, logical: 0 },
      managementResponseHash: DIGEST_B,
      managementResponderDid: 'did:exo:site-director-alpha',
      managementResponseAtHlc: { physicalMs: 1794110005000, logical: 0 },
      finalReportHash: DIGEST_C,
      approvedByDid: 'did:exo:quality-manager-alpha',
      approvedAtHlc: { physicalMs: 1794110010000, logical: 0 },
      reportVersion: 'v1',
      locked: true,
    },
    closure: {
      closedByDid: 'did:exo:quality-manager-alpha',
      closedAtHlc: { physicalMs: 1794110020000, logical: 0 },
      closureEvidenceHash: DIGEST_D,
      evidenceBundle: { complete: true, phiBoundaryAttested: true },
      followUp: {
        required: true,
        status: 'complete',
        planHash: DIGEST_E,
        ownerDid: 'did:exo:site-quality-owner-alpha',
        dueAtHlc: { physicalMs: 1794115000000, logical: 0 },
        completedAtHlc: { physicalMs: 1794114000000, logical: 0 },
        evidenceHash: DIGEST_F,
      },
      exportEligibility: {
        eligible: true,
        exportProfileRef: 'sponsor-diligence-metadata-export',
        rationaleHash: DIGEST_A,
      },
    },
    custodyDigest: DIGEST_E,
  };
}

test('internal audit lifecycle locks report and creates deterministic inactive receipt', async () => {
  const { conductInternalAudit } = await loadInternalAudits();

  const resultA = conductInternalAudit(internalAuditInput());
  const resultB = conductInternalAudit({
    ...internalAuditInput(),
    audit: {
      ...internalAuditInput().audit,
      controlsSelected: [...internalAuditInput().audit.controlsSelected].reverse(),
    },
    execution: {
      ...internalAuditInput().execution,
      evidenceReviewed: [...internalAuditInput().execution.evidenceReviewed].reverse(),
      documentReviewRefs: [...internalAuditInput().execution.documentReviewRefs].reverse(),
      recordReviewRefs: [...internalAuditInput().execution.recordReviewRefs].reverse(),
      interviewRecords: [...internalAuditInput().execution.interviewRecords].reverse(),
    },
    findings: [...internalAuditInput().findings].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.internalAudit.auditLocked, true);
  assert.equal(resultA.internalAudit.auditClosed, true);
  assert.equal(resultA.internalAudit.auditType, 'internal');
  assert.equal(resultA.internalAudit.managementResponseObtained, true);
  assert.equal(resultA.internalAudit.finalReportApproved, true);
  assert.equal(resultA.internalAudit.exportEligible, true);
  assert.equal(resultA.internalAudit.followUpRequired, true);
  assert.equal(resultA.internalAudit.followUpStatus, 'complete');
  assert.equal(resultA.internalAudit.trustState, 'inactive');
  assert.equal(resultA.internalAudit.exochainProductionClaim, false);
  assert.deepEqual(resultA.internalAudit.controlsReviewed, [
    'CM-QMS-CONSENT-001',
    'CM-QMS-DOC-001',
    'CM-QMS-PRODUCT-001',
  ]);
  assert.deepEqual(resultA.internalAudit.findingSummary, {
    critical: 1,
    major: 1,
    minor: 0,
    observation: 1,
  });
  assert.deepEqual(resultA.internalAudit.requiredEscalationRoles, [
    'capa_owner',
    'decision_forum_chair',
    'site_quality_lead',
  ]);
  assert.deepEqual(resultA.internalAudit.capaRefs, ['CAPA-FIND-IA-CONSENT-001', 'CAPA-IA-PRODUCT-001']);
  assert.equal(resultA.internalAudit.auditRecordId, resultB.internalAudit.auditRecordId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'internal_audit_report');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.doesNotMatch(JSON.stringify(resultA), /participant alice|patient|interview transcript|raw report|source document/iu);
});

test('internal audit can close with no findings no interviews and documented no follow-up rationale', async () => {
  const { conductInternalAudit } = await loadInternalAudits();
  const input = internalAuditInput();
  input.audit.auditId = 'IA-SITE-ALPHA-2026-NO-FINDINGS';
  input.audit.controlsSelected = ['CM-QMS-DOC-001'];
  input.execution.evidenceReviewed = [evidence('CM-QMS-DOC-001', 'EVD-IA-DOC-ONLY-001', DIGEST_B, DIGEST_C)];
  input.execution.interviewRequired = false;
  input.execution.interviewRecords = [];
  input.findings = [];
  input.closure.followUp = {
    required: false,
    status: 'not_required',
    rationaleHash: DIGEST_D,
    ownerDid: 'did:exo:quality-manager-alpha',
  };
  input.closure.exportEligibility = {
    eligible: false,
    exportProfileRef: null,
    rationaleHash: DIGEST_E,
  };

  const result = conductInternalAudit(input);

  assert.equal(result.decision, 'permitted');
  assert.equal(result.internalAudit.findingCount, 0);
  assert.equal(result.internalAudit.followUpRequired, false);
  assert.equal(result.internalAudit.followUpStatus, 'not_required');
  assert.equal(result.internalAudit.exportEligible, false);
  assert.deepEqual(result.internalAudit.requiredEscalationRoles, []);
});

test('internal audit fails closed for plan execution finding report and closure defects', async () => {
  const { conductInternalAudit } = await loadInternalAudits();
  const input = internalAuditInput();
  input.targetTenantId = 'tenant-site-beta';
  input.actor = { did: 'did:exo:ai-auditor-alpha', kind: 'ai_agent' };
  input.authority = { valid: true, revoked: false, expired: false, permissions: ['read'], authorityChainHash: DIGEST_A };
  input.audit = {
    ...input.audit,
    auditId: '',
    auditType: 'sponsor',
    scopeRef: '',
    protocolRef: '',
    objectiveHash: 'not-a-digest',
    scheduledForHlc: { physicalMs: 1794090000000, logical: 0 },
    controlsSelected: [],
  };
  input.auditorAssignment = {
    auditorDid: '',
    independenceStatus: 'conflicted',
    independenceEvidenceHash: '',
    assignedAtHlc: { physicalMs: 1794090000000, logical: 0 },
  };
  input.execution = {
    ...input.execution,
    startedAtHlc: { physicalMs: 1794080000000, logical: 0 },
    completedAtHlc: { physicalMs: 1794070000000, logical: 0 },
    evidenceReviewed: [
      {
        controlId: '',
        evidenceRef: '',
        artifactHash: 'bad',
        custodyDigest: '0000000000000000000000000000000000000000000000000000000000000000',
        classification: 'raw_document',
        receiptRef: '',
        reviewedByAuditor: false,
        phiBoundaryAttested: false,
      },
    ],
    documentReviewRefs: [],
    recordReviewRefs: [],
    interviewRequired: true,
    interviewRecords: [],
  };
  input.findings = [
    {
      findingRef: '',
      controlId: 'CM-QMS-UNKNOWN',
      severity: 'critical',
      status: 'open',
      riskRating: 'unknown',
      findingHash: '',
      ownerDid: '',
      assignedAtHlc: { physicalMs: 1794109000000, logical: 0 },
      dueAtHlc: { physicalMs: 1794100000000, logical: 0 },
      correctedAtHlc: null,
      closureEvidenceHash: '',
      trendCategoryHash: '',
      capaRequired: false,
      capaRef: '',
      managementResponseRef: '',
    },
  ];
  input.report = {
    draftReportHash: '',
    draftedAtHlc: { physicalMs: 1794100000000, logical: 0 },
    managementResponseHash: '',
    managementResponderDid: '',
    managementResponseAtHlc: { physicalMs: 1794100000000, logical: 0 },
    finalReportHash: '',
    approvedByDid: '',
    approvedAtHlc: { physicalMs: 1794090000000, logical: 0 },
    reportVersion: '',
    locked: false,
  };
  input.closure = {
    closedByDid: '',
    closedAtHlc: { physicalMs: 1794080000000, logical: 0 },
    closureEvidenceHash: '',
    evidenceBundle: { complete: false, phiBoundaryAttested: false },
    followUp: { required: true, status: 'scheduled', planHash: '', ownerDid: '', dueAtHlc: { physicalMs: 1794070000000, logical: 0 } },
    exportEligibility: { eligible: true, exportProfileRef: '', rationaleHash: '' },
  };
  input.custodyDigest = '';

  const denied = conductInternalAudit(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('authority_permission_missing'));
  assert.ok(denied.reasons.includes('audit_id_absent'));
  assert.ok(denied.reasons.includes('audit_type_invalid'));
  assert.ok(denied.reasons.includes('audit_scope_absent'));
  assert.ok(denied.reasons.includes('audit_objective_hash_invalid'));
  assert.ok(denied.reasons.includes('audit_controls_selected_absent'));
  assert.ok(denied.reasons.includes('auditor_independence_invalid'));
  assert.ok(denied.reasons.includes('audit_started_before_schedule'));
  assert.ok(denied.reasons.includes('audit_completed_before_start'));
  assert.ok(denied.reasons.includes('evidence_artifact_hash_invalid:unknown'));
  assert.ok(denied.reasons.includes('evidence_custody_digest_invalid:unknown'));
  assert.ok(denied.reasons.includes('evidence_classification_invalid:unknown'));
  assert.ok(denied.reasons.includes('document_review_refs_absent'));
  assert.ok(denied.reasons.includes('record_review_refs_absent'));
  assert.ok(denied.reasons.includes('interview_records_absent'));
  assert.ok(denied.reasons.includes('finding_ref_absent'));
  assert.ok(denied.reasons.includes('finding_control_unknown:unknown'));
  assert.ok(denied.reasons.includes('finding_open:unknown'));
  assert.ok(denied.reasons.includes('finding_capa_required_invalid:unknown'));
  assert.ok(denied.reasons.includes('draft_report_hash_invalid'));
  assert.ok(denied.reasons.includes('management_response_hash_invalid'));
  assert.ok(denied.reasons.includes('final_report_hash_invalid'));
  assert.ok(denied.reasons.includes('final_report_not_locked'));
  assert.ok(denied.reasons.includes('closure_evidence_hash_invalid'));
  assert.ok(denied.reasons.includes('closure_evidence_bundle_incomplete'));
  assert.ok(denied.reasons.includes('follow_up_plan_hash_invalid'));
  assert.ok(denied.reasons.includes('export_profile_ref_absent'));
  assert.ok(denied.reasons.includes('custody_digest_invalid'));
  assert.equal(denied.internalAudit, null);
  assert.equal(denied.receipt, null);

  const missingFollowUpDisposition = conductInternalAudit({
    ...internalAuditInput(),
    closure: {
      ...internalAuditInput().closure,
      followUp: { status: 'scheduled' },
    },
  });

  assert.equal(missingFollowUpDisposition.decision, 'denied');
  assert.ok(missingFollowUpDisposition.reasons.includes('follow_up_requirement_invalid'));
});

test('internal audit validates same-tick HLC ordering and scheduled follow-up branches', async () => {
  const { conductInternalAudit } = await loadInternalAudits();
  const input = internalAuditInput();
  input.audit.plannedAtHlc = { physicalMs: 1794100000000, logical: 0 };
  input.audit.scheduledForHlc = { physicalMs: 1794100000000, logical: 1 };
  input.auditorAssignment.assignedAtHlc = { physicalMs: 1794100000000, logical: 1 };
  input.execution.startedAtHlc = { physicalMs: 1794100000000, logical: 2 };
  input.execution.completedAtHlc = { physicalMs: 1794100000000, logical: 3 };
  input.execution.interviewRecords[0].conductedAtHlc = { physicalMs: 1794100000000, logical: 2 };
  input.execution.interviewRecords[1].conductedAtHlc = { physicalMs: 1794100000000, logical: 2 };
  input.report.draftedAtHlc = { physicalMs: 1794100000000, logical: 4 };
  input.report.managementResponseAtHlc = { physicalMs: 1794100000000, logical: 5 };
  input.report.approvedAtHlc = { physicalMs: 1794100000000, logical: 6 };
  input.closure.closedAtHlc = { physicalMs: 1794100000000, logical: 7 };
  input.closure.followUp.status = 'scheduled';
  input.closure.followUp.dueAtHlc = { physicalMs: 1794100000000, logical: 8 };
  delete input.closure.followUp.completedAtHlc;
  delete input.closure.followUp.evidenceHash;

  const result = conductInternalAudit(input);

  assert.equal(result.decision, 'permitted');
  assert.equal(result.internalAudit.followUpStatus, 'scheduled');
  assert.equal(result.internalAudit.followUpRequired, true);

  input.report.approvedAtHlc = { physicalMs: 1794100000000, logical: 5 };
  const denied = conductInternalAudit(input);
  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('report_approved_before_management_response'));
});

test('internal audit rejects raw audit report finding management response and interview content', async () => {
  const { conductInternalAudit } = await loadInternalAudits();

  assert.throws(
    () =>
      conductInternalAudit({
        ...internalAuditInput(),
        report: {
          ...internalAuditInput().report,
          rawReportText: 'Participant Alice Example appears in a raw report.',
        },
      }),
    /raw internal audit content field is not allowed/u,
  );

  assert.throws(
    () =>
      conductInternalAudit({
        ...internalAuditInput(),
        findings: [
          {
            ...internalAuditInput().findings[0],
            findingText: 'source document body copied here',
          },
        ],
      }),
    /raw internal audit content field is not allowed/u,
  );
});
