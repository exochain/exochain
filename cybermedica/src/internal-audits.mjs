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

import { canonicalize, createEvidenceReceipt, ProtectedContentError, sha256Hex } from './qms-contracts.mjs';

const HEX_64 = /^[0-9a-f]{64}$/u;
const REQUIRED_PERMISSION = 'internal_audit';
const AUDIT_TYPES = new Set(['internal']);
const INDEPENDENCE_STATUSES = new Set(['independent']);
const EVIDENCE_CLASSIFICATIONS = new Set([
  'audit_metadata_only',
  'confidential_metadata_only',
  'qms_metadata_only',
  'restricted_metadata_only',
  'sponsor_confidential_metadata_only',
]);
const FINDING_SEVERITIES = new Set(['critical', 'major', 'minor', 'observation']);
const FINDING_STATUSES = new Set(['closed']);
const RISK_RATINGS = new Set(['critical', 'high', 'medium', 'low']);
const FOLLOW_UP_STATUSES = new Set(['complete', 'scheduled']);
const RAW_INTERNAL_AUDIT_FIELDS = new Set([
  'findingnarrative',
  'findingtext',
  'freeformfinding',
  'interviewnotes',
  'interviewtranscript',
  'managementresponsetext',
  'rawauditreport',
  'rawfinding',
  'rawinterview',
  'rawmanagementresponse',
  'rawreport',
  'rawreporttext',
  'rawsource',
  'rawsourcedocument',
  'reportnarrative',
  'responsetext',
  'sourcedocument',
  'sourcedocumentbody',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoRawInternalAuditText(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawInternalAuditText(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (RAW_INTERNAL_AUDIT_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw internal audit content field is not allowed at ${path}.${key}`);
    }
    assertNoRawInternalAuditText(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawInternalAuditText(input ?? {});
  canonicalize(input ?? {});
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical) && hlc.logical >= 0;
}

function compareHlc(left, right) {
  if (left.physicalMs !== right.physicalMs) {
    return left.physicalMs - right.physicalMs;
  }
  return left.logical - right.logical;
}

function sortedTextList(value) {
  return Array.isArray(value) ? value.filter(hasText).sort() : [];
}

function uniqueSorted(value) {
  return [...new Set(value.filter(hasText))].sort();
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'authority_permission_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateAuditPlan(input, reasons) {
  const audit = input?.audit;
  const controlsSelected = sortedTextList(audit?.controlsSelected);
  addReason(reasons, !hasText(audit?.auditId), 'audit_id_absent');
  addReason(reasons, !AUDIT_TYPES.has(audit?.auditType), 'audit_type_invalid');
  addReason(reasons, !hasText(audit?.scopeRef), 'audit_scope_absent');
  addReason(reasons, !hasText(audit?.siteRef), 'audit_site_ref_absent');
  addReason(reasons, !hasText(audit?.protocolRef), 'audit_protocol_ref_absent');
  addReason(reasons, !hasText(audit?.controlSetRef), 'audit_control_set_ref_absent');
  addReason(reasons, !isDigest(audit?.objectiveHash), 'audit_objective_hash_invalid');
  addReason(reasons, !hlcPresent(audit?.plannedAtHlc), 'audit_planned_time_invalid');
  addReason(reasons, !hlcPresent(audit?.scheduledForHlc), 'audit_schedule_time_invalid');
  addReason(
    reasons,
    hlcPresent(audit?.plannedAtHlc) && hlcPresent(audit?.scheduledForHlc) && compareHlc(audit.scheduledForHlc, audit.plannedAtHlc) <= 0,
    'audit_scheduled_before_plan',
  );
  addReason(reasons, controlsSelected.length === 0, 'audit_controls_selected_absent');
  return controlsSelected;
}

function evaluateAuditorAssignment(input, reasons) {
  const assignment = input?.auditorAssignment;
  addReason(reasons, !hasText(assignment?.auditorDid), 'auditor_did_absent');
  addReason(reasons, !INDEPENDENCE_STATUSES.has(assignment?.independenceStatus), 'auditor_independence_invalid');
  addReason(reasons, !isDigest(assignment?.independenceEvidenceHash), 'auditor_independence_evidence_invalid');
  addReason(reasons, !hlcPresent(assignment?.assignedAtHlc), 'auditor_assignment_time_invalid');
  addReason(
    reasons,
    hlcPresent(assignment?.assignedAtHlc) &&
      hlcPresent(input?.audit?.plannedAtHlc) &&
      compareHlc(assignment.assignedAtHlc, input.audit.plannedAtHlc) < 0,
    'auditor_assigned_before_plan',
  );
}

function evidenceSort(left, right) {
  return String(left.controlId).localeCompare(String(right.controlId)) || String(left.evidenceRef).localeCompare(String(right.evidenceRef));
}

function interviewSort(left, right) {
  return String(left.interviewRef).localeCompare(String(right.interviewRef));
}

function normalizeEvidenceReviewed(input, controlsSelected, reasons) {
  const selectedControls = new Set(controlsSelected);
  const evidenceReviewed = Array.isArray(input?.execution?.evidenceReviewed) ? [...input.execution.evidenceReviewed].sort(evidenceSort) : [];
  addReason(reasons, evidenceReviewed.length === 0, 'evidence_reviewed_absent');

  const normalizedEvidence = evidenceReviewed.map((evidence) => {
    const evidenceRef = hasText(evidence?.evidenceRef) ? evidence.evidenceRef : 'unknown';
    const controlId = hasText(evidence?.controlId) ? evidence.controlId : 'unknown';
    addReason(reasons, !hasText(evidence?.evidenceRef), 'evidence_ref_absent');
    addReason(reasons, !hasText(evidence?.controlId), `evidence_control_id_absent:${evidenceRef}`);
    addReason(reasons, hasText(controlId) && controlId !== 'unknown' && !selectedControls.has(controlId), `evidence_control_not_selected:${evidenceRef}`);
    addReason(reasons, !isDigest(evidence?.artifactHash), `evidence_artifact_hash_invalid:${evidenceRef}`);
    addReason(reasons, !isDigest(evidence?.custodyDigest), `evidence_custody_digest_invalid:${evidenceRef}`);
    addReason(reasons, !EVIDENCE_CLASSIFICATIONS.has(evidence?.classification), `evidence_classification_invalid:${evidenceRef}`);
    addReason(reasons, !hasText(evidence?.receiptRef), `evidence_receipt_absent:${evidenceRef}`);
    addReason(reasons, evidence?.reviewedByAuditor !== true, `evidence_not_reviewed_by_auditor:${evidenceRef}`);
    addReason(reasons, evidence?.phiBoundaryAttested !== true, `evidence_phi_boundary_unattested:${evidenceRef}`);
    return {
      artifactHash: evidence?.artifactHash ?? null,
      classification: evidence?.classification ?? null,
      controlId,
      custodyDigest: evidence?.custodyDigest ?? null,
      evidenceRef,
      receiptRef: evidence?.receiptRef ?? null,
    };
  });

  const reviewedControls = new Set(normalizedEvidence.map((evidence) => evidence.controlId).filter((controlId) => controlId !== 'unknown'));
  for (const controlId of controlsSelected) {
    addReason(reasons, !reviewedControls.has(controlId), `selected_control_not_reviewed:${controlId}`);
  }

  return normalizedEvidence;
}

function normalizeInterviewRecords(input, reasons) {
  const records = Array.isArray(input?.execution?.interviewRecords) ? [...input.execution.interviewRecords].sort(interviewSort) : [];
  addReason(reasons, input?.execution?.interviewRequired === true && records.length === 0, 'interview_records_absent');
  addReason(reasons, typeof input?.execution?.interviewRequired !== 'boolean', 'interview_requirement_invalid');

  return records.map((record) => {
    const interviewRef = hasText(record?.interviewRef) ? record.interviewRef : 'unknown';
    addReason(reasons, !hasText(record?.interviewRef), 'interview_ref_absent');
    addReason(reasons, !hasText(record?.role), `interview_role_absent:${interviewRef}`);
    addReason(reasons, !isDigest(record?.interviewHash), `interview_hash_invalid:${interviewRef}`);
    addReason(reasons, !hlcPresent(record?.conductedAtHlc), `interview_time_invalid:${interviewRef}`);
    addReason(
      reasons,
      hlcPresent(record?.conductedAtHlc) &&
        hlcPresent(input?.execution?.startedAtHlc) &&
        compareHlc(record.conductedAtHlc, input.execution.startedAtHlc) < 0,
      `interview_before_audit_start:${interviewRef}`,
    );
    addReason(
      reasons,
      hlcPresent(record?.conductedAtHlc) &&
        hlcPresent(input?.execution?.completedAtHlc) &&
        compareHlc(record.conductedAtHlc, input.execution.completedAtHlc) > 0,
      `interview_after_audit_completion:${interviewRef}`,
    );
    return {
      conductedAtHlc: record?.conductedAtHlc ?? null,
      interviewHash: record?.interviewHash ?? null,
      interviewRef,
      role: record?.role ?? null,
    };
  });
}

function evaluateExecution(input, reasons) {
  const execution = input?.execution;
  addReason(reasons, !hlcPresent(execution?.startedAtHlc), 'audit_started_time_invalid');
  addReason(reasons, !hlcPresent(execution?.completedAtHlc), 'audit_completed_time_invalid');
  addReason(
    reasons,
    hlcPresent(execution?.startedAtHlc) &&
      hlcPresent(input?.audit?.scheduledForHlc) &&
      compareHlc(execution.startedAtHlc, input.audit.scheduledForHlc) < 0,
    'audit_started_before_schedule',
  );
  addReason(
    reasons,
    hlcPresent(execution?.startedAtHlc) &&
      hlcPresent(execution?.completedAtHlc) &&
      compareHlc(execution.completedAtHlc, execution.startedAtHlc) <= 0,
    'audit_completed_before_start',
  );

  const documentReviewRefs = sortedTextList(execution?.documentReviewRefs);
  const recordReviewRefs = sortedTextList(execution?.recordReviewRefs);
  addReason(reasons, documentReviewRefs.length === 0, 'document_review_refs_absent');
  addReason(reasons, recordReviewRefs.length === 0, 'record_review_refs_absent');

  return { documentReviewRefs, recordReviewRefs };
}

function findingSort(left, right) {
  return String(left.findingRef).localeCompare(String(right.findingRef));
}

function findingRequiresCapa(finding) {
  return finding?.severity === 'critical' || finding?.severity === 'major' || finding?.capaRequired === true;
}

function normalizeFindings(input, controlsSelected, reasons) {
  const selectedControls = new Set(controlsSelected);
  const findings = Array.isArray(input?.findings) ? [...input.findings].sort(findingSort) : [];

  return findings.map((finding) => {
    const findingRef = hasText(finding?.findingRef) ? finding.findingRef : 'unknown';
    const controlId = hasText(finding?.controlId) ? finding.controlId : 'unknown';
    addReason(reasons, !hasText(finding?.findingRef), 'finding_ref_absent');
    addReason(reasons, !hasText(finding?.controlId), `finding_control_absent:${findingRef}`);
    addReason(reasons, !selectedControls.has(controlId), `finding_control_unknown:${findingRef}`);
    addReason(reasons, !FINDING_SEVERITIES.has(finding?.severity), `finding_severity_invalid:${findingRef}`);
    addReason(reasons, !FINDING_STATUSES.has(finding?.status), `finding_open:${findingRef}`);
    addReason(reasons, !RISK_RATINGS.has(finding?.riskRating), `finding_risk_rating_invalid:${findingRef}`);
    addReason(reasons, !isDigest(finding?.findingHash), `finding_hash_invalid:${findingRef}`);
    addReason(reasons, !hasText(finding?.ownerDid), `finding_owner_absent:${findingRef}`);
    addReason(reasons, !hlcPresent(finding?.assignedAtHlc), `finding_assignment_time_invalid:${findingRef}`);
    addReason(reasons, !hlcPresent(finding?.dueAtHlc), `finding_due_time_invalid:${findingRef}`);
    addReason(
      reasons,
      hlcPresent(finding?.assignedAtHlc) && hlcPresent(finding?.dueAtHlc) && compareHlc(finding.dueAtHlc, finding.assignedAtHlc) <= 0,
      `finding_due_before_assignment:${findingRef}`,
    );
    addReason(reasons, !hlcPresent(finding?.correctedAtHlc), `finding_corrected_time_invalid:${findingRef}`);
    addReason(
      reasons,
      hlcPresent(finding?.assignedAtHlc) &&
        hlcPresent(finding?.correctedAtHlc) &&
        compareHlc(finding.correctedAtHlc, finding.assignedAtHlc) <= 0,
      `finding_corrected_before_assignment:${findingRef}`,
    );
    addReason(reasons, !isDigest(finding?.closureEvidenceHash), `finding_closure_evidence_invalid:${findingRef}`);
    addReason(reasons, !isDigest(finding?.trendCategoryHash), `finding_trend_category_invalid:${findingRef}`);
    addReason(reasons, typeof finding?.capaRequired !== 'boolean', `finding_capa_flag_invalid:${findingRef}`);
    addReason(reasons, findingRequiresCapa(finding) && finding?.capaRequired !== true, `finding_capa_required_invalid:${findingRef}`);
    addReason(reasons, findingRequiresCapa(finding) && !hasText(finding?.capaRef), `finding_capa_ref_absent:${findingRef}`);
    addReason(reasons, !hasText(finding?.managementResponseRef), `finding_management_response_ref_absent:${findingRef}`);

    return {
      capaRef: finding?.capaRef ?? null,
      capaRequired: finding?.capaRequired === true,
      closureEvidenceHash: finding?.closureEvidenceHash ?? null,
      controlId,
      correctedAtHlc: finding?.correctedAtHlc ?? null,
      findingHash: finding?.findingHash ?? null,
      findingRef,
      managementResponseRef: finding?.managementResponseRef ?? null,
      ownerDid: finding?.ownerDid ?? null,
      riskRating: finding?.riskRating ?? null,
      severity: finding?.severity ?? null,
      status: finding?.status ?? null,
      trendCategoryHash: finding?.trendCategoryHash ?? null,
    };
  });
}

function findingSummary(findings) {
  return {
    critical: findings.filter((finding) => finding.severity === 'critical').length,
    major: findings.filter((finding) => finding.severity === 'major').length,
    minor: findings.filter((finding) => finding.severity === 'minor').length,
    observation: findings.filter((finding) => finding.severity === 'observation').length,
  };
}

function evaluateReport(input, reasons) {
  const report = input?.report;
  addReason(reasons, !isDigest(report?.draftReportHash), 'draft_report_hash_invalid');
  addReason(reasons, !hlcPresent(report?.draftedAtHlc), 'report_drafted_time_invalid');
  addReason(
    reasons,
    hlcPresent(report?.draftedAtHlc) &&
      hlcPresent(input?.execution?.completedAtHlc) &&
      compareHlc(report.draftedAtHlc, input.execution.completedAtHlc) <= 0,
    'report_drafted_before_audit_completion',
  );
  addReason(reasons, !isDigest(report?.managementResponseHash), 'management_response_hash_invalid');
  addReason(reasons, !hasText(report?.managementResponderDid), 'management_responder_absent');
  addReason(reasons, !hlcPresent(report?.managementResponseAtHlc), 'management_response_time_invalid');
  addReason(
    reasons,
    hlcPresent(report?.managementResponseAtHlc) &&
      hlcPresent(report?.draftedAtHlc) &&
      compareHlc(report.managementResponseAtHlc, report.draftedAtHlc) <= 0,
    'management_response_before_draft',
  );
  addReason(reasons, !isDigest(report?.finalReportHash), 'final_report_hash_invalid');
  addReason(reasons, !hasText(report?.approvedByDid), 'report_approver_absent');
  addReason(reasons, !hlcPresent(report?.approvedAtHlc), 'report_approved_time_invalid');
  addReason(
    reasons,
    hlcPresent(report?.approvedAtHlc) &&
      hlcPresent(report?.managementResponseAtHlc) &&
      compareHlc(report.approvedAtHlc, report.managementResponseAtHlc) <= 0,
    'report_approved_before_management_response',
  );
  addReason(reasons, !hasText(report?.reportVersion), 'report_version_absent');
  addReason(reasons, report?.locked !== true, 'final_report_not_locked');
}

function evaluateFollowUp(input, reasons) {
  const followUp = input?.closure?.followUp;
  addReason(reasons, typeof followUp?.required !== 'boolean', 'follow_up_requirement_invalid');
  if (followUp?.required === true) {
    addReason(reasons, !FOLLOW_UP_STATUSES.has(followUp?.status), 'follow_up_status_invalid');
    addReason(reasons, !isDigest(followUp?.planHash), 'follow_up_plan_hash_invalid');
    addReason(reasons, !hasText(followUp?.ownerDid), 'follow_up_owner_absent');
    addReason(reasons, !hlcPresent(followUp?.dueAtHlc), 'follow_up_due_time_invalid');
    addReason(
      reasons,
      hlcPresent(followUp?.dueAtHlc) &&
        hlcPresent(input?.closure?.closedAtHlc) &&
        compareHlc(followUp.dueAtHlc, input.closure.closedAtHlc) <= 0,
      'follow_up_due_before_closure',
    );
    if (followUp.status === 'complete') {
      addReason(reasons, !hlcPresent(followUp?.completedAtHlc), 'follow_up_completed_time_invalid');
      addReason(reasons, !isDigest(followUp?.evidenceHash), 'follow_up_evidence_hash_invalid');
      addReason(
        reasons,
        hlcPresent(followUp?.completedAtHlc) &&
          hlcPresent(input?.closure?.closedAtHlc) &&
          compareHlc(followUp.completedAtHlc, input.closure.closedAtHlc) <= 0,
        'follow_up_completed_before_closure',
      );
    }
    return followUp?.status ?? 'unknown';
  }

  if (followUp?.required === false) {
    addReason(reasons, followUp?.status !== 'not_required', 'follow_up_status_invalid');
    addReason(reasons, !isDigest(followUp?.rationaleHash), 'follow_up_rationale_hash_invalid');
    addReason(reasons, !hasText(followUp?.ownerDid), 'follow_up_owner_absent');
    return followUp.status === 'not_required' ? 'not_required' : 'unknown';
  }

  return 'unknown';
}

function evaluateExportEligibility(input, reasons) {
  const eligibility = input?.closure?.exportEligibility;
  addReason(reasons, typeof eligibility?.eligible !== 'boolean', 'export_eligibility_invalid');
  addReason(reasons, !isDigest(eligibility?.rationaleHash), 'export_rationale_hash_invalid');
  addReason(reasons, eligibility?.eligible === true && !hasText(eligibility?.exportProfileRef), 'export_profile_ref_absent');
}

function evaluateClosure(input, reasons) {
  const closure = input?.closure;
  addReason(reasons, !hasText(closure?.closedByDid), 'closure_actor_absent');
  addReason(reasons, !hlcPresent(closure?.closedAtHlc), 'closure_time_invalid');
  addReason(
    reasons,
    hlcPresent(closure?.closedAtHlc) &&
      hlcPresent(input?.report?.approvedAtHlc) &&
      compareHlc(closure.closedAtHlc, input.report.approvedAtHlc) <= 0,
    'closure_before_report_approval',
  );
  addReason(reasons, !isDigest(closure?.closureEvidenceHash), 'closure_evidence_hash_invalid');
  addReason(reasons, closure?.evidenceBundle?.complete !== true, 'closure_evidence_bundle_incomplete');
  addReason(reasons, closure?.evidenceBundle?.phiBoundaryAttested !== true, 'closure_phi_boundary_unattested');
  evaluateExportEligibility(input, reasons);
  return evaluateFollowUp(input, reasons);
}

function requiredEscalationRoles(summary) {
  const roles = [];
  if (summary.critical > 0) {
    roles.push('decision_forum_chair');
  }
  if (summary.critical > 0 || summary.major > 0) {
    roles.push('capa_owner', 'site_quality_lead');
  }
  return uniqueSorted(roles);
}

function auditArtifactHash(input, normalized) {
  return sha256Hex({
    audit: {
      auditId: input.audit.auditId,
      auditType: input.audit.auditType,
      controlSetRef: input.audit.controlSetRef,
      controlsSelected: normalized.controlsSelected,
      objectiveHash: input.audit.objectiveHash,
      protocolRef: input.audit.protocolRef,
      scheduledForHlc: input.audit.scheduledForHlc,
      scopeRef: input.audit.scopeRef,
      siteRef: input.audit.siteRef,
    },
    auditorAssignment: {
      auditorDid: input.auditorAssignment.auditorDid,
      independenceEvidenceHash: input.auditorAssignment.independenceEvidenceHash,
      independenceStatus: input.auditorAssignment.independenceStatus,
    },
    closure: {
      closedAtHlc: input.closure.closedAtHlc,
      closureEvidenceHash: input.closure.closureEvidenceHash,
      exportEligibility: input.closure.exportEligibility,
      followUp: input.closure.followUp,
    },
    documentReviewRefs: normalized.documentReviewRefs,
    evidenceReviewed: normalized.evidenceReviewed,
    findingSummary: normalized.summary,
    findings: normalized.findings,
    interviewRecords: normalized.interviewRecords,
    recordReviewRefs: normalized.recordReviewRefs,
    report: {
      finalReportHash: input.report.finalReportHash,
      managementResponseHash: input.report.managementResponseHash,
      reportVersion: input.report.reportVersion,
    },
  });
}

function buildReceipt(input, artifactHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'internal_audit_report',
    artifactVersion: `${input.audit.auditId}@${input.closure.closedAtHlc.physicalMs}.${input.closure.closedAtHlc.logical}`,
    artifactHash,
    classification: 'audit_metadata_only',
    hlcTimestamp: input.closure.closedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['audit', 'internal_audit', 'metadata_only', 'human_governed'],
    sourceSystem: 'cybermedica-qms',
  });
}

function buildAuditRecord(input, normalized, artifactHash) {
  return {
    schema: 'cybermedica.internal_audit_record.v1',
    auditRecordId: `cmia_${sha256Hex({ artifactHash, auditId: input.audit.auditId, tenantId: input.tenantId }).slice(0, 32)}`,
    tenantId: input.tenantId,
    auditId: input.audit.auditId,
    auditType: input.audit.auditType,
    scopeRef: input.audit.scopeRef,
    siteRef: input.audit.siteRef,
    protocolRef: input.audit.protocolRef,
    controlSetRef: input.audit.controlSetRef,
    auditorDid: input.auditorAssignment.auditorDid,
    auditorIndependenceStatus: input.auditorAssignment.independenceStatus,
    auditLocked: input.report.locked === true,
    auditClosed: true,
    managementResponseObtained: isDigest(input.report.managementResponseHash),
    finalReportApproved: input.report.locked === true && isDigest(input.report.finalReportHash),
    closureStatus: 'closed',
    controlsReviewed: normalized.controlsSelected,
    evidenceReviewedCount: normalized.evidenceReviewed.length,
    documentReviewCount: normalized.documentReviewRefs.length,
    recordReviewCount: normalized.recordReviewRefs.length,
    interviewCount: normalized.interviewRecords.length,
    findingCount: normalized.findings.length,
    findingRefs: normalized.findings.map((finding) => finding.findingRef),
    findingSummary: normalized.summary,
    capaRefs: uniqueSorted(normalized.findings.map((finding) => finding.capaRef).filter(hasText)),
    requiredEscalationRoles: requiredEscalationRoles(normalized.summary),
    followUpRequired: input.closure.followUp.required === true,
    followUpStatus: normalized.followUpStatus,
    exportEligible: input.closure.exportEligibility.eligible === true,
    humanGovernanceRequired: true,
    aiFinalAuthority: false,
    operationalStateMutable: true,
    immutableAuditReceipt: true,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function deniedResult(reasons) {
  return {
    schema: 'cybermedica.internal_audit_decision.v1',
    decision: 'denied',
    failClosed: true,
    reasons,
    internalAudit: null,
    receipt: null,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export function conductInternalAudit(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const controlsSelected = evaluateAuditPlan(input, reasons);
  evaluateAuditorAssignment(input, reasons);
  const { documentReviewRefs, recordReviewRefs } = evaluateExecution(input, reasons);
  const evidenceReviewed = normalizeEvidenceReviewed(input, controlsSelected, reasons);
  const interviewRecords = normalizeInterviewRecords(input, reasons);
  const findings = normalizeFindings(input, controlsSelected, reasons);
  const summary = findingSummary(findings);
  evaluateReport(input, reasons);
  const followUpStatus = evaluateClosure(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = [...new Set(reasons)].sort();
  if (uniqueReasons.length > 0) {
    return deniedResult(uniqueReasons);
  }

  const normalized = {
    controlsSelected,
    documentReviewRefs,
    evidenceReviewed,
    findings,
    followUpStatus,
    interviewRecords,
    recordReviewRefs,
    summary,
  };
  const artifactHash = auditArtifactHash(input, normalized);
  const receipt = buildReceipt(input, artifactHash);

  return {
    schema: 'cybermedica.internal_audit_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    internalAudit: buildAuditRecord(input, normalized, artifactHash),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
