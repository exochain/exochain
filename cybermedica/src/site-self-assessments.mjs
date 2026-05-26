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
const ASSESSMENT_TYPES = new Set(['external_assessment', 'self_assessment']);
const APPLICABILITY_STATES = new Set(['applicable', 'not_applicable']);
const REVIEWER_ROLES = new Set(['assessment_manager', 'control_reviewer', 'external_reviewer']);
const REVIEWER_DECISIONS = new Set(['accept', 'accept_with_findings', 'not_applicable', 'reject']);
const EVIDENCE_STATUSES = new Set(['approved', 'pending', 'rejected', 'superseded']);
const EVIDENCE_CLASSIFICATIONS = new Set([
  'confidential_metadata_only',
  'restricted_metadata_only',
  'sponsor_confidential_metadata_only',
]);
const FINDING_SEVERITIES = new Set(['critical', 'major', 'minor', 'observation']);
const FINDING_STATUSES = new Set(['accepted', 'closed', 'mitigated', 'open']);
const CLOSE_DECISIONS = new Set(['close', 'close_with_conditions', 'defer', 'reject']);
const PASSPORT_UPDATE_STATUSES = new Set(['applied']);
const RAW_ASSESSMENT_FIELDS = new Set([
  'assessmentnarrative',
  'commenttext',
  'findingnarrative',
  'findingtext',
  'freeformcomment',
  'rawevidence',
  'rawreview',
  'rawreviewcomment',
  'rawsource',
  'rawsourcedocument',
  'recommendationtext',
  'reviewercommenttext',
  'reviewnarrative',
  'sourcedocument',
  'sourcedocumentbody',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
}

function isNonNegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoRawAssessmentText(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAssessmentText(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    if (RAW_ASSESSMENT_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw assessment content field is not allowed at ${path}.${key}`);
    }
    assertNoRawAssessmentText(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAssessmentText(input ?? {});
  canonicalize(input ?? {});
}

function hlcPresent(hlc) {
  return Number.isSafeInteger(hlc?.physicalMs) && Number.isSafeInteger(hlc?.logical);
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
  return [...new Set(value)].sort();
}

function basisPoints(numerator, denominator) {
  if (!isNonNegativeSafeInteger(numerator) || !Number.isSafeInteger(denominator) || denominator <= 0) {
    return 0;
  }
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
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
  addReason(reasons, !hasAuthorityPermission(input?.authority, 'govern'), 'authority_permission_missing');
}

function evaluateAssessmentShape(input, reasons) {
  const assessment = input?.assessment;
  addReason(reasons, !hasText(assessment?.assessmentId), 'assessment_id_absent');
  addReason(reasons, !ASSESSMENT_TYPES.has(assessment?.assessmentType), 'assessment_type_invalid');
  addReason(reasons, !hasText(assessment?.siteRef), 'assessment_site_ref_absent');
  addReason(reasons, !hasText(assessment?.controlSetRef), 'assessment_control_set_ref_absent');
  addReason(reasons, !hasText(assessment?.workspaceRef), 'assessment_workspace_ref_absent');
  addReason(reasons, !hlcPresent(assessment?.selectedAtHlc), 'assessment_selected_time_invalid');
  addReason(reasons, !hlcPresent(assessment?.generatedAtHlc), 'assessment_workspace_time_invalid');
  addReason(reasons, !hlcPresent(assessment?.closedAtHlc), 'assessment_closed_time_invalid');
  addReason(
    reasons,
    hlcPresent(assessment?.selectedAtHlc) &&
      hlcPresent(assessment?.generatedAtHlc) &&
      compareHlc(assessment.generatedAtHlc, assessment.selectedAtHlc) <= 0,
    'assessment_workspace_before_selection',
  );
  addReason(
    reasons,
    hlcPresent(assessment?.generatedAtHlc) &&
      hlcPresent(assessment?.closedAtHlc) &&
      compareHlc(assessment.closedAtHlc, assessment.generatedAtHlc) <= 0,
    'assessment_closed_before_workspace_generation',
  );
}

function ownerSort(left, right) {
  return String(left.controlId).localeCompare(String(right.controlId)) || String(left.ownerDid).localeCompare(String(right.ownerDid));
}

function reviewerSort(left, right) {
  return String(left.controlId).localeCompare(String(right.controlId)) || String(left.reviewerDid).localeCompare(String(right.reviewerDid));
}

function controlSort(left, right) {
  return String(left.controlId).localeCompare(String(right.controlId));
}

function evidenceSort(left, right) {
  return String(left.evidenceRef).localeCompare(String(right.evidenceRef));
}

function findingSort(left, right) {
  return String(left.findingRef).localeCompare(String(right.findingRef));
}

function normalizeControlOwners(input, reasons) {
  const owners = Array.isArray(input?.controlOwners) ? [...input.controlOwners].sort(ownerSort) : [];
  addReason(reasons, owners.length === 0, 'control_owner_assignments_absent');

  const normalized = owners.map((owner) => {
    const controlId = hasText(owner?.controlId) ? owner.controlId : 'unknown';
    addReason(reasons, !hasText(owner?.controlId), 'control_owner_control_id_absent');
    addReason(reasons, !hasText(owner?.ownerDid), `control_owner_absent:${controlId}`);
    addReason(reasons, !hlcPresent(owner?.assignedAtHlc), `control_owner_assignment_time_invalid:${controlId}`);
    return {
      controlId,
      ownerDid: owner?.ownerDid,
      assignedAtHlc: owner?.assignedAtHlc,
    };
  });

  const ownerByControl = new Map();
  for (const owner of normalized) {
    if (hasText(owner.controlId) && owner.controlId !== 'unknown') {
      ownerByControl.set(owner.controlId, owner);
    }
  }

  return { normalizedOwners: normalized, ownerByControl };
}

function normalizeReviewers(input, reasons) {
  const reviewers = Array.isArray(input?.reviewers) ? [...input.reviewers].sort(reviewerSort) : [];
  addReason(reasons, reviewers.length === 0, 'reviewer_assignments_absent');

  const normalized = reviewers.map((reviewer) => {
    const controlId = hasText(reviewer?.controlId) ? reviewer.controlId : 'unknown';
    addReason(reasons, !hasText(reviewer?.controlId), 'reviewer_control_id_absent');
    addReason(reasons, !hasText(reviewer?.reviewerDid), `reviewer_did_absent:${controlId}`);
    addReason(reasons, !REVIEWER_ROLES.has(reviewer?.role), `reviewer_role_invalid:${controlId}`);
    return {
      controlId,
      reviewerDid: reviewer?.reviewerDid,
      role: reviewer?.role,
    };
  });

  const reviewerKeys = new Set(normalized.map((reviewer) => `${reviewer.controlId}:${reviewer.reviewerDid}:${reviewer.role}`));
  const managerReviewers = normalized.filter((reviewer) => reviewer.role === 'assessment_manager' && hasText(reviewer.reviewerDid));
  const externalReviewers = normalized.filter((reviewer) => reviewer.role === 'external_reviewer' && hasText(reviewer.reviewerDid));
  addReason(reasons, managerReviewers.length === 0, 'assessment_manager_assignment_absent');
  addReason(
    reasons,
    input?.assessment?.assessmentType === 'external_assessment' && externalReviewers.length === 0,
    'external_reviewer_assignment_absent',
  );

  return {
    externalReviewerDids: uniqueSorted(externalReviewers.map((reviewer) => reviewer.reviewerDid)),
    managerReviewerDids: uniqueSorted(managerReviewers.map((reviewer) => reviewer.reviewerDid)),
    normalizedReviewers: normalized,
    reviewerKeys,
  };
}

function evaluateEvidence(evidence, reasons) {
  const evidenceRef = hasText(evidence?.evidenceRef) ? evidence.evidenceRef : 'unknown';
  addReason(reasons, !hasText(evidence?.evidenceRef), 'evidence_ref_absent');
  addReason(reasons, !isDigest(evidence?.artifactHash), `evidence_hash_invalid:${evidenceRef}`);
  addReason(reasons, !isDigest(evidence?.custodyDigest), `evidence_custody_digest_invalid:${evidenceRef}`);
  addReason(reasons, !EVIDENCE_STATUSES.has(evidence?.status), `evidence_status_invalid:${evidenceRef}`);
  addReason(reasons, evidence?.status !== 'approved', `evidence_not_approved:${evidenceRef}`);
  addReason(reasons, evidence?.fresh !== true, `evidence_stale:${evidenceRef}`);
  addReason(reasons, !EVIDENCE_CLASSIFICATIONS.has(evidence?.classification), `evidence_classification_invalid:${evidenceRef}`);
  addReason(reasons, !hasText(evidence?.receiptRef), `evidence_receipt_absent:${evidenceRef}`);

  return {
    evidenceRef,
    artifactHash: evidence?.artifactHash,
    custodyDigest: evidence?.custodyDigest,
    status: evidence?.status,
    fresh: evidence?.fresh === true,
    classification: evidence?.classification,
    receiptRef: evidence?.receiptRef,
  };
}

function normalizeEvidenceInventory(input, reasons) {
  const evidenceInventory = Array.isArray(input?.evidenceInventory) ? [...input.evidenceInventory].sort(evidenceSort) : [];
  addReason(reasons, evidenceInventory.length === 0, 'evidence_inventory_absent');
  const normalizedEvidence = evidenceInventory.map((evidence) => evaluateEvidence(evidence, reasons));
  return {
    evidenceByRef: new Map(normalizedEvidence.map((evidence) => [evidence.evidenceRef, evidence])),
    normalizedEvidence,
  };
}

function evidenceIsComplete(evidence) {
  return (
    evidence !== undefined &&
    evidence.status === 'approved' &&
    evidence.fresh === true &&
    isDigest(evidence.artifactHash) &&
    isDigest(evidence.custodyDigest) &&
    hasText(evidence.receiptRef)
  );
}

function normalizeControlEvaluations(input, ownerByControl, reviewerKeys, evidenceByRef, reasons) {
  const evaluations = Array.isArray(input?.controlEvaluations) ? [...input.controlEvaluations].sort(controlSort) : [];
  addReason(reasons, evaluations.length === 0, 'control_evaluations_absent');

  return evaluations.map((evaluation) => {
    const controlId = hasText(evaluation?.controlId) ? evaluation.controlId : 'unknown';
    const evidenceRefs = sortedTextList(evaluation?.evidenceRefs);
    const controlReviewerKey = `${controlId}:${evaluation?.reviewerDid}:control_reviewer`;
    const evidenceObjects = evidenceRefs.map((evidenceRef) => evidenceByRef.get(evidenceRef));
    const completeEvidenceRefs = evidenceObjects.filter(evidenceIsComplete).length;

    addReason(reasons, !hasText(evaluation?.controlId), 'control_id_absent');
    addReason(reasons, !APPLICABILITY_STATES.has(evaluation?.applicability), `control_applicability_invalid:${controlId}`);
    addReason(reasons, !hasText(evaluation?.ownerDid), `control_owner_absent:${controlId}`);
    addReason(reasons, !ownerByControl.has(controlId), `control_owner_assignment_missing:${controlId}`);
    addReason(reasons, !hasText(evaluation?.reviewerDid), `control_reviewer_absent:${controlId}`);
    addReason(reasons, !reviewerKeys.has(controlReviewerKey), `control_reviewer_assignment_missing:${controlId}`);
    addReason(reasons, !REVIEWER_DECISIONS.has(evaluation?.reviewerDecision), `control_reviewer_decision_invalid:${controlId}`);
    addReason(reasons, !isDigest(evaluation?.commentHash), `control_comment_hash_invalid:${controlId}`);
    addReason(reasons, !isDigest(evaluation?.recommendationHash), `control_recommendation_hash_invalid:${controlId}`);
    addReason(reasons, evaluation?.evidenceComplete !== true, `control_evidence_incomplete:${controlId}`);
    addReason(reasons, evaluation?.phiBoundaryAttested !== true, `control_phi_boundary_unattested:${controlId}`);
    addReason(reasons, !hlcPresent(evaluation?.reviewedAtHlc), `control_review_time_invalid:${controlId}`);
    addReason(
      reasons,
      evaluation?.applicability === 'applicable' && evidenceRefs.length === 0,
      `control_evidence_absent:${controlId}`,
    );
    addReason(
      reasons,
      evaluation?.applicability === 'not_applicable' && !isDigest(evaluation?.notApplicableRationaleHash),
      `not_applicable_rationale_absent:${controlId}`,
    );
    addReason(
      reasons,
      evaluation?.applicability === 'not_applicable' && evaluation?.reviewerDecision !== 'not_applicable',
      `not_applicable_reviewer_decision_invalid:${controlId}`,
    );

    for (const evidenceRef of evidenceRefs) {
      addReason(reasons, !evidenceByRef.has(evidenceRef), `control_evidence_missing:${controlId}:${evidenceRef}`);
    }

    return {
      controlId,
      applicability: evaluation?.applicability,
      ownerDid: evaluation?.ownerDid,
      reviewerDid: evaluation?.reviewerDid,
      reviewerDecision: evaluation?.reviewerDecision,
      commentHash: evaluation?.commentHash,
      recommendationHash: evaluation?.recommendationHash,
      evidenceRefs,
      evidenceComplete: evaluation?.evidenceComplete === true,
      phiBoundaryAttested: evaluation?.phiBoundaryAttested === true,
      notApplicableRationaleHash: evaluation?.notApplicableRationaleHash ?? null,
      reviewedAtHlc: evaluation?.reviewedAtHlc,
      completeEvidenceRefs,
    };
  });
}

function evaluateAiEvidenceReview(input, controlIds, reasons) {
  const review = input?.aiEvidenceReview;
  const reviewedControlIds = sortedTextList(review?.reviewedControlIds);
  addReason(reasons, review?.completed !== true, 'ai_evidence_review_incomplete');
  addReason(reasons, review?.advisoryOnly !== true || review?.finalAuthority === true, 'ai_evidence_review_must_be_advisory');
  addReason(reasons, review?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(review?.outputHash), 'ai_evidence_review_output_invalid');
  addReason(reasons, controlIds.some((controlId) => !reviewedControlIds.includes(controlId)), 'ai_evidence_review_controls_incomplete');
  addReason(
    reasons,
    Array.isArray(review?.unresolvedMissingEvidence) && review.unresolvedMissingEvidence.length > 0,
    'ai_unresolved_missing_evidence_present',
  );

  return {
    completed: review?.completed === true,
    advisoryOnly: review?.advisoryOnly === true && review?.finalAuthority !== true,
    finalAuthority: false,
    outputHash: review?.outputHash,
    reviewedControlIds,
    unresolvedMissingEvidence: sortedTextList(review?.unresolvedMissingEvidence),
  };
}

function normalizeFindings(input, controlIds, reasons) {
  const findings = Array.isArray(input?.findings) ? [...input.findings].sort(findingSort) : [];
  return findings.map((finding) => {
    const findingRef = hasText(finding?.findingRef) ? finding.findingRef : 'unknown';
    const severityRequiresCapa = finding?.severity === 'critical' || finding?.severity === 'major';
    const capaRequired = finding?.capaRequired === true || severityRequiresCapa;

    addReason(reasons, !hasText(finding?.findingRef), 'finding_ref_absent');
    addReason(reasons, !controlIds.includes(finding?.controlId), `finding_control_invalid:${findingRef}`);
    addReason(reasons, !FINDING_SEVERITIES.has(finding?.severity), `finding_severity_invalid:${findingRef}`);
    addReason(reasons, !FINDING_STATUSES.has(finding?.status), `finding_status_invalid:${findingRef}`);
    addReason(reasons, !isDigest(finding?.findingHash), `finding_hash_invalid:${findingRef}`);
    addReason(reasons, !hasText(finding?.ownerDid), `finding_owner_absent:${findingRef}`);
    addReason(reasons, capaRequired && !hasText(finding?.capaRef), `finding_capa_ref_absent:${findingRef}`);
    addReason(
      reasons,
      finding?.severity === 'critical' && finding?.status !== 'closed' && finding?.status !== 'mitigated',
      `critical_finding_unresolved:${findingRef}`,
    );

    return {
      findingRef,
      controlId: finding?.controlId,
      severity: finding?.severity,
      status: finding?.status,
      findingHash: finding?.findingHash,
      ownerDid: finding?.ownerDid,
      capaRequired,
      capaRef: finding?.capaRef ?? null,
      openForAssessmentCondition:
        FINDING_SEVERITIES.has(finding?.severity) && finding?.status !== 'closed' && finding?.status !== 'mitigated',
    };
  });
}

function openFindingSummary(findings) {
  const summary = { critical: 0, major: 0, minor: 0, observation: 0 };
  for (const finding of findings) {
    if (FINDING_SEVERITIES.has(finding.severity) && finding.openForAssessmentCondition) {
      summary[finding.severity] += 1;
    }
  }
  return summary;
}

function requiredEscalationRoles(findings) {
  const roles = [];
  for (const finding of findings) {
    if (!finding.openForAssessmentCondition) {
      continue;
    }
    if (finding.severity === 'major') {
      roles.push('site_quality_lead');
    }
    if (finding.severity === 'critical') {
      roles.push('decision_forum', 'principal_investigator', 'site_quality_lead');
    }
  }
  return uniqueSorted(roles);
}

function evaluateAssessmentClose(input, reasons) {
  const close = input?.assessmentManagerClose;
  const assessment = input?.assessment;
  addReason(reasons, !CLOSE_DECISIONS.has(close?.decision), 'assessment_close_decision_invalid');
  addReason(reasons, close?.decision === 'defer', 'assessment_close_deferred');
  addReason(reasons, close?.decision === 'reject', 'assessment_close_rejected');
  addReason(reasons, !hasText(close?.managerDid), 'assessment_manager_absent');
  addReason(reasons, close?.humanVerified !== true, 'assessment_manager_human_unverified');
  addReason(reasons, !isDigest(close?.rationaleHash), 'assessment_close_rationale_invalid');
  addReason(reasons, !hlcPresent(close?.closedAtHlc), 'assessment_close_time_invalid');
  addReason(reasons, close?.evidenceBundle?.complete !== true, 'evidence_bundle_incomplete');
  addReason(reasons, close?.evidenceBundle?.phiBoundaryAttested !== true, 'phi_boundary_unattested');
  addReason(
    reasons,
    hlcPresent(close?.closedAtHlc) &&
      hlcPresent(assessment?.generatedAtHlc) &&
      compareHlc(close.closedAtHlc, assessment.generatedAtHlc) <= 0,
    'assessment_close_before_workspace_generation',
  );
  addReason(
    reasons,
    hlcPresent(close?.closedAtHlc) &&
      hlcPresent(assessment?.closedAtHlc) &&
      compareHlc(close.closedAtHlc, assessment.closedAtHlc) !== 0,
    'assessment_close_time_mismatch',
  );

  return {
    decision: close?.decision,
    managerDid: close?.managerDid,
    humanVerified: close?.humanVerified === true,
    rationaleHash: close?.rationaleHash,
    closedAtHlc: close?.closedAtHlc,
    evidenceBundleComplete: close?.evidenceBundle?.complete === true,
    phiBoundaryAttested: close?.evidenceBundle?.phiBoundaryAttested === true,
  };
}

function evaluateLockedReport(input, close, reasons) {
  const report = input?.lockedReport;
  addReason(reasons, report?.locked !== true, 'assessment_report_not_locked');
  addReason(reasons, !isDigest(report?.reportHash), 'locked_report_hash_invalid');
  addReason(reasons, !hasText(report?.lockedByDid), 'locked_report_actor_absent');
  addReason(reasons, !hlcPresent(report?.lockedAtHlc), 'locked_report_time_invalid');
  addReason(reasons, !hasText(report?.reportVersion), 'locked_report_version_absent');
  addReason(
    reasons,
    hlcPresent(report?.lockedAtHlc) && hlcPresent(close?.closedAtHlc) && compareHlc(report.lockedAtHlc, close.closedAtHlc) <= 0,
    'locked_report_before_close',
  );

  return {
    locked: report?.locked === true,
    reportHash: report?.reportHash,
    lockedByDid: report?.lockedByDid,
    lockedAtHlc: report?.lockedAtHlc,
    reportVersion: report?.reportVersion,
  };
}

function evaluateSitePassportUpdate(input, reasons) {
  const update = input?.sitePassportUpdate;
  addReason(reasons, !hasText(update?.passportRef), 'site_passport_ref_absent');
  addReason(reasons, !PASSPORT_UPDATE_STATUSES.has(update?.status), 'site_passport_update_not_applied');
  addReason(reasons, !isDigest(update?.updateHash), 'site_passport_update_hash_invalid');
  addReason(reasons, !hasText(update?.updateReceiptRef), 'site_passport_update_receipt_absent');

  return {
    passportRef: update?.passportRef,
    status: update?.status,
    updateHash: update?.updateHash,
    updateReceiptRef: update?.updateReceiptRef,
  };
}

function buildAssessmentReport(input, normalized, reasons) {
  const sortedReasons = uniqueSorted(reasons);
  const controlIds = uniqueSorted(normalized.controlEvaluations.map((evaluation) => evaluation.controlId).filter((id) => id !== 'unknown'));
  const evidenceCompletenessCount = normalized.controlEvaluations.filter((evaluation) => {
    if (evaluation.applicability === 'not_applicable') {
      return isDigest(evaluation.notApplicableRationaleHash);
    }
    return evaluation.evidenceRefs.length > 0 && evaluation.completeEvidenceRefs === evaluation.evidenceRefs.length;
  }).length;
  const evidenceFreshnessCount = normalized.controlEvaluations.filter((evaluation) => {
    if (evaluation.applicability === 'not_applicable') {
      return isDigest(evaluation.notApplicableRationaleHash);
    }
    return evaluation.evidenceRefs.every((evidenceRef) => normalized.evidenceByRef.get(evidenceRef)?.fresh === true);
  }).length;
  const findingSummary = openFindingSummary(normalized.findings);
  const material = {
    assessmentId: input?.assessment?.assessmentId ?? null,
    assessmentType: input?.assessment?.assessmentType ?? null,
    controlIds,
    findingSummary,
    reportHash: normalized.lockedReport.reportHash ?? null,
    siteRef: input?.assessment?.siteRef ?? null,
    tenantId: input?.tenantId ?? null,
  };

  return {
    schema: 'cybermedica.site_assessment_report.v1',
    tenantId: input?.tenantId,
    assessmentId: input?.assessment?.assessmentId,
    assessmentType: input?.assessment?.assessmentType,
    siteRef: input?.assessment?.siteRef,
    controlSetRef: input?.assessment?.controlSetRef,
    workspaceRef: input?.assessment?.workspaceRef,
    controlIds,
    controlOwners: normalized.controlOwners,
    reviewers: normalized.reviewers,
    externalReviewerDids: normalized.externalReviewerDids,
    controlEvaluations: normalized.controlEvaluations,
    evidenceInventory: normalized.evidenceInventory,
    evidenceCompletenessBasisPoints: basisPoints(evidenceCompletenessCount, normalized.controlEvaluations.length),
    evidenceFreshnessBasisPoints: basisPoints(evidenceFreshnessCount, normalized.controlEvaluations.length),
    aiEvidenceReview: normalized.aiEvidenceReview,
    findings: normalized.findings,
    findingSummary,
    requiredEscalationRoles: requiredEscalationRoles(normalized.findings),
    assessmentClose: normalized.assessmentClose,
    lockedReportEvidence: normalized.lockedReport,
    sitePassportUpdate: normalized.sitePassportUpdate,
    assessmentClosed: sortedReasons.length === 0,
    lockedReport: sortedReasons.length === 0 && normalized.lockedReport.locked === true,
    sitePassportUpdated: sortedReasons.length === 0 && normalized.sitePassportUpdate.status === 'applied',
    operationalStateMutable: true,
    immutableReportReceipt: sortedReasons.length === 0,
    aiFinalAuthority: false,
    exochainProductionClaim: false,
    trustState: 'inactive',
    reportId: `cmsar_${sha256Hex(material).slice(0, 32)}`,
  };
}

function buildReceipt(input, report) {
  const artifactHash = sha256Hex({
    assessmentId: report.assessmentId,
    controlIds: report.controlIds,
    evidenceCompletenessBasisPoints: report.evidenceCompletenessBasisPoints,
    evidenceFreshnessBasisPoints: report.evidenceFreshnessBasisPoints,
    findingSummary: report.findingSummary,
    reportHash: report.lockedReportEvidence.reportHash,
    reportId: report.reportId,
    sitePassportUpdate: report.sitePassportUpdate,
  });

  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'site_self_assessment_report',
    artifactVersion: `${input.assessment.assessmentId}@${input.lockedReport.lockedAtHlc.physicalMs}.${input.lockedReport.lockedAtHlc.logical}`,
    artifactHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.lockedReport.lockedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['site_self_assessment', 'locked_report', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function closeSiteAssessment(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateAssessmentShape(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
  const { normalizedOwners, ownerByControl } = normalizeControlOwners(input, reasons);
  const { externalReviewerDids, normalizedReviewers, reviewerKeys } = normalizeReviewers(input, reasons);
  const { evidenceByRef, normalizedEvidence } = normalizeEvidenceInventory(input, reasons);
  const controlEvaluations = normalizeControlEvaluations(input, ownerByControl, reviewerKeys, evidenceByRef, reasons);
  const controlIds = uniqueSorted(controlEvaluations.map((evaluation) => evaluation.controlId).filter((id) => id !== 'unknown'));
  const aiEvidenceReview = evaluateAiEvidenceReview(input, controlIds, reasons);
  const findings = normalizeFindings(input, controlIds, reasons);
  const assessmentClose = evaluateAssessmentClose(input, reasons);
  const lockedReport = evaluateLockedReport(input, assessmentClose, reasons);
  const sitePassportUpdate = evaluateSitePassportUpdate(input, reasons);
  const normalized = {
    aiEvidenceReview,
    assessmentClose,
    controlEvaluations,
    controlOwners: normalizedOwners,
    evidenceByRef,
    evidenceInventory: normalizedEvidence,
    externalReviewerDids,
    findings,
    lockedReport,
    reviewers: normalizedReviewers,
    sitePassportUpdate,
  };
  const assessmentReport = buildAssessmentReport(input, normalized, reasons);
  const sortedReasons = uniqueSorted(reasons);

  if (sortedReasons.length > 0) {
    return {
      decision: 'denied',
      failClosed: true,
      reasons: sortedReasons,
      assessmentReport,
    };
  }

  return {
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    assessmentReport,
    receipt: buildReceipt(input, assessmentReport),
  };
}
