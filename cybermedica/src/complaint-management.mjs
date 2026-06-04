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

import { ProtectedContentError, canonicalize, createEvidenceReceipt, sha256Hex } from './qms-contracts.mjs';

export { ProtectedContentError };

const HEX_64 = /^[0-9a-f]{64}$/u;
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const REQUIRED_PERMISSION = 'complaint_manage';
const COMPLAINT_SCHEMA = 'cybermedica.complaint_management.v1';

const REQUIRED_CATEGORIES = Object.freeze([
  'data_integrity',
  'participant_rights',
  'privacy',
  'quality_system',
  'safety',
  'sponsor_cro',
  'staff_wellbeing',
  'vendor',
]);

const REQUIRED_TRIAGE_DOMAINS = Object.freeze([
  'classification',
  'confidentiality',
  'cqi_linkage',
  'decision_forum_materiality',
  'investigator_assignment',
  'non_retaliation',
  'response_plan',
]);

const SUPPORTED_CATEGORIES = new Set(REQUIRED_CATEGORIES);
const SEVERITY_LEVELS = new Set(['minor', 'moderate', 'major', 'critical']);
const RETALIATION_RISK_LEVELS = new Set(['none', 'minor', 'elevated', 'high', 'critical']);
const COMPLAINT_STATUSES = new Set(['investigation_assigned', 'response_in_progress', 'closed_cqi_linked']);
const HUMAN_REVIEW_DECISIONS = new Set(['complaint_investigation_assigned', 'complaint_response_in_progress', 'complaint_closed_cqi_linked']);

const RAW_COMPLAINT_FIELDS = new Set([
  'complaintbody',
  'complaintdetails',
  'complaintnarrative',
  'freeformcomplaint',
  'investigationnotes',
  'participantstory',
  'rawcomplaint',
  'rawfeedback',
  'rawinvestigation',
  'rawresponse',
  'responsebody',
  'sourcedocument',
  'sourcedocumentbody',
  'verbatimcomplaint',
]);

const SECRET_COMPLAINT_FIELDS = new Set([
  'accesstoken',
  'adaptersecret',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credentialsecret',
  'password',
  'privatekey',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'sessionsecret',
  'signaturesecret',
  'signingkey',
  'token',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function sensitiveValuePresent(value) {
  if (value === null || value === undefined || value === false) {
    return false;
  }
  if (typeof value === 'string') {
    return value.trim().length > 0;
  }
  if (Array.isArray(value)) {
    return value.some((item) => sensitiveValuePresent(item));
  }
  if (typeof value === 'object') {
    return Object.keys(value).length > 0;
  }
  return true;
}

function assertNoRawComplaintContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawComplaintContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_COMPLAINT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw complaint content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_COMPLAINT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`complaint secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawComplaintContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawComplaintContent(input ?? {});
  canonicalize(input ?? {});
}

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [hlc.physicalMs, hlc.logical];
}

function compareHlc(left, right) {
  if (left[0] !== right[0]) {
    return left[0] < right[0] ? -1 : 1;
  }
  if (left[1] !== right[1]) {
    return left[1] < right[1] ? -1 : 1;
  }
  return 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hlcNotAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) <= 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.siteId), 'site_id_absent');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'complaint_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
  addReason(reasons, hlcTuple(input?.checkedAtHlc) === null, 'checked_at_hlc_invalid');
}

function evaluatePolicy(policy, checkedAtHlc, reasons) {
  const categories = sortedTextList(policy?.categories);
  const triageDomains = sortedTextList(policy?.requiredTriageDomains);

  addReason(reasons, !hasText(policy?.policyRef), 'complaint_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'complaint_policy_hash_invalid');
  addReason(reasons, policy?.status !== 'active', 'complaint_policy_not_active');
  addReason(reasons, policy?.anonymousReportingAllowed !== true, 'anonymous_reporting_policy_absent');
  addReason(reasons, policy?.nonRetaliationRequired !== true, 'non_retaliation_policy_absent');
  addReason(reasons, policy?.cqiLinkageRequiredForClosure !== true, 'closure_cqi_policy_absent');
  addReason(reasons, policy?.humanInvestigatorRequired !== true, 'human_investigator_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'complaint_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'complaint_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'complaint_policy_evaluated_time_invalid');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, checkedAtHlc), 'complaint_policy_evaluated_after_check');

  for (const category of REQUIRED_CATEGORIES) {
    addReason(reasons, !categories.includes(category), `complaint_policy_category_missing:${category}`);
  }
  for (const domain of REQUIRED_TRIAGE_DOMAINS) {
    addReason(reasons, !triageDomains.includes(domain), `complaint_policy_triage_domain_missing:${domain}`);
  }

  return { categories, triageDomains };
}

function evaluateReporter(reporter, policy, reasons) {
  addReason(reasons, reporter === null || reporter === undefined, 'reporter_absent');
  addReason(reasons, typeof reporter?.anonymous !== 'boolean', 'reporter_anonymous_flag_invalid');
  addReason(reasons, reporter?.anonymous === true && policy?.anonymousReportingAllowed !== true, 'anonymous_report_not_allowed');
  addReason(reasons, reporter?.anonymous !== true && !hasText(reporter?.reporterDid), 'reporter_did_absent');
  addReason(reasons, !hasText(reporter?.reporterClass), 'reporter_class_absent');
  addReason(reasons, !hasText(reporter?.intakeChannel), 'reporter_intake_channel_absent');
  addReason(reasons, typeof reporter?.notificationPermitted !== 'boolean', 'reporter_notification_flag_invalid');
}

function normalizeReporter(reporter) {
  return {
    anonymous: reporter.anonymous,
    intakeChannel: reporter.intakeChannel,
    notificationPermitted: reporter.notificationPermitted,
    reporterClass: reporter.reporterClass,
    reporterDid: reporter.anonymous ? null : reporter.reporterDid,
  };
}

function evaluateComplaint(complaint, input, policyCategories, reasons) {
  const affectedAreaRefs = sortedTextList(complaint?.affectedAreaRefs);

  addReason(reasons, !hasText(complaint?.complaintRef), 'complaint_ref_absent');
  addReason(reasons, !SUPPORTED_CATEGORIES.has(complaint?.category), 'complaint_category_invalid');
  addReason(
    reasons,
    hasText(complaint?.category) && policyCategories.length > 0 && !policyCategories.includes(complaint.category),
    `complaint_category_not_policy_covered:${complaint?.category}`,
  );
  addReason(reasons, !SEVERITY_LEVELS.has(complaint?.severity), 'complaint_severity_invalid');
  addReason(reasons, !hasText(complaint?.sourceClass), 'complaint_source_class_absent');
  addReason(reasons, !isDigest(complaint?.summaryHash), 'complaint_summary_hash_invalid');
  addReason(reasons, !hasText(complaint?.affectedSubjectClass), 'complaint_subject_class_absent');
  addReason(reasons, !hasText(complaint?.siteRef), 'complaint_site_ref_absent');
  addReason(reasons, hasText(complaint?.siteRef) && complaint.siteRef !== input?.siteId, 'complaint_site_mismatch');
  addReason(reasons, affectedAreaRefs.length === 0, 'complaint_affected_area_refs_absent');
  addReason(reasons, typeof complaint?.participantSafetyImpact !== 'boolean', 'participant_safety_impact_flag_invalid');
  addReason(reasons, typeof complaint?.dataIntegrityImpact !== 'boolean', 'data_integrity_impact_flag_invalid');
  addReason(reasons, typeof complaint?.privacyImpact !== 'boolean', 'privacy_impact_flag_invalid');
  addReason(reasons, !RETALIATION_RISK_LEVELS.has(complaint?.retaliationRiskLevel), 'retaliation_risk_level_invalid');
  addReason(reasons, !COMPLAINT_STATUSES.has(complaint?.status), 'complaint_status_invalid');
  addReason(reasons, hlcTuple(complaint?.receivedAtHlc) === null, 'complaint_received_time_invalid');
  addReason(reasons, hlcAfter(complaint?.receivedAtHlc, input?.checkedAtHlc), 'complaint_received_after_check');

  return { affectedAreaRefs };
}

function normalizeEvidenceRefs(evidenceRefs, reasons) {
  if (!Array.isArray(evidenceRefs) || evidenceRefs.length === 0) {
    reasons.push('evidence_refs_absent');
    return [];
  }

  return evidenceRefs
    .map((evidence, index) => {
      const label = hasText(evidence?.evidenceRef) ? evidence.evidenceRef : `index_${index}`;
      addReason(reasons, !hasText(evidence?.evidenceRef), `evidence_ref_absent:${label}`);
      addReason(reasons, !hasText(evidence?.artifactType), `evidence_artifact_type_absent:${label}`);
      addReason(reasons, !isDigest(evidence?.artifactHash), `evidence_artifact_hash_invalid:${label}`);
      addReason(reasons, !isDigest(evidence?.custodyDigest), `evidence_custody_digest_invalid:${label}`);
      addReason(reasons, !hasText(evidence?.receiptId), `evidence_receipt_id_absent:${label}`);
      addReason(reasons, !hasText(evidence?.classification), `evidence_classification_absent:${label}`);

      return {
        artifactHash: evidence?.artifactHash ?? null,
        artifactType: evidence?.artifactType ?? null,
        classification: evidence?.classification ?? null,
        custodyDigest: evidence?.custodyDigest ?? null,
        evidenceRef: evidence?.evidenceRef ?? null,
        receiptId: evidence?.receiptId ?? null,
      };
    })
    .sort((left, right) => `${left.evidenceRef}:${left.receiptId}`.localeCompare(`${right.evidenceRef}:${right.receiptId}`));
}

function complaintIsMaterial(complaint) {
  return (
    complaint?.severity === 'critical' ||
    complaint?.participantSafetyImpact === true ||
    complaint?.dataIntegrityImpact === true ||
    complaint?.privacyImpact === true ||
    complaint?.retaliationRiskLevel === 'high' ||
    complaint?.retaliationRiskLevel === 'critical'
  );
}

function requiredResponseRoles(complaint, material) {
  const roles = new Set(['site_quality_lead']);
  if (complaint?.participantSafetyImpact === true || complaint?.category === 'safety') {
    roles.add('principal_investigator');
  }
  if (complaint?.category === 'participant_rights') {
    roles.add('participant_rights_reviewer');
  }
  if (complaint?.dataIntegrityImpact === true || complaint?.category === 'data_integrity') {
    roles.add('data_integrity_officer');
  }
  if (complaint?.privacyImpact === true || complaint?.category === 'privacy') {
    roles.add('security_privacy_officer');
  }
  if (complaint?.category === 'staff_wellbeing' || complaint?.retaliationRiskLevel === 'high' || complaint?.retaliationRiskLevel === 'critical') {
    roles.add('staff_wellbeing_reviewer');
  }
  if (complaint?.category === 'vendor') {
    roles.add('vendor_owner');
  }
  if (complaint?.category === 'sponsor_cro') {
    roles.add('sponsor_cro_governance');
  }
  if (material) {
    roles.add('decision_forum');
  }
  return [...roles].sort();
}

function evaluateTriage(triage, complaint, material, checkedAtHlc, reasons) {
  addReason(reasons, hlcTuple(triage?.triagedAtHlc) === null, 'triage_time_invalid');
  addReason(reasons, hlcNotAfter(triage?.triagedAtHlc, complaint?.receivedAtHlc), 'triage_not_after_complaint');
  addReason(reasons, hlcAfter(triage?.triagedAtHlc, checkedAtHlc), 'triage_after_check');
  addReason(reasons, triage?.categoryConfirmed !== true, 'triage_category_unconfirmed');
  addReason(reasons, triage?.severityConfirmed !== true, 'triage_severity_unconfirmed');
  addReason(reasons, triage?.confidentialityClass !== 'confidential_metadata_only', 'triage_confidentiality_invalid');
  addReason(reasons, !isDigest(triage?.nonRetaliationNoticeHash), 'non_retaliation_notice_hash_invalid');
  addReason(reasons, material && triage?.escalationRequired !== true, 'material_escalation_not_confirmed');
  addReason(reasons, hlcTuple(triage?.responseDueAtHlc) === null, 'response_due_time_invalid');
  addReason(reasons, hlcNotAfter(triage?.responseDueAtHlc, triage?.triagedAtHlc), 'response_due_not_after_triage');
}

function evaluateInvestigator(investigator, policy, reasons) {
  addReason(reasons, !hasText(investigator?.did), 'investigator_did_absent');
  addReason(reasons, policy?.humanInvestigatorRequired === true && investigator?.kind !== 'human', 'investigator_human_required');
  addReason(reasons, !hasText(investigator?.role), 'investigator_role_absent');
  addReason(reasons, !isDigest(investigator?.independenceAttestationHash), 'investigator_independence_hash_invalid');
  addReason(reasons, investigator?.conflictCleared !== true, 'investigator_conflict_not_cleared');
}

function evaluateInvestigation(investigation, triage, checkedAtHlc, reasons) {
  addReason(reasons, !isDigest(investigation?.planHash), 'investigation_plan_hash_invalid');
  addReason(reasons, !isDigest(investigation?.findingHash), 'investigation_finding_hash_invalid');
  addReason(reasons, !isDigest(investigation?.rootCauseHash), 'investigation_root_cause_hash_invalid');
  addReason(reasons, hlcTuple(investigation?.completedAtHlc) === null, 'investigation_completed_time_invalid');
  addReason(reasons, hlcNotAfter(investigation?.completedAtHlc, triage?.triagedAtHlc), 'investigation_not_after_triage');
  addReason(reasons, hlcAfter(investigation?.completedAtHlc, checkedAtHlc), 'investigation_after_check');
  addReason(reasons, investigation?.metadataOnly !== true, 'investigation_metadata_boundary_invalid');
  addReason(reasons, investigation?.protectedContentExcluded !== true, 'investigation_protected_boundary_invalid');
}

function evaluateResponsePlan(responsePlan, reporter, complaint, investigation, reasons) {
  const correctiveActionRefs = sortedTextList(responsePlan?.correctiveActionRefs);
  const notificationPermitted = reporter?.notificationPermitted === true;

  addReason(reasons, !isDigest(responsePlan?.responsePlanHash), 'response_plan_hash_invalid');
  addReason(reasons, notificationPermitted && !isDigest(responsePlan?.acknowledgementHash), 'complaint_acknowledgement_hash_invalid');
  addReason(reasons, notificationPermitted && !isDigest(responsePlan?.communicationRecordHash), 'complaint_communication_record_hash_invalid');
  addReason(reasons, notificationPermitted && responsePlan?.reporterResponsePermitted !== true, 'reporter_response_permission_mismatch');
  addReason(reasons, complaint?.status === 'closed_cqi_linked' && correctiveActionRefs.length === 0, 'corrective_action_refs_absent');
  addReason(reasons, hlcTuple(responsePlan?.completedAtHlc) === null, 'response_completed_time_invalid');
  addReason(reasons, hlcNotAfter(responsePlan?.completedAtHlc, investigation?.completedAtHlc), 'response_not_after_investigation');

  return { correctiveActionRefs };
}

function evaluateDecisionForum(decisionForum, material, reasons) {
  if (material) {
    addReason(reasons, decisionForum?.invoked !== true, 'material_complaint_decision_forum_required');
  }
  if (decisionForum?.invoked === true || material) {
    addReason(reasons, !hasText(decisionForum?.matterRef), 'decision_forum_matter_absent');
    addReason(reasons, !hasText(decisionForum?.receiptId), 'decision_forum_receipt_absent');
    addReason(reasons, decisionForum?.quorumStatus !== 'met', 'decision_forum_quorum_not_met');
    addReason(reasons, decisionForum?.humanGateVerified !== true, 'decision_forum_human_gate_unverified');
    addReason(reasons, decisionForum?.openChallenge === true, 'decision_forum_open_challenge');
    addReason(reasons, hlcTuple(decisionForum?.decidedAtHlc) === null, 'decision_forum_decided_time_invalid');
  }
}

function evaluateCqiLinkage(cqiLinkage, complaint, policy, reasons) {
  const closureNeedsCqi = complaint?.status === 'closed_cqi_linked';
  if (!closureNeedsCqi) {
    return null;
  }

  const invalid =
    policy?.cqiLinkageRequiredForClosure !== true ||
    cqiLinkage?.required !== true ||
    !hasText(cqiLinkage?.cqiCycleRef) ||
    !hasText(cqiLinkage?.cqiReceiptId) ||
    cqiLinkage?.improvementSource !== 'complaint' ||
    cqiLinkage?.effectivenessCheckScheduled !== true;
  addReason(reasons, invalid, 'closed_complaint_cqi_linkage_absent');

  return {
    cqiCycleRef: cqiLinkage?.cqiCycleRef ?? null,
    cqiReceiptId: cqiLinkage?.cqiReceiptId ?? null,
    effectivenessCheckScheduled: cqiLinkage?.effectivenessCheckScheduled === true,
    improvementSource: cqiLinkage?.improvementSource ?? null,
  };
}

function evaluateHumanReview(humanReview, complaint, responsePlan, reasons) {
  addReason(reasons, humanReview?.verified !== true, 'human_review_unverified');
  addReason(reasons, !hasText(humanReview?.reviewedByDid), 'human_review_did_absent');
  addReason(reasons, !isDigest(humanReview?.reviewEvidenceHash), 'human_review_evidence_hash_invalid');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(humanReview?.decision), 'human_review_decision_invalid');
  addReason(
    reasons,
    complaint?.status === 'closed_cqi_linked' && humanReview?.decision !== 'complaint_closed_cqi_linked',
    'human_review_closure_mismatch',
  );
  addReason(
    reasons,
    complaint?.status === 'investigation_assigned' && humanReview?.decision !== 'complaint_investigation_assigned',
    'human_review_status_mismatch',
  );
  addReason(reasons, hlcTuple(humanReview?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcNotAfter(humanReview?.reviewedAtHlc, responsePlan?.completedAtHlc), 'human_review_not_after_response');
}

function evaluateAuditRecord(auditRecord, humanReview, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'complaint_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'complaint_audit_record_hash_invalid');
  addReason(reasons, hlcTuple(auditRecord?.recordedAtHlc) === null, 'complaint_audit_record_time_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'complaint_audit_metadata_boundary_invalid');
  addReason(reasons, hlcNotAfter(auditRecord?.recordedAtHlc, humanReview?.reviewedAtHlc), 'complaint_audit_before_review');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance?.used === false) {
    return;
  }
  addReason(reasons, aiAssistance?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance?.advisoryOnly !== true, 'ai_advisory_boundary_invalid');
  addReason(reasons, !isDigest(aiAssistance?.promptHash), 'ai_prompt_hash_invalid');
  addReason(reasons, !isDigest(aiAssistance?.outputHash), 'ai_output_hash_invalid');
  addReason(reasons, aiAssistance?.humanReviewed !== true, 'ai_human_review_absent');
}

function buildComplaintMaterial(input, normalized, materialRequired, responseRoles) {
  return {
    actorDid: input.actor.did,
    affectedAreaRefs: normalized.affectedAreaRefs,
    auditRecordHash: input.auditRecord.auditRecordHash,
    category: input.complaint.category,
    complaintPolicyHash: input.complaintPolicy.policyHash,
    complaintRef: input.complaint.complaintRef,
    cqiLinkage: normalized.cqiLinkage,
    evidenceRefs: normalized.evidenceRefs,
    findingHash: input.investigation.findingHash,
    humanReviewEvidenceHash: input.humanReview.reviewEvidenceHash,
    materialDecisionForumRequired: materialRequired,
    reporter: normalized.reporter,
    requiredResponseRoles: responseRoles,
    responsePlanHash: input.responsePlan.responsePlanHash,
    rootCauseHash: input.investigation.rootCauseHash,
    schema: COMPLAINT_SCHEMA,
    severity: input.complaint.severity,
    siteId: input.siteId,
    status: input.complaint.status,
    summaryHash: input.complaint.summaryHash,
    tenantId: input.tenantId,
  };
}

function buildComplaint(input, artifactHash, normalized, materialRequired, responseRoles, receipt) {
  return {
    schema: COMPLAINT_SCHEMA,
    complaintId: `cmcmp_${artifactHash.slice(0, 32)}`,
    complaintRef: input.complaint.complaintRef,
    tenantId: input.tenantId,
    siteId: input.siteId,
    category: input.complaint.category,
    severity: input.complaint.severity,
    sourceClass: input.complaint.sourceClass,
    affectedSubjectClass: input.complaint.affectedSubjectClass,
    affectedAreaRefs: normalized.affectedAreaRefs,
    relatedConcernRef: input.complaint.relatedConcernRef ?? null,
    reporter: normalized.reporter,
    materialDecisionForumRequired: materialRequired,
    requiredResponseRoles: responseRoles,
    status: input.complaint.status,
    investigationStatus: input.complaint.status === 'closed_cqi_linked' ? 'closed' : 'assigned',
    decisionForumLinkage: materialRequired
      ? {
          matterRef: input.decisionForum.matterRef,
          receiptId: input.decisionForum.receiptId,
        }
      : null,
    cqiLinkage: normalized.cqiLinkage,
    evidenceReceiptIds: normalized.evidenceRefs.map((evidence) => evidence.receiptId).sort(),
    responsePlan: {
      correctiveActionRefs: normalized.correctiveActionRefs,
      reporterResponsePermitted: input.responsePlan.reporterResponsePermitted === true,
      responsePlanHash: input.responsePlan.responsePlanHash,
    },
    receivedAtHlc: input.complaint.receivedAtHlc,
    reviewedAtHlc: input.humanReview.reviewedAtHlc,
    receiptId: receipt.receiptId,
    operationalStateMutable: true,
    immutableComplaintReceipt: true,
    metadataOnly: true,
    aiFinalAuthority: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, artifactHash) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash,
    artifactType: 'complaint_management_record',
    artifactVersion: `${input.siteId}@${input.complaint.complaintRef}`,
    classification: 'quality_evidence',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.checkedAtHlc,
    sensitivityTags: ['complaint_management', 'human_governance', 'metadata_only', 'policy_7', 'policy_15'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateComplaintManagement(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policy = evaluatePolicy(input?.complaintPolicy, input?.checkedAtHlc, reasons);
  evaluateReporter(input?.reporter, input?.complaintPolicy, reasons);
  const complaint = evaluateComplaint(input?.complaint, input, policy.categories, reasons);
  const evidenceRefs = normalizeEvidenceRefs(input?.evidenceRefs, reasons);
  const materialRequired = complaintIsMaterial(input?.complaint);
  const responseRoles = requiredResponseRoles(input?.complaint, materialRequired);
  evaluateTriage(input?.triage, input?.complaint, materialRequired, input?.checkedAtHlc, reasons);
  evaluateInvestigator(input?.assignedInvestigator, input?.complaintPolicy, reasons);
  evaluateInvestigation(input?.investigation, input?.triage, input?.checkedAtHlc, reasons);
  const responsePlan = evaluateResponsePlan(input?.responsePlan, input?.reporter, input?.complaint, input?.investigation, reasons);
  evaluateDecisionForum(input?.decisionForum, materialRequired, reasons);
  const cqiLinkage = evaluateCqiLinkage(input?.cqiLinkage, input?.complaint, input?.complaintPolicy, reasons);
  evaluateHumanReview(input?.humanReview, input?.complaint, input?.responsePlan, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: 'cybermedica.complaint_management_decision.v1',
      decision: 'hold_for_complaint_gap',
      failClosed: true,
      reasons: unique,
      complaint: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const normalized = {
    affectedAreaRefs: complaint.affectedAreaRefs,
    correctiveActionRefs: responsePlan.correctiveActionRefs,
    cqiLinkage,
    evidenceRefs,
    reporter: normalizeReporter(input.reporter),
  };
  const material = buildComplaintMaterial(input, normalized, materialRequired, responseRoles);
  const artifactHash = sha256Hex(material);
  const receipt = buildReceipt(input, artifactHash);

  return {
    schema: 'cybermedica.complaint_management_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    complaint: buildComplaint(input, artifactHash, normalized, materialRequired, responseRoles, receipt),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
