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
const INCIDENT_SCHEMA = 'cybermedica.incident_response_management.v1';
const REQUIRED_PERMISSION = 'incident_response_manage';

const REQUIRED_INCIDENT_FAMILIES = Object.freeze([
  'adapter_degraded',
  'availability_outage',
  'data_integrity_event',
  'privacy_boundary_failure',
  'receipt_queue_backlog',
  'root_bundle_unavailable',
  'security_event',
  'sponsor_export_disclosure',
]);

const REQUIRED_RESPONSE_DOMAINS = Object.freeze([
  'audit_record',
  'communications',
  'containment',
  'decision_forum',
  'drift_or_cqi',
  'evidence_preservation',
  'restoration',
  'root_cause',
  'triage',
]);

const POLICY_STATUSES = new Set(['active']);
const SEVERITY_LEVELS = new Set(['minor', 'major', 'critical']);
const INCIDENT_STATUSES = new Set(['closed_corrective_action_linked', 'contained', 'monitoring', 'restored']);
const CONTAINMENT_STATUSES = new Set(['contained', 'monitoring']);
const RESTORATION_STATUSES = new Set(['monitoring_verified', 'verified_restored']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_incident_gap',
  'incident_closed_corrective_action_linked',
  'incident_monitoring_accepted',
  'incident_restoration_accepted',
]);
const DECISION_FORUM_DECISIONS = new Set(['incident_response_accepted', 'incident_response_held']);
const EVIDENCE_CLASSIFICATIONS = new Set([
  'confidential_metadata_only',
  'restricted_metadata_only',
  'sponsor_confidential_metadata_only',
]);
const MATERIAL_INCIDENT_FAMILIES = new Set([
  'data_integrity_event',
  'privacy_boundary_failure',
  'security_event',
  'sponsor_export_disclosure',
]);

const RAW_INCIDENT_FIELDS = new Set([
  'containmentnarrative',
  'debugpayload',
  'freetext',
  'healthpayload',
  'incidentbody',
  'incidentnarrative',
  'participantname',
  'rawcontainment',
  'rawevidence',
  'rawhealthresponse',
  'rawincident',
  'rawpayload',
  'rawrootcause',
  'rawsource',
  'restorationpayload',
  'rootcausenarrative',
  'sourcedocumentbody',
]);

const SECRET_INCIDENT_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'bootstraptoken',
  'clientsecret',
  'credential',
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

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
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

function assertNoRawIncidentContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawIncidentContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_INCIDENT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw incident response content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_INCIDENT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`incident response secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawIncidentContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawIncidentContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
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

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateRequiredTextSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.siteId), 'site_id_absent');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_incident_commander_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'incident_response_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
  addReason(reasons, hlcTuple(input?.checkedAtHlc) === null, 'checked_at_hlc_invalid');
}

function evaluatePolicy(policy, checkedAtHlc, reasons) {
  const families = sortedTextList(policy?.requiredIncidentFamilies);
  const domains = sortedTextList(policy?.requiredResponseDomains);

  addReason(reasons, !hasText(policy?.policyRef), 'incident_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'incident_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'incident_policy_not_active');
  addReason(reasons, policy?.materialDecisionForumRequired !== true, 'incident_policy_decision_forum_rule_absent');
  addReason(reasons, policy?.humanIncidentCommanderRequired !== true, 'incident_policy_human_commander_rule_absent');
  addReason(reasons, policy?.noProductionTrustClaimWithoutActivation !== true, 'incident_policy_trust_claim_guard_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'incident_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'incident_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'incident_policy_evaluated_time_invalid');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, checkedAtHlc), 'incident_policy_evaluated_after_check');

  evaluateRequiredTextSet(
    families,
    REQUIRED_INCIDENT_FAMILIES,
    'incident_policy_family_missing',
    'incident_policy_family_unsupported',
    reasons,
  );
  evaluateRequiredTextSet(
    domains,
    REQUIRED_RESPONSE_DOMAINS,
    'incident_policy_response_domain_missing',
    'incident_policy_response_domain_unsupported',
    reasons,
  );

  return { domains, families };
}

function materialIncident(incident) {
  return (
    incident?.severity === 'critical' ||
    MATERIAL_INCIDENT_FAMILIES.has(incident?.incidentFamily) ||
    incident?.participantSafetyImpact === true ||
    incident?.dataIntegrityImpact === true ||
    incident?.sponsorCroImpact === true
  );
}

function requiredResponseRoles(incident, material) {
  const roles = new Set(['incident_commander', 'operations_owner', 'site_quality_lead']);
  if (material) {
    roles.add('decision_forum');
  }
  if (['privacy_boundary_failure', 'sponsor_export_disclosure'].includes(incident?.incidentFamily)) {
    roles.add('privacy_officer');
  }
  if (['privacy_boundary_failure', 'security_event'].includes(incident?.incidentFamily)) {
    roles.add('security_owner');
  }
  if (incident?.sponsorCroImpact === true || incident?.incidentFamily === 'sponsor_export_disclosure') {
    roles.add('sponsor_cro_contact');
  }
  return [...roles].sort();
}

function evaluateIncident(incident, reasons) {
  addReason(reasons, !hasText(incident?.incidentRef), 'incident_ref_absent');
  addReason(reasons, !REQUIRED_INCIDENT_FAMILIES.includes(incident?.incidentFamily), 'incident_family_invalid');
  addReason(reasons, !SEVERITY_LEVELS.has(incident?.severity), 'incident_severity_invalid');
  addReason(reasons, !INCIDENT_STATUSES.has(incident?.status), 'incident_status_invalid');
  addReason(reasons, !hasText(incident?.sourceSignalRef), 'incident_source_signal_absent');
  addReason(reasons, !hasText(incident?.sourceSystemRef), 'incident_source_system_absent');
  addReason(reasons, hlcTuple(incident?.detectedAtHlc) === null, 'incident_detected_time_invalid');
  addReason(reasons, incident?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, incident?.metadataOnly !== true, 'incident_metadata_boundary_invalid');
  addReason(reasons, incident?.protectedContentExcluded !== true, 'incident_protected_boundary_invalid');
  addReason(reasons, sortedTextList(incident?.affectedServiceRefs).length === 0, 'affected_services_absent');
  addReason(reasons, sortedTextList(incident?.affectedControlRefs).length === 0, 'affected_controls_absent');
}

function evaluateTriage(input, material, reasons) {
  const triage = input?.triage;
  addReason(reasons, !isDigest(triage?.classificationHash), 'triage_classification_hash_invalid');
  addReason(reasons, !hasText(triage?.classifiedByDid), 'triage_classifier_absent');
  addReason(reasons, !hasText(triage?.incidentCommanderDid), 'incident_commander_absent');
  addReason(reasons, triage?.severityConfirmed !== true, 'incident_severity_unconfirmed');
  addReason(reasons, material && triage?.materialityConfirmed !== true, 'materiality_unconfirmed');
  addReason(reasons, input?.incident?.participantSafetyImpact === true && triage?.participantSafetyReviewed !== true, 'participant_safety_review_absent');
  addReason(reasons, input?.incident?.dataIntegrityImpact === true && triage?.dataIntegrityReviewed !== true, 'data_integrity_review_absent');
  addReason(reasons, input?.incident?.sponsorCroImpact === true && triage?.sponsorCroReviewed !== true, 'sponsor_cro_review_absent');
  addReason(reasons, triage?.metadataOnly !== true, 'triage_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(triage?.classifiedAtHlc) === null, 'triage_time_invalid');
  addReason(reasons, hlcBefore(triage?.classifiedAtHlc, input?.incident?.detectedAtHlc), 'triage_before_detection');
}

function evaluateContainment(input, material, reasons) {
  const containment = input?.containment;
  addReason(reasons, !CONTAINMENT_STATUSES.has(containment?.status), 'containment_status_invalid');
  addReason(reasons, !isDigest(containment?.containmentEvidenceHash), 'containment_evidence_hash_invalid');
  addReason(reasons, hlcTuple(containment?.containedAtHlc) === null, 'containment_time_invalid');
  addReason(reasons, hlcBefore(containment?.containedAtHlc, input?.incident?.detectedAtHlc), 'containment_before_detection');
  addReason(reasons, material && containment?.affectedAccessDisabled !== true, 'affected_access_not_disabled');
  addReason(reasons, material && containment?.trustClaimsFrozen !== true, 'trust_claim_freeze_absent');
  addReason(reasons, material && containment?.protectedExportsPaused !== true, 'protected_exports_pause_absent');
  addReason(reasons, containment?.failClosedObserved !== true, 'fail_closed_containment_absent');
  addReason(reasons, containment?.metadataOnly !== true, 'containment_metadata_boundary_invalid');
  addReason(reasons, containment?.protectedContentExcluded !== true, 'containment_protected_boundary_invalid');
}

function evaluateEvidencePreservation(input, reasons) {
  const preservation = input?.evidencePreservation;
  addReason(reasons, !isDigest(preservation?.custodyDigest), 'preservation_custody_digest_invalid');
  addReason(reasons, !isDigest(preservation?.legalHoldHash), 'legal_hold_hash_invalid');
  addReason(reasons, !isDigest(preservation?.evidenceIndexHash), 'evidence_index_hash_invalid');
  addReason(reasons, preservation?.rawPayloadsExcluded !== true, 'raw_payload_boundary_absent');
  addReason(reasons, sortedTextList(preservation?.immutableAuditRefs).length === 0, 'immutable_audit_refs_absent');
  addReason(reasons, preservation?.metadataOnly !== true, 'preservation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(preservation?.preservedAtHlc) === null, 'preservation_time_invalid');
  addReason(reasons, hlcBefore(preservation?.preservedAtHlc, input?.incident?.detectedAtHlc), 'preservation_before_detection');
}

function evidenceSort(left, right) {
  return String(left?.evidenceRef).localeCompare(String(right?.evidenceRef));
}

function normalizeEvidenceRefs(evidenceRefs, reasons) {
  const refs = Array.isArray(evidenceRefs) ? [...evidenceRefs].sort(evidenceSort) : [];
  addReason(reasons, refs.length === 0, 'incident_evidence_absent');
  return refs.map((evidence, index) => {
    const evidenceRef = hasText(evidence?.evidenceRef) ? evidence.evidenceRef : `index_${index}`;
    addReason(reasons, !hasText(evidence?.evidenceRef), 'incident_evidence_ref_absent');
    addReason(reasons, !hasText(evidence?.artifactType), `incident_evidence_type_absent:${evidenceRef}`);
    addReason(reasons, !isDigest(evidence?.artifactHash), `incident_evidence_hash_invalid:${evidenceRef}`);
    addReason(reasons, !isDigest(evidence?.custodyDigest), `incident_evidence_custody_invalid:${evidenceRef}`);
    addReason(reasons, !hasText(evidence?.receiptId), `incident_evidence_receipt_absent:${evidenceRef}`);
    addReason(reasons, !EVIDENCE_CLASSIFICATIONS.has(evidence?.classification), `incident_evidence_classification_invalid:${evidenceRef}`);
    addReason(reasons, evidence?.metadataOnly !== true, `incident_evidence_metadata_boundary_invalid:${evidenceRef}`);
    addReason(reasons, evidence?.protectedContentExcluded !== true, `incident_evidence_protected_boundary_invalid:${evidenceRef}`);
    return {
      artifactHash: evidence?.artifactHash ?? null,
      artifactType: evidence?.artifactType ?? null,
      classification: evidence?.classification ?? null,
      custodyDigest: evidence?.custodyDigest ?? null,
      evidenceRef,
      receiptId: evidence?.receiptId ?? null,
    };
  });
}

function evaluateRootCause(input, material, reasons) {
  const rootCause = input?.rootCause;
  addReason(reasons, !isDigest(rootCause?.analysisHash), 'root_cause_analysis_hash_invalid');
  addReason(reasons, sortedTextList(rootCause?.categoryRefs).length === 0, 'root_cause_categories_absent');
  addReason(reasons, material && sortedTextList(rootCause?.correctiveActionRefs).length === 0, 'root_cause_corrective_actions_absent');
  addReason(reasons, sortedTextList(rootCause?.preventiveActionRefs).length === 0, 'root_cause_preventive_actions_absent');
  addReason(reasons, rootCause?.humanReviewed !== true, 'root_cause_human_review_absent');
  addReason(reasons, rootCause?.metadataOnly !== true, 'root_cause_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(rootCause?.completedAtHlc) === null, 'root_cause_time_invalid');
  addReason(reasons, hlcBefore(rootCause?.completedAtHlc, input?.containment?.containedAtHlc), 'root_cause_before_containment');
}

function communicationSort(left, right) {
  return String(left?.audienceClass).localeCompare(String(right?.audienceClass));
}

function normalizeCommunications(input, roles, reasons) {
  const communications = Array.isArray(input?.communications) ? [...input.communications].sort(communicationSort) : [];
  const audiences = sortedTextList(communications.map((item) => item?.audienceClass));
  addReason(reasons, communications.length === 0, 'incident_communications_absent');
  for (const role of roles) {
    addReason(reasons, !audiences.includes(role), `incident_communication_missing:${role}`);
  }
  return communications.map((item, index) => {
    const audienceClass = hasText(item?.audienceClass) ? item.audienceClass : `index_${index}`;
    addReason(reasons, !hasText(item?.channelRef), `communication_channel_absent:${audienceClass}`);
    addReason(reasons, !isDigest(item?.messageHash), `communication_message_hash_invalid:${audienceClass}`);
    addReason(reasons, item?.acknowledged !== true, `communication_acknowledgement_absent:${audienceClass}`);
    addReason(reasons, item?.metadataOnly !== true, `communication_metadata_boundary_invalid:${audienceClass}`);
    addReason(reasons, item?.protectedContentExcluded !== true, `communication_protected_boundary_invalid:${audienceClass}`);
    addReason(reasons, hlcTuple(item?.deliveredAtHlc) === null, `communication_time_invalid:${audienceClass}`);
    addReason(reasons, hlcBefore(item?.deliveredAtHlc, input?.incident?.detectedAtHlc), `communication_before_detection:${audienceClass}`);
    return {
      acknowledged: item?.acknowledged === true,
      audienceClass,
      channelRef: item?.channelRef ?? null,
      deliveredAtHlc: item?.deliveredAtHlc ?? null,
      messageHash: item?.messageHash ?? null,
    };
  });
}

function evaluateDecisionForum(input, material, reasons) {
  const forum = input?.decisionForum;
  if (!material) {
    addReason(reasons, forum?.invoked === true && !hasText(forum?.matterRef), 'decision_forum_matter_ref_absent');
    return;
  }
  const missing =
    forum?.invoked !== true ||
    !hasText(forum?.matterRef) ||
    !hasText(forum?.receiptId) ||
    forum?.quorumStatus !== 'met' ||
    forum?.humanGateVerified !== true ||
    forum?.openChallenge === true ||
    !DECISION_FORUM_DECISIONS.has(forum?.decision) ||
    hlcTuple(forum?.decidedAtHlc) === null;
  addReason(reasons, missing, 'critical_incident_decision_forum_missing');
  addReason(reasons, hlcBefore(forum?.decidedAtHlc, input?.triage?.classifiedAtHlc), 'decision_forum_before_triage');
}

function evaluateRestoration(input, material, reasons) {
  const restoration = input?.restoration;
  addReason(reasons, !RESTORATION_STATUSES.has(restoration?.status), 'restoration_status_invalid');
  addReason(reasons, !isDigest(restoration?.restorationEvidenceHash), 'restoration_evidence_hash_invalid');
  addReason(reasons, !isDigest(restoration?.validationEvidenceHash), 'restoration_validation_hash_invalid');
  addReason(reasons, material && restoration?.privacyBoundaryReverified !== true, 'restoration_privacy_boundary_unverified');
  addReason(reasons, material && restoration?.receiptQueueReconciled !== true, 'restoration_receipt_queue_unreconciled');
  addReason(reasons, restoration?.trustReadinessRemainsInactive !== true, 'restoration_trust_readiness_claim_invalid');
  addReason(reasons, restoration?.metadataOnly !== true, 'restoration_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(restoration?.restoredAtHlc) === null, 'restoration_time_invalid');
  addReason(reasons, hlcBefore(restoration?.restoredAtHlc, input?.containment?.containedAtHlc), 'restoration_before_containment');
}

function evaluateCorrectiveLinkage(input, reasons) {
  const linkage = input?.correctiveLinkage;
  addReason(reasons, !hasText(linkage?.capaRef), 'corrective_capa_linkage_absent');
  addReason(reasons, !hasText(linkage?.cqiCycleRef), 'corrective_cqi_linkage_absent');
  addReason(reasons, !hasText(linkage?.driftSignalRef), 'corrective_drift_linkage_absent');
  addReason(reasons, !isDigest(linkage?.effectivenessCheckHash), 'corrective_effectiveness_hash_invalid');
  addReason(reasons, !hasText(linkage?.ownerDid), 'corrective_owner_absent');
  addReason(reasons, linkage?.metadataOnly !== true, 'corrective_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(linkage?.dueAtHlc) === null, 'corrective_due_time_invalid');
  addReason(reasons, hlcBefore(linkage?.dueAtHlc, input?.incident?.detectedAtHlc), 'corrective_due_before_detection');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, review?.verified !== true, 'human_review_unverified');
  addReason(reasons, !hasText(review?.reviewedByDid), 'human_review_reviewer_absent');
  addReason(reasons, !isDigest(review?.reviewEvidenceHash), 'human_review_evidence_hash_invalid');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, input?.restoration?.restoredAtHlc), 'human_review_before_restoration');
}

function evaluateAuditRecord(input, reasons) {
  const audit = input?.auditRecord;
  addReason(reasons, !hasText(audit?.auditRecordRef), 'audit_record_ref_absent');
  addReason(reasons, !isDigest(audit?.auditRecordHash), 'audit_record_hash_invalid');
  addReason(reasons, audit?.metadataOnly !== true, 'audit_record_metadata_boundary_invalid');
  addReason(reasons, audit?.includesProtectedContent === true, 'audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(audit?.recordedAtHlc) === null, 'audit_record_time_invalid');
  addReason(reasons, hlcBefore(audit?.recordedAtHlc, input?.humanReview?.reviewedAtHlc), 'audit_record_before_human_review');
}

function evaluateAiAssistance(input, reasons) {
  const ai = input?.aiAssistance;
  if (ai === null || ai === undefined || ai.used !== true) {
    return;
  }
  addReason(reasons, ai.advisoryOnly !== true, 'ai_assistance_not_advisory');
  addReason(reasons, ai.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(ai.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, ai.humanReviewed !== true, 'ai_human_review_absent');
}

function incidentResponseId(input) {
  return `cminc_${sha256Hex({
    detectedAtHlc: input?.incident?.detectedAtHlc ?? null,
    incidentFamily: input?.incident?.incidentFamily ?? null,
    incidentRef: input?.incident?.incidentRef ?? null,
    siteId: input?.siteId ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function buildIncidentRecord(input, material, roles, evidenceRefs, communications) {
  const recordId = incidentResponseId(input);
  return {
    schema: INCIDENT_SCHEMA,
    incidentResponseId: recordId,
    incidentRef: input.incident.incidentRef,
    tenantId: input.tenantId,
    siteId: input.siteId,
    sourceSignalRef: input.incident.sourceSignalRef,
    incidentFamily: input.incident.incidentFamily,
    severity: input.incident.severity,
    status: input.incident.status,
    materialDecisionForumRequired: material,
    participantSafetyImpact: input.incident.participantSafetyImpact === true,
    dataIntegrityImpact: input.incident.dataIntegrityImpact === true,
    sponsorCroImpact: input.incident.sponsorCroImpact === true,
    affectedServiceRefs: sortedTextList(input.incident.affectedServiceRefs),
    affectedControlRefs: sortedTextList(input.incident.affectedControlRefs),
    requiredResponseRoles: roles,
    containmentStatus: input.containment.status,
    restorationStatus: input.restoration.status,
    evidenceRefs: evidenceRefs.map((item) => item.evidenceRef),
    communicationAudiences: communications.map((item) => item.audienceClass),
    decisionForumMatterRef: material ? input.decisionForum.matterRef : null,
    decisionForumReceiptId: material ? input.decisionForum.receiptId : null,
    capaRef: input.correctiveLinkage.capaRef,
    cqiCycleRef: input.correctiveLinkage.cqiCycleRef,
    driftSignalRef: input.correctiveLinkage.driftSignalRef,
    auditRecordRef: input.auditRecord.auditRecordRef,
    reviewedByDid: input.humanReview.reviewedByDid,
    reviewedAtHlc: input.humanReview.reviewedAtHlc,
    aiFinalAuthority: input.aiAssistance?.finalAuthority === true,
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function buildReceipt(input, record) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sha256Hex(record),
    artifactType: 'incident_response_record',
    artifactVersion: `${record.incidentRef}@${record.status}`,
    classification: 'incident_response_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: ['incident_response', 'metadata_only', 'operational_readiness'],
    sourceSystem: 'cybermedica.incident_response_management',
    tenantId: input.tenantId,
  });
}

export function evaluateIncidentResponseManagement(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.incidentPolicy, input?.checkedAtHlc, reasons);
  evaluateIncident(input?.incident, reasons);

  const material = materialIncident(input?.incident);
  const roles = requiredResponseRoles(input?.incident, material);

  evaluateTriage(input, material, reasons);
  evaluateContainment(input, material, reasons);
  evaluateEvidencePreservation(input, reasons);
  const evidenceRefs = normalizeEvidenceRefs(input?.evidenceRefs, reasons);
  evaluateRootCause(input, material, reasons);
  const communications = normalizeCommunications(input, roles, reasons);
  evaluateDecisionForum(input, material, reasons);
  evaluateRestoration(input, material, reasons);
  evaluateCorrectiveLinkage(input, reasons);
  evaluateHumanReview(input, reasons);
  evaluateAuditRecord(input, reasons);
  evaluateAiAssistance(input, reasons);

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: `${INCIDENT_SCHEMA}_decision.v1`,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      incidentRecord: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const incidentRecord = buildIncidentRecord(input, material, roles, evidenceRefs, communications);
  const receipt = buildReceipt(input, incidentRecord);

  return {
    schema: `${INCIDENT_SCHEMA}_decision.v1`,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    incidentRecord,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
