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
const INSPECTION_RESPONSE_SCHEMA = 'cybermedica.inspection_response_management.v1';
const REQUIRED_PERMISSION = 'inspection_response_manage';

const REQUIRED_RESPONSE_DOMAINS = Object.freeze([
  'capa_linkage',
  'classification',
  'closure_review',
  'disclosure_log',
  'due_date_control',
  'evidence_package',
  'finding_intake',
  'management_response',
  'regulatory_communication',
]);

const REQUIRED_FINDING_CATEGORIES = Object.freeze([
  'consent',
  'data_integrity',
  'documentation',
  'participant_safety',
  'privacy_security',
  'product_handling',
  'regulatory_reporting',
  'training_delegation',
]);

const INSPECTION_SOURCE_TYPES = new Set(['cro_audit', 'monitor_visit', 'regulatory_inspection', 'sponsor_audit']);
const POLICY_STATUSES = new Set(['active']);
const INSPECTION_EVENT_STATUSES = new Set(['findings_issued', 'response_ready', 'closed']);
const RESPONSE_DOMAIN_STATUSES = new Set(['complete']);
const FINDING_SEVERITIES = new Set(['minor', 'major', 'critical']);
const FINDING_STATUSES = new Set(['responded', 'closed']);
const CLOSURE_DECISIONS = new Set([
  'closed_with_capa_linkage',
  'hold_for_inspection_gap',
  'monitoring_accepted',
  'response_ready',
]);
const DECISION_FORUM_DECISIONS = new Set(['inspection_response_accepted', 'inspection_response_held']);
const MATERIAL_CATEGORIES = new Set([
  'consent',
  'data_integrity',
  'participant_safety',
  'privacy_security',
  'product_handling',
  'regulatory_reporting',
]);

const RAW_INSPECTION_RESPONSE_FIELDS = new Set([
  'findingbody',
  'findingnarrative',
  'freeformresponse',
  'inspectionbody',
  'managementresponsebody',
  'participantname',
  'rawcorrectiveaction',
  'rawevidence',
  'rawfinding',
  'rawfindingtext',
  'rawinspection',
  'rawmanagementresponse',
  'rawresponse',
  'responsebody',
  'sourcedocumentbody',
]);

const SECRET_INSPECTION_RESPONSE_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
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

function assertNoRawInspectionResponseContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawInspectionResponseContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_INSPECTION_RESPONSE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw inspection response content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_INSPECTION_RESPONSE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`inspection response secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawInspectionResponseContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawInspectionResponseContent(input ?? {});
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

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
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
  addReason(reasons, !hasText(input?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(input?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_inspection_response_owner_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'inspection_response_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
  addReason(reasons, hlcTuple(input?.checkedAtHlc) === null, 'checked_at_hlc_invalid');
}

function evaluateResponsePolicy(policy, checkedAtHlc, reasons) {
  const policyDomains = sortedTextList(policy?.requiredResponseDomains);
  const policyCategories = sortedTextList(policy?.requiredFindingCategories);

  addReason(reasons, !hasText(policy?.policyRef), 'inspection_response_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'inspection_response_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'inspection_response_policy_not_active');
  addReason(
    reasons,
    policy?.criticalFindingsRequireDecisionForum !== true,
    'critical_finding_decision_forum_policy_absent',
  );
  addReason(reasons, policy?.majorFindingsRequireCapa !== true, 'major_finding_capa_policy_absent');
  addReason(reasons, policy?.responseDueDatesRequired !== true, 'response_due_date_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'inspection_response_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'inspection_response_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'inspection_response_policy_time_invalid');
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, checkedAtHlc), 'inspection_response_policy_after_check');

  evaluateRequiredSet(
    policyDomains,
    REQUIRED_RESPONSE_DOMAINS,
    'policy_response_domain_missing',
    'policy_response_domain_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    policyCategories,
    REQUIRED_FINDING_CATEGORIES,
    'policy_finding_category_missing',
    'policy_finding_category_unsupported',
    reasons,
  );
}

function evaluateInspectionEvent(event, reasons) {
  addReason(reasons, !hasText(event?.inspectionRef), 'inspection_ref_absent');
  addReason(reasons, !INSPECTION_SOURCE_TYPES.has(event?.sourceType), 'inspection_source_type_invalid');
  addReason(reasons, !hasText(event?.sessionRef), 'inspection_session_ref_absent');
  addReason(reasons, !hasText(event?.inspectionModeReceiptId), 'inspection_mode_receipt_absent');
  addReason(reasons, !hasText(event?.inspectorOrganizationRef), 'inspector_organization_ref_absent');
  addReason(reasons, !INSPECTION_EVENT_STATUSES.has(event?.status), 'inspection_event_status_invalid');
  addReason(reasons, hlcTuple(event?.issuedAtHlc) === null, 'inspection_issued_time_invalid');
  addReason(reasons, hlcTuple(event?.responseDueAtHlc) === null, 'inspection_response_due_time_invalid');
  addReason(reasons, !hlcAfter(event?.responseDueAtHlc, event?.issuedAtHlc), 'inspection_response_due_not_after_issue');
  addReason(reasons, event?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, event?.metadataOnly !== true, 'inspection_event_metadata_boundary_invalid');
  addReason(reasons, event?.protectedContentExcluded !== true, 'inspection_event_protected_boundary_invalid');
}

function responseDomainSort(left, right) {
  return String(left?.domain).localeCompare(String(right?.domain));
}

function normalizeResponseDomains(input, reasons) {
  const domains = Array.isArray(input?.responseDomains) ? [...input.responseDomains].sort(responseDomainSort) : [];
  const present = sortedTextList(domains.map((domain) => domain?.domain));
  evaluateRequiredSet(present, REQUIRED_RESPONSE_DOMAINS, 'response_domain_missing', 'response_domain_unsupported', reasons);

  for (const domain of domains) {
    const domainRef = hasText(domain?.domain) ? domain.domain : 'unknown';
    addReason(reasons, !RESPONSE_DOMAIN_STATUSES.has(domain?.status), `response_domain_not_complete:${domainRef}`);
    addReason(reasons, !isDigest(domain?.evidenceHash), `response_domain_evidence_hash_invalid:${domainRef}`);
    addReason(reasons, domain?.metadataOnly !== true, `response_domain_metadata_boundary_invalid:${domainRef}`);
    addReason(reasons, domain?.protectedContentExcluded !== true, `response_domain_protected_boundary_invalid:${domainRef}`);
    addReason(reasons, hlcTuple(domain?.reviewedAtHlc) === null, `response_domain_review_time_invalid:${domainRef}`);
    addReason(
      reasons,
      hlcBefore(domain?.reviewedAtHlc, input?.inspectionEvent?.issuedAtHlc),
      `response_domain_review_before_issue:${domainRef}`,
    );
  }

  return present.filter((domain) => REQUIRED_RESPONSE_DOMAINS.includes(domain));
}

function findingSort(left, right) {
  return String(left?.findingRef).localeCompare(String(right?.findingRef));
}

function findingIsMaterial(finding) {
  return (
    finding?.severity === 'critical' ||
    finding?.severity === 'major' ||
    MATERIAL_CATEGORIES.has(finding?.category)
  );
}

function requiredCommunicationRoles(input, material) {
  const roles = new Set(['site_quality_lead']);
  if (material) {
    roles.add('decision_forum');
    roles.add('principal_investigator');
  }
  if (input?.inspectionEvent?.sourceType === 'regulatory_inspection') {
    roles.add('regulatory_contact');
  }
  if (['cro_audit', 'monitor_visit', 'sponsor_audit'].includes(input?.inspectionEvent?.sourceType)) {
    roles.add('sponsor_cro_contact');
  }
  return [...roles].sort();
}

function normalizeFindings(input, reasons) {
  const findings = Array.isArray(input?.findings) ? [...input.findings].sort(findingSort) : [];
  addReason(reasons, findings.length === 0, 'inspection_findings_absent');

  const normalized = [];
  for (const finding of findings) {
    const findingRef = hasText(finding?.findingRef) ? finding.findingRef : 'unknown';
    addReason(reasons, !hasText(finding?.findingRef), 'finding_ref_absent');
    addReason(reasons, !REQUIRED_FINDING_CATEGORIES.includes(finding?.category), `finding_category_invalid:${findingRef}`);
    addReason(reasons, !FINDING_SEVERITIES.has(finding?.severity), `finding_severity_invalid:${findingRef}`);
    addReason(reasons, !FINDING_STATUSES.has(finding?.status), `finding_not_responded:${findingRef}`);
    addReason(reasons, !isDigest(finding?.findingHash), `finding_hash_invalid:${findingRef}`);
    addReason(reasons, !isDigest(finding?.responseHash), `finding_response_hash_invalid:${findingRef}`);
    addReason(reasons, !hasText(finding?.ownerDid), `finding_owner_absent:${findingRef}`);
    addReason(reasons, hlcTuple(finding?.dueAtHlc) === null, `finding_due_time_invalid:${findingRef}`);
    addReason(reasons, hlcTuple(finding?.responseSubmittedAtHlc) === null, `finding_response_time_invalid:${findingRef}`);
    addReason(reasons, hlcBefore(finding?.dueAtHlc, input?.inspectionEvent?.issuedAtHlc), `finding_due_before_issue:${findingRef}`);
    addReason(
      reasons,
      hlcAfter(finding?.responseSubmittedAtHlc, finding?.dueAtHlc),
      `finding_response_submitted_after_due:${findingRef}`,
    );
    addReason(reasons, !isDigest(finding?.correctionEvidenceHash), `finding_correction_evidence_invalid:${findingRef}`);
    addReason(reasons, finding?.metadataOnly !== true, `finding_metadata_boundary_invalid:${findingRef}`);
    addReason(reasons, finding?.protectedContentExcluded !== true, `finding_protected_boundary_invalid:${findingRef}`);

    if (finding?.severity === 'critical') {
      addReason(reasons, !hasText(finding?.capaRef), `critical_finding_capa_absent:${findingRef}`);
    }
    if (finding?.severity === 'major') {
      addReason(reasons, !hasText(finding?.capaRef), `major_finding_capa_absent:${findingRef}`);
    }
    if (finding?.category === 'participant_safety') {
      addReason(reasons, !isDigest(finding?.participantSafetyReviewHash), `participant_safety_review_absent:${findingRef}`);
    }
    if (finding?.category === 'data_integrity') {
      addReason(reasons, !isDigest(finding?.dataIntegrityReviewHash), `data_integrity_review_absent:${findingRef}`);
    }

    normalized.push({
      capaRef: finding?.capaRef ?? null,
      category: finding?.category ?? null,
      dueAtHlc: finding?.dueAtHlc ?? null,
      findingHash: finding?.findingHash ?? null,
      findingRef,
      ownerDid: finding?.ownerDid ?? null,
      responseHash: finding?.responseHash ?? null,
      responseSubmittedAtHlc: finding?.responseSubmittedAtHlc ?? null,
      severity: finding?.severity ?? null,
      status: finding?.status ?? null,
    });
  }

  return normalized;
}

function evaluateResponsePackage(input, findings, reasons) {
  const pack = input?.responsePackage;
  addReason(reasons, !hasText(pack?.packageRef), 'response_package_ref_absent');
  addReason(reasons, !isDigest(pack?.packageHash), 'response_package_hash_invalid');
  addReason(reasons, !isDigest(pack?.evidenceIndexHash), 'response_package_evidence_index_hash_invalid');
  addReason(reasons, !isDigest(pack?.managementResponseHash), 'management_response_hash_invalid');
  addReason(reasons, !isDigest(pack?.responseManifestHash), 'response_manifest_hash_invalid');
  addReason(reasons, pack?.metadataOnly !== true, 'response_package_metadata_boundary_invalid');
  addReason(reasons, pack?.protectedContentExcluded !== true, 'response_package_protected_boundary_invalid');
  addReason(reasons, hlcTuple(pack?.submittedAtHlc) === null, 'response_package_submitted_time_invalid');
  addReason(reasons, hlcBefore(pack?.submittedAtHlc, input?.inspectionEvent?.issuedAtHlc), 'response_package_before_issue');
  addReason(reasons, hlcAfter(pack?.submittedAtHlc, input?.inspectionEvent?.responseDueAtHlc), 'response_package_submitted_after_due');

  for (const finding of findings) {
    addReason(
      reasons,
      hlcAfter(finding?.responseSubmittedAtHlc, input?.inspectionEvent?.responseDueAtHlc),
      `finding_response_after_event_due:${finding.findingRef}`,
    );
  }
}

function communicationSort(left, right) {
  return String(left?.recipientRole).localeCompare(String(right?.recipientRole));
}

function normalizeCommunications(input, roles, reasons) {
  const communications = Array.isArray(input?.communications) ? [...input.communications].sort(communicationSort) : [];
  const present = sortedTextList(communications.map((item) => item?.recipientRole));
  addReason(reasons, communications.length === 0, 'inspection_response_communications_absent');
  for (const role of roles) {
    addReason(reasons, !present.includes(role), `required_communication_missing:${role}`);
  }

  return communications.map((item, index) => {
    const recipientRole = hasText(item?.recipientRole) ? item.recipientRole : `index_${index}`;
    addReason(reasons, !isDigest(item?.communicationHash), `communication_hash_invalid:${recipientRole}`);
    addReason(reasons, item?.acknowledged !== true, `communication_acknowledgement_absent:${recipientRole}`);
    addReason(reasons, item?.metadataOnly !== true, `communication_metadata_boundary_invalid:${recipientRole}`);
    addReason(reasons, item?.protectedContentExcluded !== true, `communication_protected_boundary_invalid:${recipientRole}`);
    addReason(reasons, hlcTuple(item?.sentAtHlc) === null, `communication_time_invalid:${recipientRole}`);
    addReason(reasons, hlcBefore(item?.sentAtHlc, input?.inspectionEvent?.issuedAtHlc), `communication_before_issue:${recipientRole}`);
    return {
      acknowledged: item?.acknowledged === true,
      communicationHash: item?.communicationHash ?? null,
      recipientRole,
      sentAtHlc: item?.sentAtHlc ?? null,
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

  addReason(reasons, missing, 'decision_forum_required_for_material_findings');
  addReason(reasons, hlcBefore(forum?.decidedAtHlc, input?.inspectionEvent?.issuedAtHlc), 'decision_forum_before_issue');
}

function evaluateCorrectiveLinkage(input, findings, reasons) {
  const linkage = input?.correctiveLinkage;
  const requiredCapaRefs = sortedTextList(findings.filter((finding) => finding.severity !== 'minor').map((finding) => finding.capaRef));
  const actualCapaRefs = sortedTextList(linkage?.capaRefs);

  for (const capaRef of requiredCapaRefs) {
    addReason(reasons, !actualCapaRefs.includes(capaRef), `corrective_capa_ref_missing:${capaRef}`);
  }
  addReason(reasons, !hasText(linkage?.cqiCycleRef), 'corrective_cqi_linkage_absent');
  addReason(reasons, !hasText(linkage?.driftSignalRef), 'corrective_drift_linkage_absent');
  addReason(reasons, !isDigest(linkage?.effectivenessCheckHash), 'corrective_effectiveness_hash_invalid');
  addReason(reasons, !hasText(linkage?.ownerDid), 'corrective_owner_absent');
  addReason(reasons, linkage?.metadataOnly !== true, 'corrective_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(linkage?.dueAtHlc) === null, 'corrective_due_time_invalid');
  addReason(reasons, hlcBefore(linkage?.dueAtHlc, input?.responsePackage?.submittedAtHlc), 'corrective_due_before_response');
}

function evaluateClosureReview(input, reasons) {
  const review = input?.closureReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'closure_human_reviewer_absent');
  addReason(reasons, !CLOSURE_DECISIONS.has(review?.decision), 'closure_decision_invalid');
  addReason(reasons, !isDigest(review?.reviewEvidenceHash), 'closure_review_evidence_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'closure_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, input?.responsePackage?.submittedAtHlc), 'closure_review_before_response');
  addReason(reasons, review?.aiFinalAuthority === true, 'closure_ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'closure_production_trust_claim_guard_absent');
  addReason(reasons, review?.metadataOnly !== true, 'closure_review_metadata_boundary_invalid');
}

function evaluateAuditTrail(input, reasons) {
  const audit = input?.auditTrail;
  addReason(reasons, !isDigest(audit?.auditRecordHash), 'audit_record_hash_invalid');
  addReason(reasons, !isDigest(audit?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, !isDigest(audit?.responseHistoryHash), 'response_history_hash_invalid');
  addReason(reasons, audit?.metadataOnly !== true, 'audit_trail_metadata_boundary_invalid');
  addReason(reasons, audit?.protectedContentExcluded !== true, 'audit_trail_protected_boundary_invalid');
  addReason(reasons, hlcTuple(audit?.recordedAtHlc) === null, 'audit_trail_time_invalid');
  addReason(reasons, hlcBefore(audit?.recordedAtHlc, input?.closureReview?.reviewedAtHlc), 'audit_trail_before_closure');
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

function inspectionResponseId(input) {
  return `cminspectionresp_${sha256Hex({
    inspectionRef: input?.inspectionEvent?.inspectionRef ?? null,
    protocolRef: input?.protocolRef ?? null,
    siteRef: input?.siteRef ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function countFindings(findings, severity) {
  return findings.filter((finding) => finding.severity === severity).length;
}

function buildInspectionResponse(input, findings, coveredResponseDomains, communications, material, roles) {
  const packageMaterial = {
    auditRecordHash: input.auditTrail.auditRecordHash,
    communicationRoles: communications.map((item) => item.recipientRole),
    coveredResponseDomains,
    findingRefs: findings.map((finding) => finding.findingRef),
    findingResponseHashes: findings.map((finding) => finding.responseHash),
    inspectionRef: input.inspectionEvent.inspectionRef,
    managementResponseHash: input.responsePackage.managementResponseHash,
    responseManifestHash: input.responsePackage.responseManifestHash,
    responsePackageHash: input.responsePackage.packageHash,
  };
  const responseHash = sha256Hex(packageMaterial);

  return {
    schema: INSPECTION_RESPONSE_SCHEMA,
    inspectionResponseId: inspectionResponseId(input),
    inspectionRef: input.inspectionEvent.inspectionRef,
    inspectionSourceType: input.inspectionEvent.sourceType,
    tenantId: input.tenantId,
    siteRef: input.siteRef,
    protocolRef: input.protocolRef,
    status: input.closureReview.decision,
    responseHash,
    packageRef: input.responsePackage.packageRef,
    responsePackageHash: input.responsePackage.packageHash,
    findingCount: findings.length,
    criticalFindingCount: countFindings(findings, 'critical'),
    majorFindingCount: countFindings(findings, 'major'),
    materialDecisionForumRequired: material,
    requiredResponseRoles: roles,
    coveredResponseDomains,
    findingRefs: findings.map((finding) => finding.findingRef),
    communicationRoles: communications.map((item) => item.recipientRole),
    decisionForumMatterRef: material ? input.decisionForum.matterRef : null,
    decisionForumReceiptId: material ? input.decisionForum.receiptId : null,
    capaRefs: sortedTextList(input.correctiveLinkage.capaRefs),
    cqiCycleRef: input.correctiveLinkage.cqiCycleRef,
    driftSignalRef: input.correctiveLinkage.driftSignalRef,
    auditRecordHash: input.auditTrail.auditRecordHash,
    disclosureLogHash: input.auditTrail.disclosureLogHash,
    reviewedByDid: input.closureReview.reviewerDid,
    reviewedAtHlc: input.closureReview.reviewedAtHlc,
    metadataOnly: true,
    trustState: 'inactive',
    exochainProductionClaim: false,
    containsProtectedContent: false,
  };
}

function buildReceipt(input, inspectionResponse) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sha256Hex(inspectionResponse),
    artifactType: 'inspection_response_package',
    artifactVersion: `${inspectionResponse.inspectionRef}@${inspectionResponse.status}`,
    classification: 'inspection_response_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.closureReview.reviewedAtHlc,
    sensitivityTags: ['inspection_response', 'metadata_only', 'audit_findings'],
    sourceSystem: 'cybermedica.inspection_response_management',
    tenantId: input.tenantId,
  });
}

export function evaluateInspectionResponseManagement(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateResponsePolicy(input?.responsePolicy, input?.checkedAtHlc, reasons);
  evaluateInspectionEvent(input?.inspectionEvent, reasons);
  const coveredResponseDomains = normalizeResponseDomains(input, reasons);
  const findings = normalizeFindings(input, reasons);
  evaluateResponsePackage(input, findings, reasons);
  const material = findings.some(findingIsMaterial);
  const roles = requiredCommunicationRoles(input, material);
  const communications = normalizeCommunications(input, roles, reasons);
  evaluateDecisionForum(input, material, reasons);
  evaluateCorrectiveLinkage(input, findings, reasons);
  evaluateClosureReview(input, reasons);
  evaluateAuditTrail(input, reasons);
  evaluateAiAssistance(input, reasons);

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: 'cybermedica.inspection_response_management_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      inspectionResponse: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const inspectionResponse = buildInspectionResponse(
    input,
    findings,
    coveredResponseDomains,
    communications,
    material,
    roles,
  );
  const receipt = buildReceipt(input, inspectionResponse);

  return {
    schema: 'cybermedica.inspection_response_management_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    inspectionResponse,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
