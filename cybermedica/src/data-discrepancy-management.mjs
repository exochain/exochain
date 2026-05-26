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
const REQUIRED_PERMISSION = 'manage_data_discrepancies';
const DATA_DISCREPANCY_SCHEMA = 'cybermedica.data_discrepancy_management.v1';

const REQUIRED_DISCREPANCY_DOMAINS = Object.freeze([
  'audit_trail',
  'closure_review',
  'correction_linkage',
  'discrepancy_intake',
  'medical_review',
  'monitor_review',
  'query_issuance',
  'query_response_review',
  'source_crf_linkage',
  'urgent_reporting',
]);

const ACTIVE_PLAN_STATUSES = new Set(['active']);
const VERIFIED_DOMAIN_STATUSES = new Set(['verified', 'validated']);
const DISCREPANCY_SEVERITIES = new Set(['critical', 'major', 'minor', 'observation']);
const RESOLVED_DISCREPANCY_STATUSES = new Set(['closed', 'resolved', 'void']);
const QUERY_CLOSED_STATUSES = new Set(['cancelled', 'closed']);
const REVIEW_DECISIONS = new Set(['data_discrepancies_reconciled', 'hold_data_discrepancy_gap']);

const RAW_DISCREPANCY_FIELDS = new Set([
  'crfvalue',
  'directidentifier',
  'discrepancynarrative',
  'discrepancynote',
  'freetextquery',
  'medicalrecordnumber',
  'participantidentifier',
  'participantname',
  'patientname',
  'querybody',
  'queryresponsebody',
  'rawcrf',
  'rawcrfvalue',
  'rawdiscrepancy',
  'rawquery',
  'rawqueryresponse',
  'rawsource',
  'rawsourcedata',
  'rawsourcedocument',
  'rawsourcedocumenttext',
  'responsebody',
  'sourcebody',
  'sourcedocumentbody',
  'subjectidentifier',
]);

const SECRET_DISCREPANCY_FIELDS = new Set([
  'accesstoken',
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

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function nonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
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

function assertNoRawDiscrepancyContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDiscrepancyContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_DISCREPANCY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw data discrepancy content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_DISCREPANCY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`data discrepancy secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawDiscrepancyContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawDiscrepancyContent(input ?? {});
  canonicalize(input ?? {});
}

function hlcTuple(hlc) {
  if (!Number.isSafeInteger(hlc?.physicalMs) || !Number.isSafeInteger(hlc?.logical) || hlc.logical < 0) {
    return null;
  }
  return [BigInt(hlc.physicalMs), BigInt(hlc.logical)];
}

function compareHlc(left, right) {
  if (left[0] < right[0]) {
    return -1;
  }
  if (left[0] > right[0]) {
    return 1;
  }
  if (left[1] < right[1]) {
    return -1;
  }
  if (left[1] > right[1]) {
    return 1;
  }
  return 0;
}

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
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
    'data_discrepancy_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateDiscrepancyPlan(input, reasons) {
  const plan = input?.discrepancyPlan;
  addReason(reasons, !hasText(plan?.planRef), 'plan_ref_absent');
  addReason(reasons, !hasText(plan?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(plan?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(plan?.studyRef), 'study_ref_absent');
  addReason(reasons, !ACTIVE_PLAN_STATUSES.has(plan?.status), 'plan_not_active');
  addReason(reasons, !isDigest(plan?.discrepancyProcedureHash), 'discrepancy_procedure_hash_invalid');
  addReason(reasons, !isDigest(plan?.queryProcedureHash), 'query_procedure_hash_invalid');
  addReason(reasons, !isDigest(plan?.correctionProcedureHash), 'correction_procedure_hash_invalid');
  addReason(reasons, !isDigest(plan?.urgentReportingProcedureHash), 'urgent_reporting_procedure_hash_invalid');
  addReason(reasons, !hasText(plan?.sourceTraceabilityPlanRef), 'source_traceability_plan_ref_absent');
  addReason(reasons, !hasText(plan?.informationManagementPlanRef), 'information_management_plan_ref_absent');
  addReason(reasons, hlcTuple(plan?.evaluatedAtHlc) === null, 'plan_evaluation_time_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'plan_metadata_only_attestation_absent');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'plan_protected_content_boundary_absent');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateDomainCoverage(input, reasons) {
  const requiredDomains = sortedTextList(input?.discrepancyPlan?.requiredDomains);
  evaluateRequiredSet(
    requiredDomains,
    REQUIRED_DISCREPANCY_DOMAINS,
    'required_domain_missing',
    'required_domain_unsupported',
    reasons,
  );

  const coveredDomains = sortedTextList(
    (Array.isArray(input?.domainEvidence) ? input.domainEvidence : [])
      .filter((entry) => VERIFIED_DOMAIN_STATUSES.has(entry?.status) && isDigest(entry?.evidenceHash))
      .map((entry) => entry.domainRef),
  );
  evaluateRequiredSet(
    coveredDomains,
    REQUIRED_DISCREPANCY_DOMAINS,
    'domain_evidence_missing',
    'domain_evidence_unsupported',
    reasons,
  );

  for (const entry of Array.isArray(input?.domainEvidence) ? input.domainEvidence : []) {
    const ref = hasText(entry?.domainRef) ? entry.domainRef : 'unknown';
    addReason(reasons, hlcTuple(entry?.reviewedAtHlc) === null, `domain_review_time_invalid:${ref}`);
    addReason(reasons, entry?.metadataOnly !== true, `domain_metadata_only_attestation_absent:${ref}`);
    addReason(reasons, entry?.protectedContentExcluded !== true, `domain_protected_content_boundary_absent:${ref}`);
  }

  return { coveredDomains, requiredDomains };
}

function evaluateDiscrepancyRecords(input, reasons) {
  const records = Array.isArray(input?.discrepancyRecords) ? input.discrepancyRecords : [];
  addReason(reasons, records.length === 0, 'discrepancy_record_list_absent');
  for (const record of records) {
    const ref = hasText(record?.discrepancyRef) ? record.discrepancyRef : 'unknown';
    addReason(reasons, !hasText(record?.discrepancyRef), 'discrepancy_ref_absent');
    addReason(reasons, !hasText(record?.sourceRecordRef), `discrepancy_source_record_ref_absent:${ref}`);
    addReason(reasons, !hasText(record?.crfFieldRef), `discrepancy_crf_field_ref_absent:${ref}`);
    addReason(reasons, !isDigest(record?.participantCodeHash), `discrepancy_participant_code_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(record?.discrepancyHash), `discrepancy_hash_invalid:${ref}`);
    addReason(reasons, !DISCREPANCY_SEVERITIES.has(record?.severity), `discrepancy_severity_invalid:${ref}`);
    addReason(reasons, !hasText(record?.category), `discrepancy_category_absent:${ref}`);
    addReason(reasons, !hasText(record?.assignedOwnerDid), `discrepancy_owner_absent:${ref}`);
    addReason(reasons, !hasText(record?.sourceTraceabilityRef), `discrepancy_source_traceability_ref_absent:${ref}`);
    addReason(
      reasons,
      !isDigest(record?.sourceTraceabilityHash),
      `discrepancy_source_traceability_hash_invalid:${ref}`,
    );
    addReason(reasons, hlcTuple(record?.detectedAtHlc) === null, `discrepancy_detected_time_invalid:${ref}`);
    addReason(reasons, !hlcAfter(record?.dueAtHlc, record?.detectedAtHlc), `discrepancy_due_time_invalid:${ref}`);
    addReason(reasons, !RESOLVED_DISCREPANCY_STATUSES.has(record?.status), `discrepancy_unresolved:${ref}`);
    if (RESOLVED_DISCREPANCY_STATUSES.has(record?.status)) {
      addReason(
        reasons,
        !hlcAfter(record?.resolvedAtHlc, record?.detectedAtHlc),
        `discrepancy_resolved_before_detection:${ref}`,
      );
    }
    addReason(reasons, record?.metadataOnly !== true, `discrepancy_metadata_only_attestation_absent:${ref}`);
    addReason(reasons, record?.protectedContentExcluded !== true, `discrepancy_protected_content_boundary_absent:${ref}`);
  }
  return records;
}

function discrepancyRefs(records) {
  return new Set(records.filter((record) => hasText(record?.discrepancyRef)).map((record) => record.discrepancyRef));
}

function evaluateQueryRecords(input, knownDiscrepancyRefs, reasons) {
  const records = Array.isArray(input?.queryRecords) ? input.queryRecords : [];
  addReason(reasons, records.length === 0, 'query_record_list_absent');
  for (const record of records) {
    const ref = hasText(record?.queryRef) ? record.queryRef : 'unknown';
    addReason(reasons, !hasText(record?.queryRef), 'query_ref_absent');
    addReason(reasons, !hasText(record?.discrepancyRef), `query_discrepancy_ref_absent:${ref}`);
    addReason(
      reasons,
      hasText(record?.discrepancyRef) && !knownDiscrepancyRefs.has(record.discrepancyRef),
      `query_discrepancy_ref_unknown:${record?.discrepancyRef}`,
    );
    addReason(reasons, !hasText(record?.issuedByDid), `query_issuer_absent:${ref}`);
    addReason(reasons, !hasText(record?.responderDid), `query_responder_absent:${ref}`);
    addReason(reasons, !isDigest(record?.queryHash), `query_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(record?.responseHash), `query_response_hash_invalid:${ref}`);
    addReason(reasons, !QUERY_CLOSED_STATUSES.has(record?.status), `query_not_closed:${ref}`);
    addReason(reasons, record?.responseAccepted !== true, `query_response_not_accepted:${ref}`);
    addReason(reasons, hlcTuple(record?.issuedAtHlc) === null, `query_issue_time_invalid:${ref}`);
    addReason(reasons, !hlcAfter(record?.respondedAtHlc, record?.issuedAtHlc), `query_response_before_issue:${ref}`);
    addReason(reasons, !hlcAfter(record?.reviewedAtHlc, record?.respondedAtHlc), `query_review_before_response:${ref}`);
    addReason(reasons, record?.metadataOnly !== true, `query_metadata_only_attestation_absent:${ref}`);
    addReason(reasons, record?.protectedContentExcluded !== true, `query_protected_content_boundary_absent:${ref}`);
  }
  return records;
}

function evaluateCorrectionRecords(input, knownDiscrepancyRefs, reasons) {
  const records = Array.isArray(input?.correctionRecords) ? input.correctionRecords : [];
  addReason(reasons, records.length === 0, 'correction_record_list_absent');
  for (const record of records) {
    const ref = hasText(record?.correctionRef) ? record.correctionRef : 'unknown';
    addReason(reasons, !hasText(record?.correctionRef), 'correction_ref_absent');
    addReason(reasons, !hasText(record?.discrepancyRef), `correction_discrepancy_ref_absent:${ref}`);
    addReason(
      reasons,
      hasText(record?.discrepancyRef) && !knownDiscrepancyRefs.has(record.discrepancyRef),
      `correction_discrepancy_ref_unknown:${record?.discrepancyRef}`,
    );
    addReason(reasons, !isDigest(record?.originalRecordHash), `correction_original_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(record?.correctedRecordHash), `correction_corrected_hash_invalid:${ref}`);
    addReason(reasons, record?.originalRecordHash === record?.correctedRecordHash, `correction_noop:${ref}`);
    addReason(reasons, !isDigest(record?.correctionReasonHash), `correction_reason_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(record?.correctionAuditHash), `correction_audit_hash_invalid:${ref}`);
    addReason(reasons, hlcTuple(record?.correctedAtHlc) === null, `correction_time_invalid:${ref}`);
    addReason(reasons, !hasText(record?.approvedByDid), `correction_approval_absent:${ref}`);
    addReason(reasons, record?.metadataOnly !== true, `correction_metadata_only_attestation_absent:${ref}`);
    addReason(reasons, record?.protectedContentExcluded !== true, `correction_protected_content_boundary_absent:${ref}`);
  }
  return records;
}

function evaluateControls(input, reasons) {
  const controls = input?.controls;
  addReason(reasons, !nonNegativeInteger(controls?.openQueryCount), 'open_query_count_invalid');
  addReason(reasons, Number.isSafeInteger(controls?.openQueryCount) && controls.openQueryCount > 0, 'open_queries_present');
  addReason(reasons, !nonNegativeInteger(controls?.openCriticalQueryCount), 'open_critical_query_count_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(controls?.openCriticalQueryCount) && controls.openCriticalQueryCount > 0,
    'open_critical_queries_present',
  );
  addReason(reasons, !nonNegativeInteger(controls?.unresolvedDiscrepancyCount), 'unresolved_discrepancy_count_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(controls?.unresolvedDiscrepancyCount) && controls.unresolvedDiscrepancyCount > 0,
    'unresolved_discrepancies_present',
  );
  addReason(reasons, !nonNegativeInteger(controls?.overdueDiscrepancyCount), 'overdue_discrepancy_count_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(controls?.overdueDiscrepancyCount) && controls.overdueDiscrepancyCount > 0,
    'overdue_discrepancies_present',
  );
  addReason(reasons, !nonNegativeInteger(controls?.urgentReportsOutstanding), 'urgent_reports_outstanding_count_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(controls?.urgentReportsOutstanding) && controls.urgentReportsOutstanding > 0,
    'urgent_reports_outstanding',
  );
  addReason(reasons, !isDigest(controls?.sourceCrfReconciliationHash), 'source_crf_reconciliation_hash_invalid');
  addReason(reasons, !isDigest(controls?.monitorReviewHash), 'monitor_review_hash_invalid');
  addReason(reasons, !isDigest(controls?.sponsorReportingHash), 'sponsor_reporting_hash_invalid');
  addReason(reasons, controls?.participantIdentifiersSuppressed !== true, 'participant_identifier_boundary_broken');
  addReason(reasons, controls?.allCorrectionsApproved !== true, 'correction_approval_control_incomplete');
  addReason(reasons, controls?.allResponsesReviewed !== true, 'query_response_review_control_incomplete');
  addReason(reasons, controls?.metadataOnly !== true, 'controls_metadata_only_attestation_absent');
  addReason(reasons, controls?.protectedContentExcluded !== true, 'controls_protected_content_boundary_absent');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, !hasText(review?.dataManagerDid), 'human_review_data_manager_absent');
  addReason(reasons, !REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, input?.discrepancyPlan?.evaluatedAtHlc), 'human_review_time_invalid');
  addReason(reasons, !isDigest(review?.evidenceBundleHash), 'human_review_evidence_bundle_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_final_authority_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');

  const forum = review?.decisionForum;
  addReason(reasons, forum?.verified !== true, 'decision_forum_not_verified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'decision_forum_human_gate_not_verified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'decision_forum_quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'decision_forum_open_challenge');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function discrepancyManagementId(input) {
  return `cmdisc_${sha256Hex({
    discrepancyRefs: sortedTextList(
      (Array.isArray(input?.discrepancyRecords) ? input.discrepancyRecords : []).map((record) => record?.discrepancyRef),
    ),
    planRef: input?.discrepancyPlan?.planRef ?? null,
    protocolRef: input?.discrepancyPlan?.protocolRef ?? null,
    queryRefs: sortedTextList((Array.isArray(input?.queryRecords) ? input.queryRecords : []).map((record) => record?.queryRef)),
    siteRef: input?.discrepancyPlan?.siteRef ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function buildDiscrepancySummary(input, domainState, reasons) {
  const discrepancyRecords = Array.isArray(input?.discrepancyRecords) ? input.discrepancyRecords : [];
  const queryRecords = Array.isArray(input?.queryRecords) ? input.queryRecords : [];
  const correctionRecords = Array.isArray(input?.correctionRecords) ? input.correctionRecords : [];

  return {
    schema: 'cybermedica.data_discrepancy_management_summary.v1',
    discrepancyManagementId: discrepancyManagementId(input),
    planRef: input?.discrepancyPlan?.planRef ?? null,
    protocolRef: input?.discrepancyPlan?.protocolRef ?? null,
    siteRef: input?.discrepancyPlan?.siteRef ?? null,
    reconciliationStatus: reasons.length === 0 ? 'reconciled' : 'blocked',
    requiredDomains: domainState.requiredDomains,
    coveredDomains: domainState.coveredDomains,
    discrepancyRecordCount: discrepancyRecords.length,
    queryRecordCount: queryRecords.length,
    correctionRecordCount: correctionRecords.length,
    openQueryCount: input?.controls?.openQueryCount ?? null,
    openCriticalQueryCount: input?.controls?.openCriticalQueryCount ?? null,
    unresolvedDiscrepancyCount: input?.controls?.unresolvedDiscrepancyCount ?? null,
    overdueDiscrepancyCount: input?.controls?.overdueDiscrepancyCount ?? null,
    urgentReportsOutstanding: input?.controls?.urgentReportsOutstanding ?? null,
    aiFinalAuthority: input?.humanReview?.aiFinalAuthority === true,
    exochainProductionClaim: false,
    containsProtectedContent: false,
    trustState: 'inactive',
  };
}

function createDiscrepancyReceipt(input, summary, artifactHash) {
  return createEvidenceReceipt({
    actorDid: hasText(input?.actor?.did) ? input.actor.did : 'did:exo:unknown-data-discrepancy-actor',
    artifactHash,
    artifactType: 'data_discrepancy_management',
    artifactVersion: summary.reconciliationStatus,
    classification: 'data_discrepancy_management_metadata_only',
    custodyDigest: isDigest(input?.custodyDigest) ? input.custodyDigest : sha256Hex({ fallback: 'invalid_custody_digest' }),
    hlcTimestamp: input?.humanReview?.reviewedAtHlc ?? input?.discrepancyPlan?.evaluatedAtHlc ?? { physicalMs: 0, logical: 0 },
    sensitivityTags: ['data_discrepancy', 'metadata_only', 'source_crf'],
    sourceSystem: 'cybermedica.data_discrepancy_management',
    tenantId: hasText(input?.tenantId) ? input.tenantId : 'tenant-unknown',
  });
}

export function evaluateDataDiscrepancyManagement(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateDiscrepancyPlan(input, reasons);
  const domainState = evaluateDomainCoverage(input, reasons);
  const discrepancyRecords = evaluateDiscrepancyRecords(input, reasons);
  const knownDiscrepancyRefs = discrepancyRefs(discrepancyRecords);
  evaluateQueryRecords(input, knownDiscrepancyRefs, reasons);
  evaluateCorrectionRecords(input, knownDiscrepancyRefs, reasons);
  evaluateControls(input, reasons);
  evaluateHumanReview(input, reasons);

  const denialReasons = uniqueReasons(reasons);
  const dataDiscrepancyManagement = buildDiscrepancySummary(input, domainState, denialReasons);
  const artifactHash = sha256Hex({
    correctionRefs: sortedTextList(
      (Array.isArray(input?.correctionRecords) ? input.correctionRecords : []).map((record) => record?.correctionRef),
    ),
    coveredDomains: dataDiscrepancyManagement.coveredDomains,
    discrepancyManagementId: dataDiscrepancyManagement.discrepancyManagementId,
    discrepancyRefs: sortedTextList(discrepancyRecords.map((record) => record?.discrepancyRef)),
    planRef: input?.discrepancyPlan?.planRef ?? null,
    queryRefs: sortedTextList((Array.isArray(input?.queryRecords) ? input.queryRecords : []).map((record) => record?.queryRef)),
    reconciliationStatus: dataDiscrepancyManagement.reconciliationStatus,
    tenantId: input?.tenantId ?? null,
  });
  const receipt = createDiscrepancyReceipt(input, dataDiscrepancyManagement, artifactHash);

  return {
    schema: DATA_DISCREPANCY_SCHEMA,
    decision: denialReasons.length === 0 ? 'permitted' : 'denied',
    failClosed: denialReasons.length > 0,
    reasons: denialReasons,
    denialReasons,
    dataDiscrepancyManagement,
    receipt,
  };
}
