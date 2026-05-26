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
const REQUIRED_PERMISSION = 'manage_dsmb_reporting';
const DSMB_REPORTING_SCHEMA = 'cybermedica.dsmb_reporting_readiness.v1';

const REQUIRED_DSMB_DOMAINS = Object.freeze([
  'audit_trail',
  'board_charter',
  'data_cut_schedule',
  'independence_attestation',
  'participant_code_boundary',
  'recommendation_review',
  'reporting_timeline',
  'safety_event_feed',
  'sponsor_irb_regulatory_routing',
  'unblinding_boundary',
]);

const ACTIVE_PLAN_STATUSES = new Set(['active']);
const VERIFIED_DOMAIN_STATUSES = new Set(['validated', 'verified']);
const LOCKED_DATA_CUT_STATUSES = new Set(['locked']);
const SUBMITTED_REPORT_STATUSES = new Set(['accepted', 'submitted']);
const REPORT_TYPES = new Set(['ad_hoc_safety_signal', 'scheduled_review']);
const RECOMMENDATION_TYPES = new Set([
  'continue_without_modification',
  'modify_protocol',
  'pause_enrollment',
  'request_more_information',
  'safety_hold',
  'stop_study',
]);
const MATERIAL_RECOMMENDATION_TYPES = new Set([
  'modify_protocol',
  'pause_enrollment',
  'safety_hold',
  'stop_study',
]);
const RESOLVED_RECOMMENDATION_STATUSES = new Set(['closed', 'reviewed']);
const REVIEW_DECISIONS = new Set(['dsmb_reporting_ready', 'hold_dsmb_reporting_gap']);

const RAW_DSMB_FIELDS = new Set([
  'adverseeventnarrative',
  'dsmbreportbody',
  'freeeventsafetytext',
  'medicalrecordnumber',
  'participantidentifier',
  'participantname',
  'patientname',
  'rawdsmbreport',
  'rawreport',
  'rawsafetysignal',
  'rawsource',
  'rawunblindedlisting',
  'reportbody',
  'safetynarrative',
  'sourcedocumentbody',
  'subjectidentifier',
  'unblindedparticipantlisting',
]);

const SECRET_DSMB_FIELDS = new Set([
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

function assertNoRawDsmbContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDsmbContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_DSMB_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw DSMB reporting content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_DSMB_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`DSMB reporting secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawDsmbContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawDsmbContent(input ?? {});
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
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'dsmb_reporting_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateDsmbPlan(input, reasons) {
  const plan = input?.dsmbPlan;
  addReason(reasons, !hasText(plan?.planRef), 'plan_ref_absent');
  addReason(reasons, !hasText(plan?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(plan?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(plan?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(plan?.informationManagementPlanRef), 'information_management_plan_ref_absent');
  addReason(reasons, !ACTIVE_PLAN_STATUSES.has(plan?.status), 'plan_not_active');
  addReason(reasons, !isDigest(plan?.charterHash), 'charter_hash_invalid');
  addReason(reasons, !isDigest(plan?.rosterHash), 'roster_hash_invalid');
  addReason(reasons, !isDigest(plan?.independenceAttestationHash), 'independence_attestation_hash_invalid');
  addReason(reasons, !isDigest(plan?.safetyThresholdPlanHash), 'safety_threshold_plan_hash_invalid');
  addReason(reasons, !isDigest(plan?.reportingScheduleHash), 'reporting_schedule_hash_invalid');
  addReason(reasons, !isDigest(plan?.unblindingBoundaryHash), 'unblinding_boundary_hash_invalid');
  addReason(reasons, hlcTuple(plan?.reviewedAtHlc) === null, 'plan_review_time_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'plan_metadata_only_attestation_absent');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'plan_protected_content_boundary_absent');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  evaluateRequiredSet(
    sortedTextList(plan?.requiredDomains),
    REQUIRED_DSMB_DOMAINS,
    'required_domain_missing',
    'required_domain_unsupported',
    reasons,
  );
}

function evaluateDomainCoverage(input, reasons) {
  const rows = Array.isArray(input?.domainEvidence) ? input.domainEvidence : [];
  const coveredDomains = sortedTextList(
    rows
      .filter((row) => VERIFIED_DOMAIN_STATUSES.has(row?.status) && isDigest(row?.evidenceHash))
      .map((row) => row.domainRef),
  );
  const requiredDomains = sortedTextList(input?.dsmbPlan?.requiredDomains);

  evaluateRequiredSet(
    coveredDomains,
    REQUIRED_DSMB_DOMAINS,
    'domain_evidence_missing',
    'domain_evidence_unsupported',
    reasons,
  );

  for (const row of rows) {
    const ref = hasText(row?.domainRef) ? row.domainRef : 'unknown';
    addReason(reasons, !REQUIRED_DSMB_DOMAINS.includes(ref), `domain_evidence_unsupported:${ref}`);
    addReason(reasons, !VERIFIED_DOMAIN_STATUSES.has(row?.status), `domain_evidence_unverified:${ref}`);
    addReason(reasons, !isDigest(row?.evidenceHash), `domain_evidence_hash_invalid:${ref}`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `domain_review_time_invalid:${ref}`);
    addReason(reasons, row?.metadataOnly !== true, `domain_metadata_only_attestation_absent:${ref}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `domain_protected_content_boundary_absent:${ref}`);
  }

  return { coveredDomains, requiredDomains };
}

function evaluateDataCuts(input, reasons) {
  const rows = Array.isArray(input?.dataCutRecords) ? input.dataCutRecords : [];
  const refs = new Set();
  addReason(reasons, rows.length === 0, 'data_cut_records_absent');

  for (const row of rows) {
    const ref = hasText(row?.dataCutRef) ? row.dataCutRef : 'unknown';
    addReason(reasons, !hasText(row?.dataCutRef), 'data_cut_ref_absent');
    addReason(reasons, refs.has(ref), `data_cut_duplicate:${ref}`);
    addReason(reasons, !isDigest(row?.dataCutHash), `data_cut_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(row?.safetyEventSummaryHash), `safety_event_summary_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(row?.enrollmentExposureHash), `enrollment_exposure_hash_invalid:${ref}`);
    addReason(reasons, !isDigest(row?.discrepancySummaryHash), `discrepancy_summary_hash_invalid:${ref}`);
    addReason(reasons, !LOCKED_DATA_CUT_STATUSES.has(row?.status), `data_cut_not_locked:${ref}`);
    addReason(reasons, !hlcBefore(row?.periodStartAtHlc, row?.periodEndAtHlc), `data_cut_period_order_invalid:${ref}`);
    addReason(reasons, !hlcAfter(row?.lockedAtHlc, row?.periodEndAtHlc), `data_cut_lock_time_invalid:${ref}`);
    addReason(reasons, row?.participantIdentifiersSuppressed !== true, `data_cut_participant_boundary_invalid:${ref}`);
    addReason(reasons, row?.metadataOnly !== true, `data_cut_metadata_only_attestation_absent:${ref}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `data_cut_protected_content_boundary_absent:${ref}`);
    if (hasText(row?.dataCutRef)) {
      refs.add(row.dataCutRef);
    }
  }

  return refs;
}

function evaluateReportPackages(input, knownDataCutRefs, reasons) {
  const rows = Array.isArray(input?.reportPackages) ? input.reportPackages : [];
  const refs = new Set();
  addReason(reasons, rows.length === 0, 'report_packages_absent');

  for (const row of rows) {
    const ref = hasText(row?.reportRef) ? row.reportRef : 'unknown';
    const recipients = sortedTextList(row?.recipientParties);
    addReason(reasons, !hasText(row?.reportRef), 'report_ref_absent');
    addReason(reasons, refs.has(ref), `report_duplicate:${ref}`);
    addReason(reasons, !hasText(row?.dataCutRef), `report_data_cut_ref_absent:${ref}`);
    addReason(
      reasons,
      hasText(row?.dataCutRef) && !knownDataCutRefs.has(row.dataCutRef),
      `report_data_cut_ref_unknown:${row?.dataCutRef}`,
    );
    addReason(reasons, !REPORT_TYPES.has(row?.reportType), `report_type_invalid:${ref}`);
    addReason(reasons, !isDigest(row?.reportHash), `report_hash_invalid:${ref}`);
    addReason(reasons, !SUBMITTED_REPORT_STATUSES.has(row?.status), `report_not_submitted:${ref}`);
    addReason(reasons, hlcTuple(row?.dueAtHlc) === null, `report_due_time_invalid:${ref}`);
    addReason(reasons, hlcTuple(row?.submittedAtHlc) === null, `report_submitted_time_invalid:${ref}`);
    addReason(reasons, hlcAfter(row?.submittedAtHlc, row?.dueAtHlc), `report_submitted_after_due:${ref}`);
    addReason(reasons, !recipients.includes('data_safety_monitoring_board'), `report_dsmb_recipient_absent:${ref}`);
    addReason(reasons, row?.blinded !== true && row?.unblindingAuthorized !== true, `report_unblinded_without_authorization:${ref}`);
    addReason(reasons, row?.metadataOnly !== true, `report_metadata_only_attestation_absent:${ref}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `report_protected_content_boundary_absent:${ref}`);
    if (hasText(row?.reportRef)) {
      refs.add(row.reportRef);
    }
  }

  return refs;
}

function recommendationIsMaterial(row) {
  return row?.materialProtocolImpact === true || MATERIAL_RECOMMENDATION_TYPES.has(row?.recommendationType);
}

function evaluateRecommendations(input, knownReportRefs, reasons) {
  const rows = Array.isArray(input?.recommendations) ? input.recommendations : [];
  addReason(reasons, rows.length === 0, 'recommendations_absent');

  for (const row of rows) {
    const ref = hasText(row?.recommendationRef) ? row.recommendationRef : 'unknown';
    addReason(reasons, !hasText(row?.recommendationRef), 'recommendation_ref_absent');
    addReason(reasons, !hasText(row?.reportRef), `recommendation_report_ref_absent:${ref}`);
    addReason(
      reasons,
      hasText(row?.reportRef) && !knownReportRefs.has(row.reportRef),
      `recommendation_report_ref_unknown:${row?.reportRef}`,
    );
    addReason(reasons, !isDigest(row?.recommendationHash), `recommendation_hash_invalid:${ref}`);
    addReason(reasons, !RECOMMENDATION_TYPES.has(row?.recommendationType), `recommendation_type_invalid:${ref}`);
    addReason(reasons, !RESOLVED_RECOMMENDATION_STATUSES.has(row?.status), `recommendation_unresolved:${ref}`);
    addReason(reasons, hlcTuple(row?.issuedAtHlc) === null, `recommendation_issue_time_invalid:${ref}`);
    addReason(reasons, !hlcAfter(row?.reviewedAtHlc, row?.issuedAtHlc), `recommendation_review_time_invalid:${ref}`);
    addReason(
      reasons,
      recommendationIsMaterial(row) && input?.controls?.materialRecommendationsRouted !== true,
      `material_recommendation_not_routed:${ref}`,
    );
    addReason(
      reasons,
      recommendationIsMaterial(row) && !hasText(row?.decisionForumReceiptId),
      `material_recommendation_decision_forum_receipt_absent:${ref}`,
    );
    addReason(reasons, row?.metadataOnly !== true, `recommendation_metadata_only_attestation_absent:${ref}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `recommendation_protected_content_boundary_absent:${ref}`);
  }

  return rows;
}

function evaluateControls(input, reasons) {
  const controls = input?.controls;
  addReason(reasons, !nonNegativeInteger(controls?.openCriticalSafetySignalCount), 'open_critical_safety_signal_count_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(controls?.openCriticalSafetySignalCount) && controls.openCriticalSafetySignalCount > 0,
    'open_critical_safety_signals_present',
  );
  addReason(reasons, !nonNegativeInteger(controls?.overdueReportCount), 'overdue_report_count_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(controls?.overdueReportCount) && controls.overdueReportCount > 0,
    'overdue_reports_present',
  );
  addReason(reasons, !nonNegativeInteger(controls?.unresolvedRecommendationCount), 'unresolved_recommendation_count_invalid');
  addReason(
    reasons,
    Number.isSafeInteger(controls?.unresolvedRecommendationCount) && controls.unresolvedRecommendationCount > 0,
    'unresolved_recommendations_present',
  );
  addReason(reasons, controls?.participantIdentifiersSuppressed !== true, 'participant_identifier_boundary_broken');
  addReason(reasons, controls?.unblindingBoundaryPreserved !== true, 'unblinding_boundary_broken');
  addReason(reasons, controls?.allReportsSubmitted !== true, 'report_submission_control_incomplete');
  addReason(reasons, controls?.metadataOnly !== true, 'controls_metadata_only_attestation_absent');
  addReason(reasons, controls?.protectedContentExcluded !== true, 'controls_protected_content_boundary_absent');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, !REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, input?.dsmbPlan?.reviewedAtHlc), 'human_review_time_invalid');
  addReason(reasons, !isDigest(review?.evidenceBundleHash), 'human_review_evidence_bundle_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_final_authority_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');

  const forum = review?.decisionForum;
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function dsmbReportingId(input) {
  return `cmdsmb_${sha256Hex({
    dataCutRefs: sortedTextList((Array.isArray(input?.dataCutRecords) ? input.dataCutRecords : []).map((row) => row?.dataCutRef)),
    planRef: input?.dsmbPlan?.planRef ?? null,
    protocolRef: input?.dsmbPlan?.protocolRef ?? null,
    reportRefs: sortedTextList((Array.isArray(input?.reportPackages) ? input.reportPackages : []).map((row) => row?.reportRef)),
    siteRef: input?.dsmbPlan?.siteRef ?? null,
    tenantId: input?.tenantId ?? null,
  }).slice(0, 32)}`;
}

function buildDsmbSummary(input, domainState, denialReasons) {
  const dataCutRecords = Array.isArray(input?.dataCutRecords) ? input.dataCutRecords : [];
  const reportPackages = Array.isArray(input?.reportPackages) ? input.reportPackages : [];
  const recommendations = Array.isArray(input?.recommendations) ? input.recommendations : [];

  return {
    schema: 'cybermedica.dsmb_reporting_readiness_summary.v1',
    dsmbReportingId: dsmbReportingId(input),
    planRef: input?.dsmbPlan?.planRef ?? null,
    protocolRef: input?.dsmbPlan?.protocolRef ?? null,
    siteRef: input?.dsmbPlan?.siteRef ?? null,
    reportingStatus: denialReasons.length === 0 ? 'ready' : 'blocked',
    requiredDomains: domainState.requiredDomains,
    coveredDomains: domainState.coveredDomains,
    dataCutCount: dataCutRecords.length,
    reportPackageCount: reportPackages.length,
    recommendationCount: recommendations.length,
    openCriticalSafetySignalCount: input?.controls?.openCriticalSafetySignalCount ?? null,
    overdueReportCount: input?.controls?.overdueReportCount ?? null,
    unresolvedRecommendationCount: input?.controls?.unresolvedRecommendationCount ?? null,
    aiFinalAuthority: input?.humanReview?.aiFinalAuthority === true,
    exochainProductionClaim: false,
    containsProtectedContent: false,
    trustState: 'inactive',
  };
}

function createDsmbReceipt(input, summary, artifactHash) {
  return createEvidenceReceipt({
    actorDid: hasText(input?.actor?.did) ? input.actor.did : 'did:exo:unknown-dsmb-reporting-actor',
    artifactHash,
    artifactType: 'dsmb_reporting_readiness',
    artifactVersion: summary.reportingStatus,
    classification: 'dsmb_reporting_metadata_only',
    custodyDigest: isDigest(input?.custodyDigest) ? input.custodyDigest : sha256Hex({ fallback: 'invalid_custody_digest' }),
    hlcTimestamp: input?.humanReview?.reviewedAtHlc ?? input?.dsmbPlan?.reviewedAtHlc ?? { physicalMs: 0, logical: 0 },
    sensitivityTags: ['dsmb_reporting', 'metadata_only', 'safety_oversight'],
    sourceSystem: 'cybermedica.dsmb_reporting_readiness',
    tenantId: hasText(input?.tenantId) ? input.tenantId : 'tenant-unknown',
  });
}

export function evaluateDsmbReportingReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateDsmbPlan(input, reasons);
  const domainState = evaluateDomainCoverage(input, reasons);
  const dataCutRefs = evaluateDataCuts(input, reasons);
  const reportRefs = evaluateReportPackages(input, dataCutRefs, reasons);
  evaluateRecommendations(input, reportRefs, reasons);
  evaluateControls(input, reasons);
  evaluateHumanReview(input, reasons);

  const denialReasons = uniqueReasons(reasons);
  const dsmbReportingReadiness = buildDsmbSummary(input, domainState, denialReasons);
  const artifactHash = sha256Hex({
    coveredDomains: dsmbReportingReadiness.coveredDomains,
    dataCutRefs: sortedTextList((Array.isArray(input?.dataCutRecords) ? input.dataCutRecords : []).map((row) => row?.dataCutRef)),
    dsmbReportingId: dsmbReportingReadiness.dsmbReportingId,
    planRef: input?.dsmbPlan?.planRef ?? null,
    recommendationRefs: sortedTextList(
      (Array.isArray(input?.recommendations) ? input.recommendations : []).map((row) => row?.recommendationRef),
    ),
    reportingStatus: dsmbReportingReadiness.reportingStatus,
    reportRefs: sortedTextList((Array.isArray(input?.reportPackages) ? input.reportPackages : []).map((row) => row?.reportRef)),
    tenantId: input?.tenantId ?? null,
  });
  const receipt = createDsmbReceipt(input, dsmbReportingReadiness, artifactHash);

  return {
    schema: DSMB_REPORTING_SCHEMA,
    decision: denialReasons.length === 0 ? 'permitted' : 'denied',
    failClosed: denialReasons.length > 0,
    reasons: denialReasons,
    denialReasons,
    dsmbReportingReadiness,
    receipt,
  };
}
