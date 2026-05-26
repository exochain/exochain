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
const STUDY_FINAL_REPORT_SCHEMA = 'cybermedica.study_final_report_readiness.v1';
const REQUIRED_PERMISSION = 'study_final_report';

const REQUIRED_FINAL_REPORT_DOMAINS = Object.freeze([
  'analysis_dataset_lock',
  'audit_trail_reconciliation',
  'data_query_closure',
  'deviation_capa_summary',
  'distribution_plan',
  'dsmb_recommendation_disposition',
  'final_report_document',
  'regulatory_reporting_reconciliation',
  'safety_event_reconciliation',
  'source_crf_reconciliation',
  'sponsor_cro_review',
  'statistical_outputs',
]);

const ACTIVE_DOMAIN_STATUSES = new Set(['verified']);
const FINAL_REPORT_STATUSES = new Set(['locked']);
const HUMAN_REVIEW_STATUSES = new Set(['approved']);
const ACTOR_KINDS = new Set(['human']);

const RAW_FINAL_REPORT_FIELDS = new Set([
  'analysislistingbody',
  'caseformbody',
  'clinicalnarrative',
  'crfbody',
  'datasetbody',
  'finalreportbody',
  'finalreportcontent',
  'finalreportnarrative',
  'freeformsummary',
  'participantlisting',
  'rawanalysisdataset',
  'rawcrf',
  'rawfinalreport',
  'rawfinalreportbody',
  'rawlisting',
  'rawreportcontent',
  'rawsafetylisting',
  'rawsourcedata',
  'sourcedocumentbody',
  'statisticaloutputbody',
]);

const SECRET_FINAL_REPORT_FIELDS = new Set([
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
  'secret',
  'sessionsecret',
  'signaturesecret',
  'signerprivatekey',
  'signingkey',
  'token',
]);

function hasText(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
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

function assertNoRawFinalReportContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawFinalReportContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_FINAL_REPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw study final-report content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_FINAL_REPORT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`study final-report secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawFinalReportContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawFinalReportContent(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
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

function hlcAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) > 0;
}

function hlcBefore(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) < 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'human_final_report_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'study_final_report_permission_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateReportPlan(plan, reasons) {
  addReason(reasons, !hasText(plan?.planRef), 'final_report_plan_ref_absent');
  addReason(reasons, !hasText(plan?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(plan?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(plan?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(plan?.sponsorRef), 'sponsor_ref_absent');
  addReason(reasons, !hasText(plan?.informationPlanRef), 'information_plan_ref_absent');
  addReason(reasons, !isDigest(plan?.informationPlanHash), 'information_plan_hash_invalid');
  addReason(reasons, !isDigest(plan?.finalReportRequirementHash), 'final_report_requirement_hash_invalid');
  addReason(reasons, !isDigest(plan?.distributionRuleHash), 'distribution_rule_hash_invalid');
  addReason(reasons, !isDigest(plan?.retentionRuleHash), 'retention_rule_hash_invalid');
  addReason(reasons, hlcTuple(plan?.plannedAtHlc) === null, 'final_report_plan_time_invalid');
  addReason(reasons, hlcTuple(plan?.reportDueAtHlc) === null, 'final_report_due_time_invalid');
  addReason(reasons, hlcBefore(plan?.reportDueAtHlc, plan?.plannedAtHlc), 'report_due_before_plan');
  addReason(reasons, plan?.metadataOnly !== true, 'final_report_plan_metadata_boundary_invalid');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'final_report_plan_protected_boundary_invalid');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function normalizeDomainEvidence(rows, reasons) {
  if (!Array.isArray(rows)) {
    reasons.push('final_report_domain_evidence_absent');
    return [];
  }

  const byDomain = new Map();
  for (const row of rows) {
    const label = hasText(row?.domain) ? row.domain : 'unknown';
    addReason(reasons, !hasText(row?.domain), 'final_report_domain_absent');
    addReason(reasons, byDomain.has(row?.domain), `final_report_domain_duplicate:${label}`);
    if (hasText(row?.domain)) {
      byDomain.set(row.domain, row);
    }
  }

  for (const domain of REQUIRED_FINAL_REPORT_DOMAINS) {
    addReason(reasons, !byDomain.has(domain), `final_report_domain_missing:${domain}`);
  }
  for (const domain of byDomain.keys()) {
    addReason(reasons, !REQUIRED_FINAL_REPORT_DOMAINS.includes(domain), `final_report_domain_unsupported:${domain}`);
  }

  for (const domain of [...byDomain.keys()].sort()) {
    const row = byDomain.get(domain);
    addReason(reasons, !ACTIVE_DOMAIN_STATUSES.has(row?.status), `final_report_domain_not_verified:${domain}`);
    addReason(reasons, !isDigest(row?.evidenceHash), `final_report_domain_hash_invalid:${domain}`);
    addReason(reasons, !hasText(row?.reviewerDid), `final_report_domain_reviewer_absent:${domain}`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `final_report_domain_review_time_invalid:${domain}`);
    addReason(reasons, row?.metadataOnly !== true, `final_report_domain_metadata_boundary_invalid:${domain}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `final_report_domain_protected_boundary_invalid:${domain}`);
  }

  return [...byDomain.keys()].filter((domain) => REQUIRED_FINAL_REPORT_DOMAINS.includes(domain)).sort();
}

function evaluateDataCloseout(closeout, reasons) {
  addReason(reasons, closeout?.sourceCrfReconciled !== true, 'source_crf_not_reconciled');
  addReason(reasons, !isDigest(closeout?.queryClosureHash), 'query_closure_hash_invalid');
  addReason(reasons, !isNonNegativeSafeInteger(closeout?.openQueryCount), 'open_query_count_invalid');
  addReason(reasons, closeout?.openQueryCount > 0, 'open_queries_present');
  addReason(reasons, !isNonNegativeSafeInteger(closeout?.unresolvedDiscrepancyCount), 'unresolved_discrepancy_count_invalid');
  addReason(reasons, closeout?.unresolvedDiscrepancyCount > 0, 'unresolved_discrepancies_present');
  addReason(reasons, closeout?.analysisDatasetLocked !== true, 'analysis_dataset_not_locked');
  addReason(reasons, !isDigest(closeout?.analysisDatasetHash), 'analysis_dataset_hash_invalid');
  addReason(reasons, closeout?.auditTrailReconciled !== true, 'audit_trail_not_reconciled');
  addReason(reasons, !isDigest(closeout?.auditTrailHash), 'audit_trail_hash_invalid');
  addReason(reasons, hlcTuple(closeout?.lockedAtHlc) === null, 'data_closeout_lock_time_invalid');
  addReason(reasons, closeout?.metadataOnly !== true, 'data_closeout_metadata_boundary_invalid');
  addReason(reasons, closeout?.protectedContentExcluded !== true, 'data_closeout_protected_boundary_invalid');
}

function evaluateSafetyCloseout(closeout, reasons) {
  addReason(reasons, closeout?.safetyEventsReconciled !== true, 'safety_events_not_reconciled');
  addReason(reasons, !isNonNegativeSafeInteger(closeout?.unresolvedSafetyEventCount), 'unresolved_safety_event_count_invalid');
  addReason(reasons, closeout?.unresolvedSafetyEventCount > 0, 'unresolved_safety_events_present');
  addReason(reasons, closeout?.dsmbRecommendationsClosed !== true, 'dsmb_recommendations_open');
  addReason(reasons, closeout?.regulatoryReportingReconciled !== true, 'regulatory_reporting_not_reconciled');
  addReason(reasons, !isDigest(closeout?.safetyReconciliationHash), 'safety_reconciliation_hash_invalid');
  addReason(reasons, !isDigest(closeout?.dsmbDispositionHash), 'dsmb_disposition_hash_invalid');
  addReason(reasons, !isDigest(closeout?.regulatoryReconciliationHash), 'regulatory_reconciliation_hash_invalid');
  addReason(reasons, hlcTuple(closeout?.reviewedAtHlc) === null, 'safety_closeout_review_time_invalid');
  addReason(reasons, closeout?.metadataOnly !== true, 'safety_closeout_metadata_boundary_invalid');
  addReason(reasons, closeout?.protectedContentExcluded !== true, 'safety_closeout_protected_boundary_invalid');
}

function evaluateFinalReport(report, dataCloseout, reasons) {
  addReason(reasons, !hasText(report?.reportRef), 'final_report_ref_absent');
  addReason(reasons, !hasText(report?.version), 'final_report_version_absent');
  addReason(reasons, !FINAL_REPORT_STATUSES.has(report?.status), 'final_report_not_locked');
  addReason(reasons, !isDigest(report?.reportHash), 'final_report_hash_invalid');
  addReason(reasons, !isDigest(report?.statisticalOutputHash), 'statistical_output_hash_invalid');
  addReason(reasons, !isDigest(report?.deviationCapaSummaryHash), 'deviation_capa_summary_hash_invalid');
  addReason(reasons, !isDigest(report?.sponsorCroReviewHash), 'sponsor_cro_review_hash_invalid');
  addReason(reasons, !hasText(report?.approvedByPiDid), 'pi_final_report_approval_absent');
  addReason(reasons, !hasText(report?.approvedByQualityDid), 'quality_final_report_approval_absent');
  addReason(reasons, !hasText(report?.approvedBySponsorDid), 'sponsor_final_report_approval_absent');
  addReason(reasons, hlcTuple(report?.lockedAtHlc) === null, 'final_report_lock_time_invalid');
  addReason(reasons, hlcBefore(report?.lockedAtHlc, dataCloseout?.lockedAtHlc), 'report_locked_before_data_lock');
  addReason(reasons, report?.metadataOnly !== true, 'final_report_metadata_boundary_invalid');
  addReason(reasons, report?.protectedContentExcluded !== true, 'final_report_protected_boundary_invalid');
}

function evaluateDistribution(distribution, finalReport, reasons) {
  const authorizedRecipientRoles = sortedTextList(distribution?.authorizedRecipientRoles);
  addReason(reasons, !hasText(distribution?.distributionPlanRef), 'distribution_plan_ref_absent');
  addReason(reasons, !isDigest(distribution?.distributionPlanHash), 'distribution_plan_hash_invalid');
  addReason(reasons, authorizedRecipientRoles.length === 0, 'distribution_recipient_roles_absent');
  addReason(reasons, !hasText(distribution?.exportControlRef), 'distribution_export_control_ref_absent');
  addReason(reasons, !isDigest(distribution?.exportControlHash), 'distribution_export_control_hash_invalid');
  addReason(reasons, !isDigest(distribution?.disclosureLogHash), 'distribution_disclosure_log_hash_invalid');
  addReason(reasons, hlcTuple(distribution?.scheduledAtHlc) === null, 'distribution_time_invalid');
  addReason(reasons, hlcBefore(distribution?.scheduledAtHlc, finalReport?.lockedAtHlc), 'distribution_before_report_lock');
  addReason(reasons, distribution?.metadataOnly !== true, 'distribution_metadata_boundary_invalid');
  addReason(reasons, distribution?.protectedContentExcluded !== true, 'distribution_protected_boundary_invalid');

  if (!Array.isArray(distribution?.recipients) || distribution.recipients.length === 0) {
    reasons.push('distribution_recipients_absent');
    return [];
  }

  const recipientRows = [];
  for (const recipient of distribution.recipients) {
    const label = hasText(recipient?.recipientRef) ? recipient.recipientRef : recipient?.roleRef ?? 'unknown';
    addReason(reasons, !hasText(recipient?.recipientRef), `distribution_recipient_ref_absent:${label}`);
    addReason(reasons, !hasText(recipient?.roleRef), `distribution_recipient_role_absent:${label}`);
    addReason(
      reasons,
      hasText(recipient?.roleRef) && !authorizedRecipientRoles.includes(recipient.roleRef),
      `distribution_recipient_role_not_authorized:${label}`,
    );
    addReason(reasons, recipient?.authorized !== true, `distribution_recipient_not_authorized:${label}`);
    addReason(reasons, !hasText(recipient?.accessGrantRef), `distribution_access_grant_absent:${label}`);
    addReason(reasons, recipient?.acknowledgementRequired !== true, `distribution_acknowledgement_not_required:${label}`);
    addReason(reasons, recipient?.metadataOnly !== true, `distribution_recipient_metadata_boundary_invalid:${label}`);
    addReason(reasons, recipient?.protectedContentExcluded !== true, `distribution_recipient_protected_boundary_invalid:${label}`);
    recipientRows.push({
      accessGrantRef: hasText(recipient?.accessGrantRef) ? recipient.accessGrantRef : null,
      acknowledgementRequired: recipient?.acknowledgementRequired === true,
      authorized: recipient?.authorized === true,
      recipientRef: hasText(recipient?.recipientRef) ? recipient.recipientRef : null,
      roleRef: hasText(recipient?.roleRef) ? recipient.roleRef : null,
    });
  }

  return recipientRows.sort((left, right) =>
    `${left.roleRef ?? ''}:${left.recipientRef ?? ''}`.localeCompare(`${right.roleRef ?? ''}:${right.recipientRef ?? ''}`),
  );
}

function evaluateHumanReview(review, distribution, reasons) {
  addReason(reasons, !HUMAN_REVIEW_STATUSES.has(review?.status), 'human_review_not_approved');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !hasText(review?.decisionForumMatterRef), 'decision_forum_matter_absent');
  addReason(reasons, !hasText(review?.workflowReceiptId), 'decision_forum_workflow_receipt_absent');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, distribution?.scheduledAtHlc), 'human_review_before_distribution');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'human_review_protected_boundary_invalid');
}

function evaluateReceiptEvidence(receiptEvidence, reasons) {
  addReason(reasons, !isDigest(receiptEvidence?.artifactHash), 'receipt_artifact_hash_invalid');
  addReason(reasons, !isDigest(receiptEvidence?.custodyDigest), 'custody_digest_invalid');
}

function buildRecord(input, coveredDomains, recipientRows) {
  const authorizedRecipientRoles = sortedTextList(input?.distribution?.authorizedRecipientRoles);
  const material = {
    authorizedRecipientRoles,
    coveredDomains,
    dataCloseout: {
      analysisDatasetHash: input.dataCloseout.analysisDatasetHash,
      analysisDatasetLocked: input.dataCloseout.analysisDatasetLocked === true,
      auditTrailHash: input.dataCloseout.auditTrailHash,
      auditTrailReconciled: input.dataCloseout.auditTrailReconciled === true,
      lockedAtHlc: input.dataCloseout.lockedAtHlc,
      openQueryCount: input.dataCloseout.openQueryCount,
      queryClosureHash: input.dataCloseout.queryClosureHash,
      sourceCrfReconciled: input.dataCloseout.sourceCrfReconciled === true,
      unresolvedDiscrepancyCount: input.dataCloseout.unresolvedDiscrepancyCount,
    },
    distribution: {
      disclosureLogHash: input.distribution.disclosureLogHash,
      distributionPlanHash: input.distribution.distributionPlanHash,
      distributionPlanRef: input.distribution.distributionPlanRef,
      exportControlHash: input.distribution.exportControlHash,
      exportControlRef: input.distribution.exportControlRef,
      recipients: recipientRows,
      scheduledAtHlc: input.distribution.scheduledAtHlc,
    },
    finalReport: {
      deviationCapaSummaryHash: input.finalReport.deviationCapaSummaryHash,
      lockedAtHlc: input.finalReport.lockedAtHlc,
      reportHash: input.finalReport.reportHash,
      reportRef: input.finalReport.reportRef,
      sponsorCroReviewHash: input.finalReport.sponsorCroReviewHash,
      statisticalOutputHash: input.finalReport.statisticalOutputHash,
      version: input.finalReport.version,
    },
    humanReview: {
      decisionForumMatterRef: input.humanReview.decisionForumMatterRef,
      reviewedAtHlc: input.humanReview.reviewedAtHlc,
      reviewerDid: input.humanReview.reviewerDid,
      workflowReceiptId: input.humanReview.workflowReceiptId,
    },
    reportPlan: {
      informationPlanRef: input.reportPlan.informationPlanRef,
      planRef: input.reportPlan.planRef,
      protocolRef: input.reportPlan.protocolRef,
      siteRef: input.reportPlan.siteRef,
      sponsorRef: input.reportPlan.sponsorRef,
      studyRef: input.reportPlan.studyRef,
    },
    safetyCloseout: {
      dsmbDispositionHash: input.safetyCloseout.dsmbDispositionHash,
      dsmbRecommendationsClosed: input.safetyCloseout.dsmbRecommendationsClosed === true,
      regulatoryReconciliationHash: input.safetyCloseout.regulatoryReconciliationHash,
      regulatoryReportingReconciled: input.safetyCloseout.regulatoryReportingReconciled === true,
      safetyEventsReconciled: input.safetyCloseout.safetyEventsReconciled === true,
      safetyReconciliationHash: input.safetyCloseout.safetyReconciliationHash,
      unresolvedSafetyEventCount: input.safetyCloseout.unresolvedSafetyEventCount,
    },
    schema: `${STUDY_FINAL_REPORT_SCHEMA}.material`,
    tenantId: input.tenantId,
  };
  const recordHash = sha256Hex(material);

  return {
    schema: STUDY_FINAL_REPORT_SCHEMA,
    authorizedRecipientRoles,
    distributionPlanRef: input.distribution.distributionPlanRef,
    distributionReady: true,
    domainCoverage: {
      coveredDomains,
      missingDomains: REQUIRED_FINAL_REPORT_DOMAINS.filter((domain) => !coveredDomains.includes(domain)),
      requiredDomains: [...REQUIRED_FINAL_REPORT_DOMAINS],
    },
    exochainProductionClaim: false,
    finalReportReady: true,
    lockedAtHlc: input.finalReport.lockedAtHlc,
    protocolRef: input.reportPlan.protocolRef,
    receiptEligible: true,
    recordHash,
    recordId: `cmfr_${recordHash.slice(0, 32)}`,
    reportHash: input.finalReport.reportHash,
    reportRef: input.finalReport.reportRef,
    reviewedAtHlc: input.humanReview.reviewedAtHlc,
    scheduledDistributionAtHlc: input.distribution.scheduledAtHlc,
    studyRef: input.reportPlan.studyRef,
    tenantId: input.tenantId,
    trustState: 'inactive',
  };
}

function buildReceipt(input, finalReportRecord) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: finalReportRecord.recordHash,
    artifactType: 'study_final_report_readiness',
    artifactVersion: `${input.reportPlan.studyRef}:${input.finalReport.reportRef}:${input.finalReport.version}`,
    classification: 'study_final_report_metadata_only',
    custodyDigest: input.receiptEvidence.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: [
      'final_report_metadata',
      'inactive_trust',
      'study_closeout_metadata',
    ],
    sourceSystem: 'cybermedica.study_final_report_readiness',
    tenantId: input.tenantId,
  });
}

export function evaluateStudyFinalReportReadiness(input) {
  assertMetadataOnly(input ?? {});

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateReportPlan(input?.reportPlan, reasons);
  const coveredDomains = normalizeDomainEvidence(input?.domainEvidence, reasons);
  evaluateDataCloseout(input?.dataCloseout, reasons);
  evaluateSafetyCloseout(input?.safetyCloseout, reasons);
  evaluateFinalReport(input?.finalReport, input?.dataCloseout, reasons);
  const recipients = evaluateDistribution(input?.distribution, input?.finalReport, reasons);
  evaluateHumanReview(input?.humanReview, input?.distribution, reasons);
  evaluateReceiptEvidence(input?.receiptEvidence, reasons);

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: `${STUDY_FINAL_REPORT_SCHEMA}.decision.v1`,
      decision: 'denied',
      failClosed: true,
      finalReportRecord: null,
      receipt: null,
      reasons: unique,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const finalReportRecord = buildRecord(input, coveredDomains, recipients);

  return {
    schema: `${STUDY_FINAL_REPORT_SCHEMA}.decision.v1`,
    decision: 'permitted',
    failClosed: false,
    finalReportRecord,
    receipt: buildReceipt(input, finalReportRecord),
    reasons: [],
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
