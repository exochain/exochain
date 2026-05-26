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
const MONITORING_VISIT_SCHEMA = 'cybermedica.monitoring_visit.v1';
const REQUIRED_PERMISSION = 'monitoring_visit';
const ACTIVE_POLICY_STATUSES = new Set(['active']);
const ACTOR_KINDS = new Set(['human']);
const MONITORING_ROLES = new Set(['cro_monitor', 'monitor_cra', 'sponsor_monitor']);
const VISIT_TYPES = new Set([
  'closeout_monitoring',
  'for_cause_monitoring',
  'initiation_monitoring',
  'interim_monitoring',
  'remote_monitoring',
]);
const REVIEW_STATUSES = new Set(['verified']);
const FINDING_SEVERITIES = new Set(['critical', 'major', 'minor', 'observation']);
const FINDING_STATUSES = new Set(['action_required', 'closed', 'monitoring_required']);
const ACTION_ITEM_STATUSES = new Set(['open', 'in_progress']);
const ESCALATION_ROLES = new Set([
  'capa_owner',
  'decision_forum_chair',
  'principal_investigator',
  'site_quality_lead',
  'sponsor_quality_lead',
]);
const HUMAN_REVIEW_STATUSES = new Set(['approved']);

const REQUIRED_REVIEW_DOMAINS = Object.freeze([
  'action_items',
  'consent_records',
  'data_integrity',
  'delegation_training',
  'evidence_custody',
  'protocol_adherence',
  'safety_reporting',
  'source_crf_consistency',
]);

const RAW_MONITORING_FIELDS = new Set([
  'caseformbody',
  'casereportformbody',
  'crfbody',
  'freeformfinding',
  'monitoringbody',
  'monitoringcontent',
  'monitoringnotes',
  'monitoringnarrative',
  'monitoringrawcontent',
  'monitoringtext',
  'participantbody',
  'rawcrf',
  'rawmonitoringcontent',
  'rawmonitoringnotes',
  'rawmonitoringtext',
  'rawsource',
  'rawsourcedocument',
  'rawvisitreport',
  'sourcebody',
  'sourcedocument',
  'sourcedocumentbody',
  'visitbody',
  'visitnotes',
  'visitreportbody',
]);

const SECRET_MONITORING_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'password',
  'privatekey',
  'railwaytoken',
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

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
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

function assertNoRawMonitoringContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawMonitoringContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_MONITORING_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw monitoring content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_MONITORING_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`monitoring secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawMonitoringContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawMonitoringContent(input ?? {});
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
  addReason(reasons, !ACTOR_KINDS.has(input?.actor?.kind), 'human_monitoring_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'monitoring_visit_permission_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateVisitPlan(plan, reasons) {
  addReason(reasons, !hasText(plan?.visitRef), 'visit_ref_absent');
  addReason(reasons, !VISIT_TYPES.has(plan?.visitType), 'visit_type_invalid');
  addReason(reasons, !hasText(plan?.siteRef), 'visit_site_ref_absent');
  addReason(reasons, !hasText(plan?.studyRef), 'visit_study_ref_absent');
  addReason(reasons, !hasText(plan?.protocolRef), 'visit_protocol_ref_absent');
  addReason(reasons, !hasText(plan?.sponsorRef), 'visit_sponsor_ref_absent');
  addReason(reasons, !hasText(plan?.croRef), 'visit_cro_ref_absent');
  addReason(reasons, !isDigest(plan?.objectiveHash), 'visit_objective_hash_invalid');
  addReason(reasons, !isDigest(plan?.monitoringPlanHash), 'monitoring_plan_hash_invalid');
  addReason(reasons, hlcTuple(plan?.plannedAtHlc) === null, 'visit_planned_time_invalid');
  addReason(reasons, hlcTuple(plan?.scheduledStartHlc) === null, 'visit_start_time_invalid');
  addReason(reasons, hlcTuple(plan?.scheduledEndHlc) === null, 'visit_end_time_invalid');
  addReason(reasons, hlcBefore(plan?.scheduledStartHlc, plan?.plannedAtHlc), 'visit_started_before_plan');
  addReason(reasons, !hlcAfter(plan?.scheduledEndHlc, plan?.scheduledStartHlc), 'visit_end_not_after_start');
  addReason(reasons, plan?.metadataOnly !== true, 'visit_metadata_boundary_absent');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'visit_protected_boundary_absent');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateAccessPolicy(policy, actorRoles, reasons) {
  const allowedRoles = sortedTextList(policy?.allowedRoles);
  const allowedReviewDomains = sortedTextList(policy?.allowedReviewDomains);

  addReason(reasons, !hasText(policy?.policyRef), 'monitoring_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'monitoring_policy_hash_invalid');
  addReason(reasons, !ACTIVE_POLICY_STATUSES.has(policy?.status), 'monitoring_policy_inactive');
  addReason(reasons, policy?.leastPrivilege !== true, 'monitoring_policy_least_privilege_absent');
  addReason(reasons, policy?.disclosureLogRequired !== true, 'monitoring_policy_disclosure_log_not_required');
  addReason(reasons, policy?.protectedContentSuppressed !== true, 'monitoring_policy_protected_boundary_absent');
  addReason(reasons, policy?.directIdentifiersSuppressed !== true, 'monitoring_policy_direct_identifier_boundary_absent');
  addReason(reasons, policy?.sourceDocumentsExcluded !== true, 'monitoring_policy_source_document_boundary_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'monitoring_policy_metadata_boundary_absent');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'monitoring_policy_protected_content_boundary_absent');
  addReason(reasons, hlcTuple(policy?.reviewedAtHlc) === null, 'monitoring_policy_review_time_invalid');

  for (const role of allowedRoles) {
    addReason(reasons, !MONITORING_ROLES.has(role), `monitoring_policy_role_unsupported:${role}`);
  }
  for (const domain of allowedReviewDomains) {
    addReason(reasons, !REQUIRED_REVIEW_DOMAINS.includes(domain), `monitoring_policy_domain_unsupported:${domain}`);
  }
  for (const role of actorRoles) {
    addReason(reasons, MONITORING_ROLES.has(role) && !allowedRoles.includes(role), `monitoring_actor_role_not_allowed:${role}`);
  }

  return { allowedReviewDomains, allowedRoles };
}

function normalizeDomainReviews(reviewEvidence, visitPlan, allowedReviewDomains, reasons) {
  const domains = Array.isArray(reviewEvidence?.domains) ? [...reviewEvidence.domains] : [];
  const byDomain = new Map();

  addReason(reasons, reviewEvidence === null || reviewEvidence === undefined, 'review_evidence_absent');

  for (const row of domains) {
    if (hasText(row?.domain) && byDomain.has(row.domain)) {
      reasons.push(`review_domain_duplicate:${row.domain}`);
    }
    if (hasText(row?.domain)) {
      byDomain.set(row.domain, row);
    }
  }

  for (const domain of REQUIRED_REVIEW_DOMAINS) {
    if (!byDomain.has(domain)) {
      reasons.push(`review_domain_missing:${domain}`);
      reasons.push(`review_domain_not_allowed:${domain}`);
    }
    if (!allowedReviewDomains.includes(domain)) {
      reasons.push(`review_domain_not_allowed:${domain}`);
    }
  }

  return [...byDomain.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([domain, row]) => {
      addReason(reasons, !REQUIRED_REVIEW_DOMAINS.includes(domain), `review_domain_unsupported:${domain}`);
      addReason(reasons, !allowedReviewDomains.includes(domain), `review_domain_not_allowed:${domain}`);
      addReason(reasons, !REVIEW_STATUSES.has(row?.status), `review_domain_not_verified:${domain}`);
      addReason(reasons, !isDigest(row?.evidenceHash), `review_domain_evidence_hash_invalid:${domain}`);
      addReason(reasons, !isDigest(row?.custodyDigest), `review_domain_custody_digest_invalid:${domain}`);
      addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `review_domain_time_invalid:${domain}`);
      addReason(reasons, hlcBefore(row?.reviewedAtHlc, visitPlan?.scheduledStartHlc), `review_domain_before_visit_start:${domain}`);
      addReason(reasons, row?.metadataOnly !== true, `review_domain_metadata_boundary_absent:${domain}`);
      addReason(reasons, row?.protectedContentExcluded !== true, `review_domain_protected_boundary_absent:${domain}`);
      return {
        custodyDigest: row?.custodyDigest ?? null,
        domain,
        evidenceHash: row?.evidenceHash ?? null,
        reviewedAtHlc: row?.reviewedAtHlc ?? null,
        status: row?.status ?? null,
      };
    });
}

function evaluateSourceCrfConsistency(sourceCrf, visitPlan, reasons) {
  addReason(reasons, sourceCrf?.status !== 'verified', 'source_crf_consistency_unverified');
  addReason(reasons, !isPositiveSafeInteger(sourceCrf?.reviewedRecordCount), 'source_crf_reviewed_record_count_invalid');
  addReason(reasons, !isNonNegativeSafeInteger(sourceCrf?.discrepancyCount), 'source_crf_discrepancy_count_invalid');
  addReason(reasons, isNonNegativeSafeInteger(sourceCrf?.discrepancyCount) && sourceCrf.discrepancyCount > 0, 'source_crf_discrepancies_open');
  addReason(reasons, !isDigest(sourceCrf?.discrepancyRegisterHash), 'source_crf_discrepancy_register_hash_invalid');
  addReason(reasons, !hasText(sourceCrf?.reviewerDid), 'source_crf_reviewer_absent');
  addReason(reasons, hlcTuple(sourceCrf?.reviewedAtHlc) === null, 'source_crf_review_time_invalid');
  addReason(reasons, hlcBefore(sourceCrf?.reviewedAtHlc, visitPlan?.scheduledStartHlc), 'source_crf_review_before_visit_start');
  addReason(reasons, sourceCrf?.metadataOnly !== true, 'source_crf_metadata_boundary_absent');
  addReason(reasons, sourceCrf?.protectedContentExcluded !== true, 'source_crf_protected_boundary_absent');
}

function evaluateConsentReview(consentReview, visitPlan, reasons) {
  addReason(reasons, consentReview?.status !== 'verified', 'consent_review_not_verified');
  addReason(reasons, !hasText(consentReview?.activeConsentVersionRef), 'consent_review_active_version_absent');
  addReason(reasons, !isPositiveSafeInteger(consentReview?.reviewedConsentRecordCount), 'consent_review_record_count_invalid');
  addReason(reasons, !isNonNegativeSafeInteger(consentReview?.missingConsentCount), 'consent_review_missing_count_invalid');
  addReason(
    reasons,
    isNonNegativeSafeInteger(consentReview?.missingConsentCount) && consentReview.missingConsentCount > 0,
    'consent_review_missing_consent_records',
  );
  addReason(reasons, consentReview?.supersededFormUseDetected === true, 'consent_review_superseded_form_detected');
  addReason(reasons, !isDigest(consentReview?.evidenceHash), 'consent_review_evidence_hash_invalid');
  addReason(reasons, hlcTuple(consentReview?.reviewedAtHlc) === null, 'consent_review_time_invalid');
  addReason(reasons, hlcBefore(consentReview?.reviewedAtHlc, visitPlan?.scheduledStartHlc), 'consent_review_before_visit_start');
  addReason(reasons, consentReview?.metadataOnly !== true, 'consent_review_metadata_boundary_absent');
  addReason(reasons, consentReview?.protectedContentExcluded !== true, 'consent_review_protected_boundary_absent');
}

function evaluateSafetyReview(safetyReview, visitPlan, reasons) {
  addReason(reasons, safetyReview?.status !== 'verified', 'safety_review_not_verified');
  addReason(reasons, !isDigest(safetyReview?.eventLogHash), 'safety_review_event_log_hash_invalid');
  addReason(reasons, !isDigest(safetyReview?.saeReconciliationHash), 'safety_review_sae_reconciliation_hash_invalid');
  addReason(reasons, !isNonNegativeSafeInteger(safetyReview?.unresolvedSafetySignalCount), 'safety_review_signal_count_invalid');
  addReason(
    reasons,
    isNonNegativeSafeInteger(safetyReview?.unresolvedSafetySignalCount) && safetyReview.unresolvedSafetySignalCount > 0,
    'safety_review_unresolved_signals',
  );
  addReason(reasons, hlcTuple(safetyReview?.reviewedAtHlc) === null, 'safety_review_time_invalid');
  addReason(reasons, hlcBefore(safetyReview?.reviewedAtHlc, visitPlan?.scheduledStartHlc), 'safety_review_before_visit_start');
  addReason(reasons, safetyReview?.metadataOnly !== true, 'safety_review_metadata_boundary_absent');
  addReason(reasons, safetyReview?.protectedContentExcluded !== true, 'safety_review_protected_boundary_absent');
}

function normalizeFindings(input, reasons) {
  const rows = Array.isArray(input?.findings) ? [...input.findings] : [];
  const domainSet = new Set(REQUIRED_REVIEW_DOMAINS);

  return rows
    .sort((left, right) => String(left?.findingRef ?? '').localeCompare(String(right?.findingRef ?? '')))
    .map((finding) => {
      const findingRef = hasText(finding?.findingRef) ? finding.findingRef : 'unknown_finding';
      addReason(reasons, !hasText(finding?.findingRef), 'finding_ref_absent');
      addReason(reasons, !domainSet.has(finding?.domain), `finding_domain_unsupported:${findingRef}`);
      addReason(reasons, !FINDING_SEVERITIES.has(finding?.severity), `finding_severity_invalid:${findingRef}`);
      addReason(reasons, !FINDING_STATUSES.has(finding?.status), `finding_status_invalid:${findingRef}`);
      addReason(reasons, !isDigest(finding?.findingHash), `finding_hash_invalid:${findingRef}`);
      addReason(reasons, !isDigest(finding?.evidenceHash), `finding_evidence_hash_invalid:${findingRef}`);
      addReason(reasons, !hasText(finding?.ownerDid), `finding_owner_absent:${findingRef}`);
      addReason(reasons, hlcTuple(finding?.dueAtHlc) === null, `finding_due_time_invalid:${findingRef}`);
      addReason(
        reasons,
        (finding?.severity === 'critical' || finding?.severity === 'major' || finding?.capaRequired === true) &&
          !hasText(finding?.capaRef),
        `finding_capa_ref_absent:${findingRef}`,
      );
      addReason(
        reasons,
        (finding?.severity === 'critical' || finding?.decisionForumRequired === true) && !hasText(finding?.decisionForumMatterRef),
        `finding_decision_forum_ref_absent:${findingRef}`,
      );
      addReason(reasons, finding?.metadataOnly !== true, `finding_metadata_boundary_absent:${findingRef}`);
      addReason(reasons, finding?.protectedContentExcluded !== true, `finding_protected_boundary_absent:${findingRef}`);
      return {
        capaRef: finding?.capaRef ?? null,
        decisionForumMatterRef: finding?.decisionForumMatterRef ?? null,
        domain: finding?.domain ?? null,
        evidenceHash: finding?.evidenceHash ?? null,
        findingHash: finding?.findingHash ?? null,
        findingRef,
        severity: finding?.severity ?? null,
        status: finding?.status ?? null,
      };
    });
}

function evaluateNoFindingRationale(input, findings, reasons) {
  if (findings.length !== 0) {
    return;
  }
  const rationale = input?.noFindingRationale;
  addReason(reasons, rationale === null || rationale === undefined, 'no_finding_rationale_absent');
  addReason(reasons, !isDigest(rationale?.rationaleHash), 'no_finding_rationale_hash_invalid');
  addReason(reasons, !hasText(rationale?.reviewerDid), 'no_finding_reviewer_absent');
  addReason(reasons, hlcTuple(rationale?.reviewedAtHlc) === null, 'no_finding_review_time_invalid');
  addReason(reasons, rationale?.metadataOnly !== true, 'no_finding_metadata_boundary_absent');
  addReason(reasons, rationale?.protectedContentExcluded !== true, 'no_finding_protected_boundary_absent');
}

function normalizeActionItems(input, findings, reasons) {
  const rows = Array.isArray(input?.actionItems) ? [...input.actionItems] : [];
  const findingRefs = new Set(findings.map((finding) => finding.findingRef));
  const actionableFindingRefs = new Set(
    findings
      .filter((finding) => ['critical', 'major', 'minor'].includes(finding.severity) || finding.status === 'action_required')
      .map((finding) => finding.findingRef),
  );
  const actionedFindingRefs = new Set();

  const normalized = rows
    .sort((left, right) => String(left?.actionItemRef ?? '').localeCompare(String(right?.actionItemRef ?? '')))
    .map((item) => {
      const actionItemRef = hasText(item?.actionItemRef) ? item.actionItemRef : 'unknown_action_item';
      if (hasText(item?.findingRef)) {
        actionedFindingRefs.add(item.findingRef);
      }
      addReason(reasons, !hasText(item?.actionItemRef), 'action_item_ref_absent');
      addReason(reasons, !hasText(item?.findingRef), `action_item_finding_ref_absent:${actionItemRef}`);
      addReason(
        reasons,
        hasText(item?.findingRef) && !findingRefs.has(item.findingRef),
        `action_item_finding_missing:${actionItemRef}`,
      );
      addReason(reasons, !hasText(item?.ownerDid), `action_item_owner_absent:${actionItemRef}`);
      addReason(reasons, !isDigest(item?.actionHash), `action_item_hash_invalid:${actionItemRef}`);
      addReason(reasons, hlcTuple(item?.dueAtHlc) === null, `action_item_due_time_invalid:${actionItemRef}`);
      addReason(reasons, !ACTION_ITEM_STATUSES.has(item?.status), `action_item_status_invalid:${actionItemRef}`);
      addReason(reasons, !ESCALATION_ROLES.has(item?.escalationRole), `action_item_escalation_role_invalid:${actionItemRef}`);
      addReason(reasons, item?.metadataOnly !== true, `action_item_metadata_boundary_absent:${actionItemRef}`);
      addReason(reasons, item?.protectedContentExcluded !== true, `action_item_protected_boundary_absent:${actionItemRef}`);
      return {
        actionHash: item?.actionHash ?? null,
        actionItemRef,
        escalationRole: item?.escalationRole ?? null,
        findingRef: item?.findingRef ?? null,
        status: item?.status ?? null,
      };
    });

  for (const findingRef of actionableFindingRefs) {
    addReason(reasons, !actionedFindingRefs.has(findingRef), `finding_action_item_absent:${findingRef}`);
  }

  return normalized;
}

function evaluateVisitReport(report, visitPlan, reasons) {
  addReason(reasons, report === null || report === undefined, 'visit_report_absent');
  addReason(reasons, !isDigest(report?.reportHash), 'visit_report_hash_invalid');
  addReason(reasons, !hasText(report?.reportVersion), 'visit_report_version_absent');
  addReason(reasons, hlcTuple(report?.draftedAtHlc) === null, 'visit_report_drafted_time_invalid');
  addReason(reasons, hlcBefore(report?.draftedAtHlc, visitPlan?.scheduledEndHlc), 'visit_report_drafted_before_visit_end');
  addReason(reasons, !hasText(report?.reviewedBySiteDid), 'visit_report_site_review_absent');
  addReason(reasons, !hasText(report?.reviewedBySponsorDid), 'visit_report_sponsor_review_absent');
  addReason(reasons, hlcTuple(report?.approvedAtHlc) === null, 'visit_report_approval_time_invalid');
  addReason(reasons, !hlcAfter(report?.approvedAtHlc, report?.draftedAtHlc), 'visit_report_approval_not_after_draft');
  addReason(reasons, !isDigest(report?.disclosureLogHash), 'visit_report_disclosure_log_hash_invalid');
  addReason(reasons, !isDigest(report?.oversightSummaryHash), 'visit_report_oversight_summary_hash_invalid');
  addReason(reasons, report?.locked !== true, 'report_not_locked');
  addReason(reasons, report?.metadataOnly !== true, 'visit_report_metadata_boundary_absent');
  addReason(reasons, report?.protectedContentExcluded !== true, 'visit_report_protected_boundary_absent');
}

function evaluateHumanReview(review, report, reasons) {
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !HUMAN_REVIEW_STATUSES.has(review?.status), 'human_monitoring_review_not_approved');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, report?.approvedAtHlc), 'human_review_before_report_approval');
  addReason(reasons, review?.aiAssisted === true && review?.aiFinalAuthority !== false, 'human_review_ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_absent');
  addReason(reasons, review?.protectedContentExcluded !== true, 'human_review_protected_boundary_absent');
}

function evaluateReceiptEvidence(receiptEvidence, reasons) {
  addReason(reasons, !isDigest(receiptEvidence?.artifactHash), 'receipt_artifact_hash_invalid');
  addReason(reasons, !isDigest(receiptEvidence?.custodyDigest), 'receipt_custody_digest_invalid');
}

function findingSummary(findings) {
  return {
    critical: findings.filter((finding) => finding.severity === 'critical').length,
    major: findings.filter((finding) => finding.severity === 'major').length,
    minor: findings.filter((finding) => finding.severity === 'minor').length,
    observation: findings.filter((finding) => finding.severity === 'observation').length,
  };
}

function createMonitoringVisit(input, domainReviews, findings, actionItems) {
  const reviewDomains = uniqueSorted(domainReviews.map((row) => row.domain).filter((domain) => REQUIRED_REVIEW_DOMAINS.includes(domain)));
  const capaRefs = uniqueSorted(findings.map((finding) => finding.capaRef));
  const actionItemRefs = uniqueSorted(actionItems.map((item) => item.actionItemRef));
  const requiredEscalationRoles = uniqueSorted(actionItems.map((item) => item.escalationRole));
  const monitoringVisitId = `cm_mon_${sha256Hex({
    actionItemRefs,
    findings: findings.map((finding) => [finding.findingRef, finding.severity, finding.status]),
    schema: MONITORING_VISIT_SCHEMA,
    tenantId: input.tenantId,
    visitRef: input.visitPlan.visitRef,
  }).slice(0, 32)}`;

  return {
    schema: MONITORING_VISIT_SCHEMA,
    monitoringVisitId,
    accessMode: 'metadata_only_monitoring',
    actionItemRefs,
    actorDid: input.actor.did,
    capaRefs,
    consentReviewStatus: input.reviewEvidence.consentReview.status,
    croRef: input.visitPlan.croRef,
    findingCount: findings.length,
    findingSummary: findingSummary(findings),
    lockedReportHash: input.visitReport.reportHash,
    metadataOnly: true,
    productionTrustClaim: false,
    protocolRef: input.visitPlan.protocolRef,
    requiredEscalationRoles,
    reviewDomains,
    safetyReviewStatus: input.reviewEvidence.safetyReview.status,
    sourceCrfConsistencyStatus: input.reviewEvidence.sourceCrfConsistency.status,
    sponsorRef: input.visitPlan.sponsorRef,
    status: 'ready',
    trustState: 'inactive',
    visitRef: input.visitPlan.visitRef,
    visitType: input.visitPlan.visitType,
  };
}

function createMonitoringReceipt(input, monitoringVisit) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: input.receiptEvidence.artifactHash,
    artifactType: 'monitoring_visit_record',
    artifactVersion: 'v1',
    classification: 'metadata_only_monitoring_visit',
    custodyDigest: input.receiptEvidence.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: [
      'action_item_metadata',
      'monitoring_finding_hashes',
      'no_raw_source_documents',
      'sponsor_cro_oversight',
    ],
    sourceSystem: 'CyberMedica',
    tenantId: input.tenantId,
  });
}

export function evaluateMonitoringVisit(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateVisitPlan(input?.visitPlan, reasons);

  const actorRoles = sortedTextList(input?.actor?.roleRefs);
  const policySummary = evaluateAccessPolicy(input?.accessPolicy, actorRoles, reasons);
  const domainReviews = normalizeDomainReviews(input?.reviewEvidence, input?.visitPlan, policySummary.allowedReviewDomains, reasons);
  evaluateSourceCrfConsistency(input?.reviewEvidence?.sourceCrfConsistency, input?.visitPlan, reasons);
  evaluateConsentReview(input?.reviewEvidence?.consentReview, input?.visitPlan, reasons);
  evaluateSafetyReview(input?.reviewEvidence?.safetyReview, input?.visitPlan, reasons);
  const findings = normalizeFindings(input, reasons);
  evaluateNoFindingRationale(input, findings, reasons);
  const actionItems = normalizeActionItems(input, findings, reasons);
  evaluateVisitReport(input?.visitReport, input?.visitPlan, reasons);
  evaluateHumanReview(input?.humanReview, input?.visitReport, reasons);
  evaluateReceiptEvidence(input?.receiptEvidence, reasons);

  const sortedReasons = uniqueReasons(reasons);
  if (sortedReasons.length > 0) {
    return {
      status: 'denied',
      failClosed: true,
      reasons: sortedReasons,
      monitoringVisit: null,
      receipt: null,
      sourceEvidence: [
        'cyber_medica_qms_prd_master.md:Monitor / CRA',
        'cyber_medica_qms_prd_master.md:Reporting and dashboards',
        'cyber_medica_qms_prd_master.md:FR-040',
      ],
    };
  }

  const monitoringVisit = createMonitoringVisit(input, domainReviews, findings, actionItems);
  const receipt = createMonitoringReceipt(input, monitoringVisit);

  return {
    status: 'ready',
    failClosed: false,
    reasons: [],
    monitoringVisit,
    receipt,
    sourceEvidence: [
      'cyber_medica_qms_prd_master.md:Monitor / CRA',
      'cyber_medica_qms_prd_master.md:Reporting and dashboards',
      'cyber_medica_qms_prd_master.md:FR-040',
    ],
  };
}

export const monitoringVisitRequirements = Object.freeze({
  schema: MONITORING_VISIT_SCHEMA,
  requiredPermission: REQUIRED_PERMISSION,
  requiredReviewDomains: REQUIRED_REVIEW_DOMAINS,
  visitTypes: [...VISIT_TYPES].sort(),
});
