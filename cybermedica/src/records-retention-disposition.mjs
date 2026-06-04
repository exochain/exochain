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
const RETENTION_SCHEMA = 'cybermedica.records_retention_disposition.v1';
const DECISION_SCHEMA = 'cybermedica.records_retention_disposition_decision.v1';
const REQUIRED_PERMISSION = 'records_retention_disposition';

const REQUIRED_RECORD_FAMILIES = Object.freeze([
  'audit_trails',
  'clinical_trial_agreements',
  'controlled_documents',
  'data_corrections',
  'decision_forum_records',
  'diligence_exports',
  'evidence_payload_metadata',
  'final_reports',
  'participant_consent_records',
  'safety_reporting_records',
  'source_data_traceability',
  'training_delegation_records',
]);

const POLICY_STATUSES = new Set(['active']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_records_retention_gap',
  'records_retention_ready_inactive_trust',
]);
const LEGAL_HOLD_STATUSES = new Set(['active', 'released']);
const DISPOSITION_TYPES = new Set(['archive', 'destroy', 'retain_on_hold', 'transfer']);
const ARCHIVAL_DISPOSITION_TYPES = new Set(['archive', 'retain_on_hold', 'transfer']);

const RAW_RETENTION_FIELDS = new Set([
  'archivenarrative',
  'body',
  'content',
  'destructioncertificatebody',
  'directidentifierlist',
  'freetext',
  'freetextnote',
  'participantlisting',
  'rawarchivepayload',
  'rawcontent',
  'rawrecord',
  'rawrecordbody',
  'rawretentioncontent',
  'rawsourcedata',
  'recordsbody',
  'retentionnarrative',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_RETENTION_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'apitoken',
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

function assertNoRawRetentionContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawRetentionContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_RETENTION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw records retention content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_RETENTION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`records retention secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawRetentionContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawRetentionContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_records_retention_actor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'records_retention_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  const requiredFamilies = sortedTextList(policy?.requiredRecordFamilies);

  addReason(reasons, !hasText(policy?.policyRef), 'retention_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'retention_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'retention_policy_not_active');
  addReason(reasons, policy?.conflictPolicy !== 'longest_applicable_retention', 'retention_conflict_policy_invalid');
  addReason(reasons, policy?.legalHoldOverridesDisposition !== true, 'legal_hold_override_absent');
  addReason(reasons, policy?.destructionRequiresHumanApproval !== true, 'destruction_human_approval_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'retention_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'retention_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'retention_policy_evaluation_time_invalid');
  evaluateRequiredSet(
    requiredFamilies,
    REQUIRED_RECORD_FAMILIES,
    'required_record_family_missing',
    'required_record_family_unsupported',
    reasons,
  );
}

function evaluateCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'retention_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'retention_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'retention_cycle_protected_boundary_invalid');

  const ordered = [
    policy?.evaluatedAtHlc,
    cycle?.openedAtHlc,
    cycle?.scheduleCompiledAtHlc,
    cycle?.archiveVerifiedAtHlc,
    cycle?.holdReviewedAtHlc,
    cycle?.dispositionReviewedAtHlc,
    cycle?.auditRecordedAtHlc,
  ];
  const tuples = ordered.map(hlcTuple);
  addReason(reasons, tuples.some((tuple) => tuple === null), 'retention_cycle_hlc_invalid');
  addReason(
    reasons,
    tuples.every((tuple) => tuple !== null) &&
      tuples.some((tuple, index) => index > 0 && compareHlc(tuples[index - 1], tuple) >= 0),
    'retention_cycle_hlc_order_invalid',
  );
}

function maxRetentionMonths(ruleCandidates) {
  const candidateMonths = Array.isArray(ruleCandidates)
    ? ruleCandidates
        .map((candidate) => candidate?.periodMonths)
        .filter((periodMonths) => Number.isSafeInteger(periodMonths) && periodMonths > 0)
    : [];
  return candidateMonths.length === 0 ? null : Math.max(...candidateMonths);
}

function evaluateRuleCandidate(candidate, schedule, reasons) {
  addReason(reasons, !hasText(candidate?.ruleRef), `retention_rule_ref_absent:${schedule?.recordFamily ?? 'unknown'}`);
  addReason(
    reasons,
    !hasText(candidate?.jurisdictionOrSourceRef),
    `retention_rule_source_absent:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(
    reasons,
    !Number.isSafeInteger(candidate?.periodMonths) || candidate.periodMonths < 1,
    `retention_rule_period_invalid:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(reasons, !isDigest(candidate?.ruleHash), `retention_rule_hash_invalid:${schedule?.recordFamily ?? 'unknown'}`);
  addReason(
    reasons,
    !isDigest(candidate?.legalBasisHash),
    `retention_rule_legal_basis_hash_invalid:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(
    reasons,
    candidate?.metadataOnly !== true,
    `retention_rule_metadata_boundary_invalid:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(
    reasons,
    candidate?.protectedContentExcluded !== true,
    `retention_rule_protected_boundary_invalid:${schedule?.recordFamily ?? 'unknown'}`,
  );
}

function evaluateRecordSchedule(schedule, reasons) {
  addReason(reasons, !hasText(schedule?.recordFamily), 'record_family_absent');
  addReason(
    reasons,
    !REQUIRED_RECORD_FAMILIES.includes(schedule?.recordFamily),
    `record_family_unsupported:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(reasons, !hasText(schedule?.recordSetRef), `record_set_ref_absent:${schedule?.recordFamily ?? 'unknown'}`);
  addReason(reasons, !isDigest(schedule?.recordSetHash), `record_set_hash_invalid:${schedule?.recordFamily ?? 'unknown'}`);
  addReason(
    reasons,
    !hasText(schedule?.retentionClass),
    `retention_class_absent:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(
    reasons,
    !Array.isArray(schedule?.ruleCandidates) || schedule.ruleCandidates.length === 0,
    `retention_rules_absent:${schedule?.recordFamily ?? 'unknown'}`,
  );
  for (const candidate of Array.isArray(schedule?.ruleCandidates) ? schedule.ruleCandidates : []) {
    evaluateRuleCandidate(candidate, schedule, reasons);
  }

  const selectedCandidate = Array.isArray(schedule?.ruleCandidates)
    ? schedule.ruleCandidates.find((candidate) => candidate?.ruleRef === schedule?.selectedRuleRef)
    : null;
  const longestMonths = maxRetentionMonths(schedule?.ruleCandidates);

  addReason(reasons, selectedCandidate === null, `selected_retention_rule_absent:${schedule?.recordFamily ?? 'unknown'}`);
  addReason(
    reasons,
    !Number.isSafeInteger(schedule?.selectedRetentionMonths) || schedule.selectedRetentionMonths < 1,
    `selected_retention_months_invalid:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(
    reasons,
    longestMonths !== null && schedule?.selectedRetentionMonths !== longestMonths,
    `selected_retention_not_longest:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(
    reasons,
    selectedCandidate !== null && schedule?.selectedRetentionMonths !== selectedCandidate?.periodMonths,
    `selected_retention_rule_period_mismatch:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(reasons, hlcTuple(schedule?.startAtHlc) === null, `retention_start_time_invalid:${schedule?.recordFamily ?? 'unknown'}`);
  addReason(
    reasons,
    hlcTuple(schedule?.eligibleDispositionAtHlc) === null,
    `eligible_disposition_time_invalid:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(
    reasons,
    !hlcAfter(schedule?.eligibleDispositionAtHlc, schedule?.startAtHlc),
    `eligible_disposition_not_after_start:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(reasons, !hasText(schedule?.custodianDid), `retention_custodian_absent:${schedule?.recordFamily ?? 'unknown'}`);
  addReason(
    reasons,
    !hasText(schedule?.storageBoundaryRef),
    `retention_storage_boundary_absent:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(
    reasons,
    !isDigest(schedule?.accessPolicyHash),
    `retention_access_policy_hash_invalid:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(
    reasons,
    schedule?.metadataOnly !== true,
    `record_schedule_metadata_boundary_invalid:${schedule?.recordFamily ?? 'unknown'}`,
  );
  addReason(
    reasons,
    schedule?.protectedContentExcluded !== true,
    `record_schedule_protected_boundary_invalid:${schedule?.recordFamily ?? 'unknown'}`,
  );
}

function evaluateArchivePackage(archive, reasons) {
  addReason(reasons, !hasText(archive?.recordFamily), 'archive_record_family_absent');
  addReason(
    reasons,
    !REQUIRED_RECORD_FAMILIES.includes(archive?.recordFamily),
    `archive_record_family_unsupported:${archive?.recordFamily ?? 'unknown'}`,
  );
  addReason(reasons, !hasText(archive?.archiveRef), `archive_ref_absent:${archive?.recordFamily ?? 'unknown'}`);
  addReason(reasons, !isDigest(archive?.archiveHash), `archive_hash_invalid:${archive?.recordFamily ?? 'unknown'}`);
  addReason(reasons, !isDigest(archive?.custodyDigest), `archive_custody_digest_invalid:${archive?.recordFamily ?? 'unknown'}`);
  addReason(reasons, archive?.objectLockEnabled !== true, `archive_object_lock_absent:${archive?.recordFamily ?? 'unknown'}`);
  addReason(reasons, archive?.legalHoldSupported !== true, `archive_legal_hold_absent:${archive?.recordFamily ?? 'unknown'}`);
  addReason(
    reasons,
    !isDigest(archive?.retrievalIndexHash),
    `archive_retrieval_index_hash_invalid:${archive?.recordFamily ?? 'unknown'}`,
  );
  addReason(reasons, !isDigest(archive?.accessLogHash), `archive_access_log_hash_invalid:${archive?.recordFamily ?? 'unknown'}`);
  addReason(reasons, archive?.metadataOnly !== true, `archive_metadata_boundary_invalid:${archive?.recordFamily ?? 'unknown'}`);
  addReason(
    reasons,
    archive?.protectedContentExcluded !== true,
    `archive_protected_boundary_invalid:${archive?.recordFamily ?? 'unknown'}`,
  );
}

function evaluateLegalHold(hold, reasons) {
  const families = sortedTextList(hold?.appliesToRecordFamilies);

  addReason(reasons, !hasText(hold?.holdRef), 'legal_hold_ref_absent');
  addReason(reasons, !LEGAL_HOLD_STATUSES.has(hold?.status), `legal_hold_status_invalid:${hold?.holdRef ?? 'unknown'}`);
  addReason(reasons, families.length === 0, `legal_hold_families_absent:${hold?.holdRef ?? 'unknown'}`);
  for (const family of families) {
    addReason(reasons, !REQUIRED_RECORD_FAMILIES.includes(family), `legal_hold_family_unsupported:${family}`);
  }
  addReason(reasons, !isDigest(hold?.holdHash), `legal_hold_hash_invalid:${hold?.holdRef ?? 'unknown'}`);
  addReason(reasons, !isDigest(hold?.reasonHash), `legal_hold_reason_hash_invalid:${hold?.holdRef ?? 'unknown'}`);
  addReason(reasons, hlcTuple(hold?.imposedAtHlc) === null, `legal_hold_imposed_time_invalid:${hold?.holdRef ?? 'unknown'}`);
  addReason(reasons, hlcTuple(hold?.reviewedAtHlc) === null, `legal_hold_review_time_invalid:${hold?.holdRef ?? 'unknown'}`);
  addReason(
    reasons,
    hold?.status === 'released' && hlcTuple(hold?.releasedAtHlc) === null,
    `legal_hold_release_time_invalid:${hold?.holdRef ?? 'unknown'}`,
  );
  addReason(
    reasons,
    hold?.status === 'released' && !hlcAfter(hold?.releasedAtHlc, hold?.imposedAtHlc),
    `legal_hold_release_not_after_imposition:${hold?.holdRef ?? 'unknown'}`,
  );
  addReason(
    reasons,
    hold?.status === 'released' && !hlcAfter(hold?.reviewedAtHlc, hold?.releasedAtHlc),
    `legal_hold_review_before_release:${hold?.holdRef ?? 'unknown'}`,
  );
  addReason(
    reasons,
    !hlcAfter(hold?.reviewedAtHlc, hold?.imposedAtHlc),
    `legal_hold_review_not_after_imposition:${hold?.holdRef ?? 'unknown'}`,
  );
  addReason(reasons, !hasText(hold?.reviewedByDid), `legal_hold_reviewer_absent:${hold?.holdRef ?? 'unknown'}`);
  addReason(reasons, hold?.metadataOnly !== true, `legal_hold_metadata_boundary_invalid:${hold?.holdRef ?? 'unknown'}`);
  addReason(
    reasons,
    hold?.protectedContentExcluded !== true,
    `legal_hold_protected_boundary_invalid:${hold?.holdRef ?? 'unknown'}`,
  );
}

function activeLegalHoldFamilies(holds) {
  return uniqueSorted(
    (Array.isArray(holds) ? holds : []).flatMap((hold) =>
      hold?.status === 'active' ? sortedTextList(hold?.appliesToRecordFamilies) : [],
    ),
  );
}

function releasedHoldAfterDisposition(request, holds) {
  const relevantReleasedHolds = (Array.isArray(holds) ? holds : []).filter(
    (hold) => hold?.status === 'released' && sortedTextList(hold?.appliesToRecordFamilies).includes(request?.recordFamily),
  );

  return relevantReleasedHolds.some(
    (hold) =>
      hlcTuple(hold?.releasedAtHlc) !== null &&
      (!hlcAfter(request?.requestedAtHlc, hold.releasedAtHlc) || !hlcAfter(request?.approvedAtHlc, hold.releasedAtHlc)),
  );
}

function evaluateDispositionRequest(request, activeHolds, holds, schedule, reasons) {
  const family = request?.recordFamily ?? 'unknown';
  const activeHold = activeHolds.includes(request?.recordFamily);
  const eligibleAt = schedule?.eligibleDispositionAtHlc;

  addReason(reasons, !hasText(request?.recordFamily), 'disposition_record_family_absent');
  addReason(reasons, !REQUIRED_RECORD_FAMILIES.includes(request?.recordFamily), `disposition_family_unsupported:${family}`);
  addReason(reasons, !DISPOSITION_TYPES.has(request?.dispositionType), `disposition_type_invalid:${family}`);
  addReason(reasons, !hasText(request?.requestRef), `disposition_request_ref_absent:${family}`);
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, `disposition_request_time_invalid:${family}`);
  addReason(reasons, hlcTuple(request?.approvedAtHlc) === null, `disposition_approval_time_invalid:${family}`);
  addReason(reasons, !hlcAfter(request?.approvedAtHlc, request?.requestedAtHlc), `disposition_approval_not_after_request:${family}`);
  addReason(reasons, !hasText(request?.approvedByDid), `disposition_approver_absent:${family}`);
  addReason(reasons, !isDigest(request?.dispositionEvidenceHash), `disposition_evidence_hash_invalid:${family}`);
  addReason(reasons, request?.legalHoldChecked !== true, `legal_hold_check_absent:${family}`);
  addReason(reasons, request?.recordsPastEligibleDate !== true, `disposition_before_eligible:${family}`);
  addReason(reasons, releasedHoldAfterDisposition(request, holds), `disposition_before_legal_hold_release:${family}`);
  addReason(
    reasons,
    hlcTuple(eligibleAt) !== null && !hlcAfter(request?.requestedAtHlc, eligibleAt),
    `disposition_request_before_eligible:${family}`,
  );
  addReason(
    reasons,
    hlcTuple(eligibleAt) !== null && !hlcAfter(request?.approvedAtHlc, eligibleAt),
    `disposition_approval_before_eligible:${family}`,
  );
  addReason(reasons, activeHold && request?.dispositionType !== 'retain_on_hold', `disposition_blocked_by_legal_hold:${family}`);
  addReason(
    reasons,
    !activeHold && request?.dispositionType === 'retain_on_hold',
    `retain_on_hold_without_active_hold:${family}`,
  );
  addReason(
    reasons,
    request?.dispositionType === 'destroy' && !isDigest(request?.destructionCertificateHash),
    `destruction_certificate_hash_invalid:${family}`,
  );
  addReason(
    reasons,
    ARCHIVAL_DISPOSITION_TYPES.has(request?.dispositionType) && request?.destructionCertificateHash !== null,
    `destruction_certificate_not_applicable:${family}`,
  );
  addReason(reasons, request?.metadataOnly !== true, `disposition_metadata_boundary_invalid:${family}`);
  addReason(reasons, request?.protectedContentExcluded !== true, `disposition_protected_boundary_invalid:${family}`);
}

function byRecordFamily(rows) {
  const output = new Map();
  for (const row of Array.isArray(rows) ? rows : []) {
    if (hasText(row?.recordFamily) && !output.has(row.recordFamily)) {
      output.set(row.recordFamily, row);
    }
  }
  return output;
}

function duplicateRecordFamilies(rows) {
  const counts = new Map();
  for (const row of Array.isArray(rows) ? rows : []) {
    if (hasText(row?.recordFamily)) {
      counts.set(row.recordFamily, (counts.get(row.recordFamily) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .filter(([, count]) => count > 1)
    .map(([recordFamily]) => recordFamily)
    .sort();
}

function evaluateCoverage(input, activeHolds, reasons) {
  const scheduleMap = byRecordFamily(input?.recordSchedules);
  const archiveMap = byRecordFamily(input?.archivePackages);
  const dispositionMap = byRecordFamily(input?.dispositionRequests);

  for (const family of REQUIRED_RECORD_FAMILIES) {
    addReason(reasons, !scheduleMap.has(family), `record_schedule_missing:${family}`);
    addReason(reasons, !archiveMap.has(family), `archive_package_missing:${family}`);
    addReason(reasons, !dispositionMap.has(family), `disposition_request_missing:${family}`);
  }

  for (const family of duplicateRecordFamilies(input?.recordSchedules)) {
    addReason(reasons, true, `record_schedule_duplicate:${family}`);
  }
  for (const family of duplicateRecordFamilies(input?.archivePackages)) {
    addReason(reasons, true, `archive_package_duplicate:${family}`);
  }
  for (const family of duplicateRecordFamilies(input?.dispositionRequests)) {
    addReason(reasons, true, `disposition_request_duplicate:${family}`);
  }

  for (const schedule of Array.isArray(input?.recordSchedules) ? input.recordSchedules : []) {
    evaluateRecordSchedule(schedule, reasons);
  }
  for (const archive of Array.isArray(input?.archivePackages) ? input.archivePackages : []) {
    evaluateArchivePackage(archive, reasons);
  }
  for (const hold of Array.isArray(input?.legalHolds) ? input.legalHolds : []) {
    evaluateLegalHold(hold, reasons);
  }
  for (const request of Array.isArray(input?.dispositionRequests) ? input.dispositionRequests : []) {
    evaluateDispositionRequest(request, activeHolds, input?.legalHolds, scheduleMap.get(request?.recordFamily), reasons);
  }
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;

  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !Array.isArray(review?.reviewerRoleRefs) || review.reviewerRoleRefs.length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_final_authority_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'human_review_ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_claim_not_denied');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(
    reasons,
    !hlcAfter(review?.reviewedAtHlc, input?.retentionCycle?.holdReviewedAtHlc),
    'human_review_not_after_hold_review',
  );
  addReason(
    reasons,
    hlcBefore(input?.auditRecord?.receiptRecordedAtHlc, review?.reviewedAtHlc),
    'audit_record_time_before_human_review',
  );
}

function evaluateAuditRecord(audit, reasons) {
  addReason(reasons, !hasText(audit?.auditRecordRef), 'audit_record_ref_absent');
  addReason(reasons, !isDigest(audit?.auditRecordHash), 'audit_record_hash_invalid');
  addReason(reasons, !isDigest(audit?.previousAuditRecordHash), 'previous_audit_record_hash_invalid');
  addReason(reasons, !isDigest(audit?.disclosureLogHash), 'disclosure_log_hash_invalid');
  addReason(reasons, hlcTuple(audit?.receiptRecordedAtHlc) === null, 'audit_record_receipt_time_invalid');
  addReason(reasons, audit?.metadataOnly !== true, 'audit_record_metadata_boundary_invalid');
  addReason(reasons, audit?.protectedContentExcluded !== true, 'audit_record_protected_boundary_invalid');
}

function dispositionStatusFor(request, activeHold) {
  if (activeHold) {
    return 'retained_on_legal_hold';
  }
  if (request?.dispositionType === 'archive') {
    return 'archive_approved';
  }
  if (request?.dispositionType === 'destroy') {
    return 'destruction_approved';
  }
  if (request?.dispositionType === 'transfer') {
    return 'transfer_approved';
  }
  return 'disposition_pending';
}

function buildRetentionPackage(input, activeHolds) {
  const scheduleMap = byRecordFamily(input.recordSchedules);
  const archiveMap = byRecordFamily(input.archivePackages);
  const dispositionMap = byRecordFamily(input.dispositionRequests);
  const requiredRecordFamilies = [...REQUIRED_RECORD_FAMILIES].sort();

  const dispositionOutcomes = requiredRecordFamilies.map((recordFamily) => {
    const schedule = scheduleMap.get(recordFamily);
    const archive = archiveMap.get(recordFamily);
    const request = dispositionMap.get(recordFamily);
    const legalHoldActive = activeHolds.includes(recordFamily);
    return {
      archiveRef: archive.archiveRef,
      dispositionStatus: dispositionStatusFor(request, legalHoldActive),
      dispositionType: request.dispositionType,
      eligibleDispositionAtHlc: schedule.eligibleDispositionAtHlc,
      legalHoldActive,
      recordFamily,
      selectedRetentionMonths: schedule.selectedRetentionMonths,
    };
  });

  const packageCore = {
    activeLegalHoldFamilies: activeHolds,
    auditRecordHash: input.auditRecord.auditRecordHash,
    conflictPolicy: input.retentionPolicy.conflictPolicy,
    dispositionOutcomes,
    policyHash: input.retentionPolicy.policyHash,
    policyRef: input.retentionPolicy.policyRef,
    requiredRecordFamilies,
    retentionCycleRef: input.retentionCycle.cycleRef,
    schema: RETENTION_SCHEMA,
    tenantId: input.tenantId,
  };

  const retentionMatrixHash = sha256Hex({
    recordSchedules: requiredRecordFamilies.map((recordFamily) => {
      const schedule = scheduleMap.get(recordFamily);
      return {
        recordFamily,
        recordSetHash: schedule.recordSetHash,
        selectedRetentionMonths: schedule.selectedRetentionMonths,
        selectedRuleRef: schedule.selectedRuleRef,
      };
    }),
    schema: `${RETENTION_SCHEMA}.matrix.v1`,
    tenantId: input.tenantId,
  });

  return {
    ...packageCore,
    packageId: `records_retention_${sha256Hex(packageCore).slice(0, 32)}`,
    retentionMatrixHash,
    metadataOnly: true,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildReceipt(input, retentionPackage) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: sha256Hex(retentionPackage),
    artifactType: 'records_retention_disposition_package',
    artifactVersion: input.retentionCycle.cycleRef,
    classification: 'regulated_quality_metadata',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.retentionCycle.auditRecordedAtHlc,
    sensitivityTags: ['metadata_only', 'records_retention', 'regulated_quality_record'],
    sourceSystem: 'cybermedica-qms-contracts',
    tenantId: input.tenantId,
  });
}

export function evaluateRecordsRetentionDisposition(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.retentionPolicy, reasons);
  evaluateCycle(input?.retentionCycle, input?.retentionPolicy, reasons);

  const activeHolds = activeLegalHoldFamilies(input?.legalHolds);
  evaluateCoverage(input, activeHolds, reasons);
  evaluateHumanReview(input, reasons);
  evaluateAuditRecord(input?.auditRecord, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const sortedReasons = uniqueReasons(reasons);
  if (sortedReasons.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: sortedReasons,
      retentionPackage: null,
      receipt: null,
    };
  }

  const retentionPackage = buildRetentionPackage(input, activeHolds);
  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    retentionPackage,
    receipt: buildReceipt(input, retentionPackage),
  };
}
