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
const REQUIRED_PERMISSION = 'audit_log_maintain';

const REQUIRED_AUDIT_LOG_FAMILIES = Object.freeze([
  'access',
  'approvals',
  'authentication',
  'decisions',
  'delegations',
  'document_changes',
  'evidence',
  'exports',
  'privileged_actions',
]);

const AUDIT_LOG_STATUSES = Object.freeze(['reviewed']);
const POLICY_STATUSES = Object.freeze(['active']);
const HUMAN_REVIEW_STATUSES = Object.freeze(['approved']);
const AUDIT_RESULTS = Object.freeze([
  'approved',
  'closed',
  'denied',
  'held',
  'logged',
  'permitted',
  'rejected',
  'released',
  'revoked',
]);

const RAW_AUDIT_LOG_FIELDS = Object.freeze([
  'auditbody',
  'auditcontent',
  'auditlogbody',
  'body',
  'content',
  'freetext',
  'rawauditcontent',
  'rawauditentry',
  'rawauditlog',
  'rawauditlogcontent',
  'rawevent',
  'rawlog',
  'rawpayload',
  'rawrecord',
  'rawsourcedata',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_AUDIT_LOG_FIELDS = Object.freeze([
  'accesstoken',
  'adaptersecret',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'bootstraptoken',
  'clientsecret',
  'credential',
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

function addReason(reasons, condition, reason) {
  if (condition) {
    reasons.push(reason);
  }
}

function uniqueSorted(reasons) {
  const sorted = [...reasons].sort();
  return sorted.filter((reason, index) => index === 0 || reason !== sorted[index - 1]);
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function isDigestOrZero(value) {
  return value === ZERO_HASH || isDigest(value);
}

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function isNonNegativeSafeInteger(value) {
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

function assertNoRawAuditLogContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAuditLogContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_AUDIT_LOG_FIELDS.includes(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw audit-log content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_AUDIT_LOG_FIELDS.includes(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`audit-log secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawAuditLogContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAuditLogContent(input ?? {});
  canonicalize(input ?? {});
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

function sortedTextList(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  const sorted = value.filter(hasText).sort();
  return sorted.filter((entry, index) => index === 0 || entry !== sorted[index - 1]);
}

function sortedRecords(records) {
  return [...records].sort((left, right) => {
    if (left.sequence !== right.sequence) {
      return left.sequence < right.sequence ? -1 : 1;
    }
    return String(left.eventId).localeCompare(String(right.eventId));
  });
}

function integerBasisPoints(present, total) {
  if (!Number.isSafeInteger(present) || !Number.isSafeInteger(total) || present <= 0 || total <= 0) {
    return 0;
  }
  return Number((BigInt(present) * 10_000n) / BigInt(total));
}

function hasAuthorityPermission(authority) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(REQUIRED_PERMISSION);
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
  addReason(reasons, !hasAuthorityPermission(input?.authority), 'authority_permission_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.includes(policy?.status), 'policy_not_active');
  addReason(reasons, policy?.appendOnlyRequired !== true, 'policy_append_only_not_required');
  addReason(reasons, policy?.tamperEvidenceRequired !== true, 'policy_tamper_evidence_not_required');
  addReason(reasons, policy?.immutableRecordRequired !== true, 'policy_immutable_record_not_required');
  addReason(reasons, policy?.metadataOnly !== true, 'policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'policy_protected_boundary_invalid');
  addReason(reasons, policy?.rawPayloadExcluded !== true, 'policy_raw_payload_boundary_invalid');
  addReason(reasons, policy?.silentDeletionForbidden !== true, 'policy_silent_deletion_not_forbidden');
  addReason(reasons, policy?.supplementOnlyCorrections !== true, 'policy_correction_mode_invalid');
  addReason(reasons, hlcTuple(policy?.reviewedAtHlc) === null, 'policy_review_time_invalid');

  const configuredFamilies = sortedTextList(policy?.requiredEventFamilies);
  for (const family of REQUIRED_AUDIT_LOG_FAMILIES) {
    addReason(reasons, !configuredFamilies.includes(family), `policy_required_family_missing:${family}`);
  }
}

function evaluateLogShape(log, reasons) {
  const start = hlcTuple(log?.windowStartHlc);
  const end = hlcTuple(log?.windowEndHlc);

  addReason(reasons, !hasText(log?.logRef), 'audit_log_ref_absent');
  addReason(reasons, !hasText(log?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(log?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(log?.sourceSystemRef), 'source_system_ref_absent');
  addReason(reasons, !AUDIT_LOG_STATUSES.includes(log?.status), 'audit_log_not_reviewed');
  addReason(reasons, !isDigestOrZero(log?.priorHeadHash), 'prior_head_hash_invalid');
  addReason(reasons, !isNonNegativeSafeInteger(log?.priorSequence), 'prior_sequence_invalid');
  addReason(reasons, start === null, 'audit_log_window_start_invalid');
  addReason(reasons, end === null, 'audit_log_window_end_invalid');
  addReason(reasons, start !== null && end !== null && compareHlc(end, start) <= 0, 'audit_log_window_order_invalid');
  addReason(reasons, !Array.isArray(log?.entries) || log.entries.length === 0, 'audit_log_entries_absent');
}

function evaluateDeletionControls(controls, reasons) {
  addReason(reasons, controls?.silentDeleteDisabled !== true, 'silent_delete_control_invalid');
  addReason(reasons, controls?.deleteRequiresSupersession !== true, 'silent_delete_control_invalid');
  addReason(reasons, controls?.deletionEventsAudited !== true, 'silent_delete_control_invalid');
  addReason(reasons, !isDigest(controls?.retentionOverrideHash), 'retention_override_hash_invalid');
}

function evaluateCorrectionControls(controls, reasons) {
  addReason(reasons, controls?.supplementCorrectionsOnly !== true, 'correction_control_invalid');
  addReason(reasons, controls?.supersessionAuditRequired !== true, 'correction_control_invalid');
  addReason(reasons, controls?.annotationAuditRequired !== true, 'correction_control_invalid');
  addReason(reasons, !isDigest(controls?.correctionPolicyHash), 'correction_policy_hash_invalid');
}

function evaluateHumanReview(review, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_STATUSES.includes(review?.status), 'human_review_not_approved');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !isDigest(review?.evidenceBundleHash), 'human_review_evidence_hash_invalid');
  addReason(reasons, !isDigest(review?.qualityApprovalHash), 'quality_approval_hash_invalid');
  addReason(reasons, review?.decisionForum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, review?.decisionForum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, review?.decisionForum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, review?.decisionForum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, review?.decisionForum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(review?.decisionForum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(review?.decisionForum?.workflowReceiptId), 'workflow_receipt_absent');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  addReason(reasons, aiAssistance?.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance?.used === true && aiAssistance?.reviewedByHuman !== true, 'ai_human_review_absent');
  addReason(reasons, aiAssistance?.used === true && !isDigest(aiAssistance?.scopeHash), 'ai_scope_hash_invalid');
}

function recordMaterial(entry) {
  return {
    action: entry.action,
    actorDid: entry.actorDid,
    custodyDigest: entry.custodyDigest,
    eventFamily: entry.eventFamily,
    eventHash: entry.eventHash,
    eventId: entry.eventId,
    objectRef: entry.objectRef,
    occurredAtHlc: entry.occurredAtHlc,
    previousEntryHash: entry.previousEntryHash,
    receiptHash: entry.receiptHash,
    result: entry.result,
    schema: 'cybermedica.audit_log_record_material.v1',
    sequence: entry.sequence,
  };
}

function computeRecordHash(entry) {
  return sha256Hex(recordMaterial(entry));
}

function evaluateEntry(entry, log, expectedSequence, expectedPreviousHash, reasons) {
  const family = hasText(entry?.eventFamily) ? entry.eventFamily : 'unknown';
  const occurredAt = hlcTuple(entry?.occurredAtHlc);

  addReason(reasons, !hasText(entry?.eventId), `audit_log_event_id_absent:${family}`);
  addReason(reasons, !REQUIRED_AUDIT_LOG_FAMILIES.includes(family), `audit_log_family_unsupported:${family}`);
  addReason(reasons, !isPositiveSafeInteger(entry?.sequence), `audit_log_sequence_invalid:${family}`);
  addReason(
    reasons,
    isPositiveSafeInteger(entry?.sequence) && Number.isSafeInteger(expectedSequence) && entry.sequence !== expectedSequence,
    `audit_log_sequence_gap:${family}`,
  );
  addReason(reasons, !isDigestOrZero(entry?.previousEntryHash), `audit_log_previous_hash_invalid:${family}`);
  addReason(
    reasons,
    isDigestOrZero(entry?.previousEntryHash) && entry.previousEntryHash !== expectedPreviousHash,
    `audit_log_chain_input_mismatch:${family}`,
  );
  addReason(reasons, !isDigest(entry?.eventHash), `audit_log_event_hash_invalid:${family}`);
  addReason(reasons, !hasText(entry?.actorDid), `audit_log_actor_absent:${family}`);
  addReason(reasons, !hasText(entry?.action), `audit_log_action_absent:${family}`);
  addReason(reasons, !AUDIT_RESULTS.includes(entry?.result), `audit_log_result_invalid:${family}`);
  addReason(reasons, !hasText(entry?.objectRef), `audit_log_object_ref_absent:${family}`);
  addReason(reasons, occurredAt === null, `audit_log_entry_time_invalid:${family}`);
  addReason(reasons, hlcBefore(entry?.occurredAtHlc, log?.windowStartHlc), `audit_log_entry_before_window:${family}`);
  addReason(reasons, hlcAfter(entry?.occurredAtHlc, log?.windowEndHlc), `audit_log_entry_after_window:${family}`);
  addReason(reasons, !hasText(entry?.retentionPolicyRef), `audit_log_retention_policy_absent:${family}`);
  addReason(reasons, !hasText(entry?.accessPolicyRef), `audit_log_access_policy_absent:${family}`);
  addReason(reasons, !hasText(entry?.storagePartitionRef), `audit_log_storage_partition_absent:${family}`);
  addReason(reasons, !hasText(entry?.receiptRef), `audit_log_receipt_ref_absent:${family}`);
  addReason(reasons, !isDigest(entry?.receiptHash), `audit_log_receipt_hash_invalid:${family}`);
  addReason(reasons, !isDigest(entry?.custodyDigest), `audit_log_custody_digest_invalid:${family}`);
  addReason(reasons, entry?.immutable !== true, `audit_log_entry_not_immutable:${family}`);
  addReason(reasons, entry?.appendOnly !== true, `audit_log_entry_not_append_only:${family}`);
  addReason(reasons, entry?.tamperEvident !== true, `audit_log_entry_not_tamper_evident:${family}`);
  addReason(reasons, entry?.metadataOnly !== true, `audit_log_entry_metadata_boundary_invalid:${family}`);
  addReason(reasons, entry?.protectedContentExcluded !== true, `audit_log_entry_protected_boundary_invalid:${family}`);
  addReason(reasons, entry?.rawPayloadExcluded !== true, `audit_log_entry_raw_payload_boundary_invalid:${family}`);
  addReason(reasons, entry?.deletionMarker === true, `audit_log_deletion_marker_forbidden:${family}`);
}

function buildRecord(input, entry, recordHash) {
  return {
    schema: 'cybermedica.audit_log_record.v1',
    tenantId: input.tenantId,
    logRef: input.auditLog.logRef,
    eventId: entry.eventId,
    eventFamily: entry.eventFamily,
    sequence: entry.sequence,
    previousEntryHash: entry.previousEntryHash,
    recordHash,
    eventHash: entry.eventHash,
    actorDid: entry.actorDid,
    action: entry.action,
    result: entry.result,
    objectRef: entry.objectRef,
    occurredAtHlc: entry.occurredAtHlc,
    retentionPolicyRef: entry.retentionPolicyRef,
    accessPolicyRef: entry.accessPolicyRef,
    storagePartitionRef: entry.storagePartitionRef,
    receiptRef: entry.receiptRef,
    receiptHash: entry.receiptHash,
    custodyDigest: entry.custodyDigest,
    correctionOfEventId: entry.correctionOfEventId ?? null,
    immutable: entry.immutable === true,
    appendOnly: entry.appendOnly === true,
    tamperEvident: entry.tamperEvident === true,
    metadataOnly: entry.metadataOnly === true,
    protectedContentExcluded: entry.protectedContentExcluded === true,
    rawPayloadExcluded: entry.rawPayloadExcluded === true,
    deletionMarker: entry.deletionMarker === true,
  };
}

function normalizeAuditLogEntries(input, reasons) {
  const entries = Array.isArray(input?.auditLog?.entries) ? sortedRecords(input.auditLog.entries) : [];
  const expectedByFamily = [];
  const records = [];
  let expectedPreviousHash = input?.auditLog?.priorHeadHash;
  let expectedSequence = Number.isSafeInteger(input?.auditLog?.priorSequence) ? input.auditLog.priorSequence + 1 : null;

  for (const entry of entries) {
    evaluateEntry(entry, input?.auditLog, expectedSequence, expectedPreviousHash, reasons);
    const recordHash = computeRecordHash(entry);
    records.push(buildRecord(input, entry, recordHash));
    if (hasText(entry?.eventFamily) && !expectedByFamily.includes(entry.eventFamily)) {
      expectedByFamily.push(entry.eventFamily);
    }
    expectedPreviousHash = recordHash;
    expectedSequence = Number.isSafeInteger(expectedSequence) ? expectedSequence + 1 : null;
  }

  for (const family of REQUIRED_AUDIT_LOG_FAMILIES) {
    addReason(reasons, !expectedByFamily.includes(family), `audit_log_family_missing:${family}`);
  }

  return records;
}

function buildDeniedAuditLog(input) {
  return {
    schema: 'cybermedica.fr043_audit_log.v1',
    requirementId: 'FR-043',
    tenantId: input?.tenantId ?? null,
    logRef: input?.auditLog?.logRef ?? null,
    auditLogStatus: 'blocked',
    coveredEventFamilies: [],
    entryCount: 0,
    records: [],
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildAuditLog(input, records, logHash, chainHeadHash) {
  const coveredEventFamilies = sortedTextList(records.map((record) => record.eventFamily));

  return {
    schema: 'cybermedica.fr043_audit_log.v1',
    requirementId: 'FR-043',
    tenantId: input.tenantId,
    logRef: input.auditLog.logRef,
    protocolRef: input.auditLog.protocolRef,
    siteRef: input.auditLog.siteRef,
    sourceSystemRef: input.auditLog.sourceSystemRef,
    auditLogStatus: 'maintained',
    windowStartHlc: input.auditLog.windowStartHlc,
    windowEndHlc: input.auditLog.windowEndHlc,
    priorHeadHash: input.auditLog.priorHeadHash,
    priorSequence: input.auditLog.priorSequence,
    chainHeadHash,
    logHash,
    entryCount: records.length,
    coveredEventFamilies,
    familyCoverageBasisPoints: integerBasisPoints(coveredEventFamilies.length, REQUIRED_AUDIT_LOG_FAMILIES.length),
    immutableAuditLog: true,
    appendOnly: true,
    tamperEvident: true,
    silentDeletionForbidden: true,
    supplementOnlyCorrections: true,
    operationalStateMutable: false,
    records,
    trustState: 'inactive',
    exochainProductionClaim: false,
    sourceEvidence: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md#FR-043',
      'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
    ],
  };
}

function buildReceipt(input, logHash) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'audit_log_maintenance',
    artifactVersion: `${input.auditLog.logRef}@${input.auditLog.priorSequence + input.auditLog.entries.length}`,
    artifactHash: logHash,
    classification: 'audit_metadata_only',
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['audit_log', 'append_only', 'tamper_evident', 'metadata_only'],
    sourceSystem: 'cybermedica-qms',
  });
}

export function verifyAuditLogChain(records, options = {}) {
  assertMetadataOnly({ options, records });

  const reasons = [];
  const safeRecords = Array.isArray(records) ? sortedRecords(records) : [];
  const priorHeadHash = options?.priorHeadHash ?? ZERO_HASH;
  const priorSequence = options?.priorSequence ?? 0;

  addReason(reasons, !Array.isArray(records) || records.length === 0, 'audit_log_chain_empty');
  addReason(reasons, !isDigestOrZero(priorHeadHash), 'prior_head_hash_invalid');
  addReason(reasons, !isNonNegativeSafeInteger(priorSequence), 'prior_sequence_invalid');

  let expectedPreviousHash = priorHeadHash;
  let headHash = priorHeadHash;

  safeRecords.forEach((record, index) => {
    const position = index + 1;
    const expectedSequence = priorSequence + position;
    const computedHash = computeRecordHash(record);

    addReason(reasons, record?.sequence !== expectedSequence, `audit_log_sequence_broken_at_${position}`);
    addReason(reasons, record?.previousEntryHash !== expectedPreviousHash, `audit_log_chain_broken_at_${position}`);
    addReason(reasons, record?.recordHash !== computedHash, `audit_log_record_hash_mismatch_at_${position}`);

    expectedPreviousHash = computedHash;
    headHash = computedHash;
  });

  const uniqueReasons = uniqueSorted(reasons);
  const valid = uniqueReasons.length === 0;

  return {
    schema: 'cybermedica.audit_log_chain_verification.v1',
    valid,
    failClosed: !valid,
    reasons: uniqueReasons,
    entriesVerified: valid ? safeRecords.length : 0,
    headHash: valid ? headHash : null,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export function evaluateAuditLogMaintenance(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.auditLogPolicy, reasons);
  evaluateLogShape(input?.auditLog, reasons);
  evaluateDeletionControls(input?.auditLog?.deletionControls, reasons);
  evaluateCorrectionControls(input?.auditLog?.correctionControls, reasons);
  evaluateHumanReview(input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const records = normalizeAuditLogEntries(input, reasons);
  const verification = verifyAuditLogChain(records, {
    priorHeadHash: input?.auditLog?.priorHeadHash ?? ZERO_HASH,
    priorSequence: input?.auditLog?.priorSequence ?? 0,
  });

  if (verification.valid !== true) {
    reasons.push(...verification.reasons);
  }

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return {
      schema: 'cybermedica.audit_log_maintenance_decision.v1',
      decision: 'denied',
      failClosed: true,
      reasons: uniqueReasons,
      auditLog: buildDeniedAuditLog(input),
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const chainHeadHash = verification.headHash;
  const logHash = sha256Hex({
    chainHeadHash,
    logRef: input.auditLog.logRef,
    records,
    schema: 'cybermedica.fr043_audit_log_material.v1',
    tenantId: input.tenantId,
    windowEndHlc: input.auditLog.windowEndHlc,
    windowStartHlc: input.auditLog.windowStartHlc,
  });
  const auditLog = buildAuditLog(input, records, logHash, chainHeadHash);
  const receipt = buildReceipt(input, logHash);

  return {
    schema: 'cybermedica.audit_log_maintenance_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    auditLog,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
