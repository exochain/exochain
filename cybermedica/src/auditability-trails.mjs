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
const REQUIRED_PERMISSION = 'auditability_review';

const REQUIRED_AUDIT_FAMILIES = Object.freeze([
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

const REVIEWED_TRAIL_STATUSES = new Set(['reviewed']);
const HUMAN_REVIEW_DECISIONS = new Set(['auditability_ready', 'hold_for_auditability_gap']);

const RAW_AUDITABILITY_FIELDS = new Set([
  'auditbody',
  'auditcontent',
  'auditlogbody',
  'freetext',
  'rawevent',
  'rawauditcontent',
  'rawauditentry',
  'rawauditlog',
  'rawaudittrail',
  'rawpayload',
  'rawrecord',
  'rawsourcedata',
  'sourcebody',
  'sourcedocumentbody',
  'trailbody',
]);

const SECRET_AUDITABILITY_FIELDS = new Set([
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
  return [...new Set(reasons)].sort();
}

function isDigest(value) {
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
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

function assertNoRawAuditabilityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAuditabilityContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_AUDITABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw auditability content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_AUDITABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`auditability secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawAuditabilityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAuditabilityContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function integerBasisPoints(present, total) {
  if (!Number.isSafeInteger(present) || !Number.isSafeInteger(total) || present <= 0 || total <= 0) {
    return 0;
  }
  return Number((BigInt(present) * 10_000n) / BigInt(total));
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
  addReason(reasons, hlcTuple(policy?.reviewedAtHlc) === null, 'policy_review_time_invalid');
  addReason(reasons, policy?.appendOnlyRequired !== true, 'policy_append_only_not_required');
  addReason(reasons, policy?.tamperEvidenceRequired !== true, 'policy_tamper_evidence_not_required');
  addReason(reasons, policy?.metadataOnly !== true, 'policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'policy_protected_boundary_invalid');
  addReason(reasons, policy?.rawPayloadExcluded !== true, 'policy_raw_payload_boundary_invalid');
  addReason(reasons, policy?.silentDeletionForbidden !== true, 'policy_silent_deletion_not_forbidden');

  const configuredFamilies = new Set(sortedTextList(policy?.requiredEventFamilies));
  for (const family of REQUIRED_AUDIT_FAMILIES) {
    addReason(reasons, !configuredFamilies.has(family), `policy_required_family_missing:${family}`);
  }
}

function evaluateTrailShape(trail, reasons) {
  const start = hlcTuple(trail?.reviewWindowStartHlc);
  const end = hlcTuple(trail?.reviewWindowEndHlc);

  addReason(reasons, !hasText(trail?.trailRef), 'trail_ref_absent');
  addReason(reasons, !hasText(trail?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(trail?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(trail?.sourceSystemRef), 'source_system_ref_absent');
  addReason(reasons, !REVIEWED_TRAIL_STATUSES.has(trail?.status), 'audit_trail_not_reviewed');
  addReason(reasons, start === null, 'review_window_start_invalid');
  addReason(reasons, end === null, 'review_window_end_invalid');
  addReason(reasons, start !== null && end !== null && compareHlc(end, start) <= 0, 'review_window_order_invalid');
}

function evaluateAuditFamily(row, trail, reasons) {
  const family = hasText(row?.family) ? row.family : 'unknown';
  const firstEvent = hlcTuple(row?.firstEventAtHlc);
  const latestEvent = hlcTuple(row?.latestEventAtHlc);

  addReason(reasons, !REQUIRED_AUDIT_FAMILIES.includes(family), `audit_family_unsupported:${family}`);
  addReason(reasons, !isPositiveSafeInteger(row?.eventCount), `audit_family_event_count_invalid:${family}`);
  addReason(reasons, !isPositiveSafeInteger(row?.firstSequence), `audit_family_first_sequence_invalid:${family}`);
  addReason(reasons, !isPositiveSafeInteger(row?.lastSequence), `audit_family_last_sequence_invalid:${family}`);
  addReason(
    reasons,
    isPositiveSafeInteger(row?.firstSequence) && isPositiveSafeInteger(row?.lastSequence) && row.lastSequence < row.firstSequence,
    `audit_family_sequence_order_invalid:${family}`,
  );
  addReason(reasons, !isNonNegativeSafeInteger(row?.sequenceGapCount), `audit_family_sequence_gap_count_invalid:${family}`);
  addReason(reasons, row?.sequenceGapCount > 0, `audit_family_sequence_gap:${family}`);
  addReason(reasons, !isDigest(row?.firstEventHash), `audit_family_first_hash_invalid:${family}`);
  addReason(reasons, !isDigest(row?.latestEventHash), `audit_family_latest_hash_invalid:${family}`);
  addReason(reasons, !isDigest(row?.previousFamilyHash), `audit_family_previous_hash_invalid:${family}`);
  addReason(reasons, row?.appendOnly !== true, `audit_family_not_append_only:${family}`);
  addReason(reasons, row?.tamperEvident !== true, `audit_family_not_tamper_evident:${family}`);
  addReason(reasons, !hasText(row?.retentionPolicyRef), `audit_family_retention_policy_absent:${family}`);
  addReason(reasons, !hasText(row?.accessPolicyRef), `audit_family_access_policy_absent:${family}`);
  addReason(reasons, !hasText(row?.storagePartitionRef), `audit_family_storage_partition_absent:${family}`);
  addReason(reasons, !isDigest(row?.reviewEvidenceHash), `audit_family_review_evidence_invalid:${family}`);
  addReason(reasons, firstEvent === null, `audit_family_first_time_invalid:${family}`);
  addReason(reasons, latestEvent === null, `audit_family_latest_time_invalid:${family}`);
  addReason(reasons, firstEvent !== null && latestEvent !== null && compareHlc(latestEvent, firstEvent) < 0, `audit_family_time_order_invalid:${family}`);
  addReason(reasons, hlcBefore(row?.firstEventAtHlc, trail?.reviewWindowStartHlc), `audit_family_before_review_window:${family}`);
  addReason(reasons, hlcAfter(row?.latestEventAtHlc, trail?.reviewWindowEndHlc), `audit_family_after_review_window:${family}`);
  addReason(reasons, row?.metadataOnly !== true, `audit_family_metadata_boundary_invalid:${family}`);
  addReason(reasons, row?.protectedContentExcluded !== true, `audit_family_protected_boundary_invalid:${family}`);
  addReason(reasons, row?.rawPayloadExcluded !== true, `audit_family_raw_payload_boundary_invalid:${family}`);
}

function normalizeAuditFamilies(trail, reasons) {
  const rows = Array.isArray(trail?.eventFamilies) ? trail.eventFamilies : [];
  if (rows.length === 0) {
    reasons.push('event_family_list_absent');
  }

  const byFamily = new Map();
  for (const row of rows) {
    if (hasText(row?.family) && !byFamily.has(row.family)) {
      byFamily.set(row.family, row);
    }
    evaluateAuditFamily(row, trail, reasons);
  }

  const normalized = [];
  for (const family of REQUIRED_AUDIT_FAMILIES) {
    const row = byFamily.get(family);
    if (row === undefined) {
      reasons.push(`audit_family_missing:${family}`);
      continue;
    }
    normalized.push({
      accessPolicyRef: row.accessPolicyRef,
      appendOnly: row.appendOnly === true,
      eventCount: row.eventCount,
      family,
      firstEventAtHlc: row.firstEventAtHlc,
      firstEventHash: row.firstEventHash,
      firstSequence: row.firstSequence,
      latestEventAtHlc: row.latestEventAtHlc,
      latestEventHash: row.latestEventHash,
      lastSequence: row.lastSequence,
      metadataOnly: row.metadataOnly === true,
      previousFamilyHash: row.previousFamilyHash,
      protectedContentExcluded: row.protectedContentExcluded === true,
      rawPayloadExcluded: row.rawPayloadExcluded === true,
      retentionPolicyRef: row.retentionPolicyRef,
      reviewEvidenceHash: row.reviewEvidenceHash,
      sequenceGapCount: row.sequenceGapCount,
      storagePartitionRef: row.storagePartitionRef,
      tamperEvident: row.tamperEvident === true,
    });
  }

  return normalized.sort((left, right) => left.family.localeCompare(right.family));
}

function evaluateDeletionControls(trail, reasons) {
  const controls = trail?.deletionControls;
  const invalid =
    controls?.silentDeleteDisabled !== true ||
    controls?.deleteRequiresSupersession !== true ||
    controls?.deletionEventsAudited !== true ||
    !isDigest(controls?.retentionOverrideHash);
  addReason(reasons, invalid, 'silent_delete_control_invalid');
}

function evaluateCorrectionControls(trail, reasons) {
  const controls = trail?.correctionControls;
  const invalid =
    controls?.supplementCorrectionsOnly !== true ||
    controls?.supersessionAuditRequired !== true ||
    controls?.annotationAuditRequired !== true ||
    !isDigest(controls?.correctionPolicyHash);
  addReason(reasons, invalid, 'correction_control_invalid');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  const forum = review?.decisionForum;

  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.reviewDecision), 'human_review_decision_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, input?.auditTrail?.reviewWindowEndHlc), 'human_review_not_after_review_window');
  addReason(reasons, !isDigest(review?.evidenceBundleHash), 'human_review_evidence_bundle_invalid');
  addReason(reasons, !isDigest(review?.qualityApprovalHash), 'human_review_quality_approval_invalid');
  addReason(reasons, forum?.verified !== true, 'decision_forum_unverified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'challenge_open');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_receipt_absent');
}

function auditTrailHash(input, auditFamilies) {
  return sha256Hex({
    auditFamilies,
    auditabilityPolicy: {
      policyHash: input.auditabilityPolicy.policyHash,
      policyRef: input.auditabilityPolicy.policyRef,
      requiredEventFamilies: sortedTextList(input.auditabilityPolicy.requiredEventFamilies),
    },
    auditTrail: {
      protocolRef: input.auditTrail.protocolRef,
      reviewWindowEndHlc: input.auditTrail.reviewWindowEndHlc,
      reviewWindowStartHlc: input.auditTrail.reviewWindowStartHlc,
      siteRef: input.auditTrail.siteRef,
      sourceSystemRef: input.auditTrail.sourceSystemRef,
      status: input.auditTrail.status,
      trailRef: input.auditTrail.trailRef,
    },
    authorityChainHash: input.authority.authorityChainHash,
    correctionControls: input.auditTrail.correctionControls,
    deletionControls: input.auditTrail.deletionControls,
    schema: 'cybermedica.auditability_trail_coverage_hash.v1',
    tenantId: input.tenantId,
  });
}

function buildAuditabilityTrail(input, auditFamilies, hash, receipt) {
  const coveredAuditFamilies = auditFamilies.map((family) => family.family);
  const appendOnlyCount = auditFamilies.filter((family) => family.appendOnly).length;
  const tamperEvidentCount = auditFamilies.filter((family) => family.tamperEvident).length;
  const totalAuditEvents = auditFamilies.reduce((sum, family) => sum + family.eventCount, 0);
  const auditabilityStatus = input.humanReview.reviewDecision === 'auditability_ready'
    ? 'ready'
    : 'hold_for_auditability_gap';

  return {
    schema: 'cybermedica.auditability_trail_coverage.v1',
    auditabilityTrailId: `cmatc_${sha256Hex({
      hash,
      tenantId: input.tenantId,
      trailRef: input.auditTrail.trailRef,
    }).slice(0, 32)}`,
    auditTrailHash: hash,
    tenantId: input.tenantId,
    trailRef: input.auditTrail.trailRef,
    protocolRef: input.auditTrail.protocolRef,
    siteRef: input.auditTrail.siteRef,
    sourceSystemRef: input.auditTrail.sourceSystemRef,
    auditabilityStatus,
    coveredAuditFamilies,
    familyCoverageBasisPoints: integerBasisPoints(coveredAuditFamilies.length, REQUIRED_AUDIT_FAMILIES.length),
    appendOnlyCoverageBasisPoints: integerBasisPoints(appendOnlyCount, REQUIRED_AUDIT_FAMILIES.length),
    tamperEvidenceCoverageBasisPoints: integerBasisPoints(tamperEvidentCount, REQUIRED_AUDIT_FAMILIES.length),
    totalAuditEvents,
    eventFamilyManifestHash: sha256Hex(auditFamilies),
    silentDeletionPrevented: true,
    supplementOnlyCorrections: true,
    authorityChainHash: input.authority.authorityChainHash,
    decisionForumReceiptId: input.humanReview.decisionForum.workflowReceiptId,
    receiptId: receipt.receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function deniedAuditabilityTrail(reasons) {
  return {
    schema: 'cybermedica.auditability_trail_coverage_decision.v1',
    decision: 'denied',
    failClosed: true,
    reasons,
    auditTrail: {
      schema: 'cybermedica.auditability_trail_coverage.v1',
      auditabilityStatus: 'blocked',
      trustState: 'inactive',
      exochainProductionClaim: false,
    },
    receipt: null,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export function evaluateAuditabilityTrailCoverage(input) {
  const reasons = [];
  assertMetadataOnly(input);
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.auditabilityPolicy, reasons);
  evaluateTrailShape(input?.auditTrail, reasons);
  const auditFamilies = normalizeAuditFamilies(input?.auditTrail, reasons);
  evaluateDeletionControls(input?.auditTrail, reasons);
  evaluateCorrectionControls(input?.auditTrail, reasons);
  evaluateHumanReview(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return deniedAuditabilityTrail(uniqueReasons);
  }

  const hash = auditTrailHash(input, auditFamilies);
  const receipt = createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'auditability_trail_coverage',
    artifactVersion: `${input.auditTrail.trailRef}@${input.auditTrail.reviewWindowEndHlc.physicalMs}.${input.auditTrail.reviewWindowEndHlc.logical}`,
    artifactHash: hash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.auditTrail.reviewWindowEndHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['auditability', 'metadata_only', 'nfr_005'],
    sourceSystem: 'cybermedica-qms',
  });

  return {
    schema: 'cybermedica.auditability_trail_coverage_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    auditTrail: buildAuditabilityTrail(input, auditFamilies, hash, receipt),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
