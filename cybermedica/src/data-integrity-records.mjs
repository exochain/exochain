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

const HEX_64 = /^[0-9a-f]{64}$/u;
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const REQUIRED_PERMISSION = 'data_integrity_review';

const REQUIRED_RECORD_FAMILIES = Object.freeze([
  'audit_exports',
  'case_report_forms',
  'consent_records',
  'controlled_documents',
  'decision_forum_records',
  'deviations_capa',
  'product_accountability',
  'safety_events',
  'source_data',
  'training_delegation',
]);

const REQUIRED_ALCOAC_DIMENSIONS = Object.freeze([
  'accurate',
  'attributable',
  'complete',
  'contemporaneous',
  'legible',
  'original',
]);

const VERIFIED_CONTROL_STATUSES = new Set(['validated', 'verified']);
const VERIFIED_RECORD_STATUSES = new Set(['complete', 'current']);
const VERIFIED_REVIEW_STATUSES = new Set(['human_verified', 'verified']);
const APPROVED_CORRECTION_STATUSES = new Set(['approved']);
const HUMAN_REVIEW_DECISIONS = new Set(['data_integrity_ready', 'hold_for_integrity_gap']);

const RAW_DATA_INTEGRITY_FIELDS = new Set([
  'clinicalnote',
  'freeformrecord',
  'rawclinicalcontent',
  'rawcrfdata',
  'rawdataintegritycontent',
  'rawrecordbody',
  'rawrecordcontent',
  'rawsourcedata',
  'sourcebody',
  'sourcedocumentbody',
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
  return hasText(value) && HEX_64.test(value) && value !== ZERO_HASH;
}

function normalizeFieldName(fieldName) {
  return String(fieldName).replaceAll(/[^a-z0-9]/giu, '').toLowerCase();
}

function assertNoRawDataIntegrityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawDataIntegrityContent(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RAW_DATA_INTEGRITY_FIELDS.has(normalizeFieldName(key))) {
      throw new ProtectedContentError(`raw data integrity content field is not allowed at ${path}.${key}`);
    }
    assertNoRawDataIntegrityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawDataIntegrityContent(input ?? {});
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

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function basisPoints(numerator, denominator) {
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
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

function evaluateIntegrityPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'policy_hash_invalid');
  addReason(reasons, hlcTuple(policy?.reviewedAtHlc) === null, 'policy_review_time_invalid');
  addReason(reasons, !Number.isSafeInteger(policy?.maxRecordLagMs) || policy.maxRecordLagMs < 1, 'policy_record_lag_invalid');
  addReason(reasons, policy?.metadataOnly !== true, 'policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'policy_protected_boundary_invalid');
  addReason(reasons, policy?.phiPiiExcludedFromReceipts !== true, 'policy_phi_pii_boundary_invalid');

  const configuredFamilies = new Set(sortedTextList(policy?.requiredRecordFamilies));
  for (const family of REQUIRED_RECORD_FAMILIES) {
    addReason(reasons, !configuredFamilies.has(family), `policy_required_family_missing:${family}`);
  }

  const configuredDimensions = new Set(sortedTextList(policy?.requiredAlcoacDimensions));
  for (const dimension of REQUIRED_ALCOAC_DIMENSIONS) {
    addReason(reasons, !configuredDimensions.has(dimension), `policy_alcoac_dimension_missing:${dimension}`);
  }
}

function evaluateRecordSetShape(recordSet, reasons) {
  const openedAt = hlcTuple(recordSet?.openedAtHlc);
  const reviewedAt = hlcTuple(recordSet?.reviewedAtHlc);
  const closedAt = hlcTuple(recordSet?.closedAtHlc);

  addReason(reasons, !hasText(recordSet?.recordSetRef), 'record_set_ref_absent');
  addReason(reasons, !hasText(recordSet?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(recordSet?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(recordSet?.sponsorRef), 'sponsor_ref_absent');
  addReason(reasons, !hasText(recordSet?.sourceSystemRef), 'source_system_ref_absent');
  addReason(reasons, recordSet?.status !== 'validated', 'record_set_not_validated');
  addReason(reasons, !Number.isSafeInteger(recordSet?.version) || recordSet.version < 1, 'record_set_version_invalid');
  addReason(reasons, openedAt === null, 'record_set_open_time_invalid');
  addReason(reasons, reviewedAt === null, 'record_set_review_time_invalid');
  addReason(reasons, closedAt === null, 'record_set_close_time_invalid');
  addReason(reasons, openedAt !== null && reviewedAt !== null && compareHlc(reviewedAt, openedAt) <= 0, 'record_set_review_not_after_open');
  addReason(reasons, reviewedAt !== null && closedAt !== null && compareHlc(closedAt, reviewedAt) <= 0, 'record_set_close_not_after_review');
}

function normalizeAlcoacControls(recordSet, reasons) {
  const controls = Array.isArray(recordSet?.alcoacControls) ? recordSet.alcoacControls : [];
  const byDimension = new Map();
  for (const control of controls) {
    if (hasText(control?.dimension)) {
      byDimension.set(control.dimension, control);
    }
  }

  const covered = [];
  for (const dimension of REQUIRED_ALCOAC_DIMENSIONS) {
    const control = byDimension.get(dimension);
    if (control === undefined) {
      reasons.push(`alcoac_dimension_missing:${dimension}`);
      continue;
    }
    addReason(reasons, !VERIFIED_CONTROL_STATUSES.has(control.status), `alcoac_dimension_unverified:${dimension}`);
    addReason(reasons, !isDigest(control.evidenceHash), `alcoac_dimension_evidence_invalid:${dimension}`);
    addReason(reasons, !hasText(control.controlRef), `alcoac_control_ref_absent:${dimension}`);
    addReason(reasons, hlcTuple(control.reviewedAtHlc) === null, `alcoac_review_time_invalid:${dimension}`);
    if (VERIFIED_CONTROL_STATUSES.has(control.status) && isDigest(control.evidenceHash) && hasText(control.controlRef)) {
      covered.push({
        controlRef: control.controlRef,
        dimension,
        evidenceHash: control.evidenceHash,
        reviewedAtHlc: control.reviewedAtHlc,
        status: control.status,
      });
    }
  }

  return covered.sort((left, right) => left.dimension.localeCompare(right.dimension));
}

function recordLagExceeded(record, maxRecordLagMs) {
  const observedAt = hlcTuple(record?.observedAtHlc);
  const recordedAt = hlcTuple(record?.recordedAtHlc);
  if (observedAt === null || recordedAt === null || compareHlc(recordedAt, observedAt) < 0) {
    return false;
  }
  return recordedAt[0] - observedAt[0] > BigInt(maxRecordLagMs);
}

function evaluateRecord(row, maxRecordLagMs, reasons) {
  const family = hasText(row?.recordFamily) ? row.recordFamily : 'unknown';
  const observedAt = hlcTuple(row?.observedAtHlc);
  const recordedAt = hlcTuple(row?.recordedAtHlc);
  const changed = isDigest(row?.originalRecordHash) && isDigest(row?.currentRecordHash) && row.originalRecordHash !== row.currentRecordHash;

  addReason(reasons, !REQUIRED_RECORD_FAMILIES.includes(family), `record_family_unsupported:${family}`);
  addReason(reasons, !hasText(row?.recordRef), `record_ref_absent:${family}`);
  addReason(reasons, !VERIFIED_RECORD_STATUSES.has(row?.recordStatus), `record_status_not_complete:${family}`);
  addReason(reasons, !VERIFIED_REVIEW_STATUSES.has(row?.reviewStatus), `record_review_not_verified:${family}`);
  addReason(reasons, !hasText(row?.attributableActorDid), `record_attributable_actor_absent:${family}`);
  addReason(reasons, !isDigest(row?.sourceTraceabilityHash), `record_source_traceability_invalid:${family}`);
  addReason(reasons, !isDigest(row?.originalRecordHash), `record_original_hash_invalid:${family}`);
  addReason(reasons, !isDigest(row?.currentRecordHash), `record_current_hash_invalid:${family}`);
  addReason(reasons, !isDigest(row?.originalEvidenceHash), `record_original_evidence_invalid:${family}`);
  addReason(reasons, !isDigest(row?.accuracyEvidenceHash), `record_accuracy_evidence_invalid:${family}`);
  addReason(reasons, !isDigest(row?.legibilityEvidenceHash), `record_legibility_evidence_invalid:${family}`);
  addReason(reasons, !isDigest(row?.completenessEvidenceHash), `record_completeness_evidence_invalid:${family}`);
  addReason(reasons, !isDigest(row?.versionHistoryHash), `record_version_history_invalid:${family}`);
  addReason(reasons, !isDigest(row?.auditEntryHash), `record_audit_entry_invalid:${family}`);
  addReason(reasons, observedAt === null, `record_observed_time_invalid:${family}`);
  addReason(reasons, recordedAt === null, `recorded_time_invalid:${family}`);
  addReason(reasons, observedAt !== null && recordedAt !== null && compareHlc(recordedAt, observedAt) < 0, `record_observed_time_after_recorded:${family}`);
  addReason(reasons, recordLagExceeded(row, maxRecordLagMs), `record_contemporaneous_lag_exceeded:${family}`);
  addReason(reasons, changed && !hasText(row?.correctionRef), `record_correction_ref_missing:${family}`);
  addReason(reasons, row?.participantCodeBoundaryPreserved !== true, `record_participant_boundary_invalid:${family}`);
  addReason(reasons, row?.metadataOnly !== true, `record_metadata_boundary_invalid:${family}`);
  addReason(reasons, row?.protectedContentExcluded !== true, `record_protected_boundary_invalid:${family}`);
}

function normalizeRecords(recordSet, maxRecordLagMs, reasons) {
  const records = Array.isArray(recordSet?.records) ? recordSet.records : [];
  const byFamily = new Map();
  for (const record of records) {
    if (hasText(record?.recordFamily) && !byFamily.has(record.recordFamily)) {
      byFamily.set(record.recordFamily, record);
    }
    evaluateRecord(record, Number.isSafeInteger(maxRecordLagMs) ? maxRecordLagMs : 0, reasons);
  }

  const normalized = [];
  for (const family of REQUIRED_RECORD_FAMILIES) {
    const record = byFamily.get(family);
    if (record === undefined) {
      reasons.push(`record_family_missing:${family}`);
      continue;
    }
    normalized.push({
      accuracyEvidenceHash: record.accuracyEvidenceHash,
      auditEntryHash: record.auditEntryHash,
      attributableActorDid: record.attributableActorDid,
      completenessEvidenceHash: record.completenessEvidenceHash,
      correctionRef: record.correctionRef ?? null,
      currentRecordHash: record.currentRecordHash,
      legibilityEvidenceHash: record.legibilityEvidenceHash,
      observedAtHlc: record.observedAtHlc,
      originalEvidenceHash: record.originalEvidenceHash,
      originalRecordHash: record.originalRecordHash,
      participantCodeBoundaryPreserved: record.participantCodeBoundaryPreserved,
      protectedContentExcluded: record.protectedContentExcluded,
      recordFamily: family,
      recordedAtHlc: record.recordedAtHlc,
      recordRef: record.recordRef,
      recordStatus: record.recordStatus,
      reviewStatus: record.reviewStatus,
      sourceTraceabilityHash: record.sourceTraceabilityHash,
      versionHistoryHash: record.versionHistoryHash,
    });
  }

  return normalized.sort((left, right) => left.recordFamily.localeCompare(right.recordFamily));
}

function normalizeCorrectionLedger(recordSet, records, reasons) {
  const corrections = Array.isArray(recordSet?.correctionLedger) ? recordSet.correctionLedger : [];
  const byRef = new Map();
  const normalized = [];

  for (const correction of corrections) {
    const correctionRef = hasText(correction?.correctionRef) ? correction.correctionRef : 'unknown';
    const correctedAt = hlcTuple(correction?.correctionAtHlc);
    const approvedAt = hlcTuple(correction?.approvedAtHlc);
    byRef.set(correctionRef, correction);

    addReason(reasons, !hasText(correction?.correctionRef), 'correction_ref_absent');
    addReason(reasons, !hasText(correction?.recordRef), `correction_record_ref_absent:${correctionRef}`);
    addReason(reasons, !APPROVED_CORRECTION_STATUSES.has(correction?.status), `correction_not_approved:${correctionRef}`);
    addReason(reasons, !hasText(correction?.reasonCode), `correction_reason_absent:${correctionRef}`);
    addReason(reasons, !isDigest(correction?.originalRecordHash), `correction_original_hash_invalid:${correctionRef}`);
    addReason(reasons, !isDigest(correction?.correctedRecordHash), `correction_corrected_hash_invalid:${correctionRef}`);
    addReason(reasons, !isDigest(correction?.priorAuditHash), `correction_prior_audit_invalid:${correctionRef}`);
    addReason(reasons, !isDigest(correction?.currentAuditHash), `correction_current_audit_invalid:${correctionRef}`);
    addReason(reasons, correctedAt === null, `correction_time_invalid:${correctionRef}`);
    addReason(reasons, approvedAt === null, `correction_approval_time_invalid:${correctionRef}`);
    addReason(reasons, approvedAt !== null && correctedAt !== null && compareHlc(approvedAt, correctedAt) <= 0, `correction_approval_not_after_correction:${correctionRef}`);
    addReason(reasons, !hasText(correction?.approvedByDid), `correction_approver_absent:${correctionRef}`);
    addReason(reasons, !isDigest(correction?.rationaleHash), `correction_rationale_invalid:${correctionRef}`);
    addReason(reasons, correction?.originalContentPreserved !== true, `correction_original_content_not_preserved:${correctionRef}`);
    addReason(reasons, correction?.metadataOnly !== true, `correction_metadata_boundary_invalid:${correctionRef}`);
    addReason(reasons, correction?.protectedContentExcluded !== true, `correction_protected_boundary_invalid:${correctionRef}`);

    normalized.push({
      approvedAtHlc: correction?.approvedAtHlc ?? null,
      approvedByDid: correction?.approvedByDid ?? null,
      correctedRecordHash: correction?.correctedRecordHash ?? null,
      correctionAtHlc: correction?.correctionAtHlc ?? null,
      correctionRef,
      currentAuditHash: correction?.currentAuditHash ?? null,
      originalContentPreserved: correction?.originalContentPreserved === true,
      originalRecordHash: correction?.originalRecordHash ?? null,
      priorAuditHash: correction?.priorAuditHash ?? null,
      rationaleHash: correction?.rationaleHash ?? null,
      reasonCode: correction?.reasonCode ?? null,
      recordRef: correction?.recordRef ?? null,
      status: correction?.status ?? null,
    });
  }

  let linkedChangedRecords = 0;
  for (const record of records) {
    if (record.originalRecordHash === record.currentRecordHash) {
      continue;
    }
    if (!hasText(record.correctionRef)) {
      continue;
    }
    const correction = byRef.get(record.correctionRef);
    if (correction === undefined) {
      reasons.push(`record_correction_missing:${record.correctionRef}`);
      continue;
    }
    addReason(reasons, correction.recordRef !== record.recordRef, `record_correction_record_mismatch:${record.recordFamily}`);
    addReason(reasons, correction.originalRecordHash !== record.originalRecordHash, `record_correction_original_hash_mismatch:${record.recordFamily}`);
    addReason(reasons, correction.correctedRecordHash !== record.currentRecordHash, `record_correction_current_hash_mismatch:${record.recordFamily}`);
    if (APPROVED_CORRECTION_STATUSES.has(correction.status)) {
      linkedChangedRecords += 1;
    }
  }

  return {
    corrections: normalized.sort((left, right) => left.correctionRef.localeCompare(right.correctionRef)),
    summary: {
      totalCorrections: corrections.length,
      approvedCorrections: corrections.filter((correction) => APPROVED_CORRECTION_STATUSES.has(correction.status)).length,
      linkedChangedRecords,
    },
  };
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  const forum = review?.decisionForum;

  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.reviewDecision), 'human_review_decision_invalid');
  addReason(reasons, review?.reviewDecision !== 'data_integrity_ready', 'human_review_not_ready');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, input?.recordSet?.closedAtHlc), 'human_review_not_after_record_set_close');
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

function buildRecordSetHash(input, records, alcoacControls, correctionLedger) {
  return sha256Hex({
    alcoacControls,
    authorityChainHash: input.authority.authorityChainHash,
    correctionLedger,
    integrityPolicy: {
      maxRecordLagMs: input.integrityPolicy.maxRecordLagMs,
      policyHash: input.integrityPolicy.policyHash,
      policyRef: input.integrityPolicy.policyRef,
      requiredAlcoacDimensions: sortedTextList(input.integrityPolicy.requiredAlcoacDimensions),
      requiredRecordFamilies: sortedTextList(input.integrityPolicy.requiredRecordFamilies),
    },
    recordSet: {
      closedAtHlc: input.recordSet.closedAtHlc,
      protocolRef: input.recordSet.protocolRef,
      recordSetRef: input.recordSet.recordSetRef,
      reviewedAtHlc: input.recordSet.reviewedAtHlc,
      siteRef: input.recordSet.siteRef,
      sourceSystemRef: input.recordSet.sourceSystemRef,
      sponsorRef: input.recordSet.sponsorRef,
      status: input.recordSet.status,
      version: input.recordSet.version,
    },
    records,
    schema: 'cybermedica.data_integrity_record_set_hash.v1',
    tenantId: input.tenantId,
  });
}

function buildDataIntegrityRecordSet(input, records, alcoacControls, correctionSummary, recordSetHash, receipt) {
  const coveredRecordFamilies = records.map((record) => record.recordFamily);
  const coveredAlcoacDimensions = alcoacControls.map((control) => control.dimension);
  const completeRecordCount = records.filter(
    (record) => record.recordStatus === 'complete' && VERIFIED_REVIEW_STATUSES.has(record.reviewStatus),
  ).length;

  return {
    schema: 'cybermedica.data_integrity_record_set.v1',
    dataIntegrityRecordSetId: `cmdir_${sha256Hex({
      recordSetHash,
      recordSetRef: input.recordSet.recordSetRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    recordSetHash,
    tenantId: input.tenantId,
    recordSetRef: input.recordSet.recordSetRef,
    protocolRef: input.recordSet.protocolRef,
    siteRef: input.recordSet.siteRef,
    sponsorRef: input.recordSet.sponsorRef,
    version: input.recordSet.version,
    integrityStatus: 'ready',
    coveredRecordFamilies,
    coveredAlcoacDimensions,
    recordFamilyCoverageBasisPoints: basisPoints(coveredRecordFamilies.length, REQUIRED_RECORD_FAMILIES.length),
    alcoacCoverageBasisPoints: basisPoints(coveredAlcoacDimensions.length, REQUIRED_ALCOAC_DIMENSIONS.length),
    recordCompletenessBasisPoints: basisPoints(completeRecordCount, REQUIRED_RECORD_FAMILIES.length),
    correctionSummary,
    violationSummary: {
      blockingDefects: 0,
    },
    policyRef: input.integrityPolicy.policyRef,
    authorityChainHash: input.authority.authorityChainHash,
    decisionForumReceiptId: input.humanReview.decisionForum.workflowReceiptId,
    receiptId: receipt.receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function deniedDataIntegrityRecordSet(reasons) {
  return {
    schema: 'cybermedica.data_integrity_record_set_decision.v1',
    decision: 'denied',
    failClosed: true,
    reasons,
    recordSet: {
      schema: 'cybermedica.data_integrity_record_set.v1',
      integrityStatus: 'blocked',
      trustState: 'inactive',
      exochainProductionClaim: false,
    },
    receipt: null,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export function evaluateDataIntegrityRecordSet(input) {
  const reasons = [];
  assertMetadataOnly(input);
  evaluateTenantActorAuthority(input, reasons);
  evaluateIntegrityPolicy(input?.integrityPolicy, reasons);
  evaluateRecordSetShape(input?.recordSet, reasons);
  const alcoacControls = normalizeAlcoacControls(input?.recordSet, reasons);
  const records = normalizeRecords(input?.recordSet, input?.integrityPolicy?.maxRecordLagMs, reasons);
  const correctionLedger = normalizeCorrectionLedger(input?.recordSet, records, reasons);
  evaluateHumanReview(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return deniedDataIntegrityRecordSet(uniqueReasons);
  }

  const recordSetHash = buildRecordSetHash(input, records, alcoacControls, correctionLedger.corrections);
  const receipt = createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'data_integrity_record_set',
    artifactVersion: `${input.recordSet.recordSetRef}@v${input.recordSet.version}`,
    artifactHash: recordSetHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.recordSet.closedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['alcoac', 'data_integrity', 'metadata_only', 'nfr_004'],
    sourceSystem: 'cybermedica-qms',
  });

  return {
    schema: 'cybermedica.data_integrity_record_set_decision.v1',
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    recordSet: buildDataIntegrityRecordSet(
      input,
      records,
      alcoacControls,
      correctionLedger.summary,
      recordSetHash,
      receipt,
    ),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
