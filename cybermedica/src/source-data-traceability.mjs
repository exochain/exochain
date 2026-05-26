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
const REQUIRED_PERMISSION = 'manage_source_data_traceability';
const SOURCE_DATA_SCHEMA = 'cybermedica.source_data_traceability.v1';
const DECISION_SCHEMA = 'cybermedica.source_data_traceability_decision.v1';

const REQUIRED_SOURCE_FAMILIES = Object.freeze([
  'consent_source',
  'device_output',
  'ecrf_entry',
  'imaging_report',
  'lab_result',
  'participant_reported_outcome',
  'product_accountability_source',
  'query_response',
  'safety_source',
  'source_worksheet',
]);

const REQUIRED_TRACEABILITY_DOMAINS = Object.freeze([
  'alcoac_evidence',
  'attributable_capture',
  'correction_audit',
  'crf_requirement_mapping',
  'discrepancy_management',
  'export_eligibility',
  'monitor_review',
  'participant_code_boundary',
  'retention_access',
  'source_to_crf_reconciliation',
]);

const VERIFIED_DOMAIN_STATUSES = new Set(['verified', 'validated']);
const VERIFIED_MAPPING_STATUSES = new Set(['verified', 'validated']);
const CLOSED_DISCREPANCY_STATUSES = new Set(['closed', 'none', 'resolved']);
const REVIEW_DECISIONS = new Set(['hold_source_data_gap', 'source_data_traceable']);

const RAW_SOURCE_DATA_FIELDS = new Set([
  'crfvalue',
  'directidentifier',
  'medicalrecordnumber',
  'participantidentifier',
  'participantname',
  'patientname',
  'rawcrf',
  'rawcrfdata',
  'rawcrffield',
  'rawcrfvalue',
  'rawpayload',
  'rawsource',
  'rawsourcedata',
  'rawsourcedocument',
  'rawsourcedocumenttext',
  'sourcebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'subjectidentifier',
]);

const SECRET_SOURCE_DATA_FIELDS = new Set([
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

function assertNoRawSourceDataContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawSourceDataContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_SOURCE_DATA_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw source data content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_SOURCE_DATA_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`source data secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawSourceDataContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawSourceDataContent(input ?? {});
  canonicalize(input ?? {});
}

function sortedTextList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(hasText))].sort() : [];
}

function basisPoints(numerator, denominator) {
  if (!Number.isSafeInteger(denominator) || denominator < 1) {
    return 0;
  }
  return Number((BigInt(numerator) * 10_000n) / BigInt(denominator));
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
    'source_data_traceability_authority_missing',
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

function evaluateTraceabilityPlan(plan, reasons) {
  addReason(reasons, plan === null || plan === undefined, 'traceability_plan_absent');
  addReason(reasons, !hasText(plan?.planRef), 'traceability_plan_ref_absent');
  addReason(reasons, !hasText(plan?.protocolRef), 'protocol_ref_absent');
  addReason(reasons, !hasText(plan?.siteRef), 'site_ref_absent');
  addReason(reasons, !hasText(plan?.studyRef), 'study_ref_absent');
  addReason(reasons, !hasText(plan?.activeProtocolVersionRef), 'active_protocol_version_ref_absent');
  addReason(reasons, !hasText(plan?.crfMediaRef), 'crf_media_ref_absent');
  addReason(reasons, !hasText(plan?.ecrfSystemValidationRef), 'ecrf_system_validation_ref_absent');
  addReason(reasons, !isDigest(plan?.sourceWorksheetTemplateHash), 'source_worksheet_template_hash_invalid');
  addReason(reasons, !isDigest(plan?.crfCompletionGuidelineHash), 'crf_completion_guideline_hash_invalid');
  addReason(reasons, !isDigest(plan?.discrepancyProcedureHash), 'discrepancy_procedure_hash_invalid');
  addReason(reasons, !isDigest(plan?.retentionPolicyHash), 'retention_policy_hash_invalid');
  addReason(reasons, hlcTuple(plan?.reviewedAtHlc) === null, 'traceability_plan_review_time_invalid');
  addReason(reasons, plan?.metadataOnly !== true, 'traceability_plan_metadata_boundary_invalid');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'traceability_plan_protected_boundary_invalid');
  addReason(reasons, plan?.productionTrustClaim === true, 'production_trust_claim_forbidden');

  evaluateRequiredSet(
    sortedTextList(plan?.requiredSourceFamilies),
    REQUIRED_SOURCE_FAMILIES,
    'required_source_family_missing',
    'required_source_family_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    sortedTextList(plan?.requiredTraceabilityDomains),
    REQUIRED_TRACEABILITY_DOMAINS,
    'required_traceability_domain_missing',
    'required_traceability_domain_unsupported',
    reasons,
  );
}

function normalizeSourceRecords(input, reasons) {
  const rows = Array.isArray(input?.sourceRecords) ? input.sourceRecords : [];
  const byFamily = new Map();

  for (const row of rows) {
    const family = hasText(row?.sourceFamily) ? row.sourceFamily : 'unknown';
    addReason(reasons, !REQUIRED_SOURCE_FAMILIES.includes(family), `source_family_unsupported:${family}`);
    addReason(reasons, byFamily.has(family), `source_family_duplicate:${family}`);
    addReason(reasons, !hasText(row?.sourceRecordRef), `source_record_ref_absent:${family}`);
    addReason(reasons, !isDigest(row?.participantCodeHash), `source_record_participant_code_hash_invalid:${family}`);
    addReason(reasons, !isDigest(row?.sourceRecordHash), `source_record_hash_invalid:${family}`);
    addReason(reasons, !isDigest(row?.sourceEvidenceHash), `source_evidence_hash_invalid:${family}`);
    addReason(reasons, hlcTuple(row?.capturedAtHlc) === null, `source_record_capture_time_invalid:${family}`);
    addReason(reasons, hlcTuple(row?.recordedAtHlc) === null, `source_record_record_time_invalid:${family}`);
    addReason(reasons, hlcBefore(row?.recordedAtHlc, row?.capturedAtHlc), `source_record_recorded_before_capture:${family}`);
    addReason(reasons, !hasText(row?.attributableActorDid), `source_record_actor_absent:${family}`);
    addReason(reasons, !hasText(row?.consentRef), `source_record_consent_ref_absent:${family}`);
    addReason(reasons, !hasText(row?.sourceSystemRef), `source_system_ref_absent:${family}`);
    addReason(
      reasons,
      row?.participantIdentifiersSuppressed !== true,
      `source_record_participant_boundary_invalid:${family}`,
    );
    addReason(reasons, row?.metadataOnly !== true, `source_record_metadata_boundary_invalid:${family}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `source_record_protected_boundary_invalid:${family}`);

    if (REQUIRED_SOURCE_FAMILIES.includes(family) && !byFamily.has(family)) {
      byFamily.set(family, {
        attributableActorDid: row.attributableActorDid,
        capturedAtHlc: row.capturedAtHlc,
        consentRef: row.consentRef,
        participantCodeHash: row.participantCodeHash,
        recordedAtHlc: row.recordedAtHlc,
        sourceEvidenceHash: row.sourceEvidenceHash,
        sourceFamily: family,
        sourceRecordHash: row.sourceRecordHash,
        sourceRecordRef: row.sourceRecordRef,
        sourceSystemRef: row.sourceSystemRef,
      });
    }
  }

  for (const family of REQUIRED_SOURCE_FAMILIES) {
    addReason(reasons, !byFamily.has(family), `source_family_record_missing:${family}`);
  }

  return [...byFamily.values()].sort((left, right) => left.sourceFamily.localeCompare(right.sourceFamily));
}

function sourceRecordByFamily(sourceRecords) {
  return new Map(sourceRecords.map((record) => [record.sourceFamily, record]));
}

function normalizeCrfMappings(input, sourceRecords, reasons) {
  const rows = Array.isArray(input?.crfMappings) ? input.crfMappings : [];
  const sources = sourceRecordByFamily(sourceRecords);
  const byFamily = new Map();

  for (const row of rows) {
    const family = hasText(row?.sourceFamily) ? row.sourceFamily : 'unknown';
    const sourceRecord = sources.get(family);
    addReason(reasons, !REQUIRED_SOURCE_FAMILIES.includes(family), `crf_mapping_source_family_unsupported:${family}`);
    addReason(reasons, byFamily.has(family), `crf_mapping_duplicate:${family}`);
    addReason(reasons, !hasText(row?.sourceRecordRef), `crf_mapping_source_record_ref_absent:${family}`);
    addReason(reasons, !hasText(row?.crfFieldRef), `crf_field_ref_absent:${family}`);
    addReason(reasons, !hasText(row?.crfRequirementRef), `crf_requirement_ref_absent:${family}`);
    addReason(reasons, !isDigest(row?.sourceRecordHash), `crf_mapping_source_hash_invalid:${family}`);
    addReason(reasons, !isDigest(row?.crfValueHash), `crf_value_hash_invalid:${family}`);
    addReason(reasons, !VERIFIED_MAPPING_STATUSES.has(row?.mappingStatus), `crf_mapping_unverified:${family}`);
    addReason(reasons, !CLOSED_DISCREPANCY_STATUSES.has(row?.discrepancyStatus), `crf_mapping_discrepancy_open:${family}`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `crf_mapping_review_time_invalid:${family}`);
    addReason(reasons, !hasText(row?.reviewerDid), `crf_mapping_reviewer_absent:${family}`);
    addReason(reasons, row?.metadataOnly !== true, `crf_mapping_metadata_boundary_invalid:${family}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `crf_mapping_protected_boundary_invalid:${family}`);
    addReason(
      reasons,
      sourceRecord !== undefined &&
        (row.sourceRecordRef !== sourceRecord.sourceRecordRef || row.sourceRecordHash !== sourceRecord.sourceRecordHash),
      `crf_mapping_source_hash_mismatch:${family}`,
    );

    if (REQUIRED_SOURCE_FAMILIES.includes(family) && !byFamily.has(family)) {
      byFamily.set(family, {
        crfFieldRef: row.crfFieldRef,
        crfRequirementRef: row.crfRequirementRef,
        crfValueHash: row.crfValueHash,
        discrepancyStatus: row.discrepancyStatus,
        mappingStatus: row.mappingStatus,
        queryRef: row.queryRef ?? null,
        reviewedAtHlc: row.reviewedAtHlc,
        reviewerDid: row.reviewerDid,
        sourceFamily: family,
        sourceRecordHash: row.sourceRecordHash,
        sourceRecordRef: row.sourceRecordRef,
      });
    }
  }

  for (const family of REQUIRED_SOURCE_FAMILIES) {
    addReason(reasons, !byFamily.has(family), `crf_mapping_missing:${family}`);
  }

  return [...byFamily.values()].sort((left, right) => left.sourceFamily.localeCompare(right.sourceFamily));
}

function normalizeTraceabilityDomains(controls, reasons) {
  const rows = Array.isArray(controls?.traceabilityDomainEvidence) ? controls.traceabilityDomainEvidence : [];
  const byDomain = new Map();

  for (const row of rows) {
    const domain = hasText(row?.domainRef) ? row.domainRef : 'unknown';
    addReason(reasons, !REQUIRED_TRACEABILITY_DOMAINS.includes(domain), `traceability_domain_unsupported:${domain}`);
    addReason(reasons, byDomain.has(domain), `traceability_domain_duplicate:${domain}`);
    addReason(reasons, !VERIFIED_DOMAIN_STATUSES.has(row?.status), `traceability_domain_unverified:${domain}`);
    addReason(reasons, !isDigest(row?.evidenceHash), `traceability_domain_evidence_invalid:${domain}`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `traceability_domain_review_time_invalid:${domain}`);
    addReason(reasons, row?.metadataOnly !== true, `traceability_domain_metadata_boundary_invalid:${domain}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `traceability_domain_protected_boundary_invalid:${domain}`);
    if (REQUIRED_TRACEABILITY_DOMAINS.includes(domain) && !byDomain.has(domain)) {
      byDomain.set(domain, {
        domainRef: domain,
        evidenceHash: row.evidenceHash,
        reviewedAtHlc: row.reviewedAtHlc,
        status: row.status,
      });
    }
  }

  for (const domain of REQUIRED_TRACEABILITY_DOMAINS) {
    addReason(reasons, !byDomain.has(domain), `traceability_domain_missing:${domain}`);
  }

  return [...byDomain.values()].sort((left, right) => left.domainRef.localeCompare(right.domainRef));
}

function evaluateTraceabilityControls(controls, reasons) {
  addReason(reasons, controls === null || controls === undefined, 'traceability_controls_absent');
  const domains = normalizeTraceabilityDomains(controls, reasons);

  addReason(reasons, !Number.isSafeInteger(controls?.openQueryCount) || controls.openQueryCount < 0, 'open_query_count_invalid');
  addReason(
    reasons,
    !Number.isSafeInteger(controls?.openCriticalQueryCount) || controls.openCriticalQueryCount < 0,
    'open_critical_query_count_invalid',
  );
  addReason(
    reasons,
    !Number.isSafeInteger(controls?.unresolvedDiscrepancyCount) || controls.unresolvedDiscrepancyCount < 0,
    'unresolved_discrepancy_count_invalid',
  );
  addReason(reasons, controls?.openCriticalQueryCount > 0, 'critical_query_open');
  addReason(reasons, controls?.unresolvedDiscrepancyCount > 0, 'unresolved_discrepancy_present');
  addReason(reasons, !isDigest(controls?.correctionLedgerHash), 'correction_ledger_hash_invalid');
  addReason(reasons, controls?.allCorrectionsApproved !== true, 'corrections_not_approved');
  addReason(reasons, !isDigest(controls?.monitorReviewHash), 'monitor_review_hash_invalid');
  addReason(reasons, controls?.monitorReviewComplete !== true, 'monitor_review_incomplete');
  addReason(reasons, !isDigest(controls?.participantCodeBoundaryHash), 'participant_code_boundary_hash_invalid');
  addReason(reasons, !isDigest(controls?.exportEligibilityHash), 'export_eligibility_hash_invalid');
  addReason(reasons, !isDigest(controls?.sourceToCrfReconciliationHash), 'source_to_crf_reconciliation_hash_invalid');
  addReason(reasons, controls?.metadataOnly !== true, 'traceability_controls_metadata_boundary_invalid');
  addReason(reasons, controls?.protectedContentExcluded !== true, 'traceability_controls_protected_boundary_invalid');

  return domains;
}

function evaluateHumanReview(input, reasons) {
  const review = input?.review;
  addReason(reasons, review === null || review === undefined, 'review_absent');
  addReason(reasons, !hasText(review?.humanReviewerDid), 'human_review_absent');
  addReason(reasons, !REVIEW_DECISIONS.has(review?.reviewDecision), 'review_decision_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_final_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !isDigest(review?.evidenceBundleHash), 'review_evidence_bundle_hash_invalid');

  const forum = review?.decisionForum;
  addReason(reasons, forum?.verified !== true, 'decision_forum_not_verified');
  addReason(reasons, forum?.state !== 'approved', 'decision_forum_not_approved');
  addReason(reasons, forum?.humanGate?.verified !== true, 'decision_forum_human_gate_unverified');
  addReason(reasons, forum?.quorum?.status !== 'met', 'decision_forum_quorum_not_met');
  addReason(reasons, forum?.openChallenge === true, 'decision_forum_open_challenge');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_decision_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_workflow_receipt_absent');
}

function deniedSourceDataTraceability(input, reasons) {
  return {
    schema: DECISION_SCHEMA,
    decision: 'denied',
    failClosed: true,
    reasons,
    sourceDataTraceability: {
      schema: SOURCE_DATA_SCHEMA,
      traceabilityStatus: 'blocked',
      openQueryCount: Number.isSafeInteger(input?.traceabilityControls?.openQueryCount)
        ? input.traceabilityControls.openQueryCount
        : 0,
      openCriticalQueryCount: Number.isSafeInteger(input?.traceabilityControls?.openCriticalQueryCount)
        ? input.traceabilityControls.openCriticalQueryCount
        : 0,
      unresolvedDiscrepancyCount: Number.isSafeInteger(input?.traceabilityControls?.unresolvedDiscrepancyCount)
        ? input.traceabilityControls.unresolvedDiscrepancyCount
        : 0,
      trustState: 'inactive',
      exochainProductionClaim: false,
    },
    receipt: null,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

function buildTraceabilityHash(input, sourceRecords, crfMappings, traceabilityDomains) {
  return sha256Hex({
    crfMappings,
    planRef: input.traceabilityPlan.planRef,
    protocolRef: input.traceabilityPlan.protocolRef,
    sourceRecords,
    tenantId: input.tenantId,
    traceabilityControls: {
      correctionLedgerHash: input.traceabilityControls.correctionLedgerHash,
      exportEligibilityHash: input.traceabilityControls.exportEligibilityHash,
      monitorReviewHash: input.traceabilityControls.monitorReviewHash,
      participantCodeBoundaryHash: input.traceabilityControls.participantCodeBoundaryHash,
      sourceToCrfReconciliationHash: input.traceabilityControls.sourceToCrfReconciliationHash,
    },
    traceabilityDomains,
  });
}

function buildSourceDataTraceability(input, sourceRecords, crfMappings, traceabilityDomains, traceabilityHash, receipt) {
  const sourceFamiliesCovered = sourceRecords.map((record) => record.sourceFamily).sort();
  const mappedFamilies = crfMappings
    .filter((mapping) => VERIFIED_MAPPING_STATUSES.has(mapping.mappingStatus))
    .map((mapping) => mapping.sourceFamily)
    .sort();
  const traceabilityDomainsCovered = traceabilityDomains
    .filter((domain) => VERIFIED_DOMAIN_STATUSES.has(domain.status))
    .map((domain) => domain.domainRef)
    .sort();

  return {
    schema: SOURCE_DATA_SCHEMA,
    traceabilityId: `cmsdt_${sha256Hex({
      planRef: input.traceabilityPlan.planRef,
      tenantId: input.tenantId,
      traceabilityHash,
    }).slice(0, 32)}`,
    traceabilityHash,
    tenantId: input.tenantId,
    siteRef: input.traceabilityPlan.siteRef,
    protocolRef: input.traceabilityPlan.protocolRef,
    studyRef: input.traceabilityPlan.studyRef,
    activeProtocolVersionRef: input.traceabilityPlan.activeProtocolVersionRef,
    sourceFamiliesCovered,
    traceabilityDomainsCovered,
    sourceRecordCount: sourceRecords.length,
    crfMappingCount: crfMappings.length,
    sourceFamilyCoverageBasisPoints: basisPoints(sourceFamiliesCovered.length, REQUIRED_SOURCE_FAMILIES.length),
    crfMappingCoverageBasisPoints: basisPoints(mappedFamilies.length, REQUIRED_SOURCE_FAMILIES.length),
    traceabilityDomainCoverageBasisPoints: basisPoints(
      traceabilityDomainsCovered.length,
      REQUIRED_TRACEABILITY_DOMAINS.length,
    ),
    openQueryCount: input.traceabilityControls.openQueryCount,
    openCriticalQueryCount: input.traceabilityControls.openCriticalQueryCount,
    unresolvedDiscrepancyCount: input.traceabilityControls.unresolvedDiscrepancyCount,
    reconciliationStatus: 'complete',
    traceabilityStatus: 'traceable',
    monitorReviewStatus: 'complete',
    correctionStatus: 'approved',
    decisionForumReceiptId: input.review.decisionForum.workflowReceiptId,
    receiptId: receipt.receiptId,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
  };
}

export function evaluateSourceDataTraceability(input) {
  assertMetadataOnly(input ?? {});

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateTraceabilityPlan(input?.traceabilityPlan, reasons);
  const sourceRecords = normalizeSourceRecords(input, reasons);
  const crfMappings = normalizeCrfMappings(input, sourceRecords, reasons);
  const traceabilityDomains = evaluateTraceabilityControls(input?.traceabilityControls, reasons);
  evaluateHumanReview(input, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const uniqueReasons = uniqueSorted(reasons);
  if (uniqueReasons.length > 0) {
    return deniedSourceDataTraceability(input, uniqueReasons);
  }

  const traceabilityHash = buildTraceabilityHash(input, sourceRecords, crfMappings, traceabilityDomains);
  const receipt = createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'source_data_traceability',
    artifactVersion: `${input.traceabilityPlan.planRef}@${input.traceabilityPlan.activeProtocolVersionRef}`,
    artifactHash: traceabilityHash,
    classification: 'metadata_only_source_data_traceability',
    hlcTimestamp: input.review.reviewedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: ['alcoac', 'crf_reconciliation', 'metadata_only', 'source_data'],
    sourceSystem: 'cybermedica-qms',
  });

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    sourceDataTraceability: buildSourceDataTraceability(
      input,
      sourceRecords,
      crfMappings,
      traceabilityDomains,
      traceabilityHash,
      receipt,
    ),
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}

export const sourceDataTraceabilityRequirements = Object.freeze({
  schema: SOURCE_DATA_SCHEMA,
  requiredPermission: REQUIRED_PERMISSION,
  requiredSourceFamilies: REQUIRED_SOURCE_FAMILIES,
  requiredTraceabilityDomains: REQUIRED_TRACEABILITY_DOMAINS,
  productionTrustState: 'inactive',
});
