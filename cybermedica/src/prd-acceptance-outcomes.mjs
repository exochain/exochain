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
const ACCEPTANCE_SCHEMA = 'cybermedica.prd_acceptance_outcome_matrix.v1';
const DECISION_SCHEMA = 'cybermedica.prd_acceptance_outcome_decision.v1';
const REQUIRED_PERMISSION = 'prd_acceptance_review';

const REQUIRED_DOCTRINE_LAYERS = Object.freeze([
  'ground_truth',
  'doctrine',
  'domain',
  'data',
  'doors',
  'documentation',
  'deployment',
  'drift',
]);

const REQUIRED_ACCEPTANCE_OUTCOME_IDS = Object.freeze([
  'ai_control_findings_reviewed',
  'all_material_actions_auditable',
  'audit_logs_hash_chained',
  'audits_assessments_locked',
  'capa_effectiveness_managed',
  'consent_authority_receipts_generated',
  'consent_process_documented',
  'consent_versions_controlled',
  'control_library_managed',
  'decision_receipts_generated',
  'delegation_lifecycle_governed',
  'deviation_lifecycle_closed',
  'diligence_packets_controlled',
  'emergency_actions_retrospective_reviewed',
  'enrollment_gate_authorized',
  'evidence_chain_of_custody_maintained',
  'evidence_lifecycle_governed',
  'evidence_receipts_generated',
  'facility_equipment_readiness_tracked',
  'human_review_decisions_governed',
  'kpi_decision_use_governed',
  'product_accountability_maintained',
  'protected_exports_excluded',
  'protocol_feasibility_assessed',
  'qms_passport_maintained',
  'safety_event_workflows_tracked',
  'self_assessment_completed',
  'startup_risk_approved',
  'training_blocks_delegation',
  'trial_launch_gate_authorized',
]);

const REQUIRED_CONTEXT_DOC_REFS = Object.freeze([
  'cybermedica_2_0_sandy_seven_layer_master_prd.md#acceptance-criteria',
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
]);

const POLICY_STATUSES = new Set(['active']);
const ACCEPTANCE_STATUSES = new Set(['supported_inactive_trust']);
const HUMAN_REVIEW_DECISIONS = new Set(['prd_acceptance_accepted_inactive_trust', 'hold_for_acceptance_gap']);
const REQUIRED_MODULE_REFS_BY_OUTCOME = Object.freeze({
  audits_assessments_locked: Object.freeze([
    'src/internal-audits.mjs',
    'src/monitoring-visits.mjs',
    'src/site-self-assessments.mjs',
  ]),
  trial_launch_gate_authorized: Object.freeze([
    'src/clinical-trial-product-release-authorization.mjs',
    'src/readiness-gates.mjs',
    'src/risk-assessments.mjs',
  ]),
});
const REQUIRED_TEST_REFS_BY_OUTCOME = Object.freeze({
  audits_assessments_locked: Object.freeze([
    'tests/internal-audits.test.mjs',
    'tests/monitoring-visits.test.mjs',
    'tests/site-self-assessments.test.mjs',
  ]),
  trial_launch_gate_authorized: Object.freeze([
    'tests/clinical-trial-product-release-authorization.test.mjs',
    'tests/readiness-gates.test.mjs',
    'tests/risk-assessments.test.mjs',
  ]),
});

const RAW_ACCEPTANCE_FIELDS = new Set([
  'acceptancebody',
  'acceptancecopy',
  'acceptancenarrative',
  'body',
  'clinicalnotes',
  'content',
  'freetext',
  'freetextnote',
  'outcometext',
  'participantlisting',
  'prdtext',
  'rawacceptance',
  'rawacceptancecontent',
  'rawacceptancecopy',
  'rawcontext',
  'rawevidence',
  'rawoutcome',
  'rawoutcomeevidence',
  'rawoutcometext',
  'rawsource',
  'rawsourcedata',
  'reviewnotes',
  'sourcedocumentbody',
  'validationlog',
]);

const SECRET_ACCEPTANCE_FIELDS = new Set([
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

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
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

function assertNoRawAcceptanceContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawAcceptanceContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ACCEPTANCE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw PRD acceptance content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ACCEPTANCE_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`PRD acceptance secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawAcceptanceContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawAcceptanceContent(input ?? {});
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_acceptance_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'prd_acceptance_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateAcceptancePolicy(policy, reasons) {
  const requiredOutcomeIds = sortedTextList(policy?.requiredOutcomeIds);
  const requiredDoctrineLayers = sortedTextList(policy?.requiredDoctrineLayers);
  const requiredContextDocRefs = sortedTextList(policy?.requiredContextDocRefs);

  addReason(reasons, !hasText(policy?.policyRef), 'acceptance_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'acceptance_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'acceptance_policy_not_active');
  addReason(reasons, policy?.rootVerificationRequiredForTrustClaims !== true, 'root_verification_gate_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'acceptance_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'acceptance_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'acceptance_policy_time_invalid');

  evaluateRequiredSet(
    requiredOutcomeIds,
    REQUIRED_ACCEPTANCE_OUTCOME_IDS,
    'policy_acceptance_outcome_missing',
    'policy_acceptance_outcome_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredDoctrineLayers,
    REQUIRED_DOCTRINE_LAYERS,
    'policy_doctrine_layer_missing',
    'policy_doctrine_layer_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredContextDocRefs,
    REQUIRED_CONTEXT_DOC_REFS,
    'context_doc_ref_missing',
    'context_doc_ref_unsupported',
    reasons,
  );

  return {
    requiredContextDocRefs:
      requiredContextDocRefs.length > 0 ? requiredContextDocRefs : [...REQUIRED_CONTEXT_DOC_REFS],
    requiredDoctrineLayers:
      requiredDoctrineLayers.length > 0 ? requiredDoctrineLayers : [...REQUIRED_DOCTRINE_LAYERS],
    requiredOutcomeIds: requiredOutcomeIds.length > 0 ? requiredOutcomeIds : [...REQUIRED_ACCEPTANCE_OUTCOME_IDS],
  };
}

function evaluateAcceptanceCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.acceptanceRef), 'acceptance_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'acceptance_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'acceptance_cycle_protected_boundary_invalid');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['matrixCompiledAtHlc', cycle?.matrixCompiledAtHlc],
    ['humanReviewedAtHlc', cycle?.humanReviewedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `acceptance_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'acceptance_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(
      reasons,
      hlcBefore(currentValue, previousValue),
      `acceptance_cycle_${currentLabel}_before_${previousLabel}`,
    );
  }
}

function evidenceHashesFor(row) {
  if (Array.isArray(row?.evidenceHashes)) {
    return uniqueSorted(row.evidenceHashes.filter((hash) => isDigest(hash)));
  }
  return isDigest(row?.evidenceHashes) ? [row.evidenceHashes] : [];
}

function requiredRefsFor(outcomeId, refTable) {
  return Array.isArray(refTable[outcomeId]) ? refTable[outcomeId] : [];
}

function evaluateOutcomeRows(rows, policySummary, cycle, reasons) {
  addReason(reasons, !Array.isArray(rows) || rows.length === 0, 'acceptance_outcome_rows_absent');
  if (!Array.isArray(rows)) {
    return {
      baselineBlockedOutcomeIds: [],
      doctrineLayers: [],
      outcomeIds: [],
      rowSummaries: [],
      supportedOutcomeCount: 0,
      totalOutcomeCount: 0,
    };
  }

  const outcomeIds = sortedTextList(rows.map((row) => row?.outcomeId));
  const doctrineLayers = sortedTextList(rows.map((row) => row?.doctrineLayer));
  const baselineBlockedOutcomeIds = [];
  const rowSummaries = [];
  const seenOutcomeIds = new Set();
  let supportedOutcomeCount = 0;

  evaluateRequiredSet(
    outcomeIds,
    policySummary.requiredOutcomeIds,
    'acceptance_outcome_missing',
    'acceptance_outcome_unsupported',
    reasons,
  );
  for (const layer of policySummary.requiredDoctrineLayers) {
    addReason(reasons, !doctrineLayers.includes(layer), `acceptance_doctrine_layer_missing:${layer}`);
  }

  rows.forEach((row, index) => {
    const label = hasText(row?.outcomeId) ? row.outcomeId : `index_${index}`;
    const moduleRefs = sortedTextList(row?.moduleRefs);
    const testRefs = sortedTextList(row?.testRefs);
    const evidenceHashes = evidenceHashesFor(row);
    const validationCommandRefs = sortedTextList(row?.validationCommandRefs);

    addReason(reasons, !hasText(row?.outcomeId), `acceptance_outcome_id_absent:${label}`);
    addReason(reasons, seenOutcomeIds.has(row?.outcomeId), `acceptance_outcome_duplicate:${label}`);
    if (hasText(row?.outcomeId)) {
      seenOutcomeIds.add(row.outcomeId);
    }
    addReason(
      reasons,
      !policySummary.requiredOutcomeIds.includes(row?.outcomeId),
      `acceptance_outcome_unsupported:${label}`,
    );
    addReason(
      reasons,
      !policySummary.requiredDoctrineLayers.includes(row?.doctrineLayer),
      `acceptance_doctrine_layer_invalid:${label}`,
    );
    addReason(reasons, !hasText(row?.sourceRef), `acceptance_source_ref_absent:${label}`);
    addReason(reasons, !hasText(row?.capabilityRef), `acceptance_capability_ref_absent:${label}`);
    addReason(reasons, !ACCEPTANCE_STATUSES.has(row?.acceptanceStatus), `acceptance_status_invalid:${label}`);
    addReason(reasons, moduleRefs.length === 0, `acceptance_module_refs_absent:${label}`);
    for (const requiredRef of requiredRefsFor(label, REQUIRED_MODULE_REFS_BY_OUTCOME)) {
      addReason(reasons, !moduleRefs.includes(requiredRef), `acceptance_required_module_ref_missing:${label}:${requiredRef}`);
    }
    addReason(reasons, testRefs.length === 0, `acceptance_test_refs_absent:${label}`);
    for (const requiredRef of requiredRefsFor(label, REQUIRED_TEST_REFS_BY_OUTCOME)) {
      addReason(reasons, !testRefs.includes(requiredRef), `acceptance_required_test_ref_missing:${label}:${requiredRef}`);
    }
    addReason(reasons, evidenceHashes.length === 0, `acceptance_evidence_hashes_absent:${label}`);
    addReason(reasons, validationCommandRefs.length === 0, `acceptance_validation_commands_absent:${label}`);
    addReason(reasons, row?.reviewedByHuman !== true, `acceptance_human_review_absent:${label}`);
    addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `acceptance_review_time_invalid:${label}`);
    addReason(reasons, hlcBefore(row?.reviewedAtHlc, cycle?.matrixCompiledAtHlc), `acceptance_review_before_matrix:${label}`);
    addReason(reasons, row?.metadataOnly !== true, `acceptance_metadata_boundary_invalid:${label}`);
    addReason(reasons, row?.protectedContentExcluded !== true, `acceptance_protected_boundary_invalid:${label}`);
    addReason(reasons, row?.productionTrustClaim === true, `acceptance_production_claim_forbidden:${label}`);
    addReason(reasons, row?.blocksBaselineDevelopment === true, `acceptance_blocks_baseline:${label}`);

    if (row?.blocksBaselineDevelopment === true && hasText(row?.outcomeId)) {
      baselineBlockedOutcomeIds.push(row.outcomeId);
    }
    if (row?.acceptanceStatus === 'supported_inactive_trust' && policySummary.requiredOutcomeIds.includes(row?.outcomeId)) {
      supportedOutcomeCount += 1;
    }

    rowSummaries.push({
      acceptanceStatus: row?.acceptanceStatus ?? 'invalid',
      capabilityRef: row?.capabilityRef ?? null,
      doctrineLayer: row?.doctrineLayer ?? null,
      evidenceHashes,
      moduleRefs,
      outcomeId: label,
      sourceRef: row?.sourceRef ?? null,
      testRefs,
      validationCommandRefs,
    });
  });

  return {
    baselineBlockedOutcomeIds: uniqueSorted(baselineBlockedOutcomeIds),
    doctrineLayers,
    outcomeIds,
    rowSummaries: rowSummaries.sort((left, right) => left.outcomeId.localeCompare(right.outcomeId)),
    supportedOutcomeCount,
    totalOutcomeCount: rows.length,
  };
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  addReason(reasons, validation === null || validation === undefined, 'validation_evidence_absent');
  addReason(reasons, sortedTextList(validation?.commandRefs).length === 0, 'validation_command_refs_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, !Number.isSafeInteger(validation?.testCount) || validation.testCount <= 0, 'validation_test_count_invalid');
  addReason(reasons, !isBasisPoints(validation?.coverageLineBasisPoints), 'validation_coverage_invalid');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_absent');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'validation_exochain_read_only_absent');
  addReason(reasons, validation?.docsUpdated !== true, 'validation_docs_update_absent');
  addReason(reasons, !isDigest(validation?.moduleManifestHash), 'validation_module_manifest_hash_invalid');
  addReason(reasons, !isDigest(validation?.testManifestHash), 'validation_test_manifest_hash_invalid');
  addReason(reasons, !isDigest(validation?.evidenceHash), 'validation_evidence_hash_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_time_invalid');
  addReason(reasons, hlcBefore(validation?.recordedAtHlc, cycle?.validationRecordedAtHlc), 'validation_before_cycle_validation_step');
}

function evaluateHumanReview(review, cycle, reasons) {
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_review_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_forbidden');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.humanReviewedAtHlc), 'human_review_before_cycle_review_step');
}

function evaluateAuditRecord(auditRecord, cycle, review, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'acceptance_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'acceptance_audit_record_hash_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'acceptance_audit_record_metadata_boundary_invalid');
  addReason(reasons, auditRecord?.includesProtectedContent === true, 'acceptance_audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'acceptance_audit_record_time_invalid');
  addReason(
    reasons,
    hlcBefore(auditRecord?.receiptRecordedAtHlc, cycle?.auditRecordedAtHlc),
    'acceptance_audit_before_cycle_audit_step',
  );
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, review?.reviewedAtHlc), 'acceptance_audit_before_review');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance?.used !== true) {
    return;
  }
  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, aiAssistance.reviewedByHuman !== true, 'ai_human_review_absent');
  addReason(reasons, !isDigest(aiAssistance.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, sortedTextList(aiAssistance.limitationHashes).filter(isDigest).length === 0, 'ai_limitation_hashes_absent');
}

function buildPrdAcceptanceOutcomes(input, policySummary, outcomeSummary) {
  const acceptanceHash = sha256Hex({
    acceptanceRef: input.acceptanceCycle.acceptanceRef,
    auditRecordHash: input.auditRecord.auditRecordHash,
    humanDecisionHash: input.humanReview.decisionHash,
    outcomeRows: outcomeSummary.rowSummaries,
    tenantId: input.tenantId,
    validationEvidenceHash: input.validationEvidence.evidenceHash,
  });

  return {
    schema: ACCEPTANCE_SCHEMA,
    acceptanceMatrixId: `cmprd_${sha256Hex({
      acceptanceHash,
      acceptanceRef: input.acceptanceCycle.acceptanceRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    releaseCandidateRef: input.acceptanceCycle.releaseCandidateRef,
    trustState: 'inactive',
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    baselineAcceptancePermitted: outcomeSummary.baselineBlockedOutcomeIds.length === 0,
    productionActivationPermitted: false,
    metadataOnly: true,
    containsProtectedContent: false,
    contextDocRefs: policySummary.requiredContextDocRefs,
    doctrineLayersCovered: [...REQUIRED_DOCTRINE_LAYERS],
    outcomeIdsCovered: outcomeSummary.outcomeIds,
    baselineBlockedOutcomeIds: outcomeSummary.baselineBlockedOutcomeIds,
    acceptanceRows: outcomeSummary.rowSummaries,
    acceptanceSummary: {
      supportedOutcomeCount: outcomeSummary.supportedOutcomeCount,
      totalOutcomeCount: outcomeSummary.totalOutcomeCount,
    },
    validationSummary: {
      commandRefs: sortedTextList(input.validationEvidence.commandRefs),
      coverageLineBasisPoints: input.validationEvidence.coverageLineBasisPoints,
      sourceGuardPassed: input.validationEvidence.sourceGuardPassed,
      testCount: input.validationEvidence.testCount,
    },
    acceptanceHash,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, prdAcceptanceOutcomes) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: prdAcceptanceOutcomes.acceptanceHash,
    artifactType: 'prd_acceptance_outcome_matrix',
    artifactVersion: input.acceptanceCycle.releaseCandidateRef,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: ['prd_acceptance', 'metadata_only', 'inactive_trust_state'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluatePrdAcceptanceOutcomes(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateAcceptancePolicy(input?.acceptancePolicy, reasons);
  evaluateAcceptanceCycle(input?.acceptanceCycle, input?.acceptancePolicy, reasons);
  const outcomeSummary = evaluateOutcomeRows(input?.outcomeRows, policySummary, input?.acceptanceCycle, reasons);
  evaluateValidationEvidence(input?.validationEvidence, input?.acceptanceCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.acceptanceCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.acceptanceCycle, input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      prdAcceptanceOutcomes: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const prdAcceptanceOutcomes = buildPrdAcceptanceOutcomes(input, policySummary, outcomeSummary);
  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    prdAcceptanceOutcomes,
    receipt: buildReceipt(input, prdAcceptanceOutcomes),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
