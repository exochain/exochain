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
const REGISTER_SCHEMA = 'cybermedica.policy_procedure_rule_traceability_register.v1';
const DECISION_SCHEMA = 'cybermedica.policy_procedure_rule_traceability_decision.v1';
const REQUIRED_PERMISSION = 'policy_procedure_rule_traceability_review';
const MINIMUM_COVERAGE_BASIS_POINTS = 9000;

const REQUIRED_POLICY_IDS = Object.freeze(Array.from({ length: 40 }, (_, index) => `POLICY-${String(index + 1).padStart(3, '0')}`));
const REQUIRED_PROCEDURE_IDS = Object.freeze(
  Array.from({ length: 16 }, (_, index) => `PROCEDURE-${String(index + 1).padStart(3, '0')}`),
);
const REQUIRED_RULE_IDS = Object.freeze(Array.from({ length: 15 }, (_, index) => `RULE-${String(index + 1).padStart(3, '0')}`));
const REQUIRED_SOURCE_REFS = Object.freeze([
  'cyber_medica_qms_prd_master.md#core-policies',
  'cyber_medica_qms_prd_master.md#core-procedures',
  'cyber_medica_qms_prd_master.md#governance-rules',
  'cybermedica_2_0_sandy_seven_layer_master_prd.md#appendix-a-seven-layer-implementation-backlog-skeleton',
]);
const REQUIRED_MODULE_REFS_BY_ITEM = Object.freeze({
  'POLICY-015': Object.freeze(['src/complaint-management.mjs']),
  'POLICY-016': Object.freeze(['src/risk-management-framework.mjs']),
  'POLICY-029': Object.freeze(['src/participant-data-sharing-consent.mjs']),
  'POLICY-037': Object.freeze([
    'src/internal-audits.mjs',
    'src/monitoring-visits.mjs',
    'src/site-self-assessments.mjs',
  ]),
  'POLICY-039': Object.freeze(['src/access-revocation.mjs']),
  'PROCEDURE-016': Object.freeze(['src/sponsor-cro-request-management.mjs']),
  'RULE-015': Object.freeze(['src/access-revocation.mjs']),
});
const REQUIRED_TEST_REFS_BY_ITEM = Object.freeze({
  'POLICY-015': Object.freeze(['tests/complaint-management.test.mjs']),
  'POLICY-016': Object.freeze(['tests/risk-management-framework.test.mjs']),
  'POLICY-029': Object.freeze(['tests/participant-data-sharing-consent.test.mjs']),
  'POLICY-037': Object.freeze([
    'tests/internal-audits.test.mjs',
    'tests/monitoring-visits.test.mjs',
    'tests/site-self-assessments.test.mjs',
  ]),
  'POLICY-039': Object.freeze(['tests/access-revocation.test.mjs']),
  'PROCEDURE-016': Object.freeze(['tests/sponsor-cro-request-management.test.mjs']),
  'RULE-015': Object.freeze(['tests/access-revocation.test.mjs']),
});

const POLICY_STATUSES = new Set(['active']);
const ITEM_FAMILIES = new Set(['policy', 'procedure', 'rule']);
const IMPLEMENTATION_STATUSES = new Set(['implemented', 'covered_by_aggregate_contract']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_policy_procedure_rule_gap',
  'policy_procedure_rule_traceability_accepted_inactive_trust',
]);

const RAW_TRACEABILITY_FIELDS = new Set([
  'body',
  'content',
  'freetext',
  'freetextnote',
  'policybody',
  'policycontent',
  'policytext',
  'procedurebody',
  'procedurecontent',
  'proceduretext',
  'rawcontent',
  'rawpolicy',
  'rawpolicybody',
  'rawpolicytext',
  'rawprocedure',
  'rawprocedurebody',
  'rawproceduretext',
  'rawrule',
  'rawrulebody',
  'rawruletext',
  'rawsource',
  'rawsourcedocument',
  'rawtraceability',
  'rawvalidationoutput',
  'reviewnotes',
  'rulebody',
  'rulecontent',
  'ruletext',
  'sourcedocumentbody',
]);

const SECRET_TRACEABILITY_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'integrationsecret',
  'password',
  'privatekey',
  'railwaytoken',
  'refreshtoken',
  'rootkey',
  'rootsigningkey',
  'secret',
  'servicetoken',
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

function isBasisPoints(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 10_000;
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

function assertNoRawTraceabilityContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawTraceabilityContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_TRACEABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw policy procedure rule traceability content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_TRACEABILITY_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`policy procedure rule traceability secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawTraceabilityContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawTraceabilityContent(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
}

function sortedDigestList(value) {
  return Array.isArray(value) ? uniqueSorted(value.filter(isDigest)) : [];
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function requiredRefsFor(itemId, refTable) {
  return Array.isArray(refTable[itemId]) ? refTable[itemId] : [];
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

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !expected.includes(value), `${unsupportedPrefix}:${value}`);
  }
}

function expectedItemFamily(itemId) {
  if (REQUIRED_POLICY_IDS.includes(itemId)) {
    return 'policy';
  }
  if (REQUIRED_PROCEDURE_IDS.includes(itemId)) {
    return 'procedure';
  }
  if (REQUIRED_RULE_IDS.includes(itemId)) {
    return 'rule';
  }
  if (hasText(itemId) && itemId.startsWith('POLICY-')) {
    return 'policy';
  }
  if (hasText(itemId) && itemId.startsWith('PROCEDURE-')) {
    return 'procedure';
  }
  if (hasText(itemId) && itemId.startsWith('RULE-')) {
    return 'rule';
  }
  return null;
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_traceability_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'traceability_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateTraceabilityPolicy(policy, reasons) {
  const requiredPolicyIds = sortedTextList(policy?.requiredPolicyIds);
  const requiredProcedureIds = sortedTextList(policy?.requiredProcedureIds);
  const requiredRuleIds = sortedTextList(policy?.requiredRuleIds);
  const requiredSourceRefs = sortedTextList(policy?.requiredSourceRefs);

  addReason(reasons, !hasText(policy?.policyRef), 'traceability_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'traceability_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'traceability_policy_not_active');
  addReason(reasons, policy?.metadataOnly !== true, 'traceability_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'traceability_policy_protected_boundary_invalid');
  addReason(reasons, policy?.productionTrustClaim === true, 'traceability_policy_production_trust_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'traceability_policy_time_invalid');
  evaluateRequiredSet(
    requiredPolicyIds,
    REQUIRED_POLICY_IDS,
    'required_policy_id_missing',
    'required_policy_id_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredProcedureIds,
    REQUIRED_PROCEDURE_IDS,
    'required_procedure_id_missing',
    'required_procedure_id_unsupported',
    reasons,
  );
  evaluateRequiredSet(requiredRuleIds, REQUIRED_RULE_IDS, 'required_rule_id_missing', 'required_rule_id_unsupported', reasons);
  evaluateRequiredSet(
    requiredSourceRefs,
    REQUIRED_SOURCE_REFS,
    'required_source_ref_missing',
    'required_source_ref_unsupported',
    reasons,
  );

  return {
    requiredPolicyIds: REQUIRED_POLICY_IDS,
    requiredProcedureIds: REQUIRED_PROCEDURE_IDS,
    requiredRuleIds: REQUIRED_RULE_IDS,
    requiredSourceRefs,
  };
}

function evaluateCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.registerRef), 'traceability_register_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, hlcTuple(cycle?.openedAtHlc) === null, 'cycle_open_time_invalid');
  addReason(reasons, hlcTuple(cycle?.compiledAtHlc) === null, 'cycle_compile_time_invalid');
  addReason(reasons, hlcTuple(cycle?.humanReviewedAtHlc) === null, 'cycle_human_review_time_invalid');
  addReason(reasons, hlcTuple(cycle?.validationRecordedAtHlc) === null, 'cycle_validation_time_invalid');
  addReason(reasons, hlcTuple(cycle?.auditRecordedAtHlc) === null, 'cycle_audit_time_invalid');
  addReason(reasons, policy !== null && hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'traceability_policy_after_cycle_open');
  addReason(reasons, !hlcAfter(cycle?.compiledAtHlc, cycle?.openedAtHlc), 'cycle_compile_not_after_open');
  addReason(reasons, !hlcAfter(cycle?.humanReviewedAtHlc, cycle?.compiledAtHlc), 'cycle_human_review_not_after_compile');
  addReason(reasons, !hlcAfter(cycle?.validationRecordedAtHlc, cycle?.humanReviewedAtHlc), 'cycle_validation_not_after_human_review');
  addReason(reasons, !hlcAfter(cycle?.auditRecordedAtHlc, cycle?.validationRecordedAtHlc), 'cycle_audit_not_after_validation');
  addReason(reasons, cycle?.metadataOnly !== true, 'cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'cycle_protected_boundary_invalid');
  addReason(reasons, cycle?.productionTrustClaim === true, 'cycle_production_trust_claim_forbidden');
}

function rowIdentity(row) {
  return hasText(row?.itemId) ? row.itemId : 'unidentified_item';
}

function validateRowShape(row, cycle, reasons) {
  const itemId = rowIdentity(row);
  const moduleRefs = sortedTextList(row?.moduleRefs);
  const testRefs = sortedTextList(row?.testRefs);
  const evidenceHashes = sortedDigestList(row?.evidenceHashes);
  const linkedRequirementRefs = sortedTextList(row?.linkedRequirementRefs);
  const ownerRoleRefs = sortedTextList(row?.ownerRoleRefs);
  const expectedFamily = expectedItemFamily(itemId);

  addReason(reasons, !hasText(row?.itemId), 'row_item_id_absent');
  addReason(reasons, !ITEM_FAMILIES.has(row?.itemFamily), `row_item_family_invalid:${itemId}`);
  addReason(
    reasons,
    expectedFamily !== null && row?.itemFamily !== expectedFamily,
    `row_item_family_mismatch:${itemId}`,
  );
  addReason(reasons, !hasText(row?.sourceRef), `row_source_ref_absent:${itemId}`);
  addReason(reasons, !IMPLEMENTATION_STATUSES.has(row?.implementationStatus), `row_implementation_status_invalid:${itemId}`);
  addReason(reasons, moduleRefs.length === 0, `row_module_refs_absent:${itemId}`);
  addReason(reasons, moduleRefs.some((ref) => !ref.startsWith('src/') || !ref.endsWith('.mjs')), `row_module_ref_invalid:${itemId}`);
  for (const requiredRef of requiredRefsFor(itemId, REQUIRED_MODULE_REFS_BY_ITEM)) {
    addReason(reasons, !moduleRefs.includes(requiredRef), `row_required_module_ref_missing:${itemId}:${requiredRef}`);
  }
  addReason(reasons, testRefs.length === 0, `row_test_refs_absent:${itemId}`);
  addReason(
    reasons,
    testRefs.some((ref) => !ref.startsWith('tests/') || !ref.endsWith('.test.mjs')),
    `row_test_ref_invalid:${itemId}`,
  );
  for (const requiredRef of requiredRefsFor(itemId, REQUIRED_TEST_REFS_BY_ITEM)) {
    addReason(reasons, !testRefs.includes(requiredRef), `row_required_test_ref_missing:${itemId}:${requiredRef}`);
  }
  addReason(reasons, evidenceHashes.length === 0, `row_evidence_hash_invalid:${itemId}`);
  addReason(reasons, linkedRequirementRefs.length === 0, `row_linked_requirement_refs_absent:${itemId}`);
  addReason(reasons, ownerRoleRefs.length === 0, `row_owner_role_refs_absent:${itemId}`);
  addReason(reasons, row?.reviewedByHuman !== true, `row_human_review_absent:${itemId}`);
  addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `row_review_time_invalid:${itemId}`);
  addReason(reasons, hlcBefore(row?.reviewedAtHlc, cycle?.compiledAtHlc), `row_review_before_cycle_compile:${itemId}`);
  addReason(reasons, hlcAfter(row?.reviewedAtHlc, cycle?.humanReviewedAtHlc), `row_review_after_cycle_human_review:${itemId}`);
  addReason(reasons, row?.metadataOnly !== true, `row_metadata_boundary_invalid:${itemId}`);
  addReason(reasons, row?.protectedContentExcluded !== true, `row_protected_boundary_invalid:${itemId}`);
  addReason(reasons, row?.productionTrustClaim === true, `row_production_trust_claim_forbidden:${itemId}`);

  return {
    evidenceHashes,
    itemFamily: row?.itemFamily,
    itemId,
    linkedRequirementRefs,
    moduleRefs,
    ownerRoleRefs,
    sourceRef: row?.sourceRef ?? '',
    testRefs,
  };
}

function summarizeRows(rows, policySummary, cycle, reasons) {
  const rowList = Array.isArray(rows) ? rows : [];
  addReason(reasons, rowList.length === 0, 'traceability_rows_absent');

  const byId = new Map();
  const unsupportedIds = [];
  const allExpectedIds = [...policySummary.requiredPolicyIds, ...policySummary.requiredProcedureIds, ...policySummary.requiredRuleIds];
  const allExpected = new Set(allExpectedIds);
  const rowSummaries = [];

  for (const row of rowList) {
    const itemId = rowIdentity(row);
    if (byId.has(itemId)) {
      reasons.push(`traceability_row_duplicate:${itemId}`);
    }
    byId.set(itemId, row);
    if (!allExpected.has(itemId)) {
      unsupportedIds.push(itemId);
      reasons.push(`traceability_row_unsupported:${itemId}`);
    }
    rowSummaries.push(validateRowShape(row, cycle, reasons));
  }

  for (const itemId of allExpectedIds) {
    if (!byId.has(itemId)) {
      reasons.push(`traceability_row_missing:${itemId}`);
    }
  }

  const includedSummaries = rowSummaries
    .filter((summary) => allExpected.has(summary.itemId))
    .sort((left, right) => left.itemId.localeCompare(right.itemId))
    .map((summary) => ({
      evidenceHashes: summary.evidenceHashes,
      itemFamily: summary.itemFamily,
      itemId: summary.itemId,
      linkedRequirementRefs: summary.linkedRequirementRefs,
      moduleRefs: summary.moduleRefs,
      ownerRoleRefs: summary.ownerRoleRefs,
      sourceRef: summary.sourceRef,
      testRefs: summary.testRefs,
    }));

  const policyIds = includedSummaries.filter((summary) => summary.itemFamily === 'policy').map((summary) => summary.itemId);
  const procedureIds = includedSummaries
    .filter((summary) => summary.itemFamily === 'procedure')
    .map((summary) => summary.itemId);
  const ruleIds = includedSummaries.filter((summary) => summary.itemFamily === 'rule').map((summary) => summary.itemId);

  return {
    itemFamiliesCovered: uniqueSorted(includedSummaries.map((summary) => summary.itemFamily)),
    policyIds,
    procedureIds,
    ruleIds,
    rowSummaries: includedSummaries,
    totalItemCount: includedSummaries.length,
    unsupportedIds: uniqueSorted(unsupportedIds),
  };
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  const commandRefs = sortedTextList(validation?.commandRefs);
  addReason(reasons, commandRefs.length === 0, 'validation_command_refs_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_failed');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_failed');
  addReason(reasons, validation?.docsUpdated !== true, 'validation_docs_not_updated');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'validation_exochain_source_modified');
  addReason(
    reasons,
    !isBasisPoints(validation?.coverageLineBasisPoints) ||
      validation.coverageLineBasisPoints < MINIMUM_COVERAGE_BASIS_POINTS,
    'validation_coverage_below_threshold',
  );
  addReason(reasons, !Number.isSafeInteger(validation?.testCount) || validation.testCount <= 0, 'validation_test_count_invalid');
  addReason(reasons, !isDigest(validation?.moduleManifestHash), 'validation_module_manifest_hash_invalid');
  addReason(reasons, !isDigest(validation?.testManifestHash), 'validation_test_manifest_hash_invalid');
  addReason(reasons, !isDigest(validation?.evidenceHash), 'validation_evidence_hash_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_recorded_time_invalid');
  addReason(reasons, !hlcAfter(validation?.recordedAtHlc, cycle?.humanReviewedAtHlc), 'validation_recorded_not_after_human_review');

  return {
    commandRefs,
    coverageLineBasisPoints: validation?.coverageLineBasisPoints ?? null,
    sourceGuardPassed: validation?.sourceGuardPassed === true,
    testCount: validation?.testCount ?? null,
  };
}

function evaluateHumanReview(review, cycle, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_did_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_reviewer_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_final_authority_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_claim_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, !hlcAfter(review?.reviewedAtHlc, cycle?.compiledAtHlc), 'human_review_not_after_compile');
}

function evaluateAuditRecord(audit, cycle, reasons) {
  addReason(reasons, !hasText(audit?.auditRecordRef), 'audit_record_ref_absent');
  addReason(reasons, !isDigest(audit?.auditRecordHash), 'audit_record_hash_invalid');
  addReason(reasons, audit?.metadataOnly !== true, 'audit_record_metadata_boundary_invalid');
  addReason(reasons, audit?.includesProtectedContent === true, 'audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(audit?.receiptRecordedAtHlc) === null, 'audit_record_time_invalid');
  addReason(reasons, !hlcAfter(audit?.receiptRecordedAtHlc, cycle?.validationRecordedAtHlc), 'audit_record_not_after_validation');
}

function evaluateAiAssistance(ai, reasons) {
  if (ai === null || ai === undefined || ai?.used !== true) {
    return;
  }
  addReason(reasons, ai.finalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, !isDigest(ai.recommendationHash), 'ai_recommendation_hash_invalid');
  addReason(reasons, sortedDigestList(ai.limitationHashes).length === 0, 'ai_limitation_hashes_absent');
  addReason(reasons, ai.reviewedByHuman !== true, 'ai_human_review_absent');
}

function buildRegister(input, policySummary, rowSummary, validationSummary) {
  const registerHash = sha256Hex({
    auditRecordHash: input.auditRecord.auditRecordHash,
    humanDecisionHash: input.humanReview.decisionHash,
    registerRef: input.traceabilityCycle.registerRef,
    requiredSourceRefs: policySummary.requiredSourceRefs,
    rowSummaries: rowSummary.rowSummaries,
    tenantId: input.tenantId,
    validationEvidenceHash: input.validationEvidence.evidenceHash,
  });

  return {
    schema: REGISTER_SCHEMA,
    registerId: `cmppr_${sha256Hex({
      registerHash,
      registerRef: input.traceabilityCycle.registerRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    registerHash,
    tenantId: input.tenantId,
    releaseCandidateRef: input.traceabilityCycle.releaseCandidateRef,
    trustState: 'inactive',
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    sourceRefs: policySummary.requiredSourceRefs,
    itemFamiliesCovered: rowSummary.itemFamiliesCovered,
    policyIds: rowSummary.policyIds,
    procedureIds: rowSummary.procedureIds,
    ruleIds: rowSummary.ruleIds,
    traceabilityRows: rowSummary.rowSummaries,
    coverageSummary: {
      policyCount: rowSummary.policyIds.length,
      procedureCount: rowSummary.procedureIds.length,
      ruleCount: rowSummary.ruleIds.length,
      totalItemCount: rowSummary.totalItemCount,
    },
    validationSummary,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, register) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: register.registerHash,
    artifactType: 'policy_procedure_rule_traceability_register',
    artifactVersion: input.traceabilityCycle.releaseCandidateRef,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: ['policy_procedure_rule_traceability', 'metadata_only', 'inactive_trust_state'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluatePolicyProcedureRuleTraceability(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateTraceabilityPolicy(input?.traceabilityPolicy, reasons);
  evaluateCycle(input?.traceabilityCycle, input?.traceabilityPolicy, reasons);
  const rowSummary = summarizeRows(input?.traceabilityRows, policySummary, input?.traceabilityCycle, reasons);
  const validationSummary = evaluateValidationEvidence(input?.validationEvidence, input?.traceabilityCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.traceabilityCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.traceabilityCycle, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      traceabilityRegister: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const traceabilityRegister = buildRegister(input, policySummary, rowSummary, validationSummary);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    traceabilityRegister,
    receipt: buildReceipt(input, traceabilityRegister),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
