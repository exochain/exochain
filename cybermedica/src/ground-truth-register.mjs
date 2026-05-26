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
const GROUND_TRUTH_SCHEMA = 'cybermedica.ground_truth_register.v1';
const DECISION_SCHEMA = 'cybermedica.ground_truth_register_decision.v1';
const REQUIRED_PERMISSION = 'ground_truth_review';

const REQUIRED_SOURCE_FAMILIES = Object.freeze([
  'adjacent_surface_intake',
  'context_seed',
  'council_escalation_register',
  'council_review_defaults',
  'exochain_readonly_repo',
  'implementation_path_classification',
  'integration_map',
  'master_prd',
  'production_activation_gates',
]);

const REQUIRED_CONTEXT_DOC_REFS = Object.freeze([
  'docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md',
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
  'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
  'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
]);

const DEFAULT_BOB_ESCALATION_IDS = Object.freeze([
  'ESC-CONSENT-LEGAL',
  'ESC-HUMAN-PROOFING',
  'ESC-OPS-SECRETS',
  'ESC-OPTIONAL-ADJACENT',
  'ESC-ROLE-MATRIX',
  'ESC-ROOT-ARTIFACT-STORE',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-ROOT-ROSTER',
  'ESC-RUNTIME',
]);

const POLICY_STATUSES = new Set(['active']);
const SOURCE_STATUSES = new Set(['verified']);
const SOURCE_FAMILIES = new Set(REQUIRED_SOURCE_FAMILIES);
const CONTEXT_DOC_REFS = new Set(REQUIRED_CONTEXT_DOC_REFS);
const HUMAN_REVIEW_DECISIONS = new Set(['ground_truth_accepted_inactive_trust', 'hold_for_ground_truth_gap']);

const RAW_GROUND_TRUTH_FIELDS = new Set([
  'body',
  'consoleoutput',
  'content',
  'evidencebody',
  'freetext',
  'freetextnote',
  'rawactivationevidence',
  'rawbobanswer',
  'rawcontext',
  'rawcontextbody',
  'rawcouncilreview',
  'rawexochainsource',
  'rawfinding',
  'rawgroundtruth',
  'rawopenquestion',
  'rawprdtext',
  'rawsource',
  'rawsourcecontent',
  'rawsourcedata',
  'rawsourcetext',
  'rawvalidationoutput',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
  'sourcetext',
  'validationlog',
]);

const SECRET_GROUND_TRUTH_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credentialsecret',
  'password',
  'privatekey',
  'railwaytoken',
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

function isSafeNonNegativeInteger(value) {
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

function assertNoRawGroundTruthContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawGroundTruthContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_GROUND_TRUTH_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw ground truth content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_GROUND_TRUTH_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`ground truth secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawGroundTruthContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawGroundTruthContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_ground_truth_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'ground_truth_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateGroundTruthPolicy(policy, reasons) {
  const requiredSourceFamilies = sortedTextList(policy?.requiredSourceFamilies);
  const requiredContextDocRefs = sortedTextList(policy?.requiredContextDocRefs);
  const allowedBobEscalationIds = sortedTextList(policy?.allowedBobEscalationIds);

  addReason(reasons, !hasText(policy?.policyRef), 'ground_truth_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'ground_truth_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'ground_truth_policy_inactive');
  addReason(reasons, policy?.metadataOnly !== true, 'ground_truth_policy_metadata_boundary_missing');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'ground_truth_policy_protected_boundary_missing');
  addReason(reasons, !isSafeNonNegativeInteger(policy?.maxSourceAgePhysicalMs), 'max_source_age_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'ground_truth_policy_evaluated_hlc_invalid');

  evaluateRequiredSet(
    requiredSourceFamilies,
    REQUIRED_SOURCE_FAMILIES,
    'required_source_family_missing',
    'required_source_family_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    requiredContextDocRefs,
    REQUIRED_CONTEXT_DOC_REFS,
    'required_context_doc_missing',
    'required_context_doc_unsupported',
    reasons,
  );

  for (const escalationId of allowedBobEscalationIds) {
    addReason(reasons, !DEFAULT_BOB_ESCALATION_IDS.includes(escalationId), `allowed_bob_escalation_unsupported:${escalationId}`);
  }

  return {
    allowedBobEscalationIds,
    requiredContextDocRefs,
    requiredSourceFamilies,
  };
}

function isSourceStale(source, policy) {
  const evaluated = hlcTuple(policy?.evaluatedAtHlc);
  const verified = hlcTuple(source?.verifiedAtHlc);
  if (evaluated === null || verified === null || !isSafeNonNegativeInteger(policy?.maxSourceAgePhysicalMs)) {
    return false;
  }
  return evaluated[0] - verified[0] > policy.maxSourceAgePhysicalMs;
}

function normalizeSourceRecords(input, policyShape, reasons) {
  const records = Array.isArray(input?.sourceRecords) ? [...input.sourceRecords] : [];
  const normalizedRecords = records
    .map((record) => ({
      sourceFamily: record?.sourceFamily ?? null,
      sourceRef: record?.sourceRef ?? null,
      classification: record?.classification ?? null,
      evidenceKind: record?.evidenceKind ?? null,
      evidenceHash: record?.evidenceHash ?? null,
      status: record?.status ?? null,
      ownerDid: record?.ownerDid ?? null,
      verifiedAtHlc: record?.verifiedAtHlc ?? null,
      metadataOnly: record?.metadataOnly === true,
      protectedContentExcluded: record?.protectedContentExcluded === true,
      productionTrustClaim: record?.productionTrustClaim === true,
      reviewedByHuman: record?.reviewedByHuman === true,
      stale: isSourceStale(record, input?.groundTruthPolicy),
    }))
    .sort((left, right) => String(left.sourceFamily).localeCompare(String(right.sourceFamily)));

  const sourceFamiliesCovered = uniqueSorted(normalizedRecords.map((record) => record.sourceFamily));
  const contextDocRefsCovered = uniqueSorted(
    normalizedRecords.map((record) => record.sourceRef).filter((sourceRef) => CONTEXT_DOC_REFS.has(sourceRef)),
  );
  const staleSourceFamilies = uniqueSorted(
    normalizedRecords.filter((record) => record.stale === true).map((record) => record.sourceFamily),
  );

  addReason(reasons, records.length === 0, 'source_records_absent');
  evaluateRequiredSet(
    sourceFamiliesCovered,
    policyShape.requiredSourceFamilies.length > 0 ? policyShape.requiredSourceFamilies : REQUIRED_SOURCE_FAMILIES,
    'source_family_missing',
    'source_family_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    contextDocRefsCovered,
    policyShape.requiredContextDocRefs.length > 0 ? policyShape.requiredContextDocRefs : REQUIRED_CONTEXT_DOC_REFS,
    'context_doc_missing',
    'context_doc_unsupported',
    reasons,
  );

  for (const record of normalizedRecords) {
    const label = hasText(record.sourceFamily) ? record.sourceFamily : 'unknown';
    addReason(reasons, !SOURCE_FAMILIES.has(record.sourceFamily), `source_record_family_unsupported:${label}`);
    addReason(reasons, !hasText(record.sourceRef), `source_ref_absent:${label}`);
    addReason(reasons, !hasText(record.classification), `source_classification_absent:${label}`);
    addReason(reasons, !hasText(record.evidenceKind), `source_evidence_kind_absent:${label}`);
    addReason(reasons, !isDigest(record.evidenceHash), `source_evidence_hash_invalid:${label}`);
    addReason(reasons, !SOURCE_STATUSES.has(record.status), `source_record_unverified:${label}`);
    addReason(reasons, !hasText(record.ownerDid), `source_owner_absent:${label}`);
    addReason(reasons, hlcTuple(record.verifiedAtHlc) === null, `source_verified_hlc_invalid:${label}`);
    addReason(reasons, record.reviewedByHuman !== true, `source_human_review_missing:${label}`);
    addReason(reasons, record.metadataOnly !== true, `source_metadata_boundary_missing:${label}`);
    addReason(reasons, record.protectedContentExcluded !== true, `source_protected_boundary_missing:${label}`);
    addReason(reasons, record.productionTrustClaim === true, `source_record_claims_production_trust:${label}`);
    addReason(reasons, record.stale === true, `source_record_stale:${label}`);
    addReason(
      reasons,
      input?.humanReview?.reviewedAtHlc !== undefined && hlcAfter(record.verifiedAtHlc, input?.humanReview?.reviewedAtHlc),
      `source_verified_after_human_review:${label}`,
    );
  }

  return {
    contextDocRefsCovered,
    normalizedRecords,
    sourceFamiliesCovered,
    staleSourceFamilies,
  };
}

function evaluateRegisterCycle(cycle, reasons) {
  addReason(reasons, !hasText(cycle?.registerRef), 'ground_truth_register_ref_absent');
  addReason(reasons, hlcTuple(cycle?.openedAtHlc) === null, 'ground_truth_opened_hlc_invalid');
  addReason(reasons, hlcTuple(cycle?.compiledAtHlc) === null, 'ground_truth_compiled_hlc_invalid');
  addReason(reasons, hlcTuple(cycle?.councilReviewedAtHlc) === null, 'ground_truth_council_review_hlc_invalid');
  addReason(reasons, hlcTuple(cycle?.humanReviewedAtHlc) === null, 'ground_truth_human_review_hlc_invalid');
  addReason(reasons, hlcTuple(cycle?.validationRecordedAtHlc) === null, 'ground_truth_validation_hlc_invalid');
  addReason(reasons, !hlcAfter(cycle?.compiledAtHlc, cycle?.openedAtHlc), 'ground_truth_compile_order_invalid');
  addReason(reasons, !hlcAfter(cycle?.councilReviewedAtHlc, cycle?.compiledAtHlc), 'ground_truth_council_review_order_invalid');
  addReason(reasons, !hlcAfter(cycle?.humanReviewedAtHlc, cycle?.councilReviewedAtHlc), 'ground_truth_human_review_order_invalid');
  addReason(reasons, !hlcAfter(cycle?.validationRecordedAtHlc, cycle?.humanReviewedAtHlc), 'ground_truth_validation_order_invalid');
  addReason(reasons, cycle?.metadataOnly !== true, 'ground_truth_cycle_metadata_boundary_missing');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'ground_truth_cycle_protected_boundary_missing');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateExochainBoundary(boundary, validationEvidence, reasons) {
  addReason(reasons, !hasText(boundary?.sourceRepoRef), 'exochain_source_repo_absent');
  addReason(reasons, boundary?.classification !== 'EXOCHAIN core', 'exochain_source_classification_invalid');
  addReason(reasons, boundary?.readOnlyEvidenceOnly !== true, 'exochain_readonly_boundary_missing');
  addReason(
    reasons,
    boundary?.noExochainSourceModified !== true || validationEvidence?.noExochainSourceModified !== true,
    'exochain_source_modified',
  );
  addReason(reasons, sortedTextList(boundary?.modifiedPathRefs).length > 0, 'exochain_modified_paths_present');
  addReason(reasons, sortedTextList(boundary?.verificationCommandRefs).length === 0, 'exochain_verification_commands_absent');
  addReason(reasons, !isDigest(boundary?.verificationEvidenceHash), 'exochain_verification_hash_invalid');
  addReason(reasons, hlcTuple(boundary?.verifiedAtHlc) === null, 'exochain_verified_hlc_invalid');
  addReason(reasons, boundary?.metadataOnly !== true, 'exochain_boundary_metadata_missing');
  addReason(reasons, boundary?.protectedContentExcluded !== true, 'exochain_boundary_protected_missing');
  addReason(reasons, boundary?.productionTrustClaim === true, 'production_trust_claim_forbidden');
}

function evaluateCouncilDefaults(councilDefaults, policyShape, reasons) {
  const escalations = Array.isArray(councilDefaults?.escalations) ? [...councilDefaults.escalations] : [];
  const allowedEscalations =
    policyShape.allowedBobEscalationIds.length > 0 ? policyShape.allowedBobEscalationIds : [...DEFAULT_BOB_ESCALATION_IDS];
  const narrowedEscalationIds = uniqueSorted(escalations.map((entry) => entry?.escalationId));
  const blockingEscalationIds = uniqueSorted(
    escalations.filter((entry) => entry?.blocksBaselineDevelopment === true).map((entry) => entry?.escalationId),
  );

  addReason(reasons, councilDefaults?.defaultsApplied !== true, 'council_defaults_not_applied');
  addReason(reasons, councilDefaults?.baselineDevelopmentBlocked === true, 'baseline_development_blocked_by_open_questions');
  addReason(reasons, !hasText(councilDefaults?.narrowedEscalationRegisterRef), 'narrowed_escalation_register_ref_absent');
  addReason(reasons, !isDigest(councilDefaults?.narrowedEscalationRegisterHash), 'narrowed_escalation_register_hash_invalid');
  addReason(reasons, escalations.length === 0, 'council_escalations_absent');
  addReason(reasons, hlcTuple(councilDefaults?.reviewedAtHlc) === null, 'council_defaults_review_hlc_invalid');
  addReason(reasons, councilDefaults?.metadataOnly !== true, 'council_defaults_metadata_boundary_missing');
  addReason(reasons, councilDefaults?.protectedContentExcluded !== true, 'council_defaults_protected_boundary_missing');

  for (const escalation of escalations) {
    const label = hasText(escalation?.escalationId) ? escalation.escalationId : 'unknown';
    addReason(reasons, !allowedEscalations.includes(label), `bob_escalation_not_allowed:${label}`);
    addReason(reasons, escalation?.blocksBaselineDevelopment === true, `escalation_blocks_baseline:${label}`);
    addReason(reasons, escalation?.productionActivationOnly !== true, `escalation_not_activation_only:${label}`);
    addReason(reasons, !isDigest(escalation?.baselineDefaultHash), `escalation_default_hash_invalid:${label}`);
    addReason(reasons, hlcTuple(escalation?.reviewedAtHlc) === null, `escalation_review_hlc_invalid:${label}`);
    addReason(reasons, escalation?.metadataOnly !== true, `escalation_metadata_boundary_missing:${label}`);
    addReason(reasons, escalation?.protectedContentExcluded !== true, `escalation_protected_boundary_missing:${label}`);
  }

  return {
    blockingEscalationIds,
    narrowedEscalationIds,
  };
}

function evaluateValidationEvidence(validationEvidence, reasons) {
  addReason(reasons, validationEvidence?.contextDocsPresent !== true, 'context_docs_not_present');
  addReason(reasons, validationEvidence?.commandsPassed !== true, 'ground_truth_validation_commands_failed');
  addReason(reasons, validationEvidence?.sourceGuardPassed !== true, 'source_guard_not_passed');
  addReason(reasons, validationEvidence?.noRawProtectedContentFound !== true, 'raw_protected_content_found');
  addReason(reasons, validationEvidence?.noExochainSourceModified !== true, 'exochain_source_modified');
  addReason(reasons, !isDigest(validationEvidence?.validationHash), 'ground_truth_validation_hash_invalid');
  addReason(reasons, sortedTextList(validationEvidence?.commandRefs).length === 0, 'ground_truth_validation_commands_absent');
  addReason(reasons, hlcTuple(validationEvidence?.recordedAtHlc) === null, 'ground_truth_validation_recorded_hlc_invalid');
  addReason(reasons, validationEvidence?.metadataOnly !== true, 'validation_evidence_metadata_boundary_missing');
}

function evaluateHumanReview(review, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'ground_truth_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'ground_truth_human_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'ground_truth_human_decision_hash_invalid');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'production_trust_claim_forbidden');
  addReason(reasons, review?.finalAuthority !== 'human' || review?.aiFinalAuthority === true, 'ground_truth_human_final_authority_required');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'ground_truth_human_review_hlc_invalid');
  addReason(reasons, review?.metadataOnly !== true, 'ground_truth_human_review_metadata_boundary_missing');
}

function buildGroundTruth(input, sourceSummary, escalationSummary) {
  const groundTruthMaterial = {
    schema: GROUND_TRUTH_SCHEMA,
    registerRef: input?.registerCycle?.registerRef ?? null,
    sourceFamiliesCovered: sourceSummary.sourceFamiliesCovered,
    contextDocRefsCovered: sourceSummary.contextDocRefsCovered,
    staleSourceFamilies: sourceSummary.staleSourceFamilies,
    narrowedEscalationIds: escalationSummary.narrowedEscalationIds,
    blockingEscalationIds: escalationSummary.blockingEscalationIds,
    exochainSourceReadOnly:
      input?.exochainBoundary?.readOnlyEvidenceOnly === true &&
      input?.exochainBoundary?.noExochainSourceModified === true &&
      input?.validationEvidence?.noExochainSourceModified === true,
    validationCommandRefs: sortedTextList(input?.validationEvidence?.commandRefs),
    verificationCommandRefs: sortedTextList(input?.exochainBoundary?.verificationCommandRefs),
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    protectedContentExcluded: true,
  };

  return {
    ...groundTruthMaterial,
    groundTruthHash: sha256Hex(groundTruthMaterial),
  };
}

function buildReceipt(input, groundTruth) {
  return createEvidenceReceipt({
    actorDid: input?.actor?.did ?? 'did:exo:ground-truth-unknown',
    artifactHash: groundTruth.groundTruthHash,
    artifactType: 'ground_truth_register',
    artifactVersion: 'v1',
    classification: 'metadata_only_ground_truth',
    custodyDigest: input?.custodyDigest ?? groundTruth.groundTruthHash,
    hlcTimestamp: input?.registerCycle?.validationRecordedAtHlc ?? { physicalMs: 0, logical: 0 },
    schema: DECISION_SCHEMA,
    sensitivityTags: ['ground_truth', 'metadata_only', 'inactive_trust_state'],
    sourceSystem: 'cybermedica',
    tenantId: input?.tenantId ?? 'tenant-unknown',
  });
}

export function evaluateGroundTruthRegister(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policyShape = evaluateGroundTruthPolicy(input?.groundTruthPolicy, reasons);
  evaluateRegisterCycle(input?.registerCycle, reasons);
  evaluateExochainBoundary(input?.exochainBoundary, input?.validationEvidence, reasons);
  const escalationSummary = evaluateCouncilDefaults(input?.councilDefaults, policyShape, reasons);
  evaluateValidationEvidence(input?.validationEvidence, reasons);
  evaluateHumanReview(input?.humanReview, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'ground_truth_custody_digest_invalid');

  const sourceSummary = normalizeSourceRecords(input, policyShape, reasons);
  const finalReasons = uniqueReasons(reasons);
  const groundTruth = buildGroundTruth(input, sourceSummary, escalationSummary);
  const receipt = buildReceipt(input, groundTruth);

  return {
    schema: DECISION_SCHEMA,
    decision: finalReasons.length === 0 ? 'permitted' : 'denied',
    failClosed: finalReasons.length > 0,
    reasons: finalReasons,
    groundTruth,
    receipt,
  };
}
