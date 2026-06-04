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
const PUBLICATION_SCHEMA = 'cybermedica.service_contract_publication.v1';
const PUBLICATION_DECISION_SCHEMA = 'cybermedica.service_contract_publication_decision.v1';
const REQUIRED_PERMISSION = 'service_contract_publish';

const REQUIRED_META_LAYERS = Object.freeze([
  'ground_truth',
  'doctrine',
  'domain',
  'data',
  'doors',
  'documentation',
  'deployment',
  'drift',
]);

const REQUIRED_CONTRACT_KINDS = Object.freeze([
  'adapter_contract',
  'deterministic_fixture',
  'documentation_contract',
  'evidence_receipt_contract',
  'fail_closed_boundary',
  'inactive_trust_state',
  'qms_workflow_contract',
]);

const REQUIRED_CONTEXT_REFS = Object.freeze([
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
  'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
]);

const REQUIRED_COMMAND_REFS = Object.freeze([
  'node --test tests/service-contract-publication.test.mjs',
  'node --test tests/source-guards.test.mjs',
]);

const SOURCE_EVIDENCE_REFS = Object.freeze([
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
  'docs/implementation/PATH_CLASSIFICATION.md',
]);

const POLICY_STATUSES = new Set(['active']);
const CONTRACT_STATUSES = new Set(['implemented', 'verified', 'published']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_service_contract_gap',
  'service_contracts_publishable_inactive_trust',
]);
const META_LAYER_SET = new Set(REQUIRED_META_LAYERS);
const CONTRACT_KIND_SET = new Set(REQUIRED_CONTRACT_KINDS);
const CONTEXT_REF_SET = new Set(REQUIRED_CONTEXT_REFS);

const RAW_SERVICE_CONTRACT_FIELDS = new Set([
  'body',
  'contractbody',
  'contractcontent',
  'contractpayload',
  'contracttext',
  'content',
  'evidencebody',
  'freetext',
  'freetextnote',
  'publicationbody',
  'rawbody',
  'rawcontract',
  'rawcontractbody',
  'rawcontractcontent',
  'rawpublication',
  'rawservicecontract',
  'rawsource',
  'rawsourcecontent',
  'reviewnotes',
  'servicecontractbody',
  'sourcebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'validationlog',
]);

const SECRET_SERVICE_CONTRACT_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'clientsecret',
  'credential',
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
  return hasText(value) && HEX_64.test(value) && !/^0+$/u.test(value);
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

function assertNoRawServiceContractContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawServiceContractContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_SERVICE_CONTRACT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw service contract content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_SERVICE_CONTRACT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`service contract secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawServiceContractContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawServiceContractContent(input ?? {});
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

function orderedCoveredValues(actual, required) {
  const actualSet = new Set(actual);
  return required.filter((value) => actualSet.has(value));
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

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function evaluateRequiredSet(actual, expected, missingPrefix, unsupportedPrefix, allowedSet, reasons) {
  for (const value of expected) {
    addReason(reasons, !actual.includes(value), `${missingPrefix}:${value}`);
  }
  for (const value of actual) {
    addReason(reasons, !allowedSet.has(value), `${unsupportedPrefix}:${value}`);
  }
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_service_contract_publisher_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'service_contract_publish_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePublicationPolicy(policy, reasons) {
  const metaLayers = sortedTextList(policy?.requiredMetaLayers);
  const contractKinds = sortedTextList(policy?.requiredContractKinds);
  const contextRefs = sortedTextList(policy?.requiredContextRefs);

  addReason(reasons, !hasText(policy?.policyRef), 'publication_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'publication_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'publication_policy_inactive');
  addReason(reasons, !hasText(policy?.sourcePrdRef), 'publication_policy_source_prd_ref_absent');
  addReason(reasons, policy?.requireTestsPassed !== true, 'publication_policy_test_gate_absent');
  addReason(reasons, policy?.requireFailClosedCoverage !== true, 'publication_policy_fail_closed_gate_absent');
  addReason(reasons, policy?.requireInactiveTrustState !== true, 'publication_policy_inactive_trust_gate_absent');
  addReason(reasons, policy?.requireNoExochainSourceEdits !== true, 'publication_policy_exochain_boundary_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'publication_policy_metadata_boundary_missing');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'publication_policy_protected_boundary_missing');
  addReason(reasons, policy?.noProductionTrustClaim !== true, 'publication_policy_production_claim_forbidden');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'publication_policy_evaluated_hlc_invalid');

  evaluateRequiredSet(metaLayers, REQUIRED_META_LAYERS, 'policy_meta_layer_missing', 'policy_meta_layer_unsupported', META_LAYER_SET, reasons);
  evaluateRequiredSet(
    contractKinds,
    REQUIRED_CONTRACT_KINDS,
    'policy_contract_kind_missing',
    'policy_contract_kind_unsupported',
    CONTRACT_KIND_SET,
    reasons,
  );
  evaluateRequiredSet(contextRefs, REQUIRED_CONTEXT_REFS, 'policy_context_ref_missing', 'policy_context_ref_unsupported', CONTEXT_REF_SET, reasons);
}

function evaluateContractRow(row, policy, reasons) {
  const contractRef = hasText(row?.contractRef) ? row.contractRef : `row_${reasons.length}`;
  const contextRefs = sortedTextList(row?.contextRefs);
  const commandRefs = sortedTextList(row?.lastTestCommandRefs);

  addReason(reasons, !hasText(row?.contractRef), 'contract_ref_absent');
  addReason(reasons, !META_LAYER_SET.has(row?.metaLayer), `contract_meta_layer_unsupported:${contractRef}`);
  addReason(reasons, !CONTRACT_KIND_SET.has(row?.contractKind), `contract_kind_unsupported:${contractRef}`);
  addReason(reasons, !hasText(row?.moduleRef) || !row.moduleRef.startsWith('src/'), `contract_module_ref_invalid:${contractRef}`);
  addReason(
    reasons,
    !hasText(row?.testRef) || !row.testRef.startsWith('tests/') || !row.testRef.endsWith('.test.mjs'),
    `contract_test_ref_invalid:${contractRef}`,
  );
  addReason(reasons, !hasText(row?.documentationRef), `contract_documentation_ref_absent:${contractRef}`);
  addReason(
    reasons,
    row?.pathClassificationRef !== 'docs/implementation/PATH_CLASSIFICATION.md',
    `contract_path_classification_ref_invalid:${contractRef}`,
  );
  evaluateRequiredSet(
    contextRefs,
    REQUIRED_CONTEXT_REFS,
    `contract_context_ref_missing:${contractRef}`,
    `contract_context_ref_unsupported:${contractRef}`,
    CONTEXT_REF_SET,
    reasons,
  );
  for (const commandRef of REQUIRED_COMMAND_REFS) {
    addReason(reasons, !commandRefs.includes(commandRef), `contract_test_command_missing:${contractRef}:${commandRef}`);
  }
  addReason(reasons, !isDigest(row?.deterministicFixtureHash), `contract_fixture_hash_invalid:${contractRef}`);
  addReason(reasons, !isDigest(row?.sourceEvidenceHash), `contract_source_evidence_hash_invalid:${contractRef}`);
  addReason(reasons, !CONTRACT_STATUSES.has(row?.status), `contract_status_invalid:${contractRef}`);
  addReason(reasons, policy?.requireTestsPassed === true && row?.testStatus !== 'passed', `contract_test_not_passed:${contractRef}`);
  addReason(
    reasons,
    policy?.requireFailClosedCoverage === true && row?.failClosedNegativeCoverage !== true,
    `contract_fail_closed_coverage_missing:${contractRef}`,
  );
  addReason(
    reasons,
    policy?.requireInactiveTrustState === true && row?.inactiveTrustState !== true,
    `contract_inactive_trust_missing:${contractRef}`,
  );
  addReason(
    reasons,
    policy?.requireNoExochainSourceEdits === true && row?.exochainSourceModified === true,
    `exochain_source_modified:${contractRef}`,
  );
  addReason(reasons, row?.metadataOnly !== true, `contract_metadata_boundary_missing:${contractRef}`);
  addReason(reasons, row?.protectedContentExcluded !== true, `contract_protected_boundary_missing:${contractRef}`);
  addReason(reasons, row?.productionTrustClaim === true, `contract_production_claim_forbidden:${contractRef}`);
  addReason(reasons, hlcTuple(row?.reviewedAtHlc) === null, `contract_review_hlc_invalid:${contractRef}`);
}

function evaluateContractRows(input, reasons) {
  const rows = Array.isArray(input?.contractRows) ? input.contractRows : [];
  const metaLayers = sortedTextList(rows.map((row) => row?.metaLayer));
  const contractKinds = sortedTextList(rows.map((row) => row?.contractKind));
  const contextRefs = uniqueSorted(rows.flatMap((row) => sortedTextList(row?.contextRefs)));

  addReason(reasons, rows.length === 0, 'contract_rows_absent');
  evaluateRequiredSet(metaLayers, REQUIRED_META_LAYERS, 'meta_layer_missing', 'meta_layer_unsupported', META_LAYER_SET, reasons);
  evaluateRequiredSet(
    contractKinds,
    REQUIRED_CONTRACT_KINDS,
    'contract_kind_missing',
    'contract_kind_unsupported',
    CONTRACT_KIND_SET,
    reasons,
  );
  evaluateRequiredSet(contextRefs, REQUIRED_CONTEXT_REFS, 'context_ref_missing', 'context_ref_unsupported', CONTEXT_REF_SET, reasons);

  for (const row of rows) {
    evaluateContractRow(row, input?.publicationPolicy, reasons);
  }

  return {
    rows,
    metaLayers: orderedCoveredValues(metaLayers, REQUIRED_META_LAYERS),
    contractKinds: orderedCoveredValues(contractKinds, REQUIRED_CONTRACT_KINDS),
    contextRefs: orderedCoveredValues(contextRefs, REQUIRED_CONTEXT_REFS),
  };
}

function evaluateValidationEvidence(validation, reasons) {
  const commandRefs = sortedTextList(validation?.commandRefs);

  for (const commandRef of REQUIRED_COMMAND_REFS) {
    addReason(reasons, !commandRefs.includes(commandRef), `validation_command_missing:${commandRef}`);
  }
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_failed');
  addReason(reasons, validation?.contractTestsPassed !== true, 'validation_contract_tests_failed');
  addReason(reasons, validation?.coverageGatePassed !== true, 'validation_coverage_gate_failed');
  addReason(reasons, validation?.secretScanPassed !== true, 'validation_secret_scan_failed');
  addReason(reasons, validation?.pathClassificationCurrent !== true, 'path_classification_not_current');
  addReason(reasons, !isDigest(validation?.validationHash), 'validation_hash_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_missing');
  addReason(reasons, validation?.protectedContentExcluded !== true, 'validation_protected_boundary_missing');
  addReason(reasons, hlcTuple(validation?.validatedAtHlc) === null, 'validation_hlc_invalid');
}

function evaluateHumanReview(review, validation, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_reviewer_did_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'human_review_ai_final_authority');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_claim_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_missing');
  addReason(reasons, review?.protectedContentExcluded !== true, 'human_review_protected_boundary_missing');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_hlc_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, validation?.validatedAtHlc), 'human_review_before_validation');
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === null || aiAssistance === undefined || aiAssistance?.used !== true) {
    return;
  }
  addReason(reasons, aiAssistance.finalAuthority === true, 'ai_assistance_final_authority_forbidden');
  addReason(reasons, !isDigest(aiAssistance.recommendationHash), 'ai_assistance_recommendation_hash_invalid');
  addReason(reasons, aiAssistance.metadataOnly !== true, 'ai_assistance_metadata_boundary_missing');
  addReason(reasons, aiAssistance.protectedContentExcluded !== true, 'ai_assistance_protected_boundary_missing');
}

function buildPublicationSummary(input, coverage, reasons) {
  const sortedContractRefs = coverage.rows.map((row) => row?.contractRef).filter(hasText).sort();
  const publicationHash = sha256Hex({
    schema: PUBLICATION_SCHEMA,
    tenantId: input?.tenantId ?? null,
    policyRef: input?.publicationPolicy?.policyRef ?? null,
    metaLayers: coverage.metaLayers,
    contractKinds: coverage.contractKinds,
    contextRefs: coverage.contextRefs,
    contractRefs: sortedContractRefs,
    validationHash: input?.validationEvidence?.validationHash ?? null,
    reviewHash: input?.humanReview?.reviewHash ?? null,
  });

  return {
    schema: PUBLICATION_SCHEMA,
    status: reasons.length === 0 ? 'publishable' : 'blocked',
    publicationHash,
    contractCount: coverage.rows.length,
    contractRefs: sortedContractRefs,
    metaLayers: coverage.metaLayers,
    contractKinds: coverage.contractKinds,
    contextRefs: coverage.contextRefs,
    sourceEvidenceRefs: SOURCE_EVIDENCE_REFS,
    metadataOnly: true,
    protectedContentExcluded: true,
    exochainProductionClaim: false,
    exochainSourceReadOnly: coverage.rows.every((row) => row?.exochainSourceModified !== true),
  };
}

function buildReceipt(input, publication) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'service_contract_publication',
    artifactVersion: `${input.publicationPolicy.policyRef}@${publication.status}`,
    artifactHash: publication.publicationHash,
    classification: 'confidential_metadata_only',
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    custodyDigest: input.custodyDigest,
    sensitivityTags: [
      'adjacent_surface',
      'baseline_service_contracts',
      'inactive_trust_state',
      'metadata_only',
    ],
    sourceSystem: 'cybermedica-qms',
  });
}

export function evaluateServiceContractPublication(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePublicationPolicy(input?.publicationPolicy, reasons);
  const coverage = evaluateContractRows(input, reasons);
  evaluateValidationEvidence(input?.validationEvidence, reasons);
  evaluateHumanReview(input?.humanReview, input?.validationEvidence, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const publication = buildPublicationSummary(input, coverage, unique);

  return {
    schema: PUBLICATION_DECISION_SCHEMA,
    decision: unique.length === 0 ? 'permitted' : 'denied',
    failClosed: unique.length > 0,
    reasons: unique,
    serviceContractPublication: publication,
    receipt: unique.length === 0 ? buildReceipt(input, publication) : null,
  };
}
