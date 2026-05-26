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
const INTEGRATION_CONTRACT_SCHEMA = 'cybermedica.integration_contract_readiness.v1';
const INTEGRATION_CONTRACT_DECISION = 'cybermedica.integration_contract_readiness_decision.v1';
const REQUIRED_PERMISSION = 'integration_contract_review';

const REQUIRED_INTEGRATION_FAMILIES = Object.freeze([
  'ctms',
  'data_warehouse',
  'document_system',
  'econsent',
  'edc',
  'etmf',
  'hris',
  'identity_provider',
  'irb_system',
  'lms',
  'qms',
  'sponsor_portal',
]);

const REQUIRED_CONTRACT_EVIDENCE = Object.freeze([
  'access_policy',
  'authn_authz',
  'contract_fixture',
  'error_mapping',
  'fail_closed_negative_tests',
  'health_check',
  'idempotency_replay',
  'metadata_schema',
  'payload_boundary',
  'rate_limit',
  'rollback_disablement',
  'webhook_signature',
]);

const REQUIRED_DEPENDENCY_REFS = Object.freeze([
  'src/governed-integrations.mjs',
  'src/governed-api-access.mjs',
  'src/interoperability-readiness.mjs',
  'src/structured-data-exports.mjs',
]);

const FAMILY_SET = new Set(REQUIRED_INTEGRATION_FAMILIES);
const EVIDENCE_SET = new Set(REQUIRED_CONTRACT_EVIDENCE);
const DEPENDENCY_SET = new Set(REQUIRED_DEPENDENCY_REFS);
const POLICY_STATUSES = new Set(['active']);
const BOUNDARY_STATUSES = new Set(['contracted', 'implemented', 'verified']);
const DATA_FLOW_MODES = new Set(['bidirectional', 'inbound', 'outbound', 'read_only', 'write_only']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'hold_for_integration_contract_gap',
  'integration_contracts_ready_inactive_trust',
]);

const RAW_INTEGRATION_CONTRACT_FIELDS = new Set([
  'body',
  'connectorbody',
  'connectorpayload',
  'connectorrawpayload',
  'content',
  'debugpayload',
  'endpointrawresponse',
  'freetext',
  'freetextnote',
  'healthrawresponse',
  'integrationbody',
  'integrationpayload',
  'payloadbody',
  'rawbody',
  'rawcontent',
  'rawcontract',
  'rawendpointpayload',
  'rawfixture',
  'rawhealth',
  'rawpayload',
  'rawrequest',
  'rawresponse',
  'requestbody',
  'responsebody',
  'sourcebody',
  'sourcedocumentbody',
  'sourcedocumenttext',
  'sourcepayload',
  'validationlog',
  'webhookbody',
]);

const SECRET_INTEGRATION_CONTRACT_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'bootstrapsecret',
  'clientsecret',
  'connectorsecret',
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

const SOURCE_REFS = Object.freeze([
  'cybermedica_2_0_sandy_seven_layer_master_prd.md#Deployment Backlog',
  'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md',
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/implementation/PATH_CLASSIFICATION.md',
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

function assertNoRawIntegrationContractContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawIntegrationContractContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_INTEGRATION_CONTRACT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw integration contract payload field is not allowed at ${path}.${key}`);
    }
    if (SECRET_INTEGRATION_CONTRACT_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`integration contract secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawIntegrationContractContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawIntegrationContractContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_integration_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) &&
      !hasAuthorityPermission(input?.authority, 'manage_integrations') &&
      !hasAuthorityPermission(input?.authority, 'govern'),
    'integration_contract_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateContractPolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'contract_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'contract_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'contract_policy_not_active');
  addReason(reasons, !hasText(policy?.sourcePrdRef), 'contract_policy_source_prd_ref_absent');
  addReason(reasons, policy?.requireServerSideRuntime !== true, 'contract_policy_server_side_runtime_not_required');
  addReason(reasons, policy?.requireFailClosedBoundaries !== true, 'contract_policy_fail_closed_boundary_not_required');
  addReason(reasons, policy?.requireNoProductionTrustClaim !== true, 'contract_policy_trust_claim_guard_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'contract_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'contract_policy_protected_content_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'contract_policy_time_invalid');

  evaluateRequiredSet(
    sortedTextList(policy?.requiredIntegrationFamilies),
    REQUIRED_INTEGRATION_FAMILIES,
    'contract_policy_family_missing',
    'contract_policy_family_unsupported',
    FAMILY_SET,
    reasons,
  );
  evaluateRequiredSet(
    sortedTextList(policy?.requiredContractEvidence),
    REQUIRED_CONTRACT_EVIDENCE,
    'contract_policy_evidence_missing',
    'contract_policy_evidence_unsupported',
    EVIDENCE_SET,
    reasons,
  );
  evaluateRequiredSet(
    sortedTextList(policy?.requiredDependencyRefs),
    REQUIRED_DEPENDENCY_REFS,
    'contract_policy_dependency_missing',
    'contract_policy_dependency_unsupported',
    DEPENDENCY_SET,
    reasons,
  );
}

function evaluateDependencyReadiness(readiness, reasons) {
  addReason(reasons, !hasText(readiness?.readinessRef), 'dependency_readiness_ref_absent');
  addReason(reasons, !isDigest(readiness?.readinessHash), 'dependency_readiness_hash_invalid');
  addReason(reasons, readiness?.governedIntegrationsReady !== true, 'dependency_governed_integrations_not_ready');
  addReason(reasons, readiness?.governedApiAccessReady !== true, 'dependency_governed_api_access_not_ready');
  addReason(reasons, readiness?.interoperabilityReady !== true, 'dependency_interoperability_not_ready');
  addReason(reasons, readiness?.structuredExportsReady !== true, 'dependency_structured_exports_not_ready');
  addReason(reasons, readiness?.metadataOnly !== true, 'dependency_readiness_metadata_boundary_invalid');
  addReason(reasons, readiness?.protectedContentExcluded !== true, 'dependency_readiness_protected_content_boundary_invalid');
  addReason(reasons, hlcTuple(readiness?.reviewedAtHlc) === null, 'dependency_readiness_time_invalid');
  addReason(
    reasons,
    hlcBefore(readiness?.reviewedAtHlc, readiness?.policyEvaluatedAtHlc),
    'dependency_readiness_before_policy_review',
  );

  evaluateRequiredSet(
    sortedTextList(readiness?.refs),
    REQUIRED_DEPENDENCY_REFS,
    'dependency_ref_missing',
    'dependency_ref_unsupported',
    DEPENDENCY_SET,
    reasons,
  );
}

function boundaryIdentity(boundary) {
  return hasText(boundary?.family) ? boundary.family : 'unclassified_integration';
}

function evaluateBoundaryEvidence(boundary, family, policy, reasons) {
  const requiredEvidence = sortedTextList(policy?.requiredContractEvidence);
  const required = requiredEvidence.length > 0 ? requiredEvidence : REQUIRED_CONTRACT_EVIDENCE;
  const actual = sortedTextList((Array.isArray(boundary?.contractEvidence) ? boundary.contractEvidence : []).map((item) => item.evidenceType));

  for (const evidenceType of required) {
    addReason(reasons, !actual.includes(evidenceType), `contract_evidence_missing:${family}:${evidenceType}`);
  }
  for (const evidenceType of actual) {
    addReason(reasons, !EVIDENCE_SET.has(evidenceType), `contract_evidence_unsupported:${family}:${evidenceType}`);
  }

  for (const evidence of Array.isArray(boundary?.contractEvidence) ? boundary.contractEvidence : []) {
    const evidenceType = hasText(evidence?.evidenceType) ? evidence.evidenceType : 'unclassified_evidence';
    addReason(reasons, !hasText(evidence?.evidenceRef), `contract_evidence_ref_absent:${family}:${evidenceType}`);
    addReason(reasons, !isDigest(evidence?.evidenceHash), `contract_evidence_hash_invalid:${family}:${evidenceType}`);
    addReason(reasons, evidence?.status !== 'verified', `contract_evidence_not_verified:${family}:${evidenceType}`);
    addReason(reasons, evidence?.metadataOnly !== true, `contract_evidence_metadata_boundary_invalid:${family}:${evidenceType}`);
    addReason(
      reasons,
      evidence?.protectedContentExcluded !== true,
      `contract_evidence_protected_content_boundary_invalid:${family}:${evidenceType}`,
    );
  }
}

function evaluateBoundary(boundary, policy, reasons) {
  const family = boundaryIdentity(boundary);
  addReason(reasons, !hasText(boundary?.family), 'integration_family_absent');
  addReason(reasons, !FAMILY_SET.has(boundary?.family), `integration_family_unsupported:${family}`);
  addReason(reasons, !hasText(boundary?.boundaryRef), `boundary_ref_absent:${family}`);
  addReason(reasons, !hasText(boundary?.ownerRoleRef), `boundary_owner_role_absent:${family}`);
  addReason(reasons, !hasText(boundary?.systemRef), `boundary_system_ref_absent:${family}`);
  addReason(reasons, !hasText(boundary?.endpointRouteRef), `boundary_endpoint_route_absent:${family}`);
  addReason(reasons, !hasText(boundary?.authPolicyRef), `boundary_auth_policy_absent:${family}`);
  addReason(reasons, !isDigest(boundary?.contractHash), `boundary_contract_hash_invalid:${family}`);
  addReason(reasons, !isDigest(boundary?.fixtureHash), `boundary_fixture_hash_invalid:${family}`);
  addReason(reasons, !isDigest(boundary?.negativeTestHash), `boundary_negative_test_hash_invalid:${family}`);
  addReason(reasons, !isDigest(boundary?.healthCheckHash), `boundary_health_check_hash_invalid:${family}`);
  addReason(reasons, !hasText(boundary?.rollbackRef), `boundary_rollback_ref_absent:${family}`);
  addReason(reasons, !DATA_FLOW_MODES.has(boundary?.dataFlowMode), `boundary_data_flow_mode_invalid:${family}`);
  addReason(reasons, boundary?.runtimeLocation !== 'server_side', `boundary_runtime_not_server_side:${family}`);
  addReason(reasons, !BOUNDARY_STATUSES.has(boundary?.status), `boundary_status_invalid:${family}`);
  addReason(reasons, !hasText(boundary?.governedIntegrationRef), `boundary_governed_integration_ref_absent:${family}`);
  addReason(reasons, !hasText(boundary?.governedApiAccessRef), `boundary_governed_api_access_ref_absent:${family}`);
  addReason(reasons, !hasText(boundary?.interoperabilityRef), `boundary_interoperability_ref_absent:${family}`);
  addReason(reasons, !hasText(boundary?.structuredExportRef), `boundary_structured_export_ref_absent:${family}`);
  addReason(reasons, boundary?.failClosedOnUnavailable !== true, `boundary_unavailable_not_fail_closed:${family}`);
  addReason(reasons, boundary?.failClosedOnTimeout !== true, `boundary_timeout_not_fail_closed:${family}`);
  addReason(reasons, boundary?.failClosedOnMalformedResponse !== true, `boundary_malformed_response_not_fail_closed:${family}`);
  addReason(reasons, boundary?.failClosedOnRejectedDecision !== true, `boundary_rejected_decision_not_fail_closed:${family}`);
  addReason(reasons, boundary?.tenantScoped !== true, `boundary_tenant_scope_absent:${family}`);
  addReason(reasons, boundary?.serviceAccountHumanOwnerRequired !== true, `boundary_service_account_owner_absent:${family}`);
  addReason(reasons, boundary?.secretsExternalized !== true, `boundary_secret_externalization_absent:${family}`);
  addReason(reasons, boundary?.rawPayloadLoggingDisabled !== true, `boundary_raw_payload_logging_enabled:${family}`);
  addReason(reasons, boundary?.metadataOnly !== true, `boundary_metadata_boundary_invalid:${family}`);
  addReason(reasons, boundary?.protectedContentExcluded !== true, `boundary_protected_content_boundary_invalid:${family}`);
  addReason(reasons, hlcTuple(boundary?.lastReviewedAtHlc) === null, `boundary_review_time_invalid:${family}`);
  addReason(reasons, hlcBefore(boundary?.lastReviewedAtHlc, policy?.evaluatedAtHlc), `boundary_review_before_policy:${family}`);

  evaluateBoundaryEvidence(boundary, family, policy, reasons);
}

function evaluateIntegrationBoundaries(boundaries, policy, reasons) {
  addReason(reasons, !Array.isArray(boundaries) || boundaries.length === 0, 'integration_boundaries_absent');
  const list = Array.isArray(boundaries) ? boundaries : [];
  const families = uniqueSorted(list.map((boundary) => boundary?.family));
  const requiredFamilies = sortedTextList(policy?.requiredIntegrationFamilies);
  const required = requiredFamilies.length > 0 ? requiredFamilies : REQUIRED_INTEGRATION_FAMILIES;

  for (const family of required) {
    addReason(reasons, !families.includes(family), `integration_family_missing:${family}`);
  }
  for (const family of families) {
    addReason(reasons, !FAMILY_SET.has(family), `integration_family_unsupported:${family}`);
  }
  for (const boundary of list) {
    evaluateBoundary(boundary, policy, reasons);
  }
}

function evaluateValidationEvidence(input, reasons) {
  const evidence = input?.validationEvidence;
  addReason(reasons, evidence?.contractTestsPassed !== true, 'validation_contract_tests_not_passed');
  addReason(reasons, evidence?.negativePathTestsPassed !== true, 'validation_negative_path_tests_not_passed');
  addReason(reasons, evidence?.sourceGuardPassed !== true, 'validation_source_guard_not_passed');
  addReason(reasons, evidence?.privacyFixturePassed !== true, 'validation_privacy_fixture_not_passed');
  addReason(reasons, evidence?.tenantIsolationPassed !== true, 'validation_tenant_isolation_not_passed');
  addReason(reasons, evidence?.replayProtectionPassed !== true, 'validation_replay_protection_not_passed');
  addReason(reasons, !isDigest(evidence?.validationHash), 'validation_hash_invalid');
  addReason(reasons, evidence?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, evidence?.protectedContentExcluded !== true, 'validation_protected_content_boundary_invalid');
  addReason(reasons, hlcTuple(evidence?.validatedAtHlc) === null, 'validation_time_invalid');
  addReason(
    reasons,
    hlcBefore(evidence?.validatedAtHlc, input?.contractPolicy?.evaluatedAtHlc),
    'validation_before_policy_review',
  );

  const commandRefs = sortedTextList(evidence?.commandRefs);
  addReason(
    reasons,
    !commandRefs.includes('node --test tests/integration-contract-readiness.test.mjs'),
    'validation_contract_test_command_absent',
  );
  addReason(reasons, !commandRefs.includes('node --test tests/source-guards.test.mjs'), 'validation_source_guard_command_absent');
}

function evaluateHumanReview(input, reasons) {
  const review = input?.humanReview;
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, review?.aiFinalAuthority === true, 'human_review_ai_final_authority_forbidden');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_claim_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, review?.protectedContentExcluded !== true, 'human_review_protected_content_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(
    reasons,
    hlcBefore(review?.reviewedAtHlc, input?.validationEvidence?.validatedAtHlc),
    'human_review_before_validation',
  );
}

function evaluateAiAssistance(aiAssistance, reasons) {
  if (aiAssistance === undefined || aiAssistance === null || aiAssistance?.used === false) {
    return;
  }
  addReason(reasons, aiAssistance?.finalAuthority === true, 'ai_assistance_final_authority_forbidden');
  addReason(reasons, aiAssistance?.metadataOnly !== true, 'ai_assistance_metadata_boundary_invalid');
  addReason(reasons, aiAssistance?.protectedContentExcluded !== true, 'ai_assistance_protected_content_boundary_invalid');
}

function buildReadiness(input, reasons) {
  const boundaryFamilies = uniqueSorted(
    (Array.isArray(input?.integrationBoundaries) ? input.integrationBoundaries : [])
      .map((boundary) => boundary?.family)
      .filter((family) => FAMILY_SET.has(family)),
  );
  const actualEvidenceTypes = uniqueSorted(
    (Array.isArray(input?.integrationBoundaries) ? input.integrationBoundaries : []).flatMap((boundary) =>
      Array.isArray(boundary?.contractEvidence) ? boundary.contractEvidence.map((evidence) => evidence?.evidenceType) : [],
    ),
  );
  const status = reasons.length === 0 ? 'ready' : 'blocked';

  const summary = {
    schema: INTEGRATION_CONTRACT_SCHEMA,
    status,
    policyRef: hasText(input?.contractPolicy?.policyRef) ? input.contractPolicy.policyRef : null,
    sourcePrdRef: hasText(input?.contractPolicy?.sourcePrdRef) ? input.contractPolicy.sourcePrdRef : null,
    boundaryCount: boundaryFamilies.length,
    integrationFamilies: [...REQUIRED_INTEGRATION_FAMILIES],
    missingIntegrationFamilies: REQUIRED_INTEGRATION_FAMILIES.filter((family) => !boundaryFamilies.includes(family)),
    contractEvidenceTypes: [...REQUIRED_CONTRACT_EVIDENCE],
    missingContractEvidenceTypes: REQUIRED_CONTRACT_EVIDENCE.filter((evidenceType) => !actualEvidenceTypes.includes(evidenceType)),
    dependencyRefs: [...REQUIRED_DEPENDENCY_REFS],
    serverSideRuntimeRequired: input?.contractPolicy?.requireServerSideRuntime === true,
    failClosedBoundariesRequired: input?.contractPolicy?.requireFailClosedBoundaries === true,
    trustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: input?.contractPolicy?.metadataOnly === true,
    protectedContentExcluded: input?.contractPolicy?.protectedContentExcluded === true,
    sourceRefs: SOURCE_REFS,
    reasons: uniqueReasons(reasons),
  };

  return {
    ...summary,
    readinessHash: sha256Hex(summary),
  };
}

function buildReceipt(input, readiness) {
  return createEvidenceReceipt({
    tenantId: input.tenantId,
    actorDid: input.actor.did,
    artifactType: 'integration_contract_readiness',
    artifactVersion: `deployment-integration-contracts:${input.contractPolicy.policyRef}`,
    artifactHash: readiness.readinessHash,
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    classification: 'deployment_integration_contract_metadata_only',
    sensitivityTags: [
      'integration_contract_metadata',
      'deployment_backlog',
      'no_raw_payloads',
      'inactive_trust',
    ],
    sourceSystem: 'cybermedica.integration_contract_readiness',
  });
}

function buildDeniedResponse(input, reasons, readiness) {
  return {
    schema: INTEGRATION_CONTRACT_DECISION,
    decision: 'denied',
    failClosed: true,
    trustState: 'inactive',
    exochainProductionClaim: false,
    reasons: uniqueReasons(reasons),
    integrationContractReadiness: readiness,
    receipt: null,
    sourceEvidence: SOURCE_REFS,
  };
}

export function evaluateIntegrationContractReadiness(input) {
  assertMetadataOnly(input ?? {});

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateContractPolicy(input?.contractPolicy, reasons);
  evaluateDependencyReadiness(
    {
      ...(input?.dependencyReadiness ?? {}),
      policyEvaluatedAtHlc: input?.contractPolicy?.evaluatedAtHlc,
    },
    reasons,
  );
  evaluateIntegrationBoundaries(input?.integrationBoundaries, input?.contractPolicy, reasons);
  evaluateValidationEvidence(input, reasons);
  evaluateHumanReview(input, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  const readiness = buildReadiness(input, unique);
  if (unique.length > 0) {
    return buildDeniedResponse(input, unique, readiness);
  }

  return {
    schema: INTEGRATION_CONTRACT_DECISION,
    decision: 'permitted',
    failClosed: false,
    trustState: 'inactive',
    exochainProductionClaim: false,
    reasons: [],
    integrationContractReadiness: readiness,
    receipt: buildReceipt(input, readiness),
    sourceEvidence: SOURCE_REFS,
  };
}
