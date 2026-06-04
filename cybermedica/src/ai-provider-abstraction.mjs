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
const DECISION_SCHEMA = 'cybermedica.ai_provider_abstraction_decision.v1';
const REQUEST_SCHEMA = 'cybermedica.ai_provider_request.v1';
const REQUIRED_PERMISSION = 'ai_provider_boundary_review';
const ZERO_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

const PROVIDER_KINDS = new Set(['external_llm', 'hosted_model', 'rules_engine']);
const VERIFIED_STATUSES = new Set(['verified']);
const ENDPOINT_MODES = new Set(['server_side']);
const ALLOWED_USE_CASES = new Set([
  'ai_control_review',
  'audit_assessment_review',
  'decision_support_summary',
  'kpi_trend_analysis',
  'orientation_guidance',
  'reporting_export_explanation',
  'workflow_guidance',
]);
const ALLOWED_TOOL_SCOPES = new Set([
  'control_crosswalk_lookup',
  'documentation_section_lookup',
  'finding_recommendation_generation',
  'metadata_evidence_retrieval',
  'policy_metadata_lookup',
  'workflow_state_lookup',
]);

const RAW_PROVIDER_FIELDS = new Set([
  'freeformanswer',
  'freeformprompt',
  'freeformresponse',
  'inputpayload',
  'outputpayload',
  'promptbody',
  'prompttext',
  'providerresponsebody',
  'rawanswer',
  'rawcompletion',
  'rawinput',
  'rawoutput',
  'rawprompt',
  'rawproviderresponse',
  'rawrequest',
  'rawresponse',
  'reasoningtext',
  'responsebody',
  'sourcecontent',
  'sourcedocument',
  'sourcedocumentbody',
]);

const SECRET_PROVIDER_FIELDS = new Set([
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
  'servicetoken',
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

function assertNoRawProviderContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawProviderContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_PROVIDER_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw AI provider content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_PROVIDER_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`AI provider secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawProviderContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawProviderContent(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(value) {
  return Array.isArray(value) ? uniqueSorted(value) : [];
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

function hlcNotAfter(left, right) {
  const leftTuple = hlcTuple(left);
  const rightTuple = hlcTuple(right);
  return leftTuple !== null && rightTuple !== null && compareHlc(leftTuple, rightTuple) <= 0;
}

function hasAuthorityPermission(authority, permission) {
  return Array.isArray(authority?.permissions) && authority.permissions.includes(permission);
}

function uniqueReasons(reasons) {
  return [...new Set(reasons)].sort();
}

function evaluateTenantActorAuthority(input, reasons) {
  addReason(reasons, !hasText(input?.tenantId), 'tenant_absent');
  addReason(reasons, input?.tenantId !== input?.targetTenantId, 'tenant_boundary_violation');
  addReason(reasons, !hasText(input?.actor?.did), 'actor_did_absent');
  addReason(reasons, input?.actor?.kind === 'ai_agent', 'ai_final_authority_forbidden');
  addReason(reasons, input?.actor?.kind !== 'human', 'human_ai_provider_governor_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(reasons, !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION), 'authority_permission_missing');
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateProviderConfig(config, reasons) {
  addReason(reasons, !hasText(config?.providerRef), 'provider_ref_absent');
  addReason(reasons, !PROVIDER_KINDS.has(config?.providerKind), 'provider_kind_invalid');
  addReason(reasons, !VERIFIED_STATUSES.has(config?.bindingStatus), 'provider_binding_unverified');
  addReason(reasons, !ENDPOINT_MODES.has(config?.endpointMode), 'provider_endpoint_mode_invalid');
  addReason(reasons, config?.endpointMode !== 'server_side' || config?.noBrowserRuntime !== true, 'browser_authoritative_ai_path_forbidden');
  addReason(reasons, !isDigest(config?.modelRefHash), 'model_ref_hash_invalid');
  addReason(reasons, !isDigest(config?.modelVersionHash), 'model_version_hash_invalid');
  addReason(reasons, !isDigest(config?.modelConfigurationHash), 'model_configuration_hash_invalid');
  addReason(reasons, config?.configuredByHuman !== true, 'provider_human_configuration_absent');
  addReason(reasons, config?.noRootSecrets !== true, 'root_secret_scope_not_separated');
  addReason(reasons, config?.noSharedExochainCredentials !== true, 'shared_exochain_credentials_forbidden');
  addReason(reasons, !isDigest(config?.credentialVaultRefHash), 'credential_vault_ref_hash_invalid');
  addReason(reasons, !isDigest(config?.contractHash), 'provider_contract_hash_invalid');
  addReason(reasons, !isDigest(config?.dataProcessingAgreementHash), 'provider_dpa_hash_invalid');
  addReason(reasons, !isDigest(config?.zeroRetentionPolicyHash), 'zero_retention_policy_hash_invalid');
  addReason(reasons, !hasText(config?.tenantPolicyRef), 'tenant_ai_policy_ref_absent');
  addReason(reasons, !isDigest(config?.tenantPolicyHash), 'tenant_ai_policy_hash_invalid');
}

function evaluateRuntimeHealth(health, reasons) {
  addReason(reasons, !VERIFIED_STATUSES.has(health?.status), 'provider_runtime_not_verified');
  addReason(reasons, hlcTuple(health?.checkedAtHlc) === null, 'provider_runtime_check_time_invalid');
  addReason(reasons, !Number.isSafeInteger(health?.requestTimeoutMs) || health.requestTimeoutMs <= 0, 'provider_timeout_invalid');
  addReason(reasons, !isDigest(health?.retryPolicyHash), 'provider_retry_policy_hash_invalid');
  addReason(reasons, !isDigest(health?.telemetryBoundaryHash), 'provider_telemetry_boundary_hash_invalid');
}

function evaluateRequestPolicy(policy, reasons) {
  const allowedUseCases = sortedTextList(policy?.allowedUseCases);
  const allowedToolScopes = sortedTextList(policy?.allowedToolScopes);

  addReason(reasons, !hasText(policy?.policyRef), 'request_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.promptPolicyHash), 'prompt_policy_hash_invalid');
  addReason(reasons, !isDigest(policy?.inputBoundaryHash), 'input_boundary_hash_invalid');
  addReason(reasons, !isDigest(policy?.outputRetentionPolicyHash), 'output_retention_policy_hash_invalid');
  addReason(reasons, policy?.metadataOnlyInputs !== true, 'metadata_only_inputs_absent');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'protected_content_boundary_absent');
  addReason(reasons, policy?.providerMayTrainOnInputs !== false, 'provider_training_on_inputs_forbidden');
  addReason(reasons, policy?.rawPromptOrOutputStored !== false, 'raw_prompt_or_output_storage_forbidden');
  addReason(reasons, policy?.aiFinalAuthorityAllowed === true, 'policy_allows_ai_final_authority');
  addReason(reasons, allowedUseCases.length === 0, 'allowed_use_cases_absent');
  addReason(reasons, allowedToolScopes.length === 0, 'allowed_tool_scopes_absent');

  for (const useCase of allowedUseCases) {
    addReason(reasons, !ALLOWED_USE_CASES.has(useCase), `policy_use_case_unsupported:${useCase}`);
  }
  for (const scope of allowedToolScopes) {
    addReason(reasons, !ALLOWED_TOOL_SCOPES.has(scope), `policy_tool_scope_unsupported:${scope}`);
  }

  return {
    allowedToolScopes,
    allowedUseCases,
  };
}

function evaluateRequest(request, policySummary, reasons) {
  const evidenceRefs = sortedTextList(request?.evidenceRefs);
  const contextRefs = sortedTextList(request?.contextRefs);
  const toolScopes = sortedTextList(request?.toolScopes);

  addReason(reasons, !hasText(request?.requestId), 'request_id_absent');
  addReason(reasons, !hasText(request?.useCase), 'request_use_case_absent');
  addReason(
    reasons,
    hasText(request?.useCase) && !policySummary.allowedUseCases.includes(request.useCase),
    `request_use_case_not_allowed:${request?.useCase}`,
  );
  addReason(
    reasons,
    hasText(request?.useCase) && !ALLOWED_USE_CASES.has(request.useCase),
    `request_use_case_unsupported:${request?.useCase}`,
  );
  addReason(reasons, !isDigest(request?.promptManifestHash), 'request_prompt_manifest_hash_invalid');
  addReason(reasons, !isDigest(request?.inputManifestHash), 'request_input_manifest_hash_invalid');
  addReason(reasons, !isDigest(request?.outputSchemaHash), 'request_output_schema_hash_invalid');
  addReason(reasons, evidenceRefs.length === 0, 'request_evidence_refs_absent');
  addReason(reasons, contextRefs.length === 0, 'request_context_refs_absent');
  addReason(reasons, toolScopes.length === 0, 'request_tool_scopes_absent');
  for (const scope of toolScopes) {
    addReason(reasons, !policySummary.allowedToolScopes.includes(scope), `request_tool_scope_not_allowed:${scope}`);
    addReason(reasons, !ALLOWED_TOOL_SCOPES.has(scope), `request_tool_scope_unsupported:${scope}`);
  }
  addReason(reasons, hlcTuple(request?.requestedAtHlc) === null, 'request_time_invalid');
  addReason(reasons, hlcTuple(request?.responseDueAtHlc) === null, 'request_response_due_time_invalid');
  addReason(reasons, hlcNotAfter(request?.responseDueAtHlc, request?.requestedAtHlc), 'request_response_due_not_after_request');

  return {
    contextRefs,
    evidenceRefs,
    toolScopes,
  };
}

function evaluateHumanReviewGate(gate, reasons) {
  const reviewerRoles = sortedTextList(gate?.reviewerRoles);

  addReason(reasons, gate?.required !== true, 'human_review_gate_absent');
  addReason(reasons, reviewerRoles.length === 0, 'human_review_roles_absent');
  addReason(reasons, gate?.contestable !== true, 'human_review_contestation_absent');
  addReason(reasons, gate?.finalDecisionBy !== 'human', 'human_final_decision_absent');
  addReason(reasons, !isDigest(gate?.routeHash), 'human_review_route_hash_invalid');

  return {
    reviewerRoles,
  };
}

function buildProviderRequest(input, policySummary, requestSummary, humanReviewSummary) {
  const requestHash = sha256Hex({
    contextRefs: requestSummary.contextRefs,
    evidenceRefs: requestSummary.evidenceRefs,
    inputManifestHash: input.request.inputManifestHash,
    modelConfigurationHash: input.providerConfig.modelConfigurationHash,
    modelRefHash: input.providerConfig.modelRefHash,
    modelVersionHash: input.providerConfig.modelVersionHash,
    outputSchemaHash: input.request.outputSchemaHash,
    promptManifestHash: input.request.promptManifestHash,
    providerRef: input.providerConfig.providerRef,
    requestId: input.request.requestId,
    tenantId: input.tenantId,
    toolScopes: requestSummary.toolScopes,
    useCase: input.request.useCase,
  });

  return {
    schema: REQUEST_SCHEMA,
    requestId: input.request.requestId,
    tenantId: input.tenantId,
    providerRef: input.providerConfig.providerRef,
    providerKind: input.providerConfig.providerKind,
    providerBindingStatus: input.providerConfig.bindingStatus,
    endpointMode: input.providerConfig.endpointMode,
    modelRefHash: input.providerConfig.modelRefHash,
    modelVersionHash: input.providerConfig.modelVersionHash,
    modelConfigurationHash: input.providerConfig.modelConfigurationHash,
    useCase: input.request.useCase,
    policyRef: input.requestPolicy.policyRef,
    tenantPolicyRef: input.providerConfig.tenantPolicyRef,
    promptManifestHash: input.request.promptManifestHash,
    inputManifestHash: input.request.inputManifestHash,
    outputSchemaHash: input.request.outputSchemaHash,
    outputRetentionPolicyHash: input.requestPolicy.outputRetentionPolicyHash,
    allowedUseCases: policySummary.allowedUseCases,
    allowedToolScopes: policySummary.allowedToolScopes,
    evidenceRefs: requestSummary.evidenceRefs,
    contextRefs: requestSummary.contextRefs,
    toolScopes: requestSummary.toolScopes,
    humanReviewRoles: humanReviewSummary.reviewerRoles,
    metadataOnlyInputs: true,
    protectedContentExcluded: true,
    rawPromptOrOutputStored: false,
    providerMayTrainOnInputs: false,
    assistanceOnly: true,
    aiFinalAuthority: false,
    humanFinalAuthorityRequired: true,
    contestable: true,
    noBrowserRuntime: true,
    noRootSecrets: true,
    noSharedExochainCredentials: true,
    requestedAtHlc: input.request.requestedAtHlc,
    responseDueAtHlc: input.request.responseDueAtHlc,
    runtimeCheckedAtHlc: input.runtimeHealth.checkedAtHlc,
    requestHash,
    receiptId: null,
    trustState: 'inactive',
    exochainProductionClaim: false,
    operationalStateMutable: true,
    immutableProviderBoundaryReceipt: true,
  };
}

function buildReceipt(input, providerRequest) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: providerRequest.requestHash,
    artifactType: 'ai_provider_request_boundary',
    artifactVersion: input.request.requestId,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.request.requestedAtHlc,
    sensitivityTags: ['ai_provider', 'human_review_required', 'metadata_only', 'no_raw_prompt'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateAiProviderAbstraction(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluateProviderConfig(input?.providerConfig, reasons);
  evaluateRuntimeHealth(input?.runtimeHealth, reasons);
  const policySummary = evaluateRequestPolicy(input?.requestPolicy, reasons);
  const requestSummary = evaluateRequest(input?.request, policySummary, reasons);
  const humanReviewSummary = evaluateHumanReviewGate(input?.humanReviewGate, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const finalReasons = uniqueReasons(reasons);
  if (finalReasons.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: finalReasons,
      aiProviderRequest: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const aiProviderRequest = buildProviderRequest(input, policySummary, requestSummary, humanReviewSummary);
  const receipt = buildReceipt(input, aiProviderRequest);
  aiProviderRequest.receiptId = receipt.receiptId;

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    aiProviderRequest,
    receipt,
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
