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
const PROVIDER_BINDING_SCHEMA = 'cybermedica.deployment_provider_binding.v1';
const DECISION_SCHEMA = 'cybermedica.deployment_provider_binding_decision.v1';
const REQUIRED_PERMISSION = 'deployment_provider_binding_review';

const REQUIRED_BINDING_DOMAINS = Object.freeze([
  'deployment_owner',
  'dns_tls_binding',
  'environment_binding',
  'health_readiness',
  'monitoring_linkage',
  'project_binding',
  'provider_account',
  'rollback_binding',
  'root_bundle_provider_binding',
  'runtime_adapter_binding',
  'secret_scope_binding',
  'service_binding',
]);

const DEFAULT_ALLOWED_ACTIVATION_BLOCKER_IDS = Object.freeze([
  'ESC-OPS-SECRETS',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-RUNTIME',
]);

const REQUIRED_DRIFT_STATE_TARGETS = Object.freeze(['passport', 'quality_state', 'readiness']);
const REQUIRED_ROLE_DASHBOARD_ROLES = Object.freeze([
  'auditor',
  'coordinator',
  'cro_portfolio_manager',
  'decision_forum',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_viewer',
]);

const POLICY_STATUSES = new Set(['active']);
const DOMAIN_STATUSES = new Set(['activation_blocked', 'ready']);
const OPERATIONS_READINESS_STATUSES = new Set(['deployment_operations_readiness_accepted_inactive_trust']);
const DEPLOYMENT_READINESS_MANIFEST_STATUSES = new Set(['deployment_readiness_manifest_accepted_inactive_trust']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'provider_binding_ready',
  'provider_binding_ready_with_activation_blockers',
]);

const RAW_PROVIDER_FIELDS = new Set([
  'body',
  'content',
  'deploymentnotes',
  'freetext',
  'freetextnote',
  'providerlog',
  'providernotes',
  'rawdeploymentconfig',
  'rawdeploymentcontent',
  'rawdeploymentlog',
  'rawhealthresponse',
  'rawprovidercontent',
  'rawproviderlog',
  'rawproviderstatus',
  'rawruntimeconfig',
  'rawvalidationoutput',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_PROVIDER_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'bearertoken',
  'clientsecret',
  'credential',
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
      throw new ProtectedContentError(`raw deployment provider content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_PROVIDER_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`deployment provider secret field is not allowed at ${path}.${key}`);
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_deployment_provider_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'deployment_provider_binding_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateProviderPolicy(policy, reasons) {
  const allowedProviders = sortedTextList(policy?.allowedProviders);
  const requiredBindingDomains = sortedTextList(policy?.requiredBindingDomains);
  const allowedActivationBlockerIds = sortedTextList(policy?.allowedActivationBlockerIds);

  addReason(reasons, !hasText(policy?.policyRef), 'provider_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'provider_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'provider_policy_not_active');
  addReason(reasons, allowedProviders.length === 0, 'provider_policy_allowed_providers_absent');
  addReason(reasons, policy?.rootVerificationRequiredForTrustClaims !== true, 'root_verification_gate_absent');
  addReason(reasons, policy?.noCredentialDisclosure !== true, 'credential_disclosure_guard_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'provider_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'provider_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'provider_policy_time_invalid');

  evaluateRequiredSet(
    requiredBindingDomains,
    REQUIRED_BINDING_DOMAINS,
    'policy_binding_domain_missing',
    'policy_binding_domain_unsupported',
    reasons,
  );

  return {
    allowedActivationBlockerIds:
      allowedActivationBlockerIds.length > 0
        ? allowedActivationBlockerIds
        : [...DEFAULT_ALLOWED_ACTIVATION_BLOCKER_IDS],
    allowedProviders,
    requiredBindingDomains:
      requiredBindingDomains.length > 0 ? requiredBindingDomains : [...REQUIRED_BINDING_DOMAINS],
  };
}

function evaluateBindingCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.bindingRef), 'binding_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'binding_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'binding_cycle_protected_boundary_invalid');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['evidenceCollectedAtHlc', cycle?.evidenceCollectedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
    ['humanReviewedAtHlc', cycle?.humanReviewedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `binding_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'provider_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(
      reasons,
      hlcBefore(currentValue, previousValue),
      `binding_cycle_${currentLabel}_before_${previousLabel}`,
    );
  }
}

function providerBindingStatus(binding) {
  if (
    binding?.provider === 'railway' &&
    binding?.endpointSelected === true &&
    binding?.projectLinked === true &&
    binding?.serviceBound === true &&
    binding?.environmentBound === true &&
    binding?.dashboardAccessVerified === true &&
    binding?.providerHealthVerified === true &&
    isDigest(binding?.workspaceHash) &&
    isDigest(binding?.projectHash) &&
    isDigest(binding?.serviceHash) &&
    isDigest(binding?.environmentHash) &&
    isDigest(binding?.domainHash) &&
    isDigest(binding?.publicEndpointHash)
  ) {
    return 'verified';
  }
  if (binding?.provider === 'railway' && binding?.endpointSelected !== true) {
    return 'login_required';
  }
  return 'unverified';
}

function evaluateProviderBinding(binding, policySummary, cycle, reasons) {
  addReason(reasons, binding === null || binding === undefined, 'provider_binding_absent');
  addReason(reasons, !hasText(binding?.provider), 'provider_absent');
  addReason(
    reasons,
    hasText(binding?.provider) && !policySummary.allowedProviders.includes(binding.provider),
    `provider_not_allowed:${binding?.provider}`,
  );
  addReason(reasons, !isDigest(binding?.accountHash), 'provider_account_hash_invalid');
  addReason(reasons, typeof binding?.endpointSelected !== 'boolean', 'provider_endpoint_selected_state_invalid');
  addReason(reasons, typeof binding?.projectLinked !== 'boolean', 'provider_project_link_state_invalid');
  addReason(reasons, typeof binding?.serviceBound !== 'boolean', 'provider_service_bound_state_invalid');
  addReason(reasons, typeof binding?.environmentBound !== 'boolean', 'provider_environment_bound_state_invalid');
  addReason(reasons, typeof binding?.dashboardAccessVerified !== 'boolean', 'provider_dashboard_state_invalid');
  addReason(reasons, typeof binding?.providerHealthVerified !== 'boolean', 'provider_health_state_invalid');
  addReason(reasons, binding?.credentialShared === true, 'provider_credential_disclosed');
  addReason(reasons, binding?.tokenStored === true, 'provider_token_stored');
  addReason(reasons, binding?.metadataOnly !== true, 'provider_binding_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(binding?.checkedAtHlc) === null, 'provider_binding_check_time_invalid');
  addReason(reasons, hlcBefore(binding?.checkedAtHlc, cycle?.evidenceCollectedAtHlc), 'provider_binding_check_before_evidence_collection');

  const status = providerBindingStatus(binding);
  if (binding?.endpointSelected === true && status !== 'verified') {
    addReason(reasons, true, 'endpoint_selected_without_verified_provider');
  }
  if (status === 'verified') {
    addReason(reasons, !isDigest(binding?.workspaceHash), 'provider_workspace_hash_invalid');
    addReason(reasons, !isDigest(binding?.projectHash), 'provider_project_hash_invalid');
    addReason(reasons, !isDigest(binding?.serviceHash), 'provider_service_hash_invalid');
    addReason(reasons, !isDigest(binding?.environmentHash), 'provider_environment_hash_invalid');
    addReason(reasons, !isDigest(binding?.domainHash), 'provider_domain_hash_invalid');
    addReason(reasons, !isDigest(binding?.publicEndpointHash), 'provider_public_endpoint_hash_invalid');
  }

  return {
    accountHash: binding?.accountHash ?? null,
    bindingStatus: status,
    credentialShared: binding?.credentialShared === true,
    dashboardAccessVerified: binding?.dashboardAccessVerified === true,
    domainHash: binding?.domainHash ?? null,
    endpointSelected: binding?.endpointSelected === true,
    environmentBound: binding?.environmentBound === true,
    environmentHash: binding?.environmentHash ?? null,
    projectHash: binding?.projectHash ?? null,
    projectLinked: binding?.projectLinked === true,
    provider: binding?.provider ?? null,
    providerHealthVerified: binding?.providerHealthVerified === true,
    publicEndpointHash: binding?.publicEndpointHash ?? null,
    serviceBound: binding?.serviceBound === true,
    serviceHash: binding?.serviceHash ?? null,
    tokenStored: binding?.tokenStored === true,
    workspaceHash: binding?.workspaceHash ?? null,
  };
}

function evaluateRuntimeBinding(runtime, cycle, reasons) {
  addReason(reasons, runtime === null || runtime === undefined, 'runtime_binding_absent');
  addReason(reasons, !hasText(runtime?.topologyRef), 'runtime_topology_ref_absent');
  addReason(reasons, !isDigest(runtime?.topologyHash), 'runtime_topology_hash_invalid');
  addReason(reasons, !isDigest(runtime?.gatewayAdapterHash), 'gateway_adapter_hash_invalid');
  addReason(reasons, !isDigest(runtime?.nodeReceiptAdapterHash), 'node_receipt_adapter_hash_invalid');
  addReason(reasons, !isDigest(runtime?.decisionForumAdapterHash), 'decision_forum_adapter_hash_invalid');
  addReason(reasons, runtime?.browserAuthoritativePathEnabled === true, 'browser_authoritative_path_forbidden');
  addReason(reasons, runtime?.healthEndpointSeparatesProcessAndTrust !== true, 'health_trust_separation_absent');
  addReason(reasons, runtime?.unavailableAdaptersFailClosed !== true, 'adapter_unavailable_fail_closed_absent');
  addReason(reasons, runtime?.receiptPayloadBoundaryVerified !== true, 'receipt_payload_boundary_absent');
  addReason(reasons, runtime?.productionTrustClaim === true, 'runtime_production_trust_claim_forbidden');
  addReason(reasons, runtime?.metadataOnly !== true, 'runtime_binding_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(runtime?.checkedAtHlc) === null, 'runtime_binding_check_time_invalid');
  addReason(reasons, hlcAfter(runtime?.checkedAtHlc, cycle?.validationRecordedAtHlc), 'runtime_binding_check_after_validation');

  if (runtime?.rootBundleProviderVerified === true) {
    addReason(reasons, !isDigest(runtime?.rootBundleProviderHash), 'root_bundle_provider_hash_invalid');
  }

  return {
    browserAuthoritativePathEnabled: runtime?.browserAuthoritativePathEnabled === true,
    decisionForumAdapterHash: runtime?.decisionForumAdapterHash ?? null,
    gatewayAdapterHash: runtime?.gatewayAdapterHash ?? null,
    healthEndpointSeparatesProcessAndTrust: runtime?.healthEndpointSeparatesProcessAndTrust === true,
    nodeReceiptAdapterHash: runtime?.nodeReceiptAdapterHash ?? null,
    receiptPayloadBoundaryVerified: runtime?.receiptPayloadBoundaryVerified === true,
    rootBundleProviderHash: runtime?.rootBundleProviderHash ?? null,
    rootBundleProviderVerified: runtime?.rootBundleProviderVerified === true,
    topologyHash: runtime?.topologyHash ?? null,
    topologyRef: runtime?.topologyRef ?? null,
    unavailableAdaptersFailClosed: runtime?.unavailableAdaptersFailClosed === true,
  };
}

function evaluateBindingDomains(bindingDomains, policySummary, cycle, reasons) {
  addReason(reasons, !Array.isArray(bindingDomains) || bindingDomains.length === 0, 'binding_domains_absent');
  if (!Array.isArray(bindingDomains)) {
    return { blockerIds: [], domains: [], summaries: [] };
  }

  const domains = sortedTextList(bindingDomains.map((entry) => entry?.domain));
  const blockerIds = [];
  const summaries = [];
  const seenDomains = new Set();

  evaluateRequiredSet(
    domains,
    policySummary.requiredBindingDomains,
    'binding_domain_missing',
    'binding_domain_unsupported',
    reasons,
  );

  bindingDomains.forEach((entry, index) => {
    const label = hasText(entry?.domain) ? entry.domain : `index_${index}`;
    addReason(reasons, !hasText(entry?.domain), `binding_domain_absent:${label}`);
    addReason(reasons, seenDomains.has(entry?.domain), `binding_domain_duplicate:${label}`);
    if (hasText(entry?.domain)) {
      seenDomains.add(entry.domain);
    }
    addReason(reasons, !DOMAIN_STATUSES.has(entry?.status), `binding_domain_status_invalid:${label}`);
    addReason(reasons, !hasText(entry?.evidenceRef), `binding_domain_evidence_ref_absent:${label}`);
    addReason(reasons, !isDigest(entry?.evidenceHash), `binding_domain_evidence_hash_invalid:${label}`);
    addReason(reasons, !hasText(entry?.ownerDid), `binding_domain_owner_absent:${label}`);
    addReason(reasons, entry?.blocksBaselineDevelopment === true, `binding_domain_blocks_baseline:${label}`);
    addReason(
      reasons,
      entry?.status === 'activation_blocked' && entry?.productionActivationOnly !== true,
      `binding_domain_activation_scope_invalid:${label}`,
    );
    addReason(
      reasons,
      entry?.status === 'activation_blocked' && !hasText(entry?.activationBlockerId),
      `binding_domain_activation_blocker_absent:${label}`,
    );
    addReason(reasons, entry?.reviewedByHuman !== true, `binding_domain_human_review_absent:${label}`);
    addReason(reasons, hlcTuple(entry?.reviewedAtHlc) === null, `binding_domain_review_time_invalid:${label}`);
    addReason(reasons, hlcAfter(entry?.reviewedAtHlc, cycle?.validationRecordedAtHlc), `binding_domain_review_after_validation:${label}`);
    addReason(reasons, entry?.metadataOnly !== true, `binding_domain_metadata_boundary_invalid:${label}`);
    addReason(reasons, entry?.protectedContentExcluded !== true, `binding_domain_protected_boundary_invalid:${label}`);
    addReason(reasons, entry?.productionTrustClaim === true, `binding_domain_production_claim_forbidden:${label}`);

    if (hasText(entry?.activationBlockerId)) {
      blockerIds.push(entry.activationBlockerId);
    }
    summaries.push({
      activationBlockerId: entry?.activationBlockerId ?? null,
      domain: label,
      evidenceHash: entry?.evidenceHash ?? null,
      evidenceRef: entry?.evidenceRef ?? null,
      ownerDid: entry?.ownerDid ?? null,
      status: entry?.status ?? 'invalid',
    });
  });

  return {
    blockerIds: uniqueSorted(blockerIds),
    domains,
    summaries: summaries.sort((left, right) => left.domain.localeCompare(right.domain)),
  };
}

function evaluateOperationsReadiness(readiness, policySummary, cycle, reasons) {
  addReason(reasons, readiness === null || readiness === undefined, 'operations_readiness_absent');
  addReason(reasons, !hasText(readiness?.operationsReadinessRef), 'operations_readiness_ref_absent');
  addReason(reasons, !isDigest(readiness?.operationsReadinessHash), 'operations_readiness_hash_invalid');
  addReason(reasons, !isDigest(readiness?.receiptHash), 'operations_readiness_receipt_hash_invalid');
  addReason(
    reasons,
    readiness?.receiptArtifactType !== 'deployment_operations_readiness',
    'operations_readiness_receipt_type_invalid',
  );
  addReason(reasons, !OPERATIONS_READINESS_STATUSES.has(readiness?.status), 'operations_readiness_status_invalid');
  addReason(
    reasons,
    readiness?.releaseCandidateRef !== cycle?.releaseCandidateRef,
    'operations_readiness_release_candidate_mismatch',
  );
  addReason(
    reasons,
    !isDigest(readiness?.releaseIncidentLinkageReceiptHash),
    'operations_readiness_release_incident_receipt_hash_invalid',
  );
  addReason(reasons, readiness?.baselineOperationsPackReady !== true, 'baseline_operations_pack_not_ready');
  addReason(
    reasons,
    !['login_required', 'unverified', 'verified'].includes(readiness?.railwayLoginStatus),
    'operations_railway_status_invalid',
  );
  addReason(reasons, readiness?.metadataOnly !== true, 'operations_readiness_metadata_boundary_invalid');
  addReason(reasons, readiness?.protectedContentExcluded !== true, 'operations_readiness_protected_boundary_invalid');
  addReason(reasons, readiness?.productionTrustClaim === true, 'operations_readiness_production_claim_forbidden');
  addReason(reasons, hlcTuple(readiness?.reviewedAtHlc) === null, 'operations_readiness_review_time_invalid');
  addReason(reasons, hlcAfter(readiness?.reviewedAtHlc, cycle?.validationRecordedAtHlc), 'operations_readiness_after_validation');

  const blockerIds = sortedTextList(readiness?.activationBlockerIds);
  for (const blockerId of blockerIds) {
    addReason(
      reasons,
      !policySummary.allowedActivationBlockerIds.includes(blockerId),
      `operations_blocker_not_allowed:${blockerId}`,
    );
  }

  const roleDashboardTrustStateEvidence = evaluateRoleDashboardTrustStateEvidence(
    readiness?.roleDashboardTrustStateEvidence,
    readiness,
    reasons,
    'operations_readiness_role_dashboard',
    'operations_review',
  );

  return {
    blockerIds,
    baselineOperationsPackReady: readiness?.baselineOperationsPackReady === true,
    operationsReadinessHash: readiness?.operationsReadinessHash ?? null,
    operationsReadinessRef: readiness?.operationsReadinessRef ?? null,
    productionOperationsReady: readiness?.productionOperationsReady === true,
    railwayLoginStatus: readiness?.railwayLoginStatus ?? 'invalid',
    receiptArtifactType: readiness?.receiptArtifactType ?? null,
    receiptHash: readiness?.receiptHash ?? null,
    releaseCandidateRef: readiness?.releaseCandidateRef ?? null,
    releaseIncidentLinkageReceiptHash: readiness?.releaseIncidentLinkageReceiptHash ?? null,
    roleDashboardTrustStateEvidence,
    status: readiness?.status ?? 'invalid',
  };
}

function evaluateDeploymentReadinessDriftStateUpdateEvidence(evidence, manifest, reasons) {
  addReason(reasons, evidence === null || evidence === undefined, 'deployment_readiness_drift_evidence_absent');
  addReason(reasons, !hasText(evidence?.driftLoopId), 'deployment_readiness_drift_loop_id_absent');
  addReason(reasons, !isDigest(evidence?.driftLoopHash), 'deployment_readiness_drift_loop_hash_invalid');
  addReason(reasons, !isDigest(evidence?.driftLoopReceiptHash), 'deployment_readiness_drift_loop_receipt_hash_invalid');
  addReason(reasons, !isDigest(evidence?.stateUpdateHash), 'deployment_readiness_state_update_hash_invalid');
  addReason(reasons, !isDigest(evidence?.cqiCycleHash), 'deployment_readiness_cqi_cycle_hash_invalid');
  addReason(reasons, !isDigest(evidence?.cqiCycleReceiptHash), 'deployment_readiness_cqi_cycle_receipt_hash_invalid');
  addReason(
    reasons,
    !isDigest(evidence?.inquiryCqiBacklogReceiptHash),
    'deployment_readiness_inquiry_cqi_backlog_receipt_hash_invalid',
  );
  addReason(reasons, evidence?.manualNavigationReady !== true, 'deployment_readiness_manual_navigation_not_ready');
  addReason(
    reasons,
    evidence?.manualNavigationEffectiveUseAcknowledged !== true,
    'deployment_readiness_manual_navigation_effective_use_absent',
  );
  addReason(
    reasons,
    !isDigest(evidence?.roleManualCoverageReceiptHash),
    'deployment_readiness_role_manual_coverage_receipt_hash_invalid',
  );
  addReason(reasons, evidence?.trustState !== 'inactive', 'deployment_readiness_drift_trust_state_invalid');
  addReason(reasons, evidence?.exochainProductionClaim === true, 'deployment_readiness_drift_production_claim_forbidden');
  addReason(reasons, evidence?.metadataOnly !== true, 'deployment_readiness_drift_metadata_boundary_invalid');
  addReason(reasons, evidence?.protectedContentExcluded !== true, 'deployment_readiness_drift_protected_boundary_invalid');
  addReason(reasons, hlcTuple(evidence?.reviewedAtHlc) === null, 'deployment_readiness_drift_review_time_invalid');
  addReason(
    reasons,
    hlcAfter(evidence?.reviewedAtHlc, manifest?.reviewedAtHlc),
    'deployment_readiness_drift_after_manifest_review',
  );

  const stateUpdateTargets = sortedTextList(evidence?.stateUpdateTargets);
  evaluateRequiredSet(
    stateUpdateTargets,
    REQUIRED_DRIFT_STATE_TARGETS,
    'deployment_readiness_state_update_target_missing',
    'deployment_readiness_state_update_target_unsupported',
    reasons,
  );

  return {
    cqiCycleHash: evidence?.cqiCycleHash ?? null,
    cqiCycleReceiptHash: evidence?.cqiCycleReceiptHash ?? null,
    driftLoopHash: evidence?.driftLoopHash ?? null,
    driftLoopId: evidence?.driftLoopId ?? null,
    driftLoopReceiptHash: evidence?.driftLoopReceiptHash ?? null,
    inquiryCqiBacklogReceiptHash: evidence?.inquiryCqiBacklogReceiptHash ?? null,
    manualNavigationEffectiveUseAcknowledged: evidence?.manualNavigationEffectiveUseAcknowledged === true,
    manualNavigationReady: evidence?.manualNavigationReady === true,
    roleManualCoverageReceiptHash: evidence?.roleManualCoverageReceiptHash ?? null,
    stateUpdateHash: evidence?.stateUpdateHash ?? null,
    stateUpdateTargets,
    trustState: evidence?.trustState ?? 'invalid',
  };
}

function evaluateRoleDashboardTrustStateEvidence(evidence, parent, reasons, prefix, parentLabel) {
  addReason(reasons, evidence === null || evidence === undefined, `${prefix}_trust_state_evidence_absent`);

  const dashboardRoles = sortedTextList(evidence?.dashboardRoles);
  const dashboardHashRefs = Array.isArray(evidence?.dashboardHashRefs) ? evidence.dashboardHashRefs : [];
  const hashRefRoles = sortedTextList(dashboardHashRefs.map((hashRef) => hashRef?.role));
  const productionClaimLiftRoleDashboardRoles = sortedTextList(evidence?.productionClaimLiftRoleDashboardRoles);
  const seenHashRefRoles = new Set();
  const hashRefSummaries = [];

  addReason(reasons, evidence?.schema !== 'cybermedica.role_dashboard_trust_state_lineage.v1', `${prefix}_schema_invalid`);
  addReason(reasons, !isDigest(evidence?.roleDashboardSummaryHash), `${prefix}_summary_hash_invalid`);
  addReason(reasons, !isDigest(evidence?.roleDashboardReceiptHash), `${prefix}_receipt_hash_invalid`);
  addReason(reasons, !isDigest(evidence?.roleDashboardTrustStateViewHash), `${prefix}_trust_state_view_hash_invalid`);
  addReason(reasons, !Array.isArray(evidence?.dashboardRoles) || evidence.dashboardRoles.length === 0, `${prefix}_roles_absent`);
  addReason(
    reasons,
    !Array.isArray(evidence?.dashboardHashRefs) || evidence.dashboardHashRefs.length === 0,
    `${prefix}_hash_refs_absent`,
  );

  for (const role of REQUIRED_ROLE_DASHBOARD_ROLES) {
    addReason(reasons, !dashboardRoles.includes(role), `${prefix}_role_missing:${role}`);
    addReason(reasons, !hashRefRoles.includes(role), `${prefix}_hash_ref_missing:${role}`);
  }
  for (const role of dashboardRoles) {
    addReason(reasons, !REQUIRED_ROLE_DASHBOARD_ROLES.includes(role), `${prefix}_role_unsupported:${role}`);
  }

  dashboardHashRefs.forEach((hashRef, index) => {
    const label = hasText(hashRef?.role) ? hashRef.role : `index_${index}`;
    addReason(reasons, !hasText(hashRef?.role), `${prefix}_hash_ref_role_absent:${label}`);
    addReason(reasons, !REQUIRED_ROLE_DASHBOARD_ROLES.includes(hashRef?.role), `${prefix}_hash_ref_role_unsupported:${label}`);
    addReason(reasons, seenHashRefRoles.has(hashRef?.role), `${prefix}_hash_ref_duplicate:${label}`);
    if (hasText(hashRef?.role)) {
      seenHashRefRoles.add(hashRef.role);
    }
    addReason(reasons, !isDigest(hashRef?.dashboardHash), `${prefix}_hash_invalid:${label}`);
    addReason(reasons, !isDigest(hashRef?.trustStateViewHash), `${prefix}_hash_ref_trust_state_view_hash_invalid:${label}`);
    hashRefSummaries.push({
      dashboardHash: hashRef?.dashboardHash ?? null,
      role: hashRef?.role ?? label,
      trustStateViewHash: hashRef?.trustStateViewHash ?? null,
    });
  });

  addReason(reasons, evidence?.trustState !== 'inactive', `${prefix}_trust_state_invalid`);
  addReason(reasons, evidence?.exochainProductionClaim !== false, `${prefix}_production_claim_forbidden`);
  addReason(reasons, evidence?.canShowProductionTrustClaim !== false, `${prefix}_production_claim_display_forbidden`);
  addReason(reasons, evidence?.activationLineageAccepted !== true, `${prefix}_activation_lineage_absent`);
  addReason(reasons, !isDigest(evidence?.publicClaimReviewReceiptHash), `${prefix}_public_claim_review_receipt_hash_invalid`);
  addReason(reasons, !isDigest(evidence?.publicClaimReviewPackageHash), `${prefix}_public_claim_review_package_hash_invalid`);
  addReason(reasons, !isDigest(evidence?.productionClaimLiftReceiptHash), `${prefix}_production_claim_lift_receipt_hash_invalid`);
  addReason(reasons, evidence?.productionClaimLiftTrustState !== 'inactive', `${prefix}_production_claim_lift_state_invalid`);
  addReason(
    reasons,
    evidence?.productionClaimLiftCanLiftProductionClaim !== false,
    `${prefix}_production_claim_lift_forbidden`,
  );
  addReason(
    reasons,
    !isDigest(evidence?.productionClaimLiftRoleDashboardProviderReceiptHash),
    `${prefix}_production_claim_lift_provider_receipt_hash_invalid`,
  );
  addReason(
    reasons,
    !isDigest(evidence?.productionClaimLiftRoleDashboardProviderSummaryHash),
    `${prefix}_production_claim_lift_provider_summary_hash_invalid`,
  );
  addReason(
    reasons,
    !isDigest(evidence?.productionClaimLiftRoleDashboardProviderTrustStateViewHash),
    `${prefix}_production_claim_lift_provider_trust_state_view_hash_invalid`,
  );
  addReason(
    reasons,
    !isDigest(evidence?.productionClaimLiftRoleDashboardReadinessReceiptHash),
    `${prefix}_production_claim_lift_readiness_receipt_hash_invalid`,
  );
  addReason(
    reasons,
    !isDigest(evidence?.productionClaimLiftRoleDashboardReadinessSummaryHash),
    `${prefix}_production_claim_lift_readiness_summary_hash_invalid`,
  );
  addReason(
    reasons,
    !isDigest(evidence?.productionClaimLiftRoleDashboardReadinessTrustStateViewHash),
    `${prefix}_production_claim_lift_readiness_trust_state_view_hash_invalid`,
  );
  addReason(
    reasons,
    !isDigest(evidence?.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash),
    `${prefix}_production_claim_lift_runtime_source_provider_receipt_hash_invalid`,
  );
  addReason(
    reasons,
    !isDigest(evidence?.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash),
    `${prefix}_production_claim_lift_runtime_source_provider_summary_hash_invalid`,
  );
  addReason(
    reasons,
    !isDigest(evidence?.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash),
    `${prefix}_production_claim_lift_runtime_source_provider_trust_state_view_hash_invalid`,
  );
  addReason(
    reasons,
    !isDigest(evidence?.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash),
    `${prefix}_production_claim_lift_runtime_source_readiness_receipt_hash_invalid`,
  );
  addReason(
    reasons,
    !isDigest(evidence?.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash),
    `${prefix}_production_claim_lift_runtime_source_readiness_summary_hash_invalid`,
  );
  addReason(
    reasons,
    !isDigest(evidence?.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash),
    `${prefix}_production_claim_lift_runtime_source_readiness_trust_state_view_hash_invalid`,
  );
  evaluateRequiredSet(
    productionClaimLiftRoleDashboardRoles,
    REQUIRED_ROLE_DASHBOARD_ROLES,
    `${prefix}_production_claim_lift_role_missing`,
    `${prefix}_production_claim_lift_role_unsupported`,
    reasons,
  );
  if (
    isDigest(evidence?.roleDashboardReceiptHash) &&
    isDigest(evidence?.productionClaimLiftRoleDashboardProviderReceiptHash) &&
    evidence.roleDashboardReceiptHash !== evidence.productionClaimLiftRoleDashboardProviderReceiptHash
  ) {
    reasons.push(`${prefix}_production_claim_lift_provider_receipt_mismatch`);
  }
  if (
    isDigest(evidence?.roleDashboardSummaryHash) &&
    isDigest(evidence?.productionClaimLiftRoleDashboardProviderSummaryHash) &&
    evidence.roleDashboardSummaryHash !== evidence.productionClaimLiftRoleDashboardProviderSummaryHash
  ) {
    reasons.push(`${prefix}_production_claim_lift_provider_summary_mismatch`);
  }
  if (
    isDigest(evidence?.roleDashboardTrustStateViewHash) &&
    isDigest(evidence?.productionClaimLiftRoleDashboardProviderTrustStateViewHash) &&
    evidence.roleDashboardTrustStateViewHash !== evidence.productionClaimLiftRoleDashboardProviderTrustStateViewHash
  ) {
    reasons.push(`${prefix}_production_claim_lift_provider_trust_state_view_mismatch`);
  }
  if (
    isDigest(evidence?.productionClaimLiftRoleDashboardProviderReceiptHash) &&
    isDigest(evidence?.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash) &&
    evidence.productionClaimLiftRoleDashboardProviderReceiptHash !==
      evidence.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash
  ) {
    reasons.push(`${prefix}_production_claim_lift_runtime_source_provider_receipt_mismatch`);
  }
  if (
    isDigest(evidence?.productionClaimLiftRoleDashboardProviderSummaryHash) &&
    isDigest(evidence?.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash) &&
    evidence.productionClaimLiftRoleDashboardProviderSummaryHash !==
      evidence.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash
  ) {
    reasons.push(`${prefix}_production_claim_lift_runtime_source_provider_summary_mismatch`);
  }
  if (
    isDigest(evidence?.productionClaimLiftRoleDashboardProviderTrustStateViewHash) &&
    isDigest(evidence?.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash) &&
    evidence.productionClaimLiftRoleDashboardProviderTrustStateViewHash !==
      evidence.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash
  ) {
    reasons.push(`${prefix}_production_claim_lift_runtime_source_provider_trust_state_view_mismatch`);
  }
  if (
    isDigest(evidence?.productionClaimLiftRoleDashboardReadinessReceiptHash) &&
    isDigest(evidence?.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash) &&
    evidence.productionClaimLiftRoleDashboardReadinessReceiptHash !==
      evidence.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash
  ) {
    reasons.push(`${prefix}_production_claim_lift_runtime_source_readiness_receipt_mismatch`);
  }
  if (
    isDigest(evidence?.productionClaimLiftRoleDashboardReadinessSummaryHash) &&
    isDigest(evidence?.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash) &&
    evidence.productionClaimLiftRoleDashboardReadinessSummaryHash !==
      evidence.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash
  ) {
    reasons.push(`${prefix}_production_claim_lift_runtime_source_readiness_summary_mismatch`);
  }
  if (
    isDigest(evidence?.productionClaimLiftRoleDashboardReadinessTrustStateViewHash) &&
    isDigest(evidence?.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash) &&
    evidence.productionClaimLiftRoleDashboardReadinessTrustStateViewHash !==
      evidence.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash
  ) {
    reasons.push(`${prefix}_production_claim_lift_runtime_source_readiness_trust_state_view_mismatch`);
  }
  addReason(reasons, evidence?.metadataOnly !== true, `${prefix}_metadata_boundary_invalid`);
  addReason(reasons, evidence?.protectedContentExcluded !== true, `${prefix}_protected_boundary_invalid`);
  addReason(reasons, hlcTuple(evidence?.reviewedAtHlc) === null, `${prefix}_review_time_invalid`);
  addReason(reasons, hlcAfter(evidence?.reviewedAtHlc, parent?.reviewedAtHlc), `${prefix}_after_${parentLabel}`);

  return {
    activationLineageAccepted: evidence?.activationLineageAccepted === true,
    canShowProductionTrustClaim: evidence?.canShowProductionTrustClaim === true,
    dashboardHashRefs: hashRefSummaries.sort((left, right) => left.role.localeCompare(right.role)),
    dashboardRoles,
    productionClaimLiftCanLiftProductionClaim: evidence?.productionClaimLiftCanLiftProductionClaim === true,
    productionClaimLiftRoleDashboardProviderReceiptHash:
      evidence?.productionClaimLiftRoleDashboardProviderReceiptHash ?? null,
    productionClaimLiftRoleDashboardProviderSummaryHash:
      evidence?.productionClaimLiftRoleDashboardProviderSummaryHash ?? null,
    productionClaimLiftRoleDashboardProviderTrustStateViewHash:
      evidence?.productionClaimLiftRoleDashboardProviderTrustStateViewHash ?? null,
    productionClaimLiftRoleDashboardReadinessReceiptHash:
      evidence?.productionClaimLiftRoleDashboardReadinessReceiptHash ?? null,
    productionClaimLiftRoleDashboardReadinessSummaryHash:
      evidence?.productionClaimLiftRoleDashboardReadinessSummaryHash ?? null,
    productionClaimLiftRoleDashboardReadinessTrustStateViewHash:
      evidence?.productionClaimLiftRoleDashboardReadinessTrustStateViewHash ?? null,
    productionClaimLiftRoleDashboardRoles,
    productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash:
      evidence?.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash ?? null,
    productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash:
      evidence?.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash ?? null,
    productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash:
      evidence?.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash ?? null,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash:
      evidence?.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash ?? null,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash:
      evidence?.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash ?? null,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash:
      evidence?.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash ?? null,
    productionClaimLiftReceiptHash: evidence?.productionClaimLiftReceiptHash ?? null,
    productionClaimLiftTrustState: evidence?.productionClaimLiftTrustState ?? null,
    publicClaimReviewPackageHash: evidence?.publicClaimReviewPackageHash ?? null,
    publicClaimReviewReceiptHash: evidence?.publicClaimReviewReceiptHash ?? null,
    roleDashboardReceiptHash: evidence?.roleDashboardReceiptHash ?? null,
    roleDashboardSummaryHash: evidence?.roleDashboardSummaryHash ?? null,
    roleDashboardTrustStateViewHash: evidence?.roleDashboardTrustStateViewHash ?? null,
    trustState: evidence?.trustState ?? null,
  };
}

function evaluateDeploymentReadinessManifest(manifest, cycle, reasons) {
  addReason(reasons, manifest === null || manifest === undefined, 'deployment_readiness_manifest_absent');
  addReason(reasons, !isDigest(manifest?.manifestHash), 'deployment_readiness_manifest_hash_invalid');
  addReason(reasons, !isDigest(manifest?.receiptHash), 'deployment_readiness_manifest_receipt_hash_invalid');
  addReason(
    reasons,
    manifest?.receiptArtifactType !== 'deployment_readiness_manifest',
    'deployment_readiness_manifest_receipt_type_invalid',
  );
  addReason(
    reasons,
    !DEPLOYMENT_READINESS_MANIFEST_STATUSES.has(manifest?.status),
    'deployment_readiness_manifest_status_invalid',
  );
  addReason(
    reasons,
    manifest?.releaseCandidateRef !== cycle?.releaseCandidateRef,
    'deployment_readiness_manifest_release_candidate_mismatch',
  );
  addReason(reasons, manifest?.trustState !== 'inactive', 'deployment_readiness_manifest_trust_state_invalid');
  addReason(reasons, manifest?.baselineReady !== true, 'deployment_readiness_manifest_baseline_not_ready');
  addReason(reasons, manifest?.productionClaim === true, 'deployment_readiness_manifest_production_claim_forbidden');
  addReason(reasons, manifest?.metadataOnly !== true, 'deployment_readiness_manifest_metadata_boundary_invalid');
  addReason(
    reasons,
    manifest?.protectedContentExcluded !== true,
    'deployment_readiness_manifest_protected_boundary_invalid',
  );
  addReason(reasons, hlcTuple(manifest?.reviewedAtHlc) === null, 'deployment_readiness_manifest_review_time_invalid');
  addReason(reasons, hlcAfter(manifest?.reviewedAtHlc, cycle?.validationRecordedAtHlc), 'deployment_readiness_manifest_after_validation');

  const driftStateUpdateEvidence = evaluateDeploymentReadinessDriftStateUpdateEvidence(
    manifest?.driftStateUpdateEvidence,
    manifest,
    reasons,
  );
  const roleDashboardTrustStateEvidence = evaluateRoleDashboardTrustStateEvidence(
    manifest?.roleDashboardTrustStateEvidence,
    manifest,
    reasons,
    'deployment_readiness_role_dashboard',
    'manifest_review',
  );

  return {
    baselineReady: manifest?.baselineReady === true,
    driftStateUpdateEvidence,
    manifestHash: manifest?.manifestHash ?? null,
    receiptArtifactType: manifest?.receiptArtifactType ?? null,
    receiptHash: manifest?.receiptHash ?? null,
    releaseCandidateRef: manifest?.releaseCandidateRef ?? null,
    roleDashboardTrustStateEvidence,
    status: manifest?.status ?? 'invalid',
    trustState: manifest?.trustState ?? 'invalid',
    productionClaim: manifest?.productionClaim === true,
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
  addReason(reasons, !isDigest(validation?.providerStatusEvidenceHash), 'provider_status_evidence_hash_invalid');
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
  addReason(reasons, review?.activationBlockersAccepted !== true, 'activation_blockers_not_accepted');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_forbidden');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.humanReviewedAtHlc), 'human_review_before_cycle_review_step');
}

function evaluateAuditRecord(auditRecord, cycle, review, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'provider_binding_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'provider_binding_audit_record_hash_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'provider_binding_audit_record_metadata_boundary_invalid');
  addReason(reasons, auditRecord?.includesProtectedContent === true, 'provider_binding_audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'provider_binding_audit_record_time_invalid');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, cycle?.auditRecordedAtHlc), 'provider_binding_audit_before_cycle_audit_step');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, review?.reviewedAtHlc), 'provider_binding_audit_before_review');
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

function buildProviderBinding(
  input,
  policySummary,
  domainSummary,
  providerSummary,
  runtimeSummary,
  operationsSummary,
  deploymentReadinessManifestSummary,
) {
  const activationBlockerIds = uniqueSorted([...domainSummary.blockerIds, ...operationsSummary.blockerIds]);
  const deploymentReadinessRoleDashboard = deploymentReadinessManifestSummary.roleDashboardTrustStateEvidence;
  const operationsReadinessRoleDashboard = operationsSummary.roleDashboardTrustStateEvidence;
  const productionProviderBindingReady =
    activationBlockerIds.length === 0 &&
    providerSummary.bindingStatus === 'verified' &&
    runtimeSummary.rootBundleProviderVerified === true &&
    operationsSummary.productionOperationsReady === true;
  const providerBindingHash = sha256Hex({
    activationBlockerIds,
    auditRecordHash: input.auditRecord.auditRecordHash,
    bindingRef: input.bindingCycle.bindingRef,
    domainSummaries: domainSummary.summaries,
    humanDecisionHash: input.humanReview.decisionHash,
    deploymentReadinessManifestHash: input.deploymentReadinessManifest.manifestHash,
    deploymentReadinessManifestReceiptHash: input.deploymentReadinessManifest.receiptHash,
    deploymentReadinessRoleDashboardReceiptHash:
      deploymentReadinessRoleDashboard.roleDashboardReceiptHash,
    deploymentReadinessRoleDashboardSummaryHash:
      deploymentReadinessRoleDashboard.roleDashboardSummaryHash,
    deploymentReadinessRoleDashboardTrustStateViewHash:
      deploymentReadinessRoleDashboard.roleDashboardTrustStateViewHash,
    deploymentReadinessRoleDashboardClaimLiftLineage: {
      productionClaimLiftReceiptHash: deploymentReadinessRoleDashboard.productionClaimLiftReceiptHash,
      productionClaimLiftRoleDashboardProviderReceiptHash:
        deploymentReadinessRoleDashboard.productionClaimLiftRoleDashboardProviderReceiptHash,
      productionClaimLiftRoleDashboardProviderSummaryHash:
        deploymentReadinessRoleDashboard.productionClaimLiftRoleDashboardProviderSummaryHash,
      productionClaimLiftRoleDashboardProviderTrustStateViewHash:
        deploymentReadinessRoleDashboard.productionClaimLiftRoleDashboardProviderTrustStateViewHash,
      productionClaimLiftRoleDashboardReadinessReceiptHash:
        deploymentReadinessRoleDashboard.productionClaimLiftRoleDashboardReadinessReceiptHash,
      productionClaimLiftRoleDashboardReadinessSummaryHash:
        deploymentReadinessRoleDashboard.productionClaimLiftRoleDashboardReadinessSummaryHash,
      productionClaimLiftRoleDashboardReadinessTrustStateViewHash:
        deploymentReadinessRoleDashboard.productionClaimLiftRoleDashboardReadinessTrustStateViewHash,
      productionClaimLiftRoleDashboardRoles: deploymentReadinessRoleDashboard.productionClaimLiftRoleDashboardRoles,
      productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash:
        deploymentReadinessRoleDashboard.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
      productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash:
        deploymentReadinessRoleDashboard.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
      productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash:
        deploymentReadinessRoleDashboard.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash:
        deploymentReadinessRoleDashboard.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash:
        deploymentReadinessRoleDashboard.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash:
        deploymentReadinessRoleDashboard.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    },
    deploymentReadinessStateUpdateHash: input.deploymentReadinessManifest.driftStateUpdateEvidence.stateUpdateHash,
    operationsReadinessHash: input.operationsReadiness.operationsReadinessHash,
    operationsReadinessReceiptHash: input.operationsReadiness.receiptHash,
    operationsReadinessRoleDashboardReceiptHash: operationsReadinessRoleDashboard.roleDashboardReceiptHash,
    operationsReadinessRoleDashboardSummaryHash: operationsReadinessRoleDashboard.roleDashboardSummaryHash,
    operationsReadinessRoleDashboardTrustStateViewHash: operationsReadinessRoleDashboard.roleDashboardTrustStateViewHash,
    operationsReadinessRoleDashboardClaimLiftLineage: {
      productionClaimLiftReceiptHash: operationsReadinessRoleDashboard.productionClaimLiftReceiptHash,
      productionClaimLiftRoleDashboardProviderReceiptHash:
        operationsReadinessRoleDashboard.productionClaimLiftRoleDashboardProviderReceiptHash,
      productionClaimLiftRoleDashboardProviderSummaryHash:
        operationsReadinessRoleDashboard.productionClaimLiftRoleDashboardProviderSummaryHash,
      productionClaimLiftRoleDashboardProviderTrustStateViewHash:
        operationsReadinessRoleDashboard.productionClaimLiftRoleDashboardProviderTrustStateViewHash,
      productionClaimLiftRoleDashboardReadinessReceiptHash:
        operationsReadinessRoleDashboard.productionClaimLiftRoleDashboardReadinessReceiptHash,
      productionClaimLiftRoleDashboardReadinessSummaryHash:
        operationsReadinessRoleDashboard.productionClaimLiftRoleDashboardReadinessSummaryHash,
      productionClaimLiftRoleDashboardReadinessTrustStateViewHash:
        operationsReadinessRoleDashboard.productionClaimLiftRoleDashboardReadinessTrustStateViewHash,
      productionClaimLiftRoleDashboardRoles: operationsReadinessRoleDashboard.productionClaimLiftRoleDashboardRoles,
      productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash:
        operationsReadinessRoleDashboard.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
      productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash:
        operationsReadinessRoleDashboard.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
      productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash:
        operationsReadinessRoleDashboard.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash:
        operationsReadinessRoleDashboard.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash:
        operationsReadinessRoleDashboard.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash:
        operationsReadinessRoleDashboard.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    },
    policyHash: input.providerPolicy.policyHash,
    providerSummary,
    releaseCandidateRef: input.bindingCycle.releaseCandidateRef,
    releaseIncidentLinkageReceiptHash: input.operationsReadiness.releaseIncidentLinkageReceiptHash,
    runtimeSummary,
    tenantId: input.tenantId,
    validationEvidenceHash: input.validationEvidence.providerStatusEvidenceHash,
  });

  return {
    schema: PROVIDER_BINDING_SCHEMA,
    providerBindingId: `cmdpb_${sha256Hex({
      providerBindingHash,
      releaseCandidateRef: input.bindingCycle.releaseCandidateRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    releaseCandidateRef: input.bindingCycle.releaseCandidateRef,
    trustState: 'inactive',
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    baselineProviderBindingReady: true,
    productionProviderBindingReady,
    allowedProviders: policySummary.allowedProviders,
    bindingDomainsCovered: domainSummary.domains,
    bindingDomainSummaries: domainSummary.summaries,
    allowedActivationBlockerIds: policySummary.allowedActivationBlockerIds,
    activationBlockerIds,
    provider: providerSummary,
    runtime: runtimeSummary,
    operationsReadiness: operationsSummary,
    deploymentReadinessManifest: deploymentReadinessManifestSummary,
    validationSummary: {
      commandRefs: sortedTextList(input.validationEvidence.commandRefs),
      coverageLineBasisPoints: input.validationEvidence.coverageLineBasisPoints,
      sourceGuardPassed: true,
      testCount: input.validationEvidence.testCount,
    },
    providerBindingHash,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, binding) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: binding.providerBindingHash,
    artifactType: 'deployment_provider_binding',
    artifactVersion: input.bindingCycle.releaseCandidateRef,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: [
      'continuous_quality_improvement',
      'deployment_provider_binding',
      'deployment_readiness_manifest',
      'drift_state_update',
      'inactive_trust_state',
      'manual_navigation_readiness',
      'metadata_only',
      'role_dashboard_trust_state',
    ],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateDeploymentProviderBinding(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateProviderPolicy(input?.providerPolicy, reasons);
  evaluateBindingCycle(input?.bindingCycle, input?.providerPolicy, reasons);
  const providerSummary = evaluateProviderBinding(input?.providerBinding, policySummary, input?.bindingCycle, reasons);
  const runtimeSummary = evaluateRuntimeBinding(input?.runtimeBinding, input?.bindingCycle, reasons);
  const domainSummary = evaluateBindingDomains(input?.bindingDomains, policySummary, input?.bindingCycle, reasons);
  const operationsSummary = evaluateOperationsReadiness(
    input?.operationsReadiness,
    policySummary,
    input?.bindingCycle,
    reasons,
  );
  const deploymentReadinessManifestSummary = evaluateDeploymentReadinessManifest(
    input?.deploymentReadinessManifest,
    input?.bindingCycle,
    reasons,
  );
  evaluateValidationEvidence(input?.validationEvidence, input?.bindingCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.bindingCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.bindingCycle, input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      providerBinding: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const providerBinding = buildProviderBinding(
    input,
    policySummary,
    domainSummary,
    providerSummary,
    runtimeSummary,
    operationsSummary,
    deploymentReadinessManifestSummary,
  );

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    providerBinding,
    receipt: buildReceipt(input, providerBinding),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
