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
const CONFIGURATION_SCHEMA = 'cybermedica.runtime_configuration_source.v1';
const DECISION_SCHEMA = 'cybermedica.runtime_configuration_source_decision.v1';
const REQUIRED_PERMISSION = 'runtime_configuration_review';

const REQUIRED_CONFIGURATION_DOMAINS = Object.freeze([
  'adapter_endpoints',
  'audit_evidence',
  'deployment_environment',
  'feature_flags',
  'health_readiness',
  'rollback_disablement',
  'root_bundle_provider',
  'secret_scope',
]);

const REQUIRED_ADAPTERS = Object.freeze(['decision_forum', 'gateway', 'node_receipt', 'root_bundle_provider']);

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

const DEFAULT_ALLOWED_ACTIVATION_BLOCKER_IDS = Object.freeze([
  'ESC-OPS-SECRETS',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-RUNTIME',
]);

const POLICY_STATUSES = new Set(['active']);
const DOMAIN_STATUSES = new Set(['activation_blocked', 'ready']);
const ADAPTER_STATUSES = new Set(['activation_blocked', 'ready', 'verified']);
const SECRET_SCOPE_STATUSES = new Set(['activation_blocked', 'verified']);
const DEPLOYMENT_READINESS_MANIFEST_STATUSES = new Set(['deployment_readiness_manifest_accepted_inactive_trust']);
const DEPLOYMENT_OPERATIONS_READINESS_STATUSES = new Set(['deployment_operations_readiness_accepted_inactive_trust']);
const DEPLOYMENT_PROVIDER_BINDING_STATUSES = new Set(['deployment_provider_binding_accepted_inactive_trust']);
const DEPLOYMENT_HANDOFF_CUTOVER_STATUSES = new Set(['deployment_handoff_cutover_accepted_inactive_trust']);
const HUMAN_REVIEW_DECISIONS = new Set(['configuration_ready', 'configuration_ready_with_activation_blockers']);

const RAW_CONFIGURATION_FIELDS = new Set([
  'body',
  'configbody',
  'content',
  'deploymentnotes',
  'freetext',
  'freetextnote',
  'rawconfigurationcontent',
  'rawconfigurationsource',
  'rawconfigsource',
  'rawdeploymentconfig',
  'rawhealthresponse',
  'rawruntimeconfig',
  'rawsourcecontent',
  'rawvalidationoutput',
  'reviewnotes',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_CONFIGURATION_FIELDS = new Set([
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

function assertNoRawConfigurationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawConfigurationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_CONFIGURATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw runtime configuration content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_CONFIGURATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`runtime configuration secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawConfigurationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawConfigurationContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_runtime_configuration_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'runtime_configuration_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateConfigurationPolicy(policy, reasons) {
  const requiredConfigurationDomains = sortedTextList(policy?.requiredConfigurationDomains);
  const requiredAdapters = sortedTextList(policy?.requiredAdapters);
  const allowedActivationBlockerIds = sortedTextList(policy?.allowedActivationBlockerIds);

  addReason(reasons, !hasText(policy?.policyRef), 'configuration_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'configuration_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'configuration_policy_not_active');
  addReason(reasons, policy?.serverSideAdapterRequired !== true, 'server_side_adapter_policy_absent');
  addReason(reasons, policy?.noCredentialDisclosure !== true, 'credential_disclosure_guard_absent');
  addReason(reasons, policy?.noSharedExochainSecrets !== true, 'exochain_secret_separation_policy_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'configuration_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'configuration_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'configuration_policy_time_invalid');

  evaluateRequiredSet(
    requiredConfigurationDomains,
    REQUIRED_CONFIGURATION_DOMAINS,
    'policy_configuration_domain_missing',
    'policy_configuration_domain_unsupported',
    reasons,
  );
  evaluateRequiredSet(requiredAdapters, REQUIRED_ADAPTERS, 'policy_adapter_missing', 'policy_adapter_unsupported', reasons);

  return {
    allowedActivationBlockerIds:
      allowedActivationBlockerIds.length > 0
        ? allowedActivationBlockerIds
        : [...DEFAULT_ALLOWED_ACTIVATION_BLOCKER_IDS],
    requiredAdapters: requiredAdapters.length > 0 ? requiredAdapters : [...REQUIRED_ADAPTERS],
    requiredConfigurationDomains:
      requiredConfigurationDomains.length > 0 ? requiredConfigurationDomains : [...REQUIRED_CONFIGURATION_DOMAINS],
  };
}

function evaluateConfigurationCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.configurationRef), 'configuration_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'configuration_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'configuration_cycle_protected_boundary_invalid');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['evidenceCollectedAtHlc', cycle?.evidenceCollectedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
    ['humanReviewedAtHlc', cycle?.humanReviewedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `configuration_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'configuration_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(
      reasons,
      hlcBefore(currentValue, previousValue),
      `configuration_cycle_${currentLabel}_before_${previousLabel}`,
    );
  }
}

function evaluateRuntimeConfiguration(config, cycle, reasons) {
  addReason(reasons, config === null || config === undefined, 'runtime_configuration_absent');
  addReason(reasons, !hasText(config?.sourceRef), 'runtime_configuration_source_ref_absent');
  addReason(reasons, !isDigest(config?.sourceHash), 'runtime_configuration_source_hash_invalid');
  addReason(reasons, !hasText(config?.deploymentEnvironment), 'deployment_environment_absent');
  addReason(reasons, config?.selectedTopology !== 'server_side_gateway_node', 'server_side_topology_required');
  addReason(reasons, !isDigest(config?.configSnapshotHash), 'runtime_config_snapshot_hash_invalid');
  addReason(reasons, !isDigest(config?.schemaHash), 'runtime_config_schema_hash_invalid');
  addReason(reasons, !isDigest(config?.featureFlagManifestHash), 'feature_flag_manifest_hash_invalid');
  addReason(reasons, config?.browserAuthoritativePathEnabled === true, 'browser_authoritative_path_forbidden');
  addReason(reasons, config?.healthSeparatesProcessAndTrust !== true, 'health_trust_boundary_absent');
  addReason(reasons, config?.unavailableTrustFabricFailsClosed !== true, 'unavailable_trust_fabric_fail_closed_absent');
  addReason(reasons, config?.productionTrustClaim === true, 'runtime_configuration_production_claim_forbidden');
  addReason(reasons, config?.metadataOnly !== true, 'runtime_configuration_metadata_boundary_invalid');
  addReason(reasons, config?.protectedContentExcluded !== true, 'runtime_configuration_protected_boundary_invalid');
  addReason(reasons, hlcTuple(config?.checkedAtHlc) === null, 'runtime_configuration_time_invalid');
  addReason(reasons, hlcBefore(config?.checkedAtHlc, cycle?.openedAtHlc), 'runtime_configuration_before_cycle_open');

  return {
    checkedAtHlc: config?.checkedAtHlc ?? null,
    configSnapshotHash: config?.configSnapshotHash ?? null,
    deploymentEnvironment: config?.deploymentEnvironment ?? null,
    featureFlagManifestHash: config?.featureFlagManifestHash ?? null,
    healthSeparatesProcessAndTrust: config?.healthSeparatesProcessAndTrust === true,
    schemaHash: config?.schemaHash ?? null,
    selectedTopology: config?.selectedTopology ?? null,
    sourceHash: config?.sourceHash ?? null,
    sourceRef: config?.sourceRef ?? null,
    unavailableTrustFabricFailsClosed: config?.unavailableTrustFabricFailsClosed === true,
  };
}

function domainStatus(entry) {
  if (!DOMAIN_STATUSES.has(entry?.status)) {
    return 'invalid';
  }
  return entry.status;
}

function evaluateConfigurationDomains(domains, policySummary, cycle, reasons) {
  if (!Array.isArray(domains) || domains.length === 0) {
    reasons.push('configuration_domains_absent');
  }
  const actualDomains = sortedTextList((Array.isArray(domains) ? domains : []).map((entry) => entry?.domain));
  evaluateRequiredSet(
    actualDomains,
    REQUIRED_CONFIGURATION_DOMAINS,
    'configuration_domain_missing',
    'configuration_domain_unsupported',
    reasons,
  );

  const summaries = [];
  const blockerIds = [];

  for (const entry of Array.isArray(domains) ? domains : []) {
    const status = domainStatus(entry);
    const domain = hasText(entry?.domain) ? entry.domain : 'unknown_domain';
    addReason(reasons, status === 'invalid', `configuration_domain_status_invalid:${domain}`);
    addReason(reasons, !hasText(entry?.evidenceRef), `configuration_domain_evidence_ref_absent:${domain}`);
    addReason(reasons, !isDigest(entry?.evidenceHash), `configuration_domain_evidence_hash_invalid:${domain}`);
    addReason(reasons, !hasText(entry?.ownerDid), `configuration_domain_owner_absent:${domain}`);
    addReason(reasons, entry?.reviewedByHuman !== true, `configuration_domain_human_review_absent:${domain}`);
    addReason(reasons, entry?.metadataOnly !== true, `configuration_domain_metadata_boundary_invalid:${domain}`);
    addReason(reasons, entry?.protectedContentExcluded !== true, `configuration_domain_protected_boundary_invalid:${domain}`);
    addReason(reasons, entry?.productionTrustClaim === true, `configuration_domain_production_claim_forbidden:${domain}`);
    addReason(reasons, hlcTuple(entry?.reviewedAtHlc) === null, `configuration_domain_review_time_invalid:${domain}`);
    addReason(reasons, hlcBefore(entry?.reviewedAtHlc, cycle?.openedAtHlc), `configuration_domain_before_cycle_open:${domain}`);

    if (status === 'activation_blocked') {
      addReason(reasons, entry?.productionActivationOnly !== true, `configuration_domain_activation_scope_invalid:${domain}`);
      addReason(reasons, entry?.blocksBaselineDevelopment === true, `configuration_domain_blocks_baseline:${domain}`);
      addReason(
        reasons,
        !policySummary.allowedActivationBlockerIds.includes(entry?.activationBlockerId),
        `configuration_domain_blocker_not_allowed:${entry?.activationBlockerId ?? domain}`,
      );
      if (policySummary.allowedActivationBlockerIds.includes(entry?.activationBlockerId)) {
        blockerIds.push(entry.activationBlockerId);
      }
    }

    summaries.push({
      activationBlockerId: entry?.activationBlockerId ?? null,
      domain,
      evidenceHash: entry?.evidenceHash ?? null,
      evidenceRef: entry?.evidenceRef ?? null,
      ownerDid: entry?.ownerDid ?? null,
      status,
    });
  }

  return {
    blockerIds: uniqueSorted(blockerIds),
    domains: actualDomains,
    summaries: summaries.sort((left, right) => left.domain.localeCompare(right.domain)),
  };
}

function adapterStatus(entry) {
  if (!ADAPTER_STATUSES.has(entry?.status)) {
    return 'invalid';
  }
  return entry.status;
}

function evaluateAdapterBindings(bindings, policySummary, cycle, reasons) {
  if (!Array.isArray(bindings) || bindings.length === 0) {
    reasons.push('adapter_bindings_absent');
  }
  const actualKinds = sortedTextList((Array.isArray(bindings) ? bindings : []).map((entry) => entry?.kind));
  evaluateRequiredSet(actualKinds, REQUIRED_ADAPTERS, 'adapter_kind_missing', 'adapter_kind_unsupported', reasons);

  const summaries = [];
  const blockerIds = [];

  for (const entry of Array.isArray(bindings) ? bindings : []) {
    const status = adapterStatus(entry);
    const kind = hasText(entry?.kind) ? entry.kind : 'unknown_adapter';
    addReason(reasons, status === 'invalid', `adapter_status_invalid:${kind}`);
    addReason(reasons, !hasText(entry?.providerRef), `adapter_provider_ref_absent:${kind}`);
    addReason(reasons, !isDigest(entry?.adapterHash), `adapter_hash_invalid:${kind}`);
    addReason(reasons, entry?.missingSecretsFailClosed !== true, `adapter_missing_secret_fail_closed_absent:${kind}`);
    addReason(reasons, entry?.unavailableFailsClosed !== true, `adapter_unavailable_fail_closed_absent:${kind}`);
    addReason(reasons, entry?.browserAuthoritative === true, `adapter_browser_authoritative_forbidden:${kind}`);
    addReason(reasons, entry?.metadataOnly !== true, `adapter_metadata_boundary_invalid:${kind}`);
    addReason(reasons, entry?.protectedContentExcluded !== true, `adapter_protected_boundary_invalid:${kind}`);
    addReason(reasons, hlcTuple(entry?.verifiedAtHlc) === null, `adapter_verified_time_invalid:${kind}`);
    addReason(reasons, hlcBefore(entry?.verifiedAtHlc, cycle?.openedAtHlc), `adapter_before_cycle_open:${kind}`);

    if (status === 'ready' || status === 'verified') {
      addReason(reasons, !isDigest(entry?.endpointHash), `adapter_endpoint_hash_invalid:${kind}`);
      addReason(reasons, !hasText(entry?.credentialScopeRef), `adapter_credential_scope_ref_absent:${kind}`);
      addReason(reasons, !isDigest(entry?.credentialScopeHash), `adapter_credential_scope_hash_invalid:${kind}`);
    }

    if (status === 'activation_blocked') {
      addReason(
        reasons,
        !policySummary.allowedActivationBlockerIds.includes(entry?.activationBlockerId),
        `adapter_blocker_not_allowed:${entry?.activationBlockerId ?? kind}`,
      );
      if (policySummary.allowedActivationBlockerIds.includes(entry?.activationBlockerId)) {
        blockerIds.push(entry.activationBlockerId);
      }
    }

    summaries.push({
      activationBlockerId: entry?.activationBlockerId ?? null,
      adapterHash: entry?.adapterHash ?? null,
      endpointHash: entry?.endpointHash ?? null,
      kind,
      providerRef: entry?.providerRef ?? null,
      status,
    });
  }

  return {
    adapterKinds: actualKinds,
    allAdaptersVerified:
      actualKinds.length === REQUIRED_ADAPTERS.length &&
      actualKinds.every((kind) => REQUIRED_ADAPTERS.includes(kind)) &&
      (Array.isArray(bindings) ? bindings : []).every((entry) => adapterStatus(entry) === 'verified'),
    blockerIds: uniqueSorted(blockerIds),
    summaries: summaries.sort((left, right) => left.kind.localeCompare(right.kind)),
  };
}

function evaluateSecretScope(scope, policySummary, cycle, reasons) {
  const status = SECRET_SCOPE_STATUSES.has(scope?.status) ? scope.status : 'invalid';
  const blockerIds = [];

  addReason(reasons, scope === null || scope === undefined, 'secret_scope_absent');
  addReason(reasons, !hasText(scope?.scopeRef), 'secret_scope_ref_absent');
  addReason(reasons, !isDigest(scope?.scopeHash), 'secret_scope_hash_invalid');
  addReason(reasons, status === 'invalid', 'secret_scope_status_invalid');
  addReason(reasons, scope?.cybermedicaOnly !== true, 'secret_scope_not_cybermedica_only');
  addReason(reasons, scope?.sharedWithExochainRoot === true, 'secret_scope_shared_with_exochain_root');
  addReason(reasons, scope?.sharedWithExochainBootstrap === true, 'secret_scope_shared_with_exochain_bootstrap');
  addReason(reasons, scope?.missingSecretsFailClosed !== true, 'secret_scope_missing_secret_fail_closed_absent');
  addReason(reasons, scope?.malformedSecretsFailClosed !== true, 'secret_scope_malformed_secret_fail_closed_absent');
  addReason(reasons, scope?.metadataOnly !== true, 'secret_scope_metadata_boundary_invalid');
  addReason(reasons, scope?.protectedContentExcluded !== true, 'secret_scope_protected_boundary_invalid');
  addReason(reasons, hlcTuple(scope?.checkedAtHlc) === null, 'secret_scope_time_invalid');
  addReason(reasons, hlcBefore(scope?.checkedAtHlc, cycle?.openedAtHlc), 'secret_scope_before_cycle_open');

  if (status === 'activation_blocked') {
    addReason(
      reasons,
      !policySummary.allowedActivationBlockerIds.includes(scope?.activationBlockerId),
      `secret_scope_blocker_not_allowed:${scope?.activationBlockerId ?? 'missing'}`,
    );
    if (policySummary.allowedActivationBlockerIds.includes(scope?.activationBlockerId)) {
      blockerIds.push(scope.activationBlockerId);
    }
  }

  if (status === 'verified') {
    addReason(reasons, !hasText(scope?.secretManagerRef), 'secret_manager_ref_absent');
    addReason(reasons, !isDigest(scope?.secretManagerHash), 'secret_manager_hash_invalid');
    addReason(reasons, !hasText(scope?.rotationOwnerDid), 'secret_rotation_owner_absent');
    addReason(reasons, !isDigest(scope?.rotationPolicyHash), 'secret_rotation_policy_hash_invalid');
  }

  return {
    activationBlockerId: scope?.activationBlockerId ?? null,
    blockerIds: uniqueSorted(blockerIds),
    cybermedicaOnly: scope?.cybermedicaOnly === true,
    missingSecretsFailClosed: scope?.missingSecretsFailClosed === true,
    rotationOwnerDid: scope?.rotationOwnerDid ?? null,
    scopeHash: scope?.scopeHash ?? null,
    scopeRef: scope?.scopeRef ?? null,
    secretManagerHash: scope?.secretManagerHash ?? null,
    secretManagerRef: scope?.secretManagerRef ?? null,
    status,
  };
}

function evaluateDeploymentReadinessDriftStateUpdateEvidence(evidence, manifest, reasons) {
  addReason(reasons, evidence === null || evidence === undefined, 'deployment_readiness_drift_state_update_absent');
  const stateUpdateTargets = sortedTextList(evidence?.stateUpdateTargets);

  addReason(reasons, !hasText(evidence?.driftLoopId), 'deployment_readiness_drift_loop_id_absent');
  addReason(reasons, !isDigest(evidence?.driftLoopHash), 'deployment_readiness_drift_loop_hash_invalid');
  addReason(reasons, !isDigest(evidence?.driftLoopReceiptHash), 'deployment_readiness_drift_loop_receipt_hash_invalid');
  addReason(reasons, !isDigest(evidence?.stateUpdateHash), 'deployment_readiness_drift_state_update_hash_invalid');
  addReason(reasons, !isDigest(evidence?.cqiCycleHash), 'deployment_readiness_drift_cqi_cycle_hash_invalid');
  addReason(reasons, !isDigest(evidence?.cqiCycleReceiptHash), 'deployment_readiness_drift_cqi_cycle_receipt_hash_invalid');
  addReason(
    reasons,
    !isDigest(evidence?.inquiryCqiBacklogReceiptHash),
    'deployment_readiness_drift_inquiry_cqi_backlog_receipt_hash_invalid',
  );
  addReason(reasons, !isDigest(evidence?.roleManualCoverageReceiptHash), 'deployment_readiness_drift_role_manual_receipt_hash_invalid');
  addReason(reasons, evidence?.manualNavigationReady !== true, 'deployment_readiness_drift_manual_navigation_ready_absent');
  addReason(
    reasons,
    evidence?.manualNavigationEffectiveUseAcknowledged !== true,
    'deployment_readiness_drift_manual_navigation_effective_use_absent',
  );
  addReason(reasons, evidence?.trustState !== 'inactive', 'deployment_readiness_drift_state_update_trust_state_invalid');
  addReason(
    reasons,
    evidence?.exochainProductionClaim !== false,
    'deployment_readiness_drift_state_update_production_claim_forbidden',
  );
  addReason(reasons, evidence?.metadataOnly !== true, 'deployment_readiness_drift_state_update_metadata_boundary_invalid');
  addReason(
    reasons,
    evidence?.protectedContentExcluded !== true,
    'deployment_readiness_drift_state_update_protected_boundary_invalid',
  );
  addReason(reasons, hlcTuple(evidence?.reviewedAtHlc) === null, 'deployment_readiness_drift_state_update_review_time_invalid');
  addReason(
    reasons,
    hlcAfter(evidence?.reviewedAtHlc, manifest?.reviewedAtHlc),
    'deployment_readiness_drift_state_update_after_manifest_review',
  );

  evaluateRequiredSet(
    stateUpdateTargets,
    REQUIRED_DRIFT_STATE_TARGETS,
    'deployment_readiness_drift_state_update_target_missing',
    'deployment_readiness_drift_state_update_target_unsupported',
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
  addReason(
    reasons,
    hlcAfter(manifest?.reviewedAtHlc, cycle?.validationRecordedAtHlc),
    'deployment_readiness_manifest_after_validation',
  );

  const driftStateUpdateEvidence = evaluateDeploymentReadinessDriftStateUpdateEvidence(
    manifest?.driftStateUpdateEvidence,
    manifest,
    reasons,
  );

  return {
    baselineReady: manifest?.baselineReady === true,
    driftStateUpdateEvidence,
    manifestHash: manifest?.manifestHash ?? null,
    receiptArtifactType: manifest?.receiptArtifactType ?? null,
    receiptHash: manifest?.receiptHash ?? null,
    releaseCandidateRef: manifest?.releaseCandidateRef ?? null,
    status: manifest?.status ?? 'invalid',
    trustState: manifest?.trustState ?? 'invalid',
    productionClaim: manifest?.productionClaim === true,
  };
}

function evaluateDeploymentOperationsReadiness(operations, manifestSummary, policySummary, cycle, reasons) {
  const blockerIds = sortedTextList(operations?.activationBlockerIds);

  addReason(reasons, operations === null || operations === undefined, 'deployment_operations_readiness_absent');
  addReason(reasons, !hasText(operations?.operationsReadinessRef), 'deployment_operations_readiness_ref_absent');
  addReason(reasons, !isDigest(operations?.operationsReadinessHash), 'deployment_operations_readiness_hash_invalid');
  addReason(reasons, !isDigest(operations?.receiptHash), 'deployment_operations_readiness_receipt_hash_invalid');
  addReason(
    reasons,
    operations?.receiptArtifactType !== 'deployment_operations_readiness',
    'deployment_operations_readiness_receipt_type_invalid',
  );
  addReason(
    reasons,
    !DEPLOYMENT_OPERATIONS_READINESS_STATUSES.has(operations?.status),
    'deployment_operations_readiness_status_invalid',
  );
  addReason(
    reasons,
    operations?.releaseCandidateRef !== cycle?.releaseCandidateRef,
    'deployment_operations_readiness_release_candidate_mismatch',
  );
  addReason(
    reasons,
    !isDigest(operations?.releaseIncidentLinkageReceiptHash),
    'deployment_operations_release_incident_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(operations?.deploymentReadinessManifestReceiptHash),
    'deployment_operations_readiness_manifest_receipt_hash_invalid',
  );
  addReason(
    reasons,
    operations?.deploymentReadinessManifestReceiptHash !== manifestSummary.receiptHash,
    'deployment_operations_readiness_manifest_receipt_mismatch',
  );
  addReason(reasons, operations?.trustState !== 'inactive', 'deployment_operations_readiness_trust_state_invalid');
  addReason(reasons, operations?.baselineOperationsPackReady !== true, 'deployment_operations_readiness_baseline_not_ready');
  addReason(reasons, operations?.productionTrustClaim === true, 'deployment_operations_readiness_production_claim_forbidden');
  addReason(reasons, operations?.metadataOnly !== true, 'deployment_operations_readiness_metadata_boundary_invalid');
  addReason(
    reasons,
    operations?.protectedContentExcluded !== true,
    'deployment_operations_readiness_protected_boundary_invalid',
  );
  addReason(reasons, hlcTuple(operations?.reviewedAtHlc) === null, 'deployment_operations_readiness_review_time_invalid');
  addReason(
    reasons,
    hlcAfter(operations?.reviewedAtHlc, cycle?.validationRecordedAtHlc),
    'deployment_operations_readiness_after_validation',
  );

  for (const blockerId of blockerIds) {
    addReason(
      reasons,
      !policySummary.allowedActivationBlockerIds.includes(blockerId),
      `deployment_operations_blocker_not_allowed:${blockerId}`,
    );
  }

  return {
    activationBlockerIds: blockerIds,
    baselineOperationsPackReady: operations?.baselineOperationsPackReady === true,
    deploymentReadinessManifestReceiptHash: operations?.deploymentReadinessManifestReceiptHash ?? null,
    operationsReadinessHash: operations?.operationsReadinessHash ?? null,
    operationsReadinessRef: operations?.operationsReadinessRef ?? null,
    productionOperationsReady: operations?.productionOperationsReady === true,
    railwayLoginStatus: operations?.railwayLoginStatus ?? null,
    receiptArtifactType: operations?.receiptArtifactType ?? null,
    receiptHash: operations?.receiptHash ?? null,
    releaseCandidateRef: operations?.releaseCandidateRef ?? null,
    releaseIncidentLinkageReceiptHash: operations?.releaseIncidentLinkageReceiptHash ?? null,
    status: operations?.status ?? 'invalid',
    trustState: operations?.trustState ?? 'invalid',
  };
}

function evaluateDeploymentProviderBinding(binding, operationsSummary, manifestSummary, cycle, reasons) {
  addReason(reasons, binding === null || binding === undefined, 'deployment_provider_binding_absent');
  addReason(reasons, !hasText(binding?.providerBindingRef), 'deployment_provider_binding_ref_absent');
  addReason(reasons, !isDigest(binding?.providerBindingHash), 'deployment_provider_binding_hash_invalid');
  addReason(reasons, !isDigest(binding?.receiptHash), 'deployment_provider_binding_receipt_hash_invalid');
  addReason(
    reasons,
    binding?.receiptArtifactType !== 'deployment_provider_binding',
    'deployment_provider_binding_receipt_type_invalid',
  );
  addReason(
    reasons,
    !DEPLOYMENT_PROVIDER_BINDING_STATUSES.has(binding?.status),
    'deployment_provider_binding_status_invalid',
  );
  addReason(
    reasons,
    binding?.releaseCandidateRef !== cycle?.releaseCandidateRef,
    'deployment_provider_binding_release_candidate_mismatch',
  );
  addReason(
    reasons,
    !isDigest(binding?.operationsReadinessReceiptHash),
    'deployment_provider_binding_operations_receipt_hash_invalid',
  );
  addReason(
    reasons,
    binding?.operationsReadinessReceiptHash !== operationsSummary.receiptHash,
    'deployment_provider_binding_operations_receipt_mismatch',
  );
  addReason(
    reasons,
    !isDigest(binding?.deploymentReadinessManifestReceiptHash),
    'deployment_provider_binding_manifest_receipt_hash_invalid',
  );
  addReason(
    reasons,
    binding?.deploymentReadinessManifestReceiptHash !== manifestSummary.receiptHash,
    'deployment_provider_binding_manifest_receipt_mismatch',
  );
  addReason(reasons, binding?.trustState !== 'inactive', 'deployment_provider_binding_trust_state_invalid');
  addReason(reasons, binding?.baselineProviderBindingReady !== true, 'deployment_provider_binding_baseline_not_ready');
  addReason(reasons, binding?.productionTrustClaim === true, 'deployment_provider_binding_production_claim_forbidden');
  addReason(reasons, binding?.metadataOnly !== true, 'deployment_provider_binding_metadata_boundary_invalid');
  addReason(reasons, binding?.protectedContentExcluded !== true, 'deployment_provider_binding_protected_boundary_invalid');
  addReason(reasons, hlcTuple(binding?.reviewedAtHlc) === null, 'deployment_provider_binding_review_time_invalid');
  addReason(
    reasons,
    hlcAfter(binding?.reviewedAtHlc, cycle?.validationRecordedAtHlc),
    'deployment_provider_binding_after_validation',
  );

  return {
    baselineProviderBindingReady: binding?.baselineProviderBindingReady === true,
    deploymentReadinessManifestReceiptHash: binding?.deploymentReadinessManifestReceiptHash ?? null,
    operationsReadinessReceiptHash: binding?.operationsReadinessReceiptHash ?? null,
    productionProviderBindingReady: binding?.productionProviderBindingReady === true,
    providerBindingHash: binding?.providerBindingHash ?? null,
    providerBindingRef: binding?.providerBindingRef ?? null,
    receiptArtifactType: binding?.receiptArtifactType ?? null,
    receiptHash: binding?.receiptHash ?? null,
    releaseCandidateRef: binding?.releaseCandidateRef ?? null,
    status: binding?.status ?? 'invalid',
    trustState: binding?.trustState ?? 'invalid',
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
  addReason(reasons, evidence?.productionClaimLiftCanLiftProductionClaim !== false, `${prefix}_production_claim_lift_forbidden`);
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

function evaluateDeploymentHandoffCutover(handoff, manifestSummary, operationsSummary, providerSummary, cycle, reasons) {
  addReason(reasons, handoff === null || handoff === undefined, 'deployment_handoff_cutover_absent');
  addReason(reasons, !hasText(handoff?.handoffRef), 'deployment_handoff_cutover_ref_absent');
  addReason(reasons, !isDigest(handoff?.handoffHash), 'deployment_handoff_cutover_hash_invalid');
  addReason(reasons, !isDigest(handoff?.receiptHash), 'deployment_handoff_cutover_receipt_hash_invalid');
  addReason(
    reasons,
    handoff?.receiptArtifactType !== 'deployment_handoff_cutover',
    'deployment_handoff_cutover_receipt_type_invalid',
  );
  addReason(
    reasons,
    !DEPLOYMENT_HANDOFF_CUTOVER_STATUSES.has(handoff?.status),
    'deployment_handoff_cutover_status_invalid',
  );
  addReason(
    reasons,
    handoff?.releaseCandidateRef !== cycle?.releaseCandidateRef,
    'deployment_handoff_cutover_release_candidate_mismatch',
  );
  addReason(
    reasons,
    !isDigest(handoff?.deploymentReadinessManifestReceiptHash),
    'deployment_handoff_cutover_manifest_receipt_hash_invalid',
  );
  addReason(
    reasons,
    handoff?.deploymentReadinessManifestReceiptHash !== manifestSummary.receiptHash,
    'deployment_handoff_cutover_manifest_receipt_mismatch',
  );
  addReason(
    reasons,
    !isDigest(handoff?.deploymentOperationsReadinessHash),
    'deployment_handoff_cutover_operations_hash_invalid',
  );
  addReason(
    reasons,
    handoff?.deploymentOperationsReadinessHash !== operationsSummary.operationsReadinessHash,
    'deployment_handoff_cutover_operations_hash_mismatch',
  );
  addReason(
    reasons,
    !isDigest(handoff?.deploymentProviderBindingReceiptHash),
    'deployment_handoff_cutover_provider_receipt_hash_invalid',
  );
  addReason(
    reasons,
    handoff?.deploymentProviderBindingReceiptHash !== providerSummary.receiptHash,
    'deployment_handoff_cutover_provider_receipt_mismatch',
  );
  addReason(reasons, handoff?.baselineHandoffReady !== true, 'deployment_handoff_cutover_baseline_not_ready');
  addReason(reasons, handoff?.trustState !== 'inactive', 'deployment_handoff_cutover_trust_state_invalid');
  addReason(reasons, handoff?.productionTrustClaim === true, 'deployment_handoff_cutover_production_claim_forbidden');
  addReason(reasons, handoff?.metadataOnly !== true, 'deployment_handoff_cutover_metadata_boundary_invalid');
  addReason(reasons, handoff?.protectedContentExcluded !== true, 'deployment_handoff_cutover_protected_boundary_invalid');
  addReason(reasons, hlcTuple(handoff?.reviewedAtHlc) === null, 'deployment_handoff_cutover_review_time_invalid');
  addReason(reasons, hlcAfter(handoff?.reviewedAtHlc, cycle?.validationRecordedAtHlc), 'deployment_handoff_cutover_after_validation');

  const deploymentReadinessRoleDashboardTrustStateEvidence = evaluateRoleDashboardTrustStateEvidence(
    handoff?.deploymentReadinessRoleDashboardTrustStateEvidence,
    handoff,
    reasons,
    'deployment_handoff_readiness_role_dashboard',
    'handoff_review',
  );
  const deploymentProviderBindingRoleDashboardTrustStateEvidence = evaluateRoleDashboardTrustStateEvidence(
    handoff?.deploymentProviderBindingRoleDashboardTrustStateEvidence,
    handoff,
    reasons,
    'deployment_handoff_provider_binding_role_dashboard',
    'handoff_review',
  );

  return {
    baselineHandoffReady: handoff?.baselineHandoffReady === true,
    deploymentOperationsReadinessHash: handoff?.deploymentOperationsReadinessHash ?? null,
    deploymentProviderBindingReceiptHash: handoff?.deploymentProviderBindingReceiptHash ?? null,
    deploymentProviderBindingRoleDashboardTrustStateEvidence,
    deploymentReadinessManifestReceiptHash: handoff?.deploymentReadinessManifestReceiptHash ?? null,
    deploymentReadinessRoleDashboardTrustStateEvidence,
    handoffHash: handoff?.handoffHash ?? null,
    handoffRef: handoff?.handoffRef ?? null,
    productionCutoverReady: handoff?.productionCutoverReady === true,
    receiptArtifactType: handoff?.receiptArtifactType ?? null,
    receiptHash: handoff?.receiptHash ?? null,
    releaseCandidateRef: handoff?.releaseCandidateRef ?? null,
    status: handoff?.status ?? 'invalid',
    trustState: handoff?.trustState ?? 'invalid',
  };
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  addReason(reasons, validation === null || validation === undefined, 'validation_evidence_absent');
  addReason(reasons, sortedTextList(validation?.commandRefs).length === 0, 'validation_command_refs_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, !Number.isSafeInteger(validation?.testCount) || validation.testCount <= 0, 'validation_test_count_invalid');
  addReason(reasons, !isBasisPoints(validation?.coverageLineBasisPoints), 'validation_coverage_invalid');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_absent');
  addReason(reasons, validation?.secretScanPassed !== true, 'validation_secret_scan_absent');
  addReason(reasons, !isDigest(validation?.configSchemaEvidenceHash), 'config_schema_evidence_hash_invalid');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'validation_exochain_read_only_absent');
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
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'runtime_configuration_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'runtime_configuration_audit_record_hash_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'runtime_configuration_audit_record_metadata_boundary_invalid');
  addReason(
    reasons,
    auditRecord?.includesProtectedContent === true,
    'runtime_configuration_audit_record_protected_content_forbidden',
  );
  addReason(reasons, hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'runtime_configuration_audit_record_time_invalid');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, cycle?.auditRecordedAtHlc), 'runtime_configuration_audit_before_cycle_audit_step');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, review?.reviewedAtHlc), 'runtime_configuration_audit_before_review');
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

function buildRuntimeConfiguration(
  input,
  policySummary,
  runtimeSummary,
  domainSummary,
  adapterSummary,
  secretScopeSummary,
  deploymentReadinessManifestSummary,
  deploymentOperationsReadinessSummary,
  deploymentProviderBindingSummary,
  deploymentHandoffCutoverSummary,
) {
  const activationBlockerIds = uniqueSorted([
    ...domainSummary.blockerIds,
    ...adapterSummary.blockerIds,
    ...secretScopeSummary.blockerIds,
  ]);
  const productionConfigurationReady =
    activationBlockerIds.length === 0 &&
    adapterSummary.allAdaptersVerified === true &&
    secretScopeSummary.status === 'verified';
  const runtimeConfigurationHash = sha256Hex({
    activationBlockerIds,
    adapterSummaries: adapterSummary.summaries,
    auditRecordHash: input.auditRecord.auditRecordHash,
    configurationRef: input.configurationCycle.configurationRef,
    deploymentOperationsReadinessHash: input.deploymentOperationsReadiness.operationsReadinessHash,
    deploymentOperationsReadinessReceiptHash: input.deploymentOperationsReadiness.receiptHash,
    deploymentProviderBindingHash: input.deploymentProviderBinding.providerBindingHash,
    deploymentProviderBindingReceiptHash: input.deploymentProviderBinding.receiptHash,
    deploymentHandoffCutoverHash: input.deploymentHandoffCutover.handoffHash,
    deploymentHandoffCutoverReceiptHash: input.deploymentHandoffCutover.receiptHash,
    deploymentHandoffCutoverProviderRoleDashboardReceiptHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence.roleDashboardReceiptHash,
    deploymentHandoffCutoverProviderRoleDashboardSummaryHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence.roleDashboardSummaryHash,
    deploymentHandoffCutoverProviderRoleDashboardTrustStateViewHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence.roleDashboardTrustStateViewHash,
    deploymentHandoffCutoverProviderClaimLiftProviderRoleDashboardReceiptHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardProviderReceiptHash,
    deploymentHandoffCutoverProviderClaimLiftProviderRoleDashboardSummaryHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardProviderSummaryHash,
    deploymentHandoffCutoverProviderClaimLiftProviderRoleDashboardTrustStateViewHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardProviderTrustStateViewHash,
    deploymentHandoffCutoverProviderClaimLiftReadinessRoleDashboardReceiptHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardReadinessReceiptHash,
    deploymentHandoffCutoverProviderClaimLiftReadinessRoleDashboardSummaryHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardReadinessSummaryHash,
    deploymentHandoffCutoverProviderClaimLiftReadinessRoleDashboardTrustStateViewHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardReadinessTrustStateViewHash,
    deploymentHandoffCutoverProviderClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    deploymentHandoffCutoverProviderClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    deploymentHandoffCutoverProviderClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    deploymentHandoffCutoverProviderClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    deploymentHandoffCutoverProviderClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    deploymentHandoffCutoverProviderClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    deploymentHandoffCutoverProviderClaimLiftRoleDashboardRoles:
      input.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardRoles,
    deploymentHandoffCutoverReadinessRoleDashboardReceiptHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence.roleDashboardReceiptHash,
    deploymentHandoffCutoverReadinessRoleDashboardSummaryHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence.roleDashboardSummaryHash,
    deploymentHandoffCutoverReadinessRoleDashboardTrustStateViewHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence.roleDashboardTrustStateViewHash,
    deploymentHandoffCutoverReadinessClaimLiftProviderRoleDashboardReceiptHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardProviderReceiptHash,
    deploymentHandoffCutoverReadinessClaimLiftProviderRoleDashboardSummaryHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardProviderSummaryHash,
    deploymentHandoffCutoverReadinessClaimLiftProviderRoleDashboardTrustStateViewHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardProviderTrustStateViewHash,
    deploymentHandoffCutoverReadinessClaimLiftReadinessRoleDashboardReceiptHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardReadinessReceiptHash,
    deploymentHandoffCutoverReadinessClaimLiftReadinessRoleDashboardSummaryHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardReadinessSummaryHash,
    deploymentHandoffCutoverReadinessClaimLiftReadinessRoleDashboardTrustStateViewHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardReadinessTrustStateViewHash,
    deploymentHandoffCutoverReadinessClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    deploymentHandoffCutoverReadinessClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    deploymentHandoffCutoverReadinessClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    deploymentHandoffCutoverReadinessClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    deploymentHandoffCutoverReadinessClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    deploymentHandoffCutoverReadinessClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    deploymentHandoffCutoverReadinessClaimLiftRoleDashboardRoles:
      input.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
        .productionClaimLiftRoleDashboardRoles,
    deploymentReadinessManifestHash: input.deploymentReadinessManifest.manifestHash,
    deploymentReadinessManifestReceiptHash: input.deploymentReadinessManifest.receiptHash,
    deploymentReadinessStateUpdateHash: input.deploymentReadinessManifest.driftStateUpdateEvidence.stateUpdateHash,
    domainSummaries: domainSummary.summaries,
    humanDecisionHash: input.humanReview.decisionHash,
    policyHash: input.configurationPolicy.policyHash,
    releaseCandidateRef: input.configurationCycle.releaseCandidateRef,
    runtimeSummary,
    secretScopeSummary,
    tenantId: input.tenantId,
    validationEvidenceHash: input.validationEvidence.configSchemaEvidenceHash,
  });

  return {
    schema: CONFIGURATION_SCHEMA,
    runtimeConfigurationSourceId: `cmrcs_${sha256Hex({
      releaseCandidateRef: input.configurationCycle.releaseCandidateRef,
      runtimeConfigurationHash,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    releaseCandidateRef: input.configurationCycle.releaseCandidateRef,
    trustState: 'inactive',
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    baselineConfigurationReady: true,
    productionConfigurationReady,
    allowedActivationBlockerIds: policySummary.allowedActivationBlockerIds,
    configurationDomainsCovered: domainSummary.domains,
    configurationDomainSummaries: domainSummary.summaries,
    adaptersCovered: adapterSummary.adapterKinds,
    adapterSummaries: adapterSummary.summaries,
    activationBlockerIds,
    runtime: runtimeSummary,
    secretScope: secretScopeSummary,
    deploymentReadinessManifest: deploymentReadinessManifestSummary,
    deploymentOperationsReadiness: deploymentOperationsReadinessSummary,
    deploymentProviderBinding: deploymentProviderBindingSummary,
    deploymentHandoffCutover: deploymentHandoffCutoverSummary,
    validationSummary: {
      commandRefs: sortedTextList(input.validationEvidence.commandRefs),
      coverageLineBasisPoints: input.validationEvidence.coverageLineBasisPoints,
      secretScanPassed: true,
      sourceGuardPassed: true,
      testCount: input.validationEvidence.testCount,
    },
    runtimeConfigurationHash,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, configuration) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: configuration.runtimeConfigurationHash,
    artifactType: 'runtime_configuration_source',
    artifactVersion: input.configurationCycle.releaseCandidateRef,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: [
      'continuous_quality_improvement',
      'deployment_operations',
      'deployment_provider_binding',
      'deployment_handoff_cutover',
      'deployment_readiness_manifest',
      'drift_state_update',
      'inactive_trust_state',
      'manual_navigation_readiness',
      'metadata_only',
      'role_dashboard_trust_state',
      'runtime_configuration_source',
    ],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateRuntimeConfigurationSource(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateConfigurationPolicy(input?.configurationPolicy, reasons);
  evaluateConfigurationCycle(input?.configurationCycle, input?.configurationPolicy, reasons);
  const runtimeSummary = evaluateRuntimeConfiguration(input?.runtimeConfiguration, input?.configurationCycle, reasons);
  const domainSummary = evaluateConfigurationDomains(
    input?.configurationDomains,
    policySummary,
    input?.configurationCycle,
    reasons,
  );
  const adapterSummary = evaluateAdapterBindings(input?.adapterBindings, policySummary, input?.configurationCycle, reasons);
  const secretScopeSummary = evaluateSecretScope(input?.secretScope, policySummary, input?.configurationCycle, reasons);
  const deploymentReadinessManifestSummary = evaluateDeploymentReadinessManifest(
    input?.deploymentReadinessManifest,
    input?.configurationCycle,
    reasons,
  );
  const deploymentOperationsReadinessSummary = evaluateDeploymentOperationsReadiness(
    input?.deploymentOperationsReadiness,
    deploymentReadinessManifestSummary,
    policySummary,
    input?.configurationCycle,
    reasons,
  );
  const deploymentProviderBindingSummary = evaluateDeploymentProviderBinding(
    input?.deploymentProviderBinding,
    deploymentOperationsReadinessSummary,
    deploymentReadinessManifestSummary,
    input?.configurationCycle,
    reasons,
  );
  const deploymentHandoffCutoverSummary = evaluateDeploymentHandoffCutover(
    input?.deploymentHandoffCutover,
    deploymentReadinessManifestSummary,
    deploymentOperationsReadinessSummary,
    deploymentProviderBindingSummary,
    input?.configurationCycle,
    reasons,
  );
  evaluateValidationEvidence(input?.validationEvidence, input?.configurationCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.configurationCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.configurationCycle, input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      runtimeConfiguration: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const runtimeConfiguration = buildRuntimeConfiguration(
    input,
    policySummary,
    runtimeSummary,
    domainSummary,
    adapterSummary,
    secretScopeSummary,
    deploymentReadinessManifestSummary,
    deploymentOperationsReadinessSummary,
    deploymentProviderBindingSummary,
    deploymentHandoffCutoverSummary,
  );

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    runtimeConfiguration,
    receipt: buildReceipt(input, runtimeConfiguration),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
