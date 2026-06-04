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
const HANDOFF_SCHEMA = 'cybermedica.deployment_handoff_cutover.v1';
const DECISION_SCHEMA = 'cybermedica.deployment_handoff_cutover_decision.v1';
const DATABASE_MIGRATION_READINESS_SCHEMA = 'cybermedica.database_migration_readiness.v1';
const DATABASE_MIGRATION_READINESS_RECEIPT_TYPE = 'database_migration_readiness';
const REQUIRED_PERMISSION = 'deployment_handoff_review';

const REQUIRED_HANDOFF_DOMAINS = Object.freeze([
  'activation_gate_review',
  'communication_plan',
  'deployment_manifest',
  'migration_backup',
  'monitoring_on_call',
  'operations_runbook',
  'provider_binding',
  'rollback_disablement',
  'runtime_configuration',
  'trust_claim_freeze',
]);

const REQUIRED_DRIFT_STATE_TARGETS = Object.freeze(['passport', 'quality_state', 'readiness']);
const REQUIRED_OBJECT_STORAGE_ARTIFACT_CLASSES = Object.freeze([
  'controlled_documents',
  'diligence_exports',
  'evidence_payloads',
  'generated_reports',
  'sensitive_artifacts',
]);
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

const DEFAULT_ALLOWED_CUTOVER_BLOCKER_IDS = Object.freeze([
  'ESC-OPS-SECRETS',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-RUNTIME',
  'PTAG-001',
  'PTAG-016',
  'PTAG-017',
]);

const POLICY_STATUSES = new Set(['active']);
const DOMAIN_STATUSES = new Set(['activation_blocked', 'ready']);
const DEPLOYMENT_READINESS_MANIFEST_STATUSES = new Set(['deployment_readiness_manifest_accepted_inactive_trust']);
const PROVIDER_BINDING_STATUSES = new Set(['deployment_provider_binding_accepted_inactive_trust']);
const RUNTIME_CONFIGURATION_SOURCE_RECEIPT_TYPE = 'runtime_configuration_source';
const HUMAN_REVIEW_DECISIONS = new Set([
  'cutover_ready_verified_runtime',
  'handoff_ready_inactive_trust',
  'hold_for_cutover_gap',
]);

const RAW_HANDOFF_FIELDS = new Set([
  'body',
  'content',
  'cutovernotes',
  'deploymentnotes',
  'freetext',
  'freetextnote',
  'handoffbody',
  'handoffnotes',
  'rawconfiguration',
  'rawcutovercontent',
  'rawcutoverlog',
  'rawcutovernotes',
  'rawdeploymentcontent',
  'rawhandoffcontent',
  'rawhandofflog',
  'rawmigrationplan',
  'rawrunbooktext',
  'rawruntimeconfig',
  'rawvalidationoutput',
  'reviewnotes',
  'runbookbody',
  'runbooktext',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_HANDOFF_FIELDS = new Set([
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

function assertNoRawHandoffContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawHandoffContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_HANDOFF_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw deployment handoff content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_HANDOFF_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`deployment handoff secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawHandoffContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawHandoffContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_deployment_handoff_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'deployment_handoff_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateHandoffPolicy(policy, reasons) {
  const requiredHandoffDomains = sortedTextList(policy?.requiredHandoffDomains);
  const allowedCutoverBlockerIds = sortedTextList(policy?.allowedCutoverBlockerIds);

  addReason(reasons, !hasText(policy?.policyRef), 'handoff_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'handoff_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'handoff_policy_not_active');
  addReason(reasons, policy?.rootVerificationRequiredForTrustClaims !== true, 'root_verification_gate_absent');
  addReason(reasons, policy?.noCredentialDisclosure !== true, 'credential_disclosure_guard_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'handoff_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'handoff_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'handoff_policy_time_invalid');

  evaluateRequiredSet(
    requiredHandoffDomains,
    REQUIRED_HANDOFF_DOMAINS,
    'policy_handoff_domain_missing',
    'policy_handoff_domain_unsupported',
    reasons,
  );

  return {
    allowedCutoverBlockerIds:
      allowedCutoverBlockerIds.length > 0
        ? allowedCutoverBlockerIds
        : [...DEFAULT_ALLOWED_CUTOVER_BLOCKER_IDS],
    requiredHandoffDomains:
      requiredHandoffDomains.length > 0 ? requiredHandoffDomains : [...REQUIRED_HANDOFF_DOMAINS],
  };
}

function evaluateHandoffCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.handoffRef), 'handoff_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'handoff_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'handoff_cycle_protected_boundary_invalid');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['evidenceCollectedAtHlc', cycle?.evidenceCollectedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
    ['humanReviewedAtHlc', cycle?.humanReviewedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `handoff_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'handoff_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(
      reasons,
      hlcBefore(currentValue, previousValue),
      `handoff_cycle_${currentLabel}_before_${previousLabel}`,
    );
  }
}

function evaluateHandoffDomains(handoffDomains, policySummary, cycle, reasons) {
  addReason(reasons, !Array.isArray(handoffDomains) || handoffDomains.length === 0, 'handoff_domains_absent');
  if (!Array.isArray(handoffDomains)) {
    return { blockerIds: [], domains: [], summaries: [] };
  }

  const domains = sortedTextList(handoffDomains.map((entry) => entry?.domain));
  const blockerIds = [];
  const summaries = [];
  const seenDomains = new Set();

  evaluateRequiredSet(
    domains,
    policySummary.requiredHandoffDomains,
    'handoff_domain_missing',
    'handoff_domain_unsupported',
    reasons,
  );

  handoffDomains.forEach((entry, index) => {
    const label = hasText(entry?.domain) ? entry.domain : `index_${index}`;
    addReason(reasons, !hasText(entry?.domain), `handoff_domain_absent:${label}`);
    addReason(reasons, seenDomains.has(entry?.domain), `handoff_domain_duplicate:${label}`);
    if (hasText(entry?.domain)) {
      seenDomains.add(entry.domain);
    }
    addReason(reasons, !DOMAIN_STATUSES.has(entry?.status), `handoff_domain_status_invalid:${label}`);
    addReason(reasons, !hasText(entry?.evidenceRef), `handoff_domain_evidence_ref_absent:${label}`);
    addReason(reasons, !isDigest(entry?.evidenceHash), `handoff_domain_evidence_hash_invalid:${label}`);
    addReason(reasons, !hasText(entry?.ownerDid), `handoff_domain_owner_absent:${label}`);
    addReason(reasons, !hasText(entry?.backupOwnerDid), `handoff_domain_backup_owner_absent:${label}`);
    addReason(reasons, entry?.blocksBaselineDevelopment === true, `handoff_domain_blocks_baseline:${label}`);
    addReason(
      reasons,
      entry?.status === 'activation_blocked' && entry?.productionActivationOnly !== true,
      `handoff_domain_activation_scope_invalid:${label}`,
    );
    addReason(
      reasons,
      entry?.status === 'activation_blocked' && !hasText(entry?.activationBlockerId),
      `handoff_domain_activation_blocker_absent:${label}`,
    );
    addReason(reasons, entry?.reviewedByHuman !== true, `handoff_domain_human_review_absent:${label}`);
    addReason(reasons, hlcTuple(entry?.reviewedAtHlc) === null, `handoff_domain_review_time_invalid:${label}`);
    addReason(reasons, hlcAfter(entry?.reviewedAtHlc, cycle?.validationRecordedAtHlc), `handoff_domain_review_after_validation:${label}`);
    addReason(reasons, entry?.metadataOnly !== true, `handoff_domain_metadata_boundary_invalid:${label}`);
    addReason(reasons, entry?.protectedContentExcluded !== true, `handoff_domain_protected_boundary_invalid:${label}`);
    addReason(reasons, entry?.productionTrustClaim === true, `handoff_domain_production_claim_forbidden:${label}`);

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

function evaluateRuntimeConfiguration(config, cycle, reasons) {
  addReason(reasons, config === null || config === undefined, 'runtime_configuration_absent');
  addReason(reasons, !hasText(config?.configurationRef), 'runtime_configuration_ref_absent');
  addReason(reasons, !isDigest(config?.configurationHash), 'runtime_configuration_hash_invalid');
  addReason(reasons, !hasText(config?.configurationSource), 'runtime_configuration_source_absent');
  addReason(reasons, !isDigest(config?.environmentManifestHash), 'runtime_environment_manifest_hash_invalid');
  addReason(reasons, !isDigest(config?.secretScopeHash), 'runtime_secret_scope_hash_invalid');
  addReason(reasons, !isDigest(config?.trustFeatureFlagHash), 'runtime_trust_feature_flag_hash_invalid');
  addReason(reasons, typeof config?.trustClaimsDisabled !== 'boolean', 'runtime_trust_claim_state_invalid');
  addReason(reasons, typeof config?.rootBundleProviderConfigured !== 'boolean', 'runtime_root_provider_state_invalid');
  addReason(reasons, typeof config?.adapterEndpointConfigured !== 'boolean', 'runtime_adapter_endpoint_state_invalid');
  addReason(reasons, config?.browserAuthoritativePathEnabled === true, 'browser_authoritative_path_forbidden');
  addReason(reasons, config?.missingSecretsFailClosed !== true, 'missing_secret_fail_closed_absent');
  addReason(reasons, config?.processHealthSeparatedFromTrustReadiness !== true, 'health_trust_separation_absent');
  addReason(reasons, config?.metadataOnly !== true, 'runtime_configuration_metadata_boundary_invalid');
  addReason(reasons, config?.protectedContentExcluded !== true, 'runtime_configuration_protected_boundary_invalid');
  addReason(reasons, hlcTuple(config?.reviewedAtHlc) === null, 'runtime_configuration_review_time_invalid');
  addReason(reasons, hlcAfter(config?.reviewedAtHlc, cycle?.validationRecordedAtHlc), 'runtime_configuration_after_validation');
  addReason(
    reasons,
    config?.trustClaimsDisabled !== true &&
      !(config?.rootBundleProviderConfigured === true && config?.adapterEndpointConfigured === true),
    'trust_claim_flag_without_verified_runtime',
  );

  const runtimeReadyForCutover =
    config?.trustClaimsDisabled === false &&
    config?.rootBundleProviderConfigured === true &&
    config?.adapterEndpointConfigured === true &&
    config?.browserAuthoritativePathEnabled !== true &&
    config?.missingSecretsFailClosed === true &&
    config?.processHealthSeparatedFromTrustReadiness === true;

  return {
    adapterEndpointConfigured: config?.adapterEndpointConfigured === true,
    configurationHash: config?.configurationHash ?? null,
    configurationRef: config?.configurationRef ?? null,
    configurationSource: config?.configurationSource ?? null,
    environmentManifestHash: config?.environmentManifestHash ?? null,
    missingSecretsFailClosed: config?.missingSecretsFailClosed === true,
    processHealthSeparatedFromTrustReadiness: config?.processHealthSeparatedFromTrustReadiness === true,
    rootBundleProviderConfigured: config?.rootBundleProviderConfigured === true,
    runtimeReadyForCutover,
    secretScopeHash: config?.secretScopeHash ?? null,
    trustClaimsDisabled: config?.trustClaimsDisabled === true,
    trustFeatureFlagHash: config?.trustFeatureFlagHash ?? null,
  };
}

function evaluateDeploymentReadinessDriftStateUpdateEvidence(evidence, artifacts, reasons) {
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
    hlcAfter(evidence?.reviewedAtHlc, artifacts?.linkedAtHlc),
    'deployment_readiness_drift_state_update_after_manifest_linkage',
  );

  for (const target of REQUIRED_DRIFT_STATE_TARGETS) {
    addReason(reasons, !stateUpdateTargets.includes(target), `deployment_readiness_drift_state_update_target_missing:${target}`);
  }
  for (const target of stateUpdateTargets) {
    addReason(
      reasons,
      !REQUIRED_DRIFT_STATE_TARGETS.includes(target),
      `deployment_readiness_drift_state_update_target_unsupported:${target}`,
    );
  }

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
  };
}

function evaluateRoleDashboardTrustStateEvidence(evidence, artifacts, reasons, prefix) {
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
  addReason(reasons, hlcAfter(evidence?.reviewedAtHlc, artifacts?.linkedAtHlc), `${prefix}_after_artifact_linkage`);

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

function evaluateHandoffArtifacts(artifacts, cycle, reasons) {
  addReason(reasons, artifacts === null || artifacts === undefined, 'handoff_artifacts_absent');
  addReason(reasons, !isDigest(artifacts?.deploymentReadinessManifestHash), 'deployment_readiness_manifest_hash_invalid');
  addReason(
    reasons,
    !isDigest(artifacts?.deploymentReadinessManifestReceiptHash),
    'deployment_readiness_manifest_receipt_hash_invalid',
  );
  addReason(
    reasons,
    artifacts?.deploymentReadinessManifestReceiptArtifactType !== 'deployment_readiness_manifest',
    'deployment_readiness_manifest_receipt_type_invalid',
  );
  addReason(
    reasons,
    !DEPLOYMENT_READINESS_MANIFEST_STATUSES.has(artifacts?.deploymentReadinessManifestStatus),
    'deployment_readiness_manifest_status_invalid',
  );
  addReason(
    reasons,
    artifacts?.deploymentReadinessManifestReleaseCandidateRef !== cycle?.releaseCandidateRef,
    'deployment_readiness_manifest_release_candidate_mismatch',
  );
  addReason(
    reasons,
    artifacts?.deploymentReadinessManifestTrustState !== 'inactive',
    'deployment_readiness_manifest_trust_state_invalid',
  );
  addReason(
    reasons,
    artifacts?.deploymentReadinessManifestBaselineReady !== true,
    'deployment_readiness_manifest_baseline_not_ready',
  );
  addReason(
    reasons,
    artifacts?.deploymentReadinessManifestProductionClaim === true,
    'deployment_readiness_manifest_production_claim_forbidden',
  );
  const deploymentReadinessDriftStateUpdateEvidence = evaluateDeploymentReadinessDriftStateUpdateEvidence(
    artifacts?.deploymentReadinessDriftStateUpdateEvidence,
    artifacts,
    reasons,
  );
  const deploymentReadinessRoleDashboardTrustStateEvidence = evaluateRoleDashboardTrustStateEvidence(
    artifacts?.deploymentReadinessRoleDashboardTrustStateEvidence,
    artifacts,
    reasons,
    'deployment_readiness_role_dashboard',
  );
  addReason(reasons, !isDigest(artifacts?.deploymentProviderBindingHash), 'deployment_provider_binding_hash_invalid');
  addReason(
    reasons,
    !isDigest(artifacts?.deploymentProviderBindingReceiptHash),
    'deployment_provider_binding_receipt_hash_invalid',
  );
  addReason(
    reasons,
    artifacts?.deploymentProviderBindingReceiptArtifactType !== 'deployment_provider_binding',
    'deployment_provider_binding_receipt_type_invalid',
  );
  addReason(
    reasons,
    !PROVIDER_BINDING_STATUSES.has(artifacts?.deploymentProviderBindingStatus),
    'deployment_provider_binding_status_invalid',
  );
  addReason(
    reasons,
    artifacts?.deploymentProviderBindingReleaseCandidateRef !== cycle?.releaseCandidateRef,
    'deployment_provider_binding_release_candidate_mismatch',
  );
  addReason(
    reasons,
    artifacts?.deploymentProviderBindingTrustState !== 'inactive',
    'deployment_provider_binding_trust_state_invalid',
  );
  addReason(
    reasons,
    artifacts?.deploymentProviderBindingBaselineReady !== true,
    'deployment_provider_binding_baseline_not_ready',
  );
  addReason(
    reasons,
    artifacts?.deploymentProviderBindingProductionClaim === true,
    'deployment_provider_binding_production_claim_forbidden',
  );
  const deploymentProviderBindingRoleDashboardTrustStateEvidence = evaluateRoleDashboardTrustStateEvidence(
    artifacts?.deploymentProviderBindingRoleDashboardTrustStateEvidence,
    artifacts,
    reasons,
    'deployment_provider_binding_role_dashboard',
  );
  addReason(reasons, !isDigest(artifacts?.deploymentOperationsReadinessHash), 'deployment_operations_readiness_hash_invalid');
  addReason(reasons, !isDigest(artifacts?.releaseReadinessMatrixHash), 'release_readiness_matrix_hash_invalid');
  addReason(reasons, !isDigest(artifacts?.releaseIncidentLinkageHash), 'release_incident_linkage_hash_invalid');
  addReason(reasons, !isDigest(artifacts?.releaseIncidentLinkageReceiptHash), 'release_incident_linkage_receipt_hash_invalid');
  addReason(reasons, !isDigest(artifacts?.requirementTraceabilityHash), 'requirement_traceability_hash_invalid');
  addReason(reasons, !isDigest(artifacts?.pathClassificationHash), 'path_classification_hash_invalid');
  addReason(reasons, !isDigest(artifacts?.activationGateRegisterHash), 'activation_gate_register_hash_invalid');
  addReason(reasons, !isDigest(artifacts?.validationEvidenceHash), 'artifact_validation_evidence_hash_invalid');
  addReason(reasons, artifacts?.metadataOnly !== true, 'handoff_artifacts_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(artifacts?.linkedAtHlc) === null, 'handoff_artifacts_link_time_invalid');
  addReason(reasons, hlcAfter(artifacts?.linkedAtHlc, cycle?.validationRecordedAtHlc), 'handoff_artifacts_after_validation');

  return {
    activationGateRegisterHash: artifacts?.activationGateRegisterHash ?? null,
    deploymentReadinessDriftStateUpdateEvidence,
    deploymentReadinessRoleDashboardTrustStateEvidence,
    deploymentReadinessManifestBaselineReady: artifacts?.deploymentReadinessManifestBaselineReady === true,
    deploymentReadinessManifestProductionClaim: artifacts?.deploymentReadinessManifestProductionClaim === true,
    deploymentReadinessManifestReceiptArtifactType: artifacts?.deploymentReadinessManifestReceiptArtifactType ?? null,
    deploymentReadinessManifestReceiptHash: artifacts?.deploymentReadinessManifestReceiptHash ?? null,
    deploymentReadinessManifestReleaseCandidateRef: artifacts?.deploymentReadinessManifestReleaseCandidateRef ?? null,
    deploymentReadinessManifestStatus: artifacts?.deploymentReadinessManifestStatus ?? null,
    deploymentReadinessManifestTrustState: artifacts?.deploymentReadinessManifestTrustState ?? null,
    deploymentOperationsReadinessHash: artifacts?.deploymentOperationsReadinessHash ?? null,
    deploymentProviderBindingHash: artifacts?.deploymentProviderBindingHash ?? null,
    deploymentProviderBindingBaselineReady: artifacts?.deploymentProviderBindingBaselineReady === true,
    deploymentProviderBindingProductionClaim: artifacts?.deploymentProviderBindingProductionClaim === true,
    deploymentProviderBindingReceiptArtifactType: artifacts?.deploymentProviderBindingReceiptArtifactType ?? null,
    deploymentProviderBindingReceiptHash: artifacts?.deploymentProviderBindingReceiptHash ?? null,
    deploymentProviderBindingReleaseCandidateRef: artifacts?.deploymentProviderBindingReleaseCandidateRef ?? null,
    deploymentProviderBindingRoleDashboardTrustStateEvidence,
    deploymentProviderBindingStatus: artifacts?.deploymentProviderBindingStatus ?? null,
    deploymentProviderBindingTrustState: artifacts?.deploymentProviderBindingTrustState ?? null,
    deploymentReadinessManifestHash: artifacts?.deploymentReadinessManifestHash ?? null,
    pathClassificationHash: artifacts?.pathClassificationHash ?? null,
    releaseIncidentLinkageHash: artifacts?.releaseIncidentLinkageHash ?? null,
    releaseIncidentLinkageReceiptHash: artifacts?.releaseIncidentLinkageReceiptHash ?? null,
    releaseReadinessMatrixHash: artifacts?.releaseReadinessMatrixHash ?? null,
    requirementTraceabilityHash: artifacts?.requirementTraceabilityHash ?? null,
    validationEvidenceHash: artifacts?.validationEvidenceHash ?? null,
  };
}

function evaluateRuntimeConfigurationSourceLineage(source, runtimeSummary, artifactSummary, policySummary, cycle, reasons) {
  addReason(reasons, source === null || source === undefined, 'runtime_configuration_source_lineage_absent');
  addReason(reasons, !hasText(source?.runtimeConfigurationSourceId), 'runtime_configuration_source_id_absent');
  addReason(reasons, !isDigest(source?.runtimeConfigurationHash), 'runtime_configuration_source_hash_invalid');
  addReason(reasons, !isDigest(source?.receiptHash), 'runtime_configuration_source_receipt_hash_invalid');
  addReason(
    reasons,
    source?.receiptArtifactType !== RUNTIME_CONFIGURATION_SOURCE_RECEIPT_TYPE,
    'runtime_configuration_source_receipt_type_invalid',
  );
  addReason(
    reasons,
    source?.releaseCandidateRef !== cycle?.releaseCandidateRef,
    'runtime_configuration_source_release_candidate_mismatch',
  );
  addReason(reasons, source?.trustState !== 'inactive', 'runtime_configuration_source_trust_state_invalid');
  addReason(
    reasons,
    source?.baselineConfigurationReady !== true,
    'runtime_configuration_source_baseline_not_ready',
  );
  addReason(
    reasons,
    source?.productionTrustClaim === true,
    'runtime_configuration_source_production_claim_forbidden',
  );
  addReason(reasons, !isDigest(source?.configurationHash), 'runtime_configuration_source_configuration_hash_invalid');
  addReason(reasons, !isDigest(source?.secretScopeHash), 'runtime_configuration_source_secret_scope_hash_invalid');
  addReason(
    reasons,
    !isDigest(source?.trustFeatureFlagHash),
    'runtime_configuration_source_trust_feature_flag_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(source?.deploymentReadinessManifestReceiptHash),
    'runtime_configuration_source_manifest_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(source?.deploymentOperationsReadinessHash),
    'runtime_configuration_source_operations_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(source?.deploymentProviderBindingReceiptHash),
    'runtime_configuration_source_provider_receipt_hash_invalid',
  );
  addReason(
    reasons,
    isDigest(source?.configurationHash) && source.configurationHash !== runtimeSummary.configurationHash,
    'runtime_configuration_source_configuration_hash_mismatch',
  );
  addReason(
    reasons,
    isDigest(source?.secretScopeHash) && source.secretScopeHash !== runtimeSummary.secretScopeHash,
    'runtime_configuration_source_secret_scope_hash_mismatch',
  );
  addReason(
    reasons,
    isDigest(source?.trustFeatureFlagHash) && source.trustFeatureFlagHash !== runtimeSummary.trustFeatureFlagHash,
    'runtime_configuration_source_trust_feature_flag_hash_mismatch',
  );
  addReason(
    reasons,
    isDigest(source?.deploymentReadinessManifestReceiptHash) &&
      source.deploymentReadinessManifestReceiptHash !== artifactSummary.deploymentReadinessManifestReceiptHash,
    'runtime_configuration_source_manifest_receipt_mismatch',
  );
  addReason(
    reasons,
    isDigest(source?.deploymentOperationsReadinessHash) &&
      source.deploymentOperationsReadinessHash !== artifactSummary.deploymentOperationsReadinessHash,
    'runtime_configuration_source_operations_hash_mismatch',
  );
  addReason(
    reasons,
    isDigest(source?.deploymentProviderBindingReceiptHash) &&
      source.deploymentProviderBindingReceiptHash !== artifactSummary.deploymentProviderBindingReceiptHash,
    'runtime_configuration_source_provider_receipt_mismatch',
  );
  addReason(reasons, source?.metadataOnly !== true, 'runtime_configuration_source_metadata_boundary_invalid');
  addReason(
    reasons,
    source?.protectedContentExcluded !== true,
    'runtime_configuration_source_protected_boundary_invalid',
  );
  addReason(reasons, hlcTuple(source?.reviewedAtHlc) === null, 'runtime_configuration_source_review_time_invalid');
  addReason(reasons, hlcAfter(source?.reviewedAtHlc, cycle?.validationRecordedAtHlc), 'runtime_configuration_source_after_validation');

  const blockerIds = sortedTextList(source?.activationBlockerIds);
  for (const blockerId of blockerIds) {
    addReason(
      reasons,
      !policySummary.allowedCutoverBlockerIds.includes(blockerId),
      `runtime_configuration_source_blocker_not_allowed:${blockerId}`,
    );
  }

  return {
    activationBlockerIds: blockerIds,
    baselineConfigurationReady: source?.baselineConfigurationReady === true,
    configurationHash: source?.configurationHash ?? null,
    deploymentOperationsReadinessHash: source?.deploymentOperationsReadinessHash ?? null,
    deploymentProviderBindingReceiptHash: source?.deploymentProviderBindingReceiptHash ?? null,
    deploymentReadinessManifestReceiptHash: source?.deploymentReadinessManifestReceiptHash ?? null,
    productionConfigurationReady: source?.productionConfigurationReady === true,
    receiptArtifactType: source?.receiptArtifactType ?? null,
    receiptHash: source?.receiptHash ?? null,
    releaseCandidateRef: source?.releaseCandidateRef ?? null,
    runtimeConfigurationHash: source?.runtimeConfigurationHash ?? null,
    runtimeConfigurationSourceId: source?.runtimeConfigurationSourceId ?? null,
    secretScopeHash: source?.secretScopeHash ?? null,
    trustFeatureFlagHash: source?.trustFeatureFlagHash ?? null,
    trustState: source?.trustState ?? 'invalid',
  };
}

function evaluateDatabaseMigrationReadinessEvidence(evidence, cutoverPlan, cycle, reasons) {
  addReason(reasons, evidence === null || evidence === undefined, 'database_migration_readiness_evidence_absent');

  const migrationReadinessReceiptHash = evidence?.migrationReadinessReceiptHash ?? evidence?.receiptHash;
  const objectStorageProviderRef =
    evidence?.objectStorageProviderRef ?? evidence?.objectStorageReadinessSummary?.providerRef;
  const objectStorageArtifactClassesCovered = sortedTextList(
    evidence?.objectStorageArtifactClassesCovered ?? evidence?.objectStorageReadinessSummary?.artifactClassesCovered,
  );

  addReason(
    reasons,
    evidence?.schema !== DATABASE_MIGRATION_READINESS_SCHEMA,
    'database_migration_readiness_schema_invalid',
  );
  addReason(reasons, !isDigest(evidence?.migrationReadinessHash), 'database_migration_readiness_hash_invalid');
  addReason(reasons, !isDigest(migrationReadinessReceiptHash), 'database_migration_readiness_receipt_hash_invalid');
  addReason(
    reasons,
    evidence?.receiptArtifactType !== DATABASE_MIGRATION_READINESS_RECEIPT_TYPE,
    'database_migration_readiness_receipt_type_invalid',
  );
  addReason(
    reasons,
    evidence?.releaseCandidateRef !== cycle?.releaseCandidateRef,
    'database_migration_readiness_release_candidate_mismatch',
  );
  addReason(reasons, evidence?.trustState !== 'inactive', 'database_migration_readiness_trust_state_invalid');
  addReason(
    reasons,
    evidence?.baselineMigrationReady !== true,
    'database_migration_readiness_baseline_not_ready',
  );
  addReason(
    reasons,
    evidence?.productionActivationReady === true,
    'database_migration_production_activation_forbidden',
  );
  addReason(
    reasons,
    evidence?.exochainProductionClaim === true,
    'database_migration_production_claim_forbidden',
  );
  addReason(
    reasons,
    evidence?.mutableOperationalStateSeparated !== true,
    'database_migration_mutable_state_separation_absent',
  );
  addReason(
    reasons,
    evidence?.exochainReceiptStoreExternal !== true,
    'database_migration_exochain_receipt_store_external_absent',
  );
  addReason(
    reasons,
    evidence?.evidencePayloadStoredOutsideDb !== true,
    'database_migration_evidence_payload_outside_db_absent',
  );
  addReason(
    reasons,
    isDigest(evidence?.migrationReadinessHash) &&
      isDigest(cutoverPlan?.migrationPlanHash) &&
      evidence.migrationReadinessHash !== cutoverPlan.migrationPlanHash,
    'database_migration_plan_hash_mismatch',
  );
  addReason(
    reasons,
    !isDigest(evidence?.objectStorageReadinessReceiptHash),
    'database_migration_object_storage_readiness_receipt_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(evidence?.objectStorageReadinessHash),
    'database_migration_object_storage_readiness_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(evidence?.objectStorageBoundaryHash),
    'database_migration_object_storage_boundary_hash_invalid',
  );
  addReason(
    reasons,
    !hasText(objectStorageProviderRef),
    'database_migration_object_storage_provider_ref_absent',
  );
  for (const artifactClass of REQUIRED_OBJECT_STORAGE_ARTIFACT_CLASSES) {
    addReason(
      reasons,
      !objectStorageArtifactClassesCovered.includes(artifactClass),
      `database_migration_object_storage_artifact_class_missing:${artifactClass}`,
    );
  }
  for (const artifactClass of objectStorageArtifactClassesCovered) {
    addReason(
      reasons,
      !REQUIRED_OBJECT_STORAGE_ARTIFACT_CLASSES.includes(artifactClass),
      `database_migration_object_storage_artifact_class_unsupported:${artifactClass}`,
    );
  }
  addReason(
    reasons,
    evidence?.metadataOnly !== true,
    'database_migration_readiness_metadata_boundary_invalid',
  );
  addReason(
    reasons,
    evidence?.protectedContentExcluded !== true,
    'database_migration_readiness_protected_boundary_invalid',
  );
  addReason(reasons, hlcTuple(evidence?.reviewedAtHlc) === null, 'database_migration_readiness_review_time_invalid');
  addReason(
    reasons,
    hlcAfter(evidence?.reviewedAtHlc, cycle?.validationRecordedAtHlc),
    'database_migration_readiness_after_handoff_validation',
  );

  return {
    baselineMigrationReady: evidence?.baselineMigrationReady === true,
    evidencePayloadStoredOutsideDb: evidence?.evidencePayloadStoredOutsideDb === true,
    exochainProductionClaim: evidence?.exochainProductionClaim === true,
    exochainReceiptStoreExternal: evidence?.exochainReceiptStoreExternal === true,
    migrationReadinessHash: evidence?.migrationReadinessHash ?? null,
    migrationReadinessReceiptHash: migrationReadinessReceiptHash ?? null,
    mutableOperationalStateSeparated: evidence?.mutableOperationalStateSeparated === true,
    objectStorageArtifactClassesCovered,
    objectStorageBoundaryHash: evidence?.objectStorageBoundaryHash ?? null,
    objectStorageProviderRef: objectStorageProviderRef ?? null,
    objectStorageReadinessHash: evidence?.objectStorageReadinessHash ?? null,
    objectStorageReadinessReceiptHash: evidence?.objectStorageReadinessReceiptHash ?? null,
    productionActivationReady: evidence?.productionActivationReady === true,
    receiptArtifactType: evidence?.receiptArtifactType ?? null,
    releaseCandidateRef: evidence?.releaseCandidateRef ?? null,
    schema: evidence?.schema ?? null,
    trustState: evidence?.trustState ?? null,
  };
}

function evaluateCutoverPlan(plan, policySummary, runtimeSummary, cycle, reasons) {
  addReason(reasons, plan === null || plan === undefined, 'cutover_plan_absent');
  addReason(reasons, !isDigest(plan?.migrationPlanHash), 'migration_plan_hash_invalid');
  addReason(reasons, !isDigest(plan?.backupSnapshotHash), 'backup_snapshot_hash_invalid');
  addReason(reasons, !isDigest(plan?.rollbackPlanHash), 'rollback_plan_hash_invalid');
  addReason(reasons, !isDigest(plan?.disablementPlanHash), 'disablement_plan_hash_invalid');
  addReason(reasons, !isDigest(plan?.smokeTestPlanHash), 'smoke_test_plan_hash_invalid');
  addReason(reasons, !isDigest(plan?.preCutoverChecklistHash), 'pre_cutover_checklist_hash_invalid');
  addReason(reasons, !isDigest(plan?.postCutoverObservationWindowHash), 'post_cutover_observation_window_hash_invalid');
  addReason(reasons, !hasText(plan?.cutoverOwnerDid), 'cutover_owner_absent');
  addReason(reasons, !hasText(plan?.backupOwnerDid), 'cutover_backup_owner_absent');
  addReason(reasons, !hasText(plan?.rollbackAuthorityDid), 'rollback_authority_absent');
  addReason(reasons, typeof plan?.cutoverWindowApproved !== 'boolean', 'cutover_window_state_invalid');
  addReason(reasons, typeof plan?.productionEndpointSelected !== 'boolean', 'production_endpoint_state_invalid');
  addReason(
    reasons,
    plan?.productionEndpointSelected === true && runtimeSummary.runtimeReadyForCutover !== true,
    'production_endpoint_without_verified_runtime',
  );
  addReason(reasons, plan?.metadataOnly !== true, 'cutover_plan_metadata_boundary_invalid');
  addReason(reasons, plan?.protectedContentExcluded !== true, 'cutover_plan_protected_boundary_invalid');
  addReason(reasons, hlcTuple(plan?.reviewedAtHlc) === null, 'cutover_plan_review_time_invalid');
  addReason(reasons, hlcAfter(plan?.reviewedAtHlc, cycle?.validationRecordedAtHlc), 'cutover_plan_after_validation');

  const blockerIds = sortedTextList(plan?.activationBlockerIds);
  for (const blockerId of blockerIds) {
    addReason(
      reasons,
      !policySummary.allowedCutoverBlockerIds.includes(blockerId),
      `cutover_blocker_not_allowed:${blockerId}`,
    );
  }

  return {
    backupOwnerDid: plan?.backupOwnerDid ?? null,
    cutoverOwnerDid: plan?.cutoverOwnerDid ?? null,
    cutoverPlanReady:
      plan?.cutoverWindowApproved === true &&
      plan?.productionEndpointSelected === true &&
      blockerIds.length === 0,
    cutoverWindowApproved: plan?.cutoverWindowApproved === true,
    migrationPlanHash: plan?.migrationPlanHash ?? null,
    productionEndpointSelected: plan?.productionEndpointSelected === true,
    rollbackAuthorityDid: plan?.rollbackAuthorityDid ?? null,
    rollbackPlanHash: plan?.rollbackPlanHash ?? null,
    blockerIds,
  };
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  addReason(reasons, validation === null || validation === undefined, 'validation_evidence_absent');
  addReason(reasons, sortedTextList(validation?.commandRefs).length === 0, 'validation_command_refs_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, !Number.isSafeInteger(validation?.testCount) || validation.testCount <= 0, 'validation_test_count_invalid');
  addReason(reasons, !isBasisPoints(validation?.coverageLineBasisPoints), 'validation_coverage_invalid');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_absent');
  addReason(reasons, validation?.dependencyAuditPassed !== true, 'dependency_audit_not_passed');
  addReason(reasons, validation?.secretScanPassed !== true, 'secret_scan_not_passed');
  addReason(reasons, validation?.noExochainSourceModified !== true, 'validation_exochain_read_only_absent');
  addReason(reasons, validation?.metadataOnly !== true, 'validation_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'validation_time_invalid');
  addReason(reasons, hlcBefore(validation?.recordedAtHlc, cycle?.validationRecordedAtHlc), 'validation_before_cycle_validation_step');

  return {
    commandRefs: sortedTextList(validation?.commandRefs),
    coverageLineBasisPoints: validation?.coverageLineBasisPoints ?? null,
    dependencyAuditPassed: validation?.dependencyAuditPassed === true,
    secretScanPassed: validation?.secretScanPassed === true,
    sourceGuardPassed: validation?.sourceGuardPassed === true,
    testCount: validation?.testCount ?? null,
  };
}

function evaluateHumanReview(review, cycle, reasons) {
  addReason(reasons, review === null || review === undefined, 'human_review_absent');
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, sortedTextList(review?.reviewerRoleRefs).length === 0, 'human_review_roles_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.decisionHash), 'human_review_decision_hash_invalid');
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_forbidden');
  addReason(reasons, review?.activationBlockersAccepted !== true, 'activation_blockers_not_accepted');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.humanReviewedAtHlc), 'human_review_before_cycle_review_step');
}

function evaluateAuditRecord(auditRecord, cycle, review, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'handoff_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'handoff_audit_record_hash_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'handoff_audit_record_metadata_boundary_invalid');
  addReason(reasons, auditRecord?.includesProtectedContent === true, 'handoff_audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'handoff_audit_record_time_invalid');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, cycle?.auditRecordedAtHlc), 'handoff_audit_before_cycle_audit_step');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, review?.reviewedAtHlc), 'handoff_audit_before_review');
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

function buildHandoff(
  input,
  policySummary,
  domainSummary,
  runtimeSummary,
  runtimeSourceSummary,
  migrationReadinessSummary,
  artifactSummary,
  cutoverSummary,
  validationSummary,
) {
  const cutoverBlockerIds = uniqueSorted([
    ...domainSummary.blockerIds,
    ...runtimeSourceSummary.activationBlockerIds,
    ...cutoverSummary.blockerIds,
  ]);
  const productionCutoverReady =
    cutoverBlockerIds.length === 0 &&
    runtimeSummary.runtimeReadyForCutover === true &&
    runtimeSourceSummary.productionConfigurationReady === true &&
    cutoverSummary.cutoverPlanReady === true;
  const handoffHash = sha256Hex({
    artifactSummary,
    auditRecordHash: input.auditRecord.auditRecordHash,
    cutoverBlockerIds,
    cutoverSummary,
    domainSummaries: domainSummary.summaries,
    handoffRef: input.handoffCycle.handoffRef,
    humanDecisionHash: input.humanReview.decisionHash,
    migrationReadinessSummary,
    policyHash: input.handoffPolicy.policyHash,
    releaseCandidateRef: input.handoffCycle.releaseCandidateRef,
    runtimeSummary,
    runtimeSourceSummary,
    tenantId: input.tenantId,
    validationSummary,
  });

  return {
    schema: HANDOFF_SCHEMA,
    handoffId: `cmdhc_${sha256Hex({
      handoffHash,
      releaseCandidateRef: input.handoffCycle.releaseCandidateRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    releaseCandidateRef: input.handoffCycle.releaseCandidateRef,
    trustState: 'inactive',
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    baselineHandoffReady: true,
    productionCutoverReady,
    handoffDomainsCovered: domainSummary.domains,
    handoffDomainSummaries: domainSummary.summaries,
    allowedCutoverBlockerIds: policySummary.allowedCutoverBlockerIds,
    cutoverBlockerIds,
    runtimeConfiguration: runtimeSummary,
    runtimeConfigurationSource: runtimeSourceSummary,
    databaseMigrationReadiness: migrationReadinessSummary,
    handoffArtifacts: artifactSummary,
    cutoverPlan: cutoverSummary,
    validationSummary,
    handoffHash,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, handoff) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: handoff.handoffHash,
    artifactType: 'deployment_handoff_cutover',
    artifactVersion: input.handoffCycle.releaseCandidateRef,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: [
      'continuous_quality_improvement',
      'deployment_handoff_cutover',
      'deployment_readiness_manifest',
      'drift_state_update',
      'database_migration_readiness',
      'inactive_trust_state',
      'manual_navigation_readiness',
      'metadata_only',
      'object_storage_readiness_lineage',
      'role_dashboard_trust_state',
      'runtime_configuration_source',
    ],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateDeploymentHandoffCutover(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateHandoffPolicy(input?.handoffPolicy, reasons);
  evaluateHandoffCycle(input?.handoffCycle, input?.handoffPolicy, reasons);
  const domainSummary = evaluateHandoffDomains(input?.handoffDomains, policySummary, input?.handoffCycle, reasons);
  const runtimeSummary = evaluateRuntimeConfiguration(input?.runtimeConfiguration, input?.handoffCycle, reasons);
  const artifactSummary = evaluateHandoffArtifacts(input?.handoffArtifacts, input?.handoffCycle, reasons);
  const runtimeSourceSummary = evaluateRuntimeConfigurationSourceLineage(
    input?.runtimeConfigurationSource,
    runtimeSummary,
    artifactSummary,
    policySummary,
    input?.handoffCycle,
    reasons,
  );
  const migrationReadinessSummary = evaluateDatabaseMigrationReadinessEvidence(
    input?.databaseMigrationReadinessEvidence,
    input?.cutoverPlan,
    input?.handoffCycle,
    reasons,
  );
  const cutoverSummary = evaluateCutoverPlan(
    input?.cutoverPlan,
    policySummary,
    runtimeSummary,
    input?.handoffCycle,
    reasons,
  );
  const validationSummary = evaluateValidationEvidence(input?.validationEvidence, input?.handoffCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.handoffCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.handoffCycle, input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      handoff: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const handoff = buildHandoff(
    input,
    policySummary,
    domainSummary,
    runtimeSummary,
    runtimeSourceSummary,
    migrationReadinessSummary,
    artifactSummary,
    cutoverSummary,
    validationSummary,
  );

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    handoff,
    receipt: buildReceipt(input, handoff),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
