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
const OPERATIONS_SCHEMA = 'cybermedica.deployment_operations_readiness.v1';
const DECISION_SCHEMA = 'cybermedica.deployment_operations_readiness_decision.v1';
const REQUIRED_PERMISSION = 'deployment_operations_review';

const REQUIRED_OPERATION_DOMAINS = Object.freeze([
  'dependency_audit',
  'monitoring_destination',
  'on_call_ownership',
  'railway_access',
  'rollback_disablement',
  'secret_management',
  'secret_rotation',
  'secret_scan',
]);

const DEFAULT_ALLOWED_DEPLOYMENT_BLOCKER_IDS = Object.freeze([
  'ESC-OPS-SECRETS',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-RUNTIME',
]);

const POLICY_STATUSES = new Set(['active']);
const DOMAIN_STATUSES = new Set(['activation_blocked', 'ready']);
const HUMAN_REVIEW_DECISIONS = new Set(['operations_ready', 'operations_ready_with_activation_blockers']);

const RAW_OPERATION_FIELDS = new Set([
  'content',
  'deploymentnotes',
  'freetext',
  'freetextnote',
  'operationsnotes',
  'rawdeploymentcontent',
  'rawdeploymentlog',
  'rawoperationscontent',
  'rawoperationslog',
  'rawrunbooktext',
  'rawsecretinventory',
  'rawvalidationoutput',
  'runbookbody',
  'runbooktext',
  'sourcebody',
  'sourcedocumentbody',
]);

const SECRET_OPERATION_FIELDS = new Set([
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

function assertNoRawOperationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawOperationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_OPERATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw deployment operations content field is not allowed at ${path}.${key}`);
    }
    if (SECRET_OPERATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`deployment operations secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawOperationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawOperationContent(input ?? {});
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_deployment_operations_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'deployment_operations_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluateOperationsPolicy(policy, reasons) {
  const requiredOperationDomains = sortedTextList(policy?.requiredOperationDomains);
  const allowedDeploymentBlockerIds = sortedTextList(policy?.allowedDeploymentBlockerIds);

  addReason(reasons, !hasText(policy?.policyRef), 'operations_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'operations_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'operations_policy_not_active');
  addReason(reasons, policy?.rootVerificationRequiredForTrustClaims !== true, 'root_verification_gate_absent');
  addReason(reasons, policy?.noCredentialDisclosure !== true, 'credential_disclosure_guard_absent');
  addReason(reasons, policy?.metadataOnly !== true, 'operations_policy_metadata_boundary_invalid');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'operations_policy_protected_boundary_invalid');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'operations_policy_time_invalid');

  evaluateRequiredSet(
    requiredOperationDomains,
    REQUIRED_OPERATION_DOMAINS,
    'policy_operation_domain_missing',
    'policy_operation_domain_unsupported',
    reasons,
  );

  return {
    allowedDeploymentBlockerIds:
      allowedDeploymentBlockerIds.length > 0
        ? allowedDeploymentBlockerIds
        : [...DEFAULT_ALLOWED_DEPLOYMENT_BLOCKER_IDS],
    requiredOperationDomains:
      requiredOperationDomains.length > 0 ? requiredOperationDomains : [...REQUIRED_OPERATION_DOMAINS],
  };
}

function evaluateReadinessCycle(cycle, policy, reasons) {
  addReason(reasons, !hasText(cycle?.cycleRef), 'readiness_cycle_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'release_candidate_ref_absent');
  addReason(reasons, cycle?.productionTrustClaim === true, 'production_trust_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'readiness_cycle_metadata_boundary_invalid');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'readiness_cycle_protected_boundary_invalid');

  const ordered = [
    ['openedAtHlc', cycle?.openedAtHlc],
    ['evidenceCollectedAtHlc', cycle?.evidenceCollectedAtHlc],
    ['validationRecordedAtHlc', cycle?.validationRecordedAtHlc],
    ['humanReviewedAtHlc', cycle?.humanReviewedAtHlc],
    ['auditRecordedAtHlc', cycle?.auditRecordedAtHlc],
  ];

  for (const [label, value] of ordered) {
    addReason(reasons, hlcTuple(value) === null, `readiness_cycle_${label}_invalid`);
  }
  addReason(reasons, hlcAfter(policy?.evaluatedAtHlc, cycle?.openedAtHlc), 'operations_policy_after_cycle_open');
  for (let index = 1; index < ordered.length; index += 1) {
    const [previousLabel, previousValue] = ordered[index - 1];
    const [currentLabel, currentValue] = ordered[index];
    addReason(
      reasons,
      hlcBefore(currentValue, previousValue),
      `readiness_cycle_${currentLabel}_before_${previousLabel}`,
    );
  }
}

function evaluateOperationDomains(operationDomains, policySummary, cycle, reasons) {
  addReason(reasons, !Array.isArray(operationDomains) || operationDomains.length === 0, 'operation_domains_absent');
  if (!Array.isArray(operationDomains)) {
    return { blockerIds: [], domains: [], summaries: [] };
  }

  const domains = sortedTextList(operationDomains.map((entry) => entry?.domain));
  const blockerIds = [];
  const summaries = [];
  const seenDomains = new Set();

  evaluateRequiredSet(
    domains,
    policySummary.requiredOperationDomains,
    'operation_domain_missing',
    'operation_domain_unsupported',
    reasons,
  );

  operationDomains.forEach((entry, index) => {
    const label = hasText(entry?.domain) ? entry.domain : `index_${index}`;
    addReason(reasons, !hasText(entry?.domain), `operation_domain_absent:${label}`);
    addReason(reasons, seenDomains.has(entry?.domain), `operation_domain_duplicate:${label}`);
    if (hasText(entry?.domain)) {
      seenDomains.add(entry.domain);
    }
    addReason(reasons, !DOMAIN_STATUSES.has(entry?.status), `operation_domain_status_invalid:${label}`);
    addReason(reasons, !hasText(entry?.evidenceRef), `operation_domain_evidence_ref_absent:${label}`);
    addReason(reasons, !isDigest(entry?.evidenceHash), `operation_domain_evidence_hash_invalid:${label}`);
    addReason(reasons, !hasText(entry?.ownerDid), `operation_domain_owner_absent:${label}`);
    addReason(reasons, !hasText(entry?.backupOwnerDid), `operation_domain_backup_owner_absent:${label}`);
    addReason(reasons, entry?.blocksBaselineDevelopment === true, `operation_domain_blocks_baseline:${label}`);
    addReason(
      reasons,
      entry?.status === 'activation_blocked' && entry?.productionActivationOnly !== true,
      `operation_domain_activation_scope_invalid:${label}`,
    );
    addReason(
      reasons,
      entry?.status === 'activation_blocked' && !hasText(entry?.activationBlockerId),
      `operation_domain_activation_blocker_absent:${label}`,
    );
    addReason(reasons, entry?.reviewedByHuman !== true, `operation_domain_human_review_absent:${label}`);
    addReason(reasons, hlcTuple(entry?.reviewedAtHlc) === null, `operation_domain_review_time_invalid:${label}`);
    addReason(reasons, hlcAfter(entry?.reviewedAtHlc, cycle?.validationRecordedAtHlc), `operation_domain_review_after_validation:${label}`);
    addReason(reasons, entry?.metadataOnly !== true, `operation_domain_metadata_boundary_invalid:${label}`);
    addReason(reasons, entry?.protectedContentExcluded !== true, `operation_domain_protected_boundary_invalid:${label}`);
    addReason(reasons, entry?.productionTrustClaim === true, `operation_domain_production_claim_forbidden:${label}`);

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

function evaluateDeploymentConfiguration(config, policySummary, cycle, reasons) {
  addReason(reasons, config === null || config === undefined, 'deployment_configuration_absent');
  addReason(reasons, !hasText(config?.topologyRef), 'deployment_topology_ref_absent');
  addReason(reasons, !isDigest(config?.topologyHash), 'deployment_topology_hash_invalid');
  addReason(reasons, typeof config?.monitoringDestinationSelected !== 'boolean', 'monitoring_destination_selection_invalid');
  addReason(reasons, typeof config?.onCallOwnerNamed !== 'boolean', 'on_call_owner_selection_invalid');
  addReason(reasons, typeof config?.secretManagerSelected !== 'boolean', 'secret_manager_selection_invalid');
  addReason(reasons, typeof config?.rotationOwnerNamed !== 'boolean', 'rotation_owner_selection_invalid');
  addReason(reasons, config?.dependencyAuditPassed !== true, 'dependency_audit_not_passed');
  addReason(reasons, config?.secretScanPassed !== true, 'secret_scan_not_passed');
  addReason(reasons, typeof config?.rollbackAuthorityNamed !== 'boolean', 'rollback_authority_selection_invalid');
  addReason(reasons, config?.activationStateDisablementTested !== true, 'activation_state_disablement_not_tested');
  addReason(reasons, config?.missingSecretsFailClosed !== true, 'missing_secret_fail_closed_absent');
  addReason(reasons, config?.productionEndpointSelected === true, 'production_endpoint_selected_without_activation');
  addReason(reasons, config?.metadataOnly !== true, 'deployment_configuration_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(config?.reviewedAtHlc) === null, 'deployment_configuration_review_time_invalid');
  addReason(
    reasons,
    hlcAfter(config?.reviewedAtHlc, cycle?.validationRecordedAtHlc),
    'deployment_configuration_review_after_validation',
  );

  const blockerIds = sortedTextList(config?.activationBlockerIds);
  for (const blockerId of blockerIds) {
    addReason(
      reasons,
      !policySummary.allowedDeploymentBlockerIds.includes(blockerId),
      `deployment_blocker_not_allowed:${blockerId}`,
    );
  }

  return {
    blockerIds,
    productionConfigReady:
      config?.monitoringDestinationSelected === true &&
      config?.onCallOwnerNamed === true &&
      config?.secretManagerSelected === true &&
      config?.rotationOwnerNamed === true &&
      config?.dependencyAuditPassed === true &&
      config?.secretScanPassed === true &&
      config?.rollbackAuthorityNamed === true &&
      config?.activationStateDisablementTested === true &&
      config?.missingSecretsFailClosed === true &&
      config?.productionEndpointSelected !== true,
  };
}

function railwayLoginStatus(railwayAccess) {
  if (
    railwayAccess?.authenticated === true &&
    railwayAccess?.loginRequired !== true &&
    railwayAccess?.projectLinked === true &&
    railwayAccess?.dashboardAccessVerified === true &&
    isDigest(railwayAccess?.workspaceHash) &&
    isDigest(railwayAccess?.projectHash) &&
    isDigest(railwayAccess?.serviceHash) &&
    isDigest(railwayAccess?.environmentHash)
  ) {
    return 'verified';
  }
  if (railwayAccess?.loginRequired === true || railwayAccess?.authenticated !== true) {
    return 'login_required';
  }
  return 'unverified';
}

function evaluateRailwayAccess(railwayAccess, cycle, reasons) {
  addReason(reasons, railwayAccess === null || railwayAccess === undefined, 'railway_access_absent');
  addReason(reasons, railwayAccess?.provider !== 'railway', 'railway_provider_invalid');
  addReason(reasons, railwayAccess?.cliInstalled !== true, 'railway_cli_absent');
  addReason(reasons, !hasText(railwayAccess?.cliVersion), 'railway_cli_version_absent');
  addReason(reasons, !isDigest(railwayAccess?.cliVersionHash), 'railway_cli_version_hash_invalid');
  addReason(reasons, typeof railwayAccess?.authenticated !== 'boolean', 'railway_authenticated_state_invalid');
  addReason(reasons, typeof railwayAccess?.loginRequired !== 'boolean', 'railway_login_required_state_invalid');
  addReason(reasons, typeof railwayAccess?.projectLinked !== 'boolean', 'railway_project_link_state_invalid');
  addReason(reasons, typeof railwayAccess?.dashboardAccessVerified !== 'boolean', 'railway_dashboard_state_invalid');
  addReason(reasons, railwayAccess?.credentialShared === true, 'railway_credential_disclosed');
  addReason(reasons, railwayAccess?.tokenStored === true, 'railway_token_stored');
  addReason(reasons, !isDigest(railwayAccess?.statusEvidenceHash), 'railway_status_evidence_hash_invalid');
  addReason(reasons, hlcTuple(railwayAccess?.checkedAtHlc) === null, 'railway_check_time_invalid');
  addReason(reasons, hlcBefore(railwayAccess?.checkedAtHlc, cycle?.evidenceCollectedAtHlc), 'railway_check_before_evidence_collection');
  addReason(reasons, railwayAccess?.metadataOnly !== true, 'railway_access_metadata_boundary_invalid');

  const loginStatus = railwayLoginStatus(railwayAccess);
  if (loginStatus === 'verified') {
    addReason(reasons, !isDigest(railwayAccess?.workspaceHash), 'railway_workspace_hash_invalid');
    addReason(reasons, !isDigest(railwayAccess?.projectHash), 'railway_project_hash_invalid');
    addReason(reasons, !isDigest(railwayAccess?.serviceHash), 'railway_service_hash_invalid');
    addReason(reasons, !isDigest(railwayAccess?.environmentHash), 'railway_environment_hash_invalid');
  }

  return {
    checkedAtHlc: railwayAccess?.checkedAtHlc ?? null,
    cliInstalled: railwayAccess?.cliInstalled === true,
    cliVersionHash: railwayAccess?.cliVersionHash ?? null,
    credentialShared: railwayAccess?.credentialShared === true,
    dashboardAccessVerified: railwayAccess?.dashboardAccessVerified === true,
    environmentHash: railwayAccess?.environmentHash ?? null,
    loginStatus,
    projectHash: railwayAccess?.projectHash ?? null,
    projectLinked: railwayAccess?.projectLinked === true,
    provider: railwayAccess?.provider ?? null,
    serviceHash: railwayAccess?.serviceHash ?? null,
    tokenStored: railwayAccess?.tokenStored === true,
    workspaceHash: railwayAccess?.workspaceHash ?? null,
  };
}

function evaluateValidationEvidence(validation, cycle, reasons) {
  addReason(reasons, validation === null || validation === undefined, 'validation_evidence_absent');
  addReason(reasons, sortedTextList(validation?.commandRefs).length === 0, 'validation_command_refs_absent');
  addReason(reasons, validation?.commandsPassed !== true, 'validation_commands_not_passed');
  addReason(reasons, !Number.isSafeInteger(validation?.testCount) || validation.testCount <= 0, 'validation_test_count_invalid');
  addReason(reasons, !isBasisPoints(validation?.coverageLineBasisPoints), 'validation_coverage_invalid');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'validation_source_guard_absent');
  addReason(reasons, !isDigest(validation?.dependencyAuditEvidenceHash), 'dependency_audit_evidence_hash_invalid');
  addReason(reasons, !isDigest(validation?.secretScanEvidenceHash), 'secret_scan_evidence_hash_invalid');
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
  addReason(reasons, review?.noProductionTrustClaim !== true, 'human_review_production_trust_forbidden');
  addReason(reasons, review?.activationBlockersAccepted !== true, 'activation_blockers_not_accepted');
  addReason(reasons, review?.railwayLoginRequiredAccepted !== true, 'railway_login_required_not_accepted');
  addReason(reasons, review?.finalAuthority !== 'human', 'human_review_authority_absent');
  addReason(reasons, review?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_invalid');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
  addReason(reasons, hlcBefore(review?.reviewedAtHlc, cycle?.humanReviewedAtHlc), 'human_review_before_cycle_review_step');
}

function evaluateAuditRecord(auditRecord, cycle, review, reasons) {
  addReason(reasons, !hasText(auditRecord?.auditRecordRef), 'operations_audit_record_ref_absent');
  addReason(reasons, !isDigest(auditRecord?.auditRecordHash), 'operations_audit_record_hash_invalid');
  addReason(reasons, auditRecord?.metadataOnly !== true, 'operations_audit_record_metadata_boundary_invalid');
  addReason(reasons, auditRecord?.includesProtectedContent === true, 'operations_audit_record_protected_content_forbidden');
  addReason(reasons, hlcTuple(auditRecord?.receiptRecordedAtHlc) === null, 'operations_audit_record_time_invalid');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, cycle?.auditRecordedAtHlc), 'operations_audit_before_cycle_audit_step');
  addReason(reasons, hlcBefore(auditRecord?.receiptRecordedAtHlc, review?.reviewedAtHlc), 'operations_audit_before_review');
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

function buildOperations(input, policySummary, domainSummary, deploymentSummary, railwaySummary) {
  const deploymentBlockerIds = uniqueSorted([...domainSummary.blockerIds, ...deploymentSummary.blockerIds]);
  const productionOperationsReady =
    deploymentBlockerIds.length === 0 &&
    deploymentSummary.productionConfigReady === true &&
    railwaySummary.loginStatus === 'verified';
  const operationsHash = sha256Hex({
    auditRecordHash: input.auditRecord.auditRecordHash,
    deploymentBlockerIds,
    deploymentConfigurationHash: input.deploymentConfiguration.topologyHash,
    domainSummaries: domainSummary.summaries,
    humanDecisionHash: input.humanReview.decisionHash,
    policyHash: input.operationsPolicy.policyHash,
    railwayStatusEvidenceHash: input.railwayAccess.statusEvidenceHash,
    releaseCandidateRef: input.readinessCycle.releaseCandidateRef,
    tenantId: input.tenantId,
    validationEvidenceHash: input.validationEvidence.dependencyAuditEvidenceHash,
  });

  return {
    schema: OPERATIONS_SCHEMA,
    operationsId: `cmdor_${sha256Hex({
      operationsHash,
      releaseCandidateRef: input.readinessCycle.releaseCandidateRef,
      tenantId: input.tenantId,
    }).slice(0, 32)}`,
    tenantId: input.tenantId,
    releaseCandidateRef: input.readinessCycle.releaseCandidateRef,
    trustState: 'inactive',
    productionTrustState: 'inactive',
    exochainProductionClaim: false,
    metadataOnly: true,
    containsProtectedContent: false,
    baselineOperationsPackReady: true,
    productionOperationsReady,
    operationDomainsCovered: domainSummary.domains,
    operationDomainSummaries: domainSummary.summaries,
    allowedDeploymentBlockerIds: policySummary.allowedDeploymentBlockerIds,
    deploymentBlockerIds,
    deploymentConfigurationSummary: {
      activationStateDisablementTested: input.deploymentConfiguration.activationStateDisablementTested,
      dependencyAuditPassed: input.deploymentConfiguration.dependencyAuditPassed,
      missingSecretsFailClosed: input.deploymentConfiguration.missingSecretsFailClosed,
      monitoringDestinationSelected: input.deploymentConfiguration.monitoringDestinationSelected,
      onCallOwnerNamed: input.deploymentConfiguration.onCallOwnerNamed,
      productionEndpointSelected: input.deploymentConfiguration.productionEndpointSelected,
      rollbackAuthorityNamed: input.deploymentConfiguration.rollbackAuthorityNamed,
      rotationOwnerNamed: input.deploymentConfiguration.rotationOwnerNamed,
      secretManagerSelected: input.deploymentConfiguration.secretManagerSelected,
      secretScanPassed: input.deploymentConfiguration.secretScanPassed,
      topologyHash: input.deploymentConfiguration.topologyHash,
      topologyRef: input.deploymentConfiguration.topologyRef,
    },
    railway: railwaySummary,
    validationSummary: {
      commandRefs: sortedTextList(input.validationEvidence.commandRefs),
      coverageLineBasisPoints: input.validationEvidence.coverageLineBasisPoints,
      sourceGuardPassed: true,
      testCount: input.validationEvidence.testCount,
    },
    operationsHash,
    auditRecordHash: input.auditRecord.auditRecordHash,
    auditRecordedAtHlc: input.auditRecord.receiptRecordedAtHlc,
  };
}

function buildReceipt(input, operations) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: operations.operationsHash,
    artifactType: 'deployment_operations_readiness',
    artifactVersion: input.readinessCycle.releaseCandidateRef,
    classification: 'restricted_metadata_only',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.auditRecord.receiptRecordedAtHlc,
    sensitivityTags: ['deployment_operations', 'metadata_only', 'inactive_trust_state'],
    sourceSystem: 'cybermedica-qms',
    tenantId: input.tenantId,
  });
}

export function evaluateDeploymentOperationsReadiness(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  const policySummary = evaluateOperationsPolicy(input?.operationsPolicy, reasons);
  evaluateReadinessCycle(input?.readinessCycle, input?.operationsPolicy, reasons);
  const domainSummary = evaluateOperationDomains(input?.operationDomains, policySummary, input?.readinessCycle, reasons);
  const deploymentSummary = evaluateDeploymentConfiguration(
    input?.deploymentConfiguration,
    policySummary,
    input?.readinessCycle,
    reasons,
  );
  const railwaySummary = evaluateRailwayAccess(input?.railwayAccess, input?.readinessCycle, reasons);
  evaluateValidationEvidence(input?.validationEvidence, input?.readinessCycle, reasons);
  evaluateHumanReview(input?.humanReview, input?.readinessCycle, reasons);
  evaluateAuditRecord(input?.auditRecord, input?.readinessCycle, input?.humanReview, reasons);
  evaluateAiAssistance(input?.aiAssistance, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'custody_digest_invalid');

  const unique = uniqueReasons(reasons);
  if (unique.length > 0) {
    return {
      schema: DECISION_SCHEMA,
      decision: 'denied',
      failClosed: true,
      reasons: unique,
      operations: null,
      receipt: null,
      trustState: 'inactive',
      exochainProductionClaim: false,
    };
  }

  const operations = buildOperations(input, policySummary, domainSummary, deploymentSummary, railwaySummary);

  return {
    schema: DECISION_SCHEMA,
    decision: 'permitted',
    failClosed: false,
    reasons: [],
    operations,
    receipt: buildReceipt(input, operations),
    trustState: 'inactive',
    exochainProductionClaim: false,
  };
}
