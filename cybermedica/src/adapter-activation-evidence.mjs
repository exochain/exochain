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
const DECISION_SCHEMA = 'cybermedica.adapter_activation_evidence_decision.v1';
const EVIDENCE_SCHEMA = 'cybermedica.adapter_activation_evidence.v1';
const REQUIRED_PERMISSION = 'adapter_activation_review';
const REQUIRED_THRESHOLD_SIGNATURE = '7-of-13';
const REQUIRED_CERTIFIER_COUNT = 13;
const REQUIRED_DKG_PARTICIPANT_COUNT = 13;
const RUNTIME_CONFIGURATION_SOURCE_RECEIPT_TYPE = 'runtime_configuration_source';
const DEPLOYMENT_HANDOFF_CUTOVER_RECEIPT_TYPE = 'deployment_handoff_cutover';

const DEPLOYMENT_HANDOFF_CUTOVER_STATUSES = new Set(['deployment_handoff_cutover_ready_verified_runtime']);

const REQUIRED_GATE_IDS = Object.freeze([
  'PTAG-001',
  'PTAG-005',
  'PTAG-006',
  'PTAG-016',
  'PTAG-017',
]);

const REQUIRED_COMPONENTS = Object.freeze([
  'decision_forum',
  'gateway',
  'node_receipt',
  'privacy_boundary',
  'root_bundle',
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

const REQUIRED_SOURCE_REFS = Object.freeze([
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
]);

const REQUIRED_VALIDATION_COMMANDS = Object.freeze([
  'node --test tests/adapter-activation-evidence.test.mjs',
  'node --test tests/gateway-call-path.test.mjs',
  'node --test tests/node-receipt-sync.test.mjs',
  'npm run quality',
]);

const POLICY_STATUSES = new Set(['active']);
const HUMAN_REVIEW_DECISIONS = new Set([
  'adapter_activation_ready_for_claim_lift_request',
  'hold_for_adapter_activation_gap',
]);

const RAW_ACTIVATION_FIELDS = new Set([
  'activationbody',
  'activationevidencebody',
  'body',
  'content',
  'debugpayload',
  'decisionpayload',
  'freetext',
  'gatewaypayload',
  'healthpayload',
  'logpayload',
  'nodepayload',
  'payload',
  'provenancepayload',
  'rawactivationevidence',
  'rawcontent',
  'rawdecisionforumpayload',
  'rawdeploymentconfig',
  'rawhandoffcontent',
  'rawhandofflog',
  'rawhandoffnotes',
  'rawgatewaypayload',
  'rawnodepayload',
  'rawpayload',
  'rawruntimeconfig',
  'rawruntimeconfiguration',
  'rawruntimeconfigurationsource',
  'rawrootbundle',
  'receiptpayload',
  'runtimeconfigurationpayload',
  'rootbundlepayload',
  'sourcebody',
  'sourcedocumentbody',
  'telemetrypayload',
]);

const SECRET_ACTIVATION_FIELDS = new Set([
  'accesstoken',
  'apikey',
  'authorizationheader',
  'authtoken',
  'bearertoken',
  'bootstraptoken',
  'clientsecret',
  'credential',
  'credentialsecret',
  'nodeprivatekey',
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

function assertNoRawActivationContent(value, path = '$') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRawActivationContent(item, `${path}[${index}]`));
    return;
  }

  for (const [key, nested] of Object.entries(value)) {
    const normalized = normalizeFieldName(key);
    if (RAW_ACTIVATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`raw adapter activation payload field is not allowed at ${path}.${key}`);
    }
    if (SECRET_ACTIVATION_FIELDS.has(normalized) && sensitiveValuePresent(nested)) {
      throw new ProtectedContentError(`adapter activation secret field is not allowed at ${path}.${key}`);
    }
    assertNoRawActivationContent(nested, `${path}.${key}`);
  }
}

function assertMetadataOnly(input) {
  assertNoRawActivationContent(input ?? {});
  canonicalize(input ?? {});
}

function uniqueSorted(values) {
  return [...new Set(values.filter(hasText))].sort();
}

function sortedTextList(values) {
  return Array.isArray(values) ? uniqueSorted(values) : [];
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
  addReason(reasons, input?.actor?.kind !== 'human', 'human_adapter_activation_reviewer_required');
  addReason(reasons, input?.authority?.valid !== true, 'authority_chain_invalid');
  addReason(reasons, input?.authority?.revoked === true, 'authority_chain_revoked');
  addReason(reasons, input?.authority?.expired === true, 'authority_chain_expired');
  addReason(
    reasons,
    !hasAuthorityPermission(input?.authority, REQUIRED_PERMISSION) && !hasAuthorityPermission(input?.authority, 'govern'),
    'adapter_activation_authority_missing',
  );
  addReason(reasons, !isDigest(input?.authority?.authorityChainHash), 'authority_chain_hash_invalid');
}

function evaluatePolicy(policy, reasons) {
  addReason(reasons, !hasText(policy?.policyRef), 'activation_policy_ref_absent');
  addReason(reasons, !isDigest(policy?.policyHash), 'activation_policy_hash_invalid');
  addReason(reasons, !POLICY_STATUSES.has(policy?.status), 'activation_policy_not_active');
  addReason(reasons, policy?.forbidsProductionTrustClaim !== true, 'policy_production_claim_guard_absent');
  addReason(reasons, policy?.requiresMetadataOnly !== true, 'policy_metadata_boundary_absent');
  addReason(reasons, policy?.requiresFailClosedAdapters !== true, 'policy_fail_closed_adapter_rule_absent');
  addReason(reasons, policy?.protectedContentExcluded !== true, 'policy_protected_content_boundary_absent');
  addReason(reasons, hlcTuple(policy?.evaluatedAtHlc) === null, 'activation_policy_time_invalid');

  evaluateRequiredSet(
    sortedTextList(policy?.requiredGateIds),
    REQUIRED_GATE_IDS,
    'policy_gate_missing',
    'policy_gate_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    sortedTextList(policy?.requiredComponents),
    REQUIRED_COMPONENTS,
    'policy_component_missing',
    'policy_component_unsupported',
    reasons,
  );
  evaluateRequiredSet(
    sortedTextList(policy?.sourceRefs),
    REQUIRED_SOURCE_REFS,
    'policy_source_ref_missing',
    'policy_source_ref_unsupported',
    reasons,
  );
}

function evaluateCycle(cycle, reasons) {
  addReason(reasons, !hasText(cycle?.evidencePackageRef), 'activation_evidence_package_ref_absent');
  addReason(reasons, !hasText(cycle?.releaseCandidateRef), 'activation_release_candidate_ref_absent');
  addReason(reasons, !hasText(cycle?.runtimePathRef), 'activation_runtime_path_ref_absent');
  addReason(reasons, cycle?.deploymentMode !== 'server_side_gateway_node', 'activation_deployment_mode_invalid');
  addReason(reasons, cycle?.productionTrustClaim === true, 'activation_cycle_production_claim_forbidden');
  addReason(reasons, cycle?.metadataOnly !== true, 'activation_cycle_metadata_boundary_absent');
  addReason(reasons, cycle?.protectedContentExcluded !== true, 'activation_cycle_protected_content_boundary_absent');
  addReason(reasons, hlcTuple(cycle?.openedAtHlc) === null, 'activation_cycle_time_invalid');
}

function evaluateRootBundle(root, cycle, reasons) {
  addReason(reasons, root?.state !== 'verified' || root?.verified !== true, 'root_bundle_unverified');
  addReason(reasons, !hasText(root?.rootBundleProviderRef), 'root_bundle_provider_ref_absent');
  addReason(reasons, !isDigest(root?.rootTrustBundleHash), 'root_trust_bundle_hash_invalid');
  addReason(reasons, !isDigest(root?.rosterHash), 'root_roster_hash_invalid');
  addReason(reasons, !isDigest(root?.artifactRegistryHash), 'root_artifact_registry_hash_invalid');
  addReason(reasons, !hasText(root?.verifierReceiptId), 'root_verifier_receipt_absent');
  addReason(reasons, root?.thresholdSignature !== REQUIRED_THRESHOLD_SIGNATURE, 'root_threshold_signature_unverified');
  addReason(reasons, root?.certifierCount !== REQUIRED_CERTIFIER_COUNT, 'root_certifier_count_invalid');
  addReason(reasons, root?.dkgParticipantCount !== REQUIRED_DKG_PARTICIPANT_COUNT, 'root_dkg_participant_count_invalid');
  addReason(reasons, root?.runtimePathRef !== cycle?.runtimePathRef, 'component_runtime_path_mismatch:root_bundle');
  addReason(reasons, root?.releaseCandidateRef !== cycle?.releaseCandidateRef, 'component_release_candidate_mismatch:root_bundle');
  addReason(reasons, root?.metadataOnly !== true, 'root_bundle_metadata_boundary_absent');
  addReason(reasons, root?.protectedContentExcluded !== true, 'root_bundle_protected_content_boundary_absent');
  addReason(reasons, root?.exochainProductionClaim === true, 'root_bundle_production_claim_forbidden');
  addReason(reasons, hlcTuple(root?.checkedAtHlc) === null, 'root_bundle_time_invalid');
}

function evaluateGateway(gateway, input, reasons) {
  addReason(reasons, gateway?.decision !== 'permitted', 'gateway_evidence_unverified');
  addReason(reasons, gateway?.status !== 'verified' && gateway?.state !== 'verified', 'gateway_evidence_unverified');
  addReason(reasons, !isDigest(gateway?.gatewayCallHash), 'gateway_call_hash_invalid');
  addReason(reasons, !hasText(gateway?.gatewayReceiptId), 'gateway_receipt_id_absent');
  addReason(reasons, !isDigest(gateway?.actionHash), 'gateway_action_hash_invalid');
  addReason(reasons, gateway?.tenantId !== input?.tenantId, 'component_tenant_mismatch:gateway');
  addReason(reasons, isDigest(gateway?.actionHash) && gateway.actionHash !== input?.nodeReceiptEvidence?.actionHash, 'component_action_hash_mismatch:gateway');
  addReason(reasons, gateway?.runtimePathRef !== input?.activationCycle?.runtimePathRef, 'component_runtime_path_mismatch:gateway');
  addReason(reasons, gateway?.releaseCandidateRef !== input?.activationCycle?.releaseCandidateRef, 'component_release_candidate_mismatch:gateway');
  addReason(reasons, gateway?.failClosed !== false, 'gateway_fail_closed_state_unverified');
  addReason(reasons, gateway?.noCachedOutcome !== true, 'gateway_cached_outcome_guard_absent');
  addReason(reasons, gateway?.noLocalSimulation !== true, 'gateway_local_simulation_guard_absent');
  addReason(reasons, gateway?.noOverride !== true, 'gateway_override_guard_absent');
  addReason(reasons, gateway?.serverSideOnly !== true, 'gateway_server_side_boundary_absent');
  addReason(reasons, gateway?.metadataOnly !== true, 'gateway_metadata_boundary_absent');
  addReason(reasons, gateway?.protectedContentExcluded !== true, 'gateway_protected_content_boundary_absent');
  addReason(reasons, gateway?.exochainProductionClaim === true, 'gateway_production_claim_forbidden');
  addReason(reasons, hlcTuple(gateway?.checkedAtHlc) === null, 'gateway_time_invalid');
}

function evaluateNodeReceipt(node, input, reasons) {
  addReason(reasons, node?.decision !== 'permitted', 'node_receipt_evidence_unverified');
  addReason(reasons, node?.syncStatus !== 'ready_inactive_trust' || node?.state !== 'verified', 'node_receipt_evidence_unverified');
  addReason(reasons, !isDigest(node?.nodeReceiptSyncHash), 'node_receipt_sync_hash_invalid');
  addReason(reasons, !hasText(node?.nodeReceiptId), 'node_receipt_id_absent');
  addReason(reasons, node?.linkedGatewayReceiptId !== input?.gatewayEvidence?.gatewayReceiptId, 'node_gateway_receipt_link_mismatch');
  addReason(reasons, !isDigest(node?.actionHash), 'node_action_hash_invalid');
  addReason(reasons, node?.actionHash !== input?.gatewayEvidence?.actionHash, 'component_action_hash_mismatch:node_receipt');
  addReason(reasons, node?.receiptSignatureVerified !== true, 'node_receipt_signature_unverified');
  addReason(reasons, node?.actionHashSynced !== true, 'node_action_hash_sync_unverified');
  addReason(reasons, node?.queryByActorVerified !== true, 'node_query_by_actor_unverified');
  addReason(reasons, node?.provenancePayloadSuppressed !== true, 'node_provenance_payload_suppression_unverified');
  addReason(reasons, node?.tenantId !== input?.tenantId, 'component_tenant_mismatch:node_receipt');
  addReason(reasons, node?.runtimePathRef !== input?.activationCycle?.runtimePathRef, 'component_runtime_path_mismatch:node_receipt');
  addReason(reasons, node?.releaseCandidateRef !== input?.activationCycle?.releaseCandidateRef, 'component_release_candidate_mismatch:node_receipt');
  addReason(reasons, node?.metadataOnly !== true, 'node_receipt_metadata_boundary_absent');
  addReason(reasons, node?.protectedContentExcluded !== true, 'node_receipt_protected_content_boundary_absent');
  addReason(reasons, node?.exochainProductionClaim === true, 'node_receipt_production_claim_forbidden');
  addReason(reasons, hlcTuple(node?.checkedAtHlc) === null, 'node_receipt_time_invalid');
}

function evaluateDecisionForum(forum, input, reasons) {
  addReason(reasons, forum?.state !== 'verified' || forum?.decisionState !== 'approved', 'decision_forum_evidence_unverified');
  addReason(reasons, !hasText(forum?.decisionId), 'decision_forum_decision_id_absent');
  addReason(reasons, !hasText(forum?.workflowReceiptId), 'decision_forum_workflow_receipt_absent');
  addReason(reasons, forum?.linkedGatewayReceiptId !== input?.gatewayEvidence?.gatewayReceiptId, 'decision_forum_gateway_receipt_link_mismatch');
  addReason(reasons, !isDigest(forum?.actionHash), 'decision_forum_action_hash_invalid');
  addReason(reasons, forum?.actionHash !== input?.gatewayEvidence?.actionHash, 'component_action_hash_mismatch:decision_forum');
  addReason(reasons, forum?.humanGateVerified !== true, 'decision_forum_human_gate_unverified');
  addReason(reasons, forum?.quorumVerified !== true, 'decision_forum_quorum_unverified');
  addReason(reasons, forum?.kernelVerdictVerified !== true, 'decision_forum_kernel_verdict_unverified');
  addReason(reasons, forum?.invariantSetVerified !== true, 'decision_forum_invariant_set_unverified');
  addReason(reasons, forum?.aiFinalAuthority === true, 'ai_final_authority_forbidden');
  addReason(reasons, forum?.openChallenge === true, 'decision_forum_open_challenge');
  addReason(reasons, forum?.tenantId !== input?.tenantId, 'component_tenant_mismatch:decision_forum');
  addReason(reasons, forum?.runtimePathRef !== input?.activationCycle?.runtimePathRef, 'component_runtime_path_mismatch:decision_forum');
  addReason(reasons, forum?.releaseCandidateRef !== input?.activationCycle?.releaseCandidateRef, 'component_release_candidate_mismatch:decision_forum');
  addReason(reasons, forum?.metadataOnly !== true, 'decision_forum_metadata_boundary_absent');
  addReason(reasons, forum?.protectedContentExcluded !== true, 'decision_forum_protected_content_boundary_absent');
  addReason(reasons, forum?.exochainProductionClaim === true, 'decision_forum_production_claim_forbidden');
  addReason(reasons, hlcTuple(forum?.checkedAtHlc) === null, 'decision_forum_time_invalid');
}

function evaluatePrivacyBoundary(privacy, reasons) {
  addReason(reasons, privacy?.state !== 'verified', 'privacy_boundary_unverified');
  addReason(reasons, privacy?.noRawSensitiveInReceipts !== true, 'receipt_sensitive_content_boundary_unverified');
  addReason(reasons, privacy?.noRawSensitiveInDag !== true, 'dag_sensitive_content_boundary_unverified');
  addReason(reasons, privacy?.noRawSensitiveInLogs !== true, 'log_sensitive_content_boundary_unverified');
  addReason(reasons, privacy?.noRawSensitiveInTelemetry !== true, 'telemetry_sensitive_content_boundary_unverified');
  addReason(reasons, privacy?.noRawSensitiveInHealth !== true, 'health_sensitive_content_boundary_unverified');
  addReason(reasons, privacy?.noRawSensitiveInDebug !== true, 'debug_sensitive_content_boundary_unverified');
  addReason(reasons, privacy?.noRawSensitiveInExports !== true, 'export_sensitive_content_boundary_unverified');
  addReason(reasons, privacy?.fixtureScanPassed !== true, 'privacy_fixture_scan_failed');
  addReason(reasons, !isDigest(privacy?.classificationHash), 'privacy_classification_hash_invalid');
  addReason(reasons, privacy?.metadataOnly !== true, 'privacy_boundary_metadata_absent');
  addReason(reasons, privacy?.protectedContentExcluded !== true, 'privacy_boundary_protected_content_absent');
  addReason(reasons, hlcTuple(privacy?.checkedAtHlc) === null, 'privacy_boundary_time_invalid');
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
  addReason(
    reasons,
    isDigest(evidence?.roleDashboardReceiptHash) &&
      isDigest(evidence?.productionClaimLiftRoleDashboardProviderReceiptHash) &&
      evidence.roleDashboardReceiptHash !== evidence.productionClaimLiftRoleDashboardProviderReceiptHash,
    `${prefix}_production_claim_lift_provider_receipt_mismatch`,
  );
  addReason(
    reasons,
    isDigest(evidence?.roleDashboardSummaryHash) &&
      isDigest(evidence?.productionClaimLiftRoleDashboardProviderSummaryHash) &&
      evidence.roleDashboardSummaryHash !== evidence.productionClaimLiftRoleDashboardProviderSummaryHash,
    `${prefix}_production_claim_lift_provider_summary_mismatch`,
  );
  addReason(
    reasons,
    isDigest(evidence?.roleDashboardTrustStateViewHash) &&
      isDigest(evidence?.productionClaimLiftRoleDashboardProviderTrustStateViewHash) &&
      evidence.roleDashboardTrustStateViewHash !== evidence.productionClaimLiftRoleDashboardProviderTrustStateViewHash,
    `${prefix}_production_claim_lift_provider_trust_state_view_mismatch`,
  );
  addReason(
    reasons,
    isDigest(evidence?.productionClaimLiftRoleDashboardProviderReceiptHash) &&
      isDigest(evidence?.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash) &&
      evidence.productionClaimLiftRoleDashboardProviderReceiptHash !==
        evidence.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    `${prefix}_production_claim_lift_runtime_source_provider_receipt_mismatch`,
  );
  addReason(
    reasons,
    isDigest(evidence?.productionClaimLiftRoleDashboardProviderSummaryHash) &&
      isDigest(evidence?.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash) &&
      evidence.productionClaimLiftRoleDashboardProviderSummaryHash !==
        evidence.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    `${prefix}_production_claim_lift_runtime_source_provider_summary_mismatch`,
  );
  addReason(
    reasons,
    isDigest(evidence?.productionClaimLiftRoleDashboardProviderTrustStateViewHash) &&
      isDigest(evidence?.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash) &&
      evidence.productionClaimLiftRoleDashboardProviderTrustStateViewHash !==
        evidence.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    `${prefix}_production_claim_lift_runtime_source_provider_trust_state_view_mismatch`,
  );
  addReason(
    reasons,
    isDigest(evidence?.productionClaimLiftRoleDashboardReadinessReceiptHash) &&
      isDigest(evidence?.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash) &&
      evidence.productionClaimLiftRoleDashboardReadinessReceiptHash !==
        evidence.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    `${prefix}_production_claim_lift_runtime_source_readiness_receipt_mismatch`,
  );
  addReason(
    reasons,
    isDigest(evidence?.productionClaimLiftRoleDashboardReadinessSummaryHash) &&
      isDigest(evidence?.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash) &&
      evidence.productionClaimLiftRoleDashboardReadinessSummaryHash !==
        evidence.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    `${prefix}_production_claim_lift_runtime_source_readiness_summary_mismatch`,
  );
  addReason(
    reasons,
    isDigest(evidence?.productionClaimLiftRoleDashboardReadinessTrustStateViewHash) &&
      isDigest(evidence?.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash) &&
      evidence.productionClaimLiftRoleDashboardReadinessTrustStateViewHash !==
        evidence.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    `${prefix}_production_claim_lift_runtime_source_readiness_trust_state_view_mismatch`,
  );
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

function evaluateRuntimeConfigurationSourceLineage(source, cycle, reasons) {
  const activationBlockerIds = sortedTextList(source?.activationBlockerIds);
  const deploymentHandoffCutover = source?.deploymentHandoffCutover;

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
  addReason(reasons, source?.baselineConfigurationReady !== true, 'runtime_configuration_source_baseline_not_ready');
  addReason(
    reasons,
    source?.productionConfigurationReady !== true,
    'runtime_configuration_source_production_not_ready',
  );
  addReason(reasons, activationBlockerIds.length > 0, 'runtime_configuration_source_activation_blockers_present');
  addReason(reasons, source?.trustState !== 'inactive', 'runtime_configuration_source_trust_state_invalid');
  addReason(
    reasons,
    source?.exochainProductionClaim !== false,
    'runtime_configuration_source_production_claim_forbidden',
  );
  addReason(reasons, source?.metadataOnly !== true, 'runtime_configuration_source_metadata_boundary_invalid');
  addReason(
    reasons,
    source?.protectedContentExcluded !== true,
    'runtime_configuration_source_protected_boundary_invalid',
  );
  addReason(reasons, hlcTuple(source?.reviewedAtHlc) === null, 'runtime_configuration_source_review_time_invalid');
  addReason(
    reasons,
    deploymentHandoffCutover === null || deploymentHandoffCutover === undefined,
    'runtime_configuration_source_handoff_lineage_absent',
  );
  addReason(
    reasons,
    !isDigest(deploymentHandoffCutover?.handoffHash),
    'runtime_configuration_source_handoff_hash_invalid',
  );
  addReason(
    reasons,
    !isDigest(deploymentHandoffCutover?.receiptHash),
    'runtime_configuration_source_handoff_receipt_hash_invalid',
  );

  const deploymentReadinessRoleDashboardTrustStateEvidence = evaluateRoleDashboardTrustStateEvidence(
    deploymentHandoffCutover?.deploymentReadinessRoleDashboardTrustStateEvidence,
    source,
    reasons,
    'runtime_configuration_source_handoff_readiness_role_dashboard',
    'runtime_configuration_source_review',
  );
  const deploymentProviderBindingRoleDashboardTrustStateEvidence = evaluateRoleDashboardTrustStateEvidence(
    deploymentHandoffCutover?.deploymentProviderBindingRoleDashboardTrustStateEvidence,
    source,
    reasons,
    'runtime_configuration_source_handoff_provider_binding_role_dashboard',
    'runtime_configuration_source_review',
  );

  return {
    activationBlockerIds,
    baselineConfigurationReady: source?.baselineConfigurationReady === true,
    deploymentHandoffCutover: {
      deploymentProviderBindingRoleDashboardTrustStateEvidence,
      deploymentReadinessRoleDashboardTrustStateEvidence,
      handoffHash: deploymentHandoffCutover?.handoffHash ?? null,
      receiptHash: deploymentHandoffCutover?.receiptHash ?? null,
    },
    productionConfigurationReady: source?.productionConfigurationReady === true,
    receiptHash: source?.receiptHash ?? null,
    runtimeConfigurationHash: source?.runtimeConfigurationHash ?? null,
    runtimeConfigurationSourceId: source?.runtimeConfigurationSourceId ?? null,
    trustState: source?.trustState ?? 'invalid',
  };
}

function evaluateDeploymentHandoffCutoverLineage(handoff, sourceSummary, cycle, reasons) {
  const sourceHandoff = sourceSummary.deploymentHandoffCutover;
  addReason(reasons, handoff === null || handoff === undefined, 'deployment_handoff_cutover_lineage_absent');
  addReason(reasons, !hasText(handoff?.handoffRef), 'deployment_handoff_cutover_ref_absent');
  addReason(reasons, !isDigest(handoff?.handoffHash), 'deployment_handoff_cutover_hash_invalid');
  addReason(reasons, !isDigest(handoff?.receiptHash), 'deployment_handoff_cutover_receipt_hash_invalid');
  addReason(
    reasons,
    handoff?.receiptArtifactType !== DEPLOYMENT_HANDOFF_CUTOVER_RECEIPT_TYPE,
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
  addReason(reasons, !isDigest(handoff?.deploymentConfigHash), 'deployment_handoff_deployment_config_hash_invalid');
  addReason(
    reasons,
    handoff?.runtimeConfigurationSourceId !== sourceSummary.runtimeConfigurationSourceId,
    'deployment_handoff_runtime_configuration_source_id_mismatch',
  );
  addReason(
    reasons,
    isDigest(handoff?.runtimeConfigurationHash) &&
      isDigest(sourceSummary.runtimeConfigurationHash) &&
      handoff.runtimeConfigurationHash !== sourceSummary.runtimeConfigurationHash,
    'deployment_handoff_runtime_configuration_hash_mismatch',
  );
  addReason(
    reasons,
    !isDigest(handoff?.runtimeConfigurationHash),
    'deployment_handoff_runtime_configuration_hash_invalid',
  );
  addReason(
    reasons,
    isDigest(handoff?.runtimeConfigurationSourceReceiptHash) &&
      isDigest(sourceSummary.receiptHash) &&
      handoff.runtimeConfigurationSourceReceiptHash !== sourceSummary.receiptHash,
    'deployment_handoff_runtime_configuration_receipt_mismatch',
  );
  addReason(
    reasons,
    !isDigest(handoff?.runtimeConfigurationSourceReceiptHash),
    'deployment_handoff_runtime_configuration_receipt_hash_invalid',
  );
  addReason(reasons, handoff?.baselineHandoffReady !== true, 'deployment_handoff_baseline_not_ready');
  addReason(reasons, handoff?.productionCutoverReady !== true, 'deployment_handoff_cutover_not_ready');
  addReason(reasons, handoff?.trustState !== 'inactive', 'deployment_handoff_trust_state_invalid');
  addReason(reasons, handoff?.exochainProductionClaim !== false, 'deployment_handoff_production_claim_forbidden');
  addReason(reasons, handoff?.metadataOnly !== true, 'deployment_handoff_metadata_boundary_invalid');
  addReason(reasons, handoff?.protectedContentExcluded !== true, 'deployment_handoff_protected_boundary_invalid');
  addReason(reasons, hlcTuple(handoff?.reviewedAtHlc) === null, 'deployment_handoff_review_time_invalid');
  addReason(
    reasons,
    isDigest(sourceHandoff?.handoffHash) && isDigest(handoff?.handoffHash) && sourceHandoff.handoffHash !== handoff.handoffHash,
    'runtime_configuration_source_handoff_hash_mismatch',
  );
  addReason(
    reasons,
    isDigest(sourceHandoff?.receiptHash) && isDigest(handoff?.receiptHash) && sourceHandoff.receiptHash !== handoff.receiptHash,
    'runtime_configuration_source_handoff_receipt_mismatch',
  );

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
  addRoleDashboardLineageMismatch(
    reasons,
    sourceHandoff?.deploymentReadinessRoleDashboardTrustStateEvidence,
    deploymentReadinessRoleDashboardTrustStateEvidence,
    'runtime_configuration_source_handoff_readiness_role_dashboard',
  );
  addRoleDashboardLineageMismatch(
    reasons,
    sourceHandoff?.deploymentProviderBindingRoleDashboardTrustStateEvidence,
    deploymentProviderBindingRoleDashboardTrustStateEvidence,
    'runtime_configuration_source_handoff_provider_binding_role_dashboard',
  );
}

function addRoleDashboardLineageMismatch(reasons, sourceEvidence, handoffEvidence, prefix) {
  const digestChecks = [
    ['roleDashboardReceiptHash', 'receipt_mismatch'],
    ['roleDashboardSummaryHash', 'summary_hash_mismatch'],
    ['roleDashboardTrustStateViewHash', 'trust_state_view_hash_mismatch'],
    ['productionClaimLiftRoleDashboardProviderReceiptHash', 'production_claim_lift_provider_receipt_mismatch'],
    ['productionClaimLiftRoleDashboardProviderSummaryHash', 'production_claim_lift_provider_summary_mismatch'],
    [
      'productionClaimLiftRoleDashboardProviderTrustStateViewHash',
      'production_claim_lift_provider_trust_state_view_mismatch',
    ],
    ['productionClaimLiftRoleDashboardReadinessReceiptHash', 'production_claim_lift_readiness_receipt_mismatch'],
    ['productionClaimLiftRoleDashboardReadinessSummaryHash', 'production_claim_lift_readiness_summary_mismatch'],
    [
      'productionClaimLiftRoleDashboardReadinessTrustStateViewHash',
      'production_claim_lift_readiness_trust_state_view_mismatch',
    ],
    [
      'productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash',
      'production_claim_lift_runtime_source_provider_receipt_mismatch',
    ],
    [
      'productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash',
      'production_claim_lift_runtime_source_provider_summary_mismatch',
    ],
    [
      'productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash',
      'production_claim_lift_runtime_source_provider_trust_state_view_mismatch',
    ],
    [
      'productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash',
      'production_claim_lift_runtime_source_readiness_receipt_mismatch',
    ],
    [
      'productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash',
      'production_claim_lift_runtime_source_readiness_summary_mismatch',
    ],
    [
      'productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash',
      'production_claim_lift_runtime_source_readiness_trust_state_view_mismatch',
    ],
  ];

  for (const [field, reasonSuffix] of digestChecks) {
    addReason(
      reasons,
      isDigest(sourceEvidence?.[field]) &&
        isDigest(handoffEvidence?.[field]) &&
        sourceEvidence[field] !== handoffEvidence[field],
      `${prefix}_${reasonSuffix}`,
    );
  }

  const sourceProductionClaimLiftRoles = sortedTextList(sourceEvidence?.productionClaimLiftRoleDashboardRoles);
  const handoffProductionClaimLiftRoles = sortedTextList(handoffEvidence?.productionClaimLiftRoleDashboardRoles);
  addReason(
    reasons,
    sourceProductionClaimLiftRoles.length > 0 &&
      handoffProductionClaimLiftRoles.length > 0 &&
      sourceProductionClaimLiftRoles.join('\n') !== handoffProductionClaimLiftRoles.join('\n'),
    `${prefix}_production_claim_lift_roles_mismatch`,
  );
}

function evaluateValidation(validation, reasons) {
  const commandRefs = sortedTextList(validation?.commandRefs);
  addReason(reasons, commandRefs.length === 0, 'validation_command_refs_absent');
  for (const commandRef of REQUIRED_VALIDATION_COMMANDS) {
    addReason(reasons, !commandRefs.includes(commandRef), `validation_command_missing:${commandRef}`);
  }
  addReason(reasons, validation?.adapterTestsPassed !== true, 'adapter_validation_tests_missing');
  addReason(reasons, validation?.sourceGuardPassed !== true, 'source_guard_validation_missing');
  addReason(reasons, validation?.privacyFixturesPassed !== true, 'privacy_fixture_validation_missing');
  addReason(reasons, validation?.gatewayTestsPassed !== true, 'gateway_validation_tests_missing');
  addReason(reasons, validation?.nodeReceiptTestsPassed !== true, 'node_receipt_validation_tests_missing');
  addReason(reasons, validation?.decisionForumTestsPassed !== true, 'decision_forum_validation_tests_missing');
  addReason(reasons, validation?.rootBundleTestsPassed !== true, 'root_bundle_validation_tests_missing');
  addReason(reasons, !isDigest(validation?.validationHash), 'activation_validation_hash_invalid');
  addReason(reasons, validation?.metadataOnly !== true, 'activation_validation_metadata_boundary_absent');
  addReason(reasons, validation?.protectedContentExcluded !== true, 'activation_validation_protected_content_boundary_absent');
  addReason(reasons, hlcTuple(validation?.recordedAtHlc) === null, 'activation_validation_time_invalid');
}

function evaluateHumanReview(review, reasons) {
  addReason(reasons, !hasText(review?.reviewerDid), 'human_review_reviewer_absent');
  addReason(reasons, !HUMAN_REVIEW_DECISIONS.has(review?.decision), 'human_review_decision_invalid');
  addReason(reasons, !isDigest(review?.reviewHash), 'human_review_hash_invalid');
  addReason(reasons, review?.metadataOnly !== true, 'human_review_metadata_boundary_absent');
  addReason(reasons, review?.protectedContentExcluded !== true, 'human_review_protected_content_boundary_absent');
  addReason(reasons, hlcTuple(review?.reviewedAtHlc) === null, 'human_review_time_invalid');
}

function evaluateChronology(input, reasons) {
  const ordered = [
    ['activation_cycle', input?.activationCycle?.openedAtHlc],
    ['root_bundle', input?.rootBundleEvidence?.checkedAtHlc],
    ['gateway', input?.gatewayEvidence?.checkedAtHlc],
    ['node_receipt', input?.nodeReceiptEvidence?.checkedAtHlc],
    ['decision_forum', input?.decisionForumEvidence?.checkedAtHlc],
    ['privacy_boundary', input?.privacyBoundaryEvidence?.checkedAtHlc],
    ['runtime_configuration_source', input?.runtimeConfigurationSourceEvidence?.reviewedAtHlc],
    ['deployment_handoff_cutover', input?.deploymentHandoffCutoverEvidence?.reviewedAtHlc],
    ['validation', input?.validationEvidence?.recordedAtHlc],
    ['human_review', input?.humanReview?.reviewedAtHlc],
  ];

  for (let index = 1; index < ordered.length; index += 1) {
    const [label, current] = ordered[index];
    const [, previous] = ordered[index - 1];
    addReason(reasons, hlcBefore(current, previous), `activation_hlc_order_invalid:${label}`);
  }
}

function componentState(component, successCondition) {
  if (successCondition) {
    return 'verified';
  }
  if (component?.state === 'pending' || component?.status === 'pending') {
    return 'pending';
  }
  return 'denied';
}

function buildComponentStates(input) {
  return {
    decisionForum: componentState(
      input?.decisionForumEvidence,
      input?.decisionForumEvidence?.state === 'verified' && input?.decisionForumEvidence?.decisionState === 'approved',
    ),
    deploymentHandoffCutover: componentState(
      input?.deploymentHandoffCutoverEvidence,
      DEPLOYMENT_HANDOFF_CUTOVER_STATUSES.has(input?.deploymentHandoffCutoverEvidence?.status) &&
        input?.deploymentHandoffCutoverEvidence?.productionCutoverReady === true &&
        input?.deploymentHandoffCutoverEvidence?.trustState === 'inactive',
    ),
    gateway: componentState(
      input?.gatewayEvidence,
      input?.gatewayEvidence?.decision === 'permitted' &&
        (input?.gatewayEvidence?.status === 'verified' || input?.gatewayEvidence?.state === 'verified'),
    ),
    nodeReceipt: componentState(
      input?.nodeReceiptEvidence,
      input?.nodeReceiptEvidence?.state === 'verified' && input?.nodeReceiptEvidence?.syncStatus === 'ready_inactive_trust',
    ),
    privacyBoundary: componentState(input?.privacyBoundaryEvidence, input?.privacyBoundaryEvidence?.state === 'verified'),
    rootBundle: componentState(
      input?.rootBundleEvidence,
      input?.rootBundleEvidence?.state === 'verified' && input?.rootBundleEvidence?.verified === true,
    ),
    runtimeConfigurationSource: componentState(
      input?.runtimeConfigurationSourceEvidence,
      input?.runtimeConfigurationSourceEvidence?.productionConfigurationReady === true &&
        input?.runtimeConfigurationSourceEvidence?.trustState === 'inactive' &&
        sortedTextList(input?.runtimeConfigurationSourceEvidence?.activationBlockerIds).length === 0,
    ),
  };
}

function buildActivationEvidence(input, allowed, reasons) {
  const activationGateIds = sortedTextList(input?.activationPolicy?.requiredGateIds);
  const validationCommandRefs = sortedTextList(input?.validationEvidence?.commandRefs);
  const componentStates = buildComponentStates(input);
  const sourceHandoff = input?.runtimeConfigurationSourceEvidence?.deploymentHandoffCutover;
  const sourceReadinessRoleDashboard = sourceHandoff?.deploymentReadinessRoleDashboardTrustStateEvidence;
  const sourceProviderRoleDashboard = sourceHandoff?.deploymentProviderBindingRoleDashboardTrustStateEvidence;
  const handoffReadinessRoleDashboard =
    input?.deploymentHandoffCutoverEvidence?.deploymentReadinessRoleDashboardTrustStateEvidence;
  const handoffProviderRoleDashboard =
    input?.deploymentHandoffCutoverEvidence?.deploymentProviderBindingRoleDashboardTrustStateEvidence;
  const deploymentHandoffCutoverRoleDashboardRoles = uniqueSorted([
    ...sortedTextList(handoffReadinessRoleDashboard?.dashboardRoles),
    ...sortedTextList(handoffProviderRoleDashboard?.dashboardRoles),
  ]);
  const runtimeConfigurationSourceHandoffRoleDashboardRoles = uniqueSorted([
    ...sortedTextList(sourceReadinessRoleDashboard?.dashboardRoles),
    ...sortedTextList(sourceProviderRoleDashboard?.dashboardRoles),
  ]);
  const evidenceMaterial = {
    actionHash: isDigest(input?.gatewayEvidence?.actionHash) ? input.gatewayEvidence.actionHash : null,
    activationGateIds,
    artifactRegistryHash: isDigest(input?.rootBundleEvidence?.artifactRegistryHash)
      ? input.rootBundleEvidence.artifactRegistryHash
      : null,
    classificationHash: isDigest(input?.privacyBoundaryEvidence?.classificationHash)
      ? input.privacyBoundaryEvidence.classificationHash
      : null,
    componentStates,
    custodyDigest: isDigest(input?.custodyDigest) ? input.custodyDigest : null,
    decisionForumReceiptId: hasText(input?.decisionForumEvidence?.workflowReceiptId)
      ? input.decisionForumEvidence.workflowReceiptId
      : null,
    evidencePackageRef: hasText(input?.activationCycle?.evidencePackageRef)
      ? input.activationCycle.evidencePackageRef
      : 'unclassified',
    gatewayCallHash: isDigest(input?.gatewayEvidence?.gatewayCallHash) ? input.gatewayEvidence.gatewayCallHash : null,
    gatewayReceiptId: hasText(input?.gatewayEvidence?.gatewayReceiptId) ? input.gatewayEvidence.gatewayReceiptId : null,
    deploymentHandoffCutoverHash: isDigest(input?.deploymentHandoffCutoverEvidence?.handoffHash)
      ? input.deploymentHandoffCutoverEvidence.handoffHash
      : null,
    deploymentHandoffCutoverProviderRoleDashboardReceiptHash: isDigest(
      handoffProviderRoleDashboard?.roleDashboardReceiptHash,
    )
      ? handoffProviderRoleDashboard.roleDashboardReceiptHash
      : null,
    deploymentHandoffCutoverProviderRoleDashboardSummaryHash: isDigest(
      handoffProviderRoleDashboard?.roleDashboardSummaryHash,
    )
      ? handoffProviderRoleDashboard.roleDashboardSummaryHash
      : null,
    deploymentHandoffCutoverProviderRoleDashboardTrustStateViewHash: isDigest(
      handoffProviderRoleDashboard?.roleDashboardTrustStateViewHash,
    )
      ? handoffProviderRoleDashboard.roleDashboardTrustStateViewHash
      : null,
    deploymentHandoffCutoverReadinessRoleDashboardReceiptHash: isDigest(
      handoffReadinessRoleDashboard?.roleDashboardReceiptHash,
    )
      ? handoffReadinessRoleDashboard.roleDashboardReceiptHash
      : null,
    deploymentHandoffCutoverReadinessRoleDashboardSummaryHash: isDigest(
      handoffReadinessRoleDashboard?.roleDashboardSummaryHash,
    )
      ? handoffReadinessRoleDashboard.roleDashboardSummaryHash
      : null,
    deploymentHandoffCutoverReadinessRoleDashboardTrustStateViewHash: isDigest(
      handoffReadinessRoleDashboard?.roleDashboardTrustStateViewHash,
    )
      ? handoffReadinessRoleDashboard.roleDashboardTrustStateViewHash
      : null,
    deploymentHandoffCutoverReceiptHash: isDigest(input?.deploymentHandoffCutoverEvidence?.receiptHash)
      ? input.deploymentHandoffCutoverEvidence.receiptHash
      : null,
    deploymentHandoffCutoverRoleDashboardRoles,
    nodeReceiptId: hasText(input?.nodeReceiptEvidence?.nodeReceiptId) ? input.nodeReceiptEvidence.nodeReceiptId : null,
    nodeReceiptSyncHash: isDigest(input?.nodeReceiptEvidence?.nodeReceiptSyncHash)
      ? input.nodeReceiptEvidence.nodeReceiptSyncHash
      : null,
    releaseCandidateRef: hasText(input?.activationCycle?.releaseCandidateRef)
      ? input.activationCycle.releaseCandidateRef
      : 'unreleased',
    rootTrustBundleHash: isDigest(input?.rootBundleEvidence?.rootTrustBundleHash)
      ? input.rootBundleEvidence.rootTrustBundleHash
      : null,
    rootVerifierReceiptId: hasText(input?.rootBundleEvidence?.verifierReceiptId)
      ? input.rootBundleEvidence.verifierReceiptId
      : null,
    runtimeConfigurationHash: isDigest(input?.runtimeConfigurationSourceEvidence?.runtimeConfigurationHash)
      ? input.runtimeConfigurationSourceEvidence.runtimeConfigurationHash
      : null,
    runtimeConfigurationSourceHandoffHash: isDigest(sourceHandoff?.handoffHash) ? sourceHandoff.handoffHash : null,
    runtimeConfigurationSourceHandoffProviderRoleDashboardReceiptHash: isDigest(
      sourceProviderRoleDashboard?.roleDashboardReceiptHash,
    )
      ? sourceProviderRoleDashboard.roleDashboardReceiptHash
      : null,
    runtimeConfigurationSourceHandoffProviderRoleDashboardSummaryHash: isDigest(
      sourceProviderRoleDashboard?.roleDashboardSummaryHash,
    )
      ? sourceProviderRoleDashboard.roleDashboardSummaryHash
      : null,
    runtimeConfigurationSourceHandoffProviderRoleDashboardTrustStateViewHash: isDigest(
      sourceProviderRoleDashboard?.roleDashboardTrustStateViewHash,
    )
      ? sourceProviderRoleDashboard.roleDashboardTrustStateViewHash
      : null,
    runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: isDigest(
      sourceProviderRoleDashboard?.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    )
      ? sourceProviderRoleDashboard.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash
      : null,
    runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: isDigest(
      sourceProviderRoleDashboard?.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    )
      ? sourceProviderRoleDashboard.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash
      : null,
    runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: isDigest(
      sourceProviderRoleDashboard?.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    )
      ? sourceProviderRoleDashboard.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash
      : null,
    runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: isDigest(
      sourceProviderRoleDashboard?.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    )
      ? sourceProviderRoleDashboard.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash
      : null,
    runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: isDigest(
      sourceProviderRoleDashboard?.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    )
      ? sourceProviderRoleDashboard.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash
      : null,
    runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: isDigest(
      sourceProviderRoleDashboard?.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    )
      ? sourceProviderRoleDashboard.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash
      : null,
    runtimeConfigurationSourceHandoffReadinessRoleDashboardReceiptHash: isDigest(
      sourceReadinessRoleDashboard?.roleDashboardReceiptHash,
    )
      ? sourceReadinessRoleDashboard.roleDashboardReceiptHash
      : null,
    runtimeConfigurationSourceHandoffReadinessRoleDashboardSummaryHash: isDigest(
      sourceReadinessRoleDashboard?.roleDashboardSummaryHash,
    )
      ? sourceReadinessRoleDashboard.roleDashboardSummaryHash
      : null,
    runtimeConfigurationSourceHandoffReadinessRoleDashboardTrustStateViewHash: isDigest(
      sourceReadinessRoleDashboard?.roleDashboardTrustStateViewHash,
    )
      ? sourceReadinessRoleDashboard.roleDashboardTrustStateViewHash
      : null,
    runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: isDigest(
      sourceReadinessRoleDashboard?.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    )
      ? sourceReadinessRoleDashboard.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash
      : null,
    runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: isDigest(
      sourceReadinessRoleDashboard?.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    )
      ? sourceReadinessRoleDashboard.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash
      : null,
    runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: isDigest(
      sourceReadinessRoleDashboard?.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    )
      ? sourceReadinessRoleDashboard.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash
      : null,
    runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: isDigest(
      sourceReadinessRoleDashboard?.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    )
      ? sourceReadinessRoleDashboard.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash
      : null,
    runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: isDigest(
      sourceReadinessRoleDashboard?.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    )
      ? sourceReadinessRoleDashboard.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash
      : null,
    runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: isDigest(
      sourceReadinessRoleDashboard?.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    )
      ? sourceReadinessRoleDashboard.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash
      : null,
    runtimeConfigurationSourceHandoffReceiptHash: isDigest(sourceHandoff?.receiptHash) ? sourceHandoff.receiptHash : null,
    runtimeConfigurationSourceHandoffRoleDashboardRoles,
    runtimeConfigurationSourceReceiptHash: isDigest(input?.runtimeConfigurationSourceEvidence?.receiptHash)
      ? input.runtimeConfigurationSourceEvidence.receiptHash
      : null,
    runtimePathRef: hasText(input?.activationCycle?.runtimePathRef) ? input.activationCycle.runtimePathRef : 'unclassified',
    schema: EVIDENCE_SCHEMA,
    tenantId: hasText(input?.tenantId) ? input.tenantId : 'unclassified',
    validationCommandRefs,
    validationHash: isDigest(input?.validationEvidence?.validationHash) ? input.validationEvidence.validationHash : null,
  };
  const evidencePackageHash = sha256Hex(evidenceMaterial);

  return {
    schema: EVIDENCE_SCHEMA,
    evidencePackageId: `cmaae_${evidencePackageHash.slice(0, 32)}`,
    evidencePackageRef: evidenceMaterial.evidencePackageRef,
    evidencePackageHash,
    status: allowed ? 'ready_for_claim_lift_request' : 'blocked_inactive_trust',
    trustState: 'inactive',
    canRequestProductionClaimLift: allowed,
    canShowProductionTrustClaim: false,
    exochainProductionClaim: false,
    baselineDevelopmentBlocked: false,
    tenantId: evidenceMaterial.tenantId,
    releaseCandidateRef: evidenceMaterial.releaseCandidateRef,
    runtimePathRef: evidenceMaterial.runtimePathRef,
    activationGateIds,
    componentStates,
    rootVerifierReceiptId: evidenceMaterial.rootVerifierReceiptId,
    gatewayReceiptId: evidenceMaterial.gatewayReceiptId,
    nodeReceiptId: evidenceMaterial.nodeReceiptId,
    decisionForumReceiptId: evidenceMaterial.decisionForumReceiptId,
    deploymentHandoffCutoverHash: evidenceMaterial.deploymentHandoffCutoverHash,
    deploymentHandoffCutoverProviderRoleDashboardReceiptHash:
      evidenceMaterial.deploymentHandoffCutoverProviderRoleDashboardReceiptHash,
    deploymentHandoffCutoverProviderRoleDashboardSummaryHash:
      evidenceMaterial.deploymentHandoffCutoverProviderRoleDashboardSummaryHash,
    deploymentHandoffCutoverProviderRoleDashboardTrustStateViewHash:
      evidenceMaterial.deploymentHandoffCutoverProviderRoleDashboardTrustStateViewHash,
    deploymentHandoffCutoverReadinessRoleDashboardReceiptHash:
      evidenceMaterial.deploymentHandoffCutoverReadinessRoleDashboardReceiptHash,
    deploymentHandoffCutoverReadinessRoleDashboardSummaryHash:
      evidenceMaterial.deploymentHandoffCutoverReadinessRoleDashboardSummaryHash,
    deploymentHandoffCutoverReadinessRoleDashboardTrustStateViewHash:
      evidenceMaterial.deploymentHandoffCutoverReadinessRoleDashboardTrustStateViewHash,
    deploymentHandoffCutoverReceiptHash: evidenceMaterial.deploymentHandoffCutoverReceiptHash,
    deploymentHandoffCutoverRoleDashboardRoles,
    actionHash: evidenceMaterial.actionHash,
    rootTrustBundleHash: evidenceMaterial.rootTrustBundleHash,
    runtimeConfigurationHash: evidenceMaterial.runtimeConfigurationHash,
    runtimeConfigurationSourceHandoffHash: evidenceMaterial.runtimeConfigurationSourceHandoffHash,
    runtimeConfigurationSourceHandoffProviderRoleDashboardReceiptHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffProviderRoleDashboardReceiptHash,
    runtimeConfigurationSourceHandoffProviderRoleDashboardSummaryHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffProviderRoleDashboardSummaryHash,
    runtimeConfigurationSourceHandoffProviderRoleDashboardTrustStateViewHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffProviderRoleDashboardTrustStateViewHash,
    runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash:
      evidenceMaterial
        .runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash:
      evidenceMaterial
        .runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    runtimeConfigurationSourceHandoffReadinessRoleDashboardReceiptHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffReadinessRoleDashboardReceiptHash,
    runtimeConfigurationSourceHandoffReadinessRoleDashboardSummaryHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffReadinessRoleDashboardSummaryHash,
    runtimeConfigurationSourceHandoffReadinessRoleDashboardTrustStateViewHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffReadinessRoleDashboardTrustStateViewHash,
    runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash:
      evidenceMaterial
        .runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash:
      evidenceMaterial
        .runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash:
      evidenceMaterial
        .runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash:
      evidenceMaterial.runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash:
      evidenceMaterial
        .runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash:
      evidenceMaterial
        .runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash:
      evidenceMaterial
        .runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    runtimeConfigurationSourceHandoffReceiptHash: evidenceMaterial.runtimeConfigurationSourceHandoffReceiptHash,
    runtimeConfigurationSourceHandoffRoleDashboardRoles,
    runtimeConfigurationSourceReceiptHash: evidenceMaterial.runtimeConfigurationSourceReceiptHash,
    validationHash: evidenceMaterial.validationHash,
    blockedBy: reasons,
    metadataOnly: true,
  };
}

function buildReceipt(input, activationEvidence) {
  return createEvidenceReceipt({
    actorDid: input.actor.did,
    artifactHash: activationEvidence.evidencePackageHash,
    artifactType: 'adapter_activation_evidence',
    artifactVersion: activationEvidence.evidencePackageRef,
    classification: 'metadata_only_adapter_activation_evidence',
    custodyDigest: input.custodyDigest,
    hlcTimestamp: input.humanReview.reviewedAtHlc,
    sensitivityTags: [
      'adapter_activation_evidence',
      'deployment_handoff_cutover',
      'inactive_trust',
      'metadata_only',
      'role_dashboard_trust_state',
      'runtime_configuration_source',
    ],
    sourceSystem: 'cybermedica.adapter_activation_evidence',
    tenantId: input.tenantId,
  });
}

export function evaluateAdapterActivationEvidence(input) {
  assertMetadataOnly(input);

  const reasons = [];
  evaluateTenantActorAuthority(input, reasons);
  evaluatePolicy(input?.activationPolicy, reasons);
  evaluateCycle(input?.activationCycle, reasons);
  evaluateRootBundle(input?.rootBundleEvidence, input?.activationCycle, reasons);
  evaluateGateway(input?.gatewayEvidence, input, reasons);
  evaluateNodeReceipt(input?.nodeReceiptEvidence, input, reasons);
  evaluateDecisionForum(input?.decisionForumEvidence, input, reasons);
  evaluatePrivacyBoundary(input?.privacyBoundaryEvidence, reasons);
  const runtimeConfigurationSourceSummary = evaluateRuntimeConfigurationSourceLineage(
    input?.runtimeConfigurationSourceEvidence,
    input?.activationCycle,
    reasons,
  );
  evaluateDeploymentHandoffCutoverLineage(
    input?.deploymentHandoffCutoverEvidence,
    runtimeConfigurationSourceSummary,
    input?.activationCycle,
    reasons,
  );
  evaluateValidation(input?.validationEvidence, reasons);
  evaluateHumanReview(input?.humanReview, reasons);
  addReason(reasons, !isDigest(input?.custodyDigest), 'activation_custody_digest_invalid');
  evaluateChronology(input, reasons);

  const blockedBy = uniqueReasons(reasons);
  const allowed =
    blockedBy.length === 0 &&
    input?.humanReview?.decision === 'adapter_activation_ready_for_claim_lift_request';
  const activationEvidence = buildActivationEvidence(input ?? {}, allowed, blockedBy);

  return {
    schema: DECISION_SCHEMA,
    decision: allowed ? 'permitted' : 'denied',
    failClosed: !allowed,
    reasons: blockedBy,
    activationEvidence,
    receipt: allowed ? buildReceipt(input, activationEvidence) : null,
  };
}
