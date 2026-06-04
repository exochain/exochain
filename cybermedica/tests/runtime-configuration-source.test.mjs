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

import assert from 'node:assert/strict';
import { test } from 'node:test';

const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_3 = '3333333333333333333333333333333333333333333333333333333333333333';
const DIGEST_4 = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_5 = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_6 = '6666666666666666666666666666666666666666666666666666666666666666';
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';

const REQUIRED_CONFIGURATION_DOMAINS = [
  'adapter_endpoints',
  'audit_evidence',
  'deployment_environment',
  'feature_flags',
  'health_readiness',
  'rollback_disablement',
  'root_bundle_provider',
  'secret_scope',
];

const REQUIRED_ADAPTERS = ['decision_forum', 'gateway', 'node_receipt', 'root_bundle_provider'];

const ALLOWED_ACTIVATION_BLOCKERS = [
  'ESC-OPS-SECRETS',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-RUNTIME',
];

const REQUIRED_DRIFT_STATE_TARGETS = ['passport', 'quality_state', 'readiness'];

const DASHBOARD_ROLES = [
  'auditor',
  'coordinator',
  'cro_portfolio_manager',
  'decision_forum',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_viewer',
];

async function loadRuntimeConfigurationSource() {
  try {
    return await import('../src/runtime-configuration-source.mjs');
  } catch (error) {
    assert.fail(`CyberMedica runtime configuration source module must exist and load: ${error.message}`);
  }
}

function mergeDeep(base, overrides) {
  if (Array.isArray(base) || Array.isArray(overrides)) {
    return overrides === undefined ? base : overrides;
  }
  if (base === null || overrides === null || typeof base !== 'object' || typeof overrides !== 'object') {
    return overrides === undefined ? base : overrides;
  }
  return Object.fromEntries(
    [...new Set([...Object.keys(base), ...Object.keys(overrides)])].map((key) => [
      key,
      mergeDeep(base[key], overrides[key]),
    ]),
  );
}

function configurationDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  const activationBlocked = ['root_bundle_provider', 'secret_scope'].includes(domain);
  return {
    domain,
    status: activationBlocked ? 'activation_blocked' : 'ready',
    evidenceRef: `runtime-config-evidence-${domain}`,
    evidenceHash: hashes[index],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner`,
    activationBlockerId: activationBlocked
      ? (domain === 'secret_scope' ? 'ESC-OPS-SECRETS' : 'ESC-ROOT-DEPLOYMENT')
      : null,
    productionActivationOnly: activationBlocked,
    blocksBaselineDevelopment: false,
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800004200000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function configurationDomains() {
  return REQUIRED_CONFIGURATION_DOMAINS.map((domain, index) => configurationDomain(domain, index));
}

function adapterBinding(kind, index, overrides = {}) {
  const hashes = [DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F];
  const rootAdapter = kind === 'root_bundle_provider';
  return {
    kind,
    status: rootAdapter ? 'activation_blocked' : 'ready',
    providerRef: `${kind}-adapter-provider`,
    adapterHash: hashes[index],
    endpointHash: rootAdapter ? null : hashes[(index + 1) % hashes.length],
    credentialScopeRef: rootAdapter ? null : `cm-${kind}-credential-scope`,
    credentialScopeHash: rootAdapter ? null : hashes[(index + 2) % hashes.length],
    activationBlockerId: rootAdapter ? 'ESC-ROOT-DEPLOYMENT' : null,
    missingSecretsFailClosed: true,
    unavailableFailsClosed: true,
    browserAuthoritative: false,
    verifiedAtHlc: { physicalMs: 1800004200000, logical: index + 10 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function adapterBindings() {
  return REQUIRED_ADAPTERS.map((kind, index) => adapterBinding(kind, index));
}

function deploymentReadinessDriftStateUpdateEvidence(overrides = {}) {
  return mergeDeep(
    {
      driftLoopId: 'cmdrift_deployment_readiness_alpha',
      driftLoopHash: DIGEST_4,
      driftLoopReceiptHash: DIGEST_5,
      stateUpdateHash: DIGEST_6,
      stateUpdateTargets: REQUIRED_DRIFT_STATE_TARGETS,
      cqiCycleHash: DIGEST_7,
      cqiCycleReceiptHash: DIGEST_8,
      inquiryCqiBacklogReceiptHash: DIGEST_9,
      manualNavigationReady: true,
      manualNavigationEffectiveUseAcknowledged: true,
      roleManualCoverageReceiptHash: DIGEST_F,
      trustState: 'inactive',
      exochainProductionClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800004200000, logical: 8 },
    },
    overrides,
  );
}

function roleDashboardTrustStateEvidence(overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return mergeDeep(
    {
      schema: 'cybermedica.role_dashboard_trust_state_lineage.v1',
      roleDashboardSummaryHash: DIGEST_A,
      roleDashboardReceiptHash: DIGEST_B,
      roleDashboardTrustStateViewHash: DIGEST_C,
      dashboardRoles: DASHBOARD_ROLES,
      dashboardHashRefs: DASHBOARD_ROLES.map((role, index) => ({
        role,
        dashboardHash: hashes[index],
        trustStateViewHash: hashes[index + 1],
      })),
      trustState: 'inactive',
      exochainProductionClaim: false,
      canShowProductionTrustClaim: false,
      activationLineageAccepted: true,
      publicClaimReviewReceiptHash: DIGEST_1,
      publicClaimReviewPackageHash: DIGEST_2,
      productionClaimLiftReceiptHash: DIGEST_3,
      productionClaimLiftTrustState: 'inactive',
      productionClaimLiftCanLiftProductionClaim: false,
      productionClaimLiftRoleDashboardProviderReceiptHash: DIGEST_B,
      productionClaimLiftRoleDashboardProviderSummaryHash: DIGEST_A,
      productionClaimLiftRoleDashboardProviderTrustStateViewHash: DIGEST_C,
      productionClaimLiftRoleDashboardReadinessReceiptHash: DIGEST_E,
      productionClaimLiftRoleDashboardReadinessSummaryHash: DIGEST_F,
      productionClaimLiftRoleDashboardReadinessTrustStateViewHash: DIGEST_D,
      productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_B,
      productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_A,
      productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_C,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_E,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_F,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_D,
      productionClaimLiftRoleDashboardRoles: DASHBOARD_ROLES,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800004200000, logical: 12 },
    },
    overrides,
  );
}

function runtimeConfigurationInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:deployment-config-owner-alpha',
      kind: 'human',
      roleRefs: ['deployment_owner', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['runtime_configuration_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    configurationPolicy: {
      policyRef: 'runtime-configuration-source-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredConfigurationDomains: REQUIRED_CONFIGURATION_DOMAINS,
      requiredAdapters: REQUIRED_ADAPTERS,
      allowedActivationBlockerIds: ALLOWED_ACTIVATION_BLOCKERS,
      serverSideAdapterRequired: true,
      noCredentialDisclosure: true,
      noSharedExochainSecrets: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800004000000, logical: 0 },
    },
    configurationCycle: {
      configurationRef: 'runtime-configuration-source-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-06',
      openedAtHlc: { physicalMs: 1800004100000, logical: 0 },
      evidenceCollectedAtHlc: { physicalMs: 1800004200000, logical: 12 },
      validationRecordedAtHlc: { physicalMs: 1800004300000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800004400000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800004500000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    runtimeConfiguration: {
      sourceRef: 'cybermedica-runtime-config-source-alpha',
      sourceHash: DIGEST_C,
      deploymentEnvironment: 'prototype',
      selectedTopology: 'server_side_gateway_node',
      configSnapshotHash: DIGEST_D,
      schemaHash: DIGEST_E,
      featureFlagManifestHash: DIGEST_F,
      browserAuthoritativePathEnabled: false,
      healthSeparatesProcessAndTrust: true,
      unavailableTrustFabricFailsClosed: true,
      productionTrustClaim: false,
      checkedAtHlc: { physicalMs: 1800004200000, logical: 9 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    configurationDomains: configurationDomains(),
    adapterBindings: adapterBindings(),
    secretScope: {
      scopeRef: 'cm-runtime-adapter-secret-scope-alpha',
      scopeHash: DIGEST_1,
      secretManagerRef: null,
      secretManagerHash: null,
      status: 'activation_blocked',
      activationBlockerId: 'ESC-OPS-SECRETS',
      cybermedicaOnly: true,
      sharedWithExochainRoot: false,
      sharedWithExochainBootstrap: false,
      missingSecretsFailClosed: true,
      malformedSecretsFailClosed: true,
      rotationOwnerDid: null,
      rotationPolicyHash: null,
      metadataOnly: true,
      protectedContentExcluded: true,
      checkedAtHlc: { physicalMs: 1800004200000, logical: 11 },
    },
    deploymentReadinessManifest: {
      manifestHash: DIGEST_8,
      receiptHash: DIGEST_9,
      receiptArtifactType: 'deployment_readiness_manifest',
      status: 'deployment_readiness_manifest_accepted_inactive_trust',
      releaseCandidateRef: 'cybermedica-baseline-2026-06',
      trustState: 'inactive',
      baselineReady: true,
      productionClaim: false,
      driftStateUpdateEvidence: deploymentReadinessDriftStateUpdateEvidence(),
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800004200000, logical: 9 },
    },
    deploymentOperationsReadiness: {
      operationsReadinessRef: 'deployment-operations-readiness-alpha',
      operationsReadinessHash: DIGEST_A,
      receiptHash: DIGEST_B,
      receiptArtifactType: 'deployment_operations_readiness',
      status: 'deployment_operations_readiness_accepted_inactive_trust',
      releaseCandidateRef: 'cybermedica-baseline-2026-06',
      releaseIncidentLinkageReceiptHash: DIGEST_C,
      deploymentReadinessManifestReceiptHash: DIGEST_9,
      baselineOperationsPackReady: true,
      productionOperationsReady: false,
      railwayLoginStatus: 'login_required',
      activationBlockerIds: ALLOWED_ACTIVATION_BLOCKERS,
      trustState: 'inactive',
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
      reviewedAtHlc: { physicalMs: 1800004200000, logical: 10 },
    },
    deploymentProviderBinding: {
      providerBindingRef: 'deployment-provider-binding-alpha',
      providerBindingHash: DIGEST_C,
      receiptHash: DIGEST_D,
      receiptArtifactType: 'deployment_provider_binding',
      status: 'deployment_provider_binding_accepted_inactive_trust',
      releaseCandidateRef: 'cybermedica-baseline-2026-06',
      operationsReadinessReceiptHash: DIGEST_B,
      deploymentReadinessManifestReceiptHash: DIGEST_9,
      baselineProviderBindingReady: true,
      productionProviderBindingReady: false,
      trustState: 'inactive',
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
      reviewedAtHlc: { physicalMs: 1800004200000, logical: 11 },
    },
    deploymentHandoffCutover: {
      handoffRef: 'deployment-handoff-cutover-alpha',
      handoffHash: DIGEST_E,
      receiptHash: DIGEST_F,
      receiptArtifactType: 'deployment_handoff_cutover',
      status: 'deployment_handoff_cutover_accepted_inactive_trust',
      releaseCandidateRef: 'cybermedica-baseline-2026-06',
      deploymentReadinessManifestReceiptHash: DIGEST_9,
      deploymentOperationsReadinessHash: DIGEST_A,
      deploymentProviderBindingReceiptHash: DIGEST_D,
      baselineHandoffReady: true,
      productionCutoverReady: false,
      trustState: 'inactive',
      productionTrustClaim: false,
      deploymentReadinessRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
      deploymentProviderBindingRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800004200000, logical: 12 },
    },
    validationEvidence: {
      commandRefs: ['npm run quality', 'node scripts/source-secret-scan.mjs'],
      commandsPassed: true,
      testCount: 331,
      coverageLineBasisPoints: 9812,
      sourceGuardPassed: true,
      secretScanPassed: true,
      configSchemaEvidenceHash: DIGEST_2,
      noExochainSourceModified: true,
      metadataOnly: true,
      recordedAtHlc: { physicalMs: 1800004300000, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'configuration_ready_with_activation_blockers',
      decisionHash: DIGEST_3,
      activationBlockersAccepted: true,
      noProductionTrustClaim: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800004400000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'runtime-configuration-source-audit-alpha',
      auditRecordHash: DIGEST_4,
      receiptRecordedAtHlc: { physicalMs: 1800004500000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_5,
      limitationHashes: [DIGEST_6],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_7,
  };
  return mergeDeep(base, overrides);
}

test('runtime configuration source records external config and secret blockers deterministically', async () => {
  const { evaluateRuntimeConfigurationSource } = await loadRuntimeConfigurationSource();

  const resultA = evaluateRuntimeConfigurationSource(runtimeConfigurationInput());
  const resultB = evaluateRuntimeConfigurationSource(
    runtimeConfigurationInput({
      configurationPolicy: {
        requiredConfigurationDomains: [...REQUIRED_CONFIGURATION_DOMAINS].reverse(),
        requiredAdapters: [...REQUIRED_ADAPTERS].reverse(),
        allowedActivationBlockerIds: [...ALLOWED_ACTIVATION_BLOCKERS].reverse(),
      },
      configurationDomains: [...configurationDomains()].reverse(),
      adapterBindings: [...adapterBindings()].reverse(),
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.runtimeConfiguration.trustState, 'inactive');
  assert.equal(resultA.runtimeConfiguration.exochainProductionClaim, false);
  assert.equal(resultA.runtimeConfiguration.baselineConfigurationReady, true);
  assert.equal(resultA.runtimeConfiguration.productionConfigurationReady, false);
  assert.deepEqual(resultA.runtimeConfiguration.configurationDomainsCovered, REQUIRED_CONFIGURATION_DOMAINS);
  assert.deepEqual(resultA.runtimeConfiguration.adaptersCovered, REQUIRED_ADAPTERS);
  assert.deepEqual(resultA.runtimeConfiguration.activationBlockerIds, ['ESC-OPS-SECRETS', 'ESC-ROOT-DEPLOYMENT']);
  assert.equal(resultA.runtimeConfiguration.secretScope.status, 'activation_blocked');
  assert.equal(resultA.runtimeConfiguration.secretScope.cybermedicaOnly, true);
  assert.equal(resultA.runtimeConfiguration.runtime.selectedTopology, 'server_side_gateway_node');
  assert.equal(resultA.runtimeConfiguration.deploymentReadinessManifest.receiptHash, DIGEST_9);
  assert.equal(resultA.runtimeConfiguration.deploymentReadinessManifest.driftStateUpdateEvidence.stateUpdateHash, DIGEST_6);
  assert.equal(resultA.runtimeConfiguration.deploymentOperationsReadiness.receiptHash, DIGEST_B);
  assert.equal(resultA.runtimeConfiguration.deploymentOperationsReadiness.deploymentReadinessManifestReceiptHash, DIGEST_9);
  assert.equal(resultA.runtimeConfiguration.deploymentProviderBinding.receiptHash, DIGEST_D);
  assert.equal(resultA.runtimeConfiguration.deploymentProviderBinding.operationsReadinessReceiptHash, DIGEST_B);
  assert.equal(resultA.runtimeConfiguration.deploymentHandoffCutover.receiptHash, DIGEST_F);
  assert.equal(
    resultA.runtimeConfiguration.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
      .roleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    resultA.runtimeConfiguration.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
      .productionClaimLiftRoleDashboardProviderTrustStateViewHash,
    DIGEST_C,
  );
  assert.equal(
    resultA.runtimeConfiguration.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
      .productionClaimLiftRoleDashboardReadinessTrustStateViewHash,
    DIGEST_D,
  );
  assert.deepEqual(
    resultA.runtimeConfiguration.deploymentHandoffCutover.deploymentReadinessRoleDashboardTrustStateEvidence
      .productionClaimLiftRoleDashboardRoles,
    DASHBOARD_ROLES,
  );
  assert.deepEqual(
    resultA.runtimeConfiguration.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
      .dashboardRoles,
    DASHBOARD_ROLES,
  );
  assert.equal(
    resultA.runtimeConfiguration.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
      .productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    resultA.runtimeConfiguration.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
      .productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    DIGEST_F,
  );
  assert.equal(
    resultA.runtimeConfiguration.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
      .productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    DIGEST_C,
  );
  assert.equal(
    resultA.runtimeConfiguration.deploymentHandoffCutover.deploymentProviderBindingRoleDashboardTrustStateEvidence
      .productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    DIGEST_D,
  );
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'runtime_configuration_source');
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('deployment_provider_binding'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('deployment_operations'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('deployment_readiness_manifest'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('deployment_handoff_cutover'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('drift_state_update'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('continuous_quality_improvement'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('manual_navigation_readiness'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('role_dashboard_trust_state'));
  assert.deepEqual(resultA, resultB);
});

test('runtime configuration source fails closed without accepted deployment lineage', async () => {
  const { evaluateRuntimeConfigurationSource } = await loadRuntimeConfigurationSource();

  const missing = evaluateRuntimeConfigurationSource(
    runtimeConfigurationInput({
      deploymentReadinessManifest: null,
      deploymentOperationsReadiness: null,
      deploymentProviderBinding: null,
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.runtimeConfiguration, null);
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_absent'));
  assert.ok(missing.reasons.includes('deployment_operations_readiness_absent'));
  assert.ok(missing.reasons.includes('deployment_provider_binding_absent'));

  const unsafe = evaluateRuntimeConfigurationSource(
    runtimeConfigurationInput({
      deploymentReadinessManifest: {
        receiptHash: DIGEST_A,
        releaseCandidateRef: 'wrong-release',
        trustState: 'active',
        baselineReady: false,
        productionClaim: true,
        driftStateUpdateEvidence: deploymentReadinessDriftStateUpdateEvidence({
          stateUpdateTargets: ['readiness'],
          manualNavigationReady: false,
          manualNavigationEffectiveUseAcknowledged: false,
        }),
      },
      deploymentOperationsReadiness: {
        status: 'deployment_operations_readiness_pending',
        deploymentReadinessManifestReceiptHash: DIGEST_B,
        releaseCandidateRef: 'wrong-release',
        trustState: 'active',
        baselineOperationsPackReady: false,
        productionTrustClaim: true,
      },
      deploymentProviderBinding: {
        status: 'deployment_provider_binding_pending',
        deploymentReadinessManifestReceiptHash: DIGEST_A,
        operationsReadinessReceiptHash: DIGEST_A,
        releaseCandidateRef: 'wrong-release',
        trustState: 'active',
        baselineProviderBindingReady: false,
        productionTrustClaim: true,
      },
    }),
  );

  assert.equal(unsafe.decision, 'denied');
  assert.equal(unsafe.runtimeConfiguration, null);
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_release_candidate_mismatch'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_baseline_not_ready'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_state_update_target_missing:passport'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_manual_navigation_ready_absent'));
  assert.ok(unsafe.reasons.includes('deployment_operations_readiness_status_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_operations_readiness_manifest_receipt_mismatch'));
  assert.ok(unsafe.reasons.includes('deployment_provider_binding_status_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_provider_binding_operations_receipt_mismatch'));
});

test('runtime configuration source requires deployment handoff role-dashboard trust-state lineage', async () => {
  const { evaluateRuntimeConfigurationSource } = await loadRuntimeConfigurationSource();

  const missing = evaluateRuntimeConfigurationSource(
    runtimeConfigurationInput({
      deploymentHandoffCutover: null,
    }),
  );
  const unsafe = evaluateRuntimeConfigurationSource(
    runtimeConfigurationInput({
      deploymentHandoffCutover: {
        receiptHash: 'not-a-digest',
        receiptArtifactType: 'deployment_summary',
        status: 'handoff_pending',
        releaseCandidateRef: 'wrong-release',
        deploymentReadinessManifestReceiptHash: DIGEST_A,
        deploymentOperationsReadinessHash: DIGEST_B,
        deploymentProviderBindingReceiptHash: DIGEST_C,
        baselineHandoffReady: false,
        trustState: 'active',
        productionTrustClaim: true,
        deploymentReadinessRoleDashboardTrustStateEvidence: null,
        deploymentProviderBindingRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence({
          schema: 'unsafe.role.dashboard.v1',
          dashboardRoles: DASHBOARD_ROLES.filter((role) => role !== 'sponsor_viewer'),
          dashboardHashRefs: [
            {
              role: 'unapproved_role',
              dashboardHash: 'bad-dashboard-hash',
              trustStateViewHash: null,
            },
          ],
          roleDashboardSummaryHash: null,
          roleDashboardReceiptHash: 'not-a-digest',
          roleDashboardTrustStateViewHash: null,
          trustState: 'active',
          exochainProductionClaim: true,
          canShowProductionTrustClaim: true,
          activationLineageAccepted: false,
          publicClaimReviewReceiptHash: null,
          publicClaimReviewPackageHash: 'bad-package-hash',
          productionClaimLiftReceiptHash: null,
          productionClaimLiftTrustState: 'verified',
          productionClaimLiftCanLiftProductionClaim: true,
          productionClaimLiftRoleDashboardProviderReceiptHash: 'bad-provider-receipt',
          productionClaimLiftRoleDashboardProviderSummaryHash: 'bad-provider-summary',
          productionClaimLiftRoleDashboardProviderTrustStateViewHash: 'bad-provider-view',
          productionClaimLiftRoleDashboardReadinessReceiptHash: 'bad-readiness-receipt',
          productionClaimLiftRoleDashboardReadinessSummaryHash: 'bad-readiness-summary',
          productionClaimLiftRoleDashboardReadinessTrustStateViewHash: 'bad-readiness-view',
          productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: 'bad-runtime-provider-receipt',
          productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: 'bad-runtime-provider-summary',
          productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: 'bad-runtime-provider-view',
          productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: 'bad-runtime-readiness-receipt',
          productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: 'bad-runtime-readiness-summary',
          productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: 'bad-runtime-readiness-view',
          productionClaimLiftRoleDashboardRoles: DASHBOARD_ROLES.filter((role) => role !== 'sponsor_viewer').concat(
            'unsupported_role',
          ),
          metadataOnly: false,
          protectedContentExcluded: false,
          reviewedAtHlc: { physicalMs: 1800004300000, logical: 1 },
        }),
      },
    }),
  );
  const mismatch = evaluateRuntimeConfigurationSource(
    runtimeConfigurationInput({
      deploymentHandoffCutover: {
        deploymentProviderBindingRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence({
          productionClaimLiftRoleDashboardProviderReceiptHash: DIGEST_4,
          productionClaimLiftRoleDashboardProviderSummaryHash: DIGEST_5,
          productionClaimLiftRoleDashboardProviderTrustStateViewHash: DIGEST_6,
          productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_D,
          productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
          productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_5,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_1,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_2,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_7,
        }),
      },
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.runtimeConfiguration, null);
  assert.ok(missing.reasons.includes('deployment_handoff_cutover_absent'));
  assert.ok(missing.reasons.includes('deployment_handoff_readiness_role_dashboard_trust_state_evidence_absent'));
  assert.ok(missing.reasons.includes('deployment_handoff_provider_binding_role_dashboard_trust_state_evidence_absent'));

  assert.equal(unsafe.decision, 'denied');
  assert.equal(unsafe.runtimeConfiguration, null);
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_receipt_type_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_status_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_release_candidate_mismatch'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_manifest_receipt_mismatch'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_operations_hash_mismatch'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_provider_receipt_mismatch'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_baseline_not_ready'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_readiness_role_dashboard_trust_state_evidence_absent'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_schema_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_summary_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_trust_state_view_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_role_missing:sponsor_viewer'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_hash_ref_role_unsupported:unapproved_role'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_hash_ref_missing:auditor'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_production_claim_display_forbidden'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_activation_lineage_absent'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_public_claim_review_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_public_claim_review_package_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_production_claim_lift_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_production_claim_lift_state_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_production_claim_lift_forbidden'));
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_provider_receipt_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_provider_summary_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_provider_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_readiness_receipt_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_readiness_summary_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_readiness_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_provider_receipt_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_provider_summary_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_provider_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_readiness_receipt_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_readiness_summary_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_readiness_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_role_missing:sponsor_viewer',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_role_unsupported:unsupported_role',
    ),
  );
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_provider_binding_role_dashboard_after_handoff_review'));

  assert.equal(mismatch.decision, 'denied');
  assert.equal(mismatch.runtimeConfiguration, null);
  assert.ok(
    mismatch.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_provider_receipt_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_provider_summary_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_provider_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_provider_receipt_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_provider_summary_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_provider_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_readiness_receipt_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_readiness_summary_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_readiness_trust_state_view_mismatch',
    ),
  );
});

test('runtime configuration source can verify production configuration without lifting production trust claims', async () => {
  const { evaluateRuntimeConfigurationSource } = await loadRuntimeConfigurationSource();

  const verified = evaluateRuntimeConfigurationSource(
    runtimeConfigurationInput({
      configurationDomains: REQUIRED_CONFIGURATION_DOMAINS.map((domain, index) =>
        configurationDomain(domain, index, {
          status: 'ready',
          activationBlockerId: null,
          productionActivationOnly: false,
        }),
      ),
      adapterBindings: REQUIRED_ADAPTERS.map((kind, index) =>
        adapterBinding(kind, index, {
          status: 'verified',
          endpointHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D][index],
          credentialScopeRef: `cm-${kind}-credential-scope`,
          credentialScopeHash: [DIGEST_E, DIGEST_F, DIGEST_8, DIGEST_9][index],
          activationBlockerId: null,
        }),
      ),
      secretScope: {
        secretManagerRef: 'cybermedica-secret-manager-alpha',
        secretManagerHash: DIGEST_8,
        status: 'verified',
        activationBlockerId: null,
        rotationOwnerDid: 'did:exo:secret-rotation-owner-alpha',
        rotationPolicyHash: DIGEST_9,
      },
      humanReview: {
        decision: 'configuration_ready',
      },
    }),
  );

  assert.equal(verified.decision, 'permitted');
  assert.deepEqual(verified.runtimeConfiguration.activationBlockerIds, []);
  assert.equal(verified.runtimeConfiguration.productionConfigurationReady, true);
  assert.equal(verified.runtimeConfiguration.exochainProductionClaim, false);
  assert.equal(verified.trustState, 'inactive');
});

test('runtime configuration source fails closed for missing domains unsupported adapters and unsafe claims', async () => {
  const { evaluateRuntimeConfigurationSource } = await loadRuntimeConfigurationSource();

  const result = evaluateRuntimeConfigurationSource(
    runtimeConfigurationInput({
      configurationCycle: {
        productionTrustClaim: true,
      },
      runtimeConfiguration: {
        browserAuthoritativePathEnabled: true,
        selectedTopology: 'browser_wasm_authoritative',
      },
      configurationDomains: configurationDomains().filter((entry) => entry.domain !== 'secret_scope'),
      adapterBindings: [...adapterBindings(), adapterBinding('commandbase', 0)],
      secretScope: {
        sharedWithExochainRoot: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.runtimeConfiguration, null);
  assert.ok(result.reasons.includes('configuration_domain_missing:secret_scope'));
  assert.ok(result.reasons.includes('adapter_kind_unsupported:commandbase'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('browser_authoritative_path_forbidden'));
  assert.ok(result.reasons.includes('server_side_topology_required'));
  assert.ok(result.reasons.includes('secret_scope_shared_with_exochain_root'));
});

test('runtime configuration source validates HLC ordering and AI advisory boundaries', async () => {
  const { evaluateRuntimeConfigurationSource } = await loadRuntimeConfigurationSource();

  const sameTick = evaluateRuntimeConfigurationSource(
    runtimeConfigurationInput({
      configurationCycle: {
        humanReviewedAtHlc: { physicalMs: 1800004400000, logical: 2 },
        auditRecordedAtHlc: { physicalMs: 1800004400000, logical: 3 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800004400000, logical: 2 },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1800004400000, logical: 3 },
      },
    }),
  );

  assert.equal(sameTick.decision, 'permitted');

  const invalid = evaluateRuntimeConfigurationSource(
    runtimeConfigurationInput({
      configurationCycle: {
        validationRecordedAtHlc: { physicalMs: 1800004190000, logical: 0 },
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1800004300000, logical: -1 },
      },
      aiAssistance: {
        finalAuthority: true,
        reviewedByHuman: false,
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
    }),
  );

  assert.equal(invalid.decision, 'denied');
  assert.ok(invalid.reasons.includes('configuration_cycle_validationRecordedAtHlc_before_evidenceCollectedAtHlc'));
  assert.ok(invalid.reasons.includes('validation_time_invalid'));
  assert.ok(invalid.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(invalid.reasons.includes('ai_human_review_absent'));
  assert.ok(invalid.reasons.includes('human_review_authority_absent'));
});

test('runtime configuration source rejects raw config protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateRuntimeConfigurationSource } = await loadRuntimeConfigurationSource();

  const inert = runtimeConfigurationInput({
    secretScope: {
      apiKey: {},
    },
  });

  assert.equal(evaluateRuntimeConfigurationSource(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateRuntimeConfigurationSource(
        runtimeConfigurationInput({
          runtimeConfiguration: {
            rawRuntimeConfig: ['unredacted runtime configuration stays external'],
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRuntimeConfigurationSource(
        runtimeConfigurationInput({
          validationEvidence: {
            rawValidationOutput: 'Participant Alice Example must not appear in runtime configuration evidence.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRuntimeConfigurationSource(
        runtimeConfigurationInput({
          secretScope: {
            apiKey: 7,
          },
        }),
      ),
    ProtectedContentError,
  );
});
