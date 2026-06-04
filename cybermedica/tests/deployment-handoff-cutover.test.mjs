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

const REQUIRED_HANDOFF_DOMAINS = [
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
];

const ALLOWED_CUTOVER_BLOCKERS = [
  'ESC-OPS-SECRETS',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-RUNTIME',
  'PTAG-001',
  'PTAG-016',
  'PTAG-017',
];

const REQUIRED_DRIFT_STATE_TARGETS = ['passport', 'quality_state', 'readiness'];
const REQUIRED_OBJECT_STORAGE_ARTIFACT_CLASSES = [
  'controlled_documents',
  'diligence_exports',
  'evidence_payloads',
  'generated_reports',
  'sensitive_artifacts',
];
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

async function loadDeploymentHandoffCutover() {
  try {
    return await import('../src/deployment-handoff-cutover.mjs');
  } catch (error) {
    assert.fail(`CyberMedica deployment handoff cutover module must exist and load: ${error.message}`);
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

function handoffDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4];
  const blocked = ['provider_binding', 'runtime_configuration', 'trust_claim_freeze'].includes(domain);
  return {
    domain,
    status: blocked ? 'activation_blocked' : 'ready',
    evidenceRef: `handoff-evidence-${domain}`,
    evidenceHash: hashes[index],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner`,
    backupOwnerDid: `did:exo:${domain.replaceAll('_', '-')}-backup`,
    activationBlockerId: blocked ? (domain === 'trust_claim_freeze' ? 'PTAG-001' : 'ESC-RUNTIME') : null,
    blocksBaselineDevelopment: false,
    productionActivationOnly: blocked,
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800004100000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function handoffDomains() {
  return REQUIRED_HANDOFF_DOMAINS.map((domain, index) => handoffDomain(domain, index));
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
      reviewedAtHlc: { physicalMs: 1800004050000, logical: 0 },
    },
    overrides,
  );
}

function roleDashboardTrustStateEvidence(overrides = {}) {
  return mergeDeep(
    {
      schema: 'cybermedica.role_dashboard_trust_state_lineage.v1',
      roleDashboardSummaryHash: DIGEST_A,
      roleDashboardReceiptHash: DIGEST_B,
      roleDashboardTrustStateViewHash: DIGEST_C,
      dashboardRoles: DASHBOARD_ROLES,
      dashboardHashRefs: DASHBOARD_ROLES.map((role, index) => ({
        role,
        dashboardHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_7, DIGEST_8][index],
        trustStateViewHash: [DIGEST_8, DIGEST_7, DIGEST_6, DIGEST_5, DIGEST_4, DIGEST_3, DIGEST_2, DIGEST_1][index],
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
      reviewedAtHlc: { physicalMs: 1800004050000, logical: 1 },
    },
    overrides,
  );
}

function databaseMigrationReadinessEvidence(overrides = {}) {
  return mergeDeep(
    {
      schema: 'cybermedica.database_migration_readiness.v1',
      migrationReadinessHash: DIGEST_9,
      migrationReadinessReceiptHash: DIGEST_6,
      receiptArtifactType: 'database_migration_readiness',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      trustState: 'inactive',
      baselineMigrationReady: true,
      productionActivationReady: false,
      exochainProductionClaim: false,
      mutableOperationalStateSeparated: true,
      exochainReceiptStoreExternal: true,
      evidencePayloadStoredOutsideDb: true,
      objectStorageReadinessReceiptHash: DIGEST_1,
      objectStorageReadinessHash: DIGEST_2,
      objectStorageBoundaryHash: DIGEST_1,
      objectStorageProviderRef: 'encrypted-object-storage-provider-alpha',
      objectStorageArtifactClassesCovered: REQUIRED_OBJECT_STORAGE_ARTIFACT_CLASSES,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800004100000, logical: 9 },
    },
    overrides,
  );
}

function handoffInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:deployment-owner-alpha',
      kind: 'human',
      roleRefs: ['deployment_owner', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['deployment_handoff_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    handoffPolicy: {
      policyRef: 'deployment-handoff-cutover-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredHandoffDomains: REQUIRED_HANDOFF_DOMAINS,
      allowedCutoverBlockerIds: ALLOWED_CUTOVER_BLOCKERS,
      rootVerificationRequiredForTrustClaims: true,
      noCredentialDisclosure: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800003900000, logical: 0 },
    },
    handoffCycle: {
      handoffRef: 'deployment-handoff-cutover-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800003950000, logical: 0 },
      evidenceCollectedAtHlc: { physicalMs: 1800004100000, logical: 10 },
      validationRecordedAtHlc: { physicalMs: 1800004200000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800004300000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800004400000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    handoffDomains: handoffDomains(),
    runtimeConfiguration: {
      configurationRef: 'runtime-config-baseline-alpha',
      configurationHash: DIGEST_C,
      configurationSource: 'railway_env_and_secret_manager',
      environmentManifestHash: DIGEST_D,
      secretScopeHash: DIGEST_E,
      trustFeatureFlagHash: DIGEST_F,
      trustClaimsDisabled: true,
      rootBundleProviderConfigured: false,
      adapterEndpointConfigured: false,
      browserAuthoritativePathEnabled: false,
      missingSecretsFailClosed: true,
      processHealthSeparatedFromTrustReadiness: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800004100000, logical: 8 },
    },
    runtimeConfigurationSource: {
      runtimeConfigurationSourceId: 'runtime-configuration-source-alpha',
      runtimeConfigurationHash: DIGEST_E,
      receiptHash: DIGEST_F,
      receiptArtifactType: 'runtime_configuration_source',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      trustState: 'inactive',
      baselineConfigurationReady: true,
      productionConfigurationReady: false,
      productionTrustClaim: false,
      configurationHash: DIGEST_C,
      secretScopeHash: DIGEST_E,
      trustFeatureFlagHash: DIGEST_F,
      deploymentReadinessManifestReceiptHash: DIGEST_2,
      deploymentOperationsReadinessHash: DIGEST_3,
      deploymentProviderBindingReceiptHash: DIGEST_3,
      activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-ROOT-DEPLOYMENT'],
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800004100000, logical: 9 },
    },
    databaseMigrationReadinessEvidence: databaseMigrationReadinessEvidence(),
    handoffArtifacts: {
      deploymentReadinessManifestHash: DIGEST_1,
      deploymentReadinessManifestReceiptHash: DIGEST_2,
      deploymentReadinessManifestReceiptArtifactType: 'deployment_readiness_manifest',
      deploymentReadinessManifestStatus: 'deployment_readiness_manifest_accepted_inactive_trust',
      deploymentReadinessManifestReleaseCandidateRef: 'cybermedica-baseline-2026-05',
      deploymentReadinessManifestTrustState: 'inactive',
      deploymentReadinessManifestBaselineReady: true,
      deploymentReadinessManifestProductionClaim: false,
      deploymentReadinessDriftStateUpdateEvidence: deploymentReadinessDriftStateUpdateEvidence(),
      deploymentReadinessRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
      deploymentProviderBindingHash: DIGEST_2,
      deploymentProviderBindingReceiptHash: DIGEST_3,
      deploymentProviderBindingReceiptArtifactType: 'deployment_provider_binding',
      deploymentProviderBindingStatus: 'deployment_provider_binding_accepted_inactive_trust',
      deploymentProviderBindingReleaseCandidateRef: 'cybermedica-baseline-2026-05',
      deploymentProviderBindingTrustState: 'inactive',
      deploymentProviderBindingBaselineReady: true,
      deploymentProviderBindingProductionClaim: false,
      deploymentProviderBindingRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
      deploymentOperationsReadinessHash: DIGEST_3,
      releaseReadinessMatrixHash: DIGEST_4,
      releaseIncidentLinkageHash: DIGEST_8,
      releaseIncidentLinkageReceiptHash: DIGEST_9,
      requirementTraceabilityHash: DIGEST_5,
      pathClassificationHash: DIGEST_6,
      activationGateRegisterHash: DIGEST_7,
      validationEvidenceHash: DIGEST_8,
      metadataOnly: true,
      linkedAtHlc: { physicalMs: 1800004100000, logical: 9 },
    },
    cutoverPlan: {
      migrationPlanHash: DIGEST_9,
      backupSnapshotHash: DIGEST_A,
      rollbackPlanHash: DIGEST_B,
      disablementPlanHash: DIGEST_C,
      smokeTestPlanHash: DIGEST_D,
      preCutoverChecklistHash: DIGEST_E,
      postCutoverObservationWindowHash: DIGEST_F,
      cutoverOwnerDid: 'did:exo:deployment-owner-alpha',
      backupOwnerDid: 'did:exo:deployment-backup-alpha',
      rollbackAuthorityDid: 'did:exo:rollback-owner-alpha',
      cutoverWindowApproved: false,
      productionEndpointSelected: false,
      activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-ROOT-DEPLOYMENT', 'ESC-ROOT-OWNER', 'ESC-RUNTIME', 'PTAG-001'],
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800004100000, logical: 10 },
    },
    validationEvidence: {
      commandRefs: ['npm run quality', 'railway status --json', 'secret scan'],
      commandsPassed: true,
      testCount: 332,
      coverageLineBasisPoints: 9974,
      sourceGuardPassed: true,
      dependencyAuditPassed: true,
      secretScanPassed: true,
      noExochainSourceModified: true,
      metadataOnly: true,
      recordedAtHlc: { physicalMs: 1800004200000, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'handoff_ready_inactive_trust',
      decisionHash: DIGEST_1,
      noProductionTrustClaim: true,
      activationBlockersAccepted: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800004300000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'deployment-handoff-cutover-audit-alpha',
      auditRecordHash: DIGEST_2,
      receiptRecordedAtHlc: { physicalMs: 1800004400000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_3,
      limitationHashes: [DIGEST_4],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_5,
  };
  return mergeDeep(base, overrides);
}

test('deployment handoff cutover records inactive production handoff with explicit blockers', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const resultA = evaluateDeploymentHandoffCutover(handoffInput());
  const resultB = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffPolicy: {
        requiredHandoffDomains: [...REQUIRED_HANDOFF_DOMAINS].reverse(),
        allowedCutoverBlockerIds: [...ALLOWED_CUTOVER_BLOCKERS].reverse(),
      },
      handoffDomains: [...handoffDomains()].reverse(),
      cutoverPlan: {
        activationBlockerIds: ['PTAG-001', 'ESC-RUNTIME', 'ESC-ROOT-OWNER', 'ESC-ROOT-DEPLOYMENT', 'ESC-OPS-SECRETS'],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.handoff.trustState, 'inactive');
  assert.equal(resultA.handoff.exochainProductionClaim, false);
  assert.equal(resultA.handoff.baselineHandoffReady, true);
  assert.equal(resultA.handoff.productionCutoverReady, false);
  assert.deepEqual(resultA.handoff.handoffDomainsCovered, REQUIRED_HANDOFF_DOMAINS);
  assert.deepEqual(resultA.handoff.cutoverBlockerIds, [
    'ESC-OPS-SECRETS',
    'ESC-ROOT-DEPLOYMENT',
    'ESC-ROOT-OWNER',
    'ESC-RUNTIME',
    'PTAG-001',
  ]);
  assert.equal(resultA.handoff.runtimeConfiguration.trustClaimsDisabled, true);
  assert.equal(resultA.handoff.runtimeConfiguration.rootBundleProviderConfigured, false);
  assert.equal(resultA.handoff.runtimeConfigurationSource.receiptHash, DIGEST_F);
  assert.equal(resultA.handoff.runtimeConfigurationSource.runtimeConfigurationHash, DIGEST_E);
  assert.equal(resultA.handoff.runtimeConfigurationSource.configurationHash, DIGEST_C);
  assert.deepEqual(resultA.handoff.runtimeConfigurationSource.activationBlockerIds, [
    'ESC-OPS-SECRETS',
    'ESC-ROOT-DEPLOYMENT',
  ]);
  assert.equal(resultA.handoff.databaseMigrationReadiness.migrationReadinessHash, DIGEST_9);
  assert.equal(resultA.handoff.databaseMigrationReadiness.migrationReadinessReceiptHash, DIGEST_6);
  assert.equal(resultA.handoff.databaseMigrationReadiness.objectStorageReadinessReceiptHash, DIGEST_1);
  assert.equal(resultA.handoff.databaseMigrationReadiness.objectStorageReadinessHash, DIGEST_2);
  assert.equal(resultA.handoff.databaseMigrationReadiness.objectStorageBoundaryHash, DIGEST_1);
  assert.equal(
    resultA.handoff.databaseMigrationReadiness.objectStorageProviderRef,
    'encrypted-object-storage-provider-alpha',
  );
  assert.deepEqual(
    resultA.handoff.databaseMigrationReadiness.objectStorageArtifactClassesCovered,
    REQUIRED_OBJECT_STORAGE_ARTIFACT_CLASSES,
  );
  assert.equal(resultA.handoff.handoffArtifacts.deploymentReadinessManifestReceiptHash, DIGEST_2);
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentReadinessManifestStatus,
    'deployment_readiness_manifest_accepted_inactive_trust',
  );
  assert.equal(resultA.handoff.handoffArtifacts.deploymentReadinessManifestTrustState, 'inactive');
  assert.equal(resultA.handoff.handoffArtifacts.deploymentReadinessManifestBaselineReady, true);
  assert.equal(resultA.handoff.handoffArtifacts.deploymentReadinessManifestProductionClaim, false);
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentReadinessDriftStateUpdateEvidence.driftLoopReceiptHash,
    DIGEST_5,
  );
  assert.equal(resultA.handoff.handoffArtifacts.deploymentReadinessDriftStateUpdateEvidence.stateUpdateHash, DIGEST_6);
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentReadinessDriftStateUpdateEvidence.cqiCycleReceiptHash,
    DIGEST_8,
  );
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentReadinessDriftStateUpdateEvidence.inquiryCqiBacklogReceiptHash,
    DIGEST_9,
  );
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentReadinessDriftStateUpdateEvidence.roleManualCoverageReceiptHash,
    DIGEST_F,
  );
  assert.deepEqual(
    resultA.handoff.handoffArtifacts.deploymentReadinessDriftStateUpdateEvidence.stateUpdateTargets,
    REQUIRED_DRIFT_STATE_TARGETS,
  );
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentReadinessRoleDashboardTrustStateEvidence.roleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentReadinessRoleDashboardTrustStateEvidence
      .productionClaimLiftRoleDashboardProviderTrustStateViewHash,
    DIGEST_C,
  );
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentReadinessRoleDashboardTrustStateEvidence
      .productionClaimLiftRoleDashboardReadinessTrustStateViewHash,
    DIGEST_D,
  );
  assert.deepEqual(
    resultA.handoff.handoffArtifacts.deploymentReadinessRoleDashboardTrustStateEvidence
      .productionClaimLiftRoleDashboardRoles,
    DASHBOARD_ROLES,
  );
  assert.deepEqual(
    resultA.handoff.handoffArtifacts.deploymentProviderBindingRoleDashboardTrustStateEvidence.dashboardRoles,
    DASHBOARD_ROLES,
  );
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentProviderBindingRoleDashboardTrustStateEvidence.publicClaimReviewReceiptHash,
    DIGEST_1,
  );
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentProviderBindingRoleDashboardTrustStateEvidence.productionClaimLiftTrustState,
    'inactive',
  );
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentProviderBindingRoleDashboardTrustStateEvidence
      .productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentProviderBindingRoleDashboardTrustStateEvidence
      .productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    DIGEST_C,
  );
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentProviderBindingRoleDashboardTrustStateEvidence
      .productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    DIGEST_F,
  );
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentProviderBindingRoleDashboardTrustStateEvidence
      .productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    DIGEST_D,
  );
  assert.equal(resultA.handoff.handoffArtifacts.deploymentProviderBindingReceiptHash, DIGEST_3);
  assert.equal(
    resultA.handoff.handoffArtifacts.deploymentProviderBindingStatus,
    'deployment_provider_binding_accepted_inactive_trust',
  );
  assert.equal(resultA.handoff.handoffArtifacts.deploymentProviderBindingTrustState, 'inactive');
  assert.equal(resultA.handoff.handoffArtifacts.deploymentProviderBindingBaselineReady, true);
  assert.equal(resultA.handoff.handoffArtifacts.deploymentProviderBindingProductionClaim, false);
  assert.equal(resultA.handoff.handoffArtifacts.releaseIncidentLinkageHash, DIGEST_8);
  assert.equal(resultA.handoff.handoffArtifacts.releaseIncidentLinkageReceiptHash, DIGEST_9);
  assert.equal(resultA.handoff.cutoverPlan.cutoverWindowApproved, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'deployment_handoff_cutover');
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('runtime_configuration_source'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('deployment_readiness_manifest'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('drift_state_update'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('continuous_quality_improvement'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('manual_navigation_readiness'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('role_dashboard_trust_state'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('database_migration_readiness'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('object_storage_readiness_lineage'));
  assert.deepEqual(resultA, resultB);
});

test('deployment handoff cutover requires database migration readiness object-storage lineage before packaging', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const missing = evaluateDeploymentHandoffCutover(
    handoffInput({
      databaseMigrationReadinessEvidence: null,
    }),
  );
  const unsafe = evaluateDeploymentHandoffCutover(
    handoffInput({
      databaseMigrationReadinessEvidence: databaseMigrationReadinessEvidence({
        schema: 'cybermedica.database_migration_summary.v1',
        migrationReadinessHash: DIGEST_8,
        migrationReadinessReceiptHash: 'not-a-digest',
        receiptArtifactType: 'database_migration_summary',
        releaseCandidateRef: 'different-release',
        trustState: 'verified',
        baselineMigrationReady: false,
        productionActivationReady: true,
        exochainProductionClaim: true,
        mutableOperationalStateSeparated: false,
        exochainReceiptStoreExternal: false,
        evidencePayloadStoredOutsideDb: false,
        objectStorageReadinessReceiptHash: null,
        objectStorageReadinessHash: 'bad-readiness-hash',
        objectStorageBoundaryHash: 'bad-boundary-hash',
        objectStorageProviderRef: '',
        objectStorageArtifactClassesCovered: ['evidence_payloads', 'unsupported_artifact_class'],
        metadataOnly: false,
        protectedContentExcluded: false,
        reviewedAtHlc: { physicalMs: 1800004250000, logical: 0 },
      }),
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.failClosed, true);
  assert.equal(missing.handoff, null);
  assert.ok(missing.reasons.includes('database_migration_readiness_evidence_absent'));
  assert.ok(missing.reasons.includes('database_migration_readiness_hash_invalid'));
  assert.ok(missing.reasons.includes('database_migration_readiness_receipt_hash_invalid'));
  assert.ok(missing.reasons.includes('database_migration_object_storage_readiness_receipt_hash_invalid'));

  assert.equal(unsafe.decision, 'denied');
  assert.equal(unsafe.failClosed, true);
  assert.equal(unsafe.handoff, null);
  assert.ok(unsafe.reasons.includes('database_migration_readiness_schema_invalid'));
  assert.ok(unsafe.reasons.includes('database_migration_readiness_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('database_migration_readiness_receipt_type_invalid'));
  assert.ok(unsafe.reasons.includes('database_migration_readiness_release_candidate_mismatch'));
  assert.ok(unsafe.reasons.includes('database_migration_readiness_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('database_migration_readiness_baseline_not_ready'));
  assert.ok(unsafe.reasons.includes('database_migration_production_activation_forbidden'));
  assert.ok(unsafe.reasons.includes('database_migration_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('database_migration_mutable_state_separation_absent'));
  assert.ok(unsafe.reasons.includes('database_migration_exochain_receipt_store_external_absent'));
  assert.ok(unsafe.reasons.includes('database_migration_evidence_payload_outside_db_absent'));
  assert.ok(unsafe.reasons.includes('database_migration_plan_hash_mismatch'));
  assert.ok(unsafe.reasons.includes('database_migration_object_storage_readiness_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('database_migration_object_storage_readiness_hash_invalid'));
  assert.ok(unsafe.reasons.includes('database_migration_object_storage_boundary_hash_invalid'));
  assert.ok(unsafe.reasons.includes('database_migration_object_storage_provider_ref_absent'));
  assert.ok(unsafe.reasons.includes('database_migration_object_storage_artifact_class_missing:controlled_documents'));
  assert.ok(unsafe.reasons.includes('database_migration_object_storage_artifact_class_unsupported:unsupported_artifact_class'));
  assert.ok(unsafe.reasons.includes('database_migration_readiness_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('database_migration_readiness_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('database_migration_readiness_after_handoff_validation'));
});

test('deployment handoff cutover requires accepted runtime configuration source lineage', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const missing = evaluateDeploymentHandoffCutover(
    handoffInput({
      runtimeConfigurationSource: null,
    }),
  );
  const unsafe = evaluateDeploymentHandoffCutover(
    handoffInput({
      runtimeConfigurationSource: {
        runtimeConfigurationHash: null,
        receiptHash: 'not-a-digest',
        receiptArtifactType: 'configuration_summary',
        releaseCandidateRef: 'different-release',
        trustState: 'active',
        baselineConfigurationReady: false,
        productionTrustClaim: true,
        configurationHash: DIGEST_D,
        secretScopeHash: DIGEST_D,
        trustFeatureFlagHash: DIGEST_D,
        deploymentReadinessManifestReceiptHash: DIGEST_A,
        deploymentOperationsReadinessHash: DIGEST_A,
        deploymentProviderBindingReceiptHash: DIGEST_A,
        activationBlockerIds: ['ESC-UNBOUNDED-RUNTIME'],
        metadataOnly: false,
        protectedContentExcluded: false,
        reviewedAtHlc: { physicalMs: 1800004250000, logical: 0 },
      },
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.failClosed, true);
  assert.equal(missing.handoff, null);
  assert.ok(missing.reasons.includes('runtime_configuration_source_lineage_absent'));
  assert.ok(missing.reasons.includes('runtime_configuration_source_hash_invalid'));
  assert.ok(missing.reasons.includes('runtime_configuration_source_receipt_hash_invalid'));

  assert.equal(unsafe.decision, 'denied');
  assert.equal(unsafe.failClosed, true);
  assert.equal(unsafe.handoff, null);
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_hash_invalid'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_receipt_type_invalid'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_release_candidate_mismatch'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_baseline_not_ready'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_configuration_hash_mismatch'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_secret_scope_hash_mismatch'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_trust_feature_flag_hash_mismatch'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_manifest_receipt_mismatch'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_operations_hash_mismatch'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_provider_receipt_mismatch'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_blocker_not_allowed:ESC-UNBOUNDED-RUNTIME'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_after_validation'));
});

test('deployment handoff cutover requires deployment readiness manifest Drift lineage before cutover packaging', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const missing = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffArtifacts: {
        deploymentReadinessManifestReceiptHash: null,
        deploymentReadinessManifestReceiptArtifactType: 'manifest_summary',
        deploymentReadinessManifestStatus: 'deployment_readiness_manifest_pending',
        deploymentReadinessManifestReleaseCandidateRef: 'different-release',
        deploymentReadinessManifestTrustState: 'verified',
        deploymentReadinessManifestBaselineReady: false,
        deploymentReadinessManifestProductionClaim: true,
        deploymentReadinessDriftStateUpdateEvidence: null,
      },
    }),
  );
  const unsafe = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffArtifacts: {
        deploymentReadinessDriftStateUpdateEvidence: deploymentReadinessDriftStateUpdateEvidence({
          driftLoopReceiptHash: 'not-a-digest',
          stateUpdateHash: null,
          stateUpdateTargets: ['readiness', 'unsupported_target'],
          cqiCycleReceiptHash: 'bad',
          inquiryCqiBacklogReceiptHash: null,
          manualNavigationReady: false,
          manualNavigationEffectiveUseAcknowledged: false,
          roleManualCoverageReceiptHash: 'bad',
          trustState: 'verified',
          exochainProductionClaim: true,
          metadataOnly: false,
          protectedContentExcluded: false,
          reviewedAtHlc: { physicalMs: 1800004150000, logical: 0 },
        }),
      },
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.failClosed, true);
  assert.equal(missing.handoff, null);
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_receipt_hash_invalid'));
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_receipt_type_invalid'));
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_status_invalid'));
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_release_candidate_mismatch'));
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_trust_state_invalid'));
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_baseline_not_ready'));
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_production_claim_forbidden'));
  assert.ok(missing.reasons.includes('deployment_readiness_drift_state_update_absent'));
  assert.ok(missing.reasons.includes('deployment_readiness_drift_loop_receipt_hash_invalid'));
  assert.ok(missing.reasons.includes('deployment_readiness_drift_state_update_hash_invalid'));

  assert.equal(unsafe.decision, 'denied');
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_loop_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_state_update_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_cqi_cycle_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_inquiry_cqi_backlog_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_manual_navigation_ready_absent'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_manual_navigation_effective_use_absent'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_role_manual_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_state_update_target_missing:passport'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_state_update_target_missing:quality_state'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_state_update_target_unsupported:unsupported_target'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_state_update_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_state_update_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_state_update_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_state_update_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_state_update_after_manifest_linkage'));
});

test('deployment handoff cutover requires deployment readiness and provider binding role-dashboard trust-state lineage', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const missing = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffArtifacts: {
        deploymentReadinessRoleDashboardTrustStateEvidence: null,
        deploymentProviderBindingRoleDashboardTrustStateEvidence: null,
      },
    }),
  );
  const unsafe = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffArtifacts: {
        deploymentReadinessRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence({
          dashboardRoles: DASHBOARD_ROLES.filter((role) => role !== 'sponsor_viewer'),
          dashboardHashRefs: [
            {
              role: 'unapproved_role',
              dashboardHash: 'not-a-digest',
              trustStateViewHash: null,
            },
          ],
          roleDashboardReceiptHash: 'not-a-digest',
          roleDashboardTrustStateViewHash: null,
          trustState: 'active',
          exochainProductionClaim: true,
          canShowProductionTrustClaim: true,
          activationLineageAccepted: false,
          publicClaimReviewReceiptHash: null,
          publicClaimReviewPackageHash: 'bad',
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
          productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: 'bad-runtime-source-provider-view',
          productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: 'bad-runtime-readiness-receipt',
          productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: 'bad-runtime-readiness-summary',
          productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: 'bad-runtime-source-readiness-view',
          productionClaimLiftRoleDashboardRoles: DASHBOARD_ROLES.filter((role) => role !== 'sponsor_viewer').concat(
            'unsupported_role',
          ),
          metadataOnly: false,
          protectedContentExcluded: false,
          reviewedAtHlc: { physicalMs: 1800004150000, logical: 0 },
        }),
        deploymentProviderBindingRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence({
          schema: 'unsafe.provider.role_dashboard.v1',
          roleDashboardSummaryHash: null,
          reviewedAtHlc: { physicalMs: 1800004250000, logical: 0 },
        }),
      },
    }),
  );
  const mismatch = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffArtifacts: {
        deploymentProviderBindingRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence({
          productionClaimLiftRoleDashboardProviderReceiptHash: DIGEST_4,
          productionClaimLiftRoleDashboardProviderSummaryHash: DIGEST_5,
          productionClaimLiftRoleDashboardProviderTrustStateViewHash: DIGEST_6,
          productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_D,
          productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
          productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_7,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_1,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_2,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_8,
        }),
      },
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.failClosed, true);
  assert.equal(missing.handoff, null);
  assert.ok(missing.reasons.includes('deployment_readiness_role_dashboard_trust_state_evidence_absent'));
  assert.ok(missing.reasons.includes('deployment_readiness_role_dashboard_summary_hash_invalid'));
  assert.ok(missing.reasons.includes('deployment_provider_binding_role_dashboard_trust_state_evidence_absent'));
  assert.ok(missing.reasons.includes('deployment_provider_binding_role_dashboard_summary_hash_invalid'));

  assert.equal(unsafe.decision, 'denied');
  assert.equal(unsafe.failClosed, true);
  assert.equal(unsafe.handoff, null);
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_trust_state_view_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_role_missing:sponsor_viewer'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_hash_ref_role_unsupported:unapproved_role'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_hash_ref_missing:auditor'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_display_forbidden'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_activation_lineage_absent'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_public_claim_review_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_public_claim_review_package_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_state_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_forbidden'));
  assert.ok(
    unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_provider_receipt_hash_invalid'),
  );
  assert.ok(
    unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_provider_summary_hash_invalid'),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_provider_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_readiness_receipt_hash_invalid'),
  );
  assert.ok(
    unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_readiness_summary_hash_invalid'),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_readiness_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_provider_receipt_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_provider_summary_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_provider_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_receipt_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_summary_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_role_missing:sponsor_viewer'),
  );
  assert.ok(
    unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_role_unsupported:unsupported_role'),
  );
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_after_artifact_linkage'));
  assert.ok(unsafe.reasons.includes('deployment_provider_binding_role_dashboard_schema_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_provider_binding_role_dashboard_summary_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_provider_binding_role_dashboard_after_artifact_linkage'));

  assert.equal(mismatch.decision, 'denied');
  assert.equal(mismatch.failClosed, true);
  assert.equal(mismatch.handoff, null);
  assert.ok(
    mismatch.reasons.includes('deployment_provider_binding_role_dashboard_production_claim_lift_provider_receipt_mismatch'),
  );
  assert.ok(
    mismatch.reasons.includes('deployment_provider_binding_role_dashboard_production_claim_lift_provider_summary_mismatch'),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_provider_binding_role_dashboard_production_claim_lift_provider_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_provider_binding_role_dashboard_production_claim_lift_runtime_source_provider_receipt_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_provider_binding_role_dashboard_production_claim_lift_runtime_source_provider_summary_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_provider_binding_role_dashboard_production_claim_lift_runtime_source_provider_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_provider_binding_role_dashboard_production_claim_lift_runtime_source_readiness_receipt_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_provider_binding_role_dashboard_production_claim_lift_runtime_source_readiness_summary_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_provider_binding_role_dashboard_production_claim_lift_runtime_source_readiness_trust_state_view_mismatch',
    ),
  );
});

test('deployment handoff cutover requires release incident linkage evidence before cutover packaging', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const result = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffArtifacts: {
        releaseIncidentLinkageHash: null,
        releaseIncidentLinkageReceiptHash: 'not-a-digest',
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.handoff, null);
  assert.ok(result.reasons.includes('release_incident_linkage_hash_invalid'));
  assert.ok(result.reasons.includes('release_incident_linkage_receipt_hash_invalid'));
});

test('deployment handoff cutover requires accepted provider binding receipt before cutover packaging', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const result = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffArtifacts: {
        deploymentProviderBindingReceiptHash: 'not-a-digest',
        deploymentProviderBindingReceiptArtifactType: 'provider_summary',
        deploymentProviderBindingStatus: 'deployment_provider_binding_pending',
        deploymentProviderBindingReleaseCandidateRef: 'different-release',
        deploymentProviderBindingTrustState: 'active',
        deploymentProviderBindingBaselineReady: false,
        deploymentProviderBindingProductionClaim: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.handoff, null);
  assert.ok(result.reasons.includes('deployment_provider_binding_receipt_hash_invalid'));
  assert.ok(result.reasons.includes('deployment_provider_binding_receipt_type_invalid'));
  assert.ok(result.reasons.includes('deployment_provider_binding_status_invalid'));
  assert.ok(result.reasons.includes('deployment_provider_binding_release_candidate_mismatch'));
  assert.ok(result.reasons.includes('deployment_provider_binding_trust_state_invalid'));
  assert.ok(result.reasons.includes('deployment_provider_binding_baseline_not_ready'));
  assert.ok(result.reasons.includes('deployment_provider_binding_production_claim_forbidden'));
});

test('deployment handoff cutover can mark cutover ready only when runtime and blockers verify', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const ready = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffDomains: REQUIRED_HANDOFF_DOMAINS.map((domain, index) =>
        handoffDomain(domain, index, {
          status: 'ready',
          activationBlockerId: null,
          productionActivationOnly: false,
        }),
      ),
      runtimeConfiguration: {
        trustClaimsDisabled: false,
        rootBundleProviderConfigured: true,
        adapterEndpointConfigured: true,
      },
      runtimeConfigurationSource: {
        activationBlockerIds: [],
        productionConfigurationReady: true,
      },
      cutoverPlan: {
        cutoverWindowApproved: true,
        productionEndpointSelected: true,
        activationBlockerIds: [],
      },
      humanReview: {
        decision: 'cutover_ready_verified_runtime',
      },
    }),
  );

  assert.equal(ready.decision, 'permitted');
  assert.equal(ready.handoff.productionCutoverReady, true);
  assert.deepEqual(ready.handoff.cutoverBlockerIds, []);
  assert.equal(ready.handoff.runtimeConfiguration.rootBundleProviderConfigured, true);
  assert.equal(ready.handoff.runtimeConfiguration.adapterEndpointConfigured, true);
  assert.equal(ready.handoff.exochainProductionClaim, false);
  assert.equal(ready.trustState, 'inactive');
});

test('deployment handoff cutover fails closed for missing domains broad blockers and unsafe claims', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const result = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffCycle: {
        productionTrustClaim: true,
      },
      handoffDomains: handoffDomains().filter((entry) => entry.domain !== 'rollback_disablement'),
      runtimeConfiguration: {
        browserAuthoritativePathEnabled: true,
      },
      cutoverPlan: {
        cutoverWindowApproved: true,
        productionEndpointSelected: true,
        activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-UNBOUNDED-CUTOVER'],
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.handoff, null);
  assert.ok(result.reasons.includes('handoff_domain_missing:rollback_disablement'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('browser_authoritative_path_forbidden'));
  assert.ok(result.reasons.includes('production_endpoint_without_verified_runtime'));
  assert.ok(result.reasons.includes('cutover_blocker_not_allowed:ESC-UNBOUNDED-CUTOVER'));
});

test('deployment handoff cutover validates HLC ordering and AI advisory boundaries', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const sameTick = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffCycle: {
        humanReviewedAtHlc: { physicalMs: 1800004300000, logical: 2 },
        auditRecordedAtHlc: { physicalMs: 1800004300000, logical: 3 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800004300000, logical: 2 },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1800004300000, logical: 3 },
      },
    }),
  );

  assert.equal(sameTick.decision, 'permitted');

  const invalid = evaluateDeploymentHandoffCutover(
    handoffInput({
      handoffCycle: {
        validationRecordedAtHlc: { physicalMs: 1800004090000, logical: 0 },
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1800004200000, logical: -1 },
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
  assert.ok(invalid.reasons.includes('handoff_cycle_validationRecordedAtHlc_before_evidenceCollectedAtHlc'));
  assert.ok(invalid.reasons.includes('validation_time_invalid'));
  assert.ok(invalid.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(invalid.reasons.includes('ai_human_review_absent'));
  assert.ok(invalid.reasons.includes('human_review_authority_absent'));
});

test('deployment handoff cutover handles absent objects as fail-closed denial states', async () => {
  const { evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const result = evaluateDeploymentHandoffCutover({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:deployment-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['deployment_handoff_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('handoff_policy_ref_absent'));
  assert.ok(result.reasons.includes('handoff_cycle_ref_absent'));
  assert.ok(result.reasons.includes('handoff_domains_absent'));
  assert.ok(result.reasons.includes('runtime_configuration_absent'));
  assert.ok(result.reasons.includes('handoff_artifacts_absent'));
  assert.ok(result.reasons.includes('cutover_plan_absent'));
  assert.ok(result.reasons.includes('validation_evidence_absent'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('handoff_audit_record_ref_absent'));
});

test('deployment handoff cutover rejects raw handoff content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDeploymentHandoffCutover } = await loadDeploymentHandoffCutover();

  const inert = handoffInput({
    runtimeConfiguration: {
      rawRuntimeConfig: false,
      apiKey: {},
    },
  });

  assert.equal(evaluateDeploymentHandoffCutover(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateDeploymentHandoffCutover(
        handoffInput({
          runtimeConfiguration: {
            rawRuntimeConfig: ['unredacted runtime configuration stays external'],
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentHandoffCutover(
        handoffInput({
          cutoverPlan: {
            rawCutoverNotes: 'Participant Alice Example must not appear in handoff evidence.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentHandoffCutover(
        handoffInput({
          runtimeConfiguration: {
            apiKey: 'cm_live_secret_value',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentHandoffCutover(
        handoffInput({
          humanReview: {
            token: 7,
          },
        }),
      ),
    ProtectedContentError,
  );
});
