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

const REQUIRED_OPERATION_DOMAINS = [
  'dependency_audit',
  'monitoring_destination',
  'on_call_ownership',
  'railway_access',
  'rollback_disablement',
  'secret_management',
  'secret_rotation',
  'secret_scan',
];

const REQUIRED_INCIDENT_FAMILIES = [
  'adapter_degraded',
  'availability_outage',
  'data_integrity_event',
  'privacy_boundary_failure',
  'receipt_queue_backlog',
  'root_bundle_unavailable',
  'security_event',
  'sponsor_export_disclosure',
];

const REQUIRED_RELEASE_LINKAGE_DOMAINS = [
  'capa_cqi_drift_linkage',
  'decision_forum_materiality',
  'deployment_manifest_update',
  'incident_register_current',
  'policy_traceability_update',
  'prd_acceptance_update',
  'release_readiness_update',
  'rollback_or_disablement_path',
  'validation_evidence',
];

const ALLOWED_DEPLOYMENT_BLOCKERS = [
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

async function loadDeploymentOperationsReadiness() {
  try {
    return await import('../src/deployment-operations-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica deployment operations readiness module must exist and load: ${error.message}`);
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

function operationDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    domain,
    status: domain === 'railway_access' ? 'activation_blocked' : 'ready',
    evidenceRef: `operations-evidence-${domain}`,
    evidenceHash: hashes[index],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner`,
    backupOwnerDid: `did:exo:${domain.replaceAll('_', '-')}-backup`,
    activationBlockerId: domain === 'railway_access' ? 'ESC-RUNTIME' : null,
    blocksBaselineDevelopment: false,
    productionActivationOnly: domain === 'railway_access',
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800002100000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function operationDomains() {
  return REQUIRED_OPERATION_DOMAINS.map((domain, index) => operationDomain(domain, index));
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
      reviewedAtHlc: { physicalMs: 1800002100000, logical: 9 },
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
      reviewedAtHlc: { physicalMs: 1800002100000, logical: 9 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    overrides,
  );
}

function operationsInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'site_leader'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['deployment_operations_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    operationsPolicy: {
      policyRef: 'deployment-operations-readiness-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredOperationDomains: REQUIRED_OPERATION_DOMAINS,
      allowedDeploymentBlockerIds: ALLOWED_DEPLOYMENT_BLOCKERS,
      rootVerificationRequiredForTrustClaims: true,
      noCredentialDisclosure: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800001900000, logical: 0 },
    },
    readinessCycle: {
      cycleRef: 'deployment-operations-readiness-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800001950000, logical: 0 },
      evidenceCollectedAtHlc: { physicalMs: 1800002100000, logical: 8 },
      validationRecordedAtHlc: { physicalMs: 1800002200000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800002300000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800002400000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    operationDomains: operationDomains(),
    deploymentConfiguration: {
      topologyRef: 'server-side-gateway-node-baseline',
      topologyHash: DIGEST_C,
      monitoringDestinationSelected: false,
      onCallOwnerNamed: false,
      secretManagerSelected: false,
      rotationOwnerNamed: false,
      dependencyAuditPassed: true,
      secretScanPassed: true,
      rollbackAuthorityNamed: false,
      activationStateDisablementTested: true,
      missingSecretsFailClosed: true,
      productionEndpointSelected: false,
      activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-ROOT-DEPLOYMENT', 'ESC-ROOT-OWNER'],
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800002100000, logical: 7 },
    },
    releaseIncidentLinkage: {
      linkageRegisterRef: 'cmril-release-incident-linkage-alpha',
      linkageRegisterHash: DIGEST_7,
      receiptHash: DIGEST_8,
      receiptArtifactType: 'release_incident_linkage_register',
      status: 'release_incident_linkage_accepted_inactive_trust',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      operationsReadinessRef: 'deployment-operations-readiness-alpha',
      incidentFamiliesCovered: REQUIRED_INCIDENT_FAMILIES,
      releaseLinkageDomainsCovered: REQUIRED_RELEASE_LINKAGE_DOMAINS,
      openMaterialIncidentCount: 0,
      blockingIncidentRefs: [],
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
      reviewedAtHlc: { physicalMs: 1800002100000, logical: 9 },
    },
    deploymentReadinessManifest: {
      manifestHash: DIGEST_1,
      receiptHash: DIGEST_2,
      receiptArtifactType: 'deployment_readiness_manifest',
      status: 'deployment_readiness_manifest_accepted_inactive_trust',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      trustState: 'inactive',
      baselineReady: true,
      productionClaim: false,
      driftStateUpdateEvidence: deploymentReadinessDriftStateUpdateEvidence(),
      roleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800002100000, logical: 10 },
    },
    railwayAccess: {
      provider: 'railway',
      cliInstalled: true,
      cliVersion: 'railway 4.42.1',
      cliVersionHash: DIGEST_D,
      authenticated: false,
      loginRequired: true,
      projectLinked: false,
      workspaceHash: null,
      projectHash: null,
      serviceHash: null,
      environmentHash: null,
      dashboardAccessVerified: false,
      tokenStored: false,
      credentialShared: false,
      statusEvidenceHash: DIGEST_E,
      checkedAtHlc: { physicalMs: 1800002100000, logical: 8 },
      metadataOnly: true,
    },
    validationEvidence: {
      commandRefs: ['npm run quality', 'railway whoami --json', 'railway status --json'],
      commandsPassed: true,
      testCount: 320,
      coverageLineBasisPoints: 9973,
      sourceGuardPassed: true,
      dependencyAuditEvidenceHash: DIGEST_F,
      secretScanEvidenceHash: DIGEST_1,
      noExochainSourceModified: true,
      metadataOnly: true,
      recordedAtHlc: { physicalMs: 1800002200000, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'operations_ready_with_activation_blockers',
      decisionHash: DIGEST_2,
      noProductionTrustClaim: true,
      activationBlockersAccepted: true,
      railwayLoginRequiredAccepted: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800002300000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'deployment-operations-audit-alpha',
      auditRecordHash: DIGEST_3,
      receiptRecordedAtHlc: { physicalMs: 1800002400000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_4,
      limitationHashes: [DIGEST_5],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_6,
  };
  return mergeDeep(base, overrides);
}

test('deployment operations readiness records runbook blockers and Railway login status deterministically', async () => {
  const { evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const resultA = evaluateDeploymentOperationsReadiness(operationsInput());
  const resultB = evaluateDeploymentOperationsReadiness(
    operationsInput({
      operationsPolicy: {
        requiredOperationDomains: [...REQUIRED_OPERATION_DOMAINS].reverse(),
        allowedDeploymentBlockerIds: [...ALLOWED_DEPLOYMENT_BLOCKERS].reverse(),
      },
      operationDomains: [...operationDomains()].reverse(),
      deploymentConfiguration: {
        activationBlockerIds: ['ESC-ROOT-OWNER', 'ESC-OPS-SECRETS', 'ESC-ROOT-DEPLOYMENT'],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.operations.trustState, 'inactive');
  assert.equal(resultA.operations.exochainProductionClaim, false);
  assert.equal(resultA.operations.productionOperationsReady, false);
  assert.equal(resultA.operations.baselineOperationsPackReady, true);
  assert.deepEqual(resultA.operations.operationDomainsCovered, REQUIRED_OPERATION_DOMAINS);
  assert.deepEqual(resultA.operations.deploymentBlockerIds, [
    'ESC-OPS-SECRETS',
    'ESC-ROOT-DEPLOYMENT',
    'ESC-ROOT-OWNER',
    'ESC-RUNTIME',
  ]);
  assert.equal(resultA.operations.railway.loginStatus, 'login_required');
  assert.equal(resultA.operations.railway.credentialShared, false);
  assert.equal(resultA.operations.railway.tokenStored, false);
  assert.equal(resultA.operations.releaseIncidentLinkageSummary.receiptHash, DIGEST_8);
  assert.deepEqual(resultA.operations.releaseIncidentLinkageSummary.incidentFamiliesCovered, REQUIRED_INCIDENT_FAMILIES);
  assert.deepEqual(
    resultA.operations.releaseIncidentLinkageSummary.releaseLinkageDomainsCovered,
    REQUIRED_RELEASE_LINKAGE_DOMAINS,
  );
  assert.equal(resultA.operations.deploymentReadinessManifestSummary.receiptHash, DIGEST_2);
  assert.equal(
    resultA.operations.deploymentReadinessManifestSummary.status,
    'deployment_readiness_manifest_accepted_inactive_trust',
  );
  assert.equal(resultA.operations.deploymentReadinessManifestSummary.trustState, 'inactive');
  assert.equal(resultA.operations.deploymentReadinessManifestSummary.baselineReady, true);
  assert.equal(resultA.operations.deploymentReadinessManifestSummary.productionClaim, false);
  assert.equal(
    resultA.operations.deploymentReadinessManifestSummary.driftStateUpdateEvidence.driftLoopReceiptHash,
    DIGEST_5,
  );
  assert.equal(
    resultA.operations.deploymentReadinessManifestSummary.driftStateUpdateEvidence.stateUpdateHash,
    DIGEST_6,
  );
  assert.equal(
    resultA.operations.deploymentReadinessManifestSummary.driftStateUpdateEvidence.cqiCycleReceiptHash,
    DIGEST_8,
  );
  assert.equal(
    resultA.operations.deploymentReadinessManifestSummary.driftStateUpdateEvidence.inquiryCqiBacklogReceiptHash,
    DIGEST_9,
  );
  assert.equal(
    resultA.operations.deploymentReadinessManifestSummary.driftStateUpdateEvidence.roleManualCoverageReceiptHash,
    DIGEST_F,
  );
  assert.deepEqual(
    resultA.operations.deploymentReadinessManifestSummary.driftStateUpdateEvidence.stateUpdateTargets,
    REQUIRED_DRIFT_STATE_TARGETS,
  );
  assert.deepEqual(resultA.operations.deploymentReadinessManifestSummary.roleDashboardTrustStateEvidence, {
    activationLineageAccepted: true,
    canShowProductionTrustClaim: false,
    dashboardHashRefs: DASHBOARD_ROLES.map((role, index) => ({
      dashboardHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_7, DIGEST_8][index],
      role,
      trustStateViewHash: [DIGEST_8, DIGEST_7, DIGEST_6, DIGEST_5, DIGEST_4, DIGEST_3, DIGEST_2, DIGEST_1][index],
    })),
    dashboardRoles: DASHBOARD_ROLES,
    productionClaimLiftCanLiftProductionClaim: false,
    productionClaimLiftReceiptHash: DIGEST_3,
    productionClaimLiftRoleDashboardProviderReceiptHash: DIGEST_B,
    productionClaimLiftRoleDashboardProviderSummaryHash: DIGEST_A,
    productionClaimLiftRoleDashboardProviderTrustStateViewHash: DIGEST_C,
    productionClaimLiftRoleDashboardReadinessReceiptHash: DIGEST_E,
    productionClaimLiftRoleDashboardReadinessSummaryHash: DIGEST_F,
    productionClaimLiftRoleDashboardReadinessTrustStateViewHash: DIGEST_D,
    productionClaimLiftRoleDashboardRoles: DASHBOARD_ROLES,
    productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_B,
    productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_A,
    productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_C,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_E,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_F,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_D,
    productionClaimLiftTrustState: 'inactive',
    publicClaimReviewPackageHash: DIGEST_2,
    publicClaimReviewReceiptHash: DIGEST_1,
    roleDashboardReceiptHash: DIGEST_B,
    roleDashboardSummaryHash: DIGEST_A,
    roleDashboardTrustStateViewHash: DIGEST_C,
    trustState: 'inactive',
  });
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'deployment_operations_readiness');
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('deployment_readiness_manifest'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('drift_state_update'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('continuous_quality_improvement'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('manual_navigation_readiness'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('role_dashboard_trust_state'));
  assert.deepEqual(resultA, resultB);
});

test('deployment operations readiness requires deployment readiness manifest Drift and role-dashboard trust-state lineage', async () => {
  const { evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const missing = evaluateDeploymentOperationsReadiness(
    operationsInput({
      deploymentReadinessManifest: null,
    }),
  );
  const unsafe = evaluateDeploymentOperationsReadiness(
    operationsInput({
      deploymentReadinessManifest: {
        manifestHash: 'not-a-digest',
        receiptHash: 'also-not-a-digest',
        receiptArtifactType: 'deployment_summary',
        status: 'manifest_pending',
        releaseCandidateRef: 'different-release',
        trustState: 'active',
        baselineReady: false,
        productionClaim: true,
        driftStateUpdateEvidence: deploymentReadinessDriftStateUpdateEvidence({
          driftLoopReceiptHash: 'bad-receipt',
          stateUpdateHash: 'bad-state',
          stateUpdateTargets: ['passport'],
          cqiCycleReceiptHash: null,
          inquiryCqiBacklogReceiptHash: null,
          manualNavigationReady: false,
          manualNavigationEffectiveUseAcknowledged: false,
          roleManualCoverageReceiptHash: null,
          trustState: 'active',
          exochainProductionClaim: true,
          protectedContentExcluded: false,
          reviewedAtHlc: { physicalMs: 1800002200000, logical: 2 },
        }),
        roleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence({
          dashboardRoles: DASHBOARD_ROLES.filter((role) => role !== 'sponsor_viewer'),
          dashboardHashRefs: [
            {
              role: 'quality_manager',
              dashboardHash: DIGEST_1,
              trustStateViewHash: DIGEST_2,
            },
            {
              role: 'unapproved_role',
              dashboardHash: DIGEST_3,
              trustStateViewHash: DIGEST_4,
            },
          ],
          roleDashboardReceiptHash: 'not-a-digest',
          roleDashboardTrustStateViewHash: null,
          trustState: 'verified',
          exochainProductionClaim: true,
          canShowProductionTrustClaim: true,
          activationLineageAccepted: false,
          publicClaimReviewReceiptHash: 'bad-public-claim-receipt',
          publicClaimReviewPackageHash: 'bad-public-claim-package',
          productionClaimLiftReceiptHash: 'bad-lift-receipt',
          productionClaimLiftTrustState: 'verified',
          productionClaimLiftCanLiftProductionClaim: true,
          productionClaimLiftRoleDashboardProviderReceiptHash: 'bad-provider-receipt',
          productionClaimLiftRoleDashboardProviderSummaryHash: 'bad-provider-summary',
          productionClaimLiftRoleDashboardProviderTrustStateViewHash: 'bad-provider-view',
          productionClaimLiftRoleDashboardReadinessReceiptHash: 'bad-readiness-receipt',
          productionClaimLiftRoleDashboardReadinessSummaryHash: 'bad-readiness-summary',
          productionClaimLiftRoleDashboardReadinessTrustStateViewHash: 'bad-readiness-view',
          productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_D,
          productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
          productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: 'bad-runtime-source-provider-view',
          productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_4,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_5,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: 'bad-runtime-source-readiness-view',
          productionClaimLiftRoleDashboardRoles: DASHBOARD_ROLES.filter((role) => role !== 'sponsor_viewer').concat(
            'marketing_admin',
          ),
          metadataOnly: false,
          protectedContentExcluded: false,
          reviewedAtHlc: { physicalMs: 1800002200000, logical: 3 },
        }),
        metadataOnly: false,
        protectedContentExcluded: false,
        reviewedAtHlc: { physicalMs: 1800002200000, logical: 1 },
      },
    }),
  );
  const mismatch = evaluateDeploymentOperationsReadiness(
    operationsInput({
      deploymentReadinessManifest: {
        roleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence({
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
  assert.equal(missing.operations, null);
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_absent'));
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_hash_invalid'));
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_receipt_hash_invalid'));
  assert.ok(missing.reasons.includes('deployment_readiness_role_dashboard_trust_state_evidence_absent'));
  assert.ok(missing.reasons.includes('deployment_readiness_role_dashboard_summary_hash_invalid'));

  assert.equal(unsafe.decision, 'denied');
  assert.equal(unsafe.operations, null);
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_receipt_type_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_status_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_release_candidate_mismatch'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_baseline_not_ready'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manifest_after_validation'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_loop_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_state_update_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_state_update_target_missing:quality_state'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_state_update_target_missing:readiness'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_cqi_cycle_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_inquiry_cqi_backlog_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manual_navigation_not_ready'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_manual_navigation_effective_use_absent'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_manual_coverage_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_drift_after_manifest_review'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_trust_state_view_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_role_missing:sponsor_viewer'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_hash_ref_role_unsupported:unapproved_role'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_hash_ref_missing:auditor'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_forbidden'));
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
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_provider_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_role_missing:sponsor_viewer'));
  assert.ok(
    unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_role_unsupported:marketing_admin'),
  );
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_after_manifest_review'));

  assert.equal(mismatch.decision, 'denied');
  assert.ok(
    mismatch.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_provider_receipt_mismatch'),
  );
  assert.ok(
    mismatch.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_provider_summary_mismatch'),
  );
  assert.ok(
    mismatch.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_provider_trust_state_view_mismatch'),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_provider_receipt_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_provider_summary_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_receipt_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_summary_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_provider_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_trust_state_view_mismatch',
    ),
  );
});

test('deployment operations readiness requires accepted release incident linkage receipt evidence', async () => {
  const { evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const missing = evaluateDeploymentOperationsReadiness(
    operationsInput({
      releaseIncidentLinkage: null,
    }),
  );
  const unsafe = evaluateDeploymentOperationsReadiness(
    operationsInput({
      releaseIncidentLinkage: {
        receiptHash: 'not-a-digest',
        receiptArtifactType: 'incident_summary',
        releaseCandidateRef: 'different-release',
        operationsReadinessRef: 'other-operations-readiness',
        incidentFamiliesCovered: REQUIRED_INCIDENT_FAMILIES.filter((family) => family !== 'receipt_queue_backlog'),
        releaseLinkageDomainsCovered: REQUIRED_RELEASE_LINKAGE_DOMAINS.filter(
          (domain) => domain !== 'rollback_or_disablement_path',
        ),
        openMaterialIncidentCount: 1,
        blockingIncidentRefs: ['INC-0001-adapter_degraded'],
        productionTrustClaim: true,
        reviewedAtHlc: { physicalMs: 1800002300000, logical: 1 },
      },
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.operations, null);
  assert.ok(missing.reasons.includes('release_incident_linkage_absent'));
  assert.ok(missing.reasons.includes('release_incident_linkage_ref_absent'));
  assert.ok(missing.reasons.includes('release_incident_linkage_receipt_hash_invalid'));

  assert.equal(unsafe.decision, 'denied');
  assert.equal(unsafe.operations, null);
  assert.ok(unsafe.reasons.includes('release_incident_linkage_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('release_incident_linkage_receipt_type_invalid'));
  assert.ok(unsafe.reasons.includes('release_incident_linkage_release_candidate_mismatch'));
  assert.ok(unsafe.reasons.includes('release_incident_linkage_operations_ref_mismatch'));
  assert.ok(unsafe.reasons.includes('release_incident_family_missing:receipt_queue_backlog'));
  assert.ok(unsafe.reasons.includes('release_linkage_domain_missing:rollback_or_disablement_path'));
  assert.ok(unsafe.reasons.includes('release_incident_open_material_incidents'));
  assert.ok(unsafe.reasons.includes('release_incident_blocking_refs_present'));
  assert.ok(unsafe.reasons.includes('release_incident_linkage_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('release_incident_linkage_after_validation'));
});

test('deployment operations readiness fails closed for missing domains broad blockers and production claims', async () => {
  const { evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const result = evaluateDeploymentOperationsReadiness(
    operationsInput({
      readinessCycle: {
        productionTrustClaim: true,
      },
      operationDomains: operationDomains().filter((entry) => entry.domain !== 'secret_scan'),
      deploymentConfiguration: {
        productionEndpointSelected: true,
        activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-UNBOUNDED-OPS'],
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.operations, null);
  assert.ok(result.reasons.includes('operation_domain_missing:secret_scan'));
  assert.ok(result.reasons.includes('deployment_blocker_not_allowed:ESC-UNBOUNDED-OPS'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('production_endpoint_selected_without_activation'));
});

test('deployment operations readiness separates verified Railway access from credential disclosure', async () => {
  const { ProtectedContentError, evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const verified = evaluateDeploymentOperationsReadiness(
    operationsInput({
      operationDomains: REQUIRED_OPERATION_DOMAINS.map((domain, index) =>
        operationDomain(domain, index, {
          status: 'ready',
          activationBlockerId: null,
          productionActivationOnly: false,
        }),
      ),
      deploymentConfiguration: {
        monitoringDestinationSelected: true,
        onCallOwnerNamed: true,
        secretManagerSelected: true,
        rotationOwnerNamed: true,
        rollbackAuthorityNamed: true,
        productionEndpointSelected: false,
        activationBlockerIds: [],
      },
      railwayAccess: {
        authenticated: true,
        loginRequired: false,
        projectLinked: true,
        workspaceHash: DIGEST_7,
        projectHash: DIGEST_8,
        serviceHash: DIGEST_A,
        environmentHash: DIGEST_B,
        dashboardAccessVerified: true,
      },
    }),
  );

  assert.equal(verified.decision, 'permitted');
  assert.equal(verified.operations.railway.loginStatus, 'verified');
  assert.deepEqual(verified.operations.deploymentBlockerIds, []);
  assert.equal(verified.operations.productionOperationsReady, true);

  const unverified = evaluateDeploymentOperationsReadiness(
    operationsInput({
      railwayAccess: {
        authenticated: true,
        loginRequired: false,
        projectLinked: false,
      },
    }),
  );

  assert.equal(unverified.decision, 'permitted');
  assert.equal(unverified.operations.railway.loginStatus, 'unverified');
  assert.equal(unverified.operations.productionOperationsReady, false);

  assert.throws(
    () =>
      evaluateDeploymentOperationsReadiness(
        operationsInput({
          railwayAccess: {
            accessToken: DIGEST_A,
          },
        }),
      ),
    ProtectedContentError,
  );
});

test('deployment operations readiness validates HLC ordering and AI advisory boundaries', async () => {
  const { evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const validSameTick = evaluateDeploymentOperationsReadiness(
    operationsInput({
      readinessCycle: {
        humanReviewedAtHlc: { physicalMs: 1800002300000, logical: 2 },
        auditRecordedAtHlc: { physicalMs: 1800002300000, logical: 3 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800002300000, logical: 2 },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1800002300000, logical: 3 },
      },
    }),
  );

  assert.equal(validSameTick.decision, 'permitted');

  const invalid = evaluateDeploymentOperationsReadiness(
    operationsInput({
      readinessCycle: {
        validationRecordedAtHlc: { physicalMs: 1800002090000, logical: 0 },
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1800002200000, logical: -1 },
      },
      aiAssistance: {
        finalAuthority: true,
        reviewedByHuman: false,
      },
      humanReview: {
        aiFinalAuthority: true,
        finalAuthority: 'ai',
      },
    }),
  );

  assert.equal(invalid.decision, 'denied');
  assert.ok(invalid.reasons.includes('readiness_cycle_validationRecordedAtHlc_before_evidenceCollectedAtHlc'));
  assert.ok(invalid.reasons.includes('validation_time_invalid'));
  assert.ok(invalid.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(invalid.reasons.includes('ai_human_review_absent'));
  assert.ok(invalid.reasons.includes('human_review_authority_absent'));
});

test('deployment operations readiness handles absent objects as fail-closed denial states', async () => {
  const { evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const result = evaluateDeploymentOperationsReadiness({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['deployment_operations_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('operations_policy_ref_absent'));
  assert.ok(result.reasons.includes('readiness_cycle_ref_absent'));
  assert.ok(result.reasons.includes('operation_domains_absent'));
  assert.ok(result.reasons.includes('deployment_configuration_absent'));
  assert.ok(result.reasons.includes('release_incident_linkage_absent'));
  assert.ok(result.reasons.includes('railway_access_absent'));
  assert.ok(result.reasons.includes('validation_evidence_absent'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('operations_audit_record_ref_absent'));
});

test('deployment operations readiness rejects raw operations content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDeploymentOperationsReadiness } = await loadDeploymentOperationsReadiness();

  const inert = operationsInput({
    operationDomains: [
      operationDomain('dependency_audit', 0, {
        rawRunbookText: false,
      }),
      ...operationDomains().slice(1),
    ],
    deploymentConfiguration: {
      apiKey: {},
    },
  });

  assert.equal(evaluateDeploymentOperationsReadiness(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateDeploymentOperationsReadiness(
        operationsInput({
          operationDomains: [
            operationDomain('dependency_audit', 0, {
              rawRunbookText: ['unredacted deployment runbook body stays external'],
            }),
            ...operationDomains().slice(1),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentOperationsReadiness(
        operationsInput({
          deploymentConfiguration: {
            freeTextNote: 'Participant Alice Example must not appear in operations notes.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentOperationsReadiness(
        operationsInput({
          deploymentConfiguration: {
            apiKey: 'cm_live_secret_value',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentOperationsReadiness(
        operationsInput({
          humanReview: {
            secret: 7,
          },
        }),
      ),
    ProtectedContentError,
  );
});
