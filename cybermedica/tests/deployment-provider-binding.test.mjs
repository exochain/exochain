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

const REQUIRED_BINDING_DOMAINS = [
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

const ALLOWED_ACTIVATION_BLOCKERS = [
  'ESC-OPS-SECRETS',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-RUNTIME',
];

async function loadDeploymentProviderBinding() {
  try {
    return await import('../src/deployment-provider-binding.mjs');
  } catch (error) {
    assert.fail(`CyberMedica deployment provider binding module must exist and load: ${error.message}`);
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

function bindingDomain(domain, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6];
  const activationBlocked = ['dns_tls_binding', 'root_bundle_provider_binding', 'runtime_adapter_binding'].includes(domain);
  return {
    domain,
    status: activationBlocked ? 'activation_blocked' : 'ready',
    evidenceRef: `provider-binding-evidence-${domain}`,
    evidenceHash: hashes[index],
    ownerDid: `did:exo:${domain.replaceAll('_', '-')}-owner`,
    activationBlockerId: activationBlocked ? (domain === 'dns_tls_binding' ? 'ESC-ROOT-DEPLOYMENT' : 'ESC-RUNTIME') : null,
    productionActivationOnly: activationBlocked,
    blocksBaselineDevelopment: false,
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800003200000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function bindingDomains() {
  return REQUIRED_BINDING_DOMAINS.map((domain, index) => bindingDomain(domain, index));
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
      reviewedAtHlc: { physicalMs: 1800003200000, logical: 9 },
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
      reviewedAtHlc: { physicalMs: 1800003200000, logical: 10 },
    },
    overrides,
  );
}

function providerBindingInput(overrides = {}) {
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
      permissions: ['deployment_provider_binding_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    providerPolicy: {
      policyRef: 'deployment-provider-binding-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      allowedProviders: ['railway'],
      requiredBindingDomains: REQUIRED_BINDING_DOMAINS,
      allowedActivationBlockerIds: ALLOWED_ACTIVATION_BLOCKERS,
      rootVerificationRequiredForTrustClaims: true,
      noCredentialDisclosure: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800003000000, logical: 0 },
    },
    bindingCycle: {
      bindingRef: 'deployment-provider-binding-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800003100000, logical: 0 },
      evidenceCollectedAtHlc: { physicalMs: 1800003200000, logical: 12 },
      validationRecordedAtHlc: { physicalMs: 1800003300000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800003400000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800003500000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    providerBinding: {
      provider: 'railway',
      accountHash: DIGEST_C,
      workspaceHash: null,
      projectHash: null,
      serviceHash: null,
      environmentHash: null,
      domainHash: null,
      publicEndpointHash: null,
      endpointSelected: false,
      projectLinked: false,
      serviceBound: false,
      environmentBound: false,
      dashboardAccessVerified: false,
      providerHealthVerified: false,
      checkedAtHlc: { physicalMs: 1800003200000, logical: 12 },
      metadataOnly: true,
      credentialShared: false,
      tokenStored: false,
    },
    runtimeBinding: {
      topologyRef: 'server-side-gateway-node-baseline',
      topologyHash: DIGEST_D,
      gatewayAdapterHash: DIGEST_E,
      nodeReceiptAdapterHash: DIGEST_F,
      decisionForumAdapterHash: DIGEST_1,
      rootBundleProviderHash: null,
      rootBundleProviderVerified: false,
      browserAuthoritativePathEnabled: false,
      healthEndpointSeparatesProcessAndTrust: true,
      unavailableAdaptersFailClosed: true,
      receiptPayloadBoundaryVerified: true,
      productionTrustClaim: false,
      metadataOnly: true,
      checkedAtHlc: { physicalMs: 1800003200000, logical: 11 },
    },
    bindingDomains: bindingDomains(),
    operationsReadiness: {
      operationsReadinessRef: 'deployment-operations-readiness-alpha',
      operationsReadinessHash: DIGEST_2,
      receiptHash: DIGEST_9,
      receiptArtifactType: 'deployment_operations_readiness',
      status: 'deployment_operations_readiness_accepted_inactive_trust',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      releaseIncidentLinkageReceiptHash: DIGEST_7,
      baselineOperationsPackReady: true,
      productionOperationsReady: false,
      railwayLoginStatus: 'login_required',
      activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-ROOT-DEPLOYMENT', 'ESC-ROOT-OWNER', 'ESC-RUNTIME'],
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
      roleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
      reviewedAtHlc: { physicalMs: 1800003200000, logical: 10 },
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
      reviewedAtHlc: { physicalMs: 1800003200000, logical: 10 },
    },
    validationEvidence: {
      commandRefs: ['npm run quality', 'railway whoami --json', 'railway status --json'],
      commandsPassed: true,
      testCount: 326,
      coverageLineBasisPoints: 9973,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      providerStatusEvidenceHash: DIGEST_3,
      metadataOnly: true,
      recordedAtHlc: { physicalMs: 1800003300000, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'provider_binding_ready_with_activation_blockers',
      decisionHash: DIGEST_4,
      activationBlockersAccepted: true,
      noProductionTrustClaim: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800003400000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'deployment-provider-binding-audit-alpha',
      auditRecordHash: DIGEST_5,
      receiptRecordedAtHlc: { physicalMs: 1800003500000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_6,
      limitationHashes: [DIGEST_7],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_8,
  };
  return mergeDeep(base, overrides);
}

test('deployment provider binding records Railway login-required state without production trust claims', async () => {
  const { evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const resultA = evaluateDeploymentProviderBinding(providerBindingInput());
  const resultB = evaluateDeploymentProviderBinding(
    providerBindingInput({
      providerPolicy: {
        requiredBindingDomains: [...REQUIRED_BINDING_DOMAINS].reverse(),
        allowedActivationBlockerIds: [...ALLOWED_ACTIVATION_BLOCKERS].reverse(),
      },
      bindingDomains: [...bindingDomains()].reverse(),
      operationsReadiness: {
        activationBlockerIds: ['ESC-RUNTIME', 'ESC-ROOT-OWNER', 'ESC-ROOT-DEPLOYMENT', 'ESC-OPS-SECRETS'],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.providerBinding.trustState, 'inactive');
  assert.equal(resultA.providerBinding.exochainProductionClaim, false);
  assert.equal(resultA.providerBinding.baselineProviderBindingReady, true);
  assert.equal(resultA.providerBinding.productionProviderBindingReady, false);
  assert.deepEqual(resultA.providerBinding.bindingDomainsCovered, REQUIRED_BINDING_DOMAINS);
  assert.deepEqual(resultA.providerBinding.activationBlockerIds, ALLOWED_ACTIVATION_BLOCKERS);
  assert.equal(resultA.providerBinding.provider.provider, 'railway');
  assert.equal(resultA.providerBinding.provider.bindingStatus, 'login_required');
  assert.equal(resultA.providerBinding.provider.endpointSelected, false);
  assert.equal(resultA.providerBinding.runtime.rootBundleProviderVerified, false);
  assert.equal(resultA.providerBinding.operationsReadiness.receiptHash, DIGEST_9);
  assert.equal(resultA.providerBinding.operationsReadiness.receiptArtifactType, 'deployment_operations_readiness');
  assert.equal(resultA.providerBinding.operationsReadiness.status, 'deployment_operations_readiness_accepted_inactive_trust');
  assert.equal(resultA.providerBinding.operationsReadiness.releaseIncidentLinkageReceiptHash, DIGEST_7);
  assert.deepEqual(resultA.providerBinding.operationsReadiness.roleDashboardTrustStateEvidence, {
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
  assert.equal(resultA.providerBinding.deploymentReadinessManifest.receiptHash, DIGEST_2);
  assert.equal(
    resultA.providerBinding.deploymentReadinessManifest.status,
    'deployment_readiness_manifest_accepted_inactive_trust',
  );
  assert.equal(resultA.providerBinding.deploymentReadinessManifest.trustState, 'inactive');
  assert.equal(resultA.providerBinding.deploymentReadinessManifest.baselineReady, true);
  assert.equal(resultA.providerBinding.deploymentReadinessManifest.productionClaim, false);
  assert.equal(resultA.providerBinding.deploymentReadinessManifest.driftStateUpdateEvidence.driftLoopReceiptHash, DIGEST_5);
  assert.equal(resultA.providerBinding.deploymentReadinessManifest.driftStateUpdateEvidence.stateUpdateHash, DIGEST_6);
  assert.equal(resultA.providerBinding.deploymentReadinessManifest.driftStateUpdateEvidence.cqiCycleReceiptHash, DIGEST_8);
  assert.equal(
    resultA.providerBinding.deploymentReadinessManifest.driftStateUpdateEvidence.inquiryCqiBacklogReceiptHash,
    DIGEST_9,
  );
  assert.equal(
    resultA.providerBinding.deploymentReadinessManifest.driftStateUpdateEvidence.roleManualCoverageReceiptHash,
    DIGEST_F,
  );
  assert.deepEqual(
    resultA.providerBinding.deploymentReadinessManifest.driftStateUpdateEvidence.stateUpdateTargets,
    REQUIRED_DRIFT_STATE_TARGETS,
  );
  assert.equal(
    resultA.providerBinding.deploymentReadinessManifest.roleDashboardTrustStateEvidence.roleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    resultA.providerBinding.deploymentReadinessManifest.roleDashboardTrustStateEvidence
      .productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    DIGEST_C,
  );
  assert.equal(
    resultA.providerBinding.deploymentReadinessManifest.roleDashboardTrustStateEvidence
      .productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    DIGEST_D,
  );
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'deployment_provider_binding');
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('deployment_readiness_manifest'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('drift_state_update'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('continuous_quality_improvement'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('manual_navigation_readiness'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('role_dashboard_trust_state'));
  assert.deepEqual(resultA, resultB);
});

test('deployment provider binding requires accepted operations readiness receipt and role-dashboard trust-state evidence', async () => {
  const { evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const missing = evaluateDeploymentProviderBinding(
    providerBindingInput({
      operationsReadiness: null,
    }),
  );
  const unsafe = evaluateDeploymentProviderBinding(
    providerBindingInput({
      operationsReadiness: {
        receiptHash: 'not-a-digest',
        receiptArtifactType: 'operations_summary',
        status: 'operations_pending',
        releaseCandidateRef: 'different-release',
        releaseIncidentLinkageReceiptHash: 'also-not-a-digest',
        protectedContentExcluded: false,
        productionTrustClaim: true,
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
            'unsupported_role',
          ),
          metadataOnly: false,
          protectedContentExcluded: false,
          reviewedAtHlc: { physicalMs: 1800003300000, logical: 2 },
        }),
        reviewedAtHlc: { physicalMs: 1800003300000, logical: 1 },
      },
    }),
  );
  const mismatch = evaluateDeploymentProviderBinding(
    providerBindingInput({
      operationsReadiness: {
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
  assert.equal(missing.providerBinding, null);
  assert.ok(missing.reasons.includes('operations_readiness_absent'));
  assert.ok(missing.reasons.includes('operations_readiness_receipt_hash_invalid'));
  assert.ok(missing.reasons.includes('operations_readiness_receipt_type_invalid'));
  assert.ok(missing.reasons.includes('operations_readiness_role_dashboard_trust_state_evidence_absent'));
  assert.ok(missing.reasons.includes('operations_readiness_role_dashboard_summary_hash_invalid'));

  assert.equal(unsafe.decision, 'denied');
  assert.equal(unsafe.providerBinding, null);
  assert.ok(unsafe.reasons.includes('operations_readiness_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_receipt_type_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_status_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_release_candidate_mismatch'));
  assert.ok(unsafe.reasons.includes('operations_readiness_release_incident_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('operations_readiness_after_validation'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_trust_state_view_hash_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_role_missing:sponsor_viewer'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_hash_ref_role_unsupported:unapproved_role'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_hash_ref_missing:auditor'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_activation_lineage_absent'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_public_claim_review_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_public_claim_review_package_hash_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_production_claim_lift_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_production_claim_lift_state_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_production_claim_lift_forbidden'));
  assert.ok(
    unsafe.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_provider_receipt_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_provider_summary_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_provider_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_readiness_receipt_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_readiness_summary_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_readiness_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_runtime_source_provider_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_role_missing:sponsor_viewer',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_role_unsupported:unsupported_role',
    ),
  );
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('operations_readiness_role_dashboard_after_operations_review'));

  assert.equal(mismatch.decision, 'denied');
  assert.equal(mismatch.providerBinding, null);
  assert.ok(
    mismatch.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_provider_receipt_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_provider_summary_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_provider_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_runtime_source_provider_receipt_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_runtime_source_provider_summary_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_runtime_source_provider_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_receipt_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_summary_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'operations_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_trust_state_view_mismatch',
    ),
  );
});

test('deployment provider binding requires deployment readiness manifest drift and role-dashboard trust-state lineage', async () => {
  const { evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const missing = evaluateDeploymentProviderBinding(
    providerBindingInput({
      deploymentReadinessManifest: null,
    }),
  );
  const unsafe = evaluateDeploymentProviderBinding(
    providerBindingInput({
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
          reviewedAtHlc: { physicalMs: 1800003300000, logical: 2 },
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
            'unsupported_role',
          ),
          metadataOnly: false,
          protectedContentExcluded: false,
          reviewedAtHlc: { physicalMs: 1800003300000, logical: 3 },
        }),
        metadataOnly: false,
        protectedContentExcluded: false,
        reviewedAtHlc: { physicalMs: 1800003300000, logical: 1 },
      },
    }),
  );
  const mismatch = evaluateDeploymentProviderBinding(
    providerBindingInput({
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
  assert.equal(missing.providerBinding, null);
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_absent'));
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_hash_invalid'));
  assert.ok(missing.reasons.includes('deployment_readiness_manifest_receipt_hash_invalid'));
  assert.ok(missing.reasons.includes('deployment_readiness_role_dashboard_trust_state_evidence_absent'));
  assert.ok(missing.reasons.includes('deployment_readiness_role_dashboard_summary_hash_invalid'));

  assert.equal(unsafe.decision, 'denied');
  assert.equal(unsafe.providerBinding, null);
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
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_provider_receipt_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_provider_summary_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_provider_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_readiness_receipt_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_readiness_summary_hash_invalid',
    ),
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
  assert.ok(
    unsafe.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_role_missing:sponsor_viewer'),
  );
  assert.ok(
    unsafe.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_role_unsupported:unsupported_role',
    ),
  );
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_readiness_role_dashboard_after_manifest_review'));

  assert.equal(mismatch.decision, 'denied');
  assert.equal(mismatch.providerBinding, null);
  assert.ok(
    mismatch.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_provider_receipt_mismatch'),
  );
  assert.ok(
    mismatch.reasons.includes('deployment_readiness_role_dashboard_production_claim_lift_provider_summary_mismatch'),
  );
  assert.ok(
    mismatch.reasons.includes(
      'deployment_readiness_role_dashboard_production_claim_lift_provider_trust_state_view_mismatch',
    ),
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
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_provider_trust_state_view_mismatch',
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
      'deployment_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_trust_state_view_mismatch',
    ),
  );
});

test('deployment provider binding can verify provider resources while keeping trust activation separate', async () => {
  const { evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const verified = evaluateDeploymentProviderBinding(
    providerBindingInput({
      providerBinding: {
        workspaceHash: DIGEST_9,
        projectHash: DIGEST_A,
        serviceHash: DIGEST_B,
        environmentHash: DIGEST_C,
        domainHash: DIGEST_D,
        publicEndpointHash: DIGEST_E,
        endpointSelected: true,
        projectLinked: true,
        serviceBound: true,
        environmentBound: true,
        dashboardAccessVerified: true,
        providerHealthVerified: true,
      },
      runtimeBinding: {
        rootBundleProviderHash: DIGEST_F,
        rootBundleProviderVerified: true,
      },
      bindingDomains: REQUIRED_BINDING_DOMAINS.map((domain, index) =>
        bindingDomain(domain, index, {
          status: 'ready',
          activationBlockerId: null,
          productionActivationOnly: false,
        }),
      ),
      operationsReadiness: {
        productionOperationsReady: true,
        railwayLoginStatus: 'verified',
        activationBlockerIds: [],
      },
      humanReview: {
        decision: 'provider_binding_ready',
      },
    }),
  );

  assert.equal(verified.decision, 'permitted');
  assert.equal(verified.providerBinding.provider.bindingStatus, 'verified');
  assert.deepEqual(verified.providerBinding.activationBlockerIds, []);
  assert.equal(verified.providerBinding.productionProviderBindingReady, true);
  assert.equal(verified.providerBinding.exochainProductionClaim, false);
  assert.equal(verified.trustState, 'inactive');
});

test('deployment provider binding fails closed for missing domains unsupported providers and unsafe claims', async () => {
  const { evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const result = evaluateDeploymentProviderBinding(
    providerBindingInput({
      providerPolicy: {
        allowedProviders: ['railway'],
      },
      bindingCycle: {
        productionTrustClaim: true,
      },
      providerBinding: {
        provider: 'unsupported-cloud',
        endpointSelected: true,
      },
      bindingDomains: bindingDomains().filter((entry) => entry.domain !== 'secret_scope_binding'),
      operationsReadiness: {
        activationBlockerIds: ['ESC-OPS-SECRETS', 'ESC-UNBOUNDED-PROVIDER'],
      },
      runtimeBinding: {
        browserAuthoritativePathEnabled: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.providerBinding, null);
  assert.ok(result.reasons.includes('binding_domain_missing:secret_scope_binding'));
  assert.ok(result.reasons.includes('provider_not_allowed:unsupported-cloud'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('endpoint_selected_without_verified_provider'));
  assert.ok(result.reasons.includes('operations_blocker_not_allowed:ESC-UNBOUNDED-PROVIDER'));
  assert.ok(result.reasons.includes('browser_authoritative_path_forbidden'));
});

test('deployment provider binding validates HLC ordering and AI advisory boundaries', async () => {
  const { evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const validSameTick = evaluateDeploymentProviderBinding(
    providerBindingInput({
      bindingCycle: {
        humanReviewedAtHlc: { physicalMs: 1800003400000, logical: 2 },
        auditRecordedAtHlc: { physicalMs: 1800003400000, logical: 3 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800003400000, logical: 2 },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1800003400000, logical: 3 },
      },
    }),
  );

  assert.equal(validSameTick.decision, 'permitted');

  const invalid = evaluateDeploymentProviderBinding(
    providerBindingInput({
      bindingCycle: {
        validationRecordedAtHlc: { physicalMs: 1800003190000, logical: 0 },
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1800003300000, logical: -1 },
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
  assert.ok(invalid.reasons.includes('binding_cycle_validationRecordedAtHlc_before_evidenceCollectedAtHlc'));
  assert.ok(invalid.reasons.includes('validation_time_invalid'));
  assert.ok(invalid.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(invalid.reasons.includes('ai_human_review_absent'));
  assert.ok(invalid.reasons.includes('human_review_authority_absent'));
});

test('deployment provider binding handles absent objects as fail-closed denial states', async () => {
  const { evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const result = evaluateDeploymentProviderBinding({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:deployment-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['deployment_provider_binding_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('provider_policy_ref_absent'));
  assert.ok(result.reasons.includes('binding_cycle_ref_absent'));
  assert.ok(result.reasons.includes('provider_binding_absent'));
  assert.ok(result.reasons.includes('runtime_binding_absent'));
  assert.ok(result.reasons.includes('binding_domains_absent'));
  assert.ok(result.reasons.includes('operations_readiness_absent'));
  assert.ok(result.reasons.includes('validation_evidence_absent'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('provider_binding_audit_record_ref_absent'));
});

test('deployment provider binding rejects raw deployment content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDeploymentProviderBinding } = await loadDeploymentProviderBinding();

  const inert = providerBindingInput({
    providerBinding: {
      rawProviderStatus: false,
      apiKey: {},
    },
  });

  assert.equal(evaluateDeploymentProviderBinding(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateDeploymentProviderBinding(
        providerBindingInput({
          providerBinding: {
            rawProviderStatus: ['unredacted provider status output stays external'],
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentProviderBinding(
        providerBindingInput({
          runtimeBinding: {
            rawDeploymentConfig: 'Participant Alice Example must not appear in deployment provider config.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentProviderBinding(
        providerBindingInput({
          providerBinding: {
            apiKey: 'cm_live_secret_value',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentProviderBinding(
        providerBindingInput({
          humanReview: {
            token: 7,
          },
        }),
      ),
    ProtectedContentError,
  );
});
