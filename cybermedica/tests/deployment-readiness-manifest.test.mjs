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

const REQUIRED_ARTIFACT_FAMILIES = [
  'activation_gate_register',
  'council_escalation_register',
  'inactive_trust_state',
  'path_classification',
  'release_incident_linkage_register',
  'release_readiness_matrix',
  'requirement_traceability_matrix',
  'service_contract_publication',
  'validation_evidence',
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

const ALLOWED_ACTIVATION_BLOCKERS = ['PTAG-001', 'PTAG-008', 'PTAG-015', 'PTAG-016', 'PTAG-017'];

const ALLOWED_BOB_ESCALATIONS = [
  'ESC-HUMAN-PROOFING',
  'ESC-OPS-SECRETS',
  'ESC-ROOT-ARTIFACT-STORE',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-ROOT-ROSTER',
  'ESC-RUNTIME',
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

const REQUIRED_DASHBOARD_SIGNAL_FAMILIES = [
  'controlled_document_distribution',
  'documentation_publication',
  'manual_export',
  'orientation_assistant',
];

const REQUIRED_SERVICE_CONTRACT_META_LAYERS = [
  'ground_truth',
  'doctrine',
  'domain',
  'data',
  'doors',
  'documentation',
  'deployment',
  'drift',
];

const REQUIRED_SERVICE_CONTRACT_KINDS = [
  'adapter_contract',
  'deterministic_fixture',
  'documentation_contract',
  'evidence_receipt_contract',
  'fail_closed_boundary',
  'inactive_trust_state',
  'qms_workflow_contract',
];

const REQUIRED_DRIFT_STATE_TARGETS = ['passport', 'quality_state', 'readiness'];

async function loadDeploymentReadinessManifest() {
  try {
    return await import('../src/deployment-readiness-manifest.mjs');
  } catch (error) {
    assert.fail(`CyberMedica deployment readiness manifest module must exist and load: ${error.message}`);
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

function artifact(family, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    family,
    artifactRef: `artifact-${family}`,
    artifactHash: hashes[index],
    sourceRef:
      family === 'path_classification'
        ? 'docs/implementation/PATH_CLASSIFICATION.md'
        : `docs/context/${family}.md`,
    generatedAtHlc: { physicalMs: 1800001000000, logical: index },
    schemaRef: `cybermedica.${family}.v1`,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    trustState: 'inactive',
    ...overrides,
  };
}

function manifestArtifacts() {
  return REQUIRED_ARTIFACT_FAMILIES.map((family, index) => artifact(family, index));
}

function activationGate(gateId, status, index, overrides = {}) {
  return {
    gateId,
    status,
    requiredForProductionTrustClaim: true,
    blocksBaselineDevelopment: false,
    productionClaimActive: false,
    evidenceHash: status === 'verified' ? DIGEST_7 : null,
    reviewedAtHlc: { physicalMs: 1800001100000, logical: index },
    metadataOnly: true,
    ...overrides,
  };
}

function roleDashboardReadiness(overrides = {}) {
  const dashboardReceiptHashes = Object.fromEntries(
    DASHBOARD_ROLES.map((role, index) => [role, [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2][index]]),
  );
  const dashboardResultHashes = Object.fromEntries(
    DASHBOARD_ROLES.map((role, index) => [role, [DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_7, DIGEST_8, DIGEST_A, DIGEST_B][index]]),
  );

  return mergeDeep(
    {
      readinessSetId: 'role-dashboard-documentation-readiness-alpha',
      readinessSetHash: DIGEST_6,
      dashboardRolesCovered: DASHBOARD_ROLES,
      dashboardReceiptHashes,
      dashboardResultHashes,
      requiredSignalFamilies: REQUIRED_DASHBOARD_SIGNAL_FAMILIES,
      controlledDocumentDistributionReceiptHash: DIGEST_7,
      documentationPublicationReceiptHash: DIGEST_8,
      manualExportReceiptHash: DIGEST_A,
      orientationAssistantReceiptHash: DIGEST_B,
      acknowledgementRosterHash: DIGEST_C,
      roleAcknowledgementCoverageBasisPoints: 10_000,
      visibleWidgetCount: 78,
      suppressedWidgetCount: 0,
      allWidgetsCurrentVersion: true,
      effectiveUseAcknowledged: true,
      obsoleteVersionUseBlocked: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
      reviewedAtHlc: { physicalMs: 1800001290000, logical: 0 },
    },
    overrides,
  );
}

function serviceContractPublication(overrides = {}) {
  return mergeDeep(
    {
      publicationRef: 'service-contract-publication-alpha',
      publicationHash: DIGEST_9,
      receiptHash: DIGEST_7,
      receiptArtifactType: 'service_contract_publication',
      status: 'publishable',
      contractCount: REQUIRED_SERVICE_CONTRACT_META_LAYERS.length,
      metaLayersCovered: REQUIRED_SERVICE_CONTRACT_META_LAYERS,
      contractKindsCovered: REQUIRED_SERVICE_CONTRACT_KINDS,
      sourceEvidenceRefs: [
        'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
        'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
        'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
        'docs/implementation/PATH_CLASSIFICATION.md',
      ],
      exochainSourceReadOnly: true,
      exochainProductionClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800001290000, logical: 1 },
    },
    overrides,
  );
}

function driftStateUpdateEvidence(overrides = {}) {
  return mergeDeep(
    {
      driftLoopId: 'cmdrift_deployment_readiness_alpha',
      driftLoopHash: DIGEST_1,
      driftLoopReceiptHash: DIGEST_2,
      stateUpdateHash: DIGEST_3,
      stateUpdateTargets: REQUIRED_DRIFT_STATE_TARGETS,
      cqiCycleHash: DIGEST_4,
      cqiCycleReceiptHash: DIGEST_5,
      inquiryCqiBacklogReceiptHash: DIGEST_6,
      manualNavigationReady: true,
      manualNavigationEffectiveUseAcknowledged: true,
      roleManualCoverageReceiptHash: DIGEST_F,
      trustState: 'inactive',
      exochainProductionClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800001290000, logical: 2 },
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
        dashboardHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_E, DIGEST_F][index],
        trustStateViewHash: [DIGEST_F, DIGEST_E, DIGEST_6, DIGEST_5, DIGEST_4, DIGEST_3, DIGEST_2, DIGEST_1][index],
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
      reviewedAtHlc: { physicalMs: 1800001290000, logical: 3 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    overrides,
  );
}

function manifestInput(overrides = {}) {
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
      permissions: ['deployment_readiness_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    manifestPolicy: {
      policyRef: 'deployment-readiness-manifest-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredArtifactFamilies: REQUIRED_ARTIFACT_FAMILIES,
      allowedActivationBlockerIds: ALLOWED_ACTIVATION_BLOCKERS,
      allowedBobEscalationIds: ALLOWED_BOB_ESCALATIONS,
      requiredSourceRefs: [
        'README.md',
        'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
        'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
        'docs/implementation/PATH_CLASSIFICATION.md',
      ],
      rootVerificationRequiredForTrustClaims: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800000900000, logical: 0 },
    },
    manifestCycle: {
      manifestRef: 'deployment-readiness-manifest-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800000950000, logical: 0 },
      evidenceImportedAtHlc: { physicalMs: 1800001000000, logical: 8 },
      validationRecordedAtHlc: { physicalMs: 1800001200000, logical: 0 },
      manifestCompiledAtHlc: { physicalMs: 1800001300000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800001400000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800001500000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    artifacts: manifestArtifacts(),
    releaseReadiness: {
      matrixId: 'cmrel-release-readiness-alpha',
      matrixHash: DIGEST_C,
      decision: 'baseline_ready_inactive_trust',
      acceptanceDomainsCovered: ['service_contracts', 'test_validation', 'metadata_only_boundaries'],
      unverifiedProductionGateCount: 16,
      verifiedGateCount: 2,
      driftStateUpdateEvidence: driftStateUpdateEvidence(),
      roleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
      noProductionTrustClaim: true,
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800001300000, logical: 1 },
    },
    requirementTraceability: {
      matrixId: 'cmtrace-requirement-traceability-alpha',
      matrixHash: DIGEST_D,
      requirementCount: 13,
      implementedCount: 10,
      activationOnlyBlockerIds: ['PTAG-001', 'PTAG-008', 'PTAG-015'],
      bobEscalationIds: ['ESC-ROOT-ROSTER', 'ESC-ROOT-DEPLOYMENT', 'ESC-RUNTIME'],
      validationCommandRefs: ['npm run quality'],
      noExochainSourceModified: true,
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800001300000, logical: 2 },
    },
    releaseIncidentLinkage: {
      linkageRegisterRef: 'cmril-release-incident-linkage-alpha',
      linkageRegisterHash: DIGEST_9,
      receiptHash: DIGEST_8,
      receiptArtifactType: 'release_incident_linkage_register',
      status: 'release_incident_linkage_accepted_inactive_trust',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      deploymentManifestRef: 'deployment-readiness-manifest-alpha',
      incidentFamiliesCovered: REQUIRED_INCIDENT_FAMILIES,
      releaseLinkageDomainsCovered: REQUIRED_RELEASE_LINKAGE_DOMAINS,
      materialIncidentCount: 4,
      openMaterialIncidentCount: 0,
      blockingIncidentRefs: [],
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
      reviewedAtHlc: { physicalMs: 1800001300000, logical: 3 },
    },
    serviceContractPublication: serviceContractPublication(),
    activationGates: [
      activationGate('PTAG-001', 'inactive', 0),
      activationGate('PTAG-008', 'inactive', 1),
      activationGate('PTAG-015', 'inactive', 2),
      activationGate('PTAG-016', 'inactive', 3),
      activationGate('PTAG-017', 'inactive', 4),
    ],
    deploymentConfiguration: {
      topologyRef: 'server-side-gateway-node-baseline',
      topologyHash: DIGEST_E,
      runtimeEndpointSelected: false,
      rootBundleProviderSelected: false,
      secretScopeSeparated: true,
      missingSecretsFailClosed: true,
      browserPhiTrustPathDisabled: true,
      rollbackPathRef: 'disable-production-trust-claims',
      rollbackPathHash: DIGEST_F,
      metadataOnly: true,
      reviewedAtHlc: { physicalMs: 1800001300000, logical: 3 },
    },
    validationEvidence: {
      commandRefs: ['npm test -- --test-reporter=spec', 'npm run quality'],
      commandsPassed: true,
      testCount: 314,
      coverageLineBasisPoints: 9972,
      sourceGuardPassed: true,
      pathClassificationHash: DIGEST_1,
      moduleManifestHash: DIGEST_2,
      testManifestHash: DIGEST_3,
      noExochainSourceModified: true,
      metadataOnly: true,
      recordedAtHlc: { physicalMs: 1800001200000, logical: 0 },
    },
    roleDashboardReadiness: roleDashboardReadiness(),
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'manifest_accepted_inactive_trust',
      decisionHash: DIGEST_4,
      noProductionTrustClaim: true,
      activationOnlyBlockersAccepted: true,
      bobEscalationsNarrowed: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800001400000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'deployment-readiness-audit-alpha',
      auditRecordHash: DIGEST_5,
      receiptRecordedAtHlc: { physicalMs: 1800001500000, logical: 0 },
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

test('deployment readiness manifest packages traceability release validation and inactive trust evidence deterministically', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const resultA = evaluateDeploymentReadinessManifest(manifestInput());
  const resultB = evaluateDeploymentReadinessManifest(
    manifestInput({
      manifestPolicy: {
        requiredArtifactFamilies: [...REQUIRED_ARTIFACT_FAMILIES].reverse(),
        allowedActivationBlockerIds: [...ALLOWED_ACTIVATION_BLOCKERS].reverse(),
        allowedBobEscalationIds: [...ALLOWED_BOB_ESCALATIONS].reverse(),
      },
      artifacts: [...manifestArtifacts()].reverse(),
      requirementTraceability: {
        activationOnlyBlockerIds: ['PTAG-015', 'PTAG-001', 'PTAG-008'],
        bobEscalationIds: ['ESC-RUNTIME', 'ESC-ROOT-ROSTER', 'ESC-ROOT-DEPLOYMENT'],
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.manifest.trustState, 'inactive');
  assert.equal(resultA.manifest.exochainProductionClaim, false);
  assert.equal(resultA.manifest.productionActivationReady, false);
  assert.equal(resultA.manifest.baselineEvidencePackReady, true);
  assert.equal(resultA.manifest.pathClassificationIncluded, true);
  assert.equal(resultA.manifest.roleDashboardDocumentationReady, true);
  assert.deepEqual(resultA.manifest.roleDashboardReadinessSummary.dashboardRolesCovered, DASHBOARD_ROLES);
  assert.deepEqual(resultA.manifest.roleDashboardReadinessSummary.requiredSignalFamilies, REQUIRED_DASHBOARD_SIGNAL_FAMILIES);
  assert.equal(resultA.manifest.roleDashboardReadinessSummary.controlledDocumentDistributionReceiptHash, DIGEST_7);
  assert.equal(resultA.manifest.roleDashboardReadinessSummary.orientationAssistantReceiptHash, DIGEST_B);
  assert.equal(resultA.manifest.releaseReadinessSummary.driftStateUpdateEvidence.driftLoopReceiptHash, DIGEST_2);
  assert.equal(resultA.manifest.releaseReadinessSummary.driftStateUpdateEvidence.stateUpdateHash, DIGEST_3);
  assert.equal(resultA.manifest.releaseReadinessSummary.driftStateUpdateEvidence.cqiCycleReceiptHash, DIGEST_5);
  assert.equal(resultA.manifest.releaseReadinessSummary.driftStateUpdateEvidence.inquiryCqiBacklogReceiptHash, DIGEST_6);
  assert.equal(resultA.manifest.releaseReadinessSummary.driftStateUpdateEvidence.roleManualCoverageReceiptHash, DIGEST_F);
  assert.deepEqual(
    resultA.manifest.releaseReadinessSummary.driftStateUpdateEvidence.stateUpdateTargets,
    REQUIRED_DRIFT_STATE_TARGETS,
  );
  assert.deepEqual(resultA.manifest.releaseReadinessSummary.roleDashboardTrustStateEvidence, {
    activationLineageAccepted: true,
    canShowProductionTrustClaim: false,
    dashboardHashRefs: DASHBOARD_ROLES.map((role, index) => ({
      dashboardHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_E, DIGEST_F][index],
      role,
      trustStateViewHash: [DIGEST_F, DIGEST_E, DIGEST_6, DIGEST_5, DIGEST_4, DIGEST_3, DIGEST_2, DIGEST_1][index],
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
  assert.deepEqual(resultA.manifest.artifactFamiliesCovered, REQUIRED_ARTIFACT_FAMILIES);
  assert.equal(resultA.manifest.releaseIncidentLinkageSummary.receiptHash, DIGEST_8);
  assert.equal(resultA.manifest.releaseIncidentLinkageSummary.openMaterialIncidentCount, 0);
  assert.deepEqual(resultA.manifest.releaseIncidentLinkageSummary.releaseLinkageDomainsCovered, REQUIRED_RELEASE_LINKAGE_DOMAINS);
  assert.equal(resultA.manifest.serviceContractPublicationReady, true);
  assert.equal(resultA.manifest.serviceContractPublicationSummary.receiptHash, DIGEST_7);
  assert.deepEqual(
    resultA.manifest.serviceContractPublicationSummary.metaLayersCovered,
    REQUIRED_SERVICE_CONTRACT_META_LAYERS,
  );
  assert.deepEqual(
    resultA.manifest.serviceContractPublicationSummary.contractKindsCovered,
    REQUIRED_SERVICE_CONTRACT_KINDS,
  );
  assert.deepEqual(resultA.manifest.activationOnlyBlockerIds, ['PTAG-001', 'PTAG-008', 'PTAG-015']);
  assert.deepEqual(resultA.manifest.bobEscalationIds, ['ESC-ROOT-DEPLOYMENT', 'ESC-ROOT-ROSTER', 'ESC-RUNTIME']);
  assert.equal(resultA.manifest.activationSummary.unverifiedProductionGateCount, 5);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'deployment_readiness_manifest');
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('drift_state_update'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('continuous_quality_improvement'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('manual_navigation_readiness'));
  assert.ok(resultA.receipt.anchorPayload.sensitivityTags.includes('role_dashboard_trust_state'));
  assert.deepEqual(resultA, resultB);
});

test('deployment readiness manifest requires release-readiness role-dashboard trust-state lineage before packaging', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const missing = evaluateDeploymentReadinessManifest(
    manifestInput({
      releaseReadiness: {
        roleDashboardTrustStateEvidence: null,
      },
    }),
  );
  const unsafe = evaluateDeploymentReadinessManifest(
    manifestInput({
      releaseReadiness: {
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
          productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: 'bad-runtime-provider-view',
          productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_4,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_5,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: 'bad-runtime-readiness-view',
          productionClaimLiftRoleDashboardRoles: DASHBOARD_ROLES.filter((role) => role !== 'sponsor_viewer').concat(
            'marketing_admin',
          ),
          metadataOnly: false,
          protectedContentExcluded: false,
          reviewedAtHlc: { physicalMs: 1800001310000, logical: 0 },
        }),
      },
    }),
  );
  const mismatch = evaluateDeploymentReadinessManifest(
    manifestInput({
      releaseReadiness: {
        roleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence({
          productionClaimLiftRoleDashboardProviderReceiptHash: DIGEST_4,
          productionClaimLiftRoleDashboardProviderSummaryHash: DIGEST_5,
          productionClaimLiftRoleDashboardProviderTrustStateViewHash: DIGEST_6,
          productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_D,
          productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
          productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_4,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_1,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_2,
          productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_5,
        }),
      },
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.failClosed, true);
  assert.ok(missing.reasons.includes('release_readiness_role_dashboard_trust_state_evidence_absent'));
  assert.ok(missing.reasons.includes('release_readiness_role_dashboard_summary_hash_invalid'));

  assert.equal(unsafe.decision, 'denied');
  assert.equal(unsafe.failClosed, true);
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_trust_state_view_hash_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_role_missing:sponsor_viewer'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_hash_ref_role_unsupported:unapproved_role'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_hash_ref_missing:auditor'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_activation_lineage_absent'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_public_claim_review_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_production_claim_lift_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_production_claim_lift_state_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_production_claim_lift_forbidden'));
  assert.ok(
    unsafe.reasons.includes('release_readiness_role_dashboard_production_claim_lift_provider_receipt_hash_invalid'),
  );
  assert.ok(
    unsafe.reasons.includes('release_readiness_role_dashboard_production_claim_lift_provider_summary_hash_invalid'),
  );
  assert.ok(
    unsafe.reasons.includes(
      'release_readiness_role_dashboard_production_claim_lift_provider_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes('release_readiness_role_dashboard_production_claim_lift_readiness_receipt_hash_invalid'),
  );
  assert.ok(
    unsafe.reasons.includes('release_readiness_role_dashboard_production_claim_lift_readiness_summary_hash_invalid'),
  );
  assert.ok(
    unsafe.reasons.includes(
      'release_readiness_role_dashboard_production_claim_lift_readiness_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'release_readiness_role_dashboard_production_claim_lift_runtime_source_provider_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'release_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_production_claim_lift_role_missing:sponsor_viewer'));
  assert.ok(
    unsafe.reasons.includes('release_readiness_role_dashboard_production_claim_lift_role_unsupported:marketing_admin'),
  );
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_role_dashboard_review_after_release_review'));

  assert.equal(mismatch.decision, 'denied');
  assert.equal(mismatch.failClosed, true);
  assert.ok(
    mismatch.reasons.includes('release_readiness_role_dashboard_production_claim_lift_provider_receipt_mismatch'),
  );
  assert.ok(
    mismatch.reasons.includes('release_readiness_role_dashboard_production_claim_lift_provider_summary_mismatch'),
  );
  assert.ok(
    mismatch.reasons.includes('release_readiness_role_dashboard_production_claim_lift_provider_trust_state_view_mismatch'),
  );
  assert.ok(
    mismatch.reasons.includes(
      'release_readiness_role_dashboard_production_claim_lift_runtime_source_provider_receipt_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'release_readiness_role_dashboard_production_claim_lift_runtime_source_provider_summary_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'release_readiness_role_dashboard_production_claim_lift_runtime_source_provider_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'release_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_receipt_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'release_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_summary_mismatch',
    ),
  );
  assert.ok(
    mismatch.reasons.includes(
      'release_readiness_role_dashboard_production_claim_lift_runtime_source_readiness_trust_state_view_mismatch',
    ),
  );
});

test('deployment readiness manifest requires release readiness Drift state-update lineage before packaging', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const missing = evaluateDeploymentReadinessManifest(
    manifestInput({
      releaseReadiness: {
        driftStateUpdateEvidence: null,
      },
    }),
  );
  const unsafe = evaluateDeploymentReadinessManifest(
    manifestInput({
      releaseReadiness: {
        driftStateUpdateEvidence: driftStateUpdateEvidence({
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
          reviewedAtHlc: { physicalMs: 1800001310000, logical: 0 },
        }),
      },
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.failClosed, true);
  assert.ok(missing.reasons.includes('release_readiness_drift_state_update_absent'));
  assert.ok(missing.reasons.includes('release_readiness_drift_loop_receipt_hash_invalid'));
  assert.ok(missing.reasons.includes('release_readiness_drift_state_update_hash_invalid'));

  assert.equal(unsafe.decision, 'denied');
  assert.ok(unsafe.reasons.includes('release_readiness_drift_loop_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_state_update_hash_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_cqi_cycle_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_inquiry_cqi_backlog_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_manual_navigation_ready_absent'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_manual_navigation_effective_use_absent'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_role_manual_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_state_update_target_missing:passport'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_state_update_target_missing:quality_state'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_state_update_target_unsupported:unsupported_target'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_state_update_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_state_update_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_state_update_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_state_update_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('release_readiness_drift_state_update_after_release_review'));
});

test('deployment readiness manifest requires service contract publication evidence before packaging', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const missing = evaluateDeploymentReadinessManifest(
    manifestInput({
      artifacts: manifestArtifacts().filter((item) => item.family !== 'service_contract_publication'),
      serviceContractPublication: null,
    }),
  );
  const unsafe = evaluateDeploymentReadinessManifest(
    manifestInput({
      serviceContractPublication: serviceContractPublication({
        receiptHash: 'not-a-digest',
        receiptArtifactType: 'deployment_readiness_manifest',
        status: 'blocked',
        contractCount: 7,
        metaLayersCovered: REQUIRED_SERVICE_CONTRACT_META_LAYERS.filter((layer) => layer !== 'drift'),
        contractKindsCovered: REQUIRED_SERVICE_CONTRACT_KINDS.filter((kind) => kind !== 'fail_closed_boundary'),
        exochainSourceReadOnly: false,
        exochainProductionClaim: true,
        metadataOnly: false,
        protectedContentExcluded: false,
        reviewedAtHlc: { physicalMs: 1800001310000, logical: 0 },
      }),
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.ok(missing.reasons.includes('artifact_family_missing:service_contract_publication'));
  assert.ok(missing.reasons.includes('service_contract_publication_absent'));
  assert.ok(missing.reasons.includes('service_contract_publication_ref_absent'));

  assert.equal(unsafe.decision, 'denied');
  assert.ok(unsafe.reasons.includes('service_contract_publication_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('service_contract_publication_receipt_type_invalid'));
  assert.ok(unsafe.reasons.includes('service_contract_publication_status_invalid'));
  assert.ok(unsafe.reasons.includes('service_contract_publication_contract_count_invalid'));
  assert.ok(unsafe.reasons.includes('service_contract_publication_meta_layer_missing:drift'));
  assert.ok(unsafe.reasons.includes('service_contract_publication_contract_kind_missing:fail_closed_boundary'));
  assert.ok(unsafe.reasons.includes('service_contract_publication_exochain_read_only_absent'));
  assert.ok(unsafe.reasons.includes('service_contract_publication_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('service_contract_publication_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('service_contract_publication_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('service_contract_publication_after_manifest_compile'));
});

test('deployment readiness manifest requires release incident linkage before packaging', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const missing = evaluateDeploymentReadinessManifest(
    manifestInput({
      artifacts: manifestArtifacts().filter((item) => item.family !== 'release_incident_linkage_register'),
      releaseIncidentLinkage: null,
    }),
  );
  const openIncident = evaluateDeploymentReadinessManifest(
    manifestInput({
      releaseIncidentLinkage: {
        receiptHash: 'not-a-digest',
        receiptArtifactType: 'incident_summary',
        releaseCandidateRef: 'different-release',
        deploymentManifestRef: 'other-manifest',
        incidentFamiliesCovered: REQUIRED_INCIDENT_FAMILIES.filter((family) => family !== 'receipt_queue_backlog'),
        releaseLinkageDomainsCovered: REQUIRED_RELEASE_LINKAGE_DOMAINS.filter(
          (domain) => domain !== 'deployment_manifest_update',
        ),
        openMaterialIncidentCount: 1,
        blockingIncidentRefs: ['INC-0001-privacy_boundary_failure'],
        productionTrustClaim: true,
        reviewedAtHlc: { physicalMs: 1800001200000, logical: 0 },
      },
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.ok(missing.reasons.includes('artifact_family_missing:release_incident_linkage_register'));
  assert.ok(missing.reasons.includes('release_incident_linkage_absent'));
  assert.ok(missing.reasons.includes('release_incident_linkage_ref_absent'));

  assert.equal(openIncident.decision, 'denied');
  assert.ok(openIncident.reasons.includes('release_incident_linkage_receipt_hash_invalid'));
  assert.ok(openIncident.reasons.includes('release_incident_linkage_receipt_type_invalid'));
  assert.ok(openIncident.reasons.includes('release_incident_linkage_release_candidate_mismatch'));
  assert.ok(openIncident.reasons.includes('release_incident_linkage_manifest_ref_mismatch'));
  assert.ok(openIncident.reasons.includes('release_incident_family_missing:receipt_queue_backlog'));
  assert.ok(openIncident.reasons.includes('release_linkage_domain_missing:deployment_manifest_update'));
  assert.ok(openIncident.reasons.includes('release_incident_open_material_incidents'));
  assert.ok(openIncident.reasons.includes('release_incident_blocking_refs_present'));
  assert.ok(openIncident.reasons.includes('release_incident_linkage_production_claim_forbidden'));
  assert.ok(openIncident.reasons.includes('release_incident_linkage_review_before_manifest_compile'));
});

test('deployment readiness manifest fails closed for missing evidence families and broad escalations', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const result = evaluateDeploymentReadinessManifest(
    manifestInput({
      artifacts: manifestArtifacts().filter((item) => item.family !== 'path_classification'),
      requirementTraceability: {
        bobEscalationIds: ['ESC-RUNTIME', 'ESC-UNBOUNDED-PRODUCT-SCOPE'],
        activationOnlyBlockerIds: ['PTAG-001', 'PTAG-999'],
      },
      releaseReadiness: {
        noProductionTrustClaim: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.manifest, null);
  assert.ok(result.reasons.includes('artifact_family_missing:path_classification'));
  assert.ok(result.reasons.includes('activation_blocker_not_allowed:PTAG-999'));
  assert.ok(result.reasons.includes('bob_escalation_not_allowed:ESC-UNBOUNDED-PRODUCT-SCOPE'));
  assert.ok(result.reasons.includes('release_readiness_production_claim_forbidden'));
});

test('deployment readiness manifest requires role dashboard documentation readiness before packaging', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const missing = evaluateDeploymentReadinessManifest(
    manifestInput({
      roleDashboardReadiness: null,
    }),
  );
  const unsafe = evaluateDeploymentReadinessManifest(
    manifestInput({
      roleDashboardReadiness: roleDashboardReadiness({
        dashboardRolesCovered: DASHBOARD_ROLES.filter((role) => role !== 'auditor'),
        dashboardReceiptHashes: {
          ...roleDashboardReadiness().dashboardReceiptHashes,
          quality_manager: 'not-a-digest',
        },
        dashboardResultHashes: {
          ...roleDashboardReadiness().dashboardResultHashes,
          site_leader: null,
        },
        requiredSignalFamilies: REQUIRED_DASHBOARD_SIGNAL_FAMILIES.filter((family) => family !== 'orientation_assistant'),
        documentationPublicationReceiptHash: null,
        manualExportReceiptHash: 'bad',
        roleAcknowledgementCoverageBasisPoints: 9_999,
        allWidgetsCurrentVersion: false,
        effectiveUseAcknowledged: false,
        obsoleteVersionUseBlocked: false,
        metadataOnly: false,
        protectedContentExcluded: false,
        productionTrustClaim: true,
        reviewedAtHlc: { physicalMs: 1800001300000, logical: 1 },
      }),
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.manifest, null);
  assert.ok(missing.reasons.includes('role_dashboard_readiness_absent'));
  assert.ok(missing.reasons.includes('role_dashboard_readiness_id_absent'));

  assert.equal(unsafe.decision, 'denied');
  assert.equal(unsafe.manifest, null);
  assert.ok(unsafe.reasons.includes('role_dashboard_role_missing:auditor'));
  assert.ok(unsafe.reasons.includes('role_dashboard_receipt_hash_invalid:quality_manager'));
  assert.ok(unsafe.reasons.includes('role_dashboard_result_hash_invalid:site_leader'));
  assert.ok(unsafe.reasons.includes('role_dashboard_signal_family_missing:orientation_assistant'));
  assert.ok(unsafe.reasons.includes('role_dashboard_documentation_publication_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('role_dashboard_manual_export_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('role_dashboard_acknowledgement_coverage_incomplete'));
  assert.ok(unsafe.reasons.includes('role_dashboard_current_version_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('role_dashboard_effective_use_acknowledgement_absent'));
  assert.ok(unsafe.reasons.includes('role_dashboard_obsolete_version_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('role_dashboard_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('role_dashboard_protected_content_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('role_dashboard_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('role_dashboard_readiness_after_manifest_compile'));
});

test('deployment readiness manifest blocks production activation claims until gates and deployment endpoints verify', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const result = evaluateDeploymentReadinessManifest(
    manifestInput({
      manifestCycle: {
        productionTrustClaim: true,
      },
      activationGates: [
        activationGate('PTAG-001', 'verified', 0, {
          productionClaimActive: true,
          evidenceHash: DIGEST_A,
        }),
        activationGate('PTAG-008', 'inactive', 1),
      ],
      deploymentConfiguration: {
        secretScopeSeparated: false,
        missingSecretsFailClosed: false,
        browserPhiTrustPathDisabled: false,
      },
      humanReview: {
        decision: 'production_trust_active',
        noProductionTrustClaim: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('activation_gate_active_claim_forbidden:PTAG-001'));
  assert.ok(result.reasons.includes('activation_gate_missing:PTAG-015'));
  assert.ok(result.reasons.includes('secret_scope_not_separated'));
  assert.ok(result.reasons.includes('missing_secret_fail_closed_absent'));
  assert.ok(result.reasons.includes('browser_phi_trust_path_enabled'));
  assert.ok(result.reasons.includes('human_review_production_trust_forbidden'));
});

test('deployment readiness manifest validates HLC ordering and AI advisory boundaries', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const validSameTick = evaluateDeploymentReadinessManifest(
    manifestInput({
      manifestCycle: {
        humanReviewedAtHlc: { physicalMs: 1800001400000, logical: 2 },
        auditRecordedAtHlc: { physicalMs: 1800001400000, logical: 3 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800001400000, logical: 2 },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1800001400000, logical: 3 },
      },
    }),
  );

  assert.equal(validSameTick.decision, 'permitted');

  const invalid = evaluateDeploymentReadinessManifest(
    manifestInput({
      manifestCycle: {
        manifestCompiledAtHlc: { physicalMs: 1800001190000, logical: 0 },
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1800001200000, logical: -1 },
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
  assert.ok(invalid.reasons.includes('manifest_cycle_manifestCompiledAtHlc_before_validationRecordedAtHlc'));
  assert.ok(invalid.reasons.includes('validation_time_invalid'));
  assert.ok(invalid.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(invalid.reasons.includes('ai_human_review_absent'));
  assert.ok(invalid.reasons.includes('human_review_authority_absent'));
});

test('deployment readiness manifest handles absent objects as fail-closed denial states', async () => {
  const { evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const result = evaluateDeploymentReadinessManifest({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['deployment_readiness_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('manifest_policy_ref_absent'));
  assert.ok(result.reasons.includes('manifest_cycle_ref_absent'));
  assert.ok(result.reasons.includes('manifest_artifacts_absent'));
  assert.ok(result.reasons.includes('release_readiness_absent'));
  assert.ok(result.reasons.includes('requirement_traceability_absent'));
  assert.ok(result.reasons.includes('validation_evidence_absent'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('manifest_audit_record_ref_absent'));
});

test('deployment readiness manifest rejects raw manifest content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDeploymentReadinessManifest } = await loadDeploymentReadinessManifest();

  const inert = manifestInput({
    artifacts: [
      artifact('activation_gate_register', 0, { rawManifestContent: false }),
      ...manifestArtifacts().slice(1),
    ],
    deploymentConfiguration: {
      apiKey: {},
    },
  });

  assert.equal(evaluateDeploymentReadinessManifest(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateDeploymentReadinessManifest(
        manifestInput({
          artifacts: [
            artifact('activation_gate_register', 0, {
              rawManifestContent: 'full release evidence packet body stays outside receipts',
            }),
            ...manifestArtifacts().slice(1),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentReadinessManifest(
        manifestInput({
          deploymentConfiguration: {
            freeTextNote: 'Participant Alice Example has an unredacted medical record note.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentReadinessManifest(
        manifestInput({
          deploymentConfiguration: {
            apiKey: 'cm_live_secret_value',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentReadinessManifest(
        manifestInput({
          artifacts: [
            artifact('activation_gate_register', 0, {
              rawManifestContent: ['release evidence packet text stays external'],
            }),
            ...manifestArtifacts().slice(1),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentReadinessManifest(
        manifestInput({
          serviceContractPublication: {
            rawServiceContractBody: 'service contract publication source text remains outside manifest receipts',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDeploymentReadinessManifest(
        manifestInput({
          humanReview: {
            secret: 7,
          },
        }),
      ),
    ProtectedContentError,
  );
});
