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

const REQUIRED_PRIVACY_FIXTURE_SURFACE_FAMILIES = [
  'audit_log_record',
  'dag_payload',
  'debug_response',
  'export_manifest',
  'health_response',
  'receipt_anchor',
  'telemetry_event',
];

const REQUIRED_PRIVACY_FIXTURE_DETECTOR_RULE_IDS = [
  'hash_only_metadata_required',
  'protected_field_name',
  'protected_text_pattern',
  'secret_field_name',
  'secret_text_pattern',
  'unscoped_payload_field',
];

const REQUIRED_ROLE_DASHBOARD_ROLES = [
  'auditor',
  'coordinator',
  'cro_portfolio_manager',
  'decision_forum',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_viewer',
];

async function loadProductionClaimLifting() {
  try {
    return await import('../src/production-claim-lifting.mjs');
  } catch (error) {
    assert.fail(`CyberMedica production claim lifting module must exist and load: ${error.message}`);
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

function claimLiftInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:site-leader-alpha',
      kind: 'human',
      roleRefs: ['site_leader', 'quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['production_claim_lift', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    sourceTruth: {
      exochainSourcePath: '/Users/bobstewart/dev/exochain/exochain',
      branchRef: 'main',
      commitHash: '1234567890abcdef1234567890abcdef12345678',
      repoTruthCommandRef: 'tools/repo_truth.sh --json --list-tests',
      repoTruthHash: DIGEST_B,
      currentAgainstLocalCommit: true,
      workingTreeClean: true,
      noExochainSourceModified: true,
      checkedAtHlc: { physicalMs: 1800010000000, logical: 0 },
      metadataOnly: true,
    },
    runtimePath: {
      runtimePathRef: 'server-side-gateway-node-root-verifier',
      runtimePathHash: DIGEST_C,
      enabled: true,
      serverSideOnly: true,
      browserAuthoritative: false,
      gatewayAdapterVerified: true,
      nodeReceiptPathVerified: true,
      decisionForumPathVerified: true,
      rootVerifierPathVerified: true,
      identifiedAtHlc: { physicalMs: 1800010100000, logical: 0 },
      metadataOnly: true,
    },
    deploymentConfiguration: {
      deploymentConfigRef: 'cybermedica-production-runtime-topology-alpha',
      deploymentConfigHash: DIGEST_D,
      productionEnvironmentIdentified: true,
      endpointRef: 'railway-production-private-endpoint-ref',
      rootBundleProviderRef: 'root-bundle-provider-alpha',
      secretScopeSeparated: true,
      missingSecretsFailClosed: true,
      rollbackDisablementRef: 'disable-exochain-production-claim-language',
      identifiedAtHlc: { physicalMs: 1800010200000, logical: 0 },
      metadataOnly: true,
    },
    deploymentHandoffCutover: {
      handoffRef: 'deployment-handoff-cutover-alpha',
      handoffHash: DIGEST_9,
      receiptHash: DIGEST_A,
      receiptArtifactType: 'deployment_handoff_cutover',
      status: 'deployment_handoff_cutover_ready_verified_runtime',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      deploymentConfigHash: DIGEST_D,
      baselineHandoffReady: true,
      productionCutoverReady: true,
      trustState: 'inactive',
      exochainProductionClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800010250000, logical: 0 },
    },
    adapterActivationEvidence: {
      evidencePackageId: 'cmaae_adapter_activation_alpha',
      evidencePackageHash: DIGEST_2,
      receiptHash: DIGEST_5,
      receiptArtifactType: 'adapter_activation_evidence',
      status: 'ready_for_claim_lift_request',
      trustState: 'inactive',
      canRequestProductionClaimLift: true,
      canShowProductionTrustClaim: false,
      exochainProductionClaim: false,
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      runtimePathRef: 'server-side-gateway-node-root-verifier',
      deploymentHandoffCutoverHash: DIGEST_9,
      deploymentHandoffCutoverReceiptHash: DIGEST_A,
      deploymentHandoffCutoverProviderRoleDashboardReceiptHash: DIGEST_B,
      deploymentHandoffCutoverProviderRoleDashboardSummaryHash: DIGEST_C,
      deploymentHandoffCutoverProviderRoleDashboardTrustStateViewHash: DIGEST_D,
      deploymentHandoffCutoverReadinessRoleDashboardReceiptHash: DIGEST_E,
      deploymentHandoffCutoverReadinessRoleDashboardSummaryHash: DIGEST_F,
      deploymentHandoffCutoverReadinessRoleDashboardTrustStateViewHash: DIGEST_1,
      deploymentHandoffCutoverRoleDashboardRoles: REQUIRED_ROLE_DASHBOARD_ROLES,
      runtimeConfigurationHash: DIGEST_8,
      runtimeConfigurationSourceReceiptHash: DIGEST_7,
      runtimeConfigurationSourceHandoffProviderRoleDashboardReceiptHash: DIGEST_B,
      runtimeConfigurationSourceHandoffProviderRoleDashboardSummaryHash: DIGEST_C,
      runtimeConfigurationSourceHandoffProviderRoleDashboardTrustStateViewHash: DIGEST_D,
      runtimeConfigurationSourceHandoffReadinessRoleDashboardReceiptHash: DIGEST_E,
      runtimeConfigurationSourceHandoffReadinessRoleDashboardSummaryHash: DIGEST_F,
      runtimeConfigurationSourceHandoffReadinessRoleDashboardTrustStateViewHash: DIGEST_1,
      productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_B,
      productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
      productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_D,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_E,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_F,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_1,
      actionHash: DIGEST_1,
      activationGateIds: ['PTAG-001', 'PTAG-005', 'PTAG-006', 'PTAG-016', 'PTAG-017'],
      componentStates: {
        decisionForum: 'verified',
        deploymentHandoffCutover: 'verified',
        gateway: 'verified',
        nodeReceipt: 'verified',
        privacyBoundary: 'verified',
        rootBundle: 'verified',
        runtimeConfigurationSource: 'verified',
      },
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800010270000, logical: 0 },
    },
    adapterBoundary: {
      boundaryRef: 'adapter-boundary-alpha',
      boundaryHash: DIGEST_E,
      cannotSimulateCoreOutcome: true,
      cannotCacheCoreOutcome: true,
      cannotOverrideCoreOutcome: true,
      failsClosedOnUnavailable: true,
      failsClosedOnReject: true,
      failsClosedOnTimeout: true,
      failsClosedOnMalformed: true,
      immutableExternalReceiptRequired: true,
      verifiedAtHlc: { physicalMs: 1800010300000, logical: 0 },
      metadataOnly: true,
    },
    testMatrix: {
      matrixRef: 'claim-lift-test-matrix-alpha',
      matrixHash: DIGEST_F,
      positiveCasePassed: true,
      negativeCasePassed: true,
      unavailableCasePassed: true,
      malformedCasePassed: true,
      timeoutCasePassed: true,
      crossTenantCasePassed: true,
      privacyNonAnchoringCasePassed: true,
      commandRefs: ['npm run quality', 'cargo test --workspace'],
      testsRecordedAtHlc: { physicalMs: 1800010400000, logical: 0 },
      metadataOnly: true,
    },
    privacyBoundary: {
      privacyBoundaryRef: 'claim-lift-privacy-boundary-alpha',
      privacyBoundaryHash: DIGEST_1,
      noRawSensitiveInReceipts: true,
      noRawSensitiveInDag: true,
      noRawSensitiveInLogs: true,
      noRawSensitiveInTelemetry: true,
      noRawSensitiveInHealth: true,
      noRawSensitiveInDebug: true,
      noRawSensitiveInExports: true,
      fixtureScanPassed: true,
      classificationHash: DIGEST_2,
      privacyFixtureBoundary: {
        schema: 'cybermedica.privacy_fixture_boundary.v1',
        status: 'verified_metadata_only',
        receiptId: 'cmr_privacy_fixture_boundary_alpha',
        receiptActionHash: DIGEST_5,
        receiptArtifactType: 'privacy_fixture_boundary',
        fixtureProofHash: DIGEST_6,
        scanHash: DIGEST_7,
        surfaceFamilies: REQUIRED_PRIVACY_FIXTURE_SURFACE_FAMILIES,
        detectorRuleIds: REQUIRED_PRIVACY_FIXTURE_DETECTOR_RULE_IDS,
        trustState: 'inactive',
        exochainProductionClaim: false,
        metadataOnly: true,
        protectedContentExcluded: true,
        acceptedAtHlc: { physicalMs: 1800010500001, logical: 0 },
      },
      scannedAtHlc: { physicalMs: 1800010500000, logical: 0 },
      metadataOnly: true,
    },
    claimMapping: {
      gateId: 'PTAG-001',
      claimTextHash: DIGEST_3,
      mappedArtifactType: 'receipt',
      mappedArtifactHash: DIGEST_4,
      receiptId: 'receipt-root-production-claim-alpha',
      decisionId: null,
      custodyDigest: null,
      governanceOutcomeRef: null,
      noMarketingOverclaim: true,
      mappedAtHlc: { physicalMs: 1800010600000, logical: 0 },
      metadataOnly: true,
    },
    contextReview: {
      reviewRef: 'claim-lift-context-review-alpha',
      reviewHash: DIGEST_5,
      contextRefs: [
        'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
        'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
        'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      ],
      reviewedAgainstOriginalPrd: true,
      activationGateRegisterReviewed: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewedAtHlc: { physicalMs: 1800010700000, logical: 0 },
      metadataOnly: true,
    },
    humanDecision: {
      decisionRef: 'claim-lift-human-decision-alpha',
      decisionHash: DIGEST_6,
      decision: 'approve_production_claim_lift',
      reviewerDid: 'did:exo:site-leader-alpha',
      finalAuthority: 'human',
      decidedAtHlc: { physicalMs: 1800010800000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'claim-lift-audit-alpha',
      auditRecordHash: DIGEST_7,
      receiptRecordedAtHlc: { physicalMs: 1800010900000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    custodyDigest: DIGEST_8,
  };
  return mergeDeep(base, overrides);
}

test('production claim lifting criteria verify source runtime deployment tests privacy mapping and human review', async () => {
  const { evaluateProductionClaimLift } = await loadProductionClaimLifting();

  const resultA = evaluateProductionClaimLift(claimLiftInput());
  const resultB = evaluateProductionClaimLift(
    claimLiftInput({
      testMatrix: { commandRefs: ['cargo test --workspace', 'npm run quality'] },
      contextReview: {
        contextRefs: [
          'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
          'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
          'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
        ],
      },
      privacyBoundary: {
        privacyFixtureBoundary: {
          detectorRuleIds: [...REQUIRED_PRIVACY_FIXTURE_DETECTOR_RULE_IDS].reverse(),
          surfaceFamilies: [...REQUIRED_PRIVACY_FIXTURE_SURFACE_FAMILIES].reverse(),
        },
      },
    }),
  );

  assert.equal(resultA.schema, 'cybermedica.production_claim_lift_decision.v1');
  assert.equal(resultA.allowed, true);
  assert.equal(resultA.state, 'verified');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.canLiftProductionClaim, true);
  assert.equal(resultA.exochainProductionClaim, true);
  assert.equal(resultA.claimGateId, 'PTAG-001');
  assert.deepEqual(resultA.blockedBy, []);
  assert.deepEqual(resultA.verifiedCriteria, [
    'adapter_boundary',
    'claim_mapping',
    'context_review',
    'deployment_configuration',
    'deployment_handoff_cutover',
    'adapter_activation_evidence',
    'privacy_boundary',
    'runtime_path',
    'source_truth',
    'test_matrix',
  ]);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
  assert.equal(resultA.receipt.trustState, 'verified');
  assert.equal(resultA.receipt.exochainProductionClaim, true);
  assert.equal(resultA.receipt.anchorPayload.claimGateId, 'PTAG-001');
  assert.equal(resultA.receipt.anchorPayload.deploymentHandoffCutoverReceiptHash, DIGEST_A);
  assert.equal(resultA.receipt.anchorPayload.deploymentHandoffCutoverHash, DIGEST_9);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationEvidenceHash, DIGEST_2);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationReceiptHash, DIGEST_5);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationRuntimeConfigurationHash, DIGEST_8);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationRuntimeConfigurationSourceReceiptHash, DIGEST_7);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationHandoffProviderRoleDashboardReceiptHash, DIGEST_B);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationHandoffProviderRoleDashboardSummaryHash, DIGEST_C);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationHandoffProviderRoleDashboardTrustStateViewHash, DIGEST_D);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationHandoffReadinessRoleDashboardReceiptHash, DIGEST_E);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationHandoffReadinessRoleDashboardSummaryHash, DIGEST_F);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationHandoffReadinessRoleDashboardTrustStateViewHash, DIGEST_1);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationRuntimeSourceProviderRoleDashboardReceiptHash, DIGEST_B);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationRuntimeSourceProviderRoleDashboardSummaryHash, DIGEST_C);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash, DIGEST_D);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash, DIGEST_E);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash, DIGEST_F);
  assert.equal(resultA.receipt.anchorPayload.adapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash, DIGEST_1);
  assert.equal(
    resultA.receipt.anchorPayload.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    resultA.receipt.anchorPayload.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    DIGEST_C,
  );
  assert.equal(
    resultA.receipt.anchorPayload.adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    DIGEST_D,
  );
  assert.equal(
    resultA.receipt.anchorPayload.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    DIGEST_E,
  );
  assert.equal(
    resultA.receipt.anchorPayload.adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    DIGEST_F,
  );
  assert.equal(
    resultA.receipt.anchorPayload
      .adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    DIGEST_1,
  );
  assert.deepEqual(
    resultA.receipt.anchorPayload.adapterActivationDeploymentHandoffCutoverRoleDashboardRoles,
    REQUIRED_ROLE_DASHBOARD_ROLES,
  );
  assert.deepEqual(resultA.receipt.anchorPayload.adapterActivationGateIds, [
    'PTAG-001',
    'PTAG-005',
    'PTAG-006',
    'PTAG-016',
    'PTAG-017',
  ]);
  assert.equal(resultA.receipt.anchorPayload.privacyFixtureBoundaryReceiptId, 'cmr_privacy_fixture_boundary_alpha');
  assert.equal(resultA.receipt.anchorPayload.privacyFixtureBoundaryReceiptActionHash, DIGEST_5);
  assert.equal(resultA.receipt.anchorPayload.privacyFixtureBoundaryProofHash, DIGEST_6);
  assert.deepEqual(
    resultA.receipt.anchorPayload.privacyFixtureBoundarySurfaceFamilies,
    REQUIRED_PRIVACY_FIXTURE_SURFACE_FAMILIES,
  );
  assert.deepEqual(
    resultA.receipt.anchorPayload.privacyFixtureBoundaryDetectorRuleIds,
    REQUIRED_PRIVACY_FIXTURE_DETECTOR_RULE_IDS,
  );
  assert.doesNotMatch(JSON.stringify(resultA), /root-backed production authority|Participant Alice|api[_-]?key/iu);
});

test('production claim lifting requires adapter activation role-dashboard trust-state lineage', async () => {
  const { evaluateProductionClaimLift } = await loadProductionClaimLifting();

  const missing = evaluateProductionClaimLift(
    claimLiftInput({
      adapterActivationEvidence: {
        deploymentHandoffCutoverProviderRoleDashboardReceiptHash: null,
        deploymentHandoffCutoverProviderRoleDashboardSummaryHash: null,
        deploymentHandoffCutoverProviderRoleDashboardTrustStateViewHash: null,
        deploymentHandoffCutoverReadinessRoleDashboardReceiptHash: null,
        deploymentHandoffCutoverReadinessRoleDashboardSummaryHash: null,
        deploymentHandoffCutoverReadinessRoleDashboardTrustStateViewHash: null,
        deploymentHandoffCutoverRoleDashboardRoles: [],
        runtimeConfigurationSourceHandoffProviderRoleDashboardReceiptHash: null,
        runtimeConfigurationSourceHandoffProviderRoleDashboardSummaryHash: null,
        runtimeConfigurationSourceHandoffProviderRoleDashboardTrustStateViewHash: null,
        runtimeConfigurationSourceHandoffReadinessRoleDashboardReceiptHash: null,
        runtimeConfigurationSourceHandoffReadinessRoleDashboardSummaryHash: null,
        runtimeConfigurationSourceHandoffReadinessRoleDashboardTrustStateViewHash: null,
        productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: null,
        productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: null,
        productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: null,
        productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: null,
        productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: null,
        productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: null,
      },
    }),
  );
  const unsafe = evaluateProductionClaimLift(
    claimLiftInput({
      adapterActivationEvidence: {
        deploymentHandoffCutoverProviderRoleDashboardReceiptHash: DIGEST_D,
        deploymentHandoffCutoverProviderRoleDashboardSummaryHash: DIGEST_C,
        deploymentHandoffCutoverProviderRoleDashboardTrustStateViewHash: DIGEST_D,
        deploymentHandoffCutoverReadinessRoleDashboardReceiptHash: DIGEST_E,
        deploymentHandoffCutoverReadinessRoleDashboardSummaryHash: DIGEST_F,
        deploymentHandoffCutoverReadinessRoleDashboardTrustStateViewHash: DIGEST_1,
        deploymentHandoffCutoverRoleDashboardRoles: REQUIRED_ROLE_DASHBOARD_ROLES.filter(
          (role) => role !== 'sponsor_viewer',
        ).concat('marketing_admin'),
        runtimeConfigurationSourceHandoffProviderRoleDashboardReceiptHash: DIGEST_4,
        runtimeConfigurationSourceHandoffProviderRoleDashboardSummaryHash: DIGEST_C,
        runtimeConfigurationSourceHandoffProviderRoleDashboardTrustStateViewHash: DIGEST_5,
        runtimeConfigurationSourceHandoffReadinessRoleDashboardReceiptHash: DIGEST_E,
        runtimeConfigurationSourceHandoffReadinessRoleDashboardSummaryHash: DIGEST_3,
        runtimeConfigurationSourceHandoffReadinessRoleDashboardTrustStateViewHash: DIGEST_6,
        productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_8,
        productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_9,
        productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_4,
        productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_2,
        productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_4,
        productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_7,
      },
    }),
  );

  assert.equal(missing.allowed, false);
  assert.equal(missing.failClosed, true);
  assert.ok(missing.blockedBy.includes('adapter_activation_role_dashboard_provider_receipt_hash_invalid'));
  assert.ok(missing.blockedBy.includes('adapter_activation_role_dashboard_provider_summary_hash_invalid'));
  assert.ok(missing.blockedBy.includes('adapter_activation_role_dashboard_provider_trust_state_view_hash_invalid'));
  assert.ok(missing.blockedBy.includes('adapter_activation_role_dashboard_readiness_receipt_hash_invalid'));
  assert.ok(missing.blockedBy.includes('adapter_activation_role_dashboard_readiness_summary_hash_invalid'));
  assert.ok(missing.blockedBy.includes('adapter_activation_role_dashboard_readiness_trust_state_view_hash_invalid'));
  assert.ok(missing.blockedBy.includes('adapter_activation_role_dashboard_role_missing:auditor'));
  assert.ok(missing.blockedBy.includes('adapter_activation_runtime_source_provider_role_dashboard_receipt_hash_invalid'));
  assert.ok(missing.blockedBy.includes('adapter_activation_runtime_source_provider_role_dashboard_summary_hash_invalid'));
  assert.ok(missing.blockedBy.includes('adapter_activation_runtime_source_provider_role_dashboard_trust_state_view_hash_invalid'));
  assert.ok(missing.blockedBy.includes('adapter_activation_runtime_source_readiness_role_dashboard_receipt_hash_invalid'));
  assert.ok(missing.blockedBy.includes('adapter_activation_runtime_source_readiness_role_dashboard_summary_hash_invalid'));
  assert.ok(missing.blockedBy.includes('adapter_activation_runtime_source_readiness_role_dashboard_trust_state_view_hash_invalid'));
  assert.ok(
    missing.blockedBy.includes(
      'adapter_activation_production_claim_lift_runtime_source_provider_role_dashboard_receipt_hash_invalid',
    ),
  );
  assert.ok(
    missing.blockedBy.includes(
      'adapter_activation_production_claim_lift_runtime_source_provider_role_dashboard_summary_hash_invalid',
    ),
  );
  assert.ok(
    missing.blockedBy.includes(
      'adapter_activation_production_claim_lift_runtime_source_provider_role_dashboard_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    missing.blockedBy.includes(
      'adapter_activation_production_claim_lift_runtime_source_readiness_role_dashboard_receipt_hash_invalid',
    ),
  );
  assert.ok(
    missing.blockedBy.includes(
      'adapter_activation_production_claim_lift_runtime_source_readiness_role_dashboard_summary_hash_invalid',
    ),
  );
  assert.ok(
    missing.blockedBy.includes(
      'adapter_activation_production_claim_lift_runtime_source_readiness_role_dashboard_trust_state_view_hash_invalid',
    ),
  );
  assert.equal(missing.receipt.trustState, 'inactive');
  assert.equal(missing.receipt.exochainProductionClaim, false);

  assert.equal(unsafe.allowed, false);
  assert.equal(unsafe.failClosed, true);
  assert.ok(unsafe.blockedBy.includes('adapter_activation_role_dashboard_role_missing:sponsor_viewer'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_role_dashboard_role_unsupported:marketing_admin'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_runtime_source_provider_role_dashboard_receipt_mismatch'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_runtime_source_provider_role_dashboard_trust_state_view_mismatch'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_runtime_source_readiness_role_dashboard_summary_mismatch'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_runtime_source_readiness_role_dashboard_trust_state_view_mismatch'));
  assert.ok(
    unsafe.blockedBy.includes(
      'adapter_activation_production_claim_lift_runtime_source_provider_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'adapter_activation_production_claim_lift_runtime_source_provider_role_dashboard_summary_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'adapter_activation_production_claim_lift_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'adapter_activation_production_claim_lift_runtime_source_readiness_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'adapter_activation_production_claim_lift_runtime_source_readiness_role_dashboard_summary_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'adapter_activation_production_claim_lift_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
    ),
  );
});

test('production claim lifting requires adapter activation receipt evidence before claim lift', async () => {
  const { evaluateProductionClaimLift } = await loadProductionClaimLifting();

  const missing = evaluateProductionClaimLift(
    claimLiftInput({
      adapterActivationEvidence: null,
    }),
  );
  const unsafe = evaluateProductionClaimLift(
    claimLiftInput({
      adapterActivationEvidence: {
        evidencePackageHash: 'not-a-digest',
        receiptHash: 'bad-receipt',
        receiptArtifactType: 'adapter_activation_summary',
        status: 'blocked_inactive_trust',
        trustState: 'verified',
        canRequestProductionClaimLift: false,
        canShowProductionTrustClaim: true,
        exochainProductionClaim: true,
        releaseCandidateRef: 'different-release',
        runtimePathRef: 'browser-wasm-runtime',
        deploymentHandoffCutoverHash: DIGEST_E,
        deploymentHandoffCutoverReceiptHash: DIGEST_F,
        runtimeConfigurationHash: null,
        runtimeConfigurationSourceReceiptHash: 'bad-runtime-source-receipt',
        activationGateIds: ['PTAG-005'],
        componentStates: {
          decisionForum: 'pending',
          deploymentHandoffCutover: 'denied',
          gateway: 'verified',
          nodeReceipt: 'denied',
          privacyBoundary: 'verified',
          rootBundle: 'pending',
          runtimeConfigurationSource: 'denied',
        },
        metadataOnly: false,
        protectedContentExcluded: false,
        reviewedAtHlc: { physicalMs: 1800010240000, logical: 0 },
      },
    }),
  );

  assert.equal(missing.allowed, false);
  assert.equal(missing.failClosed, true);
  assert.equal(missing.canLiftProductionClaim, false);
  assert.ok(missing.blockedBy.includes('adapter_activation_evidence_absent'));
  assert.ok(missing.blockedBy.includes('adapter_activation_evidence_hash_invalid'));
  assert.ok(missing.blockedBy.includes('adapter_activation_receipt_hash_invalid'));
  assert.equal(missing.receipt.trustState, 'inactive');
  assert.equal(missing.receipt.exochainProductionClaim, false);

  assert.equal(unsafe.allowed, false);
  assert.equal(unsafe.failClosed, true);
  assert.ok(unsafe.blockedBy.includes('adapter_activation_evidence_hash_invalid'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_receipt_hash_invalid'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_receipt_type_invalid'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_status_invalid'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_trust_state_invalid'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_request_not_ready'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_production_claim_preview_forbidden'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_production_claim_forbidden'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_release_candidate_mismatch'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_runtime_path_mismatch'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_handoff_hash_mismatch'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_handoff_receipt_mismatch'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_runtime_configuration_hash_invalid'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_runtime_configuration_source_receipt_hash_invalid'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_gate_missing:PTAG-001'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_component_unverified:decisionForum'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_component_unverified:deploymentHandoffCutover'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_component_unverified:nodeReceipt'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_component_unverified:rootBundle'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_component_unverified:runtimeConfigurationSource'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_metadata_boundary_invalid'));
  assert.ok(unsafe.blockedBy.includes('adapter_activation_protected_boundary_invalid'));
  assert.ok(unsafe.blockedBy.includes('claim_lift_hlc_order_invalid:adapter_activation_evidence'));
});

test('production claim lifting requires PTAG-009 privacy fixture boundary receipt proof', async () => {
  const { evaluateProductionClaimLift } = await loadProductionClaimLifting();

  const missing = evaluateProductionClaimLift(
    claimLiftInput({
      privacyBoundary: {
        privacyFixtureBoundary: null,
      },
    }),
  );
  const unsafe = evaluateProductionClaimLift(
    claimLiftInput({
      privacyBoundary: {
        privacyFixtureBoundary: {
          status: 'blocked',
          receiptId: '',
          receiptActionHash: 'not-a-digest',
          receiptArtifactType: 'privacy_scan_summary',
          fixtureProofHash: 'bad-proof',
          scanHash: null,
          surfaceFamilies: REQUIRED_PRIVACY_FIXTURE_SURFACE_FAMILIES.filter(
            (family) => family !== 'debug_response',
          ),
          detectorRuleIds: REQUIRED_PRIVACY_FIXTURE_DETECTOR_RULE_IDS.filter(
            (ruleId) => ruleId !== 'secret_text_pattern',
          ),
          trustState: 'verified',
          exochainProductionClaim: true,
          metadataOnly: false,
          protectedContentExcluded: false,
          acceptedAtHlc: { physicalMs: 1800010499999, logical: 0 },
        },
      },
    }),
  );

  assert.equal(missing.allowed, false);
  assert.equal(missing.failClosed, true);
  assert.equal(missing.canLiftProductionClaim, false);
  assert.ok(missing.blockedBy.includes('privacy_fixture_boundary_proof_absent'));
  assert.ok(missing.blockedBy.includes('privacy_fixture_boundary_receipt_id_absent'));
  assert.ok(missing.blockedBy.includes('privacy_fixture_boundary_receipt_action_hash_invalid'));
  assert.equal(missing.receipt.trustState, 'inactive');
  assert.equal(missing.receipt.exochainProductionClaim, false);

  assert.equal(unsafe.allowed, false);
  assert.equal(unsafe.failClosed, true);
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_status_unverified'));
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_receipt_id_absent'));
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_receipt_action_hash_invalid'));
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_receipt_type_invalid'));
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_proof_hash_invalid'));
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_scan_hash_invalid'));
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_surface_missing:debug_response'));
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_detector_missing:secret_text_pattern'));
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_trust_state_invalid'));
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_production_claim_forbidden'));
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_metadata_invalid'));
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_protected_boundary_invalid'));
  assert.ok(unsafe.blockedBy.includes('privacy_fixture_boundary_acceptance_before_scan'));
});

test('production claim lifting requires verified deployment handoff cutover receipt before claim lift', async () => {
  const { evaluateProductionClaimLift } = await loadProductionClaimLifting();

  const missing = evaluateProductionClaimLift(
    claimLiftInput({
      deploymentHandoffCutover: null,
    }),
  );
  const unsafe = evaluateProductionClaimLift(
    claimLiftInput({
      deploymentHandoffCutover: {
        handoffHash: 'not-a-digest',
        receiptHash: 'bad-receipt',
        receiptArtifactType: 'deployment_summary',
        status: 'handoff_ready_inactive_trust',
        deploymentConfigHash: DIGEST_E,
        baselineHandoffReady: false,
        productionCutoverReady: false,
        trustState: 'active',
        exochainProductionClaim: true,
        metadataOnly: false,
        protectedContentExcluded: false,
        reviewedAtHlc: { physicalMs: 1800010150000, logical: 0 },
      },
    }),
  );

  assert.equal(missing.allowed, false);
  assert.equal(missing.failClosed, true);
  assert.equal(missing.canLiftProductionClaim, false);
  assert.ok(missing.blockedBy.includes('deployment_handoff_cutover_absent'));
  assert.ok(missing.blockedBy.includes('deployment_handoff_ref_absent'));
  assert.ok(missing.blockedBy.includes('deployment_handoff_receipt_hash_invalid'));
  assert.equal(missing.receipt.trustState, 'inactive');
  assert.equal(missing.receipt.exochainProductionClaim, false);

  assert.equal(unsafe.allowed, false);
  assert.equal(unsafe.failClosed, true);
  assert.ok(unsafe.blockedBy.includes('deployment_handoff_hash_invalid'));
  assert.ok(unsafe.blockedBy.includes('deployment_handoff_receipt_hash_invalid'));
  assert.ok(unsafe.blockedBy.includes('deployment_handoff_receipt_type_invalid'));
  assert.ok(unsafe.blockedBy.includes('deployment_handoff_status_invalid'));
  assert.ok(unsafe.blockedBy.includes('deployment_handoff_deployment_config_mismatch'));
  assert.ok(unsafe.blockedBy.includes('deployment_handoff_baseline_not_ready'));
  assert.ok(unsafe.blockedBy.includes('deployment_handoff_not_cutover_ready'));
  assert.ok(unsafe.blockedBy.includes('deployment_handoff_trust_state_invalid'));
  assert.ok(unsafe.blockedBy.includes('deployment_handoff_production_claim_forbidden'));
  assert.ok(unsafe.blockedBy.includes('deployment_handoff_metadata_boundary_invalid'));
  assert.ok(unsafe.blockedBy.includes('deployment_handoff_protected_boundary_invalid'));
  assert.ok(unsafe.blockedBy.includes('claim_lift_hlc_order_invalid:deployment_handoff_cutover'));
  assert.equal(unsafe.receipt.trustState, 'inactive');
  assert.equal(unsafe.receipt.exochainProductionClaim, false);
});

test('production claim lifting fails closed for missing criteria without blocking baseline development', async () => {
  const { evaluateProductionClaimLift } = await loadProductionClaimLifting();

  const result = evaluateProductionClaimLift(
    claimLiftInput({
      sourceTruth: {
        currentAgainstLocalCommit: false,
        noExochainSourceModified: false,
      },
      runtimePath: {
        browserAuthoritative: true,
        nodeReceiptPathVerified: false,
      },
      deploymentConfiguration: {
        productionEnvironmentIdentified: false,
        rootBundleProviderRef: '',
      },
      adapterBoundary: {
        cannotSimulateCoreOutcome: false,
        cannotCacheCoreOutcome: false,
        cannotOverrideCoreOutcome: false,
        failsClosedOnTimeout: false,
      },
      testMatrix: {
        timeoutCasePassed: false,
        crossTenantCasePassed: false,
      },
      privacyBoundary: {
        noRawSensitiveInTelemetry: false,
        fixtureScanPassed: false,
      },
      claimMapping: {
        mappedArtifactType: 'marketing_copy',
        receiptId: '',
        noMarketingOverclaim: false,
      },
      contextReview: {
        reviewedAgainstOriginalPrd: false,
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
      humanDecision: {
        decision: 'approve_production_claim_lift',
        finalAuthority: 'ai',
      },
    }),
  );

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.canLiftProductionClaim, false);
  assert.equal(result.exochainProductionClaim, false);
  assert.equal(result.baselineDevelopmentBlocked, false);
  assert.ok(result.blockedBy.includes('source_not_current_against_local_commit'));
  assert.ok(result.blockedBy.includes('exochain_source_modified'));
  assert.ok(result.blockedBy.includes('browser_authoritative_runtime_forbidden'));
  assert.ok(result.blockedBy.includes('node_receipt_path_unverified'));
  assert.ok(result.blockedBy.includes('production_deployment_configuration_absent'));
  assert.ok(result.blockedBy.includes('root_bundle_provider_absent'));
  assert.ok(result.blockedBy.includes('adapter_simulated_outcome_possible'));
  assert.ok(result.blockedBy.includes('adapter_cached_outcome_possible'));
  assert.ok(result.blockedBy.includes('adapter_override_possible'));
  assert.ok(result.blockedBy.includes('adapter_timeout_not_fail_closed'));
  assert.ok(result.blockedBy.includes('timeout_case_missing'));
  assert.ok(result.blockedBy.includes('cross_tenant_case_missing'));
  assert.ok(result.blockedBy.includes('telemetry_sensitive_content_boundary_unverified'));
  assert.ok(result.blockedBy.includes('privacy_fixture_scan_failed'));
  assert.ok(result.blockedBy.includes('claim_mapping_artifact_type_unsupported'));
  assert.ok(result.blockedBy.includes('receipt_mapping_absent'));
  assert.ok(result.blockedBy.includes('marketing_overclaim_not_denied'));
  assert.ok(result.blockedBy.includes('context_prd_review_absent'));
  assert.ok(result.blockedBy.includes('ai_final_authority_forbidden'));
  assert.ok(result.blockedBy.includes('human_claim_lift_decision_invalid'));
  assert.equal(result.receipt.trustState, 'inactive');
  assert.equal(result.receipt.exochainProductionClaim, false);
});

test('production claim lifting rejects raw claim text protected content and secret material before receipts', async () => {
  const { ProtectedContentError, evaluateProductionClaimLift } = await loadProductionClaimLifting();

  assert.throws(
    () =>
      evaluateProductionClaimLift(
        claimLiftInput({
          claimMapping: {
            rawClaimText: 'Root-backed production authority for participant Alice Example is active.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateProductionClaimLift(
        claimLiftInput({
          deploymentConfiguration: {
            accessToken: 'redacted-access-token-placeholder',
          },
        }),
      ),
    ProtectedContentError,
  );
});
