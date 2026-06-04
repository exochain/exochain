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

const REQUIRED_GATE_IDS = ['PTAG-001', 'PTAG-005', 'PTAG-006', 'PTAG-016', 'PTAG-017'];
const REQUIRED_COMPONENTS = ['decision_forum', 'gateway', 'node_receipt', 'privacy_boundary', 'root_bundle'];
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

async function loadAdapterActivationEvidence() {
  try {
    return await import('../src/adapter-activation-evidence.mjs');
  } catch (error) {
    assert.fail(`CyberMedica adapter activation evidence module must exist and load: ${error.message}`);
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
      productionClaimLiftRoleDashboardReadinessReceiptHash: DIGEST_B,
      productionClaimLiftRoleDashboardReadinessSummaryHash: DIGEST_A,
      productionClaimLiftRoleDashboardReadinessTrustStateViewHash: DIGEST_D,
      productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_B,
      productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_A,
      productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_C,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_B,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_A,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_D,
      productionClaimLiftRoleDashboardRoles: DASHBOARD_ROLES,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1811000000000, logical: 5 },
    },
    overrides,
  );
}

function activationInput(overrides = {}) {
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
      permissions: ['adapter_activation_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    activationPolicy: {
      policyRef: 'adapter-activation-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredGateIds: REQUIRED_GATE_IDS,
      requiredComponents: REQUIRED_COMPONENTS,
      sourceRefs: [
        'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
        'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      ],
      forbidsProductionTrustClaim: true,
      requiresMetadataOnly: true,
      requiresFailClosedAdapters: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1811000000000, logical: 0 },
    },
    activationCycle: {
      evidencePackageRef: 'adapter-activation-evidence-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      runtimePathRef: 'server-side-gateway-node-decisionforum-root',
      deploymentMode: 'server_side_gateway_node',
      openedAtHlc: { physicalMs: 1811000000000, logical: 1 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    runtimeConfigurationSourceEvidence: {
      runtimeConfigurationSourceId: 'runtime-configuration-source-alpha',
      runtimeConfigurationHash: DIGEST_8,
      receiptHash: DIGEST_7,
      receiptArtifactType: 'runtime_configuration_source',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      configurationHash: DIGEST_6,
      secretScopeHash: DIGEST_5,
      trustFeatureFlagHash: DIGEST_4,
      deploymentReadinessManifestReceiptHash: DIGEST_3,
      deploymentOperationsReadinessHash: DIGEST_2,
      deploymentProviderBindingReceiptHash: DIGEST_1,
      baselineConfigurationReady: true,
      productionConfigurationReady: true,
      activationBlockerIds: [],
      trustState: 'inactive',
      exochainProductionClaim: false,
      deploymentHandoffCutover: {
        handoffHash: DIGEST_9,
        receiptHash: DIGEST_A,
        deploymentReadinessRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
        deploymentProviderBindingRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
      },
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1811000000000, logical: 6 },
    },
    deploymentHandoffCutoverEvidence: {
      handoffRef: 'deployment-handoff-cutover-alpha',
      handoffHash: DIGEST_9,
      receiptHash: DIGEST_A,
      receiptArtifactType: 'deployment_handoff_cutover',
      status: 'deployment_handoff_cutover_ready_verified_runtime',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      deploymentConfigHash: DIGEST_D,
      runtimeConfigurationSourceId: 'runtime-configuration-source-alpha',
      runtimeConfigurationHash: DIGEST_8,
      runtimeConfigurationSourceReceiptHash: DIGEST_7,
      baselineHandoffReady: true,
      productionCutoverReady: true,
      trustState: 'inactive',
      exochainProductionClaim: false,
      deploymentReadinessRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
      deploymentProviderBindingRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1811000000000, logical: 6 },
    },
    rootBundleEvidence: {
      state: 'verified',
      verified: true,
      rootBundleProviderRef: 'root-bundle-provider-alpha',
      rootTrustBundleHash: DIGEST_C,
      rosterHash: DIGEST_D,
      artifactRegistryHash: DIGEST_E,
      verifierReceiptId: 'root-verifier-receipt-alpha',
      thresholdSignature: '7-of-13',
      certifierCount: 13,
      dkgParticipantCount: 13,
      runtimePathRef: 'server-side-gateway-node-decisionforum-root',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      checkedAtHlc: { physicalMs: 1811000000000, logical: 2 },
      metadataOnly: true,
      protectedContentExcluded: true,
      exochainProductionClaim: false,
    },
    gatewayEvidence: {
      decision: 'permitted',
      status: 'verified',
      state: 'verified',
      gatewayCallHash: DIGEST_F,
      gatewayReceiptId: 'gateway-receipt-protocol-launch-alpha',
      actionHash: DIGEST_1,
      tenantId: 'tenant-site-alpha',
      runtimePathRef: 'server-side-gateway-node-decisionforum-root',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      failClosed: false,
      noCachedOutcome: true,
      noLocalSimulation: true,
      noOverride: true,
      serverSideOnly: true,
      checkedAtHlc: { physicalMs: 1811000000000, logical: 3 },
      metadataOnly: true,
      protectedContentExcluded: true,
      exochainProductionClaim: false,
    },
    nodeReceiptEvidence: {
      decision: 'permitted',
      syncStatus: 'ready_inactive_trust',
      state: 'verified',
      nodeReceiptSyncHash: DIGEST_2,
      nodeReceiptId: 'node-receipt-protocol-launch-alpha',
      linkedGatewayReceiptId: 'gateway-receipt-protocol-launch-alpha',
      actionHash: DIGEST_1,
      receiptSignatureVerified: true,
      actionHashSynced: true,
      queryByActorVerified: true,
      provenancePayloadSuppressed: true,
      tenantId: 'tenant-site-alpha',
      runtimePathRef: 'server-side-gateway-node-decisionforum-root',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      checkedAtHlc: { physicalMs: 1811000000000, logical: 4 },
      metadataOnly: true,
      protectedContentExcluded: true,
      exochainProductionClaim: false,
    },
    decisionForumEvidence: {
      state: 'verified',
      decisionState: 'approved',
      decisionId: 'df-protocol-launch-alpha',
      workflowReceiptId: 'df-workflow-receipt-alpha',
      linkedGatewayReceiptId: 'gateway-receipt-protocol-launch-alpha',
      actionHash: DIGEST_1,
      humanGateVerified: true,
      quorumVerified: true,
      kernelVerdictVerified: true,
      invariantSetVerified: true,
      aiFinalAuthority: false,
      openChallenge: false,
      tenantId: 'tenant-site-alpha',
      runtimePathRef: 'server-side-gateway-node-decisionforum-root',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      checkedAtHlc: { physicalMs: 1811000000000, logical: 5 },
      metadataOnly: true,
      protectedContentExcluded: true,
      exochainProductionClaim: false,
    },
    privacyBoundaryEvidence: {
      state: 'verified',
      noRawSensitiveInReceipts: true,
      noRawSensitiveInDag: true,
      noRawSensitiveInLogs: true,
      noRawSensitiveInTelemetry: true,
      noRawSensitiveInHealth: true,
      noRawSensitiveInDebug: true,
      noRawSensitiveInExports: true,
      fixtureScanPassed: true,
      classificationHash: DIGEST_3,
      checkedAtHlc: { physicalMs: 1811000000000, logical: 6 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    validationEvidence: {
      commandRefs: [
        'node --test tests/adapter-activation-evidence.test.mjs',
        'node --test tests/gateway-call-path.test.mjs',
        'node --test tests/node-receipt-sync.test.mjs',
        'npm run quality',
      ],
      adapterTestsPassed: true,
      sourceGuardPassed: true,
      privacyFixturesPassed: true,
      gatewayTestsPassed: true,
      nodeReceiptTestsPassed: true,
      decisionForumTestsPassed: true,
      rootBundleTestsPassed: true,
      validationHash: DIGEST_4,
      recordedAtHlc: { physicalMs: 1811000000000, logical: 7 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      decision: 'adapter_activation_ready_for_claim_lift_request',
      reviewHash: DIGEST_5,
      reviewedAtHlc: { physicalMs: 1811000000000, logical: 8 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    custodyDigest: DIGEST_6,
  };

  return mergeDeep(base, overrides);
}

test('adapter activation evidence packages verified root gateway node and Decision Forum proofs without lifting claims', async () => {
  const { evaluateAdapterActivationEvidence } = await loadAdapterActivationEvidence();

  const first = evaluateAdapterActivationEvidence(activationInput());
  const second = evaluateAdapterActivationEvidence(
    activationInput({
      activationPolicy: {
        requiredGateIds: [...REQUIRED_GATE_IDS].reverse(),
        requiredComponents: [...REQUIRED_COMPONENTS].reverse(),
        sourceRefs: [
          'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
          'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
        ],
      },
      validationEvidence: {
        commandRefs: [...activationInput().validationEvidence.commandRefs].reverse(),
      },
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.activationEvidence.status, 'ready_for_claim_lift_request');
  assert.equal(first.activationEvidence.trustState, 'inactive');
  assert.equal(first.activationEvidence.canRequestProductionClaimLift, true);
  assert.equal(first.activationEvidence.canShowProductionTrustClaim, false);
  assert.equal(first.activationEvidence.exochainProductionClaim, false);
  assert.deepEqual(first.activationEvidence.activationGateIds, REQUIRED_GATE_IDS);
  assert.deepEqual(first.activationEvidence.componentStates, {
    decisionForum: 'verified',
    deploymentHandoffCutover: 'verified',
    gateway: 'verified',
    nodeReceipt: 'verified',
    privacyBoundary: 'verified',
    rootBundle: 'verified',
    runtimeConfigurationSource: 'verified',
  });
  assert.equal(first.activationEvidence.gatewayReceiptId, 'gateway-receipt-protocol-launch-alpha');
  assert.equal(first.activationEvidence.nodeReceiptId, 'node-receipt-protocol-launch-alpha');
  assert.equal(first.activationEvidence.decisionForumReceiptId, 'df-workflow-receipt-alpha');
  assert.equal(first.activationEvidence.rootVerifierReceiptId, 'root-verifier-receipt-alpha');
  assert.equal(first.activationEvidence.deploymentHandoffCutoverReceiptHash, DIGEST_A);
  assert.equal(first.activationEvidence.deploymentHandoffCutoverHash, DIGEST_9);
  assert.equal(first.activationEvidence.deploymentHandoffCutoverReadinessRoleDashboardReceiptHash, DIGEST_B);
  assert.equal(first.activationEvidence.deploymentHandoffCutoverReadinessRoleDashboardSummaryHash, DIGEST_A);
  assert.equal(first.activationEvidence.deploymentHandoffCutoverReadinessRoleDashboardTrustStateViewHash, DIGEST_C);
  assert.equal(first.activationEvidence.deploymentHandoffCutoverProviderRoleDashboardReceiptHash, DIGEST_B);
  assert.equal(first.activationEvidence.deploymentHandoffCutoverProviderRoleDashboardSummaryHash, DIGEST_A);
  assert.equal(first.activationEvidence.deploymentHandoffCutoverProviderRoleDashboardTrustStateViewHash, DIGEST_C);
  assert.deepEqual(first.activationEvidence.deploymentHandoffCutoverRoleDashboardRoles, DASHBOARD_ROLES);
  assert.equal(first.activationEvidence.runtimeConfigurationSourceReceiptHash, DIGEST_7);
  assert.equal(first.activationEvidence.runtimeConfigurationHash, DIGEST_8);
  assert.equal(first.activationEvidence.runtimeConfigurationSourceHandoffReadinessRoleDashboardReceiptHash, DIGEST_B);
  assert.equal(first.activationEvidence.runtimeConfigurationSourceHandoffReadinessRoleDashboardSummaryHash, DIGEST_A);
  assert.equal(first.activationEvidence.runtimeConfigurationSourceHandoffReadinessRoleDashboardTrustStateViewHash, DIGEST_C);
  assert.equal(
    first.activationEvidence
      .runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    first.activationEvidence
      .runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    DIGEST_A,
  );
  assert.equal(
    first.activationEvidence
      .runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    DIGEST_C,
  );
  assert.equal(
    first.activationEvidence
      .runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    first.activationEvidence
      .runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    DIGEST_A,
  );
  assert.equal(
    first.activationEvidence
      .runtimeConfigurationSourceHandoffReadinessClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    DIGEST_D,
  );
  assert.equal(first.activationEvidence.runtimeConfigurationSourceHandoffProviderRoleDashboardReceiptHash, DIGEST_B);
  assert.equal(first.activationEvidence.runtimeConfigurationSourceHandoffProviderRoleDashboardSummaryHash, DIGEST_A);
  assert.equal(first.activationEvidence.runtimeConfigurationSourceHandoffProviderRoleDashboardTrustStateViewHash, DIGEST_C);
  assert.equal(
    first.activationEvidence
      .runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    first.activationEvidence
      .runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    DIGEST_A,
  );
  assert.equal(
    first.activationEvidence
      .runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    DIGEST_C,
  );
  assert.equal(
    first.activationEvidence
      .runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    first.activationEvidence
      .runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    DIGEST_A,
  );
  assert.equal(
    first.activationEvidence
      .runtimeConfigurationSourceHandoffProviderClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    DIGEST_D,
  );
  assert.equal(first.activationEvidence.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash, DIGEST_B);
  assert.equal(first.activationEvidence.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash, DIGEST_A);
  assert.equal(
    first.activationEvidence.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    DIGEST_C,
  );
  assert.equal(first.activationEvidence.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash, DIGEST_B);
  assert.equal(first.activationEvidence.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash, DIGEST_A);
  assert.equal(
    first.activationEvidence.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    DIGEST_D,
  );
  assert.deepEqual(first.activationEvidence.runtimeConfigurationSourceHandoffRoleDashboardRoles, DASHBOARD_ROLES);
  assert.equal(first.activationEvidence.actionHash, DIGEST_1);
  assert.equal(first.activationEvidence.evidencePackageHash, second.activationEvidence.evidencePackageHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'adapter_activation_evidence');
  assert.ok(first.receipt.anchorPayload.sensitivityTags.includes('role_dashboard_trust_state'));
  assert.doesNotMatch(JSON.stringify(first), /raw payload|source document|private key|access token/iu);
});

test('adapter activation evidence fails closed for unverified component states', async () => {
  const { evaluateAdapterActivationEvidence } = await loadAdapterActivationEvidence();

  const denied = evaluateAdapterActivationEvidence(
    activationInput({
      rootBundleEvidence: {
        state: 'pending',
        verified: false,
      },
      gatewayEvidence: {
        decision: 'denied',
        status: 'denied',
        failClosed: true,
      },
      nodeReceiptEvidence: {
        receiptSignatureVerified: false,
        provenancePayloadSuppressed: false,
      },
      decisionForumEvidence: {
        humanGateVerified: false,
        quorumVerified: false,
        aiFinalAuthority: true,
      },
      privacyBoundaryEvidence: {
        noRawSensitiveInReceipts: false,
        fixtureScanPassed: false,
      },
      validationEvidence: {
        adapterTestsPassed: false,
      },
      humanReview: {
        decision: 'hold_for_adapter_activation_gap',
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.activationEvidence.status, 'blocked_inactive_trust');
  assert.equal(denied.activationEvidence.canRequestProductionClaimLift, false);
  assert.equal(denied.activationEvidence.canShowProductionTrustClaim, false);
  assert.ok(denied.reasons.includes('root_bundle_unverified'));
  assert.ok(denied.reasons.includes('gateway_evidence_unverified'));
  assert.ok(denied.reasons.includes('node_receipt_signature_unverified'));
  assert.ok(denied.reasons.includes('node_provenance_payload_suppression_unverified'));
  assert.ok(denied.reasons.includes('decision_forum_human_gate_unverified'));
  assert.ok(denied.reasons.includes('decision_forum_quorum_unverified'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('receipt_sensitive_content_boundary_unverified'));
  assert.ok(denied.reasons.includes('privacy_fixture_scan_failed'));
  assert.ok(denied.reasons.includes('adapter_validation_tests_missing'));
});

test('adapter activation evidence requires verified deployment handoff and runtime configuration source lineage', async () => {
  const { evaluateAdapterActivationEvidence } = await loadAdapterActivationEvidence();

  const missing = evaluateAdapterActivationEvidence(
    activationInput({
      runtimeConfigurationSourceEvidence: null,
      deploymentHandoffCutoverEvidence: null,
    }),
  );
  const unsafe = evaluateAdapterActivationEvidence(
    activationInput({
      runtimeConfigurationSourceEvidence: {
        runtimeConfigurationHash: DIGEST_8,
        receiptHash: DIGEST_7,
        receiptArtifactType: 'runtime_config_summary',
        releaseCandidateRef: 'different-release',
        baselineConfigurationReady: false,
        productionConfigurationReady: false,
        activationBlockerIds: ['ESC-RUNTIME'],
        trustState: 'verified',
        exochainProductionClaim: true,
        metadataOnly: false,
        protectedContentExcluded: false,
        reviewedAtHlc: { physicalMs: 1811000000000, logical: 9 },
      },
      deploymentHandoffCutoverEvidence: {
        handoffHash: null,
        receiptHash: 'bad-handoff-receipt',
        receiptArtifactType: 'deployment_summary',
        status: 'handoff_ready_inactive_trust',
        releaseCandidateRef: 'different-release',
        runtimeConfigurationSourceId: 'different-source',
        runtimeConfigurationHash: DIGEST_F,
        runtimeConfigurationSourceReceiptHash: DIGEST_E,
        baselineHandoffReady: false,
        productionCutoverReady: false,
        trustState: 'verified',
        exochainProductionClaim: true,
        metadataOnly: false,
        protectedContentExcluded: false,
        reviewedAtHlc: { physicalMs: 1811000000000, logical: 9 },
      },
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.activationEvidence.canRequestProductionClaimLift, false);
  assert.ok(missing.reasons.includes('runtime_configuration_source_lineage_absent'));
  assert.ok(missing.reasons.includes('runtime_configuration_source_hash_invalid'));
  assert.ok(missing.reasons.includes('runtime_configuration_source_receipt_hash_invalid'));
  assert.ok(missing.reasons.includes('deployment_handoff_cutover_lineage_absent'));
  assert.ok(missing.reasons.includes('deployment_handoff_cutover_receipt_hash_invalid'));

  assert.equal(unsafe.decision, 'denied');
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_receipt_type_invalid'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_release_candidate_mismatch'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_baseline_not_ready'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_production_not_ready'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_activation_blockers_present'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_receipt_type_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_status_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_release_candidate_mismatch'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_runtime_configuration_source_id_mismatch'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_runtime_configuration_hash_mismatch'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_runtime_configuration_receipt_mismatch'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_baseline_not_ready'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_cutover_not_ready'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('deployment_handoff_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('activation_hlc_order_invalid:validation'));
});

test('adapter activation evidence requires runtime-source handoff role-dashboard trust-state lineage', async () => {
  const { evaluateAdapterActivationEvidence } = await loadAdapterActivationEvidence();

  const missing = evaluateAdapterActivationEvidence(
    activationInput({
      runtimeConfigurationSourceEvidence: {
        deploymentHandoffCutover: null,
      },
      deploymentHandoffCutoverEvidence: {
        deploymentReadinessRoleDashboardTrustStateEvidence: null,
        deploymentProviderBindingRoleDashboardTrustStateEvidence: null,
      },
    }),
  );
  const unsafe = evaluateAdapterActivationEvidence(
    activationInput({
      runtimeConfigurationSourceEvidence: {
        deploymentHandoffCutover: {
          handoffHash: DIGEST_4,
          receiptHash: DIGEST_5,
          deploymentReadinessRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence({
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
            metadataOnly: false,
            protectedContentExcluded: false,
            reviewedAtHlc: { physicalMs: 1811000000000, logical: 9 },
          }),
          deploymentProviderBindingRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence({
            roleDashboardReceiptHash: DIGEST_E,
          }),
        },
      },
      deploymentHandoffCutoverEvidence: {
        deploymentReadinessRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
        deploymentProviderBindingRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
      },
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.activationEvidence.canRequestProductionClaimLift, false);
  assert.ok(missing.reasons.includes('runtime_configuration_source_handoff_lineage_absent'));
  assert.ok(missing.reasons.includes('runtime_configuration_source_handoff_readiness_role_dashboard_trust_state_evidence_absent'));
  assert.ok(missing.reasons.includes('runtime_configuration_source_handoff_provider_binding_role_dashboard_trust_state_evidence_absent'));
  assert.ok(missing.reasons.includes('deployment_handoff_readiness_role_dashboard_trust_state_evidence_absent'));
  assert.ok(missing.reasons.includes('deployment_handoff_provider_binding_role_dashboard_trust_state_evidence_absent'));

  assert.equal(unsafe.decision, 'denied');
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_handoff_hash_mismatch'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_handoff_receipt_mismatch'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_handoff_readiness_role_dashboard_receipt_hash_invalid'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_handoff_readiness_role_dashboard_role_missing:sponsor_viewer'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_handoff_readiness_role_dashboard_hash_ref_role_unsupported:unapproved_role'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_handoff_readiness_role_dashboard_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_handoff_readiness_role_dashboard_production_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_handoff_readiness_role_dashboard_production_claim_display_forbidden'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_handoff_readiness_role_dashboard_production_claim_lift_forbidden'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_handoff_readiness_role_dashboard_after_runtime_configuration_source_review'));
  assert.ok(unsafe.reasons.includes('runtime_configuration_source_handoff_provider_binding_role_dashboard_receipt_mismatch'));
});

test('adapter activation evidence requires enriched runtime-source production-claim-lift role-dashboard lineage', async () => {
  const { evaluateAdapterActivationEvidence } = await loadAdapterActivationEvidence();

  const denied = evaluateAdapterActivationEvidence(
    activationInput({
      runtimeConfigurationSourceEvidence: {
        deploymentHandoffCutover: {
          deploymentReadinessRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence({
            productionClaimLiftRoleDashboardProviderTrustStateViewHash: null,
            productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_E,
            productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: null,
            productionClaimLiftRoleDashboardRoles: DASHBOARD_ROLES.filter((role) => role !== 'sponsor_viewer'),
          }),
          deploymentProviderBindingRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence({
            productionClaimLiftRoleDashboardReadinessSummaryHash: DIGEST_D,
            productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_6,
          }),
        },
      },
      deploymentHandoffCutoverEvidence: {
        deploymentReadinessRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
        deploymentProviderBindingRoleDashboardTrustStateEvidence: roleDashboardTrustStateEvidence(),
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.activationEvidence.canRequestProductionClaimLift, false);
  assert.ok(
    denied.reasons.includes(
      'runtime_configuration_source_handoff_readiness_role_dashboard_production_claim_lift_provider_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'runtime_configuration_source_handoff_readiness_role_dashboard_production_claim_lift_runtime_source_provider_receipt_mismatch',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'runtime_configuration_source_handoff_readiness_role_dashboard_production_claim_lift_runtime_source_provider_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'runtime_configuration_source_handoff_readiness_role_dashboard_production_claim_lift_role_missing:sponsor_viewer',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'runtime_configuration_source_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_readiness_summary_mismatch',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'runtime_configuration_source_handoff_provider_binding_role_dashboard_production_claim_lift_readiness_summary_mismatch',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'runtime_configuration_source_handoff_provider_binding_role_dashboard_production_claim_lift_runtime_source_readiness_trust_state_view_mismatch',
    ),
  );
});

test('adapter activation evidence rejects cross-component tenant action receipt and runtime mismatches', async () => {
  const { evaluateAdapterActivationEvidence } = await loadAdapterActivationEvidence();

  const denied = evaluateAdapterActivationEvidence(
    activationInput({
      targetTenantId: 'tenant-site-beta',
      gatewayEvidence: {
        tenantId: 'tenant-site-beta',
        actionHash: DIGEST_7,
        runtimePathRef: 'browser-wasm-runtime',
      },
      nodeReceiptEvidence: {
        linkedGatewayReceiptId: 'different-gateway-receipt',
        runtimePathRef: 'server-side-gateway-node-decisionforum-root',
      },
      decisionForumEvidence: {
        actionHash: DIGEST_8,
        linkedGatewayReceiptId: 'different-gateway-receipt',
        releaseCandidateRef: 'different-release',
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('component_tenant_mismatch:gateway'));
  assert.ok(denied.reasons.includes('component_action_hash_mismatch:gateway'));
  assert.ok(denied.reasons.includes('component_action_hash_mismatch:decision_forum'));
  assert.ok(denied.reasons.includes('node_gateway_receipt_link_mismatch'));
  assert.ok(denied.reasons.includes('decision_forum_gateway_receipt_link_mismatch'));
  assert.ok(denied.reasons.includes('component_runtime_path_mismatch:gateway'));
  assert.ok(denied.reasons.includes('component_release_candidate_mismatch:decision_forum'));
});

test('adapter activation evidence validates HLC order policy and human review authority', async () => {
  const { evaluateAdapterActivationEvidence } = await loadAdapterActivationEvidence();

  const denied = evaluateAdapterActivationEvidence(
    activationInput({
      actor: {
        kind: 'service_account',
      },
      authority: {
        expired: true,
        permissions: ['read'],
      },
      activationPolicy: {
        requiredGateIds: ['PTAG-016'],
        requiredComponents: ['gateway'],
        sourceRefs: [],
        forbidsProductionTrustClaim: false,
      },
      activationCycle: {
        productionTrustClaim: true,
        openedAtHlc: { physicalMs: 1811000000000, logical: 9 },
      },
      rootBundleEvidence: {
        checkedAtHlc: { physicalMs: 1811000000000, logical: 1 },
      },
      validationEvidence: {
        recordedAtHlc: { physicalMs: 1811000000000, logical: 4 },
      },
      humanReview: {
        decision: 'adapter_activation_ready_for_claim_lift_request',
        reviewedAtHlc: { physicalMs: 1811000000000, logical: 3 },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('human_adapter_activation_reviewer_required'));
  assert.ok(denied.reasons.includes('authority_chain_expired'));
  assert.ok(denied.reasons.includes('adapter_activation_authority_missing'));
  assert.ok(denied.reasons.includes('policy_gate_missing:PTAG-001'));
  assert.ok(denied.reasons.includes('policy_component_missing:node_receipt'));
  assert.ok(denied.reasons.includes('policy_source_ref_missing:docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md'));
  assert.ok(denied.reasons.includes('policy_production_claim_guard_absent'));
  assert.ok(denied.reasons.includes('activation_cycle_production_claim_forbidden'));
  assert.ok(denied.reasons.includes('activation_hlc_order_invalid:root_bundle'));
  assert.ok(denied.reasons.includes('activation_hlc_order_invalid:human_review'));
});

test('adapter activation evidence rejects raw activation payloads protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateAdapterActivationEvidence } = await loadAdapterActivationEvidence();

  assert.throws(
    () =>
      evaluateAdapterActivationEvidence(
        activationInput({
          gatewayEvidence: {
            rawGatewayPayload: {
              participantName: 'Participant Alice',
            },
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateAdapterActivationEvidence(
        activationInput({
          rootBundleEvidence: {
            rootSigningKey: 'not allowed',
          },
        }),
      ),
    /secret field|secret material/i,
  );
});
