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

async function loadTrustStateView() {
  try {
    return await import('../src/trust-state-view.mjs');
  } catch (error) {
    assert.fail(`CyberMedica trust-state view module must exist and load: ${error.message}`);
  }
}

async function loadTrustAdapter() {
  try {
    return await import('../src/trust-adapter.mjs');
  } catch (error) {
    assert.fail(`CyberMedica trust adapter module must exist and load: ${error.message}`);
  }
}

const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_3 = '3333333333333333333333333333333333333333333333333333333333333333';
const DIGEST_4 = '4444444444444444444444444444444444444444444444444444444444444444';
const DIGEST_5 = '5555555555555555555555555555555555555555555555555555555555555555';
const DIGEST_6 = '6666666666666666666666666666666666666666666666666666666666666666';
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

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

const verifiedDependency = Object.freeze({ verified: true });

const inactivePublicClaimReviewLineage = Object.freeze({
  receiptHash: DIGEST_1,
  receiptId: 'cmpcr_public_claim_review_inactive_alpha',
  receiptArtifactType: 'public_claim_review',
  status: 'approved_for_public_use',
  reviewPackageHash: DIGEST_2,
  trustState: 'inactive',
  publicUseAuthorized: true,
  exochainProductionClaim: false,
  aiIrbPublicLanguageAllowed: false,
  productionClaimLiftReceiptHash: DIGEST_3,
  productionClaimLiftTrustState: 'inactive',
  productionClaimLiftCanLiftProductionClaim: false,
  productionClaimLiftRoleDashboardProviderReceiptHash: DIGEST_B,
  productionClaimLiftRoleDashboardProviderSummaryHash: DIGEST_C,
  productionClaimLiftRoleDashboardProviderTrustStateViewHash: DIGEST_D,
  productionClaimLiftRoleDashboardReadinessReceiptHash: DIGEST_E,
  productionClaimLiftRoleDashboardReadinessSummaryHash: DIGEST_F,
  productionClaimLiftRoleDashboardReadinessTrustStateViewHash: DIGEST_1,
  productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_B,
  productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
  productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_D,
  productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_E,
  productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_F,
  productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_1,
  productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_B,
  productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
  productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_D,
  productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_E,
  productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_F,
  productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_1,
  productionClaimLiftRoleDashboardRoles: REQUIRED_ROLE_DASHBOARD_ROLES,
  metadataOnly: true,
  protectedContentExcluded: true,
});

test('trust-state UI view models expose inactive pending denied degraded and verified states explicitly', async () => {
  const { buildTrustStateView } = await loadTrustStateView();

  const inactive = buildTrustStateView({ state: 'inactive', blockedBy: ['root_bundle_absent'] });
  assert.equal(inactive.status, 'inactive');
  assert.equal(inactive.actionsDisabled, true);
  assert.equal(inactive.canShowProductionTrustClaim, false);
  assert.doesNotMatch(inactive.primaryText, /root-backed production authority/i);

  const pending = buildTrustStateView({ state: 'pending', blockedBy: ['root_verifier_pending'] });
  assert.equal(pending.status, 'pending');
  assert.equal(pending.actionsDisabled, true);

  const denied = buildTrustStateView({ state: 'denied', blockedBy: ['human_gate_unverified'] });
  assert.equal(denied.status, 'denied');
  assert.equal(denied.actionsDisabled, true);

  const degraded = buildTrustStateView({ state: 'degraded', blockedBy: ['gateway_timeout'] });
  assert.equal(degraded.status, 'degraded');
  assert.equal(degraded.actionsDisabled, true);

  const verified = buildTrustStateView({ state: 'verified', blockedBy: [] });
  assert.equal(verified.status, 'verified');
  assert.equal(verified.actionsDisabled, false);
  assert.equal(verified.canShowProductionTrustClaim, true);
  assert.match(verified.primaryText, /verified/i);
});

test('trust-state UI fails closed when verified evidence carries blockers', async () => {
  const { buildTrustStateView } = await loadTrustStateView();

  const view = buildTrustStateView({
    state: 'verified',
    blockedBy: [
      'gateway_adapter_unverified',
      'root_certifier_roster_absent',
      'human_gate_unverified',
      'gateway_adapter_unverified',
    ],
  });

  assert.equal(view.requestedStatus, 'verified');
  assert.equal(view.status, 'denied');
  assert.equal(view.actionsDisabled, true);
  assert.equal(view.canShowProductionTrustClaim, false);
  assert.deepEqual(view.blockedBy, [
    'gateway_adapter_unverified',
    'human_gate_unverified',
    'root_certifier_roster_absent',
  ]);
  assert.deepEqual(view.bobEscalations, [
    'ESC-HUMAN-PROOFING',
    'ESC-ROOT-ROSTER',
    'ESC-RUNTIME',
  ]);
});

test('trust-state UI removes unsafe blocker text without echoing protected values', async () => {
  const { buildTrustStateView } = await loadTrustStateView();

  const view = buildTrustStateView({
    state: 'pending',
    blockedBy: [
      'root_verifier_absent',
      'Participant Alice Example MRN A-123',
      'client_secret=redacted-client-secret',
      'gateway_timeout',
    ],
  });

  assert.equal(view.status, 'pending');
  assert.deepEqual(view.blockedBy, ['gateway_timeout', 'root_verifier_absent']);
  assert.equal(view.unsafeBlockedByCount, 2);
  assert.deepEqual(view.bobEscalations, ['ESC-ROOT-DEPLOYMENT', 'ESC-RUNTIME']);
  assert.doesNotMatch(JSON.stringify(view), /Participant Alice|MRN A-123|redacted-client-secret/u);
});

test('trust-state UI carries inactive production activation and public-claim-review lineage without lifting claims', async () => {
  const { buildTrustStateView } = await loadTrustStateView();
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();

  const activation = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: null,
    gatewayAdapter: verifiedDependency,
    receiptPath: verifiedDependency,
    privacyBoundary: verifiedDependency,
    decisionForum: verifiedDependency,
    publicClaimReviewRequired: true,
    publicClaimReviewLineage: inactivePublicClaimReviewLineage,
  });

  const view = buildTrustStateView({
    productionTrustActivation: activation,
    requireProductionTrustActivationLineage: true,
    requirePublicClaimReviewLineage: true,
  });

  assert.equal(view.requestedStatus, 'inactive');
  assert.equal(view.status, 'inactive');
  assert.equal(view.actionsDisabled, true);
  assert.equal(view.canShowProductionTrustClaim, false);
  assert.equal(view.activationLineageAccepted, true);
  assert.equal(view.productionTrustActivationLineage.claimId, 'PTAG-001');
  assert.equal(view.productionTrustActivationLineage.activationState, 'inactive');
  assert.equal(view.productionTrustActivationLineage.exochainProductionClaim, false);
  assert.equal(view.productionTrustActivationLineage.publicClaimReviewReceiptHash, DIGEST_1);
  assert.equal(view.productionTrustActivationLineage.publicClaimReviewPackageHash, DIGEST_2);
  assert.equal(view.productionTrustActivationLineage.publicClaimReviewStatus, 'approved_for_public_use');
  assert.equal(view.productionTrustActivationLineage.publicClaimReviewTrustState, 'inactive');
  assert.equal(view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftReceiptHash, DIGEST_3);
  assert.equal(view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftTrustState, 'inactive');
  assert.equal(view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftCanLiftProductionClaim, false);
  assert.equal(
    view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftRoleDashboardProviderReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftRoleDashboardProviderSummaryHash,
    DIGEST_C,
  );
  assert.equal(
    view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftRoleDashboardProviderTrustStateViewHash,
    DIGEST_D,
  );
  assert.equal(
    view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftRoleDashboardReadinessReceiptHash,
    DIGEST_E,
  );
  assert.equal(
    view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftRoleDashboardReadinessSummaryHash,
    DIGEST_F,
  );
  assert.equal(
    view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftRoleDashboardReadinessTrustStateViewHash,
    DIGEST_1,
  );
  assert.equal(
    view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash,
    DIGEST_C,
  );
  assert.equal(
    view.productionTrustActivationLineage
      .publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    DIGEST_D,
  );
  assert.equal(
    view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash,
    DIGEST_E,
  );
  assert.equal(
    view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash,
    DIGEST_F,
  );
  assert.equal(
    view.productionTrustActivationLineage
      .publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    DIGEST_1,
  );
  assert.equal(
    view.productionTrustActivationLineage
      .publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    view.productionTrustActivationLineage
      .publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash,
    DIGEST_C,
  );
  assert.equal(
    view.productionTrustActivationLineage
      .publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    DIGEST_D,
  );
  assert.equal(
    view.productionTrustActivationLineage
      .publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash,
    DIGEST_E,
  );
  assert.equal(
    view.productionTrustActivationLineage
      .publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash,
    DIGEST_F,
  );
  assert.equal(
    view.productionTrustActivationLineage
      .publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    DIGEST_1,
  );
  assert.deepEqual(
    view.productionTrustActivationLineage.publicClaimReviewProductionClaimLiftRoleDashboardRoles,
    REQUIRED_ROLE_DASHBOARD_ROLES,
  );
  assert.ok(view.blockedBy.includes('root_bundle_absent'));
  assert.deepEqual(view.bobEscalations, ['ESC-ROOT-ARTIFACT-STORE', 'ESC-ROOT-DEPLOYMENT', 'ESC-ROOT-ROSTER']);
  assert.doesNotMatch(JSON.stringify(view), /root-backed production authority|AI-IRB approval|Participant Alice/iu);
});

test('trust-state UI fails closed when required production activation lineage is absent', async () => {
  const { buildTrustStateView } = await loadTrustStateView();

  const view = buildTrustStateView({
    state: 'verified',
    blockedBy: [],
    requireProductionTrustActivationLineage: true,
    requirePublicClaimReviewLineage: true,
  });

  assert.equal(view.requestedStatus, 'verified');
  assert.equal(view.status, 'denied');
  assert.equal(view.actionsDisabled, true);
  assert.equal(view.canShowProductionTrustClaim, false);
  assert.equal(view.activationLineageAccepted, false);
  assert.ok(view.blockedBy.includes('production_trust_activation_lineage_absent'));
  assert.ok(view.blockedBy.includes('public_claim_review_lineage_absent'));
  assert.equal(view.productionTrustActivationLineage, null);
});

test('trust-state UI denies unsafe activation or public-claim-review lineage without echoing raw payloads', async () => {
  const { buildTrustStateView } = await loadTrustStateView();

  const view = buildTrustStateView({
    state: 'verified',
    blockedBy: [],
    requireProductionTrustActivationLineage: true,
    requirePublicClaimReviewLineage: true,
    productionTrustActivation: {
      schema: 'cybermedica.production_trust_activation.v1',
      claimId: 'PTAG-001',
      allowed: true,
      state: 'verified',
      failClosed: false,
      blockedBy: ['Participant Alice Example MRN: A-123'],
      exochainProductionClaim: true,
      publicClaimReviewReceiptHash: 'not-a-digest',
      publicClaimReviewPackageHash: DIGEST_2,
      publicClaimReviewStatus: 'approved_for_root_backed_language',
      publicClaimReviewTrustState: 'verified',
      publicClaimReviewPublicUseAuthorized: true,
      publicClaimReviewProductionClaimLiftReceiptHash: 'bad-lift-receipt',
      publicClaimReviewProductionClaimLiftTrustState: 'verified',
      publicClaimReviewProductionClaimLiftCanLiftProductionClaim: true,
      publicClaimReviewProductionClaimLiftRoleDashboardProviderReceiptHash: DIGEST_B,
      publicClaimReviewProductionClaimLiftRoleDashboardProviderSummaryHash: DIGEST_C,
      publicClaimReviewProductionClaimLiftRoleDashboardProviderTrustStateViewHash: DIGEST_D,
      publicClaimReviewProductionClaimLiftRoleDashboardReadinessReceiptHash: DIGEST_E,
      publicClaimReviewProductionClaimLiftRoleDashboardReadinessSummaryHash: DIGEST_F,
      publicClaimReviewProductionClaimLiftRoleDashboardReadinessTrustStateViewHash: DIGEST_1,
      publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_D,
      publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
      publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_2,
      publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_E,
      publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_2,
      publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_3,
      publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_4,
      publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_5,
      publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_6,
      publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_7,
      publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_8,
      publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_A,
      publicClaimReviewProductionClaimLiftRoleDashboardRoles: REQUIRED_ROLE_DASHBOARD_ROLES.filter(
        (role) => role !== 'sponsor_viewer',
      ).concat('marketing_admin'),
      claimLanguage: 'root-backed production authority for Participant Alice Example MRN: A-123',
    },
  });

  assert.equal(view.status, 'denied');
  assert.equal(view.actionsDisabled, true);
  assert.equal(view.canShowProductionTrustClaim, false);
  assert.equal(view.activationLineageAccepted, false);
  assert.equal(view.unsafeBlockedByCount, 1);
  assert.ok(view.blockedBy.includes('production_trust_activation_blocker_payload_disclosure'));
  assert.ok(view.blockedBy.includes('public_claim_review_receipt_hash_invalid'));
  assert.ok(view.blockedBy.includes('public_claim_review_status_invalid'));
  assert.ok(view.blockedBy.includes('public_claim_review_trust_state_invalid'));
  assert.ok(view.blockedBy.includes('public_claim_review_production_claim_lift_receipt_hash_invalid'));
  assert.ok(view.blockedBy.includes('public_claim_review_production_claim_lift_state_invalid'));
  assert.ok(view.blockedBy.includes('public_claim_review_production_claim_lift_public_claim_forbidden'));
  assert.ok(
    view.blockedBy.includes('public_claim_review_production_claim_lift_role_dashboard_role_missing:sponsor_viewer'),
  );
  assert.ok(
    view.blockedBy.includes('public_claim_review_production_claim_lift_role_dashboard_role_unsupported:marketing_admin'),
  );
  assert.ok(
    view.blockedBy.includes(
      'public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    view.blockedBy.includes(
      'public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_summary_mismatch',
    ),
  );
  assert.ok(
    view.blockedBy.includes(
      'public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    view.blockedBy.includes(
      'public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    view.blockedBy.includes(
      'public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    view.blockedBy.includes(
      'public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_summary_mismatch',
    ),
  );
  assert.ok(
    view.blockedBy.includes(
      'public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    view.blockedBy.includes(
      'public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    view.blockedBy.includes(
      'public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_summary_mismatch',
    ),
  );
  assert.ok(
    view.blockedBy.includes(
      'public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.doesNotMatch(JSON.stringify(view), /Participant Alice|MRN: A-123|root-backed production authority/iu);
});
