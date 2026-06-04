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

async function loadTrustAdapter() {
  try {
    return await import('../src/trust-adapter.mjs');
  } catch (error) {
    assert.fail(`CyberMedica trust adapter module must exist and load: ${error.message}`);
  }
}

const verifiedDependency = Object.freeze({ verified: true });

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

const rootHashEvidence = Object.freeze({
  artifactRegistryHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  operationsRunbookHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  rootTrustBundleHash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  rosterHash: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
});

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

test('production Exochain trust claims remain inactive without verified root and adapter evidence', async () => {
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();

  const result = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: null,
    gatewayAdapter: null,
    receiptPath: null,
    privacyBoundary: null,
    decisionForum: null,
  });

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'inactive');
  assert.equal(result.failClosed, true);
  assert.deepEqual(result.blockedBy, [
    'root_bundle_absent',
    'root_certifier_roster_absent',
    'root_dkg_transcript_absent',
    'root_threshold_signature_absent',
    'root_verifier_absent',
    'gateway_adapter_unverified',
    'receipt_path_unverified',
    'privacy_boundary_unverified',
    'decision_forum_unverified',
  ]);
  assert.equal(result.exochainProductionClaim, false);
  assert.match(result.displayLabel, /inactive/i);
  assert.doesNotMatch(result.claimLanguage, /root-backed production authority/i);
});

test('production activation distinguishes pending denied and verified evidence states', async () => {
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();

  const pending = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: {
      status: 'pending',
      verified: false,
      certifierCount: 13,
      dkgParticipantCount: 13,
      thresholdSignature: '7-of-13',
      verifierReceiptId: 'root-verifier-pending-alpha',
    },
    gatewayAdapter: verifiedDependency,
    receiptPath: verifiedDependency,
    privacyBoundary: verifiedDependency,
    decisionForum: verifiedDependency,
  });

  assert.equal(pending.allowed, false);
  assert.equal(pending.state, 'pending');
  assert.equal(pending.failClosed, true);
  assert.deepEqual(pending.blockedBy, ['root_verifier_pending']);

  const denied = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: {
      status: 'failed',
      verified: false,
      certifierCount: 12,
      dkgParticipantCount: 12,
      thresholdSignature: '6-of-13',
      verifierReceiptId: '',
    },
    gatewayAdapter: verifiedDependency,
    receiptPath: verifiedDependency,
    privacyBoundary: verifiedDependency,
    decisionForum: verifiedDependency,
  });

  assert.equal(denied.allowed, false);
  assert.equal(denied.state, 'denied');
  assert.ok(denied.blockedBy.includes('root_certifier_roster_absent'));
  assert.ok(denied.blockedBy.includes('root_dkg_transcript_absent'));
  assert.ok(denied.blockedBy.includes('root_threshold_signature_absent'));
  assert.ok(denied.blockedBy.includes('root_verifier_absent'));

  const verified = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: {
      status: 'verified',
      verified: true,
      certifierCount: 13,
      dkgParticipantCount: 13,
      thresholdSignature: '7-of-13',
      verifierReceiptId: 'root-verifier-receipt-alpha',
      ...rootHashEvidence,
    },
    gatewayAdapter: verifiedDependency,
    receiptPath: verifiedDependency,
    privacyBoundary: verifiedDependency,
    decisionForum: verifiedDependency,
  });

  assert.equal(verified.allowed, true);
  assert.equal(verified.state, 'verified');
  assert.equal(verified.exochainProductionClaim, true);
  assert.deepEqual(verified.blockedBy, []);
});

test('production activation denies root evidence that lacks immutable registry and bundle hashes', async () => {
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();

  const result = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: {
      status: 'verified',
      verified: true,
      certifierCount: 13,
      dkgParticipantCount: 13,
      thresholdSignature: '7-of-13',
      verifierReceiptId: 'root-verifier-receipt-alpha',
    },
    gatewayAdapter: verifiedDependency,
    receiptPath: verifiedDependency,
    privacyBoundary: verifiedDependency,
    decisionForum: verifiedDependency,
  });

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'denied');
  assert.equal(result.exochainProductionClaim, false);
  assert.ok(result.blockedBy.includes('root_trust_bundle_hash_invalid'));
  assert.ok(result.blockedBy.includes('root_roster_hash_invalid'));
  assert.ok(result.blockedBy.includes('root_artifact_registry_hash_invalid'));
  assert.ok(result.blockedBy.includes('root_operations_runbook_hash_invalid'));
});

test('production activation rejects protected or secret material in activation evidence', async () => {
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();

  const result = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: {
      status: 'verified',
      verified: true,
      certifierCount: 13,
      dkgParticipantCount: 13,
      thresholdSignature: '7-of-13',
      verifierReceiptId: 'root-verifier-receipt-alpha',
      artifactStorePayload: { accessToken: 'redacted-access-token' },
    },
    gatewayAdapter: { verified: true, healthPayload: { apiKey: 'redacted-api-key' } },
    receiptPath: { verified: true, debugPayload: { participantName: 'Participant Alice Example' } },
    privacyBoundary: { verified: true, telemetryPayload: { rawPhi: 'Participant Alice Example MRN: A-123' } },
    decisionForum: { verified: true, logPayload: { clientSecret: 'redacted-client-secret' } },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.exochainProductionClaim, false);
  assert.ok(result.blockedBy.includes('root_bundle_activation_payload_disclosure'));
  assert.ok(result.blockedBy.includes('gateway_adapter_activation_payload_disclosure'));
  assert.ok(result.blockedBy.includes('receipt_path_activation_payload_disclosure'));
  assert.ok(result.blockedBy.includes('privacy_boundary_activation_payload_disclosure'));
  assert.ok(result.blockedBy.includes('decision_forum_activation_payload_disclosure'));
  assert.doesNotMatch(JSON.stringify(result), /redacted-access-token|redacted-api-key|Participant Alice|redacted-client-secret/u);
});

test('production activation rejects simulated cached or overridden activation evidence', async () => {
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();

  const result = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: {
      status: 'verified',
      verified: true,
      certifierCount: 13,
      dkgParticipantCount: 13,
      thresholdSignature: '7-of-13',
      verifierReceiptId: 'root-verifier-receipt-alpha',
      locallySimulated: true,
    },
    gatewayAdapter: { verified: true, cacheHit: true },
    receiptPath: { verified: true, overrideApplied: true },
    privacyBoundary: { verified: true, cachedOutcome: true },
    decisionForum: { verified: true, simulated: true },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.exochainProductionClaim, false);
  assert.ok(result.blockedBy.includes('root_bundle_local_simulation_forbidden'));
  assert.ok(result.blockedBy.includes('gateway_adapter_cached_outcome_forbidden'));
  assert.ok(result.blockedBy.includes('receipt_path_override_forbidden'));
  assert.ok(result.blockedBy.includes('privacy_boundary_cached_outcome_forbidden'));
  assert.ok(result.blockedBy.includes('decision_forum_local_simulation_forbidden'));
  assert.doesNotMatch(result.claimLanguage, /verified for this CyberMedica action/i);
});

test('production activation carries inactive public claim review lineage without lifting trust claims', async () => {
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();

  const result = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: null,
    gatewayAdapter: verifiedDependency,
    receiptPath: verifiedDependency,
    privacyBoundary: verifiedDependency,
    decisionForum: verifiedDependency,
    publicClaimReviewRequired: true,
    publicClaimReviewLineage: inactivePublicClaimReviewLineage,
  });

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'inactive');
  assert.equal(result.failClosed, true);
  assert.equal(result.exochainProductionClaim, false);
  assert.ok(result.blockedBy.includes('root_bundle_absent'));
  assert.ok(!result.blockedBy.some((reason) => reason.startsWith('public_claim_review_')));
  assert.equal(result.publicClaimReviewReceiptHash, DIGEST_1);
  assert.equal(result.publicClaimReviewPackageHash, DIGEST_2);
  assert.equal(result.publicClaimReviewStatus, 'approved_for_public_use');
  assert.equal(result.publicClaimReviewTrustState, 'inactive');
  assert.equal(result.publicClaimReviewProductionClaimLiftReceiptHash, DIGEST_3);
  assert.equal(result.publicClaimReviewProductionClaimLiftTrustState, 'inactive');
  assert.equal(result.publicClaimReviewProductionClaimLiftCanLiftProductionClaim, false);
  assert.equal(result.publicClaimReviewProductionClaimLiftRoleDashboardProviderReceiptHash, DIGEST_B);
  assert.equal(result.publicClaimReviewProductionClaimLiftRoleDashboardProviderSummaryHash, DIGEST_C);
  assert.equal(result.publicClaimReviewProductionClaimLiftRoleDashboardProviderTrustStateViewHash, DIGEST_D);
  assert.equal(result.publicClaimReviewProductionClaimLiftRoleDashboardReadinessReceiptHash, DIGEST_E);
  assert.equal(result.publicClaimReviewProductionClaimLiftRoleDashboardReadinessSummaryHash, DIGEST_F);
  assert.equal(result.publicClaimReviewProductionClaimLiftRoleDashboardReadinessTrustStateViewHash, DIGEST_1);
  assert.equal(result.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash, DIGEST_B);
  assert.equal(result.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash, DIGEST_C);
  assert.equal(result.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash, DIGEST_D);
  assert.equal(result.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash, DIGEST_E);
  assert.equal(result.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash, DIGEST_F);
  assert.equal(result.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash, DIGEST_1);
  assert.equal(
    result.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    result.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash,
    DIGEST_C,
  );
  assert.equal(
    result.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    DIGEST_D,
  );
  assert.equal(
    result.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash,
    DIGEST_E,
  );
  assert.equal(
    result.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash,
    DIGEST_F,
  );
  assert.equal(
    result.publicClaimReviewProductionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    DIGEST_1,
  );
  assert.deepEqual(result.publicClaimReviewProductionClaimLiftRoleDashboardRoles, REQUIRED_ROLE_DASHBOARD_ROLES);
  assert.equal(result.publicClaimReviewPublicUseAuthorized, true);
  assert.doesNotMatch(JSON.stringify(result), /root-backed production authority|AI-IRB approval|Participant Alice/iu);
});

test('production activation fails closed for missing or unsafe public claim review lineage', async () => {
  const { evaluateProductionTrustActivation } = await loadTrustAdapter();

  const missing = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: null,
    gatewayAdapter: verifiedDependency,
    receiptPath: verifiedDependency,
    privacyBoundary: verifiedDependency,
    decisionForum: verifiedDependency,
    publicClaimReviewRequired: true,
    publicClaimReviewLineage: null,
  });
  const unsafe = evaluateProductionTrustActivation({
    claimId: 'PTAG-001',
    rootBundle: null,
    gatewayAdapter: verifiedDependency,
    receiptPath: verifiedDependency,
    privacyBoundary: verifiedDependency,
    decisionForum: verifiedDependency,
    publicClaimReviewRequired: true,
    publicClaimReviewLineage: {
      receiptHash: 'not-a-digest',
      receiptId: '',
      receiptArtifactType: 'public_claim_summary',
      status: 'approved_for_root_backed_language',
      reviewPackageHash: null,
      trustState: 'verified',
      publicUseAuthorized: true,
      exochainProductionClaim: true,
      aiIrbPublicLanguageAllowed: true,
      productionClaimLiftReceiptHash: 'bad-claim-lift-receipt',
      productionClaimLiftTrustState: 'verified',
      productionClaimLiftCanLiftProductionClaim: true,
      productionClaimLiftRoleDashboardProviderReceiptHash: DIGEST_B,
      productionClaimLiftRoleDashboardProviderSummaryHash: DIGEST_C,
      productionClaimLiftRoleDashboardProviderTrustStateViewHash: DIGEST_D,
      productionClaimLiftRoleDashboardReadinessReceiptHash: DIGEST_E,
      productionClaimLiftRoleDashboardReadinessSummaryHash: DIGEST_F,
      productionClaimLiftRoleDashboardReadinessTrustStateViewHash: DIGEST_1,
      productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_D,
      productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
      productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_2,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_E,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_2,
      productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_3,
      productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_4,
      productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_5,
      productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_6,
      productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_7,
      productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_8,
      productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_A,
      productionClaimLiftRoleDashboardRoles: REQUIRED_ROLE_DASHBOARD_ROLES.filter((role) => role !== 'sponsor_viewer').concat(
        'marketing_admin',
      ),
      metadataOnly: false,
      protectedContentExcluded: false,
    },
  });

  assert.ok(missing.blockedBy.includes('public_claim_review_lineage_absent'));
  assert.ok(missing.blockedBy.includes('public_claim_review_receipt_hash_invalid'));
  assert.ok(missing.blockedBy.includes('public_claim_review_package_hash_invalid'));
  assert.equal(missing.exochainProductionClaim, false);

  assert.ok(unsafe.blockedBy.includes('public_claim_review_receipt_hash_invalid'));
  assert.ok(unsafe.blockedBy.includes('public_claim_review_receipt_id_absent'));
  assert.ok(unsafe.blockedBy.includes('public_claim_review_receipt_type_invalid'));
  assert.ok(unsafe.blockedBy.includes('public_claim_review_status_invalid'));
  assert.ok(unsafe.blockedBy.includes('public_claim_review_package_hash_invalid'));
  assert.ok(unsafe.blockedBy.includes('public_claim_review_trust_state_invalid'));
  assert.ok(unsafe.blockedBy.includes('public_claim_review_production_claim_forbidden'));
  assert.ok(unsafe.blockedBy.includes('public_claim_review_ai_irb_language_forbidden'));
  assert.ok(unsafe.blockedBy.includes('public_claim_review_production_claim_lift_receipt_hash_invalid'));
  assert.ok(unsafe.blockedBy.includes('public_claim_review_production_claim_lift_state_invalid'));
  assert.ok(unsafe.blockedBy.includes('public_claim_review_production_claim_lift_public_claim_forbidden'));
  assert.ok(
    unsafe.blockedBy.includes('public_claim_review_production_claim_lift_role_dashboard_role_missing:sponsor_viewer'),
  );
  assert.ok(
    unsafe.blockedBy.includes('public_claim_review_production_claim_lift_role_dashboard_role_unsupported:marketing_admin'),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_summary_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_summary_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'public_claim_review_production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_summary_mismatch',
    ),
  );
  assert.ok(
    unsafe.blockedBy.includes(
      'public_claim_review_production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(unsafe.blockedBy.includes('public_claim_review_metadata_boundary_invalid'));
  assert.ok(unsafe.blockedBy.includes('public_claim_review_protected_boundary_invalid'));
  assert.equal(unsafe.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(unsafe), /root-backed production authority|AI-IRB approval|Participant Alice/iu);
});
