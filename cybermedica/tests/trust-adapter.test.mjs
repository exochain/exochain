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
import { evaluateProductionTrustActivation, TrustState } from '../src/trust-adapter.mjs';

const verifiedRootBundle = Object.freeze({
  status: 'verified',
  verified: true,
  certifierCount: 13,
  dkgParticipantCount: 13,
  thresholdSignature: '7-of-13',
  verifierReceiptId: 'root-verifier-receipt-alpha',
  artifactRegistryHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  operationsRunbookHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  rootTrustBundleHash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  rosterHash: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
});

const verifiedDependency = Object.freeze({ verified: true });
const DIGEST_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const DIGEST_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const DIGEST_C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const DIGEST_D = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const DIGEST_E = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const DIGEST_F = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const DIGEST_1 = '1111111111111111111111111111111111111111111111111111111111111111';
const DIGEST_2 = '2222222222222222222222222222222222222222222222222222222222222222';
const DIGEST_3 = '3333333333333333333333333333333333333333333333333333333333333333';

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

function activationInput(overrides = {}) {
  return {
    claimId: 'PTAG-001',
    rootBundle: verifiedRootBundle,
    gatewayAdapter: verifiedDependency,
    receiptPath: verifiedDependency,
    privacyBoundary: verifiedDependency,
    decisionForum: verifiedDependency,
    ...overrides,
  };
}

function publicClaimReviewLineage(overrides = {}) {
  return {
    receiptHash: DIGEST_A,
    receiptId: 'cmpcr_public_claim_review_alpha',
    receiptArtifactType: 'public_claim_review',
    status: 'approved_for_public_use',
    reviewPackageHash: DIGEST_B,
    trustState: TrustState.INACTIVE,
    publicUseAuthorized: true,
    exochainProductionClaim: false,
    aiIrbPublicLanguageAllowed: false,
    productionClaimLiftReceiptHash: DIGEST_C,
    productionClaimLiftTrustState: TrustState.INACTIVE,
    productionClaimLiftCanLiftProductionClaim: false,
    productionClaimLiftRoleDashboardProviderReceiptHash: DIGEST_D,
    productionClaimLiftRoleDashboardProviderSummaryHash: DIGEST_E,
    productionClaimLiftRoleDashboardProviderTrustStateViewHash: DIGEST_F,
    productionClaimLiftRoleDashboardReadinessReceiptHash: DIGEST_1,
    productionClaimLiftRoleDashboardReadinessSummaryHash: DIGEST_2,
    productionClaimLiftRoleDashboardReadinessTrustStateViewHash: DIGEST_3,
    productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_D,
    productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_E,
    productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_F,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_1,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_2,
    productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_3,
    productionClaimLiftRoleDashboardRoles: REQUIRED_ROLE_DASHBOARD_ROLES,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

test('TrustState exposes the complete inactive production-trust UI state set', () => {
  assert.deepEqual(TrustState, {
    INACTIVE: 'inactive',
    PENDING: 'pending',
    DENIED: 'denied',
    DEGRADED: 'degraded',
    VERIFIED: 'verified',
  });
});

test('production activation fails closed for explicit non-ok activation dependency statuses', () => {
  const result = evaluateProductionTrustActivation(
    activationInput({
      gatewayAdapter: { verified: true, status: 'error' },
      receiptPath: { verified: true, status: 'denied' },
      privacyBoundary: { verified: true, status: 'failed' },
      decisionForum: { verified: true, status: 'degraded' },
    }),
  );

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.exochainProductionClaim, false);
  assert.ok(result.blockedBy.includes('gateway_adapter_status_unverified'));
  assert.ok(result.blockedBy.includes('receipt_path_status_unverified'));
  assert.ok(result.blockedBy.includes('privacy_boundary_status_unverified'));
  assert.ok(result.blockedBy.includes('decision_forum_status_unverified'));
  assert.doesNotMatch(result.claimLanguage, /verified for this CyberMedica action/i);
});

test('production activation treats explicit activation dependency timeouts as degraded fail-closed states', () => {
  const result = evaluateProductionTrustActivation(
    activationInput({
      gatewayAdapter: { verified: true, status: 'timeout' },
      receiptPath: { verified: true, timeout: true },
      privacyBoundary: { verified: true },
      decisionForum: { verified: true },
    }),
  );

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'degraded');
  assert.equal(result.failClosed, true);
  assert.equal(result.exochainProductionClaim, false);
  assert.ok(result.blockedBy.includes('gateway_adapter_timeout'));
  assert.ok(result.blockedBy.includes('receipt_path_timeout'));
});

test('production activation rejects contradictory verified root evidence with non-verified status', () => {
  const result = evaluateProductionTrustActivation(
    activationInput({
      rootBundle: {
        ...verifiedRootBundle,
        status: 'failed',
        verified: true,
      },
    }),
  );

  assert.equal(result.allowed, false);
  assert.equal(result.state, 'denied');
  assert.equal(result.exochainProductionClaim, false);
  assert.ok(result.blockedBy.includes('root_verifier_status_unverified'));
});

test('production activation carries public-claim runtime-source trust-state-view lineage', () => {
  const result = evaluateProductionTrustActivation(
    activationInput({
      rootBundle: null,
      publicClaimReviewRequired: true,
      publicClaimReviewLineage: publicClaimReviewLineage(),
    }),
  );

  assert.equal(result.allowed, false);
  assert.equal(result.state, TrustState.INACTIVE);
  assert.equal(result.failClosed, true);
  assert.equal(result.exochainProductionClaim, false);
  assert.equal(result.publicClaimReviewProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash, DIGEST_F);
  assert.equal(result.publicClaimReviewProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash, DIGEST_3);
  assert.ok(result.blockedBy.includes('root_bundle_absent'));
});

test('production activation fails closed on missing or mismatched public-claim runtime-source trust-state-view lineage', () => {
  const missing = evaluateProductionTrustActivation(
    activationInput({
      rootBundle: null,
      publicClaimReviewRequired: true,
      publicClaimReviewLineage: publicClaimReviewLineage({
        productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: null,
        productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: null,
      }),
    }),
  );
  const mismatched = evaluateProductionTrustActivation(
    activationInput({
      rootBundle: null,
      publicClaimReviewRequired: true,
      publicClaimReviewLineage: publicClaimReviewLineage({
        productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_A,
        productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_B,
      }),
    }),
  );

  assert.ok(
    missing.blockedBy.includes(
      'public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    missing.blockedBy.includes(
      'public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    mismatched.blockedBy.includes(
      'public_claim_review_production_claim_lift_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    mismatched.blockedBy.includes(
      'public_claim_review_production_claim_lift_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
    ),
  );
});
