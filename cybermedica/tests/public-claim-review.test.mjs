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

const REQUIRED_PUBLIC_CONTENT_TYPES = [
  'case_study',
  'demo_script',
  'one_page_product_thesis',
  'press_release',
  'sales_deck',
  'sponsor_diligence_pitch',
  'website_copy',
];

const REQUIRED_CLAIM_FAMILIES = [
  'ai_irb_language',
  'audit_ready_evidence',
  'clinical_research_safety',
  'exochain_trust',
  'qms_readiness',
  'site_readiness',
];

const REQUIRED_REVIEWER_ROLES = ['legal', 'product_governance', 'quality', 'regulatory'];

const BASELINE_SAFE_CLAIM_CATEGORIES = [
  'audit_ready_evidence',
  'qms_passport',
  'site_readiness_fabric',
  'standard_aligned_governance_layer',
];

const PRODUCTION_CLAIM_LIFT_BLOCKERS = [
  'public_claim_copy_not_authorized_for_root_backed_language',
  'root_trust_bundle_not_verified',
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

async function loadPublicClaimReview() {
  try {
    return await import('../src/public-claim-review.mjs');
  } catch (error) {
    assert.fail(`CyberMedica public claim review module must exist and load: ${error.message}`);
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

function contentAsset(contentType, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1];
  return {
    assetRef: `public-asset-${contentType}-alpha`,
    contentType,
    artifactHash: hashes[index],
    audience: contentType === 'sponsor_diligence_pitch' ? 'sponsor_cro' : 'public',
    publicNonSensitiveClassification: true,
    legalRegulatoryReviewRequired: true,
    approvedForPublicUse: true,
    rawCopyExcluded: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    reviewedAtHlc: { physicalMs: 1806200100000, logical: index },
    ...overrides,
  };
}

function contentAssets() {
  return REQUIRED_PUBLIC_CONTENT_TYPES.map((contentType, index) => contentAsset(contentType, index));
}

function claimRecord(family, index, overrides = {}) {
  const categories = [
    'standard_aligned_governance_layer',
    'audit_ready_evidence',
    'qms_passport',
    'site_readiness_fabric',
    'standard_aligned_governance_layer',
    'audit_ready_evidence',
  ];
  return {
    claimRef: `public-claim-${family}`,
    family,
    safestClaimCategory: categories[index],
    claimHash: [DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_A][index],
    evidenceHash: [DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1][index],
    approvedForPublicUse: true,
    aiIrbEquivalentLanguageAbsent: true,
    irbIecSubstitutionClaimAbsent: true,
    exochainProductionClaimAbsent: true,
    legalRegulatoryReviewRequired: true,
    classifiedAtHlc: { physicalMs: 1806200200000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function claimRecords() {
  return REQUIRED_CLAIM_FAMILIES.map((family, index) => claimRecord(family, index));
}

function reviewFor(claim, reviewerRole, index, overrides = {}) {
  return {
    reviewRef: `public-review-${claim.family}-${reviewerRole}`,
    claimRef: claim.claimRef,
    reviewerRole,
    reviewerDid: `did:exo:${reviewerRole}-public-claim-reviewer-alpha`,
    decision: 'approved',
    reviewHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D][index],
    reviewedAtHlc: { physicalMs: 1806200300000 + index, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function reviewsForClaims(claims = claimRecords()) {
  return claims.flatMap((claim) => REQUIRED_REVIEWER_ROLES.map((role, index) => reviewFor(claim, role, index)));
}

function publicClaimInput(overrides = {}) {
  const claims = claimRecords();
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:public-claim-steward-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'product_governance_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['public_claim_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    publicClaimPolicy: {
      policyRef: 'public-claim-review-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredContentTypes: REQUIRED_PUBLIC_CONTENT_TYPES,
      requiredClaimFamilies: REQUIRED_CLAIM_FAMILIES,
      requiredReviewerRoles: REQUIRED_REVIEWER_ROLES,
      baselineSafeClaimCategories: BASELINE_SAFE_CLAIM_CATEGORIES,
      aiIrbPublicLanguageBlocked: true,
      irbIecSubstitutionBlocked: true,
      productionTrustClaimsInactive: true,
      legalRegulatoryReviewRequired: true,
      salesContentReviewRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1806200000000, logical: 0 },
    },
    contentRegister: {
      registerRef: 'public-content-register-alpha',
      sourcePrdHash: DIGEST_C,
      sandyReviewRegisterHash: DIGEST_D,
      manualClaimReviewReceiptHash: DIGEST_E,
      productionClaimLiftReceiptHash: null,
      noRawCopyStored: true,
      compiledAtHlc: { physicalMs: 1806200050000, logical: 0 },
      contentAssets: contentAssets(),
      claimRecords: claims,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    reviews: reviewsForClaims(claims),
    publicationGate: {
      gateRef: 'public-publication-gate-alpha',
      safePublicClaimCategory: 'standard_aligned_governance_layer',
      websiteCopyApproved: true,
      salesMaterialsApproved: true,
      aiIrbPublicLanguageAllowed: false,
      irbIecSubstitutionClaimAllowed: false,
      exochainProductionClaimAllowed: false,
      highRiskClaimsHeld: false,
      publicUseAuthorized: true,
      gatedAtHlc: { physicalMs: 1806200450000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    aiAssistant: {
      used: true,
      recommendationHash: DIGEST_F,
      limitationHashes: [DIGEST_1],
      advisoryOnly: true,
      finalAuthority: false,
      humanReviewed: true,
      reviewedAtHlc: { physicalMs: 1806200400000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:public-claim-owner-alpha',
      reviewerRoleRefs: REQUIRED_REVIEWER_ROLES,
      decision: 'public_claims_approved_for_use',
      decisionHash: DIGEST_2,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1806200500000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    validationEvidence: {
      commandRefs: ['node --test tests/public-claim-review.test.mjs', 'npm run quality'],
      commandsPassed: true,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      recordedAtHlc: { physicalMs: 1806200600000, logical: 0 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_3,
  };
  return mergeDeep(base, overrides);
}

function inactiveProductionClaimLiftLineage(overrides = {}) {
  const base = {
    receiptHash: DIGEST_7,
    receiptId: 'cmclaim_public_claim_lift_inactive_alpha',
    receiptSchema: 'cybermedica.production_claim_lift_receipt.v1',
    actionHash: DIGEST_8,
    claimGateId: 'PTAG-001',
    state: 'denied',
    trustState: 'inactive',
    canLiftProductionClaim: false,
    exochainProductionClaim: false,
    blockedBy: PRODUCTION_CLAIM_LIFT_BLOCKERS,
    verifiedCriteria: ['adapter_boundary', 'privacy_boundary', 'test_matrix'],
    adapterActivationHandoffProviderRoleDashboardReceiptHash: DIGEST_B,
    adapterActivationHandoffProviderRoleDashboardSummaryHash: DIGEST_C,
    adapterActivationHandoffProviderRoleDashboardTrustStateViewHash: DIGEST_D,
    adapterActivationHandoffReadinessRoleDashboardReceiptHash: DIGEST_E,
    adapterActivationHandoffReadinessRoleDashboardSummaryHash: DIGEST_F,
    adapterActivationHandoffReadinessRoleDashboardTrustStateViewHash: DIGEST_1,
    adapterActivationRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_B,
    adapterActivationRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
    adapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_D,
    adapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_E,
    adapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_F,
    adapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_1,
    adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_B,
    adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
    adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_D,
    adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_E,
    adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_F,
    adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_1,
    adapterActivationDeploymentHandoffCutoverRoleDashboardRoles: REQUIRED_ROLE_DASHBOARD_ROLES,
    metadataOnly: true,
    protectedContentExcluded: true,
    reviewedAtHlc: { physicalMs: 1806200470000, logical: 0 },
  };
  return mergeDeep(base, overrides);
}

test('public claim review creates deterministic inactive sales and public-copy approval receipts', async () => {
  const { evaluatePublicClaimReview } = await loadPublicClaimReview();

  const first = evaluatePublicClaimReview(publicClaimInput());
  const second = evaluatePublicClaimReview({
    ...publicClaimInput(),
    contentRegister: {
      ...publicClaimInput().contentRegister,
      contentAssets: [...publicClaimInput().contentRegister.contentAssets].reverse(),
      claimRecords: [...publicClaimInput().contentRegister.claimRecords].reverse(),
    },
    reviews: [...publicClaimInput().reviews].reverse(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.publicClaimReview.status, 'approved_for_public_use');
  assert.equal(first.publicClaimReview.trustState, 'inactive');
  assert.equal(first.publicClaimReview.exochainProductionClaim, false);
  assert.equal(first.publicClaimReview.metadataOnly, true);
  assert.equal(first.publicClaimReview.containsProtectedContent, false);
  assert.equal(first.publicClaimReview.aiIrbPublicLanguageAllowed, false);
  assert.equal(first.publicClaimReview.publicUseAuthorized, true);
  assert.deepEqual(first.publicClaimReview.contentTypes, REQUIRED_PUBLIC_CONTENT_TYPES);
  assert.deepEqual(first.publicClaimReview.claimFamilies, REQUIRED_CLAIM_FAMILIES);
  assert.deepEqual(first.publicClaimReview.requiredReviewerRoles, REQUIRED_REVIEWER_ROLES);
  assert.deepEqual(first.publicClaimReview.baselineSafeClaimCategories, BASELINE_SAFE_CLAIM_CATEGORIES);
  assert.equal(first.publicClaimReview.reviewedClaimCount, REQUIRED_CLAIM_FAMILIES.length);
  assert.equal(first.publicClaimReview.reviewPackageHash, second.publicClaimReview.reviewPackageHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.anchorPayload.artifactType, 'public_claim_review');
  assert.equal(first.receipt.anchorPayload.classification, 'metadata_only_public_claim_review');
  assert.doesNotMatch(JSON.stringify(first), /raw sales|Participant Alice|root-backed production authority|AI-IRB approval/iu);
});

test('public claim review carries inactive production claim lift lineage without public trust claims', async () => {
  const { evaluatePublicClaimReview } = await loadPublicClaimReview();

  const first = evaluatePublicClaimReview(
    publicClaimInput({
      contentRegister: {
        productionClaimLiftReceiptHash: DIGEST_7,
      },
      productionClaimLiftLineage: inactiveProductionClaimLiftLineage(),
    }),
  );
  const second = evaluatePublicClaimReview(
    publicClaimInput({
      contentRegister: {
        productionClaimLiftReceiptHash: DIGEST_7,
      },
      productionClaimLiftLineage: inactiveProductionClaimLiftLineage({
        blockedBy: [...PRODUCTION_CLAIM_LIFT_BLOCKERS].reverse(),
        verifiedCriteria: ['test_matrix', 'privacy_boundary', 'adapter_boundary'],
      }),
    }),
  );

  assert.equal(first.decision, 'permitted');
  assert.equal(first.publicClaimReview.productionClaimLiftReceiptHash, DIGEST_7);
  assert.equal(first.publicClaimReview.productionClaimLiftActionHash, DIGEST_8);
  assert.equal(first.publicClaimReview.productionClaimLiftClaimGateId, 'PTAG-001');
  assert.equal(first.publicClaimReview.productionClaimLiftTrustState, 'inactive');
  assert.equal(first.publicClaimReview.productionClaimLiftCanLiftProductionClaim, false);
  assert.deepEqual(first.publicClaimReview.productionClaimLiftBlockedBy, PRODUCTION_CLAIM_LIFT_BLOCKERS);
  assert.equal(first.publicClaimReview.productionClaimLiftRoleDashboardProviderReceiptHash, DIGEST_B);
  assert.equal(first.publicClaimReview.productionClaimLiftRoleDashboardProviderSummaryHash, DIGEST_C);
  assert.equal(first.publicClaimReview.productionClaimLiftRoleDashboardProviderTrustStateViewHash, DIGEST_D);
  assert.equal(first.publicClaimReview.productionClaimLiftRoleDashboardReadinessReceiptHash, DIGEST_E);
  assert.equal(first.publicClaimReview.productionClaimLiftRoleDashboardReadinessSummaryHash, DIGEST_F);
  assert.equal(first.publicClaimReview.productionClaimLiftRoleDashboardReadinessTrustStateViewHash, DIGEST_1);
  assert.equal(first.publicClaimReview.productionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash, DIGEST_B);
  assert.equal(first.publicClaimReview.productionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash, DIGEST_C);
  assert.equal(first.publicClaimReview.productionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash, DIGEST_D);
  assert.equal(first.publicClaimReview.productionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash, DIGEST_E);
  assert.equal(first.publicClaimReview.productionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash, DIGEST_F);
  assert.equal(first.publicClaimReview.productionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash, DIGEST_1);
  assert.equal(
    first.publicClaimReview.productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardReceiptHash,
    DIGEST_B,
  );
  assert.equal(
    first.publicClaimReview.productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardSummaryHash,
    DIGEST_C,
  );
  assert.equal(
    first.publicClaimReview.productionClaimLiftAdapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash,
    DIGEST_D,
  );
  assert.equal(
    first.publicClaimReview.productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash,
    DIGEST_E,
  );
  assert.equal(
    first.publicClaimReview.productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash,
    DIGEST_F,
  );
  assert.equal(
    first.publicClaimReview.productionClaimLiftAdapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash,
    DIGEST_1,
  );
  assert.deepEqual(first.publicClaimReview.productionClaimLiftRoleDashboardRoles, REQUIRED_ROLE_DASHBOARD_ROLES);
  assert.equal(first.publicClaimReview.exochainProductionClaim, false);
  assert.equal(first.publicClaimReview.aiIrbPublicLanguageAllowed, false);
  assert.equal(first.publicClaimReview.reviewPackageHash, second.publicClaimReview.reviewPackageHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.ok(first.receipt.anchorPayload.sensitivityTags.includes('production_claim_lift_lineage'));
  assert.ok(first.receipt.anchorPayload.sensitivityTags.includes('production_claim_lift_role_dashboard_lineage'));
  assert.ok(
    first.receipt.anchorPayload.sensitivityTags.includes(
      'production_claim_lift_runtime_source_trust_state_view_lineage',
    ),
  );
  assert.doesNotMatch(JSON.stringify(first), /root-backed production authority|AI-IRB approval|Participant Alice/iu);
});

test('public claim review fails closed for unsafe production claim lift lineage', async () => {
  const { evaluatePublicClaimReview } = await loadPublicClaimReview();

  const missing = evaluatePublicClaimReview(
    publicClaimInput({
      contentRegister: {
        productionClaimLiftReceiptHash: DIGEST_7,
      },
      productionClaimLiftLineage: null,
    }),
  );
  const unsafe = evaluatePublicClaimReview(
    publicClaimInput({
      contentRegister: {
        productionClaimLiftReceiptHash: DIGEST_7,
      },
      productionClaimLiftLineage: inactiveProductionClaimLiftLineage({
        receiptHash: DIGEST_8,
        receiptId: '',
        receiptSchema: 'cybermedica.production_claim_lift_summary.v1',
        actionHash: 'not-a-digest',
        claimGateId: 'PTAG-999',
        state: 'verified',
        trustState: 'verified',
        canLiftProductionClaim: true,
        exochainProductionClaim: true,
        blockedBy: [],
        adapterActivationHandoffProviderRoleDashboardReceiptHash: DIGEST_B,
        adapterActivationHandoffProviderRoleDashboardSummaryHash: DIGEST_C,
        adapterActivationHandoffProviderRoleDashboardTrustStateViewHash: DIGEST_D,
        adapterActivationHandoffReadinessRoleDashboardReceiptHash: DIGEST_E,
        adapterActivationHandoffReadinessRoleDashboardSummaryHash: DIGEST_F,
        adapterActivationHandoffReadinessRoleDashboardTrustStateViewHash: DIGEST_1,
        adapterActivationRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_4,
        adapterActivationRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_C,
        adapterActivationRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_5,
        adapterActivationRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_E,
        adapterActivationRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_3,
        adapterActivationRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_6,
        adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: DIGEST_6,
        adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: DIGEST_2,
        adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: DIGEST_6,
        adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: DIGEST_7,
        adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: DIGEST_7,
        adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: DIGEST_7,
        adapterActivationDeploymentHandoffCutoverRoleDashboardRoles: REQUIRED_ROLE_DASHBOARD_ROLES.filter(
          (role) => role !== 'sponsor_viewer',
        ).concat('marketing_admin'),
        metadataOnly: false,
        protectedContentExcluded: false,
        reviewedAtHlc: { physicalMs: 1806200040000, logical: 0 },
      }),
    }),
  );
  const missingAdapterClaimLiftAnchors = evaluatePublicClaimReview(
    publicClaimInput({
      contentRegister: {
        productionClaimLiftReceiptHash: DIGEST_7,
      },
      productionClaimLiftLineage: inactiveProductionClaimLiftLineage({
        adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardReceiptHash: null,
        adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardSummaryHash: null,
        adapterActivationProductionClaimLiftRuntimeSourceProviderRoleDashboardTrustStateViewHash: null,
        adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardReceiptHash: null,
        adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardSummaryHash: null,
        adapterActivationProductionClaimLiftRuntimeSourceReadinessRoleDashboardTrustStateViewHash: null,
      }),
    }),
  );

  assert.equal(missing.decision, 'denied');
  assert.equal(missing.failClosed, true);
  assert.ok(missing.reasons.includes('production_claim_lift_lineage_absent'));
  assert.ok(missing.reasons.includes('production_claim_lift_receipt_hash_mismatch'));
  assert.ok(missing.reasons.includes('production_claim_lift_action_hash_invalid'));

  assert.equal(unsafe.decision, 'denied');
  assert.equal(unsafe.failClosed, true);
  assert.ok(unsafe.reasons.includes('production_claim_lift_receipt_hash_mismatch'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_receipt_id_absent'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_receipt_schema_invalid'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_action_hash_invalid'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_gate_id_unsupported'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_state_invalid'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_trust_state_invalid'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_public_claim_forbidden'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_blocker_absent'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_role_dashboard_role_missing:sponsor_viewer'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_role_dashboard_role_unsupported:marketing_admin'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_runtime_source_provider_role_dashboard_receipt_mismatch'));
  assert.ok(
    unsafe.reasons.includes('production_claim_lift_runtime_source_provider_role_dashboard_trust_state_view_mismatch'),
  );
  assert.ok(unsafe.reasons.includes('production_claim_lift_runtime_source_readiness_role_dashboard_summary_mismatch'));
  assert.ok(
    unsafe.reasons.includes('production_claim_lift_runtime_source_readiness_role_dashboard_trust_state_view_mismatch'),
  );
  assert.ok(
    unsafe.reasons.includes(
      'production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_summary_mismatch',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_receipt_mismatch',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_summary_mismatch',
    ),
  );
  assert.ok(
    unsafe.reasons.includes(
      'production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_trust_state_view_mismatch',
    ),
  );
  assert.ok(unsafe.reasons.includes('production_claim_lift_metadata_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_protected_boundary_invalid'));
  assert.ok(unsafe.reasons.includes('production_claim_lift_review_before_content_register'));

  assert.equal(missingAdapterClaimLiftAnchors.decision, 'denied');
  assert.equal(missingAdapterClaimLiftAnchors.failClosed, true);
  assert.ok(
    missingAdapterClaimLiftAnchors.reasons.includes(
      'production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_receipt_hash_invalid',
    ),
  );
  assert.ok(
    missingAdapterClaimLiftAnchors.reasons.includes(
      'production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_summary_hash_invalid',
    ),
  );
  assert.ok(
    missingAdapterClaimLiftAnchors.reasons.includes(
      'production_claim_lift_adapter_activation_runtime_source_provider_role_dashboard_trust_state_view_hash_invalid',
    ),
  );
  assert.ok(
    missingAdapterClaimLiftAnchors.reasons.includes(
      'production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_receipt_hash_invalid',
    ),
  );
  assert.ok(
    missingAdapterClaimLiftAnchors.reasons.includes(
      'production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_summary_hash_invalid',
    ),
  );
  assert.ok(
    missingAdapterClaimLiftAnchors.reasons.includes(
      'production_claim_lift_adapter_activation_runtime_source_readiness_role_dashboard_trust_state_view_hash_invalid',
    ),
  );
});

test('public claim review fails closed for missing sales content coverage and reviewer gaps', async () => {
  const { evaluatePublicClaimReview } = await loadPublicClaimReview();
  const claims = claimRecords().filter((claim) => claim.family !== 'clinical_research_safety');
  const reviews = reviewsForClaims(claims).filter(
    (review) => !(review.claimRef === 'public-claim-exochain_trust' && review.reviewerRole === 'legal'),
  );

  const result = evaluatePublicClaimReview(
    publicClaimInput({
      contentRegister: {
        contentAssets: contentAssets().filter((asset) => asset.contentType !== 'sales_deck'),
        claimRecords: claims,
      },
      reviews,
      publicationGate: {
        highRiskClaimsHeld: true,
        salesMaterialsApproved: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('content_type_missing:sales_deck'));
  assert.ok(result.reasons.includes('claim_family_missing:clinical_research_safety'));
  assert.ok(result.reasons.includes('claim_required_review_missing:public-claim-exochain_trust:legal'));
  assert.ok(result.reasons.includes('sales_materials_not_approved'));
  assert.ok(result.reasons.includes('high_risk_claims_held'));
});

test('public claim review denies AI-IRB language Exochain overclaims and AI final authority', async () => {
  const { evaluatePublicClaimReview } = await loadPublicClaimReview();
  const claims = claimRecords().map((claim) => {
    if (claim.family === 'ai_irb_language') {
      return { ...claim, aiIrbEquivalentLanguageAbsent: false, irbIecSubstitutionClaimAbsent: false };
    }
    if (claim.family === 'exochain_trust') {
      return {
        ...claim,
        safestClaimCategory: 'exochained_clinical_research_qms',
        exochainProductionClaimAbsent: false,
        productionTrustClaim: true,
      };
    }
    return claim;
  });

  const result = evaluatePublicClaimReview(
    publicClaimInput({
      actor: { kind: 'ai_agent' },
      contentRegister: {
        claimRecords: claims,
      },
      publicationGate: {
        aiIrbPublicLanguageAllowed: true,
        irbIecSubstitutionClaimAllowed: true,
        exochainProductionClaimAllowed: true,
        safePublicClaimCategory: 'exochained_clinical_research_qms',
        productionTrustClaim: true,
      },
      aiAssistant: {
        advisoryOnly: false,
        finalAuthority: true,
        humanReviewed: false,
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('ai_irb_public_language_forbidden:public-claim-ai_irb_language'));
  assert.ok(result.reasons.includes('irb_iec_substitution_claim_forbidden:public-claim-ai_irb_language'));
  assert.ok(result.reasons.includes('unsafe_public_claim_category:public-claim-exochain_trust'));
  assert.ok(result.reasons.includes('claim_production_trust_claim_forbidden:public-claim-exochain_trust'));
  assert.ok(result.reasons.includes('publication_gate_ai_irb_language_forbidden'));
  assert.ok(result.reasons.includes('publication_gate_exochain_claim_forbidden'));
  assert.ok(result.reasons.includes('ai_assistant_not_advisory_only'));
  assert.ok(result.reasons.includes('human_final_authority_missing'));
});

test('public claim review enforces HLC ordering and supports no-AI review', async () => {
  const { evaluatePublicClaimReview } = await loadPublicClaimReview();

  const noAi = evaluatePublicClaimReview(publicClaimInput({ aiAssistant: { used: false } }));
  assert.equal(noAi.decision, 'permitted');
  assert.equal(noAi.publicClaimReview.aiAssistanceUsed, false);

  const result = evaluatePublicClaimReview(
    publicClaimInput({
      publicClaimPolicy: { evaluatedAtHlc: { physicalMs: 1806200200001, logical: 0 } },
      reviews: reviewsForClaims().map((review) =>
        review.claimRef === 'public-claim-qms_readiness' && review.reviewerRole === 'quality'
          ? { ...review, reviewedAtHlc: { physicalMs: 1806200199999, logical: 0 } }
          : review,
      ),
      aiAssistant: { reviewedAtHlc: { physicalMs: 1806200550000, logical: 0 } },
      humanReview: { reviewedAtHlc: { physicalMs: 1806200499999, logical: 0 } },
      validationEvidence: { recordedAtHlc: { physicalMs: 1806200599999, logical: -1 } },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('policy_review_after_claim_classification'));
  assert.ok(result.reasons.includes('claim_review_before_classification:public-claim-qms_readiness:quality'));
  assert.ok(result.reasons.includes('human_review_before_ai_review'));
  assert.ok(result.reasons.includes('ai_review_not_before_human_review'));
  assert.ok(result.reasons.includes('validation_record_time_invalid'));
});

test('public claim review rejects raw sales copy protected content and secrets before receipts', async () => {
  const { evaluatePublicClaimReview, ProtectedContentError } = await loadPublicClaimReview();

  assert.throws(
    () =>
      evaluatePublicClaimReview(
        publicClaimInput({
          contentRegister: {
            rawSalesCopy: 'CyberMedica guarantees root-backed production authority for Participant Alice.',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluatePublicClaimReview(
        publicClaimInput({
          publicationGate: {
            apiKey: 'cm-public-claim-secret',
          },
        }),
      ),
    ProtectedContentError,
  );
});
