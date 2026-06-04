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

const REQUIRED_BENCHMARK_FAMILIES = [
  'audit_findings',
  'capa_aging',
  'consent_readiness',
  'deviation_rate',
  'site_readiness',
  'training_coverage',
];

async function loadCrossSiteBenchmarking() {
  try {
    return await import('../src/cross-site-benchmarking.mjs');
  } catch (error) {
    assert.fail(`CyberMedica cross-site benchmarking module must exist and load: ${error.message}`);
  }
}

function observationRows() {
  const rows = [
    ['site-alpha', DIGEST_A, 'site_readiness', 91, 100, DIGEST_B, DIGEST_C, 23],
    ['site-alpha', DIGEST_A, 'training_coverage', 88, 100, DIGEST_C, DIGEST_D, 19],
    ['site-alpha', DIGEST_A, 'capa_aging', 74, 100, DIGEST_D, DIGEST_E, 13],
    ['site-alpha', DIGEST_A, 'audit_findings', 93, 100, DIGEST_E, DIGEST_F, 17],
    ['site-alpha', DIGEST_A, 'consent_readiness', 96, 100, DIGEST_F, DIGEST_1, 21],
    ['site-alpha', DIGEST_A, 'deviation_rate', 82, 100, DIGEST_1, DIGEST_2, 11],
    ['site-beta', DIGEST_B, 'site_readiness', 84, 100, DIGEST_2, DIGEST_3, 18],
    ['site-beta', DIGEST_B, 'training_coverage', 79, 100, DIGEST_3, DIGEST_4, 16],
    ['site-beta', DIGEST_B, 'capa_aging', 65, 100, DIGEST_4, DIGEST_5, 10],
    ['site-beta', DIGEST_B, 'audit_findings', 88, 100, DIGEST_5, DIGEST_6, 14],
    ['site-beta', DIGEST_B, 'consent_readiness', 90, 100, DIGEST_6, DIGEST_A, 20],
    ['site-beta', DIGEST_B, 'deviation_rate', 71, 100, DIGEST_A, DIGEST_B, 12],
  ];

  return rows.map(([siteTenantRef, siteAliasHash, family, numerator, denominator, evidenceHash, custodyDigest, cellCount], index) => ({
    siteTenantRef,
    siteAliasHash,
    family,
    numerator,
    denominator,
    evidenceHash,
    custodyDigest,
    cellCount,
    measuredAtHlc: { physicalMs: 1800000500000 + index, logical: 0 },
    sourceControlIds: [`CM-QMS-${family.toUpperCase()}-001`],
    privacy: {
      metadataOnly: true,
      directIdentifiersExcluded: true,
      sourcePayloadExcluded: true,
      sponsorConfidentialMinimized: true,
      aggregateCellCountOnly: true,
    },
  }));
}

function crossSiteBenchmarkingInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-portfolio-alpha',
    targetTenantId: 'tenant-portfolio-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['cross_site_benchmark_view', 'report_generate'],
      authorityChainHash: DIGEST_A,
    },
    benchmarkPlan: {
      benchmarkRef: 'cross-site-benchmark-2026-05',
      purpose: 'quality_manager_cross_site_benchmarking',
      methodHash: DIGEST_B,
      baselineHash: DIGEST_C,
      approvedByDid: 'did:exo:qms-governance-owner',
      approvedAtHlc: { physicalMs: 1800000000000, logical: 0 },
      requiredFamilies: REQUIRED_BENCHMARK_FAMILIES,
      minCellCount: 10,
      metadataOnly: true,
      sourcePayloadsExcluded: true,
      productionTrustClaim: false,
    },
    comparisonWindow: {
      windowRef: '2026-05',
      startsAtHlc: { physicalMs: 1799913600000, logical: 0 },
      endsAtHlc: { physicalMs: 1800000800000, logical: 0 },
      extractedAtHlc: { physicalMs: 1800000900000, logical: 0 },
      extractionManifestHash: DIGEST_D,
      custodyDigest: DIGEST_E,
    },
    visibilityPolicy: {
      audienceClass: 'quality_manager',
      dashboardRefs: ['quality-manager-dashboard', 'cro-portfolio-dashboard'],
      sponsorCroBoundary: {
        externalAudience: false,
        controlledRequestRequired: false,
      },
      suppressedSiteTenantRefs: [],
      phiPiiExcluded: true,
      siteAliasOnly: true,
      metadataOnly: true,
    },
    observations: observationRows(),
    aiAssistance: {
      used: true,
      advisoryOnly: true,
      finalAuthority: false,
      recommendationHash: DIGEST_F,
      humanReviewed: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      status: 'approved',
      reviewedAtHlc: { physicalMs: 1800001000000, logical: 0 },
      reviewEvidenceHash: DIGEST_1,
      aiFinalAuthorityRejected: true,
    },
    sponsorCroRequestEvidence: null,
  };

  return {
    ...base,
    ...overrides,
    actor: { ...base.actor, ...overrides.actor },
    authority: { ...base.authority, ...overrides.authority },
    benchmarkPlan: { ...base.benchmarkPlan, ...overrides.benchmarkPlan },
    comparisonWindow: { ...base.comparisonWindow, ...overrides.comparisonWindow },
    visibilityPolicy: { ...base.visibilityPolicy, ...overrides.visibilityPolicy },
    aiAssistance: { ...base.aiAssistance, ...overrides.aiAssistance },
    humanReview: { ...base.humanReview, ...overrides.humanReview },
  };
}

test('cross-site benchmarking creates deterministic inactive metadata-only benchmark receipts', async () => {
  const { evaluateCrossSiteBenchmarking } = await loadCrossSiteBenchmarking();

  const resultA = evaluateCrossSiteBenchmarking(crossSiteBenchmarkingInput());
  const resultB = evaluateCrossSiteBenchmarking(
    crossSiteBenchmarkingInput({
      benchmarkPlan: {
        requiredFamilies: [...REQUIRED_BENCHMARK_FAMILIES].reverse(),
      },
      visibilityPolicy: {
        dashboardRefs: ['cro-portfolio-dashboard', 'quality-manager-dashboard'],
      },
      observations: [...observationRows()].reverse(),
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.benchmark.benchmarkRef, 'cross-site-benchmark-2026-05');
  assert.equal(resultA.benchmark.siteCount, 2);
  assert.equal(resultA.benchmark.overallBasisPoints, 8341);
  assert.equal(resultA.benchmark.lowestFamily.family, 'capa_aging');
  assert.equal(resultA.benchmark.lowestFamily.basisPoints, 6950);
  assert.deepEqual(resultA.benchmark.requiredFamilies, REQUIRED_BENCHMARK_FAMILIES);
  assert.deepEqual(resultA.benchmark.dashboardRefs, ['cro-portfolio-dashboard', 'quality-manager-dashboard']);
  assert.deepEqual(resultA.benchmark.siteSummaries.map((summary) => summary.siteAliasHash), [DIGEST_A, DIGEST_B]);
  assert.deepEqual(resultA.benchmark.siteSummaries.map((summary) => summary.siteTenantRef), ['suppressed', 'suppressed']);
  assert.equal(resultA.benchmark.exochainProductionClaim, false);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.actionHash, resultB.receipt.actionHash);
});

test('cross-site benchmarking fails closed for scope authority privacy and external visibility defects', async () => {
  const { evaluateCrossSiteBenchmarking } = await loadCrossSiteBenchmarking();

  const denied = evaluateCrossSiteBenchmarking(
    crossSiteBenchmarkingInput({
      targetTenantId: 'tenant-other',
      actor: { did: 'did:exo:ai-quality-reviewer-alpha', kind: 'ai_agent' },
      authority: { valid: false, permissions: ['read'], authorityChainHash: '' },
      benchmarkPlan: {
        requiredFamilies: REQUIRED_BENCHMARK_FAMILIES.filter((family) => family !== 'deviation_rate'),
        minCellCount: 15,
        metadataOnly: false,
        sourcePayloadsExcluded: false,
        productionTrustClaim: true,
      },
      visibilityPolicy: {
        audienceClass: 'sponsor',
        sponsorCroBoundary: {
          externalAudience: true,
          controlledRequestRequired: true,
        },
        phiPiiExcluded: false,
        siteAliasOnly: false,
        metadataOnly: false,
      },
      observations: [
        {
          ...observationRows()[0],
          cellCount: 4,
          privacy: {
            metadataOnly: false,
            directIdentifiersExcluded: false,
            sourcePayloadExcluded: false,
            sponsorConfidentialMinimized: false,
            aggregateCellCountOnly: false,
          },
        },
      ],
      aiAssistance: {
        used: true,
        advisoryOnly: false,
        finalAuthority: true,
        recommendationHash: '',
        humanReviewed: false,
      },
      humanReview: {
        reviewerDid: '',
        status: 'pending',
        reviewedAtHlc: { physicalMs: 1800000200000, logical: 0 },
        reviewEvidenceHash: '',
        aiFinalAuthorityRejected: false,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('tenant_boundary_violation'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('benchmark_authority_missing'));
  assert.ok(denied.reasons.includes('required_benchmark_family_missing:deviation_rate'));
  assert.ok(denied.reasons.includes('benchmark_metadata_boundary_invalid'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('external_visibility_request_evidence_absent'));
  assert.ok(denied.reasons.includes('visibility_phi_boundary_invalid'));
  assert.ok(denied.reasons.includes('site_alias_boundary_invalid'));
  assert.ok(denied.reasons.includes('observation_cell_count_below_minimum:site_readiness:site-alpha'));
  assert.ok(denied.reasons.includes('observation_metadata_boundary_invalid:site_readiness:site-alpha'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_review_not_approved'));
});

test('cross-site benchmarking permits controlled sponsor CRO visibility with request evidence', async () => {
  const { evaluateCrossSiteBenchmarking } = await loadCrossSiteBenchmarking();

  const result = evaluateCrossSiteBenchmarking(
    crossSiteBenchmarkingInput({
      actor: {
        did: 'did:exo:cro-portfolio-manager-alpha',
        roleRefs: ['cro_portfolio_manager'],
      },
      visibilityPolicy: {
        audienceClass: 'cro',
        sponsorCroBoundary: {
          externalAudience: true,
          controlledRequestRequired: true,
        },
      },
      sponsorCroRequestEvidence: {
        requestRef: 'sponsor-cro-request-benchmark-alpha',
        requestHash: DIGEST_2,
        requesterClass: 'cro',
        workItemRef: 'sponsor-cro-work-item-benchmark-alpha',
        workItemStatus: 'routed_to_decision_forum',
        disclosureLogHash: DIGEST_3,
        humanReviewHash: DIGEST_4,
        responsePackageHash: DIGEST_5,
        linkedBenchmarkRef: 'cross-site-benchmark-2026-05',
        metadataOnly: true,
        sourcePayloadExcluded: true,
        protectedContentExcluded: true,
        productionTrustClaim: false,
        linkedAtHlc: { physicalMs: 1800000950000, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'permitted');
  assert.equal(result.failClosed, false);
  assert.equal(result.benchmark.visibilityAudience, 'cro');
  assert.equal(result.benchmark.externalVisibility, true);
  assert.equal(result.benchmark.sponsorCroRequestRef, 'sponsor-cro-request-benchmark-alpha');
  assert.equal(result.receipt.trustState, 'inactive');
});

test('cross-site benchmarking rejects raw benchmark payloads protected content and secrets before receipts', async () => {
  const { evaluateCrossSiteBenchmarking } = await loadCrossSiteBenchmarking();

  assert.throws(
    () =>
      evaluateCrossSiteBenchmarking({
        ...crossSiteBenchmarkingInput(),
        rawBenchmarkData: 'free text performance narrative',
      }),
    /raw benchmark content/i,
  );

  assert.throws(
    () =>
      evaluateCrossSiteBenchmarking({
        ...crossSiteBenchmarkingInput(),
        participantName: 'Participant Alice Example',
      }),
    /protected content/i,
  );

  assert.throws(
    () =>
      evaluateCrossSiteBenchmarking({
        ...crossSiteBenchmarkingInput(),
        apiKey: 'metadata-key-ref',
      }),
    /benchmark secret field/i,
  );
});
