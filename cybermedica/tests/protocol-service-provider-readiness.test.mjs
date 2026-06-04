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

const REQUIRED_PROVIDER_CATEGORIES = ['imaging', 'laboratory', 'logistics', 'pharmacy'];
const REQUIRED_REVIEW_DOMAINS = [
  'access_policy',
  'chain_of_custody',
  'contract_scope',
  'data_minimization',
  'privacy_boundary',
  'protocol_fit',
  'qualification',
  'service_level',
];

async function loadProviderReadiness() {
  try {
    return await import('../src/protocol-service-provider-readiness.mjs');
  } catch (error) {
    assert.fail(`CyberMedica protocol service provider readiness module must exist and load: ${error.message}`);
  }
}

function provider(category, index, overrides = {}) {
  const digestCycle = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    category,
    providerRef: `provider-${category}-alpha`,
    status: 'ready',
    protocolScopeHash: digestCycle[index],
    qualificationEvidenceHash: digestCycle[(index + 1) % digestCycle.length],
    contractAgreementHash: digestCycle[(index + 2) % digestCycle.length],
    serviceLevelHash: digestCycle[(index + 3) % digestCycle.length],
    chainOfCustodyHash: digestCycle[(index + 4) % digestCycle.length],
    privacyBoundaryHash: digestCycle[(index + 5) % digestCycle.length],
    accessPolicyHash: digestCycle[(index + 6) % digestCycle.length],
    dataMinimizationHash: digestCycle[(index + 7) % digestCycle.length],
    escalationPathHash: digestCycle[(index + 1) % digestCycle.length],
    businessContinuityHash: digestCycle[(index + 2) % digestCycle.length],
    sponsorVisibilityPolicyHash: digestCycle[(index + 3) % digestCycle.length],
    metadataOnly: true,
    protectedContentExcluded: true,
    reviewedAtHlc: { physicalMs: 1812700000000 + index * 1000, logical: 0 },
    ...overrides,
  };
}

function providerReadinessInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:provider-readiness-owner-alpha',
      kind: 'human',
      roleRefs: ['principal_investigator', 'regulatory_coordinator'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['protocol_service_provider_readiness', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    readinessPackage: {
      packageRef: 'protocol-service-provider-readiness-alpha',
      protocolRef: 'protocol-cm-alpha',
      studyRef: 'study-alpha',
      siteRef: 'site-alpha',
      status: 'ready',
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1812700010000, logical: 0 },
    },
    serviceProviders: REQUIRED_PROVIDER_CATEGORIES.map((category, index) => provider(category, index)),
    reviewDomains: REQUIRED_REVIEW_DOMAINS.map((domain, index) => ({
      domain,
      evidenceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2][index],
      status: 'verified',
      metadataOnly: true,
    })),
    dependencyEvidence: {
      protocolControlReceiptId: 'cmr_protocol_control_alpha',
      protocolFeasibilityReceiptId: 'cmr_protocol_feasibility_alpha',
      vendorSubcontractorReceiptId: 'cmr_vendor_subcontractor_alpha',
      facilityProductReadinessReceiptId: 'cmr_facility_product_alpha',
      participantProtectionReceiptId: 'cmr_participant_protection_alpha',
      privacyBoundaryHash: DIGEST_B,
      custodyDigest: DIGEST_C,
    },
    reviewGovernance: {
      humanReviewerDid: 'did:exo:principal-investigator-alpha',
      reviewedAtHlc: { physicalMs: 1812700020000, logical: 0 },
      decisionForum: {
        required: true,
        verified: true,
        state: 'approved',
        humanGate: { verified: true },
        quorum: { status: 'met' },
        openChallenge: false,
        decisionId: 'df-provider-readiness-alpha',
        workflowReceiptId: 'df-provider-readiness-workflow-alpha',
      },
      aiAssisted: true,
      aiFinalAuthority: false,
    },
    custodyDigest: DIGEST_D,
  };

  return {
    ...base,
    ...overrides,
  };
}

test('protocol service provider readiness module loads', async () => {
  const mod = await loadProviderReadiness();
  assert.equal(typeof mod.evaluateProtocolServiceProviderReadiness, 'function');
});

test('protocol service provider readiness creates deterministic inactive provider receipts', async () => {
  const { evaluateProtocolServiceProviderReadiness } = await loadProviderReadiness();

  const first = evaluateProtocolServiceProviderReadiness(providerReadinessInput());
  const second = evaluateProtocolServiceProviderReadiness({
    ...providerReadinessInput(),
    serviceProviders: [...providerReadinessInput().serviceProviders].reverse(),
    reviewDomains: [...providerReadinessInput().reviewDomains].reverse(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.providerReadiness.status, 'ready');
  assert.equal(first.providerReadiness.trustState, 'inactive');
  assert.equal(first.providerReadiness.exochainProductionClaim, false);
  assert.deepEqual(first.providerReadiness.requiredProviderCategories, REQUIRED_PROVIDER_CATEGORIES);
  assert.deepEqual(first.providerReadiness.coveredProviderCategories, REQUIRED_PROVIDER_CATEGORIES);
  assert.deepEqual(first.providerReadiness.reviewDomains, REQUIRED_REVIEW_DOMAINS);
  assert.equal(first.providerReadiness.providerCount, 4);
  assert.equal(first.providerReadiness.providerReadinessBasisPoints, 10000);
  assert.equal(first.providerReadiness.readinessHash, second.providerReadiness.readinessHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.receipt.anchorPayload.artifactType, 'protocol_service_provider_readiness');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(first), /lab result body|image report body|drug accountability body|courier manifest body/iu);
});

test('protocol service provider readiness fails closed for missing providers and review domains', async () => {
  const { evaluateProtocolServiceProviderReadiness } = await loadProviderReadiness();

  const result = evaluateProtocolServiceProviderReadiness({
    ...providerReadinessInput(),
    serviceProviders: providerReadinessInput().serviceProviders.filter((entry) => entry.category !== 'imaging'),
    reviewDomains: providerReadinessInput().reviewDomains.filter((entry) => entry.domain !== 'chain_of_custody'),
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.equal(result.providerReadiness.status, 'blocked');
  assert.ok(result.reasons.includes('provider_category_missing:imaging'));
  assert.ok(result.reasons.includes('review_domain_missing:chain_of_custody'));
});

test('protocol service provider readiness denies unsafe provider controls and production trust claims', async () => {
  const { evaluateProtocolServiceProviderReadiness } = await loadProviderReadiness();

  const result = evaluateProtocolServiceProviderReadiness({
    ...providerReadinessInput(),
    readinessPackage: {
      ...providerReadinessInput().readinessPackage,
      productionTrustClaim: true,
    },
    serviceProviders: providerReadinessInput().serviceProviders.map((entry) =>
      entry.category === 'pharmacy'
        ? {
            ...entry,
            status: 'pending',
            dataMinimizationHash: null,
            sponsorVisibilityPolicyHash: null,
            metadataOnly: false,
          }
        : entry,
    ),
  });

  assert.equal(result.decision, 'denied');
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('provider_not_ready:pharmacy'));
  assert.ok(result.reasons.includes('provider_data_minimization_hash_invalid:pharmacy'));
  assert.ok(result.reasons.includes('provider_sponsor_visibility_policy_hash_invalid:pharmacy'));
  assert.ok(result.reasons.includes('provider_metadata_boundary_invalid:pharmacy'));
});

test('protocol service provider readiness validates governance timing and AI boundaries', async () => {
  const { evaluateProtocolServiceProviderReadiness } = await loadProviderReadiness();

  const result = evaluateProtocolServiceProviderReadiness({
    ...providerReadinessInput(),
    actor: { ...providerReadinessInput().actor, kind: 'ai_agent' },
    reviewGovernance: {
      ...providerReadinessInput().reviewGovernance,
      reviewedAtHlc: { physicalMs: 1812600000000, logical: 0 },
      aiFinalAuthority: true,
      decisionForum: {
        ...providerReadinessInput().reviewGovernance.decisionForum,
        humanGate: { verified: false },
        quorum: { status: 'missing' },
      },
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('human_actor_required'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_gate_unverified'));
  assert.ok(result.reasons.includes('quorum_not_met'));
  assert.ok(result.reasons.includes('governance_review_before_package_evaluation'));
});

test('protocol service provider readiness rejects protected provider content and secrets', async () => {
  const { ProtectedContentError, evaluateProtocolServiceProviderReadiness } = await loadProviderReadiness();

  assert.throws(
    () =>
      evaluateProtocolServiceProviderReadiness({
        ...providerReadinessInput(),
        serviceProviders: [
          ...providerReadinessInput().serviceProviders,
          {
            ...provider('laboratory', 0),
            rawLabReport: 'lab result body must stay outside the readiness receipt',
          },
        ],
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateProtocolServiceProviderReadiness({
        ...providerReadinessInput(),
        serviceProviders: [
          {
            ...provider('logistics', 2),
            courierApiToken: 'secret-token-value',
          },
          ...providerReadinessInput().serviceProviders.slice(1),
        ],
      }),
    ProtectedContentError,
  );
});
