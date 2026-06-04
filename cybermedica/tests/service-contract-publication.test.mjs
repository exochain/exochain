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

const REQUIRED_META_LAYERS = [
  'ground_truth',
  'doctrine',
  'domain',
  'data',
  'doors',
  'documentation',
  'deployment',
  'drift',
];

const REQUIRED_CONTRACT_KINDS = [
  'adapter_contract',
  'deterministic_fixture',
  'documentation_contract',
  'evidence_receipt_contract',
  'fail_closed_boundary',
  'inactive_trust_state',
  'qms_workflow_contract',
];

const REQUIRED_CONTEXT_REFS = [
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
  'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
];

async function loadServiceContractPublication() {
  try {
    return await import('../src/service-contract-publication.mjs');
  } catch (error) {
    assert.fail(`CyberMedica service contract publication module must exist and load: ${error.message}`);
  }
}

function digestFor(index) {
  return (index + 1).toString(16).padStart(2, '0').repeat(32);
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

function contractRow(metaLayer, index, overrides = {}) {
  const kind = REQUIRED_CONTRACT_KINDS[index % REQUIRED_CONTRACT_KINDS.length];

  return {
    contractRef: `svc-${metaLayer}`,
    metaLayer,
    contractKind: kind,
    moduleRef: `src/${metaLayer.replaceAll('_', '-')}-service-contract.mjs`,
    testRef: `tests/${metaLayer.replaceAll('_', '-')}-service-contract.test.mjs`,
    documentationRef: 'README.md',
    pathClassificationRef: 'docs/implementation/PATH_CLASSIFICATION.md',
    contextRefs: REQUIRED_CONTEXT_REFS,
    deterministicFixtureHash: digestFor(index + 20),
    sourceEvidenceHash: digestFor(index + 40),
    lastTestCommandRefs: [
      'node --test tests/service-contract-publication.test.mjs',
      'node --test tests/source-guards.test.mjs',
    ],
    status: 'implemented',
    testStatus: 'passed',
    failClosedNegativeCoverage: true,
    inactiveTrustState: true,
    exochainSourceModified: false,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    reviewedAtHlc: { physicalMs: 1809000000000, logical: index },
    ...overrides,
  };
}

function serviceContractPublicationInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-cybermedica-alpha',
    targetTenantId: 'tenant-cybermedica-alpha',
    actor: {
      did: 'did:exo:service-contract-publisher-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'documentation_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['service_contract_publish', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    publicationPolicy: {
      policyRef: 'service-contract-publication-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      sourcePrdRef: 'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md#baseline-development',
      requiredMetaLayers: REQUIRED_META_LAYERS,
      requiredContractKinds: REQUIRED_CONTRACT_KINDS,
      requiredContextRefs: REQUIRED_CONTEXT_REFS,
      requireTestsPassed: true,
      requireFailClosedCoverage: true,
      requireInactiveTrustState: true,
      requireNoExochainSourceEdits: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      noProductionTrustClaim: true,
      evaluatedAtHlc: { physicalMs: 1809000000100, logical: 0 },
    },
    contractRows: REQUIRED_META_LAYERS.map(contractRow).reverse(),
    validationEvidence: {
      commandRefs: [
        'node --test tests/service-contract-publication.test.mjs',
        'node --test tests/source-guards.test.mjs',
        'npm test',
      ],
      sourceGuardPassed: true,
      contractTestsPassed: true,
      coverageGatePassed: true,
      secretScanPassed: true,
      pathClassificationCurrent: true,
      validationHash: DIGEST_C,
      metadataOnly: true,
      protectedContentExcluded: true,
      validatedAtHlc: { physicalMs: 1809000000200, logical: 0 },
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-manager-alpha',
      reviewerRoleRefs: ['quality_manager'],
      decision: 'service_contracts_publishable_inactive_trust',
      reviewHash: DIGEST_D,
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1809000000300, logical: 0 },
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_E,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    custodyDigest: DIGEST_F,
  };

  return mergeDeep(base, overrides);
}

test('service contract publication creates deterministic inactive metadata-only evidence', async () => {
  const { evaluateServiceContractPublication } = await loadServiceContractPublication();

  const first = evaluateServiceContractPublication(serviceContractPublicationInput());
  const second = evaluateServiceContractPublication({
    ...serviceContractPublicationInput(),
    contractRows: [...serviceContractPublicationInput().contractRows].reverse(),
    publicationPolicy: {
      ...serviceContractPublicationInput().publicationPolicy,
      requiredMetaLayers: [...REQUIRED_META_LAYERS].reverse(),
      requiredContractKinds: [...REQUIRED_CONTRACT_KINDS].reverse(),
      requiredContextRefs: [...REQUIRED_CONTEXT_REFS].reverse(),
    },
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.serviceContractPublication.status, 'publishable');
  assert.deepEqual(first.serviceContractPublication.metaLayers, REQUIRED_META_LAYERS);
  assert.deepEqual(first.serviceContractPublication.contractKinds, REQUIRED_CONTRACT_KINDS);
  assert.deepEqual(first.serviceContractPublication.contextRefs, REQUIRED_CONTEXT_REFS);
  assert.equal(first.serviceContractPublication.contractCount, REQUIRED_META_LAYERS.length);
  assert.equal(first.serviceContractPublication.exochainProductionClaim, false);
  assert.equal(first.serviceContractPublication.metadataOnly, true);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'service_contract_publication');
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.equal(first.serviceContractPublication.publicationHash, second.serviceContractPublication.publicationHash);
  assert.doesNotMatch(JSON.stringify(first), /Participant Alice|client_secret|raw service contract/iu);
});

test('service contract publication fails closed for coverage test and source-boundary gaps', async () => {
  const { evaluateServiceContractPublication } = await loadServiceContractPublication();
  const rows = REQUIRED_META_LAYERS.map((metaLayer, index) => {
    if (metaLayer === 'data') {
      return contractRow(metaLayer, index, { testStatus: 'failed' });
    }
    if (metaLayer === 'domain') {
      return contractRow(metaLayer, index, { exochainSourceModified: true });
    }
    return contractRow(metaLayer, index);
  }).filter((row) => row.metaLayer !== 'drift');

  const result = evaluateServiceContractPublication(
    serviceContractPublicationInput({
      contractRows: rows,
      validationEvidence: {
        contractTestsPassed: false,
        pathClassificationCurrent: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.serviceContractPublication.status, 'blocked');
  assert.ok(result.reasons.includes('meta_layer_missing:drift'));
  assert.ok(result.reasons.includes('contract_test_not_passed:svc-data'));
  assert.ok(result.reasons.includes('exochain_source_modified:svc-domain'));
  assert.ok(result.reasons.includes('validation_contract_tests_failed'));
  assert.ok(result.reasons.includes('path_classification_not_current'));
  assert.equal(result.receipt, null);
});

test('service contract publication requires human final authority and safe HLC ordering', async () => {
  const { evaluateServiceContractPublication } = await loadServiceContractPublication();

  const result = evaluateServiceContractPublication(
    serviceContractPublicationInput({
      actor: { did: '', kind: 'ai_agent' },
      humanReview: {
        aiFinalAuthority: true,
        reviewedAtHlc: { physicalMs: 1809000000150, logical: 0 },
      },
      validationEvidence: {
        validatedAtHlc: { physicalMs: 1809000000400, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('actor_did_absent'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_review_ai_final_authority'));
  assert.ok(result.reasons.includes('human_review_before_validation'));
});

test('service contract publication rejects raw contract content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateServiceContractPublication } = await loadServiceContractPublication();

  assert.throws(
    () =>
      evaluateServiceContractPublication(
        serviceContractPublicationInput({
          contractRows: [
            contractRow('ground_truth', 0, {
              rawContractBody: 'Participant Alice Example service contract narrative',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateServiceContractPublication(
        serviceContractPublicationInput({
          validationEvidence: {
            clientSecret: DIGEST_1,
          },
        }),
      ),
    ProtectedContentError,
  );
});
