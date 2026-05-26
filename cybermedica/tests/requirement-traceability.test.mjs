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

const REQUIRED_REQUIREMENT_FAMILIES = ['activation_gate', 'context_obligation', 'functional', 'nonfunctional'];
const REQUIRED_DOCTRINE_LAYERS = [
  'data',
  'deployment',
  'doctrine',
  'documentation',
  'domain',
  'doors',
  'drift',
  'ground_truth',
];
const REQUIRED_CONTEXT_DOC_REFS = [
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
  'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
];
const ALLOWED_ACTIVATION_BLOCKER_IDS = ['PTAG-001', 'PTAG-002', 'PTAG-008', 'PTAG-015', 'PTAG-016', 'PTAG-017'];
const ALLOWED_BOB_ESCALATION_IDS = [
  'ESC-CONSENT-LEGAL',
  'ESC-HUMAN-PROOFING',
  'ESC-OPS-SECRETS',
  'ESC-ROLE-MATRIX',
  'ESC-ROOT-ARTIFACT-STORE',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-ROOT-ROSTER',
  'ESC-RUNTIME',
];

async function loadRequirementTraceability() {
  try {
    return await import('../src/requirement-traceability.mjs');
  } catch (error) {
    assert.fail(`CyberMedica requirement traceability module must exist and load: ${error.message}`);
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

function row(requirementId, family, doctrineLayer, index, overrides = {}) {
  const sourceRef =
    family === 'activation_gate'
      ? `docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md#${requirementId}`
      : `CyberMedica_EXOCHAIN_Genesis_Master_PRD_v3.md#${requirementId}`;
  const activationOnly = family === 'activation_gate';
  return {
    requirementId,
    requirementFamily: family,
    doctrineLayer,
    sourceRef,
    implementationStatus: activationOnly ? 'activation_only_blocked' : 'implemented',
    moduleRefs: activationOnly
      ? ['src/root-trust-registry.mjs', 'src/trust-adapter.mjs']
      : ['src/readiness-gates.mjs', 'src/release-readiness-matrix.mjs'],
    testRefs: activationOnly
      ? ['tests/root-trust-registry.test.mjs', 'tests/production-trust-activation.test.mjs']
      : ['tests/readiness-gates.test.mjs', 'tests/release-readiness-matrix.test.mjs'],
    evidenceHashes: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    exochainPrimitiveRefs: activationOnly
      ? ['crates/exo-root/src/bundle.rs', 'crates/exo-root/src/signing.rs']
      : ['crates/exo-core/src/types.rs', 'crates/exo-gatekeeper/src/kernel.rs'],
    adapterBoundaryRefs: activationOnly
      ? ['src/root-trust-registry.mjs', 'src/trust-adapter.mjs']
      : ['src/qms-contracts.mjs'],
    validationCommandRefs: ['npm run quality'],
    activationGateIds: activationOnly ? [requirementId] : [],
    bobEscalationIds: activationOnly ? [ALLOWED_BOB_ESCALATION_IDS[index % ALLOWED_BOB_ESCALATION_IDS.length]] : [],
    activationOnlyBlocker: activationOnly,
    blocksBaselineDevelopment: false,
    productionTrustClaim: false,
    metadataOnly: true,
    protectedContentExcluded: true,
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800000100000, logical: index },
    ...overrides,
  };
}

function allRows() {
  return [
    row('FR-031', 'functional', 'data', 0, {
      moduleRefs: ['src/document-versions.mjs', 'src/controlled-document-distribution.mjs'],
      testRefs: ['tests/document-versions.test.mjs', 'tests/controlled-document-distribution.test.mjs'],
    }),
    row('FR-040', 'functional', 'doors', 1, {
      moduleRefs: ['src/search-retrieval.mjs'],
      testRefs: ['tests/search-retrieval.test.mjs'],
    }),
    row('FR-047', 'functional', 'doors', 2, {
      moduleRefs: ['src/role-dashboards.mjs'],
      testRefs: ['tests/role-dashboards.test.mjs'],
    }),
    row('FR-050', 'functional', 'documentation', 3, {
      moduleRefs: ['src/governed-reporting.mjs'],
      testRefs: ['tests/governed-reporting.test.mjs'],
    }),
    row('NFR-003', 'nonfunctional', 'deployment', 4, {
      moduleRefs: ['src/availability-recovery-readiness.mjs'],
      testRefs: ['tests/availability-recovery-readiness.test.mjs'],
    }),
    row('NFR-011', 'nonfunctional', 'doctrine', 5, {
      moduleRefs: ['src/assistant-explainability.mjs'],
      testRefs: ['tests/assistant-explainability.test.mjs'],
    }),
    row('NFR-014', 'nonfunctional', 'documentation', 6, {
      moduleRefs: ['src/legal-defensibility.mjs'],
      testRefs: ['tests/legal-defensibility.test.mjs'],
    }),
    row('CTX-010', 'context_obligation', 'ground_truth', 7, {
      sourceRef: 'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md#section-12',
      moduleRefs: ['src/release-readiness-matrix.mjs'],
      testRefs: ['tests/release-readiness-matrix.test.mjs'],
      exochainPrimitiveRefs: ['docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md'],
    }),
    row('CTX-011', 'context_obligation', 'drift', 8, {
      sourceRef: 'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md#section-15',
      moduleRefs: ['src/drift-improvement.mjs', 'src/release-readiness-matrix.mjs'],
      testRefs: ['tests/drift-improvement.test.mjs', 'tests/release-readiness-matrix.test.mjs'],
      exochainPrimitiveRefs: ['docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md'],
    }),
    row('CTX-012', 'context_obligation', 'domain', 9, {
      sourceRef: 'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md#section-5',
      moduleRefs: ['src/qms-contracts.mjs', 'src/trust-adapter.mjs'],
      testRefs: ['tests/qms-contracts.test.mjs', 'tests/adapter-fail-closed.test.mjs'],
      exochainPrimitiveRefs: ['crates/exo-core/src/types.rs', 'crates/exo-authority/src/chain.rs'],
    }),
    row('PTAG-001', 'activation_gate', 'deployment', 10),
    row('PTAG-008', 'activation_gate', 'data', 11),
    row('PTAG-015', 'activation_gate', 'doors', 12),
  ];
}

function traceabilityInput(overrides = {}) {
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
      permissions: ['traceability_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    traceabilityPolicy: {
      policyRef: 'requirement-traceability-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredRequirementFamilies: REQUIRED_REQUIREMENT_FAMILIES,
      requiredDoctrineLayers: REQUIRED_DOCTRINE_LAYERS,
      requiredContextDocRefs: REQUIRED_CONTEXT_DOC_REFS,
      allowedActivationBlockerIds: ALLOWED_ACTIVATION_BLOCKER_IDS,
      allowedBobEscalationIds: ALLOWED_BOB_ESCALATION_IDS,
      rootVerificationRequiredForTrustClaims: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800000000000, logical: 0 },
    },
    matrixCycle: {
      matrixRef: 'traceability-matrix-baseline-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800000050000, logical: 0 },
      compiledAtHlc: { physicalMs: 1800000100000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800000200000, logical: 0 },
      validationRecordedAtHlc: { physicalMs: 1800000300000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800000400000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    requirementRows: allRows(),
    validationEvidence: {
      commandRefs: ['npm run quality'],
      commandsPassed: true,
      testCount: 307,
      coverageLineBasisPoints: 9971,
      sourceGuardPassed: true,
      moduleManifestHash: DIGEST_C,
      testManifestHash: DIGEST_D,
      noExochainSourceModified: true,
      docsUpdated: true,
      evidenceHash: DIGEST_E,
      recordedAtHlc: { physicalMs: 1800000300000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'traceability_accepted_inactive_trust',
      decisionHash: DIGEST_F,
      activationOnlyBlockersAccepted: true,
      noProductionTrustClaim: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800000200000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'traceability-audit-alpha',
      auditRecordHash: DIGEST_1,
      receiptRecordedAtHlc: { physicalMs: 1800000400000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_2,
      limitationHashes: [DIGEST_3],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_4,
  };
  return mergeDeep(base, overrides);
}

test('requirement traceability matrix maps requirements to modules tests evidence and activation blockers deterministically', async () => {
  const { evaluateRequirementTraceability } = await loadRequirementTraceability();

  const resultA = evaluateRequirementTraceability(traceabilityInput());
  const resultB = evaluateRequirementTraceability({
    ...traceabilityInput(),
    traceabilityPolicy: {
      ...traceabilityInput().traceabilityPolicy,
      requiredRequirementFamilies: [...traceabilityInput().traceabilityPolicy.requiredRequirementFamilies].reverse(),
      requiredDoctrineLayers: [...traceabilityInput().traceabilityPolicy.requiredDoctrineLayers].reverse(),
      allowedActivationBlockerIds: [...traceabilityInput().traceabilityPolicy.allowedActivationBlockerIds].reverse(),
      allowedBobEscalationIds: [...traceabilityInput().traceabilityPolicy.allowedBobEscalationIds].reverse(),
    },
    requirementRows: [...traceabilityInput().requirementRows].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.traceability.productionTrustState, 'inactive');
  assert.equal(resultA.traceability.exochainProductionClaim, false);
  assert.deepEqual(resultA.traceability.requirementFamiliesCovered, REQUIRED_REQUIREMENT_FAMILIES);
  assert.deepEqual(resultA.traceability.doctrineLayersCovered, REQUIRED_DOCTRINE_LAYERS);
  assert.equal(resultA.traceability.coverageSummary.totalRequirementCount, 13);
  assert.equal(resultA.traceability.coverageSummary.implementedCount, 10);
  assert.equal(resultA.traceability.coverageSummary.activationOnlyBlockerCount, 3);
  assert.deepEqual(resultA.traceability.activationOnlyBlockerIds, ['PTAG-001', 'PTAG-008', 'PTAG-015']);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.deepEqual(resultA, resultB);
});

test('requirement traceability matrix fails closed for incomplete PRD family and layer coverage', async () => {
  const { evaluateRequirementTraceability } = await loadRequirementTraceability();

  const result = evaluateRequirementTraceability(
    traceabilityInput({
      requirementRows: allRows().filter((entry) => entry.requirementFamily !== 'nonfunctional'),
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('requirement_family_missing:nonfunctional'));
  assert.ok(result.reasons.includes('doctrine_layer_missing:doctrine'));
});

test('requirement traceability matrix rejects unimplemented rows and non-activation blockers', async () => {
  const { evaluateRequirementTraceability } = await loadRequirementTraceability();

  const result = evaluateRequirementTraceability(
    traceabilityInput({
      requirementRows: [
        ...allRows().slice(0, 1),
        row('FR-099', 'functional', 'data', 1, {
          implementationStatus: 'planned',
          activationOnlyBlocker: true,
          activationGateIds: ['PTAG-999'],
          blocksBaselineDevelopment: true,
          bobEscalationIds: ['ESC-CI-GATES'],
        }),
        ...allRows().slice(2),
      ],
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('requirement_row_not_implemented:FR-099'));
  assert.ok(result.reasons.includes('activation_blocker_not_allowed:PTAG-999'));
  assert.ok(result.reasons.includes('bob_escalation_not_allowed:ESC-CI-GATES'));
  assert.ok(result.reasons.includes('requirement_blocks_baseline:FR-099'));
});

test('requirement traceability matrix requires concrete module test evidence and Exochain primitive mappings', async () => {
  const { evaluateRequirementTraceability } = await loadRequirementTraceability();

  const result = evaluateRequirementTraceability(
    traceabilityInput({
      requirementRows: [
        row('FR-031', 'functional', 'data', 0, {
          moduleRefs: [],
          testRefs: [],
          evidenceHashes: [],
          exochainPrimitiveRefs: [],
          adapterBoundaryRefs: [],
          reviewedByHuman: false,
        }),
        ...allRows().slice(1),
      ],
      validationEvidence: {
        commandsPassed: false,
        sourceGuardPassed: false,
        noExochainSourceModified: false,
        moduleManifestHash: 'not-a-hash',
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('requirement_module_refs_absent:FR-031'));
  assert.ok(result.reasons.includes('requirement_test_refs_absent:FR-031'));
  assert.ok(result.reasons.includes('requirement_evidence_hashes_absent:FR-031'));
  assert.ok(result.reasons.includes('requirement_exochain_primitives_absent:FR-031'));
  assert.ok(result.reasons.includes('requirement_adapter_boundary_absent:FR-031'));
  assert.ok(result.reasons.includes('requirement_human_review_absent:FR-031'));
  assert.ok(result.reasons.includes('validation_commands_not_passed'));
  assert.ok(result.reasons.includes('validation_source_guard_absent'));
  assert.ok(result.reasons.includes('validation_exochain_read_only_absent'));
  assert.ok(result.reasons.includes('validation_module_manifest_hash_invalid'));
});

test('requirement traceability matrix validates HLC ordering and AI advisory boundaries', async () => {
  const { evaluateRequirementTraceability } = await loadRequirementTraceability();

  const result = evaluateRequirementTraceability(
    traceabilityInput({
      matrixCycle: {
        compiledAtHlc: { physicalMs: 1800000000000, logical: 0 },
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

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('matrix_cycle_compiledAtHlc_before_openedAtHlc'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('ai_human_review_absent'));
  assert.ok(result.reasons.includes('human_review_authority_absent'));
});

test('requirement traceability matrix handles absent objects as fail-closed denial states', async () => {
  const { evaluateRequirementTraceability } = await loadRequirementTraceability();

  const result = evaluateRequirementTraceability({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['traceability_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('traceability_policy_ref_absent'));
  assert.ok(result.reasons.includes('matrix_cycle_ref_absent'));
  assert.ok(result.reasons.includes('requirement_rows_absent'));
  assert.ok(result.reasons.includes('validation_evidence_absent'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('traceability_audit_record_ref_absent'));
});

test('requirement traceability matrix rejects raw requirements protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateRequirementTraceability } = await loadRequirementTraceability();

  const inert = traceabilityInput({
    requirementRows: [
      row('FR-031', 'functional', 'data', 0, {
        rawRequirementText: false,
      }),
      ...allRows().slice(1),
    ],
    humanReview: {
      secret: {},
    },
  });

  assert.equal(evaluateRequirementTraceability(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateRequirementTraceability(
        traceabilityInput({
          requirementRows: [
            row('FR-031', 'functional', 'data', 0, {
              rawRequirementText: 'source PRD text stays outside metadata receipts',
            }),
            ...allRows().slice(1),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRequirementTraceability(
        traceabilityInput({
          validationEvidence: {
            rawValidationOutput: ['full test logs stay outside traceability receipts'],
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRequirementTraceability(
        traceabilityInput({
          humanReview: {
            accessToken: DIGEST_A,
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRequirementTraceability(
        traceabilityInput({
          humanReview: {
            secret: 7,
          },
        }),
      ),
    ProtectedContentError,
  );
});
