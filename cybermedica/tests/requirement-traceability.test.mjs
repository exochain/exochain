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
const REQUIRED_FUNCTIONAL_REQUIREMENT_IDS = [
  'FR-001',
  'FR-002',
  'FR-003',
  'FR-004',
  'FR-005',
  'FR-006',
  'FR-007',
  'FR-008',
  'FR-009',
  'FR-010',
  'FR-011',
  'FR-012',
  'FR-013',
  'FR-014',
  'FR-015',
  'FR-016',
  'FR-017',
  'FR-018',
  'FR-019',
  'FR-020',
  'FR-021',
  'FR-022',
  'FR-023',
  'FR-024',
  'FR-025',
  'FR-026',
  'FR-027',
  'FR-028',
  'FR-029',
  'FR-030',
  'FR-031',
  'FR-032',
  'FR-033',
  'FR-034',
  'FR-035',
  'FR-036',
  'FR-037',
  'FR-038',
  'FR-039',
  'FR-040',
  'FR-041',
  'FR-042',
  'FR-043',
  'FR-044',
  'FR-045',
  'FR-046',
  'FR-047',
  'FR-048',
  'FR-049',
  'FR-050',
];
const REQUIRED_NONFUNCTIONAL_REQUIREMENT_IDS = [
  'NFR-001',
  'NFR-002',
  'NFR-003',
  'NFR-004',
  'NFR-005',
  'NFR-006',
  'NFR-007',
  'NFR-008',
  'NFR-009',
  'NFR-010',
  'NFR-011',
  'NFR-012',
  'NFR-013',
  'NFR-014',
];
const REQUIRED_MASTER_PRD_REQUIREMENT_IDS = [
  ...REQUIRED_FUNCTIONAL_REQUIREMENT_IDS,
  ...REQUIRED_NONFUNCTIONAL_REQUIREMENT_IDS,
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

const REQUIREMENT_TRACEABILITY_REFS = Object.freeze({
  'FR-001': ['site-profile-management'],
  'FR-002': ['site-profile-management'],
  'FR-003': ['standards-control-library'],
  'FR-004': ['standards-control-library'],
  'FR-005': ['evidence-linking'],
  'FR-006': ['evidence-scoring'],
  'FR-007': ['evidence-scoring'],
  'FR-008': ['ai-control-review'],
  'FR-009': ['site-qms-passport'],
  'FR-010': ['protocol-intake'],
  'FR-011': ['protocol-feasibility'],
  'FR-012': ['risk-assessments'],
  'FR-013': ['readiness-gates'],
  'FR-014': ['readiness-gates'],
  'FR-015': ['consent-materials'],
  'FR-016': ['consent-materials', 'participant-data-sharing-consent'],
  'FR-017': ['participant-protection'],
  'FR-018': ['participant-protection'],
  'FR-019': ['safety-events'],
  'FR-020': ['deviation-workflows'],
  'FR-021': ['capa-workflows'],
  'FR-022': ['training-delegation'],
  'FR-023': ['staff-training-gap-management'],
  'FR-024': ['training-delegation'],
  'FR-025': ['delegation-audit-log'],
  'FR-026': ['concern-reporting'],
  'FR-027': ['conflict-disclosures'],
  'FR-028': ['recusal-management'],
  'FR-029': ['decision-forum-matters'],
  'FR-030': ['emergency-actions'],
  'FR-031': ['document-versions', 'controlled-document-distribution'],
  'FR-032': ['information-management'],
  'FR-033': ['electronic-system-validation'],
  'FR-034': ['facility-product-readiness'],
  'FR-035': ['equipment-calibration-readiness'],
  'FR-036': ['clinical-trial-product-accountability'],
  'FR-037': ['kpi-management'],
  'FR-038': ['internal-audits'],
  'FR-039': ['site-self-assessments'],
  'FR-040': ['diligence-exports'],
  'FR-041': ['export-controls'],
  'FR-042': ['exochain-anchoring'],
  'FR-043': ['audit-logs'],
  'FR-044': ['evidence-custody'],
  'FR-045': ['notifications-alerts'],
  'FR-046': ['search-retrieval'],
  'FR-047': ['role-dashboards'],
  'FR-048': ['governed-integrations'],
  'FR-049': ['governed-api-access'],
  'FR-050': ['governed-reporting'],
  'NFR-001': ['security-privacy-readiness'],
  'NFR-002': ['security-privacy-readiness'],
  'NFR-003': ['availability-recovery-readiness'],
  'NFR-004': ['data-integrity-records'],
  'NFR-005': ['auditability-trails'],
  'NFR-006': ['tamper-evidence-ledger'],
  'NFR-007': ['interoperability-readiness'],
  'NFR-008': ['tenant-configurations'],
  'NFR-009': ['scalability-capacity'],
  'NFR-010': ['guided-workflow-usability'],
  'NFR-011': ['assistant-explainability'],
  'NFR-012': ['reliability-readiness'],
  'NFR-013': ['structured-data-exports'],
  'NFR-014': ['legal-defensibility'],
});

const REQUIREMENT_DOCTRINE_LAYERS = Object.freeze({
  'FR-001': 'ground_truth',
  'FR-002': 'ground_truth',
  'FR-003': 'domain',
  'FR-004': 'domain',
  'FR-005': 'data',
  'FR-006': 'data',
  'FR-007': 'data',
  'FR-008': 'doors',
  'FR-009': 'domain',
  'FR-010': 'domain',
  'FR-011': 'domain',
  'FR-012': 'domain',
  'FR-013': 'doors',
  'FR-014': 'doors',
  'FR-015': 'domain',
  'FR-016': 'domain',
  'FR-017': 'data',
  'FR-018': 'domain',
  'FR-019': 'domain',
  'FR-020': 'domain',
  'FR-021': 'domain',
  'FR-022': 'domain',
  'FR-023': 'drift',
  'FR-024': 'domain',
  'FR-025': 'data',
  'FR-026': 'drift',
  'FR-027': 'doctrine',
  'FR-028': 'doctrine',
  'FR-029': 'doors',
  'FR-030': 'domain',
  'FR-031': 'data',
  'FR-032': 'data',
  'FR-033': 'deployment',
  'FR-034': 'domain',
  'FR-035': 'domain',
  'FR-036': 'domain',
  'FR-037': 'drift',
  'FR-038': 'drift',
  'FR-039': 'drift',
  'FR-040': 'doors',
  'FR-041': 'data',
  'FR-042': 'deployment',
  'FR-043': 'data',
  'FR-044': 'data',
  'FR-045': 'doors',
  'FR-046': 'doors',
  'FR-047': 'doors',
  'FR-048': 'deployment',
  'FR-049': 'deployment',
  'FR-050': 'documentation',
  'NFR-001': 'deployment',
  'NFR-002': 'data',
  'NFR-003': 'deployment',
  'NFR-004': 'data',
  'NFR-005': 'data',
  'NFR-006': 'data',
  'NFR-007': 'deployment',
  'NFR-008': 'domain',
  'NFR-009': 'deployment',
  'NFR-010': 'doors',
  'NFR-011': 'doctrine',
  'NFR-012': 'deployment',
  'NFR-013': 'data',
  'NFR-014': 'documentation',
});

function requirementRow(requirementId, index) {
  const modules = REQUIREMENT_TRACEABILITY_REFS[requirementId];
  const specialRefs = {
    'FR-016': {
      adapterBoundaryRefs: ['src/consent-materials.mjs', 'src/participant-data-sharing-consent.mjs'],
      exochainPrimitiveRefs: ['crates/exo-consent/src/bailment.rs', 'crates/exo-consent/src/policy.rs'],
    },
    'FR-017': {
      adapterBoundaryRefs: ['src/participant-protection.mjs'],
      exochainPrimitiveRefs: ['crates/exo-consent/src/bailment.rs', 'crates/exo-core/src/types.rs'],
    },
    'FR-018': {
      adapterBoundaryRefs: ['src/participant-protection.mjs'],
      exochainPrimitiveRefs: ['crates/exo-consent/src/gatekeeper.rs', 'crates/exo-core/src/types.rs'],
    },
  }[requirementId] ?? {};
  return row(
    requirementId,
    requirementId.startsWith('NFR-') ? 'nonfunctional' : 'functional',
    REQUIREMENT_DOCTRINE_LAYERS[requirementId],
    index,
    {
      moduleRefs: modules.map((moduleRef) => `src/${moduleRef}.mjs`),
      testRefs: modules.map((moduleRef) => `tests/${moduleRef}.test.mjs`),
      sourceRef: `cyber_medica_qms_prd_master.md#${requirementId}`,
      ...specialRefs,
    },
  );
}

function allRows() {
  return [
    ...REQUIRED_MASTER_PRD_REQUIREMENT_IDS.map((requirementId, index) => requirementRow(requirementId, index)),
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
  assert.equal(resultA.traceability.coverageSummary.totalRequirementCount, 70);
  assert.equal(resultA.traceability.coverageSummary.implementedCount, 67);
  assert.equal(resultA.traceability.coverageSummary.activationOnlyBlockerCount, 3);
  assert.deepEqual(resultA.traceability.activationOnlyBlockerIds, ['PTAG-001', 'PTAG-008', 'PTAG-015']);
  assert.deepEqual(
    resultA.traceability.requirementIds.filter((requirementId) => requirementId.startsWith('FR-')),
    REQUIRED_FUNCTIONAL_REQUIREMENT_IDS,
  );
  assert.deepEqual(
    resultA.traceability.requirementIds.filter((requirementId) => requirementId.startsWith('NFR-')),
    REQUIRED_NONFUNCTIONAL_REQUIREMENT_IDS,
  );
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.deepEqual(resultA, resultB);
});

test('requirement traceability matrix requires every master PRD FR and NFR row', async () => {
  const { evaluateRequirementTraceability } = await loadRequirementTraceability();

  const result = evaluateRequirementTraceability(
    traceabilityInput({
      requirementRows: allRows().filter(
        (entry) => entry.requirementId !== 'FR-001' && entry.requirementId !== 'NFR-001',
      ),
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('requirement_id_missing:FR-001'));
  assert.ok(result.reasons.includes('requirement_id_missing:NFR-001'));

  const unsupported = evaluateRequirementTraceability(
    traceabilityInput({
      requirementRows: [
        ...allRows(),
        row('FR-099', 'functional', 'data', 99, {
          moduleRefs: ['src/readiness-gates.mjs'],
          testRefs: ['tests/readiness-gates.test.mjs'],
        }),
      ],
    }),
  );

  assert.equal(unsupported.decision, 'denied');
  assert.ok(unsupported.reasons.includes('requirement_id_unsupported:FR-099'));
});

test('requirement traceability matrix requires FR-016 consent process and data sharing consent mappings', async () => {
  const { evaluateRequirementTraceability } = await loadRequirementTraceability();

  const result = evaluateRequirementTraceability(traceabilityInput());
  const fr016Row = result.traceability.requirementRows.find((entry) => entry.requirementId === 'FR-016');

  assert.ok(fr016Row, 'FR-016 must be represented as a standalone requirement row');
  assert.deepEqual(fr016Row.moduleRefs, [
    'src/consent-materials.mjs',
    'src/participant-data-sharing-consent.mjs',
  ]);
  assert.deepEqual(fr016Row.testRefs, [
    'tests/consent-materials.test.mjs',
    'tests/participant-data-sharing-consent.test.mjs',
  ]);
  assert.deepEqual(fr016Row.exochainPrimitiveRefs, [
    'crates/exo-consent/src/bailment.rs',
    'crates/exo-consent/src/policy.rs',
  ]);
  assert.deepEqual(fr016Row.adapterBoundaryRefs, [
    'src/consent-materials.mjs',
    'src/participant-data-sharing-consent.mjs',
  ]);

  const denied = evaluateRequirementTraceability(
    traceabilityInput({
      requirementRows: allRows().map((entry) =>
        entry.requirementId === 'FR-016'
          ? {
              ...entry,
              moduleRefs: ['src/consent-materials.mjs'],
              testRefs: ['tests/consent-materials.test.mjs'],
              exochainPrimitiveRefs: ['crates/exo-consent/src/bailment.rs'],
              adapterBoundaryRefs: ['src/consent-materials.mjs'],
            }
          : entry,
      ),
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(
    denied.reasons.includes(
      'requirement_required_module_ref_missing:FR-016:src/participant-data-sharing-consent.mjs',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'requirement_required_test_ref_missing:FR-016:tests/participant-data-sharing-consent.test.mjs',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'requirement_required_exochain_primitive_ref_missing:FR-016:crates/exo-consent/src/policy.rs',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'requirement_required_adapter_boundary_ref_missing:FR-016:src/participant-data-sharing-consent.mjs',
    ),
  );
});

test('requirement traceability matrix requires FR-017 and FR-018 participant protection mappings', async () => {
  const { evaluateRequirementTraceability } = await loadRequirementTraceability();

  const result = evaluateRequirementTraceability(traceabilityInput());
  const fr017Row = result.traceability.requirementRows.find((entry) => entry.requirementId === 'FR-017');
  const fr018Row = result.traceability.requirementRows.find((entry) => entry.requirementId === 'FR-018');

  assert.ok(fr017Row, 'FR-017 must be represented as a participant-code requirement row');
  assert.ok(fr018Row, 'FR-018 must be represented as a participant-disposition requirement row');
  assert.deepEqual(fr017Row.moduleRefs, ['src/participant-protection.mjs']);
  assert.deepEqual(fr017Row.testRefs, ['tests/participant-protection.test.mjs']);
  assert.deepEqual(fr017Row.exochainPrimitiveRefs, ['crates/exo-consent/src/bailment.rs', 'crates/exo-core/src/types.rs']);
  assert.deepEqual(fr017Row.adapterBoundaryRefs, ['src/participant-protection.mjs']);
  assert.deepEqual(fr018Row.moduleRefs, ['src/participant-protection.mjs']);
  assert.deepEqual(fr018Row.testRefs, ['tests/participant-protection.test.mjs']);
  assert.deepEqual(fr018Row.exochainPrimitiveRefs, ['crates/exo-consent/src/gatekeeper.rs', 'crates/exo-core/src/types.rs']);
  assert.deepEqual(fr018Row.adapterBoundaryRefs, ['src/participant-protection.mjs']);

  const denied = evaluateRequirementTraceability(
    traceabilityInput({
      requirementRows: allRows().map((entry) => {
        if (entry.requirementId === 'FR-017') {
          return {
            ...entry,
            moduleRefs: ['src/consent-materials.mjs'],
            testRefs: ['tests/consent-materials.test.mjs'],
            exochainPrimitiveRefs: ['crates/exo-consent/src/policy.rs'],
            adapterBoundaryRefs: ['src/consent-materials.mjs'],
          };
        }
        if (entry.requirementId === 'FR-018') {
          return {
            ...entry,
            moduleRefs: [],
            testRefs: [],
            exochainPrimitiveRefs: ['crates/exo-consent/src/bailment.rs'],
            adapterBoundaryRefs: [],
          };
        }
        return entry;
      }),
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('requirement_required_module_ref_missing:FR-017:src/participant-protection.mjs'));
  assert.ok(
    denied.reasons.includes('requirement_required_test_ref_missing:FR-017:tests/participant-protection.test.mjs'),
  );
  assert.ok(
    denied.reasons.includes(
      'requirement_required_exochain_primitive_ref_missing:FR-017:crates/exo-consent/src/bailment.rs',
    ),
  );
  assert.ok(
    denied.reasons.includes('requirement_required_adapter_boundary_ref_missing:FR-017:src/participant-protection.mjs'),
  );
  assert.ok(denied.reasons.includes('requirement_required_module_ref_missing:FR-018:src/participant-protection.mjs'));
  assert.ok(
    denied.reasons.includes('requirement_required_test_ref_missing:FR-018:tests/participant-protection.test.mjs'),
  );
  assert.ok(
    denied.reasons.includes(
      'requirement_required_exochain_primitive_ref_missing:FR-018:crates/exo-consent/src/gatekeeper.rs',
    ),
  );
  assert.ok(
    denied.reasons.includes('requirement_required_adapter_boundary_ref_missing:FR-018:src/participant-protection.mjs'),
  );
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
  assert.ok(result.reasons.includes('requirement_id_missing:NFR-001'));
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
        ...allRows().filter((entry) => entry.requirementId !== 'FR-031'),
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
      ...allRows().filter((entry) => entry.requirementId !== 'FR-031'),
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
            ...allRows().filter((entry) => entry.requirementId !== 'FR-031'),
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
