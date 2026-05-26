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

const REQUIRED_SOURCE_FAMILIES = [
  'adjacent_surface_intake',
  'context_seed',
  'council_escalation_register',
  'council_review_defaults',
  'exochain_readonly_repo',
  'implementation_path_classification',
  'integration_map',
  'master_prd',
  'production_activation_gates',
];

const REQUIRED_CONTEXT_DOC_REFS = [
  'docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md',
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
  'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
  'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
];

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

async function loadGroundTruthRegister() {
  try {
    return await import('../src/ground-truth-register.mjs');
  } catch (error) {
    assert.fail(`CyberMedica ground truth register module must exist and load: ${error.message}`);
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

function sourceRecord(sourceFamily, index, overrides = {}) {
  const sourceRefByFamily = {
    adjacent_surface_intake: 'docs/context/CYBERMEDICA_ADJACENT_SURFACE_DECISIONS.md',
    context_seed: 'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
    council_escalation_register: 'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
    council_review_defaults: 'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md',
    exochain_readonly_repo: '/Users/bobstewart/dev/exochain/exochain',
    implementation_path_classification: 'docs/implementation/PATH_CLASSIFICATION.md',
    integration_map: 'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
    master_prd: 'cybermedica_2_0_sandy_seven_layer_master_prd.md',
    production_activation_gates: 'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  };

  return {
    sourceFamily,
    sourceRef: sourceRefByFamily[sourceFamily],
    classification: sourceFamily === 'exochain_readonly_repo' ? 'EXOCHAIN core' : 'Adjacent surface',
    evidenceKind: sourceFamily === 'exochain_readonly_repo' ? 'read_only_source' : 'controlling_context',
    evidenceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3][index],
    status: 'verified',
    ownerDid: `did:exo:${sourceFamily.replaceAll('_', '-')}-owner`,
    verifiedAtHlc: { physicalMs: 1800000100000, logical: index },
    reviewedByHuman: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function sourceRecords() {
  return REQUIRED_SOURCE_FAMILIES.map((sourceFamily, index) => sourceRecord(sourceFamily, index));
}

function councilEscalation(escalationId, index, overrides = {}) {
  return {
    escalationId,
    disposition: 'bob_decision_required_for_activation_only',
    baselineDefaultHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    productionActivationOnly: true,
    blocksBaselineDevelopment: false,
    reviewedAtHlc: { physicalMs: 1800000200000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function groundTruthInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:ground-truth-steward-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'site_leader'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['ground_truth_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    groundTruthPolicy: {
      policyRef: 'ground-truth-register-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredSourceFamilies: REQUIRED_SOURCE_FAMILIES,
      requiredContextDocRefs: REQUIRED_CONTEXT_DOC_REFS,
      allowedBobEscalationIds: ALLOWED_BOB_ESCALATION_IDS,
      maxSourceAgePhysicalMs: 2_000_000,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800001000000, logical: 0 },
    },
    registerCycle: {
      registerRef: 'ground-truth-register-alpha',
      openedAtHlc: { physicalMs: 1800000000000, logical: 0 },
      compiledAtHlc: { physicalMs: 1800000150000, logical: 0 },
      councilReviewedAtHlc: { physicalMs: 1800000250000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800000300000, logical: 0 },
      validationRecordedAtHlc: { physicalMs: 1800000350000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    sourceRecords: sourceRecords(),
    exochainBoundary: {
      sourceRepoRef: '/Users/bobstewart/dev/exochain/exochain',
      classification: 'EXOCHAIN core',
      readOnlyEvidenceOnly: true,
      noExochainSourceModified: true,
      modifiedPathRefs: [],
      verificationCommandRefs: ['git status --short', 'tools/repo_truth.sh --json --list-tests'],
      verificationEvidenceHash: DIGEST_C,
      verifiedAtHlc: { physicalMs: 1800000200000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    councilDefaults: {
      defaultsApplied: true,
      baselineDevelopmentBlocked: false,
      narrowedEscalationRegisterRef: 'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
      narrowedEscalationRegisterHash: DIGEST_D,
      escalations: ALLOWED_BOB_ESCALATION_IDS.map((escalationId, index) => councilEscalation(escalationId, index)),
      reviewedAtHlc: { physicalMs: 1800000250000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    validationEvidence: {
      contextDocsPresent: true,
      commandsPassed: true,
      sourceGuardPassed: true,
      noRawProtectedContentFound: true,
      noExochainSourceModified: true,
      validationHash: DIGEST_E,
      commandRefs: ['npm run quality'],
      recordedAtHlc: { physicalMs: 1800000350000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      decision: 'ground_truth_accepted_inactive_trust',
      decisionHash: DIGEST_F,
      noProductionTrustClaim: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      reviewedAtHlc: { physicalMs: 1800000300000, logical: 0 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_5,
  };
  return mergeDeep(base, overrides);
}

test('ground truth register permits deterministic metadata-only context source basis', async () => {
  const { evaluateGroundTruthRegister } = await loadGroundTruthRegister();

  const resultA = evaluateGroundTruthRegister(groundTruthInput());
  const resultB = evaluateGroundTruthRegister({
    ...groundTruthInput(),
    groundTruthPolicy: {
      ...groundTruthInput().groundTruthPolicy,
      requiredSourceFamilies: [...REQUIRED_SOURCE_FAMILIES].reverse(),
      allowedBobEscalationIds: [...ALLOWED_BOB_ESCALATION_IDS].reverse(),
      requiredContextDocRefs: [...REQUIRED_CONTEXT_DOC_REFS].reverse(),
    },
    sourceRecords: [...sourceRecords()].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.groundTruth.productionTrustState, 'inactive');
  assert.equal(resultA.groundTruth.exochainSourceReadOnly, true);
  assert.deepEqual(resultA.groundTruth.sourceFamiliesCovered, REQUIRED_SOURCE_FAMILIES);
  assert.deepEqual(resultA.groundTruth.contextDocRefsCovered, REQUIRED_CONTEXT_DOC_REFS);
  assert.deepEqual(resultA.groundTruth.staleSourceFamilies, []);
  assert.deepEqual(resultA.groundTruth.blockingEscalationIds, []);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'ground_truth_register');
  assert.deepEqual(resultA, resultB);
});

test('ground truth register accepts optional adjacent scope as a narrowed Bob escalation', async () => {
  const { evaluateGroundTruthRegister } = await loadGroundTruthRegister();

  const result = evaluateGroundTruthRegister(
    groundTruthInput({
      groundTruthPolicy: {
        allowedBobEscalationIds: [...ALLOWED_BOB_ESCALATION_IDS, 'ESC-OPTIONAL-ADJACENT'],
      },
      councilDefaults: {
        escalations: [
          ...ALLOWED_BOB_ESCALATION_IDS.map((escalationId, index) => councilEscalation(escalationId, index)),
          councilEscalation('ESC-OPTIONAL-ADJACENT', 9),
        ],
      },
    }),
  );

  assert.equal(result.decision, 'permitted');
  assert.equal(result.failClosed, false);
  assert.ok(result.groundTruth.narrowedEscalationIds.includes('ESC-OPTIONAL-ADJACENT'));
  assert.equal(result.groundTruth.productionTrustState, 'inactive');
  assert.equal(result.receipt.exochainProductionClaim, false);
});

test('ground truth register fails closed for missing stale or modified source truth', async () => {
  const { evaluateGroundTruthRegister } = await loadGroundTruthRegister();

  const result = evaluateGroundTruthRegister(
    groundTruthInput({
      sourceRecords: [
        sourceRecord('context_seed', 1, { verifiedAtHlc: { physicalMs: 1799990000000, logical: 0 } }),
        ...sourceRecords().filter((record) => !['context_seed', 'integration_map'].includes(record.sourceFamily)),
      ],
      exochainBoundary: {
        noExochainSourceModified: false,
        modifiedPathRefs: ['/Users/bobstewart/dev/exochain/exochain/crates/exo-core/src/types.rs'],
      },
      councilDefaults: {
        baselineDevelopmentBlocked: true,
      },
      validationEvidence: {
        noExochainSourceModified: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('source_family_missing:integration_map'));
  assert.ok(result.reasons.includes('source_record_stale:context_seed'));
  assert.ok(result.reasons.includes('exochain_source_modified'));
  assert.ok(result.reasons.includes('baseline_development_blocked_by_open_questions'));
});

test('ground truth register rejects premature trust claims and broad Bob escalation', async () => {
  const { evaluateGroundTruthRegister } = await loadGroundTruthRegister();

  const result = evaluateGroundTruthRegister(
    groundTruthInput({
      registerCycle: {
        productionTrustClaim: true,
      },
      sourceRecords: [
        sourceRecord('context_seed', 1, { productionTrustClaim: true }),
        ...sourceRecords().filter((record) => record.sourceFamily !== 'context_seed'),
      ],
      councilDefaults: {
        escalations: [
          councilEscalation('ESC-UNBOUNDED-LEGAL-REVIEW', 0, {
            productionActivationOnly: false,
            blocksBaselineDevelopment: true,
          }),
          ...ALLOWED_BOB_ESCALATION_IDS.slice(1).map((escalationId, index) => councilEscalation(escalationId, index + 1)),
        ],
      },
      humanReview: {
        noProductionTrustClaim: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('source_record_claims_production_trust:context_seed'));
  assert.ok(result.reasons.includes('bob_escalation_not_allowed:ESC-UNBOUNDED-LEGAL-REVIEW'));
  assert.ok(result.reasons.includes('escalation_blocks_baseline:ESC-UNBOUNDED-LEGAL-REVIEW'));
  assert.ok(result.reasons.includes('escalation_not_activation_only:ESC-UNBOUNDED-LEGAL-REVIEW'));
});

test('ground truth register enforces HLC ordering and human final authority', async () => {
  const { evaluateGroundTruthRegister } = await loadGroundTruthRegister();

  const result = evaluateGroundTruthRegister(
    groundTruthInput({
      actor: {
        did: 'did:exo:agent-reviewer',
        kind: 'ai_agent',
      },
      sourceRecords: [
        sourceRecord('context_seed', 1, { verifiedAtHlc: { physicalMs: 1800000400000, logical: 0 } }),
        ...sourceRecords().filter((record) => record.sourceFamily !== 'context_seed'),
      ],
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_ground_truth_reviewer_required'));
  assert.ok(result.reasons.includes('ground_truth_human_final_authority_required'));
  assert.ok(result.reasons.includes('source_verified_after_human_review:context_seed'));
});

test('ground truth register rejects raw source content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateGroundTruthRegister } = await loadGroundTruthRegister();

  assert.throws(
    () =>
      evaluateGroundTruthRegister(
        groundTruthInput({
          sourceRecords: [
            sourceRecord('context_seed', 1, { rawContext: 'Participant Alice Example belongs outside ground truth receipts.' }),
            ...sourceRecords().filter((record) => record.sourceFamily !== 'context_seed'),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateGroundTruthRegister(
        groundTruthInput({
          validationEvidence: {
            apiKey: DIGEST_A,
          },
        }),
      ),
    ProtectedContentError,
  );
});
