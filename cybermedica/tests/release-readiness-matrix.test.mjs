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

const REQUIRED_ACCEPTANCE_DOMAINS = [
  'consent_authority',
  'deterministic_fixtures',
  'documentation',
  'fail_closed_adapters',
  'human_governance',
  'inactive_trust_state_ui',
  'metadata_only_boundaries',
  'release_decision',
  'service_contracts',
  'test_validation',
];

const BOB_ESCALATION_IDS = [
  'ESC-CONSENT-LEGAL',
  'ESC-HUMAN-PROOFING',
  'ESC-OPS-SECRETS',
  'ESC-OPTIONAL-ADJACENT',
  'ESC-ROLE-MATRIX',
  'ESC-ROOT-ARTIFACT-STORE',
  'ESC-ROOT-DEPLOYMENT',
  'ESC-ROOT-OWNER',
  'ESC-ROOT-ROSTER',
  'ESC-RUNTIME',
];

const ACTIVATION_GATE_IDS = Array.from({ length: 18 }, (_, index) => `PTAG-${String(index + 1).padStart(3, '0')}`);

async function loadReleaseReadinessMatrix() {
  try {
    return await import('../src/release-readiness-matrix.mjs');
  } catch (error) {
    assert.fail(`CyberMedica release readiness matrix module must exist and load: ${error.message}`);
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

function acceptanceRow(domain, index, overrides = {}) {
  return {
    domain,
    doctrineLayer: REQUIRED_DOCTRINE_LAYERS[index % REQUIRED_DOCTRINE_LAYERS.length],
    status: 'passed',
    ownerRoleRef: index % 2 === 0 ? 'quality_manager' : 'site_leader',
    evidenceRefs: [`evidence-${domain}`],
    evidenceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800000100000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function activationGate(gateId, index, overrides = {}) {
  return {
    gateId,
    sourceRef: `docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md#${gateId}`,
    status: index < 2 ? 'verified' : 'inactive',
    requiredForProductionTrustClaim: true,
    blocksBaselineDevelopment: false,
    productionClaimActive: false,
    minimumTestRefs: [`test-${gateId.toLowerCase()}`],
    minimumTestHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    verificationEvidenceHash: index < 2 ? [DIGEST_1, DIGEST_2][index] : null,
    reviewedAtHlc: { physicalMs: 1800000200000, logical: index },
    metadataOnly: true,
    ...overrides,
  };
}

function openQuestion(questionId, escalationId, index, overrides = {}) {
  const escalated = escalationId !== null;
  return {
    questionId,
    disposition: escalated ? 'bob_escalation_required' : 'council_consensus_default',
    escalationId,
    baselineDefaultHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    productionClaimGateId: ACTIVATION_GATE_IDS[index % ACTIVATION_GATE_IDS.length],
    blocksBaselineDevelopment: false,
    productionActivationOnly: escalated,
    escalatedToBob: escalated,
    reviewedAtHlc: { physicalMs: 1800000300000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function releaseInput(overrides = {}) {
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
      permissions: ['release_readiness_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    releasePolicy: {
      policyRef: 'release-readiness-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredDoctrineLayers: REQUIRED_DOCTRINE_LAYERS,
      requiredAcceptanceDomains: REQUIRED_ACCEPTANCE_DOMAINS,
      allowedBobEscalationIds: BOB_ESCALATION_IDS,
      activationGateIds: ACTIVATION_GATE_IDS,
      contextDocRefs: [
        'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
        'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md',
        'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
        'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
        'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
      ],
      councilDefaultsApplied: true,
      rootVerificationRequiredForTrustClaims: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800000000000, logical: 0 },
    },
    releaseCycle: {
      cycleRef: 'release-readiness-cycle-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      releaseClass: 'baseline_contract_build',
      openedAtHlc: { physicalMs: 1800000050000, logical: 0 },
      matrixCompiledAtHlc: { physicalMs: 1800000100000, logical: 0 },
      councilReviewedAtHlc: { physicalMs: 1800000300000, logical: 11 },
      bobEscalationReviewedAtHlc: { physicalMs: 1800000400000, logical: 0 },
      validationRecordedAtHlc: { physicalMs: 1800000500000, logical: 0 },
      releaseDecisionAtHlc: { physicalMs: 1800000600000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800000700000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    acceptanceRows: REQUIRED_ACCEPTANCE_DOMAINS.map((domain, index) => acceptanceRow(domain, index)),
    openQuestions: [
      openQuestion('ROOT-001', 'ESC-ROOT-ROSTER', 0),
      openQuestion('ROOT-002', 'ESC-ROOT-ARTIFACT-STORE', 1),
      openQuestion('ROOT-004', 'ESC-ROOT-DEPLOYMENT', 2),
      openQuestion('ROOT-005', 'ESC-ROOT-OWNER', 3),
      openQuestion('ID-001', 'ESC-HUMAN-PROOFING', 4),
      openQuestion('ID-003', 'ESC-ROLE-MATRIX', 5),
      openQuestion('CONSENT-002', 'ESC-CONSENT-LEGAL', 6),
      openQuestion('RT-001', 'ESC-RUNTIME', 7),
      openQuestion('RT-003', 'ESC-OPS-SECRETS', 8),
      openQuestion('ADJ-001', 'ESC-OPTIONAL-ADJACENT', 9),
      openQuestion('RT-005', null, 10),
      openQuestion('ADJ-002', null, 11),
    ],
    activationGates: ACTIVATION_GATE_IDS.map((gateId, index) => activationGate(gateId, index)),
    validationEvidence: {
      commandRef: 'npm run quality',
      passed: true,
      testCount: 301,
      coverageLineBasisPoints: 9971,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      docsUpdated: true,
      evidenceHash: DIGEST_C,
      recordedAtHlc: { physicalMs: 1800000500000, logical: 0 },
      metadataOnly: true,
    },
    releaseDecision: {
      decision: 'baseline_ready_inactive_trust',
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decisionHash: DIGEST_D,
      noProductionTrustClaim: true,
      bobEscalationsNarrowed: true,
      exochainSourceReadOnly: true,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      decidedAtHlc: { physicalMs: 1800000600000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'release-readiness-audit-alpha',
      auditRecordHash: DIGEST_E,
      receiptRecordedAtHlc: { physicalMs: 1800000700000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_F,
      limitationHashes: [DIGEST_1],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_2,
  };

  return mergeDeep(base, overrides);
}

test('release readiness matrix creates deterministic inactive baseline release receipts', async () => {
  const { evaluateReleaseReadinessMatrix } = await loadReleaseReadinessMatrix();

  const resultA = evaluateReleaseReadinessMatrix(releaseInput());
  const resultB = evaluateReleaseReadinessMatrix({
    ...releaseInput(),
    releasePolicy: {
      ...releaseInput().releasePolicy,
      requiredDoctrineLayers: [...releaseInput().releasePolicy.requiredDoctrineLayers].reverse(),
      requiredAcceptanceDomains: [...releaseInput().releasePolicy.requiredAcceptanceDomains].reverse(),
      allowedBobEscalationIds: [...releaseInput().releasePolicy.allowedBobEscalationIds].reverse(),
      activationGateIds: [...releaseInput().releasePolicy.activationGateIds].reverse(),
    },
    acceptanceRows: [...releaseInput().acceptanceRows].reverse(),
    activationGates: [...releaseInput().activationGates].reverse(),
    openQuestions: [...releaseInput().openQuestions].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.releaseReadiness.releaseState, 'baseline_ready_inactive_trust');
  assert.equal(resultA.releaseReadiness.productionTrustState, 'inactive');
  assert.equal(resultA.releaseReadiness.exochainProductionClaim, false);
  assert.deepEqual(resultA.releaseReadiness.doctrineLayersCovered, REQUIRED_DOCTRINE_LAYERS);
  assert.deepEqual(resultA.releaseReadiness.acceptanceDomainsCovered, REQUIRED_ACCEPTANCE_DOMAINS);
  assert.deepEqual(resultA.releaseReadiness.bobEscalationIds, BOB_ESCALATION_IDS);
  assert.equal(resultA.releaseReadiness.openQuestionSummary.escalatedToBobCount, 10);
  assert.equal(resultA.releaseReadiness.openQuestionSummary.consensusDefaultCount, 2);
  assert.equal(resultA.releaseReadiness.activationGateSummary.totalGateCount, 18);
  assert.equal(resultA.releaseReadiness.activationGateSummary.verifiedGateCount, 2);
  assert.equal(resultA.releaseReadiness.activationGateSummary.unverifiedProductionGateCount, 16);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.deepEqual(resultA, resultB);
});

test('release readiness matrix fails closed for incomplete acceptance coverage and broad Bob escalation', async () => {
  const { evaluateReleaseReadinessMatrix } = await loadReleaseReadinessMatrix();

  const result = evaluateReleaseReadinessMatrix(
    releaseInput({
      acceptanceRows: REQUIRED_ACCEPTANCE_DOMAINS.filter((domain) => domain !== 'fail_closed_adapters').map(
        (domain, index) => acceptanceRow(domain, index),
      ),
      openQuestions: [
        openQuestion('RT-005', null, 0, {
          disposition: 'bob_escalation_required',
          escalatedToBob: true,
          escalationId: 'ESC-CI-GATES',
        }),
      ],
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('acceptance_domain_missing:fail_closed_adapters'));
  assert.ok(result.reasons.includes('bob_escalation_not_allowed:ESC-CI-GATES'));
  assert.ok(result.reasons.includes('open_question_baseline_default_absent:RT-005'));
});

test('release readiness matrix blocks production trust claims while activation gates remain unverified', async () => {
  const { evaluateReleaseReadinessMatrix } = await loadReleaseReadinessMatrix();

  const result = evaluateReleaseReadinessMatrix(
    releaseInput({
      releaseCycle: {
        productionTrustClaim: true,
      },
      activationGates: [
        activationGate('PTAG-001', 0, {
          status: 'verified',
          verificationEvidenceHash: null,
          productionClaimActive: true,
        }),
        activationGate('PTAG-002', 1, {
          status: 'inactive',
          verificationEvidenceHash: null,
          productionClaimActive: true,
        }),
      ],
      releaseDecision: {
        decision: 'production_trust_active',
        noProductionTrustClaim: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('release_decision_production_trust_forbidden'));
  assert.ok(result.reasons.includes('activation_gate_verification_evidence_missing:PTAG-001'));
  assert.ok(result.reasons.includes('activation_gate_active_claim_forbidden:PTAG-002'));
  assert.ok(result.reasons.includes('production_claim_gate_unverified:PTAG-002'));
});

test('release readiness matrix validates HLC ordering and AI advisory boundaries', async () => {
  const { evaluateReleaseReadinessMatrix } = await loadReleaseReadinessMatrix();

  const result = evaluateReleaseReadinessMatrix(
    releaseInput({
      releaseCycle: {
        matrixCompiledAtHlc: { physicalMs: 1800000000000, logical: 0 },
      },
      aiAssistance: {
        finalAuthority: true,
        reviewedByHuman: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('release_cycle_matrixCompiledAtHlc_before_openedAtHlc'));
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('ai_human_review_absent'));
});

test('release readiness matrix handles absent objects as fail-closed denial states', async () => {
  const { evaluateReleaseReadinessMatrix } = await loadReleaseReadinessMatrix();

  const result = evaluateReleaseReadinessMatrix({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['release_readiness_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('release_policy_ref_absent'));
  assert.ok(result.reasons.includes('release_cycle_ref_absent'));
  assert.ok(result.reasons.includes('acceptance_rows_absent'));
  assert.ok(result.reasons.includes('activation_gates_absent'));
  assert.ok(result.reasons.includes('validation_evidence_absent'));
  assert.ok(result.reasons.includes('release_decision_absent'));
  assert.ok(result.reasons.includes('release_audit_record_ref_absent'));
});

test('release readiness matrix rejects raw register content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateReleaseReadinessMatrix } = await loadReleaseReadinessMatrix();

  const inert = releaseInput({
    openQuestions: [
      openQuestion('ROOT-001', 'ESC-ROOT-ROSTER', 0, {
        rawOpenQuestionText: false,
      }),
      ...releaseInput().openQuestions.slice(1),
    ],
    releaseDecision: {
      secret: {},
    },
  });

  assert.equal(evaluateReleaseReadinessMatrix(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateReleaseReadinessMatrix(
        releaseInput({
          openQuestions: [
            openQuestion('ROOT-001', 'ESC-ROOT-ROSTER', 0, {
              rawOpenQuestionText: 'actual institutional answer belongs outside receipts',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateReleaseReadinessMatrix(
        releaseInput({
          releaseDecision: {
            accessToken: DIGEST_A,
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateReleaseReadinessMatrix(
        releaseInput({
          validationEvidence: {
            rawValidationOutput: ['test logs stay outside receipt anchors'],
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateReleaseReadinessMatrix(
        releaseInput({
          releaseDecision: {
            secret: 7,
          },
        }),
      ),
    ProtectedContentError,
  );
});
