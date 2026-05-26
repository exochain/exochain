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

const REQUIRED_QUESTION_FAMILIES = [
  'adjacent_scope',
  'clinical_consent_legal',
  'data_privacy',
  'governance_decision_forum',
  'identity_human_gate',
  'operations_secret_management',
  'role_authority_matrix',
  'root_trust_activation',
  'runtime_topology',
];

const ALLOWED_BOB_ESCALATION_IDS = [
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

async function loadOpenQuestionRegister() {
  try {
    return await import('../src/open-question-register.mjs');
  } catch (error) {
    assert.fail(`CyberMedica open question register module must exist and load: ${error.message}`);
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

function questionRecord(questionId, questionFamily, index, overrides = {}) {
  const escalationByFamily = {
    adjacent_scope: 'ESC-OPTIONAL-ADJACENT',
    clinical_consent_legal: 'ESC-CONSENT-LEGAL',
    identity_human_gate: 'ESC-HUMAN-PROOFING',
    operations_secret_management: 'ESC-OPS-SECRETS',
    role_authority_matrix: 'ESC-ROLE-MATRIX',
    root_trust_activation: 'ESC-ROOT-ROSTER',
    runtime_topology: 'ESC-RUNTIME',
  };
  const escalationId = escalationByFamily[questionFamily] ?? null;
  const escalated = escalationId !== null;

  return {
    questionId,
    questionFamily,
    sourceRef: 'docs/context/EXOCHAIN_OPEN_QUESTIONS_FOR_BOB.md',
    disposition: escalated ? 'bob_activation_escalation' : 'council_consensus_default',
    escalationId,
    baselineDefaultHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    decisionNeededHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5][index % 5],
    ownerRoleRef: escalated ? 'bob' : 'council_default_steward',
    productionActivationOnly: escalated,
    blocksBaselineDevelopment: false,
    visibleUntilClosed: true,
    closedByGovernance: false,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    reviewedAtHlc: { physicalMs: 1800000200000, logical: index },
    ...overrides,
  };
}

function questionRecords() {
  return [
    questionRecord('ROOT-001', 'root_trust_activation', 0, { escalationId: 'ESC-ROOT-ROSTER' }),
    questionRecord('ROOT-002', 'root_trust_activation', 1, { escalationId: 'ESC-ROOT-ARTIFACT-STORE' }),
    questionRecord('ROOT-004', 'root_trust_activation', 2, { escalationId: 'ESC-ROOT-DEPLOYMENT' }),
    questionRecord('ROOT-005', 'root_trust_activation', 3, { escalationId: 'ESC-ROOT-OWNER' }),
    questionRecord('ID-001', 'identity_human_gate', 4),
    questionRecord('ID-003', 'role_authority_matrix', 5),
    questionRecord('CONSENT-002', 'clinical_consent_legal', 6),
    questionRecord('DATA-001', 'data_privacy', 7, { disposition: 'council_consensus_default' }),
    questionRecord('DF-004', 'governance_decision_forum', 8, { disposition: 'council_consensus_default' }),
    questionRecord('RT-001', 'runtime_topology', 9),
    questionRecord('RT-004', 'operations_secret_management', 10),
    questionRecord('ADJ-001', 'adjacent_scope', 11),
  ];
}

function registerInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:open-question-steward-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'site_leader'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['open_question_register_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    openQuestionPolicy: {
      policyRef: 'open-question-register-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredQuestionFamilies: REQUIRED_QUESTION_FAMILIES,
      allowedBobEscalationIds: ALLOWED_BOB_ESCALATION_IDS,
      contextDocRefs: [
        'docs/context/EXOCHAIN_OPEN_QUESTIONS_FOR_BOB.md',
        'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
        'docs/context/EXOCHAIN_COUNCIL_REVIEW_FOR_CYBERMEDICA_OPEN_QUESTIONS.md',
        'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
      ],
      councilDefaultsRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800000000000, logical: 0 },
    },
    registerCycle: {
      registerRef: 'open-question-register-alpha',
      openedAtHlc: { physicalMs: 1800000050000, logical: 0 },
      compiledAtHlc: { physicalMs: 1800000100000, logical: 0 },
      councilReviewedAtHlc: { physicalMs: 1800000200000, logical: 20 },
      humanReviewedAtHlc: { physicalMs: 1800000300000, logical: 0 },
      validationRecordedAtHlc: { physicalMs: 1800000400000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    questionRecords: questionRecords(),
    validationEvidence: {
      commandRef: 'npm run quality',
      passed: true,
      sourceGuardPassed: true,
      docsUpdated: true,
      noExochainSourceModified: true,
      evidenceHash: DIGEST_C,
      recordedAtHlc: { physicalMs: 1800000400000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      decision: 'open_question_register_accepted_inactive_trust',
      decisionHash: DIGEST_D,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1800000300000, logical: 0 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_E,
  };
  return mergeDeep(base, overrides);
}

test('open question register creates deterministic visible inactive-trust records', async () => {
  const { evaluateOpenQuestionRegister } = await loadOpenQuestionRegister();

  const resultA = evaluateOpenQuestionRegister(registerInput());
  const resultB = evaluateOpenQuestionRegister({
    ...registerInput(),
    openQuestionPolicy: {
      ...registerInput().openQuestionPolicy,
      requiredQuestionFamilies: [...REQUIRED_QUESTION_FAMILIES].reverse(),
      allowedBobEscalationIds: [...ALLOWED_BOB_ESCALATION_IDS].reverse(),
    },
    questionRecords: [...questionRecords()].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.openQuestionRegister.productionTrustState, 'inactive');
  assert.deepEqual(resultA.openQuestionRegister.questionFamiliesCovered, REQUIRED_QUESTION_FAMILIES);
  assert.deepEqual(resultA.openQuestionRegister.baselineBlockedQuestionIds, []);
  assert.equal(resultA.openQuestionRegister.summary.totalQuestionCount, 12);
  assert.equal(resultA.openQuestionRegister.summary.bobEscalationCount, 10);
  assert.equal(resultA.openQuestionRegister.summary.consensusDefaultCount, 2);
  assert.equal(resultA.openQuestionRegister.summary.visibleOpenQuestionCount, 12);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'open_question_register');
  assert.deepEqual(resultA, resultB);
});

test('open question register fails closed for missing families and broad escalations', async () => {
  const { evaluateOpenQuestionRegister } = await loadOpenQuestionRegister();

  const result = evaluateOpenQuestionRegister(
    registerInput({
      questionRecords: [
        questionRecord('Q-UNSAFE', 'runtime_topology', 0, {
          disposition: 'bob_activation_escalation',
          escalationId: 'ESC-CI-GATES',
          productionActivationOnly: false,
          blocksBaselineDevelopment: true,
          baselineDefaultHash: null,
        }),
        ...questionRecords().filter((record) => record.questionFamily !== 'operations_secret_management'),
      ],
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('question_family_missing:operations_secret_management'));
  assert.ok(result.reasons.includes('bob_escalation_not_allowed:ESC-CI-GATES'));
  assert.ok(result.reasons.includes('open_question_blocks_baseline:Q-UNSAFE'));
  assert.ok(result.reasons.includes('open_question_escalation_not_activation_only:Q-UNSAFE'));
  assert.ok(result.reasons.includes('open_question_baseline_default_hash_invalid:Q-UNSAFE'));
});

test('open question register enforces HLC ordering and human final authority', async () => {
  const { evaluateOpenQuestionRegister } = await loadOpenQuestionRegister();

  const result = evaluateOpenQuestionRegister(
    registerInput({
      actor: {
        did: 'did:exo:ai-question-agent',
        kind: 'ai_agent',
      },
      registerCycle: {
        productionTrustClaim: true,
        humanReviewedAtHlc: { physicalMs: 1800000090000, logical: 0 },
      },
      questionRecords: [
        questionRecord('ROOT-001', 'root_trust_activation', 0, {
          reviewedAtHlc: { physicalMs: 1800000500000, logical: 0 },
        }),
        ...questionRecords().filter((record) => record.questionId !== 'ROOT-001'),
      ],
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_open_question_reviewer_required'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('open_question_human_final_authority_required'));
  assert.ok(result.reasons.includes('open_question_human_review_order_invalid'));
  assert.ok(result.reasons.includes('open_question_review_after_human_review:ROOT-001'));
});

test('open question register rejects raw question content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateOpenQuestionRegister } = await loadOpenQuestionRegister();

  assert.throws(
    () =>
      evaluateOpenQuestionRegister(
        registerInput({
          questionRecords: [
            questionRecord('ROOT-001', 'root_trust_activation', 0, {
              rawQuestionText: 'Participant Alice Example must not enter register receipts.',
            }),
            ...questionRecords().filter((record) => record.questionId !== 'ROOT-001'),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateOpenQuestionRegister(
        registerInput({
          validationEvidence: {
            apiKey: DIGEST_A,
          },
        }),
      ),
    ProtectedContentError,
  );
});
