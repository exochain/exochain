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

const REQUIRED_SANDY_QUESTION_FAMILIES = [
  'ai_irb_language',
  'control_source_legal_permission',
  'exochain_deployment_model',
  'first_commercial_deployment',
  'minimum_viable_control_library',
  'participant_facing_scope',
  'product_positioning',
  'public_claim',
  'sales_content_review',
  'sponsor_visibility_model',
];

async function loadSandyReviewRegister() {
  try {
    return await import('../src/sandy-review-register.mjs');
  } catch (error) {
    assert.fail(`CyberMedica Sandy review register module must exist and load: ${error.message}`);
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

function sandyQuestion(questionFamily, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4];
  const legalReviewFamilies = new Set([
    'ai_irb_language',
    'control_source_legal_permission',
    'participant_facing_scope',
    'public_claim',
    'sales_content_review',
  ]);
  const commercialDecisionFamilies = new Set([
    'first_commercial_deployment',
    'product_positioning',
    'sponsor_visibility_model',
  ]);

  return {
    questionId: `SANDY-${String(index + 1).padStart(3, '0')}`,
    questionFamily,
    sourceRef: 'cybermedica_2_0_sandy_seven_layer_master_prd.md#appendix-b-sandy-review-questions',
    sourceLineRef: 2900 + index,
    disposition: 'council_default_for_baseline',
    conservativeDefaultRef: `sandy-default-${questionFamily}`,
    conservativeDefaultHash: hashes[index],
    decisionNeededHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6][index % 6],
    ownerRoleRef: legalReviewFamilies.has(questionFamily) ? 'legal_regulatory_quality_review' : 'product_governance_review',
    legalReviewRequired: legalReviewFamilies.has(questionFamily),
    commercialDecisionRequired: commercialDecisionFamilies.has(questionFamily),
    productionActivationOnly: questionFamily === 'exochain_deployment_model',
    blocksBaselineDevelopment: false,
    publicClaimAllowed: false,
    visibleUntilClosed: true,
    councilDefaultUsed: true,
    bobEscalationId: null,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    reviewedAtHlc: { physicalMs: 1803100200000 + index, logical: index % 3 },
    ...overrides,
  };
}

function sandyQuestions() {
  return REQUIRED_SANDY_QUESTION_FAMILIES.map(sandyQuestion);
}

function registerInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:sandy-review-steward-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'product_governance_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['sandy_review_register', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    sandyReviewPolicy: {
      policyRef: 'sandy-review-register-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredQuestionFamilies: REQUIRED_SANDY_QUESTION_FAMILIES,
      sourceDocRefs: [
        'cybermedica_2_0_sandy_seven_layer_master_prd.md',
        'cyber_medica_qms_prd_master.md',
        'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
      ],
      allowedBobEscalationIds: ['ESC-ROOT-DEPLOYMENT', 'ESC-RUNTIME'],
      councilDefaultsRequired: true,
      publicClaimReviewRequired: true,
      legalRegulatoryReviewRequired: true,
      aiIrbPublicLanguageBlocked: true,
      participantFacingDisabledUntilReview: true,
      productionTrustClaimsInactive: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1803100000000, logical: 0 },
    },
    registerCycle: {
      registerRef: 'sandy-review-register-alpha',
      compiledAtHlc: { physicalMs: 1803100100000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1803100400000, logical: 0 },
      validationRecordedAtHlc: { physicalMs: 1803100500000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    questionRecords: sandyQuestions().reverse(),
    claimBoundary: {
      boundaryRef: 'sandy-review-claim-boundary-alpha',
      manualClaimReviewReceiptHash: DIGEST_C,
      legalRegulatoryReviewHash: DIGEST_D,
      controlledSponsorCroRequestPolicyHash: DIGEST_E,
      noRawStandardTextEmbedded: true,
      aiIrbPublicLanguageAllowed: false,
      productionTrustClaimsInactive: true,
      participantFacingFeaturesEnabled: false,
      sponsorVisibilityRequiresTenantConfig: true,
      exochainDeploymentChoiceActivationOnly: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1803100300000, logical: 0 },
    },
    sourceControl: {
      sandyPrdHash: DIGEST_F,
      masterPrdHash: DIGEST_1,
      noRawPrdText: true,
      noExochainSourceModified: true,
      sourceGuardEvidenceHash: DIGEST_2,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:product-governance-owner-alpha',
      decision: 'sandy_review_register_accepted_inactive_trust',
      decisionHash: DIGEST_3,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1803100400000, logical: 0 },
      metadataOnly: true,
    },
    validationEvidence: {
      commandRefs: ['node --test tests/sandy-review-register.test.mjs', 'npm run quality'],
      commandsPassed: true,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      recordedAtHlc: { physicalMs: 1803100500000, logical: 0 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_4,
  };
  return mergeDeep(base, overrides);
}

test('Sandy review register creates deterministic inactive Appendix B records', async () => {
  const { evaluateSandyReviewRegister } = await loadSandyReviewRegister();

  const first = evaluateSandyReviewRegister(registerInput());
  const second = evaluateSandyReviewRegister({
    ...registerInput(),
    sandyReviewPolicy: {
      ...registerInput().sandyReviewPolicy,
      requiredQuestionFamilies: [...REQUIRED_SANDY_QUESTION_FAMILIES].reverse(),
    },
    questionRecords: sandyQuestions(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first.reasons, []);
  assert.equal(first.sandyReviewRegister.productionTrustState, 'inactive');
  assert.equal(first.sandyReviewRegister.exochainProductionClaim, false);
  assert.equal(first.sandyReviewRegister.questionCount, 10);
  assert.equal(first.sandyReviewRegister.summary.conservativeDefaultCount, 10);
  assert.equal(first.sandyReviewRegister.summary.bobEscalationCount, 0);
  assert.equal(first.sandyReviewRegister.summary.baselineBlockedCount, 0);
  assert.equal(first.sandyReviewRegister.summary.legalReviewCount, 5);
  assert.deepEqual(first.sandyReviewRegister.questionFamiliesCovered, REQUIRED_SANDY_QUESTION_FAMILIES);
  assert.deepEqual(first.sandyReviewRegister.baselineBlockedQuestionIds, []);
  assert.equal(first.sandyReviewRegister.claimBoundary.aiIrbPublicLanguageAllowed, false);
  assert.equal(first.sandyReviewRegister.claimBoundary.participantFacingFeaturesEnabled, false);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'sandy_review_register');
  assert.equal(first.receipt.anchorPayload.classification, 'metadata_only_sandy_review_register');
  assert.deepEqual(first, second);
});

test('Sandy review register fails closed for missing questions broad Bob escalations and public claims', async () => {
  const { evaluateSandyReviewRegister } = await loadSandyReviewRegister();

  const result = evaluateSandyReviewRegister(
    registerInput({
      questionRecords: [
        sandyQuestion('public_claim', 7, {
          questionId: 'SANDY-UNSAFE',
          bobEscalationId: 'ESC-SALES-COPY',
          blocksBaselineDevelopment: true,
          publicClaimAllowed: true,
          conservativeDefaultHash: null,
        }),
        ...sandyQuestions().filter((record) => record.questionFamily !== 'sales_content_review'),
      ],
      claimBoundary: {
        aiIrbPublicLanguageAllowed: true,
        productionTrustClaimsInactive: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('sandy_question_family_missing:sales_content_review'));
  assert.ok(result.reasons.includes('bob_escalation_not_allowed:ESC-SALES-COPY'));
  assert.ok(result.reasons.includes('sandy_question_blocks_baseline:SANDY-UNSAFE'));
  assert.ok(result.reasons.includes('sandy_question_public_claim_forbidden:SANDY-UNSAFE'));
  assert.ok(result.reasons.includes('sandy_question_default_hash_invalid:SANDY-UNSAFE'));
  assert.ok(result.reasons.includes('ai_irb_public_language_not_blocked'));
  assert.ok(result.reasons.includes('claim_boundary_production_trust_not_inactive'));
  assert.equal(result.sandyReviewRegister, null);
  assert.equal(result.receipt, null);
});

test('Sandy review register enforces HLC ordering human authority and metadata source control', async () => {
  const { evaluateSandyReviewRegister } = await loadSandyReviewRegister();

  const result = evaluateSandyReviewRegister(
    registerInput({
      actor: {
        did: 'did:exo:ai-sandy-reviewer',
        kind: 'ai_agent',
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      registerCycle: {
        humanReviewedAtHlc: { physicalMs: 1803100050000, logical: 0 },
        productionTrustClaim: true,
      },
      questionRecords: [
        sandyQuestion('ai_irb_language', 0, {
          reviewedAtHlc: { physicalMs: 1803100600000, logical: 0 },
        }),
        ...sandyQuestions().filter((record) => record.questionFamily !== 'ai_irb_language'),
      ],
      sourceControl: {
        noRawPrdText: false,
        noExochainSourceModified: false,
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
      },
      validationEvidence: {
        commandsPassed: false,
        sourceGuardPassed: false,
        noExochainSourceModified: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_sandy_review_actor_required'));
  assert.ok(result.reasons.includes('sandy_review_authority_missing'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('sandy_question_review_after_human_review:SANDY-001'));
  assert.ok(result.reasons.includes('sandy_review_human_final_authority_required'));
  assert.ok(result.reasons.includes('source_control_raw_prd_boundary_absent'));
  assert.ok(result.reasons.includes('source_control_exochain_modified'));
  assert.ok(result.reasons.includes('validation_commands_not_passed'));
  assert.ok(result.reasons.includes('validation_source_guard_failed'));
});

test('Sandy review register rejects raw review content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateSandyReviewRegister } = await loadSandyReviewRegister();

  assert.throws(
    () =>
      evaluateSandyReviewRegister(
        registerInput({
          questionRecords: [
            sandyQuestion('product_positioning', 6, {
              rawSandyAnswer: 'Use raw sales positioning copy here.',
            }),
            ...sandyQuestions().filter((record) => record.questionFamily !== 'product_positioning'),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateSandyReviewRegister(
        registerInput({
          claimBoundary: {
            rootSigningKey: 'secret-root-signing-key',
          },
        }),
      ),
    ProtectedContentError,
  );
});
