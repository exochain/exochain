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

const REQUIRED_SCOPE_QUESTION_FAMILIES = [
  'accreditation_language',
  'ai_irb_public_language',
  'anchoring_metadata_prohibitions',
  'control_library_amendment_authority',
  'control_library_scope',
  'cro_white_labeling',
  'ctms_scope_boundary',
  'decision_forum_panel_model',
  'econsent_execution_model',
  'evidence_retention_policy_model',
  'exochain_deployment_model',
  'first_commercial_form',
  'inspection_mode_support',
  'participant_facing_scope',
  'portable_site_passports',
  'product_accountability_model',
  'safest_commercial_claim',
  'sasi_qms_rights',
  'sponsor_visibility_standard',
  'system_of_record_posture',
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

async function loadScopeLegalReviewRegister() {
  try {
    return await import('../src/scope-legal-review-register.mjs');
  } catch (error) {
    assert.fail(`CyberMedica scope legal review register module must exist and load: ${error.message}`);
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

function scopeQuestion(questionFamily, index, overrides = {}) {
  const legalFamilies = new Set([
    'accreditation_language',
    'ai_irb_public_language',
    'control_library_scope',
    'econsent_execution_model',
    'safest_commercial_claim',
    'sasi_qms_rights',
  ]);
  const commercialFamilies = new Set([
    'cro_white_labeling',
    'first_commercial_form',
    'portable_site_passports',
    'sponsor_visibility_standard',
    'system_of_record_posture',
  ]);

  return {
    questionId: `SCOPE-${String(index + 1).padStart(3, '0')}`,
    questionFamily,
    sourceRef: 'cybermedica_2_0_sandy_seven_layer_master_prd.md#open-questions-for-scoping-and-legal-review',
    sourceLineRef: 2785 + index,
    disposition: 'council_default_for_baseline',
    baselineDefaultRef: `scope-default-${questionFamily}`,
    baselineDefaultHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    decisionNeededHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6][index % 6],
    ownerRoleRef: legalFamilies.has(questionFamily)
      ? 'legal_regulatory_quality_review'
      : 'product_scope_governance_review',
    legalReviewRequired: legalFamilies.has(questionFamily),
    commercialDecisionRequired: commercialFamilies.has(questionFamily),
    councilDefaultUsed: true,
    productionActivationOnly: questionFamily === 'exochain_deployment_model',
    blocksBaselineDevelopment: false,
    publicClaimAllowed: false,
    visibleUntilClosed: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    reviewedAtHlc: { physicalMs: 1807100200000 + index, logical: index % 5 },
    ...overrides,
  };
}

function scopeQuestions() {
  return REQUIRED_SCOPE_QUESTION_FAMILIES.map(scopeQuestion);
}

function registerInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:scope-legal-review-steward-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'product_governance_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['scope_legal_review_register', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    scopeLegalPolicy: {
      policyRef: 'scope-legal-review-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredQuestionFamilies: REQUIRED_SCOPE_QUESTION_FAMILIES,
      allowedBobEscalationIds: ALLOWED_BOB_ESCALATION_IDS,
      sourceDocRefs: [
        'cyber_medica_qms_prd_master.md#open-questions-for-scoping-and-legal-review',
        'cybermedica_2_0_sandy_seven_layer_master_prd.md#open-questions-for-scoping-and-legal-review',
        'docs/context/EXOCHAIN_COUNCIL_ESCALATIONS_FOR_BOB.md',
      ],
      councilDefaultsRequired: true,
      noBroadBobEscalations: true,
      publicClaimReviewRequired: true,
      legalRegulatoryReviewRequired: true,
      productionTrustClaimsInactive: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1807100000000, logical: 0 },
    },
    registerCycle: {
      registerRef: 'scope-legal-review-register-alpha',
      compiledAtHlc: { physicalMs: 1807100100000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1807100500000, logical: 0 },
      validationRecordedAtHlc: { physicalMs: 1807100600000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    questionRecords: scopeQuestions().reverse(),
    scopeBoundary: {
      boundaryRef: 'scope-legal-boundary-alpha',
      sasiRightsVerified: false,
      accreditationLanguageAllowed: false,
      aiIrbPublicLanguageAllowed: false,
      econsentExecutionEnabled: false,
      ctmsPrimaryFunctionEnabled: false,
      croWhiteLabelingEnabled: false,
      portablePassportTransferEnabled: false,
      participantFacingFeaturesEnabled: false,
      productAccountabilityNativeDefaultApproved: false,
      inspectionModeControlledAccessOnly: true,
      exochainProductionClaimsInactive: true,
      manualClaimReviewReceiptHash: DIGEST_C,
      publicClaimReviewReceiptHash: DIGEST_D,
      openQuestionRegisterHash: DIGEST_E,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1807100300000, logical: 0 },
    },
    sourceControl: {
      masterPrdHash: DIGEST_F,
      sandyPrdHash: DIGEST_1,
      noRawPrdText: true,
      noExochainSourceModified: true,
      sourceGuardEvidenceHash: DIGEST_2,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:product-governance-owner-alpha',
      decision: 'scope_legal_register_accepted_inactive_trust',
      decisionHash: DIGEST_3,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1807100500000, logical: 0 },
      metadataOnly: true,
    },
    validationEvidence: {
      commandRefs: ['node --test tests/scope-legal-review-register.test.mjs', 'npm run quality'],
      commandsPassed: true,
      sourceGuardPassed: true,
      docsUpdated: true,
      noExochainSourceModified: true,
      evidenceHash: DIGEST_4,
      recordedAtHlc: { physicalMs: 1807100600000, logical: 0 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_5,
  };
  return mergeDeep(base, overrides);
}

test('scope legal review register creates deterministic inactive records for all 20 PRD questions', async () => {
  const { evaluateScopeLegalReviewRegister } = await loadScopeLegalReviewRegister();

  const first = evaluateScopeLegalReviewRegister(registerInput());
  const second = evaluateScopeLegalReviewRegister({
    ...registerInput(),
    scopeLegalPolicy: {
      ...registerInput().scopeLegalPolicy,
      requiredQuestionFamilies: [...REQUIRED_SCOPE_QUESTION_FAMILIES].reverse(),
      allowedBobEscalationIds: [...ALLOWED_BOB_ESCALATION_IDS].reverse(),
    },
    questionRecords: scopeQuestions(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first.reasons, []);
  assert.equal(first.scopeLegalReviewRegister.productionTrustState, 'inactive');
  assert.equal(first.scopeLegalReviewRegister.exochainProductionClaim, false);
  assert.equal(first.scopeLegalReviewRegister.summary.totalQuestionCount, 20);
  assert.equal(first.scopeLegalReviewRegister.summary.baselineBlockedCount, 0);
  assert.equal(first.scopeLegalReviewRegister.summary.bobEscalationCount, 0);
  assert.equal(first.scopeLegalReviewRegister.summary.legalReviewCount, 6);
  assert.equal(first.scopeLegalReviewRegister.scopeBoundary.accreditationLanguageAllowed, false);
  assert.equal(first.scopeLegalReviewRegister.scopeBoundary.econsentExecutionEnabled, false);
  assert.deepEqual(first.scopeLegalReviewRegister.questionFamiliesCovered, REQUIRED_SCOPE_QUESTION_FAMILIES);
  assert.deepEqual(first.scopeLegalReviewRegister.baselineBlockedQuestionIds, []);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'scope_legal_review_register');
  assert.equal(first.receipt.anchorPayload.classification, 'metadata_only_scope_legal_review_register');
  assert.deepEqual(first, second);
}
);

test('scope legal review register fails closed for missing families broad escalations and unsafe scope claims', async () => {
  const { evaluateScopeLegalReviewRegister } = await loadScopeLegalReviewRegister();

  const result = evaluateScopeLegalReviewRegister(
    registerInput({
      questionRecords: [
        scopeQuestion('public_claim', 10, {
          questionId: 'SCOPE-UNSAFE',
          bobEscalationId: 'ESC-SALES-COPY',
          blocksBaselineDevelopment: true,
          publicClaimAllowed: true,
          baselineDefaultHash: null,
          productionActivationOnly: false,
        }),
        ...scopeQuestions().filter((record) => record.questionFamily !== 'control_library_scope'),
      ],
      scopeBoundary: {
        accreditationLanguageAllowed: true,
        aiIrbPublicLanguageAllowed: true,
        econsentExecutionEnabled: true,
        exochainProductionClaimsInactive: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('scope_question_family_missing:control_library_scope'));
  assert.ok(result.reasons.includes('scope_question_family_unsupported:public_claim'));
  assert.ok(result.reasons.includes('bob_escalation_not_allowed:ESC-SALES-COPY'));
  assert.ok(result.reasons.includes('scope_question_blocks_baseline:SCOPE-UNSAFE'));
  assert.ok(result.reasons.includes('scope_question_public_claim_allowed:SCOPE-UNSAFE'));
  assert.ok(result.reasons.includes('scope_question_baseline_default_hash_invalid:SCOPE-UNSAFE'));
  assert.ok(result.reasons.includes('scope_accreditation_language_unreviewed'));
  assert.ok(result.reasons.includes('scope_ai_irb_public_language_unreviewed'));
  assert.ok(result.reasons.includes('scope_econsent_execution_unreviewed'));
  assert.ok(result.reasons.includes('scope_production_trust_claim_active'));
});

test('scope legal review register rejects AI final authority raw review content and secret material', async () => {
  const { ProtectedContentError, evaluateScopeLegalReviewRegister } = await loadScopeLegalReviewRegister();

  const aiResult = evaluateScopeLegalReviewRegister(
    registerInput({
      actor: { did: 'did:exo:ai-scope-reviewer-alpha', kind: 'ai_agent' },
      humanReview: { aiFinalAuthority: true, finalAuthority: 'ai' },
    }),
  );

  assert.equal(aiResult.decision, 'denied');
  assert.ok(aiResult.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(aiResult.reasons.includes('human_scope_legal_reviewer_required'));
  assert.ok(aiResult.reasons.includes('human_review_final_authority_invalid'));

  assert.throws(
    () =>
      evaluateScopeLegalReviewRegister(
        registerInput({
          questionRecords: [
            scopeQuestion('accreditation_language', 0, {
              rawQuestionText: 'Should we use accreditation copy from a protected source document?',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateScopeLegalReviewRegister(
        registerInput({
          scopeBoundary: { clientSecret: 'redacted-client-secret-placeholder' },
        }),
      ),
    ProtectedContentError,
  );
});
