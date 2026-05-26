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

const REQUIRED_DOCTRINE_DECISIONS = [
  'ai_non_final_authority_rules',
  'non_negotiable_doctrine_statements',
  'participant_protection_data_integrity_gates',
  'privacy_preserving_exochain_receipt_policy',
  'sponsor_cro_visibility_defaults',
];

const REQUIRED_OPERATING_RULES = [
  'access_defaults_to_deny',
  'ai_assists_never_authorizes',
  'contestability_and_recourse',
  'data_integrity_non_negotiable',
  'delegation_valid_scoped_trained_time_bound_revocable',
  'evidence_before_assertion',
  'exochain_receipts_preserve_proof_without_exposure',
  'human_authority_explicit',
  'participant_protection_paramount',
  'standards_become_controls',
];

const REGULATED_AI_ACTIONS = [
  'capa_closure',
  'clinical_trial_product_release',
  'consent',
  'deviation_closure',
  'enrollment',
  'ethics_approval',
  'launch',
  'participant_affecting_decision',
  'protocol_amendment_approval',
  'risk_acceptance',
];

const REQUIRED_GATE_FAMILIES = [
  'alcoac_records',
  'authority_chain',
  'consent_status',
  'data_correction_control',
  'evidence_traceability',
  'participant_rights',
  'privacy_boundary',
  'protocol_conformance',
];

async function loadDoctrineControlPolicy() {
  try {
    return await import('../src/doctrine-control-policy.mjs');
  } catch (error) {
    assert.fail(`CyberMedica doctrine control policy module must exist and load: ${error.message}`);
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

function doctrineDecision(decisionType, index, overrides = {}) {
  return {
    decisionRef: `doctrine-decision-${decisionType}`,
    decisionType,
    status: 'approved',
    ownerRole: index % 2 === 0 ? 'quality_manager' : 'decision_forum_chair',
    evidenceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E][index % 5],
    decisionForumRef: 'df-doctrine-policy-alpha',
    approvedAtHlc: { physicalMs: 1802400100000 + index, logical: index % 3 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function operatingRule(ruleRef, index, overrides = {}) {
  return {
    ruleRef,
    status: 'approved',
    priority: 'required',
    sourceRequirementRef: `cybermedica-doctrine-rule-${index + 1}`,
    evidenceHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6][index % 6],
    ownerRole: index % 2 === 0 ? 'quality_manager' : 'principal_investigator',
    reviewedAtHlc: { physicalMs: 1802400200000 + index, logical: index % 4 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function aiRule(actionRef, index, overrides = {}) {
  return {
    actionRef,
    aiMayAssist: true,
    aiFinalAuthorityAllowed: false,
    humanFinalAuthorityRequired: true,
    decisionForumRequired: ['launch', 'enrollment', 'risk_acceptance', 'capa_closure'].includes(actionRef),
    evidenceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    reviewedAtHlc: { physicalMs: 1802400300000 + index, logical: index % 5 },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function doctrineInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:quality-manager-alpha',
      kind: 'human',
      roleRefs: ['quality_manager'],
    },
    requestedAtHlc: { physicalMs: 1802401000000, logical: 0 },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['govern', 'doctrine_governance'],
      authorityChainHash: DIGEST_A,
    },
    doctrinePolicy: {
      policyRef: 'cybermedica-doctrine-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      evaluatedAtHlc: { physicalMs: 1802400000000, logical: 0 },
      requiredDoctrineDecisions: REQUIRED_DOCTRINE_DECISIONS,
      requiredOperatingRules: REQUIRED_OPERATING_RULES,
      activationGateIds: ['PTAG-001', 'PTAG-005', 'PTAG-009', 'PTAG-010'],
      allowedBobEscalationIds: ['ESC-CONSENT-LEGAL', 'ESC-ROLE-MATRIX'],
      metadataOnly: true,
      productionTrustClaim: false,
    },
    doctrineDecisions: REQUIRED_DOCTRINE_DECISIONS.map(doctrineDecision).reverse(),
    operatingRules: REQUIRED_OPERATING_RULES.map(operatingRule).reverse(),
    aiNonFinalAuthorityPolicy: {
      policyRef: 'ai-non-final-authority-doctrine-alpha',
      policyHash: DIGEST_C,
      status: 'active',
      evaluatedAtHlc: { physicalMs: 1802400250000, logical: 0 },
      regulatedActionRules: REGULATED_AI_ACTIONS.map(aiRule).reverse(),
      aiOutputsLabeledAdvisory: true,
      humanDispositionRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    receiptPrivacyPolicy: {
      policyRef: 'privacy-preserving-receipts-alpha',
      policyHash: DIGEST_D,
      status: 'active',
      hashOnlyAnchoring: true,
      rawSensitiveAnchoringAllowed: false,
      phiPiiExcluded: true,
      sponsorConfidentialExcluded: true,
      privilegedContentExcluded: true,
      sourceDocumentContentExcluded: true,
      healthDebugTelemetryExcluded: true,
      receiptPayloadMetadataOnly: true,
      evidenceHash: DIGEST_E,
      evaluatedAtHlc: { physicalMs: 1802400500000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    visibilityDefaults: {
      policyRef: 'sponsor-cro-visibility-defaults-alpha',
      policyHash: DIGEST_E,
      status: 'active',
      sponsorVisibilityDefault: 'limited',
      croVisibilityDefault: 'role_scoped',
      directIdentifierVisibilityDefault: 'blocked',
      participantLinkedVisibilityDefault: 'coded_metadata_only',
      externalExportDefault: 'explicit_human_authorization',
      waiverRequiresDecisionForum: true,
      evaluatedAtHlc: { physicalMs: 1802400600000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    protectionIntegrityGates: {
      policyRef: 'participant-protection-data-integrity-gates-alpha',
      policyHash: DIGEST_F,
      status: 'active',
      requiredGateFamilies: REQUIRED_GATE_FAMILIES,
      participantProtectionGateActive: true,
      dataIntegrityGateActive: true,
      participantImpactRequiresHumanReview: true,
      dataCorrectionRequiresAuditTrail: true,
      evidenceHash: DIGEST_6,
      evaluatedAtHlc: { physicalMs: 1802400700000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    decisionForum: {
      matterRef: 'df-doctrine-policy-alpha',
      status: 'approved',
      quorumMet: true,
      humanGateVerified: true,
      decisionReceiptHash: DIGEST_1,
      approvedAtHlc: { physicalMs: 1802400800000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:decision-chair-alpha',
      decision: 'doctrine_policy_ready',
      reviewEvidenceHash: DIGEST_2,
      reviewedAtHlc: { physicalMs: 1802400900000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      advisoryOutputHash: DIGEST_3,
      humanReviewed: true,
      reviewedAtHlc: { physicalMs: 1802400850000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
  };

  return mergeDeep(base, overrides);
}

test('doctrine control policy creates deterministic inactive Doctrine backlog receipts', async () => {
  const { evaluateDoctrineControlPolicy } = await loadDoctrineControlPolicy();

  const first = evaluateDoctrineControlPolicy(doctrineInput());
  const second = evaluateDoctrineControlPolicy(
    doctrineInput({
      doctrineDecisions: doctrineInput().doctrineDecisions.toReversed(),
      operatingRules: doctrineInput().operatingRules.toReversed(),
      aiNonFinalAuthorityPolicy: {
        regulatedActionRules: doctrineInput().aiNonFinalAuthorityPolicy.regulatedActionRules.toReversed(),
      },
      protectionIntegrityGates: {
        requiredGateFamilies: [...REQUIRED_GATE_FAMILIES].toReversed(),
      },
    }),
  );

  assert.equal(first.decision, 'doctrine_policy_ready');
  assert.deepEqual(first.reasons, []);
  assert.equal(first.doctrineControl.trustState, 'inactive');
  assert.equal(first.doctrineControl.exochainProductionClaim, false);
  assert.equal(first.doctrineControl.metadataOnly, true);
  assert.deepEqual(first.doctrineControl.doctrineDecisionsCovered, REQUIRED_DOCTRINE_DECISIONS);
  assert.deepEqual(first.doctrineControl.operatingRulesCovered, REQUIRED_OPERATING_RULES);
  assert.deepEqual(first.doctrineControl.regulatedAiActionsCovered, REGULATED_AI_ACTIONS);
  assert.deepEqual(first.doctrineControl.gateFamiliesCovered, REQUIRED_GATE_FAMILIES);
  assert.equal(first.doctrineControl.sponsorVisibilityDefault, 'limited');
  assert.equal(first.doctrineControl.croVisibilityDefault, 'role_scoped');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.exochainProductionClaim, false);
  assert.equal(first.receipt.anchorPayload.artifactType, 'doctrine_control_policy');
  assert.equal(first.doctrineControl.controlHash, second.doctrineControl.controlHash);
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
});

test('doctrine control policy fails closed for incomplete decisions visibility and gate coverage', async () => {
  const { evaluateDoctrineControlPolicy } = await loadDoctrineControlPolicy();
  const input = doctrineInput();
  input.doctrineDecisions = input.doctrineDecisions.filter(
    (decision) => decision.decisionType !== 'privacy_preserving_exochain_receipt_policy',
  );
  input.operatingRules = input.operatingRules.filter((rule) => rule.ruleRef !== 'access_defaults_to_deny');
  input.visibilityDefaults.sponsorVisibilityDefault = 'unrestricted';
  input.visibilityDefaults.directIdentifierVisibilityDefault = 'visible';
  input.protectionIntegrityGates.requiredGateFamilies = ['participant_rights'];
  input.protectionIntegrityGates.dataIntegrityGateActive = false;

  const denied = evaluateDoctrineControlPolicy(input);

  assert.equal(denied.decision, 'hold_for_doctrine_gap');
  assert.ok(denied.reasons.includes('doctrine_decision_missing:privacy_preserving_exochain_receipt_policy'));
  assert.ok(denied.reasons.includes('operating_rule_missing:access_defaults_to_deny'));
  assert.ok(denied.reasons.includes('sponsor_visibility_default_unsafe'));
  assert.ok(denied.reasons.includes('direct_identifier_visibility_unsafe'));
  assert.ok(denied.reasons.includes('gate_family_missing:alcoac_records'));
  assert.ok(denied.reasons.includes('data_integrity_gate_inactive'));
  assert.equal(denied.doctrineControl.trustState, 'inactive');
  assert.equal(denied.receipt, null);
});

test('doctrine control policy keeps AI advisory and blocks production trust claims', async () => {
  const { evaluateDoctrineControlPolicy } = await loadDoctrineControlPolicy();
  const denied = evaluateDoctrineControlPolicy(
    doctrineInput({
      actor: { kind: 'ai_agent' },
      doctrinePolicy: { productionTrustClaim: true },
      aiNonFinalAuthorityPolicy: {
        regulatedActionRules: [
          aiRule('launch', 0, {
            aiFinalAuthorityAllowed: true,
            humanFinalAuthorityRequired: false,
          }),
          ...REGULATED_AI_ACTIONS.filter((action) => action !== 'launch').map(aiRule),
        ],
      },
      aiAssistance: {
        finalAuthority: true,
        humanReviewed: false,
      },
    }),
  );

  assert.equal(denied.decision, 'hold_for_doctrine_gap');
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('regulated_action_allows_ai_final_authority:launch'));
  assert.ok(denied.reasons.includes('regulated_action_human_final_authority_absent:launch'));
  assert.ok(denied.reasons.includes('ai_assistance_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_assistance_human_review_missing'));
  assert.equal(denied.doctrineControl.exochainProductionClaim, false);
});

test('doctrine control policy validates HLC ordering and human governance', async () => {
  const { evaluateDoctrineControlPolicy } = await loadDoctrineControlPolicy();
  const denied = evaluateDoctrineControlPolicy(
    doctrineInput({
      doctrinePolicy: {
        evaluatedAtHlc: { physicalMs: 1802400810000, logical: 0 },
      },
      decisionForum: {
        quorumMet: false,
        humanGateVerified: false,
        approvedAtHlc: { physicalMs: 1802400600000, logical: 0 },
      },
      humanReview: {
        decision: 'approved_without_doctrine',
        reviewedAtHlc: { physicalMs: 1802400500000, logical: 0 },
      },
    }),
  );

  assert.equal(denied.decision, 'hold_for_doctrine_gap');
  assert.ok(denied.reasons.includes('decision_forum_quorum_missing'));
  assert.ok(denied.reasons.includes('decision_forum_human_gate_missing'));
  assert.ok(denied.reasons.includes('decision_forum_before_policy_evaluation'));
  assert.ok(denied.reasons.includes('human_review_decision_invalid'));
  assert.ok(denied.reasons.includes('human_review_before_decision_forum'));
});

test('doctrine control policy handles absent objects as fail-closed denial states', async () => {
  const { evaluateDoctrineControlPolicy } = await loadDoctrineControlPolicy();
  const denied = evaluateDoctrineControlPolicy({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: { valid: false, permissions: [] },
  });

  assert.equal(denied.decision, 'hold_for_doctrine_gap');
  assert.ok(denied.reasons.includes('requested_time_invalid'));
  assert.ok(denied.reasons.includes('authority_chain_invalid'));
  assert.ok(denied.reasons.includes('doctrine_policy_ref_absent'));
  assert.ok(denied.reasons.includes('doctrine_decisions_absent'));
  assert.ok(denied.reasons.includes('operating_rules_absent'));
  assert.ok(denied.reasons.includes('ai_policy_ref_absent'));
  assert.ok(denied.reasons.includes('receipt_privacy_policy_ref_absent'));
  assert.ok(denied.reasons.includes('visibility_policy_ref_absent'));
  assert.ok(denied.reasons.includes('protection_integrity_policy_ref_absent'));
  assert.equal(denied.receipt, null);
});

test('doctrine control policy rejects raw doctrine content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDoctrineControlPolicy } = await loadDoctrineControlPolicy();

  assert.throws(
    () => evaluateDoctrineControlPolicy(doctrineInput({ doctrinePolicy: { rawDoctrineBody: 'unapproved source text' } })),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateDoctrineControlPolicy(doctrineInput({ operatingRules: [operatingRule('access_defaults_to_deny', 0, { sourceDocumentBody: 'source text' })] })),
    ProtectedContentError,
  );
  assert.throws(
    () => evaluateDoctrineControlPolicy(doctrineInput({ receiptPrivacyPolicy: { apiKey: 'cm-secret' } })),
    ProtectedContentError,
  );
});
