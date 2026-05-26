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

const REQUIRED_ESCALATION_FAMILIES = [
  'capa_closure',
  'consent_policy_change',
  'enrollment_gate',
  'production_trust_activation',
  'protocol_launch',
  'qms_control_approval',
  'support_access_policy',
];

async function loadDecisionForumEscalationEngine() {
  try {
    return await import('../src/decision-forum-escalation-engine.mjs');
  } catch (error) {
    assert.fail(`CyberMedica Decision Forum escalation engine module must exist and load: ${error.message}`);
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

function signalFor(signalFamily, index, overrides = {}) {
  const strategicFamilies = new Set([
    'capa_closure',
    'consent_policy_change',
    'enrollment_gate',
    'protocol_launch',
    'qms_control_approval',
    'support_access_policy',
  ]);
  return {
    signalRef: `df-escalation-signal-${signalFamily}`,
    signalFamily,
    sourceWorkflowRef: `workflow-${signalFamily}`,
    sourceArtifactHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1][index],
    controlRefs: [`control-${signalFamily}`],
    riskLevel: signalFamily === 'production_trust_activation' ? 'constitutional' : 'high',
    urgency: signalFamily === 'production_trust_activation' ? 'immediate' : 'standard',
    participantSafetyImpact: ['enrollment_gate', 'protocol_launch'].includes(signalFamily),
    consentOrAuthorityImpact: ['consent_policy_change', 'enrollment_gate', 'support_access_policy'].includes(signalFamily),
    trustActivationImpact: signalFamily === 'production_trust_activation',
    materialDecision: true,
    recommendedDecisionClass: signalFamily === 'production_trust_activation'
      ? 'constitutional'
      : strategicFamilies.has(signalFamily)
        ? 'strategic'
        : 'operational',
    metadataOnly: true,
    protectedContentExcluded: true,
    detectedAtHlc: { physicalMs: 1802000100000, logical: index },
    ...overrides,
  };
}

function routeFor(signal, index, overrides = {}) {
  return {
    routeRef: `df-escalation-route-${signal.signalFamily}`,
    signalRef: signal.signalRef,
    routeType: 'decision_forum',
    matterRef: `DF-${signal.signalFamily.toUpperCase().replaceAll('_', '-')}-001`,
    decisionType: signal.signalFamily,
    decisionClass: signal.recommendedDecisionClass,
    requiredGovernanceRoleRefs: signal.decisionClass === 'constitutional'
      ? ['root_ceremony_owner', 'quality_governance']
      : ['principal_investigator', 'quality_manager'],
    evidenceBundleHash: [DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_A, DIGEST_B][index],
    rationaleHash: [DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3][index],
    openedByDid: 'did:exo:quality-manager-alpha',
    routedAtHlc: { physicalMs: 1802000200000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function escalationInput(overrides = {}) {
  const signals = REQUIRED_ESCALATION_FAMILIES.map((family, index) => signalFor(family, index));
  const routes = signals.map((signal, index) => routeFor(signal, index));

  return mergeDeep(
    {
      tenantId: 'tenant-site-alpha',
      targetTenantId: 'tenant-site-alpha',
      actor: {
        did: 'did:exo:quality-manager-alpha',
        kind: 'human',
        roleRefs: ['quality_manager'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['decision_forum_escalate', 'govern'],
        authorityChainHash: DIGEST_A,
      },
      escalationPolicy: {
        policyRef: 'decision-forum-escalation-policy-alpha',
        policyHash: DIGEST_B,
        status: 'active',
        requiredEscalationFamilies: REQUIRED_ESCALATION_FAMILIES,
        requireDecisionForumForMaterialSignals: true,
        requireHumanFinalAuthority: true,
        requireMetadataOnlyRoutes: true,
        protectedContentExcluded: true,
        evaluatedAtHlc: { physicalMs: 1802000000000, logical: 0 },
      },
      escalationCycle: {
        cycleRef: 'decision-forum-escalation-cycle-alpha',
        openedAtHlc: { physicalMs: 1802000050000, logical: 0 },
        signalsClassifiedAtHlc: { physicalMs: 1802000120000, logical: 0 },
        routesDeterminedAtHlc: { physicalMs: 1802000200000, logical: 0 },
        humanReviewedAtHlc: { physicalMs: 1802000300000, logical: 0 },
        auditRecordedAtHlc: { physicalMs: 1802000400000, logical: 0 },
        exochainProductionClaim: false,
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      escalationSignals: signals,
      escalationRoutes: routes,
      aiAssistance: {
        used: true,
        advisoryOnly: true,
        finalAuthority: false,
        recommendationHash: DIGEST_C,
        limitationHashes: [DIGEST_D],
        reviewedByHuman: true,
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      humanReview: {
        reviewerDid: 'did:exo:principal-investigator-alpha',
        reviewerRoleRefs: ['principal_investigator', 'quality_manager'],
        decision: 'decision_forum_escalation_ready',
        decisionHash: DIGEST_E,
        finalAuthority: 'human',
        aiFinalAuthority: false,
        noProductionTrustClaim: true,
        reviewedAtHlc: { physicalMs: 1802000300000, logical: 0 },
        metadataOnly: true,
      },
      auditRecord: {
        auditRecordRef: 'decision-forum-escalation-audit-alpha',
        auditRecordHash: DIGEST_F,
        receiptRecordedAtHlc: { physicalMs: 1802000400000, logical: 0 },
        metadataOnly: true,
        includesProtectedContent: false,
      },
      custodyDigest: DIGEST_1,
    },
    overrides,
  );
}

test('Decision Forum escalation engine creates deterministic inactive matter routing', async () => {
  const { evaluateDecisionForumEscalationEngine } = await loadDecisionForumEscalationEngine();

  const first = evaluateDecisionForumEscalationEngine(escalationInput());
  const second = evaluateDecisionForumEscalationEngine({
    ...escalationInput(),
    escalationPolicy: {
      ...escalationInput().escalationPolicy,
      requiredEscalationFamilies: [...escalationInput().escalationPolicy.requiredEscalationFamilies].reverse(),
    },
    escalationSignals: [...escalationInput().escalationSignals].reverse(),
    escalationRoutes: [...escalationInput().escalationRoutes].reverse(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first.reasons, []);
  assert.equal(first.escalationEngine.trustState, 'inactive');
  assert.equal(first.escalationEngine.exochainProductionClaim, false);
  assert.equal(first.escalationEngine.metadataOnly, true);
  assert.equal(first.escalationEngine.containsProtectedContent, false);
  assert.deepEqual(first.escalationEngine.escalationFamiliesCovered, REQUIRED_ESCALATION_FAMILIES);
  assert.equal(first.escalationEngine.decisionForumMatterCount, 7);
  assert.deepEqual(first.escalationEngine.decisionClassCounts, {
    constitutional: 1,
    operational: 0,
    routine: 0,
    strategic: 6,
  });
  assert.deepEqual(first.matterDrafts.map((draft) => draft.matterRef), [
    'DF-CAPA-CLOSURE-001',
    'DF-CONSENT-POLICY-CHANGE-001',
    'DF-ENROLLMENT-GATE-001',
    'DF-PRODUCTION-TRUST-ACTIVATION-001',
    'DF-PROTOCOL-LAUNCH-001',
    'DF-QMS-CONTROL-APPROVAL-001',
    'DF-SUPPORT-ACCESS-POLICY-001',
  ]);
  assert.equal(first.receipt.anchorPayload.artifactType, 'decision_forum_escalation_engine');
  assert.equal(first.receipt.trustState, 'inactive');
  assert.deepEqual(first, second);
  assert.doesNotMatch(JSON.stringify(first), /patient|subject name|raw deliberation|source document/iu);
});

test('Decision Forum escalation engine fails closed when material signals lack forum routes', async () => {
  const { evaluateDecisionForumEscalationEngine } = await loadDecisionForumEscalationEngine();
  const input = escalationInput();
  input.escalationSignals = input.escalationSignals.filter((signal) => signal.signalFamily !== 'enrollment_gate');
  input.escalationRoutes = input.escalationRoutes.filter((route) => route.decisionType !== 'protocol_launch');
  input.escalationRoutes[0] = {
    ...input.escalationRoutes[0],
    routeType: 'cqi',
    evidenceBundleHash: '',
    rationaleHash: 'bad',
    requiredGovernanceRoleRefs: [],
  };
  input.humanReview = {
    reviewerDid: '',
    reviewerRoleRefs: [],
    decision: 'rubber_stamp',
    decisionHash: '',
    finalAuthority: 'ai',
    aiFinalAuthority: true,
  };

  const denied = evaluateDecisionForumEscalationEngine(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.escalationEngine.trustState, 'inactive');
  assert.equal(denied.escalationEngine.decisionForumMatterCount, 5);
  assert.ok(denied.reasons.includes('escalation_signal_family_missing:enrollment_gate'));
  assert.ok(denied.reasons.includes('material_signal_route_missing:protocol_launch'));
  assert.ok(denied.reasons.includes('material_signal_requires_decision_forum_route:capa_closure'));
  assert.ok(denied.reasons.includes('route_evidence_bundle_hash_invalid:df-escalation-route-capa_closure'));
  assert.ok(denied.reasons.includes('route_rationale_hash_invalid:df-escalation-route-capa_closure'));
  assert.ok(denied.reasons.includes('route_governance_roles_absent:df-escalation-route-capa_closure'));
  assert.ok(denied.reasons.includes('human_reviewer_did_absent'));
  assert.ok(denied.reasons.includes('human_review_decision_invalid'));
  assert.ok(denied.reasons.includes('human_final_authority_missing'));
});

test('Decision Forum escalation engine keeps AI advisory and blocks production trust claims', async () => {
  const { evaluateDecisionForumEscalationEngine } = await loadDecisionForumEscalationEngine();

  const denied = evaluateDecisionForumEscalationEngine(
    escalationInput({
      actor: { did: 'did:exo:ai-routing-agent-alpha', kind: 'ai_agent', roleRefs: ['ai_assistant'] },
      escalationCycle: {
        exochainProductionClaim: true,
      },
      aiAssistance: {
        used: true,
        advisoryOnly: false,
        finalAuthority: true,
        recommendationHash: '',
        limitationHashes: ['bad'],
        reviewedByHuman: false,
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('ai_actor_cannot_escalate_final'));
  assert.ok(denied.reasons.includes('human_escalation_reviewer_required'));
  assert.ok(denied.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(denied.reasons.includes('ai_assistance_must_be_advisory'));
  assert.ok(denied.reasons.includes('ai_assistance_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_assistance_human_review_absent'));
});

test('Decision Forum escalation engine validates HLC route ordering', async () => {
  const { evaluateDecisionForumEscalationEngine } = await loadDecisionForumEscalationEngine();
  const input = escalationInput();
  input.escalationRoutes[0] = {
    ...input.escalationRoutes[0],
    routedAtHlc: { physicalMs: 1802000090000, logical: 0 },
  };
  input.escalationCycle.routesDeterminedAtHlc = { physicalMs: 1802000110000, logical: 0 };

  const denied = evaluateDecisionForumEscalationEngine(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('route_before_signal_detection:df-escalation-route-capa_closure'));
  assert.ok(denied.reasons.includes('routes_determined_before_signals_classified'));

  const sameTick = evaluateDecisionForumEscalationEngine(
    escalationInput({
      escalationSignals: [
        signalFor('capa_closure', 0, { detectedAtHlc: { physicalMs: 1802000100000, logical: 0 } }),
        ...REQUIRED_ESCALATION_FAMILIES.slice(1).map((family, index) => signalFor(family, index + 1)),
      ],
      escalationRoutes: [
        routeFor(signalFor('capa_closure', 0), 0, {
          routedAtHlc: { physicalMs: 1802000100000, logical: 1 },
        }),
        ...REQUIRED_ESCALATION_FAMILIES.slice(1).map((family, index) =>
          routeFor(signalFor(family, index + 1), index + 1),
        ),
      ],
    }),
  );

  assert.equal(sameTick.decision, 'permitted');
  assert.equal(sameTick.failClosed, false);
});

test('Decision Forum escalation engine rejects raw protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDecisionForumEscalationEngine } = await loadDecisionForumEscalationEngine();

  assert.throws(
    () =>
      evaluateDecisionForumEscalationEngine(
        escalationInput({
          escalationSignals: [
            signalFor('capa_closure', 0, {
              rawEscalationNarrative: 'patient name and source document text must stay out of receipts',
            }),
            ...REQUIRED_ESCALATION_FAMILIES.slice(1).map((family, index) => signalFor(family, index + 1)),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDecisionForumEscalationEngine(
        escalationInput({
          adapterToken: 'secret-token-value',
        }),
      ),
    /secret field is not allowed/iu,
  );
}
);
