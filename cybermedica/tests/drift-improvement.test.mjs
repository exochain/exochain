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
const DIGEST_7 = '7777777777777777777777777777777777777777777777777777777777777777';
const DIGEST_8 = '8888888888888888888888888888888888888888888888888888888888888888';
const DIGEST_9 = '9999999999999999999999999999999999999999999999999999999999999999';

const REQUIRED_SIGNAL_FAMILIES = [
  'ai_finding',
  'audit',
  'capa_trend',
  'concern',
  'consent_supersession',
  'deviation',
  'equipment_expiration',
  'evidence_aging',
  'protocol_amendment',
  'sponsor_expectation',
  'staff_change',
  'stakeholder_feedback',
  'training_gap',
];
const REQUIRED_INQUIRY_BACKLOG_SOURCE_FAMILIES = [
  'accessibility_barrier',
  'ai_orientation_question',
  'manual_confusion',
  'missing_documentation',
  'product_gap',
  'repeated_inquiry',
  'search_zero_result',
  'workflow_exit',
];
const REQUIRED_INQUIRY_BACKLOG_IMPROVEMENT_CATEGORIES = [
  'cqi_review',
  'documentation_update',
  'manual_crosslink_refresh',
  'system_change',
  'training_update',
  'workflow_change',
];

async function loadDriftImprovement() {
  try {
    return await import('../src/drift-improvement.mjs');
  } catch (error) {
    assert.fail(`CyberMedica drift improvement module must exist and load: ${error.message}`);
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

function signalFor(family, index, overrides = {}) {
  const materialFamilies = new Set([
    'consent_supersession',
    'deviation',
    'evidence_aging',
    'protocol_amendment',
    'sponsor_expectation',
  ]);
  return {
    signalRef: `signal-${family}`,
    signalFamily: family,
    sourceRef: `${family}-source-alpha`,
    sourceFamily: family,
    sourceHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    detectedAtHlc: { physicalMs: 1799100000000 + index, logical: 0 },
    affectedControlRefs: [`control-${family}`],
    riskLevel: materialFamilies.has(family) ? 'critical' : 'major',
    urgency: materialFamilies.has(family) ? 'urgent' : 'standard',
    participantSafetyImpact: ['consent_supersession', 'deviation', 'protocol_amendment'].includes(family),
    dataIntegrityImpact: ['evidence_aging', 'audit', 'ai_finding'].includes(family),
    sponsorCroImpact: ['sponsor_expectation', 'protocol_amendment', 'stakeholder_feedback'].includes(family),
    riskScoreBasisPoints: materialFamilies.has(family) ? 9100 : 5400,
    freshnessWindowExpired: ['evidence_aging', 'equipment_expiration', 'training_gap'].includes(family),
    humanVisible: true,
    reviewable: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function assignmentFor(signalRef, index, overrides = {}) {
  return {
    signalRef,
    ownerRoleRef: index % 2 === 0 ? 'quality_manager' : 'site_leader',
    ownerDidHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4][index % 4],
    assignedAtHlc: { physicalMs: 1799100100000, logical: index },
    acceptedAtHlc: { physicalMs: 1799100100000, logical: index + 1 },
    dueAtHlc: { physicalMs: 1799200000000 + index, logical: 0 },
    metadataOnly: true,
    ...overrides,
  };
}

function actionFor(actionRef, actionType, linkedSignalRefs, logical, overrides = {}) {
  return {
    actionRef,
    actionType,
    linkedSignalRefs,
    ownerRoleRef: actionType === 'capa' ? 'quality_manager' : 'site_leader',
    openedAtHlc: { physicalMs: 1799100300000, logical },
    implementedAtHlc: { physicalMs: 1799100400000, logical },
    implementationTrackingHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][logical % 6],
    effectivenessCheckHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6][logical % 6],
    effectivenessStatus: 'effective',
    effectivenessCheckedAtHlc: { physicalMs: 1799100500000, logical },
    stateUpdateTargets: ['passport', 'quality_state', 'readiness'],
    stateUpdateHash: [DIGEST_7, DIGEST_8, DIGEST_9, DIGEST_A, DIGEST_B, DIGEST_C][logical % 6],
    stateUpdatedAtHlc: { physicalMs: 1799100600000, logical },
    metadataOnly: true,
    ...overrides,
  };
}

function driftInput(overrides = {}) {
  const signals = REQUIRED_SIGNAL_FAMILIES.map((family, index) => signalFor(family, index));
  const signalRefs = signals.map((signal) => signal.signalRef);
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
      permissions: ['drift_manage', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    driftPolicy: {
      policyRef: 'drift-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredSignalFamilies: [...REQUIRED_SIGNAL_FAMILIES],
      allowedActionTypes: [
        'capa',
        'cqi',
        'documentation_update',
        'passport_update',
        'quality_state_update',
        'readiness_update',
        'risk_reassessment',
        'system_change',
        'training_update',
        'workflow_change',
      ],
      materialDecisionForumRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1799099900000, logical: 0 },
    },
    driftCycle: {
      cycleRef: 'drift-cycle-alpha',
      siteRef: 'site-alpha',
      studyRef: 'study-alpha',
      openedAtHlc: { physicalMs: 1799100000000, logical: 0 },
      classifiedAtHlc: { physicalMs: 1799100050000, logical: 0 },
      ownerAssignedAtHlc: { physicalMs: 1799100100000, logical: 0 },
      reviewPathIdentifiedAtHlc: { physicalMs: 1799100200000, logical: 0 },
      improvementCreatedAtHlc: { physicalMs: 1799100300000, logical: 0 },
      effectivenessCheckedAtHlc: { physicalMs: 1799100500000, logical: 0 },
      stateUpdatedAtHlc: { physicalMs: 1799100600000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1799100700000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      exochainProductionClaim: false,
    },
    signals,
    ownerAssignments: signalRefs.map((signalRef, index) => assignmentFor(signalRef, index)),
    reviewPath: {
      pathRef: 'drift-review-path-alpha',
      pathHash: DIGEST_C,
      requiredEvidenceRefs: ['evidence-aging-index-alpha', 'training-gap-index-alpha', 'audit-finding-index-alpha'],
      materialSignalRefs: [
        'signal-consent_supersession',
        'signal-deviation',
        'signal-evidence_aging',
        'signal-protocol_amendment',
        'signal-sponsor_expectation',
      ],
      decisionForumInvoked: true,
      decisionForumMatterRefs: ['decision-forum-drift-alpha'],
      participantSafetyReviewed: true,
      dataIntegrityReviewed: true,
      sponsorCroReviewed: true,
      reviewedAtHlc: { physicalMs: 1799100200000, logical: 1 },
      reviewerRoleRefs: ['quality_manager', 'principal_investigator', 'sponsor_liaison'],
      metadataOnly: true,
    },
    improvementActions: [
      actionFor('action-capa-safety', 'capa', [
        'signal-consent_supersession',
        'signal-deviation',
        'signal-protocol_amendment',
      ], 0),
      actionFor('action-cqi-evidence', 'cqi', [
        'signal-ai_finding',
        'signal-audit',
        'signal-capa_trend',
        'signal-evidence_aging',
      ], 1),
      actionFor('action-training-update', 'training_update', ['signal-staff_change', 'signal-training_gap'], 2),
      actionFor('action-system-change', 'system_change', [
        'signal-equipment_expiration',
        'signal-sponsor_expectation',
      ], 3),
      actionFor('action-documentation-update', 'documentation_update', [
        'signal-concern',
        'signal-stakeholder_feedback',
      ], 4),
      actionFor('action-readiness-update', 'readiness_update', signalRefs, 5),
    ],
    stateUpdate: {
      updateRef: 'drift-state-update-alpha',
      passportUpdated: true,
      readinessUpdated: true,
      qualityStateUpdated: true,
      updateReceiptHash: DIGEST_D,
      updatedAtHlc: { physicalMs: 1799100600000, logical: 6 },
      metadataOnly: true,
      cqiLineage: {
        cqiCycleId: 'cmcqi_documentation_friction_alpha',
        cqiCycleHash: DIGEST_6,
        cqiReceiptHash: DIGEST_7,
        cqiStatus: 'closed_effective',
        trustState: 'inactive',
        exochainProductionClaim: false,
        metadataOnly: true,
        protectedContentExcluded: true,
        inquiryCqiBacklogReceiptHash: DIGEST_8,
        inquiryCqiBacklogDigest: DIGEST_9,
        inquiryCqiBacklogSourceFamilies: REQUIRED_INQUIRY_BACKLOG_SOURCE_FAMILIES,
        inquiryCqiBacklogImprovementCategories: REQUIRED_INQUIRY_BACKLOG_IMPROVEMENT_CATEGORIES,
        inquiryCqiBacklogLinkedItemRefs: ['cqi-item-manual_confusion', 'cqi-item-search_zero_result'],
        driftSignalRefs: ['signal-concern', 'signal-stakeholder_feedback'],
        manualNavigationReady: true,
        manualNavigationEffectiveUseAcknowledged: true,
        manualNavigationCurrentVersionOnly: true,
        manualNavigationObsoleteVersionUseBlocked: true,
        roleManualCoverageReceiptHash: DIGEST_F,
        reviewedAtHlc: { physicalMs: 1799100550000, logical: 0 },
      },
    },
    auditRecord: {
      auditRecordRef: 'drift-audit-record-alpha',
      auditRecordHash: DIGEST_E,
      receiptRecordedAtHlc: { physicalMs: 1799100700000, logical: 0 },
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
  };
  return mergeDeep(base, overrides);
}

test('drift improvement loop turns stale quality signals into deterministic owned reviewable change', async () => {
  const { evaluateDriftImprovementLoop } = await loadDriftImprovement();

  const resultA = evaluateDriftImprovementLoop(driftInput());
  const resultB = evaluateDriftImprovementLoop(
    driftInput({
      signals: [...driftInput().signals].reverse(),
      improvementActions: [...driftInput().improvementActions].reverse(),
      driftPolicy: {
        requiredSignalFamilies: [...REQUIRED_SIGNAL_FAMILIES].reverse(),
      },
      stateUpdate: {
        cqiLineage: {
          inquiryCqiBacklogImprovementCategories: [...REQUIRED_INQUIRY_BACKLOG_IMPROVEMENT_CATEGORIES].reverse(),
          inquiryCqiBacklogLinkedItemRefs: ['cqi-item-search_zero_result', 'cqi-item-manual_confusion'],
          inquiryCqiBacklogSourceFamilies: [...REQUIRED_INQUIRY_BACKLOG_SOURCE_FAMILIES].reverse(),
          driftSignalRefs: ['signal-stakeholder_feedback', 'signal-concern'],
        },
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.driftLoop.loopId, resultB.driftLoop.loopId);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.driftLoop.trustState, 'inactive');
  assert.equal(resultA.driftLoop.exochainProductionClaim, false);
  assert.equal(resultA.driftLoop.metadataOnly, true);
  assert.deepEqual(resultA.driftLoop.signalFamilies, REQUIRED_SIGNAL_FAMILIES);
  assert.deepEqual(resultA.driftLoop.materialSignalRefs, [
    'signal-consent_supersession',
    'signal-deviation',
    'signal-evidence_aging',
    'signal-protocol_amendment',
    'signal-sponsor_expectation',
  ]);
  assert.deepEqual(resultA.driftLoop.improvementActionTypes, [
    'capa',
    'cqi',
    'documentation_update',
    'readiness_update',
    'system_change',
    'training_update',
  ]);
  assert.deepEqual(resultA.driftLoop.stateUpdateTargets, ['passport', 'quality_state', 'readiness']);
  assert.equal(resultA.driftLoop.ownerCoverage.signalCount, REQUIRED_SIGNAL_FAMILIES.length);
  assert.equal(resultA.driftLoop.ownerCoverage.allSignalsOwned, true);
  assert.equal(resultA.driftLoop.decisionForumRequired, true);
  assert.equal(resultA.driftLoop.decisionForumInvoked, true);
  assert.equal(resultA.driftLoop.effectivenessChecked, true);
  assert.deepEqual(resultA.driftLoop.stateUpdateEvidence, {
    cqiBacklogDriftSignalRefs: ['signal-concern', 'signal-stakeholder_feedback'],
    cqiCycleHash: DIGEST_6,
    cqiCycleId: 'cmcqi_documentation_friction_alpha',
    cqiCycleReceiptHash: DIGEST_7,
    inquiryCqiBacklogDigest: DIGEST_9,
    inquiryCqiBacklogImprovementCategories: REQUIRED_INQUIRY_BACKLOG_IMPROVEMENT_CATEGORIES,
    inquiryCqiBacklogReceiptHash: DIGEST_8,
    inquiryCqiBacklogSourceFamilies: REQUIRED_INQUIRY_BACKLOG_SOURCE_FAMILIES,
    manualNavigationEffectiveUseAcknowledged: true,
    manualNavigationReady: true,
    roleManualCoverageReceiptHash: DIGEST_F,
    stateUpdateHash: DIGEST_D,
    stateUpdateTargets: ['passport', 'quality_state', 'readiness'],
  });
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'drift_improvement_loop');
  assert.deepEqual(resultA.receipt.anchorPayload.sensitivityTags, [
    'continuous_quality_improvement',
    'drift_management',
    'inquiry_cqi_backlog',
    'manual_navigation_readiness',
    'metadata_only',
  ]);
});

test('drift improvement loop fails closed for missing signal coverage ownership and state updates', async () => {
  const { evaluateDriftImprovementLoop } = await loadDriftImprovement();

  const input = driftInput({
    signals: driftInput().signals.filter((signal) => signal.signalFamily !== 'training_gap'),
    ownerAssignments: driftInput().ownerAssignments.filter((assignment) => assignment.signalRef !== 'signal-staff_change'),
    stateUpdate: {
      readinessUpdated: false,
      updateReceiptHash: 'not-a-digest',
    },
  });

  const result = evaluateDriftImprovementLoop(input);

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.deepEqual(result.reasons, [
    'drift_signal_action_absent:signal-training_gap',
    'drift_signal_family_missing:training_gap',
    'drift_signal_owner_absent:signal-staff_change',
    'state_update_readiness_absent',
    'state_update_receipt_hash_invalid',
  ]);
  assert.equal(result.driftLoop, undefined);
  assert.equal(result.receipt, undefined);
});

test('drift improvement loop requires CQI backlog and manual-navigation lineage before state update', async () => {
  const { evaluateDriftImprovementLoop } = await loadDriftImprovement();

  const result = evaluateDriftImprovementLoop(
    driftInput({
      stateUpdate: {
        cqiLineage: {
          cqiCycleHash: 'bad',
          cqiReceiptHash: '',
          cqiStatus: 'open',
          trustState: 'verified',
          exochainProductionClaim: true,
          metadataOnly: false,
          protectedContentExcluded: false,
          inquiryCqiBacklogReceiptHash: 'bad',
          inquiryCqiBacklogDigest: '',
          inquiryCqiBacklogSourceFamilies: ['manual_confusion'],
          inquiryCqiBacklogImprovementCategories: ['cqi_review'],
          inquiryCqiBacklogLinkedItemRefs: [],
          driftSignalRefs: ['missing-drift-signal'],
          manualNavigationReady: false,
          manualNavigationEffectiveUseAcknowledged: false,
          manualNavigationCurrentVersionOnly: false,
          manualNavigationObsoleteVersionUseBlocked: false,
          roleManualCoverageReceiptHash: 'bad',
          reviewedAtHlc: { physicalMs: 1799100700000, logical: 0 },
        },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('cqi_cycle_hash_invalid'));
  assert.ok(result.reasons.includes('cqi_cycle_receipt_hash_invalid'));
  assert.ok(result.reasons.includes('cqi_cycle_status_invalid'));
  assert.ok(result.reasons.includes('cqi_cycle_trust_state_invalid'));
  assert.ok(result.reasons.includes('cqi_cycle_production_claim_forbidden'));
  assert.ok(result.reasons.includes('cqi_cycle_metadata_boundary_invalid'));
  assert.ok(result.reasons.includes('cqi_cycle_protected_boundary_invalid'));
  assert.ok(result.reasons.includes('cqi_inquiry_backlog_receipt_hash_invalid'));
  assert.ok(result.reasons.includes('cqi_inquiry_backlog_digest_invalid'));
  assert.ok(result.reasons.includes('cqi_inquiry_backlog_source_family_missing:accessibility_barrier'));
  assert.ok(result.reasons.includes('cqi_inquiry_backlog_improvement_category_missing:documentation_update'));
  assert.ok(result.reasons.includes('cqi_inquiry_backlog_item_refs_absent'));
  assert.ok(result.reasons.includes('cqi_lineage_drift_signal_missing:missing-drift-signal'));
  assert.ok(result.reasons.includes('cqi_manual_navigation_ready_absent'));
  assert.ok(result.reasons.includes('cqi_manual_navigation_effective_use_absent'));
  assert.ok(result.reasons.includes('cqi_manual_navigation_current_version_boundary_invalid'));
  assert.ok(result.reasons.includes('cqi_manual_navigation_obsolete_version_boundary_invalid'));
  assert.ok(result.reasons.includes('cqi_role_manual_coverage_receipt_hash_invalid'));
  assert.ok(result.reasons.includes('cqi_lineage_review_after_state_update'));
  assert.equal(result.driftLoop, undefined);
  assert.equal(result.receipt, undefined);
});

test('material drift requires Decision Forum review and AI remains advisory only', async () => {
  const { evaluateDriftImprovementLoop } = await loadDriftImprovement();

  const result = evaluateDriftImprovementLoop(
    driftInput({
      reviewPath: {
        decisionForumInvoked: false,
        decisionForumMatterRefs: [],
        materialSignalRefs: ['signal-deviation'],
        participantSafetyReviewed: false,
      },
      aiAssistance: {
        finalAuthority: true,
        reviewedByHuman: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('ai_human_review_absent'));
  assert.ok(result.reasons.includes('material_decision_forum_absent'));
  assert.ok(result.reasons.includes('participant_safety_review_absent'));
  assert.ok(result.reasons.includes('material_signal_review_absent:signal-consent_supersession'));
  assert.ok(result.reasons.includes('material_signal_review_absent:signal-evidence_aging'));
});

test('drift improvement loop enforces HLC ordering including same-tick logical clocks', async () => {
  const { evaluateDriftImprovementLoop } = await loadDriftImprovement();

  const sameTick = evaluateDriftImprovementLoop(
    driftInput({
      driftCycle: {
        openedAtHlc: { physicalMs: 1799100000000, logical: 0 },
        classifiedAtHlc: { physicalMs: 1799100000000, logical: 1 },
        ownerAssignedAtHlc: { physicalMs: 1799100000000, logical: 2 },
        reviewPathIdentifiedAtHlc: { physicalMs: 1799100000000, logical: 3 },
        improvementCreatedAtHlc: { physicalMs: 1799100000000, logical: 4 },
        effectivenessCheckedAtHlc: { physicalMs: 1799100000000, logical: 5 },
        stateUpdatedAtHlc: { physicalMs: 1799100000000, logical: 6 },
        auditRecordedAtHlc: { physicalMs: 1799100000000, logical: 7 },
      },
      reviewPath: {
        reviewedAtHlc: { physicalMs: 1799100000000, logical: 3 },
      },
      stateUpdate: {
        updatedAtHlc: { physicalMs: 1799100000000, logical: 6 },
        cqiLineage: {
          reviewedAtHlc: { physicalMs: 1799100000000, logical: 5 },
        },
      },
      auditRecord: {
        receiptRecordedAtHlc: { physicalMs: 1799100000000, logical: 7 },
      },
    }),
  );
  assert.equal(sameTick.decision, 'permitted');

  const invalid = evaluateDriftImprovementLoop(
    driftInput({
      improvementActions: [
        actionFor('action-bad-clock', 'capa', ['signal-deviation'], 0, {
          implementedAtHlc: { physicalMs: 1799100200000, logical: 0 },
          stateUpdatedAtHlc: { physicalMs: 1799100400000, logical: 0 },
        }),
      ],
    }),
  );

  assert.equal(invalid.decision, 'denied');
  assert.ok(invalid.reasons.includes('drift_action_implemented_before_opened:action-bad-clock'));
  assert.ok(invalid.reasons.includes('drift_action_state_update_before_effectiveness:action-bad-clock'));
});

test('drift improvement loop handles absent collections malformed HLC and no AI operation', async () => {
  const { evaluateDriftImprovementLoop } = await loadDriftImprovement();

  const result = evaluateDriftImprovementLoop(
    driftInput({
      driftCycle: {
        openedAtHlc: { physicalMs: 'bad-clock', logical: 0 },
      },
      signals: null,
      ownerAssignments: null,
      improvementActions: null,
      aiAssistance: {
        used: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('drift_signals_absent'));
  assert.ok(result.reasons.includes('drift_owner_assignments_absent'));
  assert.ok(result.reasons.includes('drift_actions_absent'));
  assert.ok(result.reasons.includes('drift_cycle_openedAtHlc_invalid'));

  const inert = driftInput({
    aiAssistance: {
      used: false,
    },
    reviewPath: {
      accessToken: false,
    },
  });
  inert.signals[0] = {
    ...inert.signals[0],
    rawDriftNarrative: false,
  };

  assert.equal(evaluateDriftImprovementLoop(inert).decision, 'permitted');
});

test('drift improvement loop rejects raw drift content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateDriftImprovementLoop } = await loadDriftImprovement();

  assert.throws(
    () =>
      evaluateDriftImprovementLoop(
        driftInput({
          signals: [
            signalFor('evidence_aging', 0, {
              rawDriftNarrative: 'stale evidence details belong outside CyberMedica anchors',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDriftImprovementLoop(
        driftInput({
          reviewPath: {
            accessToken: DIGEST_A,
          },
        }),
    ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDriftImprovementLoop(
        driftInput({
          signals: [
            signalFor('evidence_aging', 0, {
              rawSignal: ['metadata references only'],
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDriftImprovementLoop(
        driftInput({
          reviewPath: {
            accessToken: {
              digest: DIGEST_A,
            },
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateDriftImprovementLoop(
        driftInput({
          reviewPath: {
            token: 7,
          },
        }),
      ),
    ProtectedContentError,
  );
});
