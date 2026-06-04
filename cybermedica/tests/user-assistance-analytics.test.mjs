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

const REQUIRED_NAVIGATION_STATES = [
  'administrator_runbook_linkage',
  'ai_orientation_prompt',
  'audit_inspector_help',
  'contextual_manual_drawer',
  'cqi_inquiry_capture',
  'evidence_checklist_guidance',
  'role_manual_entrypoint',
  'workflow_step_help',
];

const REQUIRED_FRICTION_FAMILIES = [
  'accessibility_barrier',
  'ai_confidence_low',
  'checklist_blocker',
  'manual_dead_end',
  'policy_crosslink_gap',
  'repeated_inquiry',
  'search_zero_result',
  'workflow_exit',
];

async function loadUserAssistanceAnalytics() {
  try {
    return await import('../src/user-assistance-analytics.mjs');
  } catch (error) {
    assert.fail(`CyberMedica user assistance analytics module must exist and load: ${error.message}`);
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

function navigationState(stateFamily, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2];
  return {
    stateRef: `nav-${stateFamily}`,
    stateFamily,
    roleRef: index % 2 === 0 ? 'quality_manager' : 'clinical_research_coordinator',
    manualRef: `manual-${stateFamily}`,
    manualVersionRef: `manual-${stateFamily}-v1`,
    entrypointHash: hashes[index],
    targetArtifactHash: [DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_7, DIGEST_8, DIGEST_9, DIGEST_A][index],
    successfulNavigationCount: 20 + index,
    blockedNavigationCount: index % 3 === 0 ? 3 : 1,
    totalNavigationCount: 25 + index,
    completionBasisPoints: index % 3 === 0 ? 7600 : 9200,
    lastUpdatedAtHlc: { physicalMs: 1800006100000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function navigationStates() {
  return REQUIRED_NAVIGATION_STATES.map((stateFamily, index) =>
    navigationState(
      stateFamily,
      index,
      stateFamily === 'contextual_manual_drawer' ? { targetArtifactHash: DIGEST_8 } : {},
    ),
  );
}

function frictionSignal(signalFamily, index, overrides = {}) {
  const materialFamilies = new Set(['accessibility_barrier', 'checklist_blocker', 'policy_crosslink_gap']);
  return {
    signalRef: `friction-${signalFamily}`,
    signalFamily,
    sourceNavigationRef: `nav-${REQUIRED_NAVIGATION_STATES[index]}`,
    signalHash: [DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3][index],
    eventCount: materialFamilies.has(signalFamily) ? 8 : 3,
    affectedRoleRefs: index % 2 === 0 ? ['quality_manager'] : ['clinical_research_coordinator'],
    severity: materialFamilies.has(signalFamily) ? 'major' : 'minor',
    requiresCqi: materialFamilies.has(signalFamily),
    detectedAtHlc: { physicalMs: 1800006200000, logical: index },
    participantLinked: false,
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function frictionSignals() {
  return REQUIRED_FRICTION_FAMILIES.map((signalFamily, index) => frictionSignal(signalFamily, index));
}

function assistanceInput(overrides = {}) {
  const signals = frictionSignals();
  const routedSignalRefs = signals.filter((signal) => signal.requiresCqi).map((signal) => signal.signalRef);
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:documentation-analytics-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'administrator'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['user_assistance_review', 'drift_manage'],
      authorityChainHash: DIGEST_A,
    },
    assistancePolicy: {
      policyRef: 'user-assistance-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredNavigationStates: REQUIRED_NAVIGATION_STATES,
      requiredFrictionFamilies: REQUIRED_FRICTION_FAMILIES,
      cqiThresholdBasisPoints: 500,
      manualVersionGovernanceRequired: true,
      aiAssistanceAdvisoryOnly: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800006000000, logical: 0 },
    },
    assistanceCycle: {
      cycleRef: 'user-assistance-cycle-alpha',
      openedAtHlc: { physicalMs: 1800006050000, logical: 0 },
      navigationCapturedAtHlc: { physicalMs: 1800006100000, logical: 0 },
      frictionAnalyzedAtHlc: { physicalMs: 1800006200000, logical: 0 },
      cqiRoutedAtHlc: { physicalMs: 1800006300000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800006400000, logical: 0 },
      receiptRecordedAtHlc: { physicalMs: 1800006500000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    manualIndex: {
      documentationReadinessRef: 'documentation-runbook-cycle-alpha',
      documentationRunbookReceiptHash: DIGEST_C,
      currentManualSetHash: DIGEST_D,
      crosslinkMatrixHash: DIGEST_E,
      versionGovernanceHash: DIGEST_F,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800006080000, logical: 0 },
    },
    manualNavigationReadiness: {
      contextualManualDrawerReceiptHash: DIGEST_7,
      contextualManualDrawerHash: DIGEST_8,
      controlledDocumentDistributionRecordId: 'cmdist-role-manual-navigation-v1',
      controlledDocumentDistributionReceiptHash: DIGEST_9,
      documentationPublicationReceiptHash: DIGEST_A,
      manualExportReceiptHash: DIGEST_B,
      roleManualCoverageReceiptHash: DIGEST_C,
      acknowledgementRosterHash: DIGEST_D,
      requiredAcknowledgementRoleRefs: ['clinical_research_coordinator', 'quality_manager'],
      acknowledgedRoleRefs: ['clinical_research_coordinator', 'quality_manager'],
      distributionPublishedAtHlc: { physicalMs: 1800006090000, logical: 0 },
      effectiveUseAcknowledged: true,
      currentVersionOnly: true,
      obsoleteVersionUseBlocked: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    navigationStates: navigationStates(),
    frictionSignals: signals,
    cqiRouting: {
      routeRef: 'user-assistance-cqi-route-alpha',
      destination: 'drift_improvement',
      qualityOwnerRoleRef: 'quality_manager',
      routedSignalRefs,
      frictionTagSetHash: DIGEST_1,
      cqiActionPolicyHash: DIGEST_2,
      noRetaliationReminderHash: DIGEST_3,
      permitsAnonymousInquiry: true,
      routedAtHlc: { physicalMs: 1800006300000, logical: 1 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    accessibilityReview: {
      reviewRef: 'manual-navigation-accessibility-alpha',
      reviewHash: DIGEST_4,
      keyboardNavigationVerified: true,
      screenReaderNavigationVerified: true,
      statusIndicatorsVerified: true,
      roleSpecificNavigationVerified: true,
      reviewedAtHlc: { physicalMs: 1800006350000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    aiAssistant: {
      used: true,
      assistantRef: 'manual-assistance-ai-alpha',
      promptPolicyHash: DIGEST_5,
      outputHash: DIGEST_6,
      limitationHashes: [DIGEST_7],
      unresolvedQuestionRoutingHash: DIGEST_8,
      confidenceFloorBasisPoints: 8000,
      advisoryOnly: true,
      finalAuthority: false,
      humanReviewed: true,
      reviewedAtHlc: { physicalMs: 1800006360000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-director-alpha',
      reviewerRoleRefs: ['quality_manager', 'administrator'],
      decision: 'assistance_analytics_ready',
      decisionHash: DIGEST_9,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1800006400000, logical: 1 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_A,
  };
  return mergeDeep(base, overrides);
}

test('user assistance analytics creates deterministic inactive navigation and friction receipts', async () => {
  const { evaluateUserAssistanceAnalytics } = await loadUserAssistanceAnalytics();

  const resultA = evaluateUserAssistanceAnalytics(assistanceInput());
  const resultB = evaluateUserAssistanceAnalytics(
    assistanceInput({
      assistancePolicy: {
        requiredNavigationStates: [...REQUIRED_NAVIGATION_STATES].reverse(),
        requiredFrictionFamilies: [...REQUIRED_FRICTION_FAMILIES].reverse(),
      },
      navigationStates: [...navigationStates()].reverse(),
      frictionSignals: [...frictionSignals()].reverse(),
      cqiRouting: {
        routedSignalRefs: [...assistanceInput().cqiRouting.routedSignalRefs].reverse(),
      },
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.assistanceAnalytics.ready, true);
  assert.equal(resultA.assistanceAnalytics.trustState, 'inactive');
  assert.equal(resultA.assistanceAnalytics.exochainProductionClaim, false);
  assert.deepEqual(resultA.assistanceAnalytics.navigationFamilies, REQUIRED_NAVIGATION_STATES);
  assert.deepEqual(resultA.assistanceAnalytics.frictionFamilies, REQUIRED_FRICTION_FAMILIES);
  assert.deepEqual(resultA.assistanceAnalytics.cqiRoutedSignalRefs, [
    'friction-accessibility_barrier',
    'friction-checklist_blocker',
    'friction-policy_crosslink_gap',
  ]);
  assert.equal(resultA.assistanceAnalytics.frictionRateBasisPoints, 1710);
  assert.equal(resultA.assistanceAnalytics.manualNavigationReady, true);
  assert.equal(resultA.assistanceAnalytics.contextualManualDrawerReceiptHash, DIGEST_7);
  assert.equal(resultA.assistanceAnalytics.controlledDocumentDistributionReceiptHash, DIGEST_9);
  assert.equal(resultA.assistanceAnalytics.roleManualCoverageReceiptHash, DIGEST_C);
  assert.deepEqual(resultA.assistanceAnalytics.manualNavigationAcknowledgedRoleRefs, [
    'clinical_research_coordinator',
    'quality_manager',
  ]);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'user_assistance_friction_analytics');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.equal(resultA.receipt.containsProtectedContent, false);
  assert.deepEqual(resultA, resultB);
  assert.doesNotMatch(JSON.stringify(resultA), /manual body|help query|participant alice|raw text|secret/iu);
});

test('user assistance analytics requires contextual manual drawer and effective-use readiness', async () => {
  const { evaluateUserAssistanceAnalytics } = await loadUserAssistanceAnalytics();

  const missingReadiness = evaluateUserAssistanceAnalytics(
    assistanceInput({
      manualNavigationReadiness: null,
    }),
  );
  const unsafeReadiness = evaluateUserAssistanceAnalytics(
    assistanceInput({
      manualNavigationReadiness: {
        contextualManualDrawerReceiptHash: '',
        contextualManualDrawerHash: 'not-a-digest',
        controlledDocumentDistributionRecordId: '',
        controlledDocumentDistributionReceiptHash: null,
        documentationPublicationReceiptHash: 'bad',
        manualExportReceiptHash: '',
        roleManualCoverageReceiptHash: null,
        acknowledgementRosterHash: '',
        requiredAcknowledgementRoleRefs: ['quality_manager', 'principal_investigator'],
        acknowledgedRoleRefs: ['quality_manager'],
        distributionPublishedAtHlc: { physicalMs: 1800006110000, logical: 0 },
        effectiveUseAcknowledged: false,
        currentVersionOnly: false,
        obsoleteVersionUseBlocked: false,
        metadataOnly: false,
        protectedContentExcluded: false,
        productionTrustClaim: true,
      },
      navigationStates: navigationStates().map((state) =>
        state.stateFamily === 'contextual_manual_drawer' ? { ...state, targetArtifactHash: DIGEST_1 } : state,
      ),
    }),
  );

  assert.equal(missingReadiness.decision, 'denied');
  assert.equal(missingReadiness.receipt, null);
  assert.ok(missingReadiness.reasons.includes('manual_navigation_drawer_receipt_hash_invalid'));
  assert.ok(missingReadiness.reasons.includes('manual_navigation_drawer_hash_invalid'));
  assert.ok(missingReadiness.reasons.includes('manual_navigation_distribution_receipt_hash_invalid'));
  assert.ok(missingReadiness.reasons.includes('manual_navigation_effective_use_acknowledgement_absent'));

  assert.equal(unsafeReadiness.decision, 'denied');
  assert.equal(unsafeReadiness.receipt, null);
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_drawer_receipt_hash_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_drawer_hash_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_distribution_record_absent'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_publication_receipt_hash_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_manual_export_receipt_hash_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_role_manual_coverage_receipt_hash_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_acknowledgement_roster_hash_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_acknowledgement_roles_incomplete'));
  assert.ok(
    unsafeReadiness.reasons.includes(
      'manual_navigation_role_effective_use_acknowledgement_missing:clinical_research_coordinator',
    ),
  );
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_effective_use_acknowledgement_absent'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_current_version_boundary_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_obsolete_version_boundary_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_metadata_boundary_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_protected_boundary_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_production_claim_forbidden'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_distribution_after_capture'));
  assert.ok(unsafeReadiness.reasons.includes('manual_navigation_contextual_drawer_target_mismatch:nav-contextual_manual_drawer'));
});

test('user assistance analytics fails closed for missing navigation and friction coverage', async () => {
  const { evaluateUserAssistanceAnalytics } = await loadUserAssistanceAnalytics();

  const result = evaluateUserAssistanceAnalytics(
    assistanceInput({
      assistancePolicy: {
        requiredNavigationStates: REQUIRED_NAVIGATION_STATES.filter((state) => state !== 'workflow_step_help'),
        requiredFrictionFamilies: REQUIRED_FRICTION_FAMILIES.filter((family) => family !== 'workflow_exit'),
      },
      manualIndex: {
        metadataOnly: false,
        documentationRunbookReceiptHash: '',
      },
      navigationStates: navigationStates().filter((state) => state.stateFamily !== 'contextual_manual_drawer'),
      frictionSignals: frictionSignals().filter((signal) => signal.signalFamily !== 'search_zero_result'),
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('policy_navigation_state_missing:workflow_step_help'));
  assert.ok(result.reasons.includes('policy_friction_family_missing:workflow_exit'));
  assert.ok(result.reasons.includes('navigation_state_missing:contextual_manual_drawer'));
  assert.ok(result.reasons.includes('friction_family_missing:search_zero_result'));
  assert.ok(result.reasons.includes('manual_index_receipt_hash_invalid'));
  assert.ok(result.reasons.includes('manual_index_metadata_boundary_invalid'));
});

test('user assistance analytics requires CQI routing accessibility proof and advisory AI only', async () => {
  const { evaluateUserAssistanceAnalytics } = await loadUserAssistanceAnalytics();

  const result = evaluateUserAssistanceAnalytics(
    assistanceInput({
      cqiRouting: {
        destination: 'manual_backlog_only',
        routedSignalRefs: ['friction-accessibility_barrier'],
        cqiActionPolicyHash: '',
        permitsAnonymousInquiry: false,
      },
      accessibilityReview: {
        keyboardNavigationVerified: false,
        screenReaderNavigationVerified: false,
        reviewHash: '',
      },
      aiAssistant: {
        finalAuthority: true,
        advisoryOnly: false,
        humanReviewed: false,
        confidenceFloorBasisPoints: 10_001,
        outputHash: '',
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('cqi_destination_invalid'));
  assert.ok(result.reasons.includes('cqi_action_policy_hash_invalid'));
  assert.ok(result.reasons.includes('cqi_anonymous_route_missing'));
  assert.ok(result.reasons.includes('cqi_route_missing_required_signal:friction-checklist_blocker'));
  assert.ok(result.reasons.includes('cqi_route_missing_required_signal:friction-policy_crosslink_gap'));
  assert.ok(result.reasons.includes('accessibility_review_hash_invalid'));
  assert.ok(result.reasons.includes('accessibility_keyboard_navigation_missing'));
  assert.ok(result.reasons.includes('accessibility_screen_reader_navigation_missing'));
  assert.ok(result.reasons.includes('ai_assistance_final_authority_forbidden'));
  assert.ok(result.reasons.includes('ai_assistance_not_advisory'));
  assert.ok(result.reasons.includes('ai_assistance_human_review_absent'));
  assert.ok(result.reasons.includes('ai_assistance_output_hash_invalid'));
  assert.ok(result.reasons.includes('ai_assistance_confidence_floor_invalid'));
});

test('user assistance analytics validates HLC ordering absent objects and no-AI operation', async () => {
  const { evaluateUserAssistanceAnalytics } = await loadUserAssistanceAnalytics();

  const absent = evaluateUserAssistanceAnalytics({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:documentation-analytics-owner-alpha', kind: 'human' },
    authority: { valid: true, permissions: ['user_assistance_review'], authorityChainHash: DIGEST_A },
  });
  assert.equal(absent.decision, 'denied');
  assert.ok(absent.reasons.includes('assistance_policy_ref_absent'));
  assert.ok(absent.reasons.includes('assistance_cycle_ref_absent'));
  assert.ok(absent.reasons.includes('manual_index_ref_absent'));
  assert.ok(absent.reasons.includes('accessibility_review_ref_absent'));
  assert.ok(absent.reasons.includes('human_reviewer_absent'));

  const noAi = evaluateUserAssistanceAnalytics(assistanceInput({ aiAssistant: { used: false } }));
  assert.equal(noAi.decision, 'permitted');
  assert.equal(noAi.assistanceAnalytics.aiAssistanceUsed, false);

  const inertSensitiveMarkers = evaluateUserAssistanceAnalytics(
    assistanceInput({
      navigationStates: navigationStates().map((state) =>
        state.stateFamily === 'contextual_manual_drawer' ? { ...state, rawHelpText: false } : state,
      ),
      aiAssistant: { ...assistanceInput().aiAssistant, token: null },
    }),
  );
  assert.equal(inertSensitiveMarkers.decision, 'permitted');

  const denied = evaluateUserAssistanceAnalytics(
    assistanceInput({
      assistancePolicy: { evaluatedAtHlc: { physicalMs: 1800006060000, logical: 0 } },
      assistanceCycle: {
        openedAtHlc: { physicalMs: 1800006050000, logical: -1 },
        frictionAnalyzedAtHlc: { physicalMs: 1800006090000, logical: 0 },
        receiptRecordedAtHlc: { physicalMs: 1800006390000, logical: 0 },
      },
      humanReview: { reviewedAtHlc: { physicalMs: 1800006400000, logical: 0 } },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('assistance_cycle_open_time_invalid'));
  assert.ok(denied.reasons.includes('navigation_capture_before_open'));
  assert.ok(denied.reasons.includes('friction_analysis_before_navigation_capture'));
  assert.ok(denied.reasons.includes('receipt_recorded_before_human_review'));
});

test('user assistance analytics rejects raw help content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateUserAssistanceAnalytics } = await loadUserAssistanceAnalytics();

  assert.throws(
    () =>
      evaluateUserAssistanceAnalytics(
        assistanceInput({
          navigationStates: [
            navigationState('contextual_manual_drawer', 0, {
              rawHelpText: 'Manual body and help query stay in controlled documentation storage only.',
            }),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateUserAssistanceAnalytics(
        assistanceInput({
          frictionSignals: [
            frictionSignal('manual_dead_end', 0, {
              helpQuery: 'participant Alice could not find the consent form',
            }),
          ],
        }),
      ),
    /raw user assistance content|protected content/i,
  );

  assert.throws(
    () =>
      evaluateUserAssistanceAnalytics(
        assistanceInput({
          aiAssistant: {
            used: true,
            token: ['secret-runtime-token'],
          },
        }),
      ),
    /secret/i,
  );

  assert.throws(
    () =>
      evaluateUserAssistanceAnalytics(
        assistanceInput({
          accessibilityReview: {
            ...assistanceInput().accessibilityReview,
            rawHelpText: { source: 'manual-navigation-body' },
          },
        }),
      ),
    /raw user assistance content/i,
  );

  assert.throws(
    () =>
      evaluateUserAssistanceAnalytics(
        assistanceInput({
          cqiRouting: {
            ...assistanceInput().cqiRouting,
            token: 7,
          },
        }),
      ),
    /secret/i,
  );
});
