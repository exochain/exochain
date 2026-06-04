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

const REQUIRED_SOURCE_FAMILIES = [
  'accessibility_barrier',
  'ai_orientation_question',
  'manual_confusion',
  'missing_documentation',
  'product_gap',
  'repeated_inquiry',
  'search_zero_result',
  'workflow_exit',
];

const REQUIRED_CATEGORIES = [
  'cqi_review',
  'documentation_update',
  'manual_crosslink_refresh',
  'system_change',
  'training_update',
  'workflow_change',
];

async function loadInquiryCqiBacklog() {
  try {
    return await import('../src/inquiry-cqi-backlog.mjs');
  } catch (error) {
    assert.fail(`CyberMedica inquiry-to-CQI backlog module must exist and load: ${error.message}`);
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

function inquirySignal(sourceFamily, index, overrides = {}) {
  const categoryByFamily = {
    accessibility_barrier: 'system_change',
    ai_orientation_question: 'cqi_review',
    manual_confusion: 'documentation_update',
    missing_documentation: 'documentation_update',
    product_gap: 'workflow_change',
    repeated_inquiry: 'training_update',
    search_zero_result: 'manual_crosslink_refresh',
    workflow_exit: 'workflow_change',
  };
  const severeFamilies = new Set(['accessibility_barrier', 'missing_documentation', 'product_gap', 'workflow_exit']);
  return {
    signalRef: `inquiry-${sourceFamily}`,
    sourceFamily,
    sourceSignalHash: [DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3][index],
    roleRef: index % 2 === 0 ? 'quality_manager' : 'clinical_research_coordinator',
    manualSectionRef: `manual-section-${sourceFamily}`,
    workflowRef: `workflow-${sourceFamily}`,
    suggestedImprovementCategory: categoryByFamily[sourceFamily],
    eventCount: severeFamilies.has(sourceFamily) ? 9 : 3,
    affectedRoleRefs: index % 2 === 0 ? ['quality_manager'] : ['clinical_research_coordinator'],
    severity: severeFamilies.has(sourceFamily) ? 'major' : 'minor',
    highRiskContent: sourceFamily === 'missing_documentation',
    requiresCqi: true,
    capturedAtHlc: { physicalMs: 1800007100000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function inquirySignals() {
  return REQUIRED_SOURCE_FAMILIES.map((sourceFamily, index) => inquirySignal(sourceFamily, index));
}

function backlogItem(signal, index, overrides = {}) {
  return {
    backlogItemRef: `cqi-item-${signal.sourceFamily}`,
    sourceSignalRef: signal.signalRef,
    priority: signal.severity === 'major' ? 'high' : 'standard',
    ownerRoleRef: signal.sourceFamily === 'accessibility_barrier' ? 'system_admin' : 'quality_manager',
    triageDisposition: signal.highRiskContent ? 'hold_for_high_risk_review' : 'open_for_cqi',
    improvementCategory: signal.suggestedImprovementCategory,
    requiredReviewRoleRefs: signal.highRiskContent ? ['quality_manager', 'regulatory_reviewer'] : ['quality_manager'],
    linkedDocumentationSectionHash: [DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_7, DIGEST_8, DIGEST_9, DIGEST_A, DIGEST_B][index],
    noRetaliationReminderHash: [DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_7, DIGEST_8][index],
    dueAtHlc: { physicalMs: 1800007500000, logical: index },
    triagedAtHlc: { physicalMs: 1800007300000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function backlogItems(signals) {
  return signals.map((signal, index) => backlogItem(signal, index));
}

function backlogInput(overrides = {}) {
  const signals = inquirySignals();
  const items = backlogItems(signals);
  const linkedBacklogItemRefs = items.map((item) => item.backlogItemRef);
  return mergeDeep(
    {
      tenantId: 'tenant-site-alpha',
      targetTenantId: 'tenant-site-alpha',
      actor: {
        did: 'did:exo:documentation-cqi-owner-alpha',
        kind: 'human',
        roleRefs: ['quality_manager', 'administrator'],
      },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['cqi_triage', 'drift_manage'],
        authorityChainHash: DIGEST_A,
      },
      backlogPolicy: {
        policyRef: 'inquiry-cqi-policy-alpha',
        policyHash: DIGEST_B,
        status: 'active',
        requiredSourceFamilies: REQUIRED_SOURCE_FAMILIES,
        allowedImprovementCategories: REQUIRED_CATEGORIES,
        highRiskReviewRequired: true,
        documentationVersionGovernanceRequired: true,
        driftRoutingRequired: true,
        aiAssistanceAdvisoryOnly: true,
        metadataOnly: true,
        protectedContentExcluded: true,
        evaluatedAtHlc: { physicalMs: 1800007000000, logical: 0 },
      },
      backlogCycle: {
        cycleRef: 'inquiry-cqi-cycle-alpha',
        openedAtHlc: { physicalMs: 1800007050000, logical: 0 },
        signalsCapturedAtHlc: { physicalMs: 1800007100000, logical: 0 },
        triagedAtHlc: { physicalMs: 1800007300000, logical: 0 },
        ownerAssignedAtHlc: { physicalMs: 1800007400000, logical: 0 },
        actionPackagedAtHlc: { physicalMs: 1800007600000, logical: 0 },
        humanReviewedAtHlc: { physicalMs: 1800007700000, logical: 0 },
        auditRecordedAtHlc: { physicalMs: 1800007800000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
        productionTrustClaim: false,
      },
      sourceAnalytics: {
        userAssistanceReceiptHash: DIGEST_C,
        userAssistanceAnalyticsDigest: DIGEST_6,
        documentationRunbookReceiptHash: DIGEST_D,
        driftPolicyHash: DIGEST_E,
        currentManualSetHash: DIGEST_F,
        currentManualIndexHash: DIGEST_1,
        manualNavigationReady: true,
        contextualManualDrawerReceiptHash: DIGEST_7,
        contextualManualDrawerHash: DIGEST_8,
        controlledDocumentDistributionRecordId: 'cmdist-role-manual-navigation-v1',
        controlledDocumentDistributionReceiptHash: DIGEST_9,
        documentationPublicationReceiptHash: DIGEST_A,
        manualExportReceiptHash: DIGEST_B,
        roleManualCoverageReceiptHash: DIGEST_C,
        acknowledgementRosterHash: DIGEST_D,
        manualNavigationAcknowledgedRoleRefs: ['clinical_research_coordinator', 'quality_manager'],
        manualNavigationRequiredAcknowledgementRoleRefs: ['clinical_research_coordinator', 'quality_manager'],
        manualNavigationRoleRefs: ['clinical_research_coordinator', 'quality_manager'],
        manualNavigationCurrentVersionOnly: true,
        manualNavigationObsoleteVersionUseBlocked: true,
        manualNavigationEffectiveUseAcknowledged: true,
        noRawInquiryContent: true,
        reviewedAtHlc: { physicalMs: 1800007080000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      inquirySignals: signals,
      backlogItems: items,
      actionPackage: {
        packageRef: 'inquiry-cqi-action-package-alpha',
        linkedBacklogItemRefs,
        improvementCategories: REQUIRED_CATEGORIES,
        driftSignalRefs: signals.map((signal) => `drift-${signal.signalRef}`),
        documentationUpdateDraftHashes: [DIGEST_2, DIGEST_3],
        cqiQueueHash: DIGEST_4,
        crosslinkRefreshHash: DIGEST_5,
        versionGovernanceHash: DIGEST_6,
        highRiskReviewHashes: [DIGEST_7],
        qualityOwnerRoleRef: 'quality_manager',
        packagedAtHlc: { physicalMs: 1800007600000, logical: 1 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      aiAssistant: {
        used: true,
        assistantRef: 'documentation-orientation-ai-alpha',
        recommendationHash: DIGEST_8,
        limitationHashes: [DIGEST_9],
        advisoryOnly: true,
        finalAuthority: false,
        humanReviewed: true,
        reviewedAtHlc: { physicalMs: 1800007650000, logical: 0 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      humanReview: {
        reviewerDid: 'did:exo:quality-owner-alpha',
        reviewerRoleRefs: ['quality_manager'],
        decision: 'cqi_backlog_ready',
        decisionHash: DIGEST_9,
        finalAuthority: 'human',
        aiFinalAuthority: false,
        noProductionTrustClaim: true,
        reviewedAtHlc: { physicalMs: 1800007700000, logical: 1 },
        metadataOnly: true,
        protectedContentExcluded: true,
      },
      custodyDigest: DIGEST_5,
    },
    overrides,
  );
}

test('inquiry to CQI backlog packages documentation friction into deterministic inactive actions', async () => {
  const { evaluateInquiryCqiBacklog } = await loadInquiryCqiBacklog();
  const input = backlogInput();

  const first = evaluateInquiryCqiBacklog(input);
  const second = evaluateInquiryCqiBacklog(input);

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.deepEqual(first, second);
  assert.equal(first.cqiBacklog.trustState, 'inactive');
  assert.equal(first.cqiBacklog.exochainProductionClaim, false);
  assert.equal(first.cqiBacklog.metadataOnly, true);
  assert.equal(first.cqiBacklog.containsProtectedContent, false);
  assert.deepEqual(first.cqiBacklog.sourceFamilies, REQUIRED_SOURCE_FAMILIES);
  assert.deepEqual(first.cqiBacklog.improvementCategories, REQUIRED_CATEGORIES);
  assert.equal(first.cqiBacklog.backlogItemCount, 8);
  assert.deepEqual(first.cqiBacklog.highRiskBacklogItemRefs, ['cqi-item-missing_documentation']);
  assert.equal(first.cqiBacklog.driftReady, true);
  assert.equal(first.cqiBacklog.aiAssistanceUsed, true);
  assert.equal(first.cqiBacklog.userAssistanceReceiptHash, DIGEST_C);
  assert.equal(first.cqiBacklog.userAssistanceAnalyticsDigest, DIGEST_6);
  assert.equal(first.cqiBacklog.contextualManualDrawerReceiptHash, DIGEST_7);
  assert.equal(first.cqiBacklog.controlledDocumentDistributionReceiptHash, DIGEST_9);
  assert.equal(first.cqiBacklog.documentationPublicationReceiptHash, DIGEST_A);
  assert.equal(first.cqiBacklog.manualExportReceiptHash, DIGEST_B);
  assert.equal(first.cqiBacklog.roleManualCoverageReceiptHash, DIGEST_C);
  assert.equal(first.cqiBacklog.manualNavigationEffectiveUseAcknowledged, true);
  assert.deepEqual(first.cqiBacklog.manualNavigationAcknowledgedRoleRefs, [
    'clinical_research_coordinator',
    'quality_manager',
  ]);
  assert.equal(first.receipt.anchorPayload.artifactType, 'inquiry_cqi_backlog');
  assert.equal(first.receipt.anchorPayload.classification, 'metadata_only_documentation_cqi');
  assert.ok(first.receipt.anchorPayload.sensitivityTags.includes('manual_navigation_readiness'));
});

test('inquiry to CQI backlog requires user-assistance manual-navigation readiness lineage', async () => {
  const { evaluateInquiryCqiBacklog } = await loadInquiryCqiBacklog();
  const result = evaluateInquiryCqiBacklog(
    backlogInput({
      sourceAnalytics: {
        userAssistanceAnalyticsDigest: '',
        manualNavigationReady: false,
        contextualManualDrawerReceiptHash: 'bad',
        controlledDocumentDistributionReceiptHash: '',
        documentationPublicationReceiptHash: '',
        manualExportReceiptHash: '',
        roleManualCoverageReceiptHash: '',
        acknowledgementRosterHash: '',
        manualNavigationAcknowledgedRoleRefs: ['quality_manager'],
        manualNavigationRequiredAcknowledgementRoleRefs: ['clinical_research_coordinator', 'quality_manager'],
        manualNavigationRoleRefs: ['clinical_research_coordinator', 'quality_manager'],
        manualNavigationCurrentVersionOnly: false,
        manualNavigationObsoleteVersionUseBlocked: false,
        manualNavigationEffectiveUseAcknowledged: false,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.receipt, null);
  assert.match(result.reasons.join('\n'), /source_assistance_analytics_digest_invalid/u);
  assert.match(result.reasons.join('\n'), /source_manual_navigation_ready_absent/u);
  assert.match(result.reasons.join('\n'), /source_manual_navigation_drawer_receipt_hash_invalid/u);
  assert.match(result.reasons.join('\n'), /source_manual_navigation_distribution_receipt_hash_invalid/u);
  assert.match(result.reasons.join('\n'), /source_manual_navigation_publication_receipt_hash_invalid/u);
  assert.match(result.reasons.join('\n'), /source_manual_navigation_manual_export_receipt_hash_invalid/u);
  assert.match(result.reasons.join('\n'), /source_manual_navigation_role_manual_coverage_receipt_hash_invalid/u);
  assert.match(result.reasons.join('\n'), /source_manual_navigation_acknowledgement_roster_hash_invalid/u);
  assert.match(result.reasons.join('\n'), /source_manual_navigation_acknowledgement_incomplete/u);
  assert.match(
    result.reasons.join('\n'),
    /source_manual_navigation_signal_role_acknowledgement_missing:clinical_research_coordinator/u,
  );
  assert.match(result.reasons.join('\n'), /source_manual_navigation_current_version_boundary_invalid/u);
  assert.match(result.reasons.join('\n'), /source_manual_navigation_obsolete_version_boundary_invalid/u);
  assert.match(result.reasons.join('\n'), /source_manual_navigation_effective_use_absent/u);
});

test('inquiry to CQI backlog fails closed for missing source coverage and incomplete action packaging', async () => {
  const { evaluateInquiryCqiBacklog } = await loadInquiryCqiBacklog();
  const signals = inquirySignals().filter((signal) => signal.sourceFamily !== 'product_gap');
  const items = backlogItems(signals).slice(0, -1);
  const result = evaluateInquiryCqiBacklog(
    backlogInput({
      backlogCycle: { productionTrustClaim: true },
      inquirySignals: signals,
      backlogItems: items,
      actionPackage: {
        linkedBacklogItemRefs: items.map((item) => item.backlogItemRef),
        improvementCategories: ['documentation_update'],
        driftSignalRefs: [],
        highRiskReviewHashes: [],
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.match(result.reasons.join('\n'), /source_family_missing:product_gap/);
  assert.match(result.reasons.join('\n'), /backlog_item_absent:inquiry-workflow_exit/);
  assert.match(result.reasons.join('\n'), /action_package_category_missing:cqi_review/);
  assert.match(result.reasons.join('\n'), /action_package_drift_signals_absent/);
  assert.match(result.reasons.join('\n'), /production_trust_claim_forbidden/);
});

test('inquiry to CQI backlog requires high risk review and keeps AI advisory', async () => {
  const { evaluateInquiryCqiBacklog } = await loadInquiryCqiBacklog();
  const result = evaluateInquiryCqiBacklog(
    backlogInput({
      actionPackage: { highRiskReviewHashes: [] },
      aiAssistant: {
        finalAuthority: true,
        humanReviewed: false,
        limitationHashes: [],
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('\n'), /high_risk_review_hash_absent/);
  assert.match(result.reasons.join('\n'), /ai_final_authority_forbidden/);
  assert.match(result.reasons.join('\n'), /ai_human_review_absent/);
  assert.match(result.reasons.join('\n'), /human_final_authority_absent/);
});

test('inquiry to CQI backlog validates HLC ordering and supports no AI operation', async () => {
  const { evaluateInquiryCqiBacklog } = await loadInquiryCqiBacklog();
  const sameTick = evaluateInquiryCqiBacklog(
    backlogInput({
      aiAssistant: { used: false },
      backlogCycle: {
        signalsCapturedAtHlc: { physicalMs: 1800007050000, logical: 1 },
        triagedAtHlc: { physicalMs: 1800007050000, logical: 2 },
        ownerAssignedAtHlc: { physicalMs: 1800007050000, logical: 3 },
        actionPackagedAtHlc: { physicalMs: 1800007050000, logical: 4 },
        humanReviewedAtHlc: { physicalMs: 1800007050000, logical: 5 },
        auditRecordedAtHlc: { physicalMs: 1800007050000, logical: 6 },
      },
      sourceAnalytics: {
        reviewedAtHlc: { physicalMs: 1800007050000, logical: 0 },
      },
      inquirySignals: inquirySignals().map((signal, index) => ({
        ...signal,
        capturedAtHlc: { physicalMs: 1800007050000, logical: index + 1 },
      })),
      backlogItems: backlogItems(inquirySignals()).map((item, index) => ({
        ...item,
        triagedAtHlc: { physicalMs: 1800007050000, logical: 2 + index },
        dueAtHlc: { physicalMs: 1800007050000, logical: 12 + index },
      })),
      actionPackage: {
        packagedAtHlc: { physicalMs: 1800007050000, logical: 4 },
      },
      humanReview: {
        reviewedAtHlc: { physicalMs: 1800007050000, logical: 5 },
      },
    }),
  );

  assert.equal(sameTick.decision, 'permitted');
  assert.equal(sameTick.cqiBacklog.aiAssistanceUsed, false);

  const malformed = evaluateInquiryCqiBacklog(
    backlogInput({
      backlogCycle: { triagedAtHlc: { physicalMs: 1800007040000, logical: 0 } },
      sourceAnalytics: { reviewedAtHlc: { physicalMs: 1800007900000, logical: 0 } },
    }),
  );

  assert.equal(malformed.decision, 'denied');
  assert.match(malformed.reasons.join('\n'), /backlog_cycle_triagedAtHlc_before_signalsCapturedAtHlc/);
  assert.match(malformed.reasons.join('\n'), /source_analytics_review_after_signal_capture/);
});

test('inquiry to CQI backlog handles absent collections and malformed clocks as denial states', async () => {
  const { evaluateInquiryCqiBacklog } = await loadInquiryCqiBacklog();
  const result = evaluateInquiryCqiBacklog(
    backlogInput({
      backlogCycle: {
        openedAtHlc: { physicalMs: 1800007050000, logical: -1 },
      },
      inquirySignals: null,
      backlogItems: null,
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.match(result.reasons.join('\n'), /backlog_cycle_openedAtHlc_invalid/);
  assert.match(result.reasons.join('\n'), /inquiry_signals_absent/);
  assert.match(result.reasons.join('\n'), /backlog_items_absent/);
});

test('inquiry to CQI backlog rejects raw inquiry content protected content and secrets before receipts', async () => {
  const { evaluateInquiryCqiBacklog, ProtectedContentError } = await loadInquiryCqiBacklog();

  const inert = evaluateInquiryCqiBacklog(
    backlogInput({
      inert: [{ rawInquiryText: false }, { apiKey: null }, { rawManualContent: [null, false] }],
    }),
  );
  assert.equal(inert.decision, 'permitted');

  assert.throws(
    () =>
      evaluateInquiryCqiBacklog(
        backlogInput({
          rawInquiryText: 'participant and sponsor confidential narrative must not be anchored',
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateInquiryCqiBacklog(
        backlogInput({
          nested: [{ rawInquiryText: { sourceHash: DIGEST_A } }],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateInquiryCqiBacklog(
        backlogInput({
          nested: [{ rawManualContent: [null, 'not allowed'] }],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateInquiryCqiBacklog(
        backlogInput({
          nested: [{ apiKey: DIGEST_A }, { rawManualContent: ['not allowed'] }],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateInquiryCqiBacklog(
        backlogInput({
          nested: [{ token: 7 }],
        }),
      ),
    ProtectedContentError,
  );
});
