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
const DIGEST_R = 'abababababababababababababababababababababababababababababababab';

const REQUIRED_CONTEXT_FAMILIES = [
  'control',
  'dashboard_card',
  'decision_matter',
  'evidence_object',
  'major_page',
  'procedure',
  'workflow',
];

const REQUIRED_INSTRUCTION_SLOTS = [
  'approval_required',
  'audit_export_result',
  'common_failure_modes',
  'evidence_needed',
  'step_by_step',
  'what_this_is',
  'when_to_use_it',
  'who_owns_it',
];

const REQUIRED_CROSSLINK_KINDS = [
  'acceptance_test',
  'ai_review_prompt',
  'audit_export',
  'dashboard',
  'decision_forum_escalation',
  'evidence_object',
  'exochain_receipt',
  'open_question',
  'policy',
  'procedure',
  'role_authority',
  'source_control',
  'version_effective_date',
  'workflow',
];

async function loadContextualManualDrawer() {
  try {
    return await import('../src/contextual-manual-drawer.mjs');
  } catch (error) {
    assert.fail(`CyberMedica contextual manual drawer module must exist and load: ${error.message}`);
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

function instructionHashes(offset = 0, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    approval_required: hashes[(offset + 0) % hashes.length],
    audit_export_result: hashes[(offset + 1) % hashes.length],
    common_failure_modes: hashes[(offset + 2) % hashes.length],
    evidence_needed: hashes[(offset + 3) % hashes.length],
    step_by_step: hashes[(offset + 4) % hashes.length],
    what_this_is: hashes[(offset + 5) % hashes.length],
    when_to_use_it: hashes[(offset + 6) % hashes.length],
    who_owns_it: hashes[(offset + 7) % hashes.length],
    ...overrides,
  };
}

function crosslinks(offset = 0, overrides = {}) {
  const hashes = [
    DIGEST_A,
    DIGEST_B,
    DIGEST_C,
    DIGEST_D,
    DIGEST_E,
    DIGEST_F,
    DIGEST_1,
    DIGEST_2,
    DIGEST_3,
    DIGEST_4,
    DIGEST_5,
    DIGEST_6,
    DIGEST_7,
    DIGEST_8,
    DIGEST_9,
  ];
  return REQUIRED_CROSSLINK_KINDS.map((kind, index) => ({
    kind,
    targetRef: `manual-crosslink-${kind}`,
    targetHash: hashes[(index + offset) % hashes.length],
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides[kind],
  }));
}

function manualSection(contextFamily, index, overrides = {}) {
  const objectRef = contextFamily === 'control' ? 'CTRL-LAUNCH-READINESS' : `${contextFamily}-alpha`;
  return {
    sectionRef: `manual-section-${contextFamily}`,
    manualRef: 'quality-manager-manual',
    manualVersionRef: 'quality-manager-manual-v1',
    contextFamily,
    objectType: contextFamily === 'control' ? 'quality_control' : contextFamily,
    objectRef,
    sectionHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1][index],
    roleScopes: ['quality_manager', 'principal_investigator'],
    ownerRoleRef: 'quality_manager',
    highLevelOrientationHash: [DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5, DIGEST_6, DIGEST_7, DIGEST_8][index],
    instructionHashes: instructionHashes(index),
    crosslinks: crosslinks(index),
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1804500200000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function manualSections() {
  return REQUIRED_CONTEXT_FAMILIES.map((contextFamily, index) => manualSection(contextFamily, index));
}

function distributionReadiness(overrides = {}) {
  return {
    controlledDocumentDistributionRecordId: 'cmdist-quality-manager-manual-set-v1',
    controlledDocumentDistributionReceiptHash: DIGEST_6,
    documentationPublicationReceiptHash: DIGEST_7,
    manualExportReceiptHash: DIGEST_8,
    roleManualCoverageReceiptHash: DIGEST_R,
    acknowledgementRosterHash: DIGEST_9,
    requiredAcknowledgementRoleRefs: ['quality_manager'],
    acknowledgedRoleRefs: ['quality_manager'],
    distributionPublishedAtHlc: { physicalMs: 1804500160000, logical: 0 },
    effectiveUseAcknowledged: true,
    currentVersionOnly: true,
    obsoleteVersionUseBlocked: true,
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function drawerInput(overrides = {}) {
  const base = {
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
      permissions: ['manual_drawer_read'],
      authorityChainHash: DIGEST_A,
    },
    drawerPolicy: {
      policyRef: 'contextual-manual-drawer-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredContextFamilies: REQUIRED_CONTEXT_FAMILIES,
      requiredInstructionSlots: REQUIRED_INSTRUCTION_SLOTS,
      requiredCrosslinkKinds: REQUIRED_CROSSLINK_KINDS,
      roleAwareRequired: true,
      rightSideDrawerRequired: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1804500000000, logical: 0 },
    },
    manualIndex: {
      indexRef: 'manual-index-alpha',
      currentManualSetHash: DIGEST_C,
      manualIndexHash: DIGEST_D,
      documentationRunbookReceiptHash: DIGEST_E,
      crosslinkMatrixHash: DIGEST_F,
      versionGovernanceHash: DIGEST_1,
      currentVersionRef: 'manual-set-v1',
      effectiveAtHlc: { physicalMs: 1804500100000, logical: 0 },
      reviewedAtHlc: { physicalMs: 1804500150000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    drawerRequest: {
      requestRef: 'drawer-request-control-alpha',
      contextFamily: 'control',
      objectType: 'quality_control',
      objectRef: 'CTRL-LAUNCH-READINESS',
      requestedRoleRef: 'quality_manager',
      requestedAtHlc: { physicalMs: 1804500300000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    manualSections: manualSections(),
    distributionReadiness: distributionReadiness(),
    humanReview: {
      reviewedByDid: 'did:exo:documentation-governance-alpha',
      status: 'approved',
      decision: 'manual_drawer_ready_inactive_trust',
      reviewedAtHlc: { physicalMs: 1804500400000, logical: 0 },
      rationaleHash: DIGEST_2,
      humanGate: { verified: true },
    },
  };

  return mergeDeep(base, overrides);
}

test('contextual manual drawer resolves role-aware right-side help to deterministic metadata sections', async () => {
  const { evaluateContextualManualDrawer } = await loadContextualManualDrawer();

  const first = evaluateContextualManualDrawer(drawerInput());
  const second = evaluateContextualManualDrawer({
    ...drawerInput(),
    manualSections: [...manualSections()].reverse().map((section) => ({
      ...section,
      crosslinks: [...section.crosslinks].reverse(),
    })),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.drawerView.drawerSide, 'right');
  assert.equal(first.drawerView.state, 'ready_inactive_trust');
  assert.equal(first.drawerView.trustState, 'inactive');
  assert.equal(first.drawerView.exochainProductionClaim, false);
  assert.equal(first.drawerView.rawContentIncluded, false);
  assert.equal(first.selectedSection.sectionRef, 'manual-section-control');
  assert.equal(first.selectedSection.contextFamily, 'control');
  assert.equal(first.selectedSection.manualRef, 'quality-manager-manual');
  assert.equal(first.selectedSection.roleScopeMatched, 'quality_manager');
  assert.equal(first.drawerView.controlledDocumentDistributionReceiptHash, DIGEST_6);
  assert.equal(first.drawerView.manualExportReceiptHash, DIGEST_8);
  assert.equal(first.drawerView.roleManualCoverageReceiptHash, DIGEST_R);
  assert.equal(first.drawerView.effectiveUseAcknowledged, true);
  assert.equal(first.selectedSection.controlledDocumentDistributionRecordId, 'cmdist-quality-manager-manual-set-v1');
  assert.equal(first.selectedSection.controlledDocumentDistributionReceiptHash, DIGEST_6);
  assert.equal(first.selectedSection.roleManualCoverageReceiptHash, DIGEST_R);
  assert.deepEqual(first.drawerView.availableContextFamilies, REQUIRED_CONTEXT_FAMILIES);
  assert.deepEqual(first.selectedSection.instructionSlots, REQUIRED_INSTRUCTION_SLOTS);
  assert.deepEqual(first.selectedSection.crosslinkKinds, REQUIRED_CROSSLINK_KINDS);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.equal(first.receipt.anchorPayload.artifactType, 'contextual_manual_drawer');
  assert.equal(first.receipt.anchorPayload.artifactVersion, 'manual-set-v1:manual-section-control');
  assert.equal(first.drawerView.drawerHash, second.drawerView.drawerHash);
  assert.equal(first.receipt.actionHash, second.receipt.actionHash);
  assert.equal(Object.hasOwn(first, 'inputEcho'), false);
});

test('contextual manual drawer requires controlled document distribution readiness before opening manual navigation', async () => {
  const { evaluateContextualManualDrawer } = await loadContextualManualDrawer();

  const missingReadiness = evaluateContextualManualDrawer(
    drawerInput({
      distributionReadiness: null,
    }),
  );
  const unsafeReadiness = evaluateContextualManualDrawer(
    drawerInput({
      distributionReadiness: distributionReadiness({
        controlledDocumentDistributionReceiptHash: 'not-a-digest',
        documentationPublicationReceiptHash: '',
        manualExportReceiptHash: null,
        roleManualCoverageReceiptHash: 'bad',
        acknowledgementRosterHash: '',
        requiredAcknowledgementRoleRefs: ['principal_investigator'],
        acknowledgedRoleRefs: [],
        distributionPublishedAtHlc: { physicalMs: 1804500300000, logical: 1 },
        effectiveUseAcknowledged: false,
        currentVersionOnly: false,
        obsoleteVersionUseBlocked: false,
        metadataOnly: false,
        protectedContentExcluded: false,
        productionTrustClaim: true,
      }),
    }),
  );

  assert.equal(missingReadiness.decision, 'denied');
  assert.equal(missingReadiness.drawerView, null);
  assert.equal(missingReadiness.selectedSection, null);
  assert.equal(missingReadiness.receipt, null);
  assert.ok(
    missingReadiness.reasons.includes('manual_drawer_distribution_record_absent'),
    missingReadiness.reasons.join(','),
  );
  assert.ok(
    missingReadiness.reasons.includes('manual_drawer_distribution_receipt_hash_invalid'),
    missingReadiness.reasons.join(','),
  );
  assert.ok(missingReadiness.reasons.includes('manual_drawer_manual_export_receipt_hash_invalid'));
  assert.ok(missingReadiness.reasons.includes('manual_drawer_role_manual_coverage_receipt_hash_invalid'));
  assert.ok(missingReadiness.reasons.includes('manual_drawer_acknowledgement_roles_missing'));

  assert.equal(unsafeReadiness.decision, 'denied');
  assert.equal(unsafeReadiness.drawerView, null);
  assert.equal(unsafeReadiness.receipt, null);
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_distribution_receipt_hash_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_publication_receipt_hash_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_manual_export_receipt_hash_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_role_manual_coverage_receipt_hash_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_acknowledgement_roster_hash_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_requested_role_acknowledgement_required:quality_manager'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_requested_role_acknowledgement_missing:quality_manager'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_effective_use_acknowledgement_absent'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_current_document_version_boundary_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_obsolete_document_boundary_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_distribution_metadata_boundary_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_distribution_protected_boundary_invalid'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_distribution_production_claim_forbidden'));
  assert.ok(unsafeReadiness.reasons.includes('manual_drawer_distribution_after_request'));
});

test('contextual manual drawer fails closed for missing coverage role scope crosslinks and review defects', async () => {
  const { evaluateContextualManualDrawer } = await loadContextualManualDrawer();
  const input = drawerInput({
    actor: { roleRefs: ['sponsor_viewer'] },
    drawerPolicy: {
      requiredContextFamilies: REQUIRED_CONTEXT_FAMILIES.filter((family) => family !== 'dashboard_card'),
    },
    manualSections: manualSections().map((section) =>
      section.contextFamily === 'control'
        ? {
            ...section,
            roleScopes: ['principal_investigator'],
            instructionHashes: instructionHashes(0, { step_by_step: '' }),
            crosslinks: crosslinks(0).filter((link) => link.kind !== 'exochain_receipt'),
          }
        : section,
    ),
    humanReview: {
      status: 'pending',
      humanGate: { verified: false },
      rationaleHash: '',
    },
  });

  const denied = evaluateContextualManualDrawer(input);

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.equal(denied.drawerView, null);
  assert.equal(denied.selectedSection, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('policy_context_family_missing:dashboard_card'));
  assert.ok(denied.reasons.includes('manual_section_role_scope_denied:manual-section-control'));
  assert.ok(denied.reasons.includes('manual_section_instruction_missing:manual-section-control:step_by_step'));
  assert.ok(denied.reasons.includes('manual_section_crosslink_missing:manual-section-control:exochain_receipt'));
  assert.ok(denied.reasons.includes('manual_drawer_human_review_not_approved'));
  assert.ok(denied.reasons.includes('manual_drawer_human_gate_unverified'));
  assert.ok(denied.reasons.includes('manual_drawer_review_rationale_invalid'));
});

test('contextual manual drawer denies unsupported contexts AI actors and unsafe HLC ordering', async () => {
  const { evaluateContextualManualDrawer } = await loadContextualManualDrawer();

  const denied = evaluateContextualManualDrawer(
    drawerInput({
      actor: {
        kind: 'ai_agent',
      },
      drawerRequest: {
        contextFamily: 'raw_document_body',
        requestedAtHlc: { physicalMs: 1804490000000, logical: 0 },
      },
      manualIndex: {
        reviewedAtHlc: { physicalMs: 1804490000000, logical: 0 },
      },
      manualSections: manualSections().filter((section) => section.contextFamily !== 'control'),
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('human_manual_drawer_actor_required'));
  assert.ok(denied.reasons.includes('manual_drawer_context_unsupported:raw_document_body'));
  assert.ok(denied.reasons.includes('manual_drawer_section_not_found'));
  assert.ok(denied.reasons.includes('manual_index_review_before_effective'));
  assert.ok(denied.reasons.includes('drawer_request_before_manual_index_review'));
});

test('contextual manual drawer rejects raw manual protected source content and secrets', async () => {
  const { evaluateContextualManualDrawer } = await loadContextualManualDrawer();

  assert.throws(
    () =>
      evaluateContextualManualDrawer(
        drawerInput({
          manualSections: [
            manualSection('control', 0, {
              rawManualContent: 'This raw manual body belongs in controlled storage, not drawer receipts.',
            }),
            ...manualSections().slice(1),
          ],
        }),
      ),
    /raw manual drawer content|rawManualContent/i,
  );

  assert.throws(
    () =>
      evaluateContextualManualDrawer(
        drawerInput({
          drawerRequest: {
            sourceDocumentBody: 'Source record narrative for participant Alice Example.',
          },
        }),
      ),
    /protected content|sourceDocumentBody/i,
  );

  assert.throws(
    () =>
      evaluateContextualManualDrawer(
        drawerInput({
          manualIndex: {
            apiKey: 'secret-provider-token',
          },
        }),
      ),
    /manual drawer secret|apiKey/i,
  );
});
