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

const REQUIRED_ROLE_REFS = [
  'ai_quality_reviewer',
  'auditor_inspector',
  'clinical_research_coordinator',
  'cro_portfolio_manager',
  'decision_forum_member',
  'principal_investigator',
  'quality_manager',
  'site_leader',
  'sponsor_viewer',
  'system_administrator',
  'tenant_administrator',
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

const REQUIRED_CROSSLINK_FAMILIES = [
  'acceptance_tests',
  'authority_rules',
  'controls',
  'dashboard_location',
  'decision_forum_escalation',
  'evidence_objects',
  'exochain_receipt_type',
  'open_questions',
  'policies',
  'procedures',
  'tenant_configuration',
  'workflows',
];

async function loadRoleManuals() {
  try {
    return await import('../src/role-manuals.mjs');
  } catch (error) {
    assert.fail(`CyberMedica role manuals module must exist and load: ${error.message}`);
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

function roleManual(roleRef, index, overrides = {}) {
  const hashes = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3, DIGEST_4, DIGEST_5];
  return {
    roleRef,
    manualRef: `role-manual-${roleRef}`,
    versionRef: `role-manual-${roleRef}-v1`,
    versionHash: hashes[index],
    instructionSlots: REQUIRED_INSTRUCTION_SLOTS,
    crosslinkFamilies: REQUIRED_CROSSLINK_FAMILIES,
    workflowRefs: ['workflow-startup-risk', 'workflow-evidence-intake', 'workflow-decision-forum'],
    evidenceChecklistRefs: ['checklist-role-evidence', 'checklist-controlled-documentation'],
    dashboardRefs: [`dashboard-${roleRef}`],
    authorityScopeRefs: [`authority-${roleRef}`],
    escalationRouteRefs: ['decision-forum-material-documentation-change'],
    acceptanceTestRefs: ['tests/role-manuals.test.mjs'],
    prohibitedClaimFamilies: ['production_exochain_trust', 'clinical_authority_without_human_review'],
    guidanceNotAuthority: true,
    approvedForUse: true,
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800007100000, logical: index },
    effectiveAtHlc: { physicalMs: 1800007300000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function roleManuals() {
  return REQUIRED_ROLE_REFS.map((roleRef, index) => roleManual(roleRef, index));
}

function roleManualInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:documentation-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'tenant_administrator'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['role_manual_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    roleManualPolicy: {
      policyRef: 'role-manual-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredRoleRefs: REQUIRED_ROLE_REFS,
      requiredInstructionSlots: REQUIRED_INSTRUCTION_SLOTS,
      requiredCrosslinkFamilies: REQUIRED_CROSSLINK_FAMILIES,
      manualVersionGovernanceRequired: true,
      highRiskClaimsRequireReview: true,
      aiAssistanceAdvisoryOnly: true,
      metadataOnly: true,
      protectedContentExcluded: true,
      evaluatedAtHlc: { physicalMs: 1800007000000, logical: 0 },
    },
    manualCycle: {
      cycleRef: 'role-manual-cycle-alpha',
      openedAtHlc: { physicalMs: 1800007050000, logical: 0 },
      manualReviewAtHlc: { physicalMs: 1800007100000, logical: 0 },
      humanApprovedAtHlc: { physicalMs: 1800007200000, logical: 0 },
      publishedAtHlc: { physicalMs: 1800007300000, logical: 0 },
      receiptRecordedAtHlc: { physicalMs: 1800007400000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    manualIndex: {
      documentationRunbookReceiptHash: DIGEST_C,
      contextualManualDrawerReceiptHash: DIGEST_D,
      documentationPublicationReceiptHash: DIGEST_E,
      currentManualSetHash: DIGEST_F,
      versionGovernanceHash: DIGEST_1,
      metadataOnly: true,
      protectedContentExcluded: true,
      reviewedAtHlc: { physicalMs: 1800007080000, logical: 0 },
    },
    roleManuals: roleManuals(),
    aiAssistance: {
      used: true,
      assistantRef: 'role-manual-ai-assistant-alpha',
      promptPolicyHash: DIGEST_2,
      outputHash: DIGEST_3,
      limitationHashes: [DIGEST_4],
      advisoryOnly: true,
      finalAuthority: false,
      humanReviewed: true,
      reviewedAtHlc: { physicalMs: 1800007180000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:quality-director-alpha',
      reviewerRoleRefs: ['quality_manager', 'tenant_administrator'],
      decision: 'role_manuals_ready',
      decisionHash: DIGEST_5,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1800007200000, logical: 1 },
      metadataOnly: true,
    },
    custodyDigest: DIGEST_6,
  };
  return mergeDeep(base, overrides);
}

test('role manuals produce deterministic inactive coverage receipts for every required role', async () => {
  const { evaluateRoleManuals } = await loadRoleManuals();

  const resultA = evaluateRoleManuals(roleManualInput());
  const resultB = evaluateRoleManuals(
    roleManualInput({
      roleManualPolicy: {
        requiredRoleRefs: [...REQUIRED_ROLE_REFS].reverse(),
        requiredInstructionSlots: [...REQUIRED_INSTRUCTION_SLOTS].reverse(),
        requiredCrosslinkFamilies: [...REQUIRED_CROSSLINK_FAMILIES].reverse(),
      },
      roleManuals: [...roleManuals()].reverse().map((manual) => ({
        ...manual,
        instructionSlots: [...manual.instructionSlots].reverse(),
        crosslinkFamilies: [...manual.crosslinkFamilies].reverse(),
      })),
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.roleManuals.ready, true);
  assert.equal(resultA.roleManuals.trustState, 'inactive');
  assert.equal(resultA.roleManuals.exochainProductionClaim, false);
  assert.equal(resultA.roleManuals.manualCount, REQUIRED_ROLE_REFS.length);
  assert.deepEqual(resultA.roleManuals.roleRefs, REQUIRED_ROLE_REFS);
  assert.deepEqual(resultA.roleManuals.instructionSlotCoverage, REQUIRED_INSTRUCTION_SLOTS);
  assert.deepEqual(resultA.roleManuals.crosslinkFamilyCoverage, REQUIRED_CROSSLINK_FAMILIES);
  assert.deepEqual(resultA.roleManuals.sourceEvidence, [
    'cybermedica_2_0_sandy_seven_layer_master_prd.md#documentation-layer',
    'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
    'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  ]);
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'role_manual_coverage');
  assert.deepEqual(resultA, resultB);
});

test('role manuals fail closed for missing role coverage instruction slots and crosslinks', async () => {
  const { evaluateRoleManuals } = await loadRoleManuals();

  const result = evaluateRoleManuals(
    roleManualInput({
      manualCycle: { productionTrustClaim: true },
      roleManuals: roleManuals()
        .filter((manual) => manual.roleRef !== 'sponsor_viewer')
        .map((manual) =>
          manual.roleRef === 'site_leader'
            ? {
                ...manual,
                instructionSlots: manual.instructionSlots.filter((slot) => slot !== 'audit_export_result'),
                crosslinkFamilies: manual.crosslinkFamilies.filter((family) => family !== 'acceptance_tests'),
                guidanceNotAuthority: false,
                productionTrustClaim: true,
              }
            : manual,
        ),
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.equal(result.receipt, null);
  assert.ok(result.reasons.includes('manual_role_missing:sponsor_viewer'));
  assert.ok(result.reasons.includes('manual_instruction_slot_missing:site_leader:audit_export_result'));
  assert.ok(result.reasons.includes('manual_crosslink_family_missing:site_leader:acceptance_tests'));
  assert.ok(result.reasons.includes('manual_guidance_authority_boundary_invalid:site_leader'));
  assert.ok(result.reasons.includes('manual_production_trust_claim_forbidden:site_leader'));
  assert.ok(result.reasons.includes('cycle_production_trust_claim_forbidden'));
  assert.deepEqual(result.roleManuals.missingRoleRefs, ['sponsor_viewer']);
});

test('role manuals require human final authority advisory AI and monotonic HLC evidence', async () => {
  const { evaluateRoleManuals } = await loadRoleManuals();

  const result = evaluateRoleManuals(
    roleManualInput({
      actor: { kind: 'ai_agent' },
      authority: { permissions: ['read'] },
      aiAssistance: {
        advisoryOnly: false,
        finalAuthority: true,
        humanReviewed: false,
        reviewedAtHlc: { physicalMs: 1800007040000, logical: 0 },
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
        noProductionTrustClaim: false,
        reviewedAtHlc: { physicalMs: 1800007060000, logical: 0 },
      },
      manualIndex: {
        reviewedAtHlc: { physicalMs: 1800007410000, logical: 0 },
      },
    }),
  );

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_actor_cannot_approve_role_manuals'));
  assert.ok(result.reasons.includes('authority_permission_missing'));
  assert.ok(result.reasons.includes('ai_assistance_not_advisory'));
  assert.ok(result.reasons.includes('ai_assistance_final_authority_forbidden'));
  assert.ok(result.reasons.includes('ai_assistance_human_review_absent'));
  assert.ok(result.reasons.includes('ai_assistance_review_before_manual_review'));
  assert.ok(result.reasons.includes('human_final_authority_absent'));
  assert.ok(result.reasons.includes('human_review_ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('human_review_production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('human_review_before_cycle_approval'));
  assert.ok(result.reasons.includes('manual_index_review_after_receipt'));
});

test('role manuals reject raw manual content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateRoleManuals } = await loadRoleManuals();

  assert.throws(
    () =>
      evaluateRoleManuals(
        roleManualInput({
          roleManuals: [roleManual('site_leader', 0, { rawManualText: 'Use the clinical source narrative here.' })],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateRoleManuals(
        roleManualInput({
          manualIndex: {
            apiKey: 'vault-ref-role-manual-alpha',
          },
        }),
      ),
    ProtectedContentError,
  );
});
