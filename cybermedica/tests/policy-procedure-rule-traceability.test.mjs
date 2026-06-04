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

const REQUIRED_POLICY_IDS = Array.from({ length: 40 }, (_, index) => `POLICY-${String(index + 1).padStart(3, '0')}`);
const REQUIRED_PROCEDURE_IDS = Array.from({ length: 16 }, (_, index) => `PROCEDURE-${String(index + 1).padStart(3, '0')}`);
const REQUIRED_RULE_IDS = Array.from({ length: 15 }, (_, index) => `RULE-${String(index + 1).padStart(3, '0')}`);
const REQUIRED_SOURCE_REFS = [
  'cyber_medica_qms_prd_master.md#core-policies',
  'cyber_medica_qms_prd_master.md#core-procedures',
  'cyber_medica_qms_prd_master.md#governance-rules',
  'cybermedica_2_0_sandy_seven_layer_master_prd.md#appendix-a-seven-layer-implementation-backlog-skeleton',
];

const MODULE_REFS_BY_ITEM = {
  'POLICY-001': ['src/site-governance-readiness.mjs'],
  'POLICY-002': ['src/site-governance-readiness.mjs'],
  'POLICY-003': ['src/site-governance-readiness.mjs'],
  'POLICY-004': ['src/ethical-framework-readiness.mjs'],
  'POLICY-005': ['src/independent-ethics-review.mjs'],
  'POLICY-006': ['src/site-governance-readiness.mjs'],
  'POLICY-007': ['src/concern-reporting.mjs'],
  'POLICY-008': ['src/protocol-control.mjs'],
  'POLICY-009': ['src/protocol-feasibility.mjs', 'src/study-budget-feasibility.mjs'],
  'POLICY-010': ['src/clinical-trial-agreements.mjs'],
  'POLICY-011': ['src/training-delegation.mjs', 'src/delegation-audit-log.mjs'],
  'POLICY-012': ['src/document-versions.mjs', 'src/controlled-document-distribution.mjs'],
  'POLICY-013': ['src/deviation-workflows.mjs'],
  'POLICY-014': ['src/capa-workflows.mjs'],
  'POLICY-015': ['src/complaint-management.mjs', 'src/continuous-quality-improvement.mjs'],
  'POLICY-016': ['src/risk-assessments.mjs', 'src/risk-management-framework.mjs'],
  'POLICY-017': ['src/risk-assessments.mjs'],
  'POLICY-018': ['src/safety-events.mjs'],
  'POLICY-019': ['src/workforce-profile-readiness.mjs'],
  'POLICY-020': ['src/workforce-profile-readiness.mjs'],
  'POLICY-021': ['src/training-delegation.mjs', 'src/workforce-profile-readiness.mjs'],
  'POLICY-022': ['src/workforce-profile-readiness.mjs'],
  'POLICY-023': ['src/staff-training-gap-management.mjs', 'src/training-delegation.mjs'],
  'POLICY-024': ['src/workforce-profile-readiness.mjs'],
  'POLICY-025': ['src/workforce-profile-readiness.mjs'],
  'POLICY-026': ['src/workforce-profile-readiness.mjs'],
  'POLICY-027': ['src/participant-protection.mjs'],
  'POLICY-028': ['src/consent-materials.mjs'],
  'POLICY-029': ['src/participant-communications.mjs', 'src/export-controls.mjs', 'src/participant-data-sharing-consent.mjs'],
  'POLICY-030': ['src/information-management.mjs'],
  'POLICY-031': ['src/electronic-system-validation.mjs', 'src/security-privacy-readiness.mjs'],
  'POLICY-032': ['src/availability-recovery-readiness.mjs'],
  'POLICY-033': ['src/facility-product-readiness.mjs'],
  'POLICY-034': ['src/equipment-calibration-readiness.mjs'],
  'POLICY-035': ['src/clinical-trial-product-accountability.mjs'],
  'POLICY-036': ['src/kpi-management.mjs'],
  'POLICY-037': ['src/internal-audits.mjs', 'src/site-self-assessments.mjs', 'src/monitoring-visits.mjs'],
  'POLICY-038': ['src/records-retention-disposition.mjs'],
  'POLICY-039': ['src/access-revocation.mjs', 'src/tenant-isolation.mjs'],
  'POLICY-040': ['src/exochain-anchoring.mjs'],
  'PROCEDURE-001': ['src/site-profile-management.mjs', 'src/site-qms-passport.mjs'],
  'PROCEDURE-002': ['src/standards-control-library.mjs', 'src/qms-control-approvals.mjs'],
  'PROCEDURE-003': ['src/site-self-assessments.mjs'],
  'PROCEDURE-004': ['src/protocol-feasibility.mjs'],
  'PROCEDURE-005': ['src/risk-assessments.mjs'],
  'PROCEDURE-006': ['src/readiness-gates.mjs'],
  'PROCEDURE-007': ['src/consent-materials.mjs'],
  'PROCEDURE-008': ['src/clinical-trust-workflows.mjs', 'src/participant-communications.mjs'],
  'PROCEDURE-009': ['src/deviation-workflows.mjs'],
  'PROCEDURE-010': ['src/safety-events.mjs'],
  'PROCEDURE-011': ['src/capa-workflows.mjs'],
  'PROCEDURE-012': ['src/internal-audits.mjs'],
  'PROCEDURE-013': ['src/staff-training-gap-management.mjs'],
  'PROCEDURE-014': ['src/training-delegation.mjs', 'src/delegation-audit-log.mjs'],
  'PROCEDURE-015': ['src/concern-reporting.mjs'],
  'PROCEDURE-016': ['src/diligence-exports.mjs', 'src/export-controls.mjs', 'src/sponsor-cro-request-management.mjs'],
  'RULE-001': ['src/readiness-gates.mjs'],
  'RULE-002': ['src/consent-materials.mjs', 'src/controlled-document-distribution.mjs'],
  'RULE-003': ['src/training-delegation.mjs'],
  'RULE-004': ['src/training-delegation.mjs', 'src/access-revocation.mjs'],
  'RULE-005': ['src/decision-forum-escalation-engine.mjs'],
  'RULE-006': ['src/readiness-gates.mjs', 'src/evidence-scoring.mjs'],
  'RULE-007': ['src/ai-control-review.mjs', 'src/verified-human-provider.mjs'],
  'RULE-008': ['src/conflict-disclosures.mjs'],
  'RULE-009': ['src/emergency-actions.mjs'],
  'RULE-010': ['src/exochain-anchoring.mjs', 'src/trust-adapter.mjs'],
  'RULE-011': ['src/information-management.mjs', 'src/audit-logs.mjs'],
  'RULE-012': ['src/capa-workflows.mjs'],
  'RULE-013': ['src/readiness-gates.mjs'],
  'RULE-014': ['src/tamper-evidence-ledger.mjs', 'src/auditability-trails.mjs'],
  'RULE-015': ['src/access-revocation.mjs'],
};

const SOURCE_SECTION_BY_FAMILY = {
  policy: 'cyber_medica_qms_prd_master.md#core-policies',
  procedure: 'cyber_medica_qms_prd_master.md#core-procedures',
  rule: 'cyber_medica_qms_prd_master.md#governance-rules',
};

async function loadPolicyProcedureRuleTraceability() {
  try {
    return await import('../src/policy-procedure-rule-traceability.mjs');
  } catch (error) {
    assert.fail(`CyberMedica policy/procedure/rule traceability module must exist and load: ${error.message}`);
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

function itemFamily(itemId) {
  if (itemId.startsWith('POLICY-')) {
    return 'policy';
  }
  if (itemId.startsWith('PROCEDURE-')) {
    return 'procedure';
  }
  return 'rule';
}

function row(itemId, index, overrides = {}) {
  const moduleRefs = MODULE_REFS_BY_ITEM[itemId] ?? ['src/readiness-gates.mjs'];
  const family = itemFamily(itemId);
  const digestValues = [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2, DIGEST_3];
  return {
    itemId,
    itemFamily: family,
    sourceRef: `${SOURCE_SECTION_BY_FAMILY[family]}#${itemId.toLowerCase()}`,
    implementationStatus: 'implemented',
    moduleRefs,
    testRefs: moduleRefs.map((moduleRef) => moduleRef.replace('src/', 'tests/').replace('.mjs', '.test.mjs')),
    evidenceHashes: [digestValues[index % digestValues.length], digestValues[(index + 1) % digestValues.length]],
    linkedRequirementRefs: [`CM-QMS-${itemId}`, 'cybermedica_2_0_sandy_seven_layer_master_prd.md#appendix-a'],
    ownerRoleRefs: ['quality_manager', 'site_leader'],
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1802000100000 + index, logical: index % 5 },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    ...overrides,
  };
}

function allRows() {
  return [...REQUIRED_POLICY_IDS, ...REQUIRED_PROCEDURE_IDS, ...REQUIRED_RULE_IDS].map((itemId, index) =>
    row(itemId, index),
  );
}

function traceabilityInput(overrides = {}) {
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
      permissions: ['policy_procedure_rule_traceability_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    traceabilityPolicy: {
      policyRef: 'policy-procedure-rule-traceability-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredPolicyIds: REQUIRED_POLICY_IDS,
      requiredProcedureIds: REQUIRED_PROCEDURE_IDS,
      requiredRuleIds: REQUIRED_RULE_IDS,
      requiredSourceRefs: REQUIRED_SOURCE_REFS,
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
      evaluatedAtHlc: { physicalMs: 1802000000000, logical: 0 },
    },
    traceabilityCycle: {
      registerRef: 'policy-procedure-rule-register-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1802000050000, logical: 0 },
      compiledAtHlc: { physicalMs: 1802000100000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1802000200000, logical: 0 },
      validationRecordedAtHlc: { physicalMs: 1802000300000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1802000400000, logical: 0 },
      metadataOnly: true,
      protectedContentExcluded: true,
      productionTrustClaim: false,
    },
    traceabilityRows: allRows(),
    validationEvidence: {
      commandRefs: ['node --test tests/policy-procedure-rule-traceability.test.mjs', 'npm run quality'],
      commandsPassed: true,
      testCount: 710,
      coverageLineBasisPoints: 9854,
      sourceGuardPassed: true,
      docsUpdated: true,
      noExochainSourceModified: true,
      moduleManifestHash: DIGEST_C,
      testManifestHash: DIGEST_D,
      evidenceHash: DIGEST_E,
      recordedAtHlc: { physicalMs: 1802000300000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'policy_procedure_rule_traceability_accepted_inactive_trust',
      decisionHash: DIGEST_F,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1802000200000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'policy-procedure-rule-traceability-audit-alpha',
      auditRecordHash: DIGEST_1,
      receiptRecordedAtHlc: { physicalMs: 1802000400000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_2,
      limitationHashes: [DIGEST_3],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_4,
  };
  return mergeDeep(base, overrides);
}

test('policy procedure rule traceability covers all PRD control items deterministically', async () => {
  const { evaluatePolicyProcedureRuleTraceability } = await loadPolicyProcedureRuleTraceability();

  const resultA = evaluatePolicyProcedureRuleTraceability(traceabilityInput());
  const resultB = evaluatePolicyProcedureRuleTraceability(
    traceabilityInput({
      traceabilityPolicy: {
        requiredPolicyIds: [...REQUIRED_POLICY_IDS].reverse(),
        requiredProcedureIds: [...REQUIRED_PROCEDURE_IDS].reverse(),
        requiredRuleIds: [...REQUIRED_RULE_IDS].reverse(),
        requiredSourceRefs: [...REQUIRED_SOURCE_REFS].reverse(),
      },
      traceabilityRows: allRows()
        .map((item) => ({
          ...item,
          moduleRefs: [...item.moduleRefs].reverse(),
          testRefs: [...item.testRefs].reverse(),
          evidenceHashes: [...item.evidenceHashes].reverse(),
          linkedRequirementRefs: [...item.linkedRequirementRefs].reverse(),
          ownerRoleRefs: [...item.ownerRoleRefs].reverse(),
        }))
        .reverse(),
    }),
  );

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.deepEqual(resultA.reasons, []);
  assert.equal(resultA.trustState, 'inactive');
  assert.equal(resultA.exochainProductionClaim, false);
  assert.equal(resultA.traceabilityRegister.coverageSummary.policyCount, 40);
  assert.equal(resultA.traceabilityRegister.coverageSummary.procedureCount, 16);
  assert.equal(resultA.traceabilityRegister.coverageSummary.ruleCount, 15);
  assert.equal(resultA.traceabilityRegister.coverageSummary.totalItemCount, 71);
  assert.deepEqual(resultA.traceabilityRegister.itemFamiliesCovered, ['policy', 'procedure', 'rule']);
  assert.deepEqual(resultA.traceabilityRegister.policyIds, REQUIRED_POLICY_IDS);
  assert.deepEqual(resultA.traceabilityRegister.procedureIds, REQUIRED_PROCEDURE_IDS);
  assert.deepEqual(resultA.traceabilityRegister.ruleIds, REQUIRED_RULE_IDS);
  assert.equal(resultA.traceabilityRegister.registerHash, resultB.traceabilityRegister.registerHash);
  assert.equal(resultA.receipt.receiptId, resultB.receipt.receiptId);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'policy_procedure_rule_traceability_register');
  assert.equal(resultA.receipt.trustState, 'inactive');
  assert.equal(resultA.receipt.exochainProductionClaim, false);
  assert.doesNotMatch(JSON.stringify(resultA), /root-backed production authority|raw policy text|participant alice/iu);
});

test('policy procedure rule traceability requires Policy 29 standalone data sharing consent mapping', async () => {
  const { evaluatePolicyProcedureRuleTraceability } = await loadPolicyProcedureRuleTraceability();

  const result = evaluatePolicyProcedureRuleTraceability(traceabilityInput());
  const policy29Row = result.traceabilityRegister.traceabilityRows.find((entry) => entry.itemId === 'POLICY-029');

  assert.deepEqual(policy29Row.moduleRefs, [
    'src/export-controls.mjs',
    'src/participant-communications.mjs',
    'src/participant-data-sharing-consent.mjs',
  ]);
  assert.deepEqual(policy29Row.testRefs, [
    'tests/export-controls.test.mjs',
    'tests/participant-communications.test.mjs',
    'tests/participant-data-sharing-consent.test.mjs',
  ]);

  const denied = evaluatePolicyProcedureRuleTraceability(
    traceabilityInput({
      traceabilityRows: allRows().map((item) =>
        item.itemId === 'POLICY-029'
          ? {
              ...item,
              moduleRefs: ['src/export-controls.mjs', 'src/participant-communications.mjs'],
              testRefs: ['tests/export-controls.test.mjs', 'tests/participant-communications.test.mjs'],
            }
          : item,
      ),
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(
    denied.reasons.includes(
      'row_required_module_ref_missing:POLICY-029:src/participant-data-sharing-consent.mjs',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'row_required_test_ref_missing:POLICY-029:tests/participant-data-sharing-consent.test.mjs',
    ),
  );
});

test('policy procedure rule traceability requires Policy 16 standalone risk management framework mapping', async () => {
  const { evaluatePolicyProcedureRuleTraceability } = await loadPolicyProcedureRuleTraceability();

  const result = evaluatePolicyProcedureRuleTraceability(traceabilityInput());
  const policy16Row = result.traceabilityRegister.traceabilityRows.find((entry) => entry.itemId === 'POLICY-016');

  assert.deepEqual(policy16Row.moduleRefs, [
    'src/risk-assessments.mjs',
    'src/risk-management-framework.mjs',
  ]);
  assert.deepEqual(policy16Row.testRefs, [
    'tests/risk-assessments.test.mjs',
    'tests/risk-management-framework.test.mjs',
  ]);

  const denied = evaluatePolicyProcedureRuleTraceability(
    traceabilityInput({
      traceabilityRows: allRows().map((item) =>
        item.itemId === 'POLICY-016'
          ? {
              ...item,
              moduleRefs: ['src/risk-assessments.mjs'],
              testRefs: ['tests/risk-assessments.test.mjs'],
            }
          : item,
      ),
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(
    denied.reasons.includes(
      'row_required_module_ref_missing:POLICY-016:src/risk-management-framework.mjs',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'row_required_test_ref_missing:POLICY-016:tests/risk-management-framework.test.mjs',
    ),
  );
});

test('policy procedure rule traceability requires Policy 15 complaint management to CQI mapping', async () => {
  const { evaluatePolicyProcedureRuleTraceability } = await loadPolicyProcedureRuleTraceability();

  const result = evaluatePolicyProcedureRuleTraceability(traceabilityInput());
  const policy15Row = result.traceabilityRegister.traceabilityRows.find((entry) => entry.itemId === 'POLICY-015');

  assert.deepEqual(policy15Row.moduleRefs, [
    'src/complaint-management.mjs',
    'src/continuous-quality-improvement.mjs',
  ]);
  assert.deepEqual(policy15Row.testRefs, [
    'tests/complaint-management.test.mjs',
    'tests/continuous-quality-improvement.test.mjs',
  ]);

  const denied = evaluatePolicyProcedureRuleTraceability(
    traceabilityInput({
      traceabilityRows: allRows().map((item) =>
        item.itemId === 'POLICY-015'
          ? {
              ...item,
              moduleRefs: ['src/continuous-quality-improvement.mjs'],
              testRefs: ['tests/continuous-quality-improvement.test.mjs'],
            }
          : item,
      ),
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(
    denied.reasons.includes(
      'row_required_module_ref_missing:POLICY-015:src/complaint-management.mjs',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'row_required_test_ref_missing:POLICY-015:tests/complaint-management.test.mjs',
    ),
  );
});

test('policy procedure rule traceability requires Procedure 16 controlled Sponsor/CRO request mapping', async () => {
  const { evaluatePolicyProcedureRuleTraceability } = await loadPolicyProcedureRuleTraceability();

  const result = evaluatePolicyProcedureRuleTraceability(traceabilityInput());
  const procedure16Row = result.traceabilityRegister.traceabilityRows.find((entry) => entry.itemId === 'PROCEDURE-016');

  assert.deepEqual(procedure16Row.moduleRefs, [
    'src/diligence-exports.mjs',
    'src/export-controls.mjs',
    'src/sponsor-cro-request-management.mjs',
  ]);
  assert.deepEqual(procedure16Row.testRefs, [
    'tests/diligence-exports.test.mjs',
    'tests/export-controls.test.mjs',
    'tests/sponsor-cro-request-management.test.mjs',
  ]);

  const denied = evaluatePolicyProcedureRuleTraceability(
    traceabilityInput({
      traceabilityRows: allRows().map((item) =>
        item.itemId === 'PROCEDURE-016'
          ? {
              ...item,
              moduleRefs: ['src/diligence-exports.mjs', 'src/export-controls.mjs'],
              testRefs: ['tests/diligence-exports.test.mjs', 'tests/export-controls.test.mjs'],
            }
          : item,
      ),
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(
    denied.reasons.includes(
      'row_required_module_ref_missing:PROCEDURE-016:src/sponsor-cro-request-management.mjs',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'row_required_test_ref_missing:PROCEDURE-016:tests/sponsor-cro-request-management.test.mjs',
    ),
  );
});

test('policy procedure rule traceability requires Policy 37 monitoring visit assessment mapping', async () => {
  const { evaluatePolicyProcedureRuleTraceability } = await loadPolicyProcedureRuleTraceability();

  const result = evaluatePolicyProcedureRuleTraceability(traceabilityInput());
  const policy37Row = result.traceabilityRegister.traceabilityRows.find((entry) => entry.itemId === 'POLICY-037');

  assert.deepEqual(policy37Row.moduleRefs, [
    'src/internal-audits.mjs',
    'src/monitoring-visits.mjs',
    'src/site-self-assessments.mjs',
  ]);
  assert.deepEqual(policy37Row.testRefs, [
    'tests/internal-audits.test.mjs',
    'tests/monitoring-visits.test.mjs',
    'tests/site-self-assessments.test.mjs',
  ]);

  const denied = evaluatePolicyProcedureRuleTraceability(
    traceabilityInput({
      traceabilityRows: allRows().map((item) =>
        item.itemId === 'POLICY-037'
          ? {
              ...item,
              moduleRefs: ['src/internal-audits.mjs', 'src/site-self-assessments.mjs'],
              testRefs: ['tests/internal-audits.test.mjs', 'tests/site-self-assessments.test.mjs'],
            }
          : item,
      ),
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(
    denied.reasons.includes(
      'row_required_module_ref_missing:POLICY-037:src/monitoring-visits.mjs',
    ),
  );
  assert.ok(
    denied.reasons.includes(
      'row_required_test_ref_missing:POLICY-037:tests/monitoring-visits.test.mjs',
    ),
  );
});

test('policy procedure rule traceability requires access-revocation mapping for Policy 39 and Rule 15', async () => {
  const { evaluatePolicyProcedureRuleTraceability } = await loadPolicyProcedureRuleTraceability();

  const result = evaluatePolicyProcedureRuleTraceability(traceabilityInput());
  const policy39Row = result.traceabilityRegister.traceabilityRows.find((entry) => entry.itemId === 'POLICY-039');
  const rule15Row = result.traceabilityRegister.traceabilityRows.find((entry) => entry.itemId === 'RULE-015');

  assert.deepEqual(policy39Row.moduleRefs, ['src/access-revocation.mjs', 'src/tenant-isolation.mjs']);
  assert.deepEqual(policy39Row.testRefs, ['tests/access-revocation.test.mjs', 'tests/tenant-isolation.test.mjs']);
  assert.deepEqual(rule15Row.moduleRefs, ['src/access-revocation.mjs']);
  assert.deepEqual(rule15Row.testRefs, ['tests/access-revocation.test.mjs']);

  const denied = evaluatePolicyProcedureRuleTraceability(
    traceabilityInput({
      traceabilityRows: allRows().map((item) => {
        if (item.itemId === 'POLICY-039') {
          return {
            ...item,
            moduleRefs: ['src/tenant-isolation.mjs'],
            testRefs: ['tests/tenant-isolation.test.mjs'],
          };
        }
        if (item.itemId === 'RULE-015') {
          return {
            ...item,
            moduleRefs: ['src/readiness-gates.mjs'],
            testRefs: ['tests/readiness-gates.test.mjs'],
          };
        }
        return item;
      }),
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('row_required_module_ref_missing:POLICY-039:src/access-revocation.mjs'));
  assert.ok(denied.reasons.includes('row_required_test_ref_missing:POLICY-039:tests/access-revocation.test.mjs'));
  assert.ok(denied.reasons.includes('row_required_module_ref_missing:RULE-015:src/access-revocation.mjs'));
  assert.ok(denied.reasons.includes('row_required_test_ref_missing:RULE-015:tests/access-revocation.test.mjs'));
});

test('policy procedure rule traceability fails closed for missing rows and unsafe authority', async () => {
  const { evaluatePolicyProcedureRuleTraceability } = await loadPolicyProcedureRuleTraceability();
  const denied = evaluatePolicyProcedureRuleTraceability(
    traceabilityInput({
      actor: { did: 'did:exo:traceability-ai-alpha', kind: 'ai_agent' },
      authority: {
        valid: true,
        revoked: false,
        expired: false,
        permissions: ['read'],
        authorityChainHash: DIGEST_A,
      },
      traceabilityRows: allRows()
        .filter((item) => item.itemId !== 'POLICY-040' && item.itemId !== 'PROCEDURE-016' && item.itemId !== 'RULE-015')
        .concat(
          row('POLICY-999', 72, {
            itemFamily: 'policy',
            moduleRefs: [],
            testRefs: [],
            evidenceHashes: ['not-a-digest'],
            linkedRequirementRefs: [],
            ownerRoleRefs: [],
            reviewedByHuman: false,
            reviewedAtHlc: { physicalMs: 1802000500000, logical: 0 },
            metadataOnly: false,
            protectedContentExcluded: false,
            productionTrustClaim: true,
          }),
        ),
      validationEvidence: {
        commandsPassed: false,
        sourceGuardPassed: false,
        docsUpdated: false,
        noExochainSourceModified: false,
        coverageLineBasisPoints: 8999,
        evidenceHash: '',
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
  assert.equal(denied.traceabilityRegister, null);
  assert.equal(denied.receipt, null);
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('traceability_authority_missing'));
  assert.ok(denied.reasons.includes('traceability_row_missing:POLICY-040'));
  assert.ok(denied.reasons.includes('traceability_row_missing:PROCEDURE-016'));
  assert.ok(denied.reasons.includes('traceability_row_missing:RULE-015'));
  assert.ok(denied.reasons.includes('traceability_row_unsupported:POLICY-999'));
  assert.ok(denied.reasons.includes('row_module_refs_absent:POLICY-999'));
  assert.ok(denied.reasons.includes('row_test_refs_absent:POLICY-999'));
  assert.ok(denied.reasons.includes('row_evidence_hash_invalid:POLICY-999'));
  assert.ok(denied.reasons.includes('row_human_review_absent:POLICY-999'));
  assert.ok(denied.reasons.includes('row_review_after_cycle_human_review:POLICY-999'));
  assert.ok(denied.reasons.includes('row_metadata_boundary_invalid:POLICY-999'));
  assert.ok(denied.reasons.includes('row_production_trust_claim_forbidden:POLICY-999'));
  assert.ok(denied.reasons.includes('validation_commands_failed'));
  assert.ok(denied.reasons.includes('validation_source_guard_failed'));
  assert.ok(denied.reasons.includes('validation_exochain_source_modified'));
  assert.ok(denied.reasons.includes('validation_coverage_below_threshold'));
  assert.ok(denied.reasons.includes('human_review_final_authority_invalid'));
});

test('policy procedure rule traceability rejects raw content and secrets before receipts', async () => {
  const { evaluatePolicyProcedureRuleTraceability, ProtectedContentError } = await loadPolicyProcedureRuleTraceability();

  assert.throws(
    () =>
      evaluatePolicyProcedureRuleTraceability(
        traceabilityInput({
          traceabilityRows: [
            ...allRows(),
            {
              itemId: 'POLICY-999',
              itemFamily: 'policy',
              rawPolicyText: 'full policy wording must stay out of traceability receipts',
            },
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluatePolicyProcedureRuleTraceability(
        traceabilityInput({
          validationEvidence: {
            serviceToken: 'prod-secret',
          },
        }),
      ),
    ProtectedContentError,
  );
}
);
