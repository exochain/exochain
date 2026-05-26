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

const REQUIRED_DOCTRINE_LAYERS = [
  'data',
  'deployment',
  'doctrine',
  'documentation',
  'domain',
  'doors',
  'drift',
  'ground_truth',
];

const REQUIRED_ACCEPTANCE_OUTCOME_IDS = [
  'ai_control_findings_reviewed',
  'all_material_actions_auditable',
  'audit_logs_hash_chained',
  'audits_assessments_locked',
  'capa_effectiveness_managed',
  'consent_authority_receipts_generated',
  'consent_process_documented',
  'consent_versions_controlled',
  'control_library_managed',
  'decision_receipts_generated',
  'delegation_lifecycle_governed',
  'deviation_lifecycle_closed',
  'diligence_packets_controlled',
  'emergency_actions_retrospective_reviewed',
  'enrollment_gate_authorized',
  'evidence_chain_of_custody_maintained',
  'evidence_lifecycle_governed',
  'evidence_receipts_generated',
  'facility_equipment_readiness_tracked',
  'human_review_decisions_governed',
  'kpi_decision_use_governed',
  'product_accountability_maintained',
  'protected_exports_excluded',
  'protocol_feasibility_assessed',
  'qms_passport_maintained',
  'safety_event_workflows_tracked',
  'self_assessment_completed',
  'startup_risk_approved',
  'training_blocks_delegation',
  'trial_launch_gate_authorized',
];

const REQUIRED_CONTEXT_DOC_REFS = [
  'cybermedica_2_0_sandy_seven_layer_master_prd.md#acceptance-criteria',
  'docs/context/CYBERMEDICA_PRODUCTION_TRUST_ACTIVATION_GATES.md',
  'docs/context/EXOCHAIN_CONTEXT_SEED_FOR_CYBERMEDICA.md',
  'docs/context/EXOCHAIN_TO_CYBERMEDICA_INTEGRATION_MAP.md',
];

async function loadPrdAcceptanceOutcomes() {
  try {
    return await import('../src/prd-acceptance-outcomes.mjs');
  } catch (error) {
    assert.fail(`CyberMedica PRD acceptance outcome module must exist and load: ${error.message}`);
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

function outcomeRow(outcomeId, index, overrides = {}) {
  const moduleByOutcome = {
    ai_control_findings_reviewed: ['src/ai-control-review.mjs'],
    all_material_actions_auditable: ['src/auditability-trails.mjs', 'src/decision-forum-matters.mjs'],
    audit_logs_hash_chained: ['src/audit-logs.mjs', 'src/tamper-evidence-ledger.mjs'],
    audits_assessments_locked: ['src/internal-audits.mjs', 'src/site-self-assessments.mjs'],
    capa_effectiveness_managed: ['src/capa-workflows.mjs'],
    consent_authority_receipts_generated: ['src/exochain-anchoring.mjs', 'src/training-delegation.mjs'],
    consent_process_documented: ['src/consent-materials.mjs'],
    consent_versions_controlled: ['src/consent-materials.mjs', 'src/participant-communications.mjs'],
    control_library_managed: ['src/standards-control-library.mjs'],
    decision_receipts_generated: ['src/decision-forum-matters.mjs'],
    delegation_lifecycle_governed: ['src/delegation-audit-log.mjs', 'src/training-delegation.mjs'],
    deviation_lifecycle_closed: ['src/deviation-workflows.mjs'],
    diligence_packets_controlled: ['src/diligence-exports.mjs', 'src/export-controls.mjs'],
    emergency_actions_retrospective_reviewed: ['src/emergency-actions.mjs'],
    enrollment_gate_authorized: ['src/readiness-gates.mjs'],
    evidence_chain_of_custody_maintained: ['src/evidence-custody.mjs'],
    evidence_lifecycle_governed: ['src/evidence-intake.mjs', 'src/evidence-linking.mjs'],
    evidence_receipts_generated: ['src/audit-event-receipts.mjs', 'src/evidence-custody.mjs'],
    facility_equipment_readiness_tracked: ['src/facility-product-readiness.mjs'],
    human_review_decisions_governed: ['src/decision-forum-matters.mjs', 'src/verified-human-provider.mjs'],
    kpi_decision_use_governed: ['src/kpi-management.mjs'],
    product_accountability_maintained: ['src/clinical-trial-product-accountability.mjs'],
    protected_exports_excluded: ['src/export-controls.mjs', 'src/structured-data-exports.mjs'],
    protocol_feasibility_assessed: ['src/protocol-feasibility.mjs', 'src/protocol-intake.mjs'],
    qms_passport_maintained: ['src/site-qms-passport.mjs'],
    safety_event_workflows_tracked: ['src/safety-events.mjs'],
    self_assessment_completed: ['src/site-self-assessments.mjs'],
    startup_risk_approved: ['src/risk-assessments.mjs'],
    training_blocks_delegation: ['src/training-delegation.mjs', 'src/workforce-profile-readiness.mjs'],
    trial_launch_gate_authorized: ['src/readiness-gates.mjs', 'src/risk-assessments.mjs'],
  };
  const moduleRefs = moduleByOutcome[outcomeId] ?? ['src/release-readiness-matrix.mjs'];
  return {
    outcomeId,
    doctrineLayer: REQUIRED_DOCTRINE_LAYERS[index % REQUIRED_DOCTRINE_LAYERS.length],
    sourceRef: 'cybermedica_2_0_sandy_seven_layer_master_prd.md#acceptance-criteria',
    capabilityRef: `prd-acceptance-${String(index + 1).padStart(2, '0')}`,
    acceptanceStatus: 'supported_inactive_trust',
    moduleRefs,
    testRefs: moduleRefs.map((moduleRef) => moduleRef.replace('src/', 'tests/').replace('.mjs', '.test.mjs')),
    evidenceHashes: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    validationCommandRefs: ['npm run quality'],
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800002100000, logical: index },
    metadataOnly: true,
    protectedContentExcluded: true,
    productionTrustClaim: false,
    blocksBaselineDevelopment: false,
    ...overrides,
  };
}

function outcomeRows() {
  return REQUIRED_ACCEPTANCE_OUTCOME_IDS.map((outcomeId, index) => outcomeRow(outcomeId, index));
}

function acceptanceInput(overrides = {}) {
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
      permissions: ['prd_acceptance_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    acceptancePolicy: {
      policyRef: 'prd-acceptance-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredOutcomeIds: REQUIRED_ACCEPTANCE_OUTCOME_IDS,
      requiredDoctrineLayers: REQUIRED_DOCTRINE_LAYERS,
      requiredContextDocRefs: REQUIRED_CONTEXT_DOC_REFS,
      metadataOnly: true,
      protectedContentExcluded: true,
      rootVerificationRequiredForTrustClaims: true,
      evaluatedAtHlc: { physicalMs: 1800001900000, logical: 0 },
    },
    acceptanceCycle: {
      acceptanceRef: 'prd-acceptance-baseline-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800002000000, logical: 0 },
      matrixCompiledAtHlc: { physicalMs: 1800002050000, logical: 0 },
      humanReviewedAtHlc: { physicalMs: 1800002200000, logical: 0 },
      validationRecordedAtHlc: { physicalMs: 1800002300000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800002400000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    outcomeRows: outcomeRows(),
    validationEvidence: {
      commandRefs: ['node --test tests/prd-acceptance-outcomes.test.mjs', 'npm run quality'],
      commandsPassed: true,
      testCount: 596,
      coverageLineBasisPoints: 9886,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      docsUpdated: true,
      moduleManifestHash: DIGEST_C,
      testManifestHash: DIGEST_D,
      evidenceHash: DIGEST_E,
      recordedAtHlc: { physicalMs: 1800002300000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'prd_acceptance_accepted_inactive_trust',
      decisionHash: DIGEST_F,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1800002200000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'prd-acceptance-audit-alpha',
      auditRecordHash: DIGEST_1,
      receiptRecordedAtHlc: { physicalMs: 1800002400000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      reviewedByHuman: true,
      recommendationHash: DIGEST_2,
      limitationHashes: [DIGEST_3],
    },
    custodyDigest: DIGEST_4,
  };
  return mergeDeep(base, overrides);
}

test('PRD acceptance outcomes create deterministic inactive-trust coverage for all 30 end-to-end outcomes', async () => {
  const { evaluatePrdAcceptanceOutcomes } = await loadPrdAcceptanceOutcomes();

  const resultA = evaluatePrdAcceptanceOutcomes(acceptanceInput());
  const resultB = evaluatePrdAcceptanceOutcomes({
    ...acceptanceInput(),
    acceptancePolicy: {
      ...acceptanceInput().acceptancePolicy,
      requiredOutcomeIds: [...REQUIRED_ACCEPTANCE_OUTCOME_IDS].reverse(),
      requiredDoctrineLayers: [...REQUIRED_DOCTRINE_LAYERS].reverse(),
      requiredContextDocRefs: [...REQUIRED_CONTEXT_DOC_REFS].reverse(),
    },
    outcomeRows: [...outcomeRows()].reverse(),
  });

  assert.equal(resultA.decision, 'permitted');
  assert.equal(resultA.failClosed, false);
  assert.equal(resultA.prdAcceptanceOutcomes.trustState, 'inactive');
  assert.equal(resultA.prdAcceptanceOutcomes.exochainProductionClaim, false);
  assert.equal(resultA.prdAcceptanceOutcomes.acceptanceSummary.totalOutcomeCount, 30);
  assert.equal(resultA.prdAcceptanceOutcomes.acceptanceSummary.supportedOutcomeCount, 30);
  assert.deepEqual(resultA.prdAcceptanceOutcomes.outcomeIdsCovered, REQUIRED_ACCEPTANCE_OUTCOME_IDS);
  assert.deepEqual(resultA.prdAcceptanceOutcomes.baselineBlockedOutcomeIds, []);
  assert.equal(resultA.receipt.anchorPayload.artifactType, 'prd_acceptance_outcome_matrix');
  assert.deepEqual(resultA, resultB);
});

test('PRD acceptance outcomes fail closed for missing unsupported or incomplete outcome rows', async () => {
  const { evaluatePrdAcceptanceOutcomes } = await loadPrdAcceptanceOutcomes();
  const input = acceptanceInput({
    outcomeRows: [
      ...outcomeRows().slice(1),
      outcomeRow('unsupported_outcome', 99, {
        moduleRefs: [],
        testRefs: [],
        evidenceHashes: [],
        validationCommandRefs: [],
        reviewedByHuman: false,
        metadataOnly: false,
        protectedContentExcluded: false,
        blocksBaselineDevelopment: true,
        acceptanceStatus: 'draft',
      }),
    ],
  });

  const result = evaluatePrdAcceptanceOutcomes(input);

  assert.equal(result.decision, 'denied');
  assert.equal(result.failClosed, true);
  assert.ok(result.reasons.includes('acceptance_outcome_missing:ai_control_findings_reviewed'));
  assert.ok(result.reasons.includes('acceptance_outcome_unsupported:unsupported_outcome'));
  assert.ok(result.reasons.includes('acceptance_module_refs_absent:unsupported_outcome'));
  assert.ok(result.reasons.includes('acceptance_test_refs_absent:unsupported_outcome'));
  assert.ok(result.reasons.includes('acceptance_evidence_hashes_absent:unsupported_outcome'));
  assert.ok(result.reasons.includes('acceptance_validation_commands_absent:unsupported_outcome'));
  assert.ok(result.reasons.includes('acceptance_human_review_absent:unsupported_outcome'));
  assert.ok(result.reasons.includes('acceptance_blocks_baseline:unsupported_outcome'));
  assert.equal(result.prdAcceptanceOutcomes, null);
  assert.equal(result.receipt, null);
});

test('PRD acceptance outcomes reject production trust claims AI authority and unsafe HLC ordering', async () => {
  const { evaluatePrdAcceptanceOutcomes } = await loadPrdAcceptanceOutcomes();
  const input = acceptanceInput({
    actor: { ...acceptanceInput().actor, kind: 'ai_agent' },
    acceptanceCycle: {
      ...acceptanceInput().acceptanceCycle,
      productionTrustClaim: true,
      matrixCompiledAtHlc: { physicalMs: 1800001990000, logical: 0 },
    },
    outcomeRows: outcomeRows().map((row, index) =>
      index === 0
        ? {
            ...row,
            productionTrustClaim: true,
            reviewedAtHlc: { physicalMs: 1800001980000, logical: 0 },
          }
        : row,
    ),
    humanReview: {
      ...acceptanceInput().humanReview,
      finalAuthority: 'ai',
      aiFinalAuthority: true,
      noProductionTrustClaim: false,
      reviewedAtHlc: { physicalMs: 1800002100000, logical: 0 },
    },
    validationEvidence: {
      ...acceptanceInput().validationEvidence,
      commandsPassed: false,
      noExochainSourceModified: false,
      docsUpdated: false,
      recordedAtHlc: { physicalMs: 1800002200000, logical: 0 },
    },
  });

  const result = evaluatePrdAcceptanceOutcomes(input);

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(result.reasons.includes('production_trust_claim_forbidden'));
  assert.ok(result.reasons.includes('acceptance_production_claim_forbidden:ai_control_findings_reviewed'));
  assert.ok(result.reasons.includes('acceptance_review_before_matrix:ai_control_findings_reviewed'));
  assert.ok(result.reasons.includes('validation_commands_not_passed'));
  assert.ok(result.reasons.includes('validation_exochain_read_only_absent'));
  assert.ok(result.reasons.includes('validation_docs_update_absent'));
  assert.ok(result.reasons.includes('human_review_authority_absent'));
  assert.ok(result.reasons.includes('human_review_production_trust_forbidden'));
});

test('PRD acceptance outcomes handle absent objects as fail-closed denial states', async () => {
  const { evaluatePrdAcceptanceOutcomes } = await loadPrdAcceptanceOutcomes();

  const result = evaluatePrdAcceptanceOutcomes({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:quality-manager-alpha', kind: 'human' },
    authority: { valid: false, permissions: [] },
  });

  assert.equal(result.decision, 'denied');
  assert.ok(result.reasons.includes('authority_chain_invalid'));
  assert.ok(result.reasons.includes('acceptance_policy_ref_absent'));
  assert.ok(result.reasons.includes('acceptance_cycle_ref_absent'));
  assert.ok(result.reasons.includes('acceptance_outcome_rows_absent'));
  assert.ok(result.reasons.includes('validation_evidence_absent'));
  assert.ok(result.reasons.includes('human_review_absent'));
  assert.ok(result.reasons.includes('acceptance_audit_record_ref_absent'));
  assert.ok(result.reasons.includes('custody_digest_invalid'));
});

test('PRD acceptance outcomes reject raw acceptance content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluatePrdAcceptanceOutcomes } = await loadPrdAcceptanceOutcomes();

  assert.throws(
    () =>
      evaluatePrdAcceptanceOutcomes({
        ...acceptanceInput(),
        outcomeRows: [
          {
            ...outcomeRows()[0],
            rawOutcomeText: 'Participant Alice Example must not enter PRD acceptance receipts.',
          },
          ...outcomeRows().slice(1),
        ],
      }),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluatePrdAcceptanceOutcomes({
        ...acceptanceInput(),
        validationEvidence: {
          ...acceptanceInput().validationEvidence,
          rootSigningKey: 'root signing key material must never be accepted',
        },
      }),
    ProtectedContentError,
  );
});
