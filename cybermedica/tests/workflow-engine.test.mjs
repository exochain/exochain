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

const REQUIRED_WORKFLOW_DOMAINS = [
  'approval',
  'audit',
  'capa',
  'consent',
  'deviation',
  'enrollment',
  'export',
  'gate',
  'launch',
  'policy',
  'procedure',
  'risk',
];

async function loadWorkflowEngine() {
  try {
    return await import('../src/workflow-engine.mjs');
  } catch (error) {
    assert.fail(`CyberMedica workflow engine module must exist and load: ${error.message}`);
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

function workflowDefinition(domain, index, overrides = {}) {
  return {
    workflowRef: `workflow-${domain}`,
    domain,
    versionRef: `workflow-${domain}:v1`,
    definitionHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D, DIGEST_E, DIGEST_F][index % 6],
    sourceRequirementRefs: [
      'cybermedica_2_0_sandy_seven_layer_master_prd.md:Deployment Backlog:workflow-engine',
    ],
    ownerRoleRefs: ['quality_manager', 'site_leader'],
    stepRefs: [`${domain}-intake`, `${domain}-review`, `${domain}-decision`],
    entryGateRefs: [`${domain}-entry-authority`],
    exitGateRefs: [`${domain}-exit-receipt`],
    humanReviewRequired: true,
    aiMayAssist: true,
    aiFinalAuthorityForbidden: true,
    boundedLoop: {
      enabled: domain === 'capa' || domain === 'deviation',
      maxIterations: domain === 'capa' || domain === 'deviation' ? 3 : 0,
      stopConditionRef: domain === 'capa' || domain === 'deviation' ? `${domain}-verified-effective` : null,
      escalationPathRef: domain === 'capa' || domain === 'deviation' ? `${domain}-decision-forum` : null,
      sameFailureEscalatesAfterCount: domain === 'capa' || domain === 'deviation' ? 2 : 0,
    },
    transitionPolicy: {
      authorityRequired: true,
      consentRequiredWhenParticipantAffecting: ['consent', 'enrollment'].includes(domain),
      decisionForumRequired: ['approval', 'capa', 'enrollment', 'gate', 'launch', 'policy'].includes(domain),
      receiptRequired: true,
      protectedPayloadProhibited: true,
      metadataOnly: true,
    },
    nodeOutputBoundary: {
      boundedUntrustedWorkflowNodeOutputs: true,
      nodeOutputCannotAuthorizeTrustClaims: true,
      nodeOutputCannotAuthorizeGitOperations: true,
      humanReviewRequiredForTransitions: true,
    },
    metadataOnly: true,
    protectedContentExcluded: true,
    reviewedByHuman: true,
    reviewedAtHlc: { physicalMs: 1800000100000, logical: index },
    ...overrides,
  };
}

function workflowDefinitions() {
  return REQUIRED_WORKFLOW_DOMAINS.map((domain, index) => workflowDefinition(domain, index));
}

function workflowEngineInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:workflow-owner-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'site_leader'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['workflow_engine_review', 'govern'],
      authorityChainHash: DIGEST_A,
    },
    enginePolicy: {
      policyRef: 'workflow-engine-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredWorkflowDomains: REQUIRED_WORKFLOW_DOMAINS,
      maxLoopIterations: 25,
      sameFailureEscalatesAfterCount: 2,
      requireBoundedUntrustedNodeOutputs: true,
      requireHumanFinalAuthority: true,
      requireMetadataOnlyDefinitions: true,
      protectedContentExcluded: true,
      rootVerificationRequiredForTrustClaims: true,
      evaluatedAtHlc: { physicalMs: 1800000000000, logical: 0 },
    },
    engineCycle: {
      cycleRef: 'workflow-engine-cycle-alpha',
      releaseCandidateRef: 'cybermedica-baseline-2026-05',
      openedAtHlc: { physicalMs: 1800000050000, logical: 0 },
      definitionsReviewedAtHlc: { physicalMs: 1800000200000, logical: 0 },
      validationRecordedAtHlc: { physicalMs: 1800000300000, logical: 0 },
      auditRecordedAtHlc: { physicalMs: 1800000400000, logical: 0 },
      productionTrustClaim: false,
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    workflowDefinitions: workflowDefinitions(),
    runtimeContract: {
      contractRef: 'workflow-runtime-contract-alpha',
      deterministicReducerHash: DIGEST_C,
      noSystemTime: true,
      noRandomness: true,
      noFloatingPoint: true,
      noRuntimeSecretMaterial: true,
      externalNodeOutputsTreatedAsUntrusted: true,
      idempotencyKeyRequired: true,
      replayProtectionRequired: true,
      receiptBoundaryHash: DIGEST_D,
      operationalStateSeparateFromReceipts: true,
      metadataOnly: true,
    },
    validationEvidence: {
      commandRefs: ['node --test tests/workflow-engine.test.mjs', 'npm run quality'],
      commandsPassed: true,
      testCount: 435,
      coverageLineBasisPoints: 9960,
      sourceGuardPassed: true,
      noExochainSourceModified: true,
      workflowManifestHash: DIGEST_E,
      evidenceHash: DIGEST_F,
      recordedAtHlc: { physicalMs: 1800000300000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'workflow_engine_ready_inactive_trust',
      decisionHash: DIGEST_1,
      finalAuthority: 'human',
      aiFinalAuthority: false,
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1800000200000, logical: 0 },
      metadataOnly: true,
    },
    auditRecord: {
      auditRecordRef: 'workflow-engine-audit-alpha',
      auditRecordHash: DIGEST_2,
      receiptRecordedAtHlc: { physicalMs: 1800000400000, logical: 0 },
      metadataOnly: true,
      includesProtectedContent: false,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_3,
      limitationHashes: [DIGEST_4],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_5,
  };
  return mergeDeep(base, overrides);
}

test('workflow engine module loads', async () => {
  const mod = await loadWorkflowEngine();
  assert.equal(typeof mod.evaluateWorkflowEngineReadiness, 'function');
});

test('workflow engine records deterministic inactive readiness for all deployment workflow domains', async () => {
  const { evaluateWorkflowEngineReadiness } = await loadWorkflowEngine();

  const first = evaluateWorkflowEngineReadiness(workflowEngineInput());
  const second = evaluateWorkflowEngineReadiness({
    ...workflowEngineInput(),
    enginePolicy: {
      ...workflowEngineInput().enginePolicy,
      requiredWorkflowDomains: [...workflowEngineInput().enginePolicy.requiredWorkflowDomains].reverse(),
    },
    workflowDefinitions: [...workflowEngineInput().workflowDefinitions].reverse(),
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.workflowEngine.engineReady, true);
  assert.equal(first.workflowEngine.productionActivationReady, false);
  assert.equal(first.workflowEngine.trustState, 'inactive');
  assert.equal(first.workflowEngine.exochainProductionClaim, false);
  assert.deepEqual(first.workflowEngine.workflowDomainsCovered, REQUIRED_WORKFLOW_DOMAINS);
  assert.equal(first.workflowEngine.coverageSummary.totalWorkflowCount, 12);
  assert.equal(first.workflowEngine.coverageSummary.boundedLoopCount, 2);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.deepEqual(first, second);
});

test('workflow engine fails closed for missing workflow domains and unbounded loops', async () => {
  const { evaluateWorkflowEngineReadiness } = await loadWorkflowEngine();

  const denied = evaluateWorkflowEngineReadiness(
    workflowEngineInput({
      workflowDefinitions: [
        ...workflowDefinitions().filter((entry) => entry.domain !== 'enrollment'),
        workflowDefinition('capa', 20, {
          workflowRef: 'workflow-capa-unbounded',
          boundedLoop: {
            enabled: true,
            maxIterations: 26,
            stopConditionRef: '',
            escalationPathRef: '',
            sameFailureEscalatesAfterCount: 3,
          },
        }),
      ],
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('workflow_domain_missing:enrollment'));
  assert.ok(denied.reasons.includes('workflow_id_duplicate:workflow-capa'));
  assert.ok(denied.reasons.includes('workflow_loop_max_iterations_invalid:workflow-capa-unbounded'));
  assert.ok(denied.reasons.includes('workflow_loop_stop_condition_absent:workflow-capa-unbounded'));
  assert.ok(denied.reasons.includes('workflow_loop_escalation_absent:workflow-capa-unbounded'));
  assert.ok(denied.reasons.includes('workflow_loop_repeated_failure_limit_invalid:workflow-capa-unbounded'));
});

test('workflow engine denies transition contracts that bypass authority consent governance or receipts', async () => {
  const { evaluateWorkflowEngineReadiness } = await loadWorkflowEngine();

  const denied = evaluateWorkflowEngineReadiness(
    workflowEngineInput({
      workflowDefinitions: [
        workflowDefinition('enrollment', 1, {
          transitionPolicy: {
            authorityRequired: false,
            consentRequiredWhenParticipantAffecting: false,
            decisionForumRequired: false,
            receiptRequired: false,
            protectedPayloadProhibited: false,
            metadataOnly: false,
          },
          nodeOutputBoundary: {
            boundedUntrustedWorkflowNodeOutputs: false,
            nodeOutputCannotAuthorizeTrustClaims: false,
            nodeOutputCannotAuthorizeGitOperations: false,
            humanReviewRequiredForTransitions: false,
          },
        }),
        ...workflowDefinitions().filter((entry) => entry.domain !== 'enrollment'),
      ],
      runtimeContract: {
        externalNodeOutputsTreatedAsUntrusted: false,
        idempotencyKeyRequired: false,
        replayProtectionRequired: false,
        operationalStateSeparateFromReceipts: false,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('workflow_transition_authority_absent:workflow-enrollment'));
  assert.ok(denied.reasons.includes('workflow_transition_consent_absent:workflow-enrollment'));
  assert.ok(denied.reasons.includes('workflow_transition_decision_forum_absent:workflow-enrollment'));
  assert.ok(denied.reasons.includes('workflow_transition_receipt_absent:workflow-enrollment'));
  assert.ok(denied.reasons.includes('workflow_node_output_boundary_absent:workflow-enrollment'));
  assert.ok(denied.reasons.includes('runtime_untrusted_node_output_boundary_absent'));
  assert.ok(denied.reasons.includes('runtime_receipt_state_separation_absent'));
});

test('workflow engine validates HLC ordering and keeps AI advisory only', async () => {
  const { evaluateWorkflowEngineReadiness } = await loadWorkflowEngine();

  const denied = evaluateWorkflowEngineReadiness(
    workflowEngineInput({
      engineCycle: {
        definitionsReviewedAtHlc: { physicalMs: 1800000040000, logical: 0 },
      },
      humanReview: {
        finalAuthority: 'ai',
        aiFinalAuthority: true,
      },
      aiAssistance: {
        finalAuthority: true,
        reviewedByHuman: false,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('engine_cycle_definitionsReviewedAtHlc_before_openedAtHlc'));
  assert.ok(denied.reasons.includes('ai_final_authority_forbidden'));
  assert.ok(denied.reasons.includes('ai_human_review_absent'));
  assert.ok(denied.reasons.includes('human_review_authority_absent'));
});

test('workflow engine handles absent objects as fail-closed denial states', async () => {
  const { evaluateWorkflowEngineReadiness } = await loadWorkflowEngine();

  const denied = evaluateWorkflowEngineReadiness({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:workflow-owner-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['workflow_engine_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('workflow_engine_policy_ref_absent'));
  assert.ok(denied.reasons.includes('engine_cycle_ref_absent'));
  assert.ok(denied.reasons.includes('workflow_definitions_absent'));
  assert.ok(denied.reasons.includes('runtime_contract_absent'));
  assert.ok(denied.reasons.includes('validation_evidence_absent'));
  assert.ok(denied.reasons.includes('human_review_absent'));
  assert.ok(denied.reasons.includes('workflow_engine_audit_record_ref_absent'));
});

test('workflow engine rejects raw workflow content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateWorkflowEngineReadiness } = await loadWorkflowEngine();

  const inert = workflowEngineInput({
    workflowDefinitions: [
      workflowDefinition('policy', 0, {
        rawWorkflowText: false,
      }),
      ...workflowDefinitions().filter((entry) => entry.domain !== 'policy'),
    ],
    humanReview: {
      secret: {},
    },
  });

  assert.equal(evaluateWorkflowEngineReadiness(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateWorkflowEngineReadiness(
        workflowEngineInput({
          workflowDefinitions: [
            workflowDefinition('policy', 0, {
              rawWorkflowText: 'raw workflow body stays outside metadata receipts',
            }),
            ...workflowDefinitions().filter((entry) => entry.domain !== 'policy'),
          ],
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateWorkflowEngineReadiness(
        workflowEngineInput({
          runtimeContract: {
            rawNodeOutput: ['workflow node output is untrusted external data'],
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateWorkflowEngineReadiness(
        workflowEngineInput({
          validationEvidence: {
            serviceToken: DIGEST_A,
          },
        }),
      ),
    ProtectedContentError,
  );
});
