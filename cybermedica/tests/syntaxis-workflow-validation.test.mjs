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

const REQUIRED_NODE_TYPES = [
  'authority-check',
  'consent-verify',
  'dag-append',
  'governance-propose',
  'governance-resolve',
  'governance-vote',
  'identity-verify',
  'kernel-adjudicate',
];

async function loadSyntaxisWorkflowValidation() {
  try {
    return await import('../src/syntaxis-workflow-validation.mjs');
  } catch (error) {
    assert.fail(`CyberMedica Syntaxis workflow validation module must exist and load: ${error.message}`);
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

function registryNode(nodeType, overrides = {}) {
  const crateByNode = {
    'authority-check': 'exo-authority',
    'consent-verify': 'exo-consent',
    'dag-append': 'exo-dag',
    'governance-propose': 'exo-governance',
    'governance-resolve': 'exo-governance',
    'governance-vote': 'exo-governance',
    'identity-verify': 'exo-identity',
    'kernel-adjudicate': 'exo-gatekeeper',
  };
  return {
    nodeType,
    crate: crateByNode[nodeType],
    rustModule: crateByNode[nodeType].replace('-', '_'),
    rustTraitRef: `${nodeType}:trait-ref`,
    combinatorRef: `${nodeType}:combinator-ref`,
    invariantRefs: nodeType === 'dag-append' ? ['ProvenanceVerifiable'] : ['AuthorityChainValid', 'ProvenanceVerifiable'],
    inputRefs: [`${nodeType}:input`],
    outputRefs: [`${nodeType}:output`],
    sourcePathRefs: ['tools/syntaxis/node_registry.json'],
    verifiedAgainstCurrentSource: true,
    metadataOnly: true,
    ...overrides,
  };
}

function workflowStep(nodeType, index, overrides = {}) {
  return {
    stepRef: `step-${index}-${nodeType}`,
    nodeType,
    registryNodeType: nodeType,
    inputSchemaHash: [DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_D][index % 4],
    outputSchemaHash: [DIGEST_E, DIGEST_F, DIGEST_1, DIGEST_2][index % 4],
    edgeRefs: index === 0 ? [] : [`step-${index - 1}->step-${index}`],
    metadataOnly: true,
    protectedContentExcluded: true,
    ...overrides,
  };
}

function syntaxisInput(overrides = {}) {
  const base = {
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: {
      did: 'did:exo:syntaxis-reviewer-alpha',
      kind: 'human',
      roleRefs: ['quality_manager', 'workflow_engine_owner'],
    },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['syntaxis_registry_review', 'workflow_engine_review'],
      authorityChainHash: DIGEST_A,
    },
    validationPolicy: {
      policyRef: 'syntaxis-validation-policy-alpha',
      policyHash: DIGEST_B,
      status: 'active',
      requiredNodeTypes: REQUIRED_NODE_TYPES,
      designTimeOnly: true,
      productionTrustClaimForbidden: true,
      registryToCodeValidationRequired: true,
      generatedWorkflowCompileRequired: true,
      generatedTestsRequired: true,
      invalidNodeEdgeDenialRequired: true,
      untrustedGeneratedOutputBoundaryRequired: true,
      metadataOnly: true,
      evaluatedAtHlc: { physicalMs: 1800000000000, logical: 0 },
    },
    registrySnapshot: {
      registryRef: 'tools/syntaxis/node_registry.json',
      registryHash: DIGEST_C,
      schemaRef: 'https://exochain.dev/schemas/syntaxis-node-registry-v1.json',
      version: '1.0.0',
      sourceCommitHash: DIGEST_D,
      generatedAtHlc: { physicalMs: 1800000050000, logical: 0 },
      verifiedReadOnly: true,
      metadataOnly: true,
      nodeMappings: REQUIRED_NODE_TYPES.map((nodeType) => registryNode(nodeType)),
    },
    generatedWorkflow: {
      workflowRef: 'syntaxis-qms-launch-gate-alpha',
      workflowHash: DIGEST_E,
      generatedModuleHash: DIGEST_F,
      generatedTestHash: DIGEST_1,
      sourceWorkflowHash: DIGEST_2,
      composition: 'guarded_sequence',
      workflowClass: 'clinical_governance',
      compile: {
        commandRef: 'python3 tools/syntaxis/generate_workflow.py workflow.json --output-dir generated/',
        passed: true,
        artifactHash: DIGEST_3,
      },
      steps: REQUIRED_NODE_TYPES.map((nodeType, index) => workflowStep(nodeType, index)),
      edgeValidation: {
        passed: true,
        invalidNodeRejected: true,
        invalidEdgeRejected: true,
        missingNodeRejected: true,
        cycleRejected: true,
      },
      trustBoundary: {
        designTimeOnly: true,
        runtimeEnforcementClaim: false,
        generatedOutputCannotAuthorizeGovernance: true,
        generatedOutputCannotAuthorizeTrustClaims: true,
        generatedOutputCannotModifyExochainSource: true,
        boundedUntrustedWorkflowOutputs: true,
        metadataOnly: true,
      },
      metadataOnly: true,
      protectedContentExcluded: true,
    },
    validationEvidence: {
      commandRefs: [
        'node --test tests/syntaxis-workflow-validation.test.mjs',
        'npm run quality',
      ],
      registryToCodeValidationPassed: true,
      generatedWorkflowCompilePassed: true,
      generatedTestsPassed: true,
      invalidNodeEdgeTestsPassed: true,
      noExochainSourceModified: true,
      sourceGuardPassed: true,
      testCount: 553,
      coverageLineBasisPoints: 9900,
      evidenceHash: DIGEST_4,
      recordedAtHlc: { physicalMs: 1800000200000, logical: 0 },
      metadataOnly: true,
    },
    humanReview: {
      reviewerDid: 'did:exo:site-leader-alpha',
      reviewerRoleRefs: ['site_leader', 'quality_manager'],
      decision: 'syntaxis_design_time_validated_inactive_trust',
      decisionHash: DIGEST_A,
      finalAuthority: 'human',
      noProductionTrustClaim: true,
      reviewedAtHlc: { physicalMs: 1800000300000, logical: 0 },
      metadataOnly: true,
    },
    aiAssistance: {
      used: true,
      finalAuthority: false,
      recommendationHash: DIGEST_B,
      limitationHashes: [DIGEST_C],
      reviewedByHuman: true,
    },
    custodyDigest: DIGEST_D,
  };
  return mergeDeep(base, overrides);
}

test('Syntaxis workflow validation module loads', async () => {
  const mod = await loadSyntaxisWorkflowValidation();
  assert.equal(typeof mod.evaluateSyntaxisWorkflowValidation, 'function');
});

test('Syntaxis workflow validation permits deterministic design-time readiness only', async () => {
  const { evaluateSyntaxisWorkflowValidation } = await loadSyntaxisWorkflowValidation();

  const first = evaluateSyntaxisWorkflowValidation(syntaxisInput());
  const second = evaluateSyntaxisWorkflowValidation({
    ...syntaxisInput(),
    validationPolicy: {
      ...syntaxisInput().validationPolicy,
      requiredNodeTypes: [...syntaxisInput().validationPolicy.requiredNodeTypes].reverse(),
    },
    registrySnapshot: {
      ...syntaxisInput().registrySnapshot,
      nodeMappings: [...syntaxisInput().registrySnapshot.nodeMappings].reverse(),
    },
    generatedWorkflow: {
      ...syntaxisInput().generatedWorkflow,
      steps: [...syntaxisInput().generatedWorkflow.steps].reverse(),
    },
  });

  assert.equal(first.decision, 'permitted');
  assert.equal(first.failClosed, false);
  assert.equal(first.syntaxisValidation.designTimeReady, true);
  assert.equal(first.syntaxisValidation.runtimeEnforcementReady, false);
  assert.equal(first.syntaxisValidation.trustState, 'inactive');
  assert.equal(first.syntaxisValidation.exochainProductionClaim, false);
  assert.deepEqual(first.syntaxisValidation.nodeTypesCovered, REQUIRED_NODE_TYPES);
  assert.deepEqual(first.syntaxisValidation.crateRefsCovered, [
    'exo-authority',
    'exo-consent',
    'exo-dag',
    'exo-gatekeeper',
    'exo-governance',
    'exo-identity',
  ]);
  assert.equal(first.receipt.trustState, 'inactive');
  assert.deepEqual(first, second);
});

test('Syntaxis workflow validation fails closed for missing registry nodes and invalid generated graph checks', async () => {
  const { evaluateSyntaxisWorkflowValidation } = await loadSyntaxisWorkflowValidation();

  const denied = evaluateSyntaxisWorkflowValidation(
    syntaxisInput({
      registrySnapshot: {
        nodeMappings: syntaxisInput().registrySnapshot.nodeMappings.filter(
          (mapping) => mapping.nodeType !== 'kernel-adjudicate',
        ),
      },
      generatedWorkflow: {
        steps: [
          ...syntaxisInput().generatedWorkflow.steps,
          workflowStep('synthetic-admin-approve', 99, {
            registryNodeType: 'synthetic-admin-approve',
            stepRef: 'step-99-synthetic-admin-approve',
          }),
        ],
        edgeValidation: {
          invalidNodeRejected: false,
          invalidEdgeRejected: false,
          missingNodeRejected: false,
          cycleRejected: false,
        },
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.equal(denied.failClosed, true);
  assert.ok(denied.reasons.includes('registry_node_missing:kernel-adjudicate'));
  assert.ok(denied.reasons.includes('generated_step_registry_node_missing:step-7-kernel-adjudicate'));
  assert.ok(denied.reasons.includes('generated_step_unsupported_node:step-99-synthetic-admin-approve'));
  assert.ok(denied.reasons.includes('invalid_node_rejection_absent'));
  assert.ok(denied.reasons.includes('invalid_edge_rejection_absent'));
  assert.ok(denied.reasons.includes('missing_node_rejection_absent'));
  assert.ok(denied.reasons.includes('cycle_rejection_absent'));
});

test('Syntaxis workflow validation denies compile test and production-claim defects', async () => {
  const { evaluateSyntaxisWorkflowValidation } = await loadSyntaxisWorkflowValidation();

  const denied = evaluateSyntaxisWorkflowValidation(
    syntaxisInput({
      generatedWorkflow: {
        compile: {
          passed: false,
        },
        trustBoundary: {
          designTimeOnly: false,
          runtimeEnforcementClaim: true,
          generatedOutputCannotAuthorizeGovernance: false,
          generatedOutputCannotAuthorizeTrustClaims: false,
          generatedOutputCannotModifyExochainSource: false,
          boundedUntrustedWorkflowOutputs: false,
        },
      },
      validationEvidence: {
        registryToCodeValidationPassed: false,
        generatedWorkflowCompilePassed: false,
        generatedTestsPassed: false,
        invalidNodeEdgeTestsPassed: false,
        noExochainSourceModified: false,
      },
      humanReview: {
        finalAuthority: 'ai',
        noProductionTrustClaim: false,
      },
    }),
  );

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('generated_workflow_compile_failed'));
  assert.ok(denied.reasons.includes('runtime_enforcement_claim_forbidden'));
  assert.ok(denied.reasons.includes('generated_output_governance_authority_forbidden'));
  assert.ok(denied.reasons.includes('generated_output_trust_claim_authority_forbidden'));
  assert.ok(denied.reasons.includes('generated_output_exochain_source_edit_forbidden'));
  assert.ok(denied.reasons.includes('untrusted_generated_output_boundary_absent'));
  assert.ok(denied.reasons.includes('validation_registry_to_code_absent'));
  assert.ok(denied.reasons.includes('validation_generated_tests_absent'));
  assert.ok(denied.reasons.includes('validation_exochain_read_only_absent'));
  assert.ok(denied.reasons.includes('human_review_authority_absent'));
  assert.ok(denied.reasons.includes('human_review_production_trust_forbidden'));
});

test('Syntaxis workflow validation handles absent objects as fail-closed denial states', async () => {
  const { evaluateSyntaxisWorkflowValidation } = await loadSyntaxisWorkflowValidation();

  const denied = evaluateSyntaxisWorkflowValidation({
    tenantId: 'tenant-site-alpha',
    targetTenantId: 'tenant-site-alpha',
    actor: { did: 'did:exo:syntaxis-reviewer-alpha', kind: 'human' },
    authority: {
      valid: true,
      revoked: false,
      expired: false,
      permissions: ['syntaxis_registry_review'],
      authorityChainHash: DIGEST_A,
    },
  });

  assert.equal(denied.decision, 'denied');
  assert.ok(denied.reasons.includes('syntaxis_policy_ref_absent'));
  assert.ok(denied.reasons.includes('registry_snapshot_absent'));
  assert.ok(denied.reasons.includes('generated_workflow_absent'));
  assert.ok(denied.reasons.includes('validation_evidence_absent'));
  assert.ok(denied.reasons.includes('human_review_absent'));
});

test('Syntaxis workflow validation rejects raw generated content protected content and secrets before receipts', async () => {
  const { ProtectedContentError, evaluateSyntaxisWorkflowValidation } = await loadSyntaxisWorkflowValidation();

  const inert = syntaxisInput({
    generatedWorkflow: {
      rawGeneratedRust: false,
    },
    validationEvidence: {
      serviceToken: {},
    },
  });

  assert.equal(evaluateSyntaxisWorkflowValidation(inert).decision, 'permitted');

  assert.throws(
    () =>
      evaluateSyntaxisWorkflowValidation(
        syntaxisInput({
          registrySnapshot: {
            rawRegistryJson: '{"nodes":{"identity-verify":{}}}',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateSyntaxisWorkflowValidation(
        syntaxisInput({
          generatedWorkflow: {
            rawGeneratedRust: 'pub fn generated_qms_workflow() {}',
          },
        }),
      ),
    ProtectedContentError,
  );

  assert.throws(
    () =>
      evaluateSyntaxisWorkflowValidation(
        syntaxisInput({
          validationEvidence: {
            apiKey: DIGEST_A,
          },
        }),
      ),
    ProtectedContentError,
  );
});
