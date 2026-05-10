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

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const { SyntaxisCompiler } = require('./compiler');
const { NODE_IMPLEMENTATIONS } = require('./nodes');
const { SolutionsBuilder } = require('./solutions-builder');
const { deterministicId, hashCanonical } = require('./determinism');

const HLC = { physicalMs: 1700000000000, logical: 7 };
const DEPLOY_HLC = { physicalMs: 1700000000001, logical: 0 };

function verdict() {
  return {
    id: 'verdict-test-001',
    status: 'PASSED',
    affectedPanels: ['Identity Panel', 'Governance Panel', 'Consent Panel'],
    panelAssessments: {
      'Consent Panel': 'FOR',
      'Governance Panel': 'FOR',
      'Identity Panel': 'FOR'
    },
    consentResponses: {},
    systemState: { invariant: 'covered' },
    precedingProposals: ['parent-a']
  };
}

function proposal() {
  return {
    id: 'proposal-test-001',
    type: 'governance-amendment',
    proposer: 'GOVERNANCE_PANEL',
    content: {
      amendmentType: 'VOTING_THRESHOLD',
      oldThresholdBasisPoints: 6700,
      newThresholdBasisPoints: 7500
    },
    affectedPanels: ['Governance Panel', 'Consent Panel'],
    requiresConsent: true,
    requiredConsentBasisPoints: 8000,
    faultTolerant: true,
    rollbackOnFailure: true,
    maxDuration: 604800000,
    createdAtHlc: HLC
  };
}

function run() {
  const compiler = new SyntaxisCompiler();

  const first = compiler.compileSyntaxis(verdict(), proposal());
  const second = compiler.compileSyntaxis(verdict(), proposal());
  assert.deepStrictEqual(first, second, 'same Syntaxis inputs must produce identical workflow output');
  assert.deepStrictEqual(
    compiler.validateSyntaxisWorkflow(first),
    { valid: true, errors: [], nodeCount: 5, dependencyCount: 4 },
    'compiled Syntaxis workflow must satisfy the BCTS transition validator'
  );
  const missingNodeHlc = JSON.parse(JSON.stringify(first));
  delete missingNodeHlc.nodes[0].inputs.timestampHlc;
  assert.ok(
    compiler
      .validateSyntaxisWorkflow(missingNodeHlc)
      .errors.some(error => error.includes('timestampHlc is required')),
    'workflow validation must reject nodes missing caller-supplied HLC metadata'
  );
  assert.strictEqual(first.createdAt, '1700000000000:7');
  assert.deepStrictEqual(first.createdAtHlc, HLC);
  assert.ok(first.workflowId.startsWith('workflow_'));
  assert.ok(first.nodes.every(node => node.id.startsWith(`node_${node.type}_`)));
  assert.ok(first.nodes.every(node => node.inputs.timestamp === '1700000000000:7'));
  assert.ok(first.nodes.every(node => node.inputs.timestampHlc.physicalMs === HLC.physicalMs));
  assert.ok(first.nodes.every(node => Number.isInteger(node.requiredConsentBasisPoints)));

  assert.throws(
    () => compiler.compileSyntaxis(verdict(), { ...proposal(), createdAtHlc: undefined }),
    /createdAtHlc is required/
  );

  const yamlA = compiler.syntaxisToArchonYaml(first);
  const yamlB = compiler.syntaxisToArchonYaml(second);
  assert.strictEqual(yamlA, yamlB, 'YAML conversion must be deterministic for identical workflows');
  assert.ok(yamlA.includes('# Generated HLC: 1700000000000:7'));
  assert.ok(!yamlA.includes('Generated: 20'), 'YAML must not include wall-clock ISO generation time');

  const consent = NODE_IMPLEMENTATIONS['consent-verify'].execute({
    inputs: {
      consentRequestId: 'consent-001',
      recipientResponses: {
        alice: { consent: true },
        bob: { consent: true },
        carol: { consent: true },
        dave: { consent: false }
      },
      requiredConsentBasisPoints: 8000,
      timestampHlc: HLC
    }
  });
  assert.strictEqual(consent.outputs.consentBasisPoints, 7500);
  assert.strictEqual(consent.outputs.allConsented, false);
  assert.ok(!Object.prototype.hasOwnProperty.call(consent.outputs, 'consentRate'));

  const adjudication = NODE_IMPLEMENTATIONS['kernel-adjudicate'].execute({
    inputs: {
      conflictId: 'conflict-001',
      conflictType: 'GOVERNANCE_DISPUTE',
      evidenceProofs: [{ hash: 'a' }, {}, { hash: 'c' }],
      timestampHlc: HLC
    }
  });
  assert.strictEqual(adjudication.outputs.confidenceBasisPoints, 6666);
  assert.ok(!Object.prototype.hasOwnProperty.call(adjudication.outputs, 'confidence'));

  const proofInputs = {
    dataHash: `0x${'11'.repeat(32)}`,
    prover: 'GOVERNANCE_PANEL',
    proofType: 'PROPOSAL_VALIDITY',
    proofData: { claim: 'proposal-hash' },
    timestampHlc: HLC
  };
  const generatedProof = NODE_IMPLEMENTATIONS['proof-generate'].execute({ inputs: proofInputs });
  const proofVerificationInputs = {
    proofId: generatedProof.outputs.proofId,
    proofHash: generatedProof.outputs.proofHash,
    dataHash: generatedProof.outputs.dataHash,
    proofType: generatedProof.outputs.proofType,
    prover: generatedProof.outputs.prover,
    proofData: proofInputs.proofData,
    generatedAtHlc: generatedProof.outputs.generatedAtHlc,
    verifier: 'KERNEL_PANEL',
    timestampHlc: HLC
  };
  const proofVerification = NODE_IMPLEMENTATIONS['proof-verify'].execute({
    inputs: proofVerificationInputs
  });
  assert.strictEqual(proofVerification.outputs.verified, true);
  assert.strictEqual(proofVerification.nextState, 'PROOF_VERIFIED');

  const forgedShapeOnlyProof = NODE_IMPLEMENTATIONS['proof-verify'].execute({
    inputs: {
      proofId: 'proof_untrusted',
      proofHash: 'proof_hash_attacker_controlled',
      verifier: 'KERNEL_PANEL',
      timestampHlc: HLC
    }
  });
  assert.strictEqual(
    forgedShapeOnlyProof.outputs.verified,
    false,
    'proof-verify must reject caller-controlled proofId/proofHash strings without a generated proof statement'
  );
  assert.strictEqual(forgedShapeOnlyProof.nextState, 'PROOF_INVALID');

  const omittedStatementFieldsProof = NODE_IMPLEMENTATIONS['proof-verify'].execute({
    inputs: {
      proofId: deterministicId('proof', { proofData: {}, timestampHlc: HLC }),
      proofHash: `proof_hash_${hashCanonical({ proofData: {} }).slice(0, 32)}`,
      generatedAtHlc: HLC,
      verifier: 'KERNEL_PANEL',
      timestampHlc: HLC
    }
  });
  assert.strictEqual(
    omittedStatementFieldsProof.outputs.verified,
    false,
    'proof-verify execute must fail closed when dataHash, proofType, or prover are omitted'
  );
  assert.strictEqual(omittedStatementFieldsProof.nextState, 'PROOF_INVALID');

  const tamperedProof = NODE_IMPLEMENTATIONS['proof-verify'].execute({
    inputs: {
      ...proofVerificationInputs,
      proofHash: `proof_hash_${'00'.repeat(16)}`
    }
  });
  assert.strictEqual(tamperedProof.outputs.verified, false);
  assert.strictEqual(tamperedProof.nextState, 'PROOF_INVALID');

  const missingStatementValidation = NODE_IMPLEMENTATIONS['proof-verify'].validate({
    proofId: generatedProof.outputs.proofId,
    proofHash: generatedProof.outputs.proofHash,
    verifier: 'KERNEL_PANEL'
  });
  assert.strictEqual(missingStatementValidation.valid, false);
  assert.ok(
    missingStatementValidation.errors.some(error => error.includes('dataHash is required')),
    'proof-verify validation must require the proof statement, not just proofId/proofHash'
  );

  const bugFixWorkflow = compiler.compileSyntaxis(verdict(), {
    ...proposal(),
    id: 'proposal-bugfix-001',
    type: 'bug-fix',
    proposer: 'ENGINEERING_PANEL'
  });
  assert.deepStrictEqual(
    compiler.validateSyntaxisWorkflow(bugFixWorkflow),
    { valid: true, errors: [], nodeCount: 5, dependencyCount: 4 },
    'compiled bug-fix workflows must satisfy proof node validation'
  );
  const proofGenerateNode = bugFixWorkflow.nodes.find(node => node.type === 'proof-generate');
  const proofVerifyNode = bugFixWorkflow.nodes.find(node => node.type === 'proof-verify');
  const generatedWorkflowProof = NODE_IMPLEMENTATIONS['proof-generate'].execute({
    inputs: proofGenerateNode.inputs
  });
  assert.strictEqual(
    proofVerifyNode.inputs.proofId,
    generatedWorkflowProof.outputs.proofId,
    'compiled proof-verify node must bind to the proof generated for the same workflow statement'
  );
  const compiledProofVerification = NODE_IMPLEMENTATIONS['proof-verify'].execute({
    inputs: proofVerifyNode.inputs
  });
  assert.strictEqual(compiledProofVerification.outputs.verified, true);

  const builder = new SolutionsBuilder();
  const solutionA = builder.createSolution('security-patch', {
    name: 'Critical Security Patch',
    author: 'SECURITY_TEAM',
    patchSeverity: 'CRITICAL',
    affectedSystems: ['AUTH_SERVICE', 'LEDGER_SERVICE'],
    testingRequired: true,
    rolloutPhase: 1,
    createdAtHlc: HLC
  });
  const solutionB = builder.createSolution('security-patch', {
    name: 'Critical Security Patch',
    author: 'SECURITY_TEAM',
    patchSeverity: 'CRITICAL',
    affectedSystems: ['AUTH_SERVICE', 'LEDGER_SERVICE'],
    testingRequired: true,
    rolloutPhase: 1,
    createdAtHlc: HLC
  });
  assert.deepStrictEqual(solutionA, solutionB, 'same solution inputs must produce identical solution output');
  assert.strictEqual(solutionA.createdAt, '1700000000000:7');

  assert.throws(
    () => builder.createSolution('security-patch', { author: 'SECURITY_TEAM' }),
    /createdAtHlc is required/
  );

  const deploymentA = builder.deploySolution(solutionA, {
    path: '/exoforge/deployments',
    environment: 'PRODUCTION',
    deploymentHlc: DEPLOY_HLC
  });
  const deploymentB = new SolutionsBuilder().deploySolution(solutionA, {
    path: '/exoforge/deployments',
    environment: 'PRODUCTION',
    deploymentHlc: DEPLOY_HLC
  });
  assert.deepStrictEqual(deploymentA, deploymentB, 'same deployment inputs must produce identical deployment output');
  assert.strictEqual(deploymentA.startTime, '1700000000001:0');
  assert.ok(deploymentA.stages.every(stage => stage.completedAt.includes(':')));
  assert.ok(deploymentA.stages.every(stage => !Object.prototype.hasOwnProperty.call(stage, 'executionTime')));

  for (const file of ['determinism.js', 'nodes.js', 'compiler.js', 'solutions-builder.js']) {
    const source = fs.readFileSync(path.join(__dirname, file), 'utf8');
    assert.ok(!source.includes('Date.now('), `${file} must not use Date.now`);
    assert.ok(!source.includes('new Date('), `${file} must not use new Date`);
    assert.ok(!source.includes('Math.random('), `${file} must not use Math.random`);
    assert.ok(!source.includes('Math.'), `${file} must not use floating-point Math helpers`);
  }
}

run();
