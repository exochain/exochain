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

/**
 * Syntaxis Compiler
 *
 * The compilation engine that translates council verdicts and proposals
 * into complete Syntaxis workflows.
 */

const { NODE_IMPLEMENTATIONS } = require('./nodes');
const {
  canonicalJson,
  deterministicId,
  hashCanonical,
  hlcToString,
  normalizeBasisPoints,
  normalizeHlc
} = require('./determinism');

/**
 * BCTS State Transition Map
 * Defines valid state transitions for the 14-state BCTS model
 */
const BCTS_TRANSITIONS = {
  'INITIALIZED': ['IDENTITY_REQUIRED', 'INVALID'],
  'IDENTITY_REQUIRED': ['IDENTITY_VERIFIED', 'VERIFICATION_FAILED'],
  'IDENTITY_VERIFIED': ['AUTHORITY_CHECK', 'INSUFFICIENT_AUTHORITY'],
  'AUTHORITY_CHECK': ['AUTHORIZED', 'UNAUTHORIZED'],
  'AUTHORIZED': ['CONSENT_PHASE', 'DIRECT_EXECUTION'],
  'CONSENT_PHASE': ['CONSENT_VERIFIED', 'CONSENT_INSUFFICIENT'],
  'CONSENT_VERIFIED': ['GOVERNANCE_REVIEW', 'EXECUTION_READY'],
  'GOVERNANCE_REVIEW': ['GOVERNANCE_PASSED', 'GOVERNANCE_FAILED'],
  'GOVERNANCE_PASSED': ['EXECUTION_READY', 'DISPUTE_ESCALATION'],
  'EXECUTION_READY': ['EXECUTING', 'AWAITING_FINAL_AUTHORIZATION'],
  'EXECUTING': ['COMPLETED', 'EXECUTION_FAILED'],
  'COMPLETED': ['FINALIZED', 'ROLLBACK_REQUIRED'],
  'FINALIZED': ['CLOSED'],
  'CLOSED': []
};

const STANDARD_BCTS_FLOW = [
  'INITIALIZED',
  'IDENTITY_REQUIRED',
  'IDENTITY_VERIFIED',
  'AUTHORITY_CHECK',
  'AUTHORIZED',
  'CONSENT_PHASE',
  'CONSENT_VERIFIED',
  'GOVERNANCE_REVIEW',
  'GOVERNANCE_PASSED',
  'EXECUTION_READY',
  'EXECUTING',
  'COMPLETED',
  'FINALIZED',
  'CLOSED'
];

const BCTS_REQUIRED_GATE_TRANSITIONS = [
  {
    currentState: 'IDENTITY_REQUIRED',
    nextState: 'IDENTITY_VERIFIED',
    nodeTypes: ['identity-verify']
  },
  {
    currentState: 'AUTHORITY_CHECK',
    nextState: 'AUTHORIZED',
    nodeTypes: ['authority-check']
  },
  {
    currentState: 'AUTHORIZED',
    nextState: 'CONSENT_PHASE',
    nodeTypes: ['consent-request']
  },
  {
    currentState: 'CONSENT_PHASE',
    nextState: 'CONSENT_VERIFIED',
    nodeTypes: ['consent-verify']
  },
  {
    currentState: 'CONSENT_VERIFIED',
    nextState: 'GOVERNANCE_REVIEW',
    nodeTypes: ['governance-propose']
  },
  {
    currentState: 'GOVERNANCE_REVIEW',
    nextState: 'GOVERNANCE_PASSED',
    nodeTypes: ['governance-vote']
  },
  {
    currentState: 'GOVERNANCE_PASSED',
    nextState: 'EXECUTION_READY',
    nodeTypes: ['governance-resolve']
  }
];

const BCTS_NODE_TRANSITIONS = {
  'identity-verify': [
    { currentState: 'IDENTITY_REQUIRED', nextState: 'IDENTITY_VERIFIED' }
  ],
  'authority-check': [
    { currentState: 'AUTHORITY_CHECK', nextState: 'AUTHORIZED' }
  ],
  'consent-request': [
    { currentState: 'AUTHORIZED', nextState: 'CONSENT_PHASE' }
  ],
  'consent-verify': [
    { currentState: 'CONSENT_PHASE', nextState: 'CONSENT_VERIFIED' }
  ],
  'governance-propose': [
    { currentState: 'CONSENT_VERIFIED', nextState: 'GOVERNANCE_REVIEW' }
  ],
  'governance-vote': [
    { currentState: 'GOVERNANCE_REVIEW', nextState: 'GOVERNANCE_PASSED' }
  ],
  'governance-resolve': [
    { currentState: 'GOVERNANCE_PASSED', nextState: 'EXECUTION_READY' }
  ],
  'kernel-adjudicate': [
    { currentState: 'EXECUTION_READY', nextState: 'EXECUTING' }
  ],
  'invariant-check': [
    { currentState: 'EXECUTION_READY', nextState: 'EXECUTING' }
  ],
  'proof-generate': [
    { currentState: 'EXECUTION_READY', nextState: 'EXECUTING' }
  ],
  'proof-verify': [
    { currentState: 'EXECUTING', nextState: 'COMPLETED' }
  ],
  'dag-append': [
    { currentState: 'COMPLETED', nextState: 'FINALIZED' }
  ],
  'escalation-trigger': [
    { currentState: 'EXECUTION_READY', nextState: 'EXECUTING' }
  ],
  'human-override': [
    { currentState: 'EXECUTING', nextState: 'COMPLETED' }
  ],
  'tenant-isolate': [
    { currentState: 'EXECUTION_READY', nextState: 'EXECUTING' }
  ],
  'mcp-enforce': [
    { currentState: 'EXECUTING', nextState: 'COMPLETED' }
  ],
  'combinator-sequence': [
    { currentState: 'EXECUTION_READY', nextState: 'EXECUTING' }
  ],
  'combinator-parallel': [
    { currentState: 'EXECUTION_READY', nextState: 'EXECUTING' }
  ],
  'combinator-choice': [
    { currentState: 'EXECUTION_READY', nextState: 'EXECUTING' }
  ],
  'combinator-guard': [
    { currentState: 'EXECUTION_READY', nextState: 'EXECUTING' }
  ],
  'combinator-transform': [
    { currentState: 'EXECUTION_READY', nextState: 'EXECUTING' }
  ]
};

function isObjectRecord(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Proposal type to Syntaxis node mappings
 */
const PROPOSAL_TYPE_MAPPINGS = {
  'governance-amendment': {
    nodes: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'kernel-adjudicate'
    ],
    requiredPanels: ['Governance Panel', 'Consent Panel', 'Kernel Panel'],
    stateFlow: STANDARD_BCTS_FLOW
  },
  'feature-implementation': {
    nodes: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'authority-delegate',
      'proof-generate',
      'proof-verify',
      'tenant-isolate',
      'combinator-sequence'
    ],
    requiredPanels: ['Governance Panel', 'Identity Panel', 'Kernel Panel', 'Infrastructure Panel'],
    stateFlow: STANDARD_BCTS_FLOW
  },
  'bug-fix': {
    nodes: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'proof-generate',
      'proof-verify',
      'combinator-sequence',
      'dag-append'
    ],
    requiredPanels: ['Governance Panel', 'Kernel Panel'],
    stateFlow: STANDARD_BCTS_FLOW
  },
  'security-patch': {
    nodes: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'proof-generate',
      'proof-verify',
      'kernel-adjudicate',
      'invariant-check'
    ],
    requiredPanels: ['Governance Panel', 'Identity Panel', 'Kernel Panel'],
    stateFlow: STANDARD_BCTS_FLOW
  },
  'infrastructure-change': {
    nodes: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'tenant-isolate',
      'combinator-parallel',
      'mcp-enforce'
    ],
    requiredPanels: ['Governance Panel', 'Identity Panel', 'Infrastructure Panel', 'AI Panel'],
    stateFlow: STANDARD_BCTS_FLOW
  },
  'escalation-resolution': {
    nodes: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'escalation-trigger',
      'kernel-adjudicate',
      'human-override'
    ],
    requiredPanels: ['Escalation Panel', 'Kernel Panel', 'Executive Panel', 'Consent Panel'],
    stateFlow: STANDARD_BCTS_FLOW
  },
  'access-control-update': {
    nodes: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'authority-delegate'
    ],
    requiredPanels: ['Identity Panel', 'Governance Panel', 'Consent Panel'],
    stateFlow: STANDARD_BCTS_FLOW
  }
};

/**
 * Syntaxis Compiler Class
 */
class SyntaxisCompiler {
  constructor() {
    this.proposalTypeMappers = PROPOSAL_TYPE_MAPPINGS;
    this.bctsTransitions = BCTS_TRANSITIONS;
  }

  /**
   * Compiles a council verdict and proposal into a Syntaxis workflow
   * @param {Object} councilVerdict - Verdict from council with panel assessments
   * @param {Object} proposal - The proposal being compiled
   * @returns {Object} Complete Syntaxis workflow definition
   */
  compileSyntaxis(councilVerdict, proposal) {
    if (!councilVerdict || !proposal) {
      throw new Error('Council verdict and proposal are required');
    }

    // Validate inputs
    if (!proposal.type || !this.proposalTypeMappers[proposal.type]) {
      throw new Error(`Unknown proposal type: ${proposal.type}`);
    }

    const proposalMapping = this.proposalTypeMappers[proposal.type];
    const createdAtHlc = normalizeHlc(
      proposal.createdAtHlc ?? councilVerdict.createdAtHlc,
      'createdAtHlc'
    );
    const createdAt = hlcToString(createdAtHlc);

    // Build the node graph
    const nodes = [];
    const nodesByType = {};
    const dependencies = {};

    // Create nodes based on proposal type
    for (let index = 0; index < proposalMapping.nodes.length; index++) {
      const nodeType = proposalMapping.nodes[index];
      const node = {
        id: deterministicId(`node_${nodeType}`, {
          createdAtHlc,
          index,
          nodeType,
          proposalId: proposal.id,
          verdictId: councilVerdict.id
        }),
        type: nodeType,
        category: this._getCategoryForNodeType(nodeType),
        inputs: this._buildNodeInputs(nodeType, councilVerdict, proposal, createdAtHlc),
        requiredPanels: NODE_IMPLEMENTATIONS[nodeType].getRequiredPanels(),
        requiredConsentBasisPoints: this._getConsentRequirementBasisPoints(nodeType),
        timeoutMs: this._getNodeTimeout(nodeType),
        retryPolicy: this._getRetryPolicy(nodeType),
        fallback: null
      };

      nodes.push(node);
      nodesByType[nodeType] = node;
    }

    // Build dependency graph based on BCTS state flow
    const stateFlow = proposalMapping.stateFlow;
    for (let i = 0; i < nodes.length - 1; i++) {
      dependencies[nodes[i].id] = [nodes[i + 1].id];
    }

    // Validate constitutional invariants
    const invariantChecks = this._validateInvariants(
      proposal,
      councilVerdict,
      proposalMapping.nodes
    );

    // Build final workflow
    const workflow = {
      workflowId: deterministicId('workflow', {
        createdAtHlc,
        nodeTypes: proposalMapping.nodes,
        proposalId: proposal.id,
        proposalType: proposal.type,
        verdictId: councilVerdict.id
      }),
      proposalId: proposal.id,
      proposalType: proposal.type,
      councilVerdictId: councilVerdict.id,
      createdAt,
      createdAtHlc,
      status: 'COMPILED',
      nodes,
      dependencies,
      initialNode: nodes[0].id,
      stateFlow,
      bctsMappings: this._mapNodesToBCTS(nodes, stateFlow),
      invariantCoverage: invariantChecks,
      panelAssessments: councilVerdict.panelAssessments || {},
      executionPolicy: {
        parallelizable: this._canParallelize(nodes),
        faultTolerant: proposal.faultTolerant !== false,
        requiresHumanApproval: this._requiresHumanApproval(proposal.type),
        maxDuration: proposal.maxDuration || 3600000, // 1 hour default
        rollbackOnFailure: proposal.rollbackOnFailure !== false
      },
      metadata: {
        proposer: proposal.proposer,
        affectedPanels: proposalMapping.requiredPanels,
        consentRequired: proposal.requiresConsent !== false,
        estimatedCost: proposal.estimatedCost || 0
      }
    };

    return workflow;
  }

  /**
   * Validates a compiled workflow against the Syntaxis registry
   * @param {Object} workflow - The workflow to validate
   * @returns {Object} { valid: boolean, errors: string[] }
   */
  validateSyntaxisWorkflow(workflow) {
    const errors = [];

    if (!workflow.workflowId) {
      errors.push('workflowId is required');
    }

    if (!Array.isArray(workflow.nodes) || workflow.nodes.length === 0) {
      errors.push('workflow must contain at least one node');
    }

    if (!workflow.initialNode) {
      errors.push('initialNode must be specified');
    }

    // Validate each node
    for (const node of workflow.nodes || []) {
      const nodeImpl = NODE_IMPLEMENTATIONS[node.type];
      if (!nodeImpl) {
        errors.push(`Unknown node type: ${node.type}`);
        continue;
      }
      try {
        normalizeHlc(node.inputs?.timestampHlc, `Node ${node.id}: timestampHlc`);
      } catch (error) {
        errors.push(`Node ${node.id}: timestampHlc is required (${error.message})`);
      }

      const validation = nodeImpl.validate(node.inputs);
      if (!validation.valid) {
        errors.push(`Node ${node.id}: ${validation.errors.join(', ')}`);
      }
    }

    // Validate dependencies
    for (const [nodeId, dependentIds] of Object.entries(workflow.dependencies || {})) {
      const nodeExists = workflow.nodes.some(n => n.id === nodeId);
      if (!nodeExists) {
        errors.push(`Dependency references unknown node: ${nodeId}`);
      }

      if (Array.isArray(dependentIds)) {
        for (const depId of dependentIds) {
          const depExists = workflow.nodes.some(n => n.id === depId);
          if (!depExists) {
            errors.push(`Dependency references unknown node: ${depId}`);
          }
        }
      }
    }

    // Validate state flow
    if (Array.isArray(workflow.stateFlow)) {
      for (let i = 0; i < workflow.stateFlow.length - 1; i++) {
        const currentState = workflow.stateFlow[i];
        const nextState = workflow.stateFlow[i + 1];
        const validTransitions = this.bctsTransitions[currentState] || [];

        if (!validTransitions.includes(nextState)) {
          errors.push(`Invalid state transition: ${currentState} -> ${nextState}`);
        }
      }
      this._validateBctsGateCoverage(workflow, errors);
      this._validateBctsMappings(workflow, errors);
      this._validateBctsMappingCoverage(workflow, errors);
    }

    return {
      valid: errors.length === 0,
      errors,
      nodeCount: workflow.nodes?.length || 0,
      dependencyCount: Object.keys(workflow.dependencies || {}).length
    };
  }

  /**
   * Converts a Syntaxis workflow to Archon-compatible YAML DAG definition
   * @param {Object} syntaxisWorkflow - The compiled Syntaxis workflow
   * @returns {string} YAML DAG definition
   */
  syntaxisToArchonYaml(syntaxisWorkflow) {
    const yaml = [];

    // Header
    yaml.push('# Syntaxis Workflow to Archon DAG Conversion');
    yaml.push(`# Generated HLC: ${syntaxisWorkflow.createdAt}`);
    yaml.push(`# Workflow ID: ${syntaxisWorkflow.workflowId}`);
    yaml.push('');

    // DAG definition
    yaml.push('dag:');
    yaml.push(`  id: "${syntaxisWorkflow.workflowId}"`);
    yaml.push(`  name: "${syntaxisWorkflow.proposalType}-${syntaxisWorkflow.proposalId}"`);
    yaml.push(`  status: "${syntaxisWorkflow.status}"`);
    yaml.push('');

    // Parameters
    yaml.push('parameters:');
    yaml.push(`  proposal_id: "${syntaxisWorkflow.proposalId}"`);
    yaml.push(`  proposal_type: "${syntaxisWorkflow.proposalType}"`);
    yaml.push(`  council_verdict_id: "${syntaxisWorkflow.councilVerdictId}"`);
    yaml.push('');

    // Tasks (nodes)
    yaml.push('tasks:');
    for (const node of syntaxisWorkflow.nodes) {
      yaml.push(`  - id: "${node.id}"`);
      yaml.push(`    type: "${node.type}"`);
      yaml.push(`    category: "${node.category}"`);
      yaml.push(`    timeout_ms: ${node.timeoutMs}`);
      yaml.push(`    required_panels: [${node.requiredPanels.map(p => `"${p}"`).join(', ')}]`);
      yaml.push(`    required_consent_basis_points: ${node.requiredConsentBasisPoints}`);
      yaml.push('    inputs:');

      // Add inputs
      for (const [key, value] of Object.entries(node.inputs || {})) {
        if (typeof value === 'string') {
          yaml.push(`      ${key}: "${value}"`);
        } else if (typeof value === 'number' || typeof value === 'boolean') {
          yaml.push(`      ${key}: ${value}`);
        } else if (Array.isArray(value)) {
          yaml.push(`      ${key}: [${value.map(v => typeof v === 'string' ? `"${v}"` : v).join(', ')}]`);
        } else if (value && typeof value === 'object') {
          yaml.push(`      ${key}: ${canonicalJson(value)}`);
        } else {
          yaml.push(`      ${key}: null`);
        }
      }

      // Dependencies
      const deps = syntaxisWorkflow.dependencies[node.id] || [];
      if (deps.length > 0) {
        yaml.push(`    dependencies: [${deps.map(d => `"${d}"`).join(', ')}]`);
      }

      yaml.push('');
    }

    // Execution policy
    yaml.push('execution_policy:');
    yaml.push(`  parallelizable: ${syntaxisWorkflow.executionPolicy.parallelizable}`);
    yaml.push(`  fault_tolerant: ${syntaxisWorkflow.executionPolicy.faultTolerant}`);
    yaml.push(`  requires_human_approval: ${syntaxisWorkflow.executionPolicy.requiresHumanApproval}`);
    yaml.push(`  max_duration_ms: ${syntaxisWorkflow.executionPolicy.maxDuration}`);
    yaml.push(`  rollback_on_failure: ${syntaxisWorkflow.executionPolicy.rollbackOnFailure}`);
    yaml.push('');

    // Invariant coverage
    yaml.push('invariant_coverage:');
    for (const [invariant, coverage] of Object.entries(syntaxisWorkflow.invariantCoverage || {})) {
      yaml.push(`  ${invariant}: ${coverage.covered}`);
    }

    return yaml.join('\n');
  }

  /**
   * Private helper methods
   */

  _getCategoryForNodeType(nodeType) {
    const categoryMap = {
      'identity-verify': 'Identity & Access',
      'authority-check': 'Identity & Access',
      'authority-delegate': 'Identity & Access',
      'consent-request': 'Consent',
      'consent-verify': 'Consent',
      'consent-revoke': 'Consent',
      'governance-propose': 'Governance',
      'governance-vote': 'Governance',
      'governance-resolve': 'Governance',
      'kernel-adjudicate': 'Kernel',
      'invariant-check': 'Kernel',
      'proof-generate': 'Proof & Ledger',
      'proof-verify': 'Proof & Ledger',
      'dag-append': 'Proof & Ledger',
      'escalation-trigger': 'Escalation & Enforcement',
      'human-override': 'Escalation & Enforcement',
      'tenant-isolate': 'Multi-Tenancy & AI',
      'mcp-enforce': 'Multi-Tenancy & AI',
      'combinator-sequence': 'Flow Control',
      'combinator-parallel': 'Flow Control',
      'combinator-choice': 'Flow Control',
      'combinator-guard': 'Flow Control',
      'combinator-transform': 'Flow Control'
    };
    return categoryMap[nodeType] || 'Unknown';
  }

  _buildNodeInputs(nodeType, councilVerdict, proposal, createdAtHlc) {
    const baseInputs = {
      proposalId: proposal.id,
      verdictId: councilVerdict.id,
      timestamp: hlcToString(createdAtHlc),
      timestampHlc: createdAtHlc
    };

    switch (nodeType) {
      case 'identity-verify':
        return {
          ...baseInputs,
          identity: { id: proposal.proposer },
          verificationMethod: 'cryptographic',
          nonce: deterministicId('nonce', {
            createdAtHlc,
            proposalId: proposal.id,
            verdictId: councilVerdict.id
          }),
          proof: proposal.identityProof || councilVerdict.identityProof || null
        };

      case 'authority-check':
        return {
          ...baseInputs,
          subjectId: proposal.proposer,
          requiredAuthority: 'GOVERNANCE_PROPOSER',
          scope: proposal.type,
          delegationChain: proposal.delegationChain || councilVerdict.delegationChain || []
        };

      case 'authority-delegate':
        return {
          ...baseInputs,
          delegatorId: proposal.proposer,
          delegateeId: proposal.executor || proposal.proposer,
          authority: 'GOVERNANCE_EXECUTOR'
        };

      case 'consent-request':
        return {
          ...baseInputs,
          requesterId: proposal.proposer,
          consentType: proposal.consentType || 'STANDARD',
          recipientIds: councilVerdict.affectedPanels || [],
          consentData: proposal.consentData || {}
        };

      case 'consent-verify':
        return {
          ...baseInputs,
          consentRequestId: `consent_req_${proposal.id}`,
          recipientResponses: councilVerdict.consentResponses || {},
          requiredConsentBasisPoints: normalizeBasisPoints(
            proposal.requiredConsentBasisPoints,
            'proposal.requiredConsentBasisPoints',
            8000
          )
        };

      case 'governance-propose':
        return {
          ...baseInputs,
          proposerId: proposal.proposer,
          proposalType: proposal.type,
          proposalContent: proposal.content || {},
          affectedPanels: councilVerdict.affectedPanels || []
        };

      case 'governance-vote':
        return {
          ...baseInputs,
          proposalId: proposal.id,
          panelVotes: councilVerdict.panelAssessments || {}
        };

      case 'governance-resolve':
        return {
          ...baseInputs,
          proposalId: proposal.id,
          voteResult: this._normalizeVoteResult(councilVerdict.status),
          resolutionDetails: councilVerdict.resolution || {}
        };

      case 'kernel-adjudicate':
        return {
          ...baseInputs,
          conflictId: `conflict_${proposal.id}`,
          conflictType: 'GOVERNANCE_DISPUTE',
          evidenceProofs: proposal.evidence || []
        };

      case 'invariant-check':
        return {
          ...baseInputs,
          invariantId: `invariant_${proposal.type}`,
          invariantRule: { type: 'GOVERNANCE_RULE' },
          stateSnapshot: councilVerdict.systemState || {}
        };

      case 'proof-generate':
        return this._buildProofGenerateInputs(baseInputs, proposal);

      case 'proof-verify':
        return this._buildProofVerifyInputs(baseInputs, proposal);

      case 'dag-append':
        return {
          ...baseInputs,
          dagId: 'GOVERNANCE_DAG',
          nodeData: proposal,
          parentHashes: councilVerdict.precedingProposals || []
        };

      case 'escalation-trigger':
        return {
          ...baseInputs,
          escalationReason: proposal.escalationReason || 'GOVERNANCE_REVIEW_REQUIRED',
          escalationLevel: proposal.escalationLevel || 'WARNING',
          affectedComponent: proposal.type
        };

      case 'human-override':
        return {
          ...baseInputs,
          escalationId: `escalation_${proposal.id}`,
          overrideDecision: 'PROCEED',
          overridingAuthority: proposal.overseer || 'EXECUTIVE_PANEL',
          justification: proposal.justification || ''
        };

      case 'tenant-isolate':
        return {
          ...baseInputs,
          tenantId: proposal.tenantId || 'DEFAULT',
          isolationLevel: proposal.isolationLevel || 'LOGICAL',
          resourceScope: proposal.resourceScope || {}
        };

      case 'mcp-enforce':
        return {
          ...baseInputs,
          mcpInstanceId: proposal.mcpInstance || 'DEFAULT',
          enforcementPolicy: { type: 'GOVERNANCE_POLICY' },
          constraints: proposal.constraints || []
        };

      case 'combinator-sequence':
        return {
          ...baseInputs,
          steps: this._buildSequenceSteps(proposal),
          executionMode: 'STRICT'
        };

      case 'combinator-parallel':
        return {
          ...baseInputs,
          branches: proposal.parallelBranches || [],
          joinStrategy: 'ALL'
        };

      case 'combinator-choice':
        return {
          ...baseInputs,
          condition: proposal.condition || {},
          trueBranch: proposal.trueBranch || {},
          falseBranch: proposal.falseBranch || {}
        };

      case 'combinator-guard':
        return {
          ...baseInputs,
          guardCondition: { type: 'SAFETY_CHECK' },
          guardedAction: proposal.action || {},
          fallbackAction: proposal.fallback || {}
        };

      case 'combinator-transform':
        return {
          ...baseInputs,
          sourceData: proposal.sourceData || {},
          transformation: proposal.transformation || {},
          targetSchema: proposal.targetSchema || {}
        };

      default:
        return baseInputs;
    }
  }

  _buildProofGenerateInputs(baseInputs, proposal) {
    return {
      ...baseInputs,
      dataHash: this._hashObject(proposal),
      prover: proposal.proposer,
      proofType: 'PROPOSAL_VALIDITY',
      proofData: proposal.proofData || {}
    };
  }

  _buildProofVerifyInputs(baseInputs, proposal) {
    const proofInputs = this._buildProofGenerateInputs(baseInputs, proposal);
    const generated = NODE_IMPLEMENTATIONS['proof-generate'].execute({ inputs: proofInputs });

    return {
      ...baseInputs,
      proofId: generated.outputs.proofId,
      proofHash: generated.outputs.proofHash,
      dataHash: generated.outputs.dataHash,
      proofType: generated.outputs.proofType,
      prover: generated.outputs.prover,
      proofData: proofInputs.proofData,
      generatedAtHlc: generated.outputs.generatedAtHlc,
      verifier: 'KERNEL_PANEL'
    };
  }

  _getConsentRequirementBasisPoints(nodeType) {
    const requiresConsent = [
      'consent-request',
      'consent-verify',
      'authority-delegate',
      'governance-propose'
    ];
    return requiresConsent.includes(nodeType) ? 8000 : 0;
  }

  _getNodeTimeout(nodeType) {
    const timeouts = {
      'identity-verify': 10000,
      'authority-check': 5000,
      'consent-verify': 60000,
      'governance-vote': 120000,
      'kernel-adjudicate': 30000,
      'proof-verify': 20000
    };
    return timeouts[nodeType] || 15000;
  }

  _getRetryPolicy(nodeType) {
    return {
      maxRetries: 3,
      backoffMs: 1000,
      exponentialBackoff: true
    };
  }

  _validateInvariants(proposal, verdict, nodeTypes = []) {
    const evidence = isObjectRecord(verdict.invariantEvidence) ? verdict.invariantEvidence : {};
    const requirements = {
      GOVERNANCE_AUTHORITY: 'authority-check',
      CONSENT_COVERAGE: 'consent-verify',
      PROOF_VALIDITY: 'proof-verify',
      KERNEL_INTEGRITY: 'kernel-adjudicate'
    };

    const coverage = {};
    for (const [invariant, nodeType] of Object.entries(requirements)) {
      const record = evidence[invariant];
      const covered = (
        nodeTypes.includes(nodeType) &&
        isObjectRecord(record) &&
        record.nodeType === nodeType &&
        isNonEmptyString(record.evidenceHash)
      );
      coverage[invariant] = {
        covered,
        nodeId: nodeType,
        evidenceHash: covered ? record.evidenceHash : null
      };
    }
    return coverage;
  }

  _mapNodesToBCTS(nodes, stateFlow) {
    const mapping = {};
    for (const node of nodes) {
      const transitions = BCTS_NODE_TRANSITIONS[node.type] || [];
      const transition = transitions.find(candidate => this._stateFlowIncludesTransition(
        stateFlow,
        candidate.currentState,
        candidate.nextState
      ));
      if (transition) {
        mapping[node.id] = {
          currentState: transition.currentState,
          nextState: transition.nextState
        };
      }
    }
    return mapping;
  }

  _validateBctsGateCoverage(workflow, errors) {
    const nodeTypes = (workflow.nodes || []).map(node => node.type);
    for (const requirement of BCTS_REQUIRED_GATE_TRANSITIONS) {
      if (!this._stateFlowIncludesTransition(
        workflow.stateFlow,
        requirement.currentState,
        requirement.nextState
      )) {
        continue;
      }
      const covered = requirement.nodeTypes.some(nodeType => nodeTypes.includes(nodeType));
      if (!covered) {
        errors.push(
          `Missing BCTS gate node for ${requirement.currentState} -> ${requirement.nextState}: requires ${requirement.nodeTypes.join(' or ')}`
        );
      }
    }
  }

  _validateBctsMappings(workflow, errors) {
    const nodesById = Object.create(null);
    for (const node of workflow.nodes || []) {
      nodesById[node.id] = node;
    }

    for (const [nodeId, mapping] of Object.entries(workflow.bctsMappings || {})) {
      const node = nodesById[nodeId];
      if (!node) {
        errors.push(`BCTS mapping references unknown node: ${nodeId}`);
        continue;
      }
      if (!this._stateFlowIncludesTransition(
        workflow.stateFlow,
        mapping.currentState,
        mapping.nextState
      )) {
        errors.push(
          `BCTS mapping for node ${nodeId} references non-workflow transition: ${mapping.currentState} -> ${mapping.nextState}`
        );
        continue;
      }
      if (!this._nodeTypeCanClaimBctsTransition(
        node.type,
        mapping.currentState,
        mapping.nextState
      )) {
        errors.push(
          `BCTS mapping for node ${nodeId} (${node.type}) cannot claim ${mapping.currentState} -> ${mapping.nextState}`
        );
      }
    }
  }

  _validateBctsMappingCoverage(workflow, errors) {
    const nodesById = Object.create(null);
    for (const node of workflow.nodes || []) {
      nodesById[node.id] = node;
    }

    for (const requirement of BCTS_REQUIRED_GATE_TRANSITIONS) {
      if (!this._stateFlowIncludesTransition(
        workflow.stateFlow,
        requirement.currentState,
        requirement.nextState
      )) {
        continue;
      }
      const covered = Object.entries(workflow.bctsMappings || {}).some(([nodeId, mapping]) => {
        const node = nodesById[nodeId];
        return (
          node &&
          requirement.nodeTypes.includes(node.type) &&
          mapping.currentState === requirement.currentState &&
          mapping.nextState === requirement.nextState
        );
      });
      if (!covered) {
        errors.push(
          `Missing BCTS mapping for ${requirement.currentState} -> ${requirement.nextState}: requires ${requirement.nodeTypes.join(' or ')}`
        );
      }
    }
  }

  _stateFlowIncludesTransition(stateFlow, currentState, nextState) {
    if (!Array.isArray(stateFlow)) {
      return false;
    }
    for (let i = 0; i < stateFlow.length - 1; i++) {
      if (stateFlow[i] === currentState && stateFlow[i + 1] === nextState) {
        return true;
      }
    }
    return false;
  }

  _nodeTypeCanClaimBctsTransition(nodeType, currentState, nextState) {
    const transitions = BCTS_NODE_TRANSITIONS[nodeType] || [];
    return transitions.some(transition => (
      transition.currentState === currentState &&
      transition.nextState === nextState
    ));
  }

  _canParallelize(nodes) {
    const flowControlTypes = [
      'combinator-parallel',
      'combinator-choice'
    ];
    return nodes.some(n => flowControlTypes.includes(n.type));
  }

  _requiresHumanApproval(proposalType) {
    const requiresApproval = [
      'governance-amendment',
      'infrastructure-change',
      'security-patch'
    ];
    return requiresApproval.includes(proposalType);
  }

  _buildSequenceSteps(proposal) {
    return proposal.steps || [
      { action: 'INITIALIZE' },
      { action: 'EXECUTE' },
      { action: 'FINALIZE' }
    ];
  }

  _hashObject(obj) {
    return `0x${hashCanonical(obj)}`;
  }

  _normalizeVoteResult(status) {
    const normalized = {
      APPROVED: 'PASSED',
      PASSED: 'PASSED',
      REJECTED: 'FAILED',
      FAILED: 'FAILED',
      DISPUTED: 'DISPUTED'
    }[status];
    if (!normalized) {
      throw new Error(`Unsupported council verdict status: ${status}`);
    }
    return normalized;
  }
}

module.exports = {
  SyntaxisCompiler,
  BCTS_TRANSITIONS,
  PROPOSAL_TYPE_MAPPINGS,
  STANDARD_BCTS_FLOW
};
