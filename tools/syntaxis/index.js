/**
 * Syntaxis Protocol Engine - Main Entry Point
 *
 * The Syntaxis Protocol is an intermediary protocol that translates council
 * governance decisions into executable workflow definitions for ExoForge.
 *
 * It comprises 23 node types across 8 categories and supports the full
 * governance lifecycle from proposals through execution and finalization.
 */

const { NODE_IMPLEMENTATIONS, SyntaxisNode } = require('./nodes');
const { SyntaxisCompiler, BCTS_TRANSITIONS, PROPOSAL_TYPE_MAPPINGS } = require('./compiler');
const { SolutionsBuilder, SOLUTION_TEMPLATES } = require('./solutions-builder');

/**
 * BCTS State Model (14 states)
 * Represents the lifecycle of a governance decision
 */
const BCTS_STATES = {
  INITIALIZED: {
    description: 'Workflow initialized',
    transitions: ['IDENTITY_REQUIRED', 'INVALID']
  },
  IDENTITY_REQUIRED: {
    description: 'Identity verification required',
    transitions: ['IDENTITY_VERIFIED', 'VERIFICATION_FAILED']
  },
  IDENTITY_VERIFIED: {
    description: 'Identity verified successfully',
    transitions: ['AUTHORITY_CHECK', 'INSUFFICIENT_AUTHORITY']
  },
  AUTHORITY_CHECK: {
    description: 'Checking subject authority',
    transitions: ['AUTHORIZED', 'UNAUTHORIZED']
  },
  AUTHORIZED: {
    description: 'Subject is authorized',
    transitions: ['CONSENT_PHASE', 'DIRECT_EXECUTION']
  },
  CONSENT_PHASE: {
    description: 'Gathering consent from affected parties',
    transitions: ['CONSENT_VERIFIED', 'CONSENT_INSUFFICIENT']
  },
  CONSENT_VERIFIED: {
    description: 'Consent thresholds met',
    transitions: ['GOVERNANCE_REVIEW', 'EXECUTION_READY']
  },
  GOVERNANCE_REVIEW: {
    description: 'Under governance panel review',
    transitions: ['GOVERNANCE_PASSED', 'GOVERNANCE_FAILED']
  },
  GOVERNANCE_PASSED: {
    description: 'Passed governance review',
    transitions: ['EXECUTION_READY', 'DISPUTE_ESCALATION']
  },
  EXECUTION_READY: {
    description: 'Ready for execution',
    transitions: ['EXECUTING', 'AWAITING_FINAL_AUTHORIZATION']
  },
  EXECUTING: {
    description: 'Currently executing',
    transitions: ['COMPLETED', 'EXECUTION_FAILED']
  },
  COMPLETED: {
    description: 'Execution completed successfully',
    transitions: ['FINALIZED', 'ROLLBACK_REQUIRED']
  },
  FINALIZED: {
    description: 'Finalized and recorded',
    transitions: ['CLOSED']
  },
  CLOSED: {
    description: 'Workflow closed',
    transitions: []
  }
};

/**
 * NODE_REGISTRY - Map of all 23 node types
 * Organized by category with metadata about each node
 */
const NODE_REGISTRY = {
  'identity-verify': {
    category: 'Identity & Access',
    description: 'Verifies identity of request initiator',
    requiredInputs: ['identity', 'verificationMethod', 'nonce'],
    outputs: ['identityId', 'verified', 'verificationTimestamp'],
    bctsTransition: 'IDENTITY_REQUIRED -> IDENTITY_VERIFIED',
    requiredPanels: ['Identity Panel'],
    timeoutMs: 10000,
    implementation: NODE_IMPLEMENTATIONS['identity-verify']
  },

  'authority-check': {
    category: 'Identity & Access',
    description: 'Checks if subject has required authority for action',
    requiredInputs: ['subjectId', 'requiredAuthority', 'scope'],
    outputs: ['subjectId', 'authorized', 'authorityLevel'],
    bctsTransition: 'IDENTITY_VERIFIED -> AUTHORIZED',
    requiredPanels: ['Identity Panel'],
    timeoutMs: 5000,
    implementation: NODE_IMPLEMENTATIONS['authority-check']
  },

  'authority-delegate': {
    category: 'Identity & Access',
    description: 'Delegates authority from one subject to another',
    requiredInputs: ['delegatorId', 'delegateeId', 'authority'],
    outputs: ['delegationId', 'delegatorId', 'delegateeId', 'authority'],
    bctsTransition: 'AUTHORIZED -> AUTHORIZED',
    requiredPanels: ['Identity Panel', 'Governance Panel'],
    timeoutMs: 5000,
    implementation: NODE_IMPLEMENTATIONS['authority-delegate']
  },

  'consent-request': {
    category: 'Consent',
    description: 'Requests consent from affected parties',
    requiredInputs: ['requesterId', 'consentType', 'recipientIds', 'consentData'],
    outputs: ['consentRequestId', 'requesterId', 'recipientCount', 'status'],
    bctsTransition: 'AUTHORIZED -> CONSENT_PHASE',
    requiredPanels: ['Consent Panel'],
    timeoutMs: 60000,
    implementation: NODE_IMPLEMENTATIONS['consent-request']
  },

  'consent-verify': {
    category: 'Consent',
    description: 'Verifies that consent thresholds have been met',
    requiredInputs: ['consentRequestId', 'recipientResponses'],
    outputs: ['consentRequestId', 'allConsented', 'consentBasisPoints'],
    bctsTransition: 'CONSENT_PHASE -> CONSENT_VERIFIED',
    requiredPanels: ['Consent Panel'],
    timeoutMs: 60000,
    implementation: NODE_IMPLEMENTATIONS['consent-verify']
  },

  'consent-revoke': {
    category: 'Consent',
    description: 'Revokes previously granted consent',
    requiredInputs: ['consentRequestId', 'revokerId', 'revocationReason'],
    outputs: ['revocationId', 'consentRequestId', 'revokerId', 'revokedAt'],
    bctsTransition: 'CONSENT_VERIFIED -> CONSENT_PHASE',
    requiredPanels: ['Consent Panel'],
    timeoutMs: 10000,
    implementation: NODE_IMPLEMENTATIONS['consent-revoke']
  },

  'governance-propose': {
    category: 'Governance',
    description: 'Submits a proposal for governance review',
    requiredInputs: ['proposerId', 'proposalType', 'proposalContent', 'affectedPanels'],
    outputs: ['proposalId', 'proposerId', 'proposalType', 'status'],
    bctsTransition: 'CONSENT_VERIFIED -> GOVERNANCE_REVIEW',
    requiredPanels: ['Governance Panel'],
    timeoutMs: 15000,
    implementation: NODE_IMPLEMENTATIONS['governance-propose']
  },

  'governance-vote': {
    category: 'Governance',
    description: 'Collects votes from governance panels',
    requiredInputs: ['proposalId', 'panelVotes'],
    outputs: ['proposalId', 'passed', 'voteCount', 'resultDetails'],
    bctsTransition: 'GOVERNANCE_REVIEW -> GOVERNANCE_PASSED',
    requiredPanels: ['Governance Panel'],
    timeoutMs: 120000,
    implementation: NODE_IMPLEMENTATIONS['governance-vote']
  },

  'governance-resolve': {
    category: 'Governance',
    description: 'Resolves governance decision and records outcome',
    requiredInputs: ['proposalId', 'voteResult'],
    outputs: ['resolutionId', 'proposalId', 'voteResult', 'resolutionStatus'],
    bctsTransition: 'GOVERNANCE_PASSED -> EXECUTION_READY',
    requiredPanels: ['Governance Panel'],
    timeoutMs: 10000,
    implementation: NODE_IMPLEMENTATIONS['governance-resolve']
  },

  'kernel-adjudicate': {
    category: 'Kernel',
    description: 'Kernel-level adjudication of disputes and conflicts',
    requiredInputs: ['conflictId', 'conflictType', 'evidenceProofs'],
    outputs: ['adjudicationId', 'conflictId', 'verdict', 'confidenceBasisPoints'],
    bctsTransition: 'GOVERNANCE_PASSED -> EXECUTION_READY',
    requiredPanels: ['Kernel Panel'],
    timeoutMs: 30000,
    implementation: NODE_IMPLEMENTATIONS['kernel-adjudicate']
  },

  'invariant-check': {
    category: 'Kernel',
    description: 'Validates that system invariants are satisfied',
    requiredInputs: ['invariantId', 'invariantRule', 'stateSnapshot'],
    outputs: ['invariantId', 'satisfied', 'checkedAt', 'ruleType'],
    bctsTransition: 'EXECUTION_READY -> EXECUTING',
    requiredPanels: ['Kernel Panel'],
    timeoutMs: 15000,
    implementation: NODE_IMPLEMENTATIONS['invariant-check']
  },

  'proof-generate': {
    category: 'Proof & Ledger',
    description: 'Generates cryptographic proofs of execution',
    requiredInputs: ['dataHash', 'prover', 'proofType'],
    outputs: ['proofId', 'proofHash', 'proofType', 'prover'],
    bctsTransition: 'EXECUTING -> EXECUTING',
    requiredPanels: ['Kernel Panel'],
    timeoutMs: 20000,
    implementation: NODE_IMPLEMENTATIONS['proof-generate']
  },

  'proof-verify': {
    category: 'Proof & Ledger',
    description: 'Verifies cryptographic proofs',
    requiredInputs: ['proofId', 'proofHash', 'verifier'],
    outputs: ['proofId', 'verified', 'verifier', 'integrity'],
    bctsTransition: 'EXECUTING -> COMPLETED',
    requiredPanels: ['Kernel Panel'],
    timeoutMs: 20000,
    implementation: NODE_IMPLEMENTATIONS['proof-verify']
  },

  'dag-append': {
    category: 'Proof & Ledger',
    description: 'Appends execution record to governance DAG',
    requiredInputs: ['dagId', 'nodeData', 'parentHashes'],
    outputs: ['dagNodeId', 'dagId', 'nodeHash', 'appendedAt'],
    bctsTransition: 'COMPLETED -> FINALIZED',
    requiredPanels: ['Kernel Panel'],
    timeoutMs: 15000,
    implementation: NODE_IMPLEMENTATIONS['dag-append']
  },

  'escalation-trigger': {
    category: 'Escalation & Enforcement',
    description: 'Triggers escalation for critical issues',
    requiredInputs: ['escalationReason', 'escalationLevel', 'affectedComponent'],
    outputs: ['escalationId', 'escalationLevel', 'affectedComponent', 'requiresHumanReview'],
    bctsTransition: 'GOVERNANCE_PASSED -> DISPUTE_ESCALATION',
    requiredPanels: ['Escalation Panel'],
    timeoutMs: 5000,
    implementation: NODE_IMPLEMENTATIONS['escalation-trigger']
  },

  'human-override': {
    category: 'Escalation & Enforcement',
    description: 'Allows human override of automated decisions',
    requiredInputs: ['escalationId', 'overrideDecision', 'overridingAuthority', 'justification'],
    outputs: ['overrideId', 'escalationId', 'decision', 'authority', 'justification'],
    bctsTransition: 'DISPUTE_ESCALATION -> EXECUTION_READY',
    requiredPanels: ['Executive Panel'],
    timeoutMs: 30000,
    implementation: NODE_IMPLEMENTATIONS['human-override']
  },

  'tenant-isolate': {
    category: 'Multi-Tenancy & AI',
    description: 'Creates tenant isolation boundaries',
    requiredInputs: ['tenantId', 'isolationLevel', 'resourceScope'],
    outputs: ['isolationId', 'tenantId', 'isolationLevel', 'resourceCount'],
    bctsTransition: 'AUTHORIZED -> EXECUTING',
    requiredPanels: ['Infrastructure Panel'],
    timeoutMs: 10000,
    implementation: NODE_IMPLEMENTATIONS['tenant-isolate']
  },

  'mcp-enforce': {
    category: 'Multi-Tenancy & AI',
    description: 'Enforces MCP policies and constraints',
    requiredInputs: ['mcpInstanceId', 'enforcementPolicy', 'constraints'],
    outputs: ['enforcementId', 'mcpInstanceId', 'policyApplied', 'constraintCount'],
    bctsTransition: 'EXECUTING -> EXECUTING',
    requiredPanels: ['AI Panel'],
    timeoutMs: 15000,
    implementation: NODE_IMPLEMENTATIONS['mcp-enforce']
  },

  'combinator-sequence': {
    category: 'Flow Control',
    description: 'Executes steps in strict sequential order',
    requiredInputs: ['steps', 'executionMode'],
    outputs: ['stepCount', 'executionMode', 'sequenceId', 'startedAt'],
    bctsTransition: 'EXECUTING -> EXECUTING',
    requiredPanels: [],
    timeoutMs: 300000,
    implementation: NODE_IMPLEMENTATIONS['combinator-sequence']
  },

  'combinator-parallel': {
    category: 'Flow Control',
    description: 'Executes multiple branches in parallel',
    requiredInputs: ['branches', 'joinStrategy'],
    outputs: ['branchCount', 'joinStrategy', 'parallelId', 'startedAt'],
    bctsTransition: 'EXECUTING -> EXECUTING',
    requiredPanels: [],
    timeoutMs: 300000,
    implementation: NODE_IMPLEMENTATIONS['combinator-parallel']
  },

  'combinator-choice': {
    category: 'Flow Control',
    description: 'Conditional branching based on evaluation',
    requiredInputs: ['condition', 'trueBranch', 'falseBranch'],
    outputs: ['conditionMet', 'selectedBranch', 'choiceId', 'evaluatedAt'],
    bctsTransition: 'EXECUTING -> EXECUTING',
    requiredPanels: [],
    timeoutMs: 10000,
    implementation: NODE_IMPLEMENTATIONS['combinator-choice']
  },

  'combinator-guard': {
    category: 'Flow Control',
    description: 'Guards action execution with preconditions',
    requiredInputs: ['guardCondition', 'guardedAction', 'fallbackAction'],
    outputs: ['guardPassed', 'executedAction', 'guardId', 'checkedAt'],
    bctsTransition: 'EXECUTING -> EXECUTING',
    requiredPanels: [],
    timeoutMs: 10000,
    implementation: NODE_IMPLEMENTATIONS['combinator-guard']
  },

  'combinator-transform': {
    category: 'Flow Control',
    description: 'Transforms data between schema boundaries',
    requiredInputs: ['sourceData', 'transformation', 'targetSchema'],
    outputs: ['transformedData', 'targetSchema', 'transformId', 'transformedAt'],
    bctsTransition: 'EXECUTING -> EXECUTING',
    requiredPanels: [],
    timeoutMs: 15000,
    implementation: NODE_IMPLEMENTATIONS['combinator-transform']
  }
};

/**
 * Syntaxis Protocol Engine Main Class
 */
class SyntaxisProtocolEngine {
  constructor() {
    this.nodeRegistry = NODE_REGISTRY;
    this.bctsTransitions = BCTS_TRANSITIONS;
    this.bctsStates = BCTS_STATES;
    this.compiler = new SyntaxisCompiler();
    this.solutionsBuilder = new SolutionsBuilder();
  }

  /**
   * Compiles a council verdict into a Syntaxis workflow
   * @param {Object} councilVerdict - Verdict from council
   * @param {Object} proposal - The proposal to compile
   * @returns {Object} Syntaxis workflow
   */
  compileSyntaxis(councilVerdict, proposal) {
    return this.compiler.compileSyntaxis(councilVerdict, proposal);
  }

  /**
   * Validates a Syntaxis workflow
   * @param {Object} workflow - Workflow to validate
   * @returns {Object} Validation result
   */
  validateSyntaxisWorkflow(workflow) {
    return this.compiler.validateSyntaxisWorkflow(workflow);
  }

  /**
   * Converts Syntaxis workflow to Archon YAML
   * @param {Object} workflow - Syntaxis workflow
   * @returns {string} YAML definition
   */
  syntaxisToArchonYaml(workflow) {
    return this.compiler.syntaxisToArchonYaml(workflow);
  }

  /**
   * Creates a solution from a template
   * @param {string} solutionType - Solution type
   * @param {Object} config - Configuration
   * @returns {Object} Solution
   */
  createSolution(solutionType, config) {
    return this.solutionsBuilder.createSolution(solutionType, config);
  }

  /**
   * Deploys a solution
   * @param {Object} solution - Solution to deploy
   * @param {string|Object} target - Deployment target
   * @returns {Object} Deployment result
   */
  deploySolution(solution, target) {
    return this.solutionsBuilder.deploySolution(solution, target);
  }

  /**
   * Lists available solution templates
   * @returns {Array} Templates
   */
  listSolutionTemplates() {
    return this.solutionsBuilder.listTemplates();
  }

  /**
   * Gets a specific node implementation
   * @param {string} nodeType - Type of node
   * @returns {Object} Node implementation
   */
  getNode(nodeType) {
    if (!NODE_IMPLEMENTATIONS[nodeType]) {
      throw new Error(`Unknown node type: ${nodeType}`);
    }
    return NODE_IMPLEMENTATIONS[nodeType];
  }

  /**
   * Gets node registry entry
   * @param {string} nodeType - Type of node
   * @returns {Object} Registry entry
   */
  getNodeRegistry(nodeType) {
    if (!this.nodeRegistry[nodeType]) {
      throw new Error(`Unknown node type: ${nodeType}`);
    }
    return this.nodeRegistry[nodeType];
  }

  /**
   * Lists all nodes by category
   * @returns {Object} Nodes grouped by category
   */
  getNodesByCategory() {
    const categories = {};
    for (const [nodeType, entry] of Object.entries(this.nodeRegistry)) {
      const category = entry.category;
      if (!categories[category]) {
        categories[category] = [];
      }
      categories[category].push({
        type: nodeType,
        description: entry.description,
        requiredInputs: entry.requiredInputs,
        outputs: entry.outputs
      });
    }
    return categories;
  }

  /**
   * Gets BCTS state information
   * @param {string} state - State name
   * @returns {Object} State info
   */
  getBCTSState(state) {
    if (!this.bctsStates[state]) {
      throw new Error(`Unknown BCTS state: ${state}`);
    }
    return this.bctsStates[state];
  }

  /**
   * Gets valid state transitions
   * @param {string} fromState - Current state
   * @returns {Array} Valid next states
   */
  getValidTransitions(fromState) {
    if (!this.bctsTransitions[fromState]) {
      throw new Error(`Unknown state: ${fromState}`);
    }
    return this.bctsTransitions[fromState];
  }

  /**
   * Gets statistics about the protocol
   * @returns {Object} Protocol statistics
   */
  getStatistics() {
    const byCategory = {};
    for (const [nodeType, entry] of Object.entries(this.nodeRegistry)) {
      const category = entry.category;
      byCategory[category] = (byCategory[category] || 0) + 1;
    }

    return {
      totalNodes: Object.keys(this.nodeRegistry).length,
      totalCategories: Object.keys(byCategory).length,
      nodesByCategory: byCategory,
      totalBCTSStates: Object.keys(this.bctsStates).length,
      availableSolutionTemplates: this.solutionsBuilder.listTemplates().length
    };
  }
}

/**
 * Factory function to create engine instance
 */
function createSyntaxisEngine() {
  return new SyntaxisProtocolEngine();
}

/**
 * Exports
 */
module.exports = {
  SyntaxisProtocolEngine,
  createSyntaxisEngine,
  NODE_REGISTRY,
  BCTS_TRANSITIONS,
  BCTS_STATES,
  NODE_IMPLEMENTATIONS,
  SyntaxisCompiler,
  SolutionsBuilder,
  SOLUTION_TEMPLATES,
  // Export node classes for advanced usage
  SyntaxisNode,
  // Version info
  version: '0.1.0'
};
