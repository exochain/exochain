# Syntaxis Protocol Engine

## Overview

The Syntaxis Protocol Engine is an intermediary protocol that translates council governance decisions into executable workflow definitions for ExoForge. It provides a structured, verifiable mechanism for converting governance verdicts into deterministic, auditable execution plans.

## Architecture

### 23 Node Registry Across 8 Categories

#### Core Governance Nodes (10 nodes)
- **Identity & Access (3 nodes)**
  - `identity-verify`: Verifies identity of request initiator
  - `authority-check`: Checks if subject has required authority
  - `authority-delegate`: Delegates authority between subjects

- **Consent (3 nodes)**
  - `consent-request`: Requests consent from affected parties
  - `consent-verify`: Verifies consent thresholds are met
  - `consent-revoke`: Revokes previously granted consent

- **Governance (3 nodes)**
  - `governance-propose`: Submits proposal for review
  - `governance-vote`: Collects votes from governance panels
  - `governance-resolve`: Resolves decision and records outcome

- **Kernel (1 node)**
  - `kernel-adjudicate`: Kernel-level adjudication of disputes
  - `invariant-check`: Validates system invariants

#### Proof & Ledger Nodes (3 nodes)
- `proof-generate`: Generates cryptographic proofs
- `proof-verify`: Verifies cryptographic proofs
- `dag-append`: Appends execution record to governance DAG

#### Escalation & Enforcement (2 nodes)
- `escalation-trigger`: Triggers escalation for critical issues
- `human-override`: Allows human override of automated decisions

#### Multi-Tenancy & AI (2 nodes)
- `tenant-isolate`: Creates tenant isolation boundaries
- `mcp-enforce`: Enforces MCP policies and constraints

#### Flow Control (5 nodes)
- `combinator-sequence`: Executes steps in strict sequence
- `combinator-parallel`: Executes branches in parallel
- `combinator-choice`: Conditional branching
- `combinator-guard`: Guards action execution with preconditions
- `combinator-transform`: Transforms data between schemas

### BCTS State Machine (14 States)

The protocol uses a 14-state Byzantine Consensus and Trust System (BCTS) model:

1. **INITIALIZED** - Workflow initialized
2. **IDENTITY_REQUIRED** - Identity verification required
3. **IDENTITY_VERIFIED** - Identity verified successfully
4. **AUTHORITY_CHECK** - Checking subject authority
5. **AUTHORIZED** - Subject is authorized
6. **CONSENT_PHASE** - Gathering consent from affected parties
7. **CONSENT_VERIFIED** - Consent thresholds met
8. **GOVERNANCE_REVIEW** - Under governance panel review
9. **GOVERNANCE_PASSED** - Passed governance review
10. **EXECUTION_READY** - Ready for execution
11. **EXECUTING** - Currently executing
12. **COMPLETED** - Execution completed successfully
13. **FINALIZED** - Finalized and recorded
14. **CLOSED** - Workflow closed

## Solution Templates

Pre-built templates for common governance workflows:

### 1. Governance Amendment
Amends governance rules and policies with full council review
- **Nodes**: 7
- **Required Panels**: Identity, Governance, Consent, Kernel
- **Consent Threshold**: 80%
- **Default Duration**: 7 days

### 2. Feature Implementation
Implements new features with tenant isolation
- **Nodes**: 8
- **Required Panels**: Governance, Identity, Infrastructure, Kernel
- **Consent Required**: No
- **Default Duration**: 1 hour

### 3. Bug Fix Deployment
Deploys bug fixes with proof verification
- **Nodes**: 7
- **Required Panels**: Governance, Kernel
- **Consent Required**: No
- **Default Duration**: 30 minutes

### 4. Security Patch
Critical security patches with strict verification
- **Nodes**: 10
- **Required Panels**: Identity, Governance, Kernel, Escalation, Executive
- **Consent Threshold**: 100%
- **Requires Human Approval**: Yes
- **Default Duration**: 5 minutes (urgent)

### 5. Infrastructure Change
Infrastructure modifications with multi-tenant isolation
- **Nodes**: 8
- **Required Panels**: Governance, Identity, Infrastructure, AI, Kernel
- **Consent Threshold**: 75%
- **Isolation Level**: Physical
- **Default Duration**: 30 minutes

### 6. Access Control Update
Updates identity and authorization rules
- **Nodes**: 8
- **Required Panels**: Identity, Governance, Consent, Kernel
- **Consent Required**: Yes
- **Default Duration**: 1 hour

### 7. Escalation Resolution
Resolves governance disputes through escalation
- **Nodes**: 6
- **Required Panels**: Escalation, Kernel, Executive, Consent, Governance
- **Requires Human Approval**: Yes
- **Default Duration**: 10 minutes

## Core Concepts

### Node
A discrete, verifiable unit of execution that represents a specific governance action. Each node:
- Has a type from the 23-node registry
- Accepts specific required inputs
- Produces deterministic outputs
- Belongs to a functional category
- Requires specific council panels for approval
- Has a timeout and retry policy
- Transitions the workflow through BCTS states

### Workflow
A directed acyclic graph of nodes compiled from a council verdict and proposal. Workflows:
- Start with an initial node
- Define dependencies between nodes
- Map to BCTS state transitions
- Validate constitutional invariants
- Execute with fault tolerance policies
- Generate cryptographic proofs
- Record execution in the governance DAG

### Council Verdict
The output of council governance decision-making, containing:
- Panel assessments (FOR/AGAINST/ABSTAIN)
- Consent responses from affected parties
- System state snapshots
- Preceding proposal references
- Resolution details

### Solution
A customized workflow template for common governance patterns. Solutions:
- Start from pre-built templates
- Can be customized with template-specific fields
- Compile to complete Syntaxis workflows
- Deploy through ExoForge pipeline
- Track execution and results

## Usage

### Basic Example

```javascript
const { createSyntaxisEngine } = require('@exochain/syntaxis');

const engine = createSyntaxisEngine();
const createdAtHlc = { physicalMs: 1700000000000, logical: 0 };
const deploymentHlc = { physicalMs: 1700000000001, logical: 0 };

// Create a governance amendment solution
const solution = engine.createSolution('governance-amendment', {
  name: 'Update Voting Threshold',
  author: 'GOVERNANCE_PANEL',
  consentThresholdBasisPoints: 7500,
  maxDuration: 604800000, // 7 days
  createdAtHlc
});

// Deploy the solution
const deployment = engine.deploySolution(solution, {
  path: '/exoforge/deployments',
  deploymentHlc
});
console.log(`Deployment ID: ${deployment.deploymentId}`);
console.log(`Status: ${deployment.status}`);
```

### Compiling from Council Verdict

```javascript
// Create council verdict with panel assessments
const verdict = {
  id: 'verdict_001',
  status: 'APPROVED',
  affectedPanels: ['Governance Panel', 'Kernel Panel'],
  panelAssessments: {
    'Governance Panel': 'FOR',
    'Kernel Panel': 'FOR'
  },
  consentResponses: {},
  systemState: {},
  precedingProposals: []
};

// Create proposal
const proposal = {
  id: 'proposal_001',
  type: 'security-patch',
  proposer: 'SECURITY_TEAM',
  content: { patchVersion: '1.2.3' },
  affectedPanels: ['Governance Panel', 'Kernel Panel'],
  requiresConsent: true,
  requiredConsentBasisPoints: 8000,
  faultTolerant: true,
  createdAtHlc
};

// Compile to workflow
const workflow = engine.compileSyntaxis(verdict, proposal);

// Validate workflow
const validation = engine.validateSyntaxisWorkflow(workflow);
console.log(`Valid: ${validation.valid}`);

// Convert to Archon YAML
const yaml = engine.syntaxisToArchonYaml(workflow);
```

### Getting Node Information

```javascript
// Get a specific node
const node = engine.getNode('governance-propose');

// Get all nodes by category
const nodesByCategory = engine.getNodesByCategory();

// Get BCTS state information
const state = engine.getBCTSState('EXECUTING');
const transitions = engine.getValidTransitions('EXECUTING');

// Get protocol statistics
const stats = engine.getStatistics();
console.log(`Total Nodes: ${stats.totalNodes}`);
console.log(`Categories: ${stats.totalCategories}`);
```

## API Reference

### SyntaxisProtocolEngine

#### Methods

- **`compileSyntaxis(councilVerdict, proposal): Object`**
  - Compiles a council verdict and proposal into a Syntaxis workflow
  - Requires `proposal.createdAtHlc` or `councilVerdict.createdAtHlc`
  - Returns: Complete workflow definition with all nodes and dependencies

- **`validateSyntaxisWorkflow(workflow): Object`**
  - Validates a compiled workflow against the registry
  - Returns: { valid: boolean, errors: string[], nodeCount: number, dependencyCount: number }

- **`syntaxisToArchonYaml(workflow): string`**
  - Converts a Syntaxis workflow to Archon-compatible YAML DAG
  - Returns: YAML definition string

- **`createSolution(solutionType, config): Object`**
  - Creates a custom solution from a template
  - solutionType: One of the 7 solution types
  - config: Customization parameters, including required `createdAtHlc`
  - Returns: Complete solution definition

- **`deploySolution(solution, target): Object`**
  - Deploys a solution through the ExoForge pipeline
  - target: Configuration object including required `deploymentHlc`
  - Returns: Deployment result with status and stages

- **`listSolutionTemplates(): Array`**
  - Lists all available solution templates
  - Returns: Array of template metadata

- **`getNode(nodeType): Object`**
  - Gets a specific node implementation
  - Returns: Node instance

- **`getNodeRegistry(nodeType): Object`**
  - Gets registry entry for a node type
  - Returns: Node metadata and implementation

- **`getNodesByCategory(): Object`**
  - Gets all nodes grouped by category
  - Returns: Object with categories as keys, node arrays as values

- **`getBCTSState(state): Object`**
  - Gets BCTS state information
  - Returns: { description, transitions: string[] }

- **`getValidTransitions(fromState): Array`**
  - Gets valid state transitions
  - Returns: Array of valid next states

- **`getStatistics(): Object`**
  - Gets protocol statistics
  - Returns: { totalNodes, totalCategories, nodesByCategory, totalBCTSStates }

## File Structure

```
/tools/syntaxis/
├── package.json                 # Package metadata
├── index.js                     # Main entry point (exports and API)
├── nodes.js                     # Node type implementations (23 nodes)
├── compiler.js                  # Compilation engine (verdict -> workflow)
├── solutions-builder.js         # Solution templates and deployment
├── test.js                      # Comprehensive test suite
└── README.md                    # This file
```

## Node Execution Model

Each node follows a consistent execution pattern:

1. **Validation**: Validates required inputs
2. **Execution**: Performs node-specific logic
3. **State Transition**: Updates BCTS state
4. **Output Generation**: Produces deterministic outputs
5. **Error Handling**: Records any errors with context

## Security Properties

The Syntaxis Protocol provides:

- **Byzantine Fault Tolerance**: Through BCTS state machine with consensus
- **Cryptographic Proof Generation**: Every execution step generates verifiable proofs
- **Invariant Checking**: Validates constitutional invariants before execution
- **Audit Trail**: Complete DAG of all governance decisions and executions
- **Multi-Panel Oversight**: Critical decisions require multiple panel approvals
- **Escalation Paths**: Unresolved conflicts trigger human escalation
- **Tenant Isolation**: Multi-tenancy support with configurable isolation levels

## Testing

Run the test suite:

```bash
node test.js
```

This will validate:
- Protocol statistics and structure
- Node registry completeness
- BCTS state model validity
- Solution template creation
- Workflow compilation from verdicts
- Workflow validation
- Archon YAML conversion
- Solution deployment
- All 23 node types

## Integration with ExoForge

Compiled Syntaxis workflows are converted to Archon-compatible YAML DAG definitions for execution by ExoForge. The conversion includes:

- Node definitions with inputs/outputs
- Dependency graph
- Execution policies (parallelization, fault tolerance)
- Timeout and retry configurations
- Panel approval requirements
- Invariant coverage mappings

## Version History

- **0.1.0** - Initial release
  - 23 node types across 8 categories
  - 14-state BCTS model
  - 7 solution templates
  - Full workflow compilation and validation
  - Archon YAML export

## License

MIT

## Author

ExoChain Team
