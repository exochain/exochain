/**
 * Syntaxis Protocol Engine - Test Suite
 *
 * Demonstrates usage of the Syntaxis Protocol Engine with various workflows
 */

const {
  createSyntaxisEngine,
  NODE_REGISTRY,
  BCTS_TRANSITIONS,
  BCTS_STATES
} = require('./index');

const CREATED_AT_HLC = { physicalMs: 1700000000000, logical: 0 };
const SECURITY_HLC = { physicalMs: 1700000000000, logical: 1 };
const INFRA_HLC = { physicalMs: 1700000000000, logical: 2 };
const DEPLOYMENT_HLC = { physicalMs: 1700000000001, logical: 0 };

/**
 * Run all tests
 */
async function runTests() {
  const engine = createSyntaxisEngine();

  console.log('========================================');
  console.log('Syntaxis Protocol Engine Test Suite');
  console.log('========================================\n');

  try {
    // Test 1: Engine Statistics
    console.log('TEST 1: Protocol Statistics');
    console.log('---------------------------');
    const stats = engine.getStatistics();
    console.log(`Total Nodes: ${stats.totalNodes}`);
    console.log(`Total Categories: ${stats.totalCategories}`);
    console.log(`Total BCTS States: ${stats.totalBCTSStates}`);
    console.log(`Available Solutions: ${stats.availableSolutionTemplates}`);
    console.log('Nodes by Category:');
    Object.entries(stats.nodesByCategory).forEach(([cat, count]) => {
      console.log(`  - ${cat}: ${count}`);
    });
    console.log('\n');

    // Test 2: Get Nodes by Category
    console.log('TEST 2: Nodes by Category');
    console.log('------------------------');
    const nodesByCategory = engine.getNodesByCategory();
    for (const [category, nodes] of Object.entries(nodesByCategory)) {
      console.log(`\n${category}:`);
      nodes.forEach(node => {
        console.log(`  - ${node.type}: ${node.description}`);
        console.log(`    Inputs: ${node.requiredInputs.join(', ')}`);
      });
    }
    console.log('\n');

    // Test 3: BCTS State Model
    console.log('TEST 3: BCTS State Model');
    console.log('------------------------');
    const initialState = 'INITIALIZED';
    console.log(`Starting state: ${initialState}`);
    console.log(`Description: ${engine.getBCTSState(initialState).description}`);
    console.log(`Valid transitions: ${engine.getValidTransitions(initialState).join(', ')}`);
    console.log('\n');

    // Test 4: Create Governance Amendment Solution
    console.log('TEST 4: Create Governance Amendment Solution');
    console.log('-------------------------------------------');
    const amendmentSolution = engine.createSolution('governance-amendment', {
      name: 'Update Voting Threshold',
      author: 'GOVERNANCE_PANEL',
      tags: ['critical', 'governance'],
      consentThresholdBasisPoints: 7500,
      maxDuration: 604800000,
      createdAtHlc: CREATED_AT_HLC
    });
    console.log(`Solution ID: ${amendmentSolution.solutionId}`);
    console.log(`Type: ${amendmentSolution.solutionType}`);
    console.log(`Nodes: ${amendmentSolution.nodeSequence.length}`);
    console.log(`Required Panels: ${amendmentSolution.requiredPanels.join(', ')}`);
    console.log('\n');

    // Test 5: Create Security Patch Solution
    console.log('TEST 5: Create Security Patch Solution');
    console.log('--------------------------------------');
    const securitySolution = engine.createSolution('security-patch', {
      name: 'Critical Security Patch',
      author: 'SECURITY_TEAM',
      patchSeverity: 'CRITICAL',
      affectedSystems: ['AUTH_SERVICE', 'LEDGER_SERVICE'],
      testingRequired: true,
      rolloutPhase: 1,
      createdAtHlc: SECURITY_HLC
    });
    console.log(`Solution ID: ${securitySolution.solutionId}`);
    console.log(`Type: ${securitySolution.solutionType}`);
    console.log(`Status: ${securitySolution.status}`);
    console.log(`Config:`, JSON.stringify(securitySolution.config, null, 2));
    console.log('\n');

    // Test 6: Compile Workflow
    console.log('TEST 6: Compile Governance Workflow');
    console.log('-----------------------------------');
    const mockCouncilVerdict = {
      id: 'verdict_test_001',
      status: 'APPROVED',
      affectedPanels: ['Identity Panel', 'Governance Panel', 'Consent Panel'],
      panelAssessments: {
        'Identity Panel': 'FOR',
        'Governance Panel': 'FOR',
        'Consent Panel': 'FOR'
      },
      consentResponses: {},
      systemState: {},
      precedingProposals: []
    };

    const mockProposal = {
      id: 'proposal_test_001',
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
      createdAtHlc: CREATED_AT_HLC
    };

    const workflow = engine.compileSyntaxis(mockCouncilVerdict, mockProposal);
    console.log(`Workflow ID: ${workflow.workflowId}`);
    console.log(`Proposal: ${workflow.proposalId}`);
    console.log(`Status: ${workflow.status}`);
    console.log(`Nodes: ${workflow.nodes.length}`);
    console.log(`State Flow: ${workflow.stateFlow.join(' -> ')}`);
    console.log('\n');

    // Test 7: Validate Workflow
    console.log('TEST 7: Validate Compiled Workflow');
    console.log('----------------------------------');
    const validation = engine.validateSyntaxisWorkflow(workflow);
    console.log(`Valid: ${validation.valid}`);
    console.log(`Nodes: ${validation.nodeCount}`);
    console.log(`Dependencies: ${validation.dependencyCount}`);
    if (validation.errors.length > 0) {
      console.log('Errors:', validation.errors);
    } else {
      console.log('No validation errors');
    }
    console.log('\n');

    // Test 8: Convert to Archon YAML
    console.log('TEST 8: Convert to Archon YAML (First 30 lines)');
    console.log('----------------------------------------------');
    const yaml = engine.syntaxisToArchonYaml(workflow);
    const yamlLines = yaml.split('\n');
    yamlLines.slice(0, 30).forEach(line => {
      console.log(line);
    });
    if (yamlLines.length > 30) {
      console.log(`... (${yamlLines.length - 30} more lines)`);
    }
    console.log('\n');

    // Test 9: Deploy Solution
    console.log('TEST 9: Deploy Solution');
    console.log('-----------------------');
    const deployment = engine.deploySolution(amendmentSolution, {
      path: '/exoforge/deployments',
      environment: 'PRODUCTION',
      deploymentHlc: DEPLOYMENT_HLC
    });
    console.log(`Deployment ID: ${deployment.deploymentId}`);
    console.log(`Solution ID: ${deployment.solutionId}`);
    console.log(`Status: ${deployment.status}`);
    console.log(`Duration: ${deployment.durationLogicalTicks} logical ticks`);
    console.log(`Stages Completed: ${deployment.stages.length}`);
    deployment.stages.forEach((stage, idx) => {
      console.log(`  ${idx + 1}. ${stage.name}: ${stage.description}`);
    });
    console.log('\n');

    // Test 10: List Solution Templates
    console.log('TEST 10: Available Solution Templates');
    console.log('-------------------------------------');
    const templates = engine.listSolutionTemplates();
    templates.forEach(template => {
      console.log(`\n${template.name}:`);
      console.log(`  Type: ${template.type}`);
      console.log(`  Category: ${template.category}`);
      console.log(`  Nodes: ${template.nodeCount}`);
      console.log(`  Panels: ${template.panelCount}`);
      console.log(`  Customizable: ${template.customizableFields.join(', ')}`);
    });
    console.log('\n');

    // Test 11: Node Registry Information
    console.log('TEST 11: Sample Node Registry Entry');
    console.log('-----------------------------------');
    const nodeInfo = engine.getNodeRegistry('governance-propose');
    console.log(`Node Type: ${nodeInfo.implementation.nodeType}`);
    console.log(`Category: ${nodeInfo.category}`);
    console.log(`Description: ${nodeInfo.description}`);
    console.log(`Required Inputs: ${nodeInfo.requiredInputs.join(', ')}`);
    console.log(`Outputs: ${nodeInfo.outputs.join(', ')}`);
    console.log(`Timeout: ${nodeInfo.timeoutMs}ms`);
    console.log(`Required Panels: ${nodeInfo.requiredPanels.join(', ')}`);
    console.log('\n');

    // Test 12: Complex Workflow with Multiple Solutions
    console.log('TEST 12: Complex Workflow - Infrastructure Change');
    console.log('------------------------------------------------');
    const infraSolution = engine.createSolution('infrastructure-change', {
      name: 'Database Migration',
      author: 'INFRASTRUCTURE_TEAM',
      affectedTenants: ['tenant-prod-001', 'tenant-prod-002'],
      changeScope: 'FULL_DATABASE_MIGRATION',
      maintenanceWindow: '2024-04-15T00:00:00Z',
      blueGreenStrategy: true,
      consentThresholdBasisPoints: 7500,
      createdAtHlc: INFRA_HLC
    });
    console.log(`Solution: ${infraSolution.name}`);
    console.log(`Nodes in Sequence: ${infraSolution.nodeSequence.length}`);
    console.log('Node Sequence:');
    infraSolution.nodeSequence.forEach((node, idx) => {
      console.log(`  ${idx + 1}. ${node}`);
    });
    console.log(`Configuration:`, JSON.stringify(infraSolution.config, null, 2));
    console.log('\n');

    // Summary
    console.log('========================================');
    console.log('All Tests Completed Successfully!');
    console.log('========================================');
    console.log(`\nProtocol Version: 0.1.0`);
    console.log(`Total Node Types: ${stats.totalNodes}`);
    console.log(`Total Categories: ${stats.totalCategories}`);
    console.log(`BCTS State Machine: ${stats.totalBCTSStates} states`);
    console.log(`Solution Templates: ${stats.availableSolutionTemplates}`);

  } catch (error) {
    console.error('ERROR:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

/**
 * Run tests if this is the main module
 */
if (require.main === module) {
  runTests().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

module.exports = { runTests };
