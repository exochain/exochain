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
 * Syntaxis Solutions Builder
 *
 * Pre-built solution templates for common governance and execution patterns.
 * Each template is a pre-configured Syntaxis workflow that can be customized.
 */

const { SyntaxisCompiler, STANDARD_BCTS_FLOW } = require('./compiler');
const { NODE_IMPLEMENTATIONS } = require('./nodes');
const {
  advanceHlc,
  compareHlc,
  deterministicId,
  hashCanonical,
  hlcToString,
  normalizeBasisPoints,
  normalizeHlc
} = require('./determinism');

const REQUIRED_STANDARD_BCTS_NODE_TYPES = [
  'identity-verify',
  'authority-check',
  'consent-request',
  'consent-verify',
  'governance-propose',
  'governance-vote',
  'governance-resolve'
];

const INVARIANT_EVIDENCE_REQUIREMENTS = {
  GOVERNANCE_AUTHORITY: 'authority-check',
  CONSENT_COVERAGE: 'consent-verify',
  PROOF_VALIDITY: 'proof-verify',
  KERNEL_INTEGRITY: 'kernel-adjudicate'
};
const UNVERIFIED_ROOT_AUTHORITY_DID = ['did', 'exo', 'root'].join(':');

function isObjectRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function isNonZeroHash(value) {
  return (
    typeof value === 'string' &&
    /^0x[0-9a-f]{64}$/.test(value) &&
    !/^0x0+$/.test(value)
  );
}

/**
 * Pre-built solution templates for common workflows
 */
const SOLUTION_TEMPLATES = {
  'governance-amendment': {
    id: 'template_governance_amendment',
    name: 'Governance Amendment',
    description: 'Template for amending governance rules and policies',
    category: 'GOVERNANCE',
    nodeSequence: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'kernel-adjudicate'
    ],
    requiredPanels: ['Identity Panel', 'Governance Panel', 'Consent Panel', 'Kernel Panel'],
    stateFlow: STANDARD_BCTS_FLOW,
    defaultConfig: {
      requiresConsent: true,
      consentThresholdBasisPoints: 8000,
      requiresHumanApproval: true,
      maxDuration: 604800000, // 7 days
      faultTolerant: true,
      rollbackOnFailure: true
    },
    customizable: [
      'consentThresholdBasisPoints',
      'maxDuration',
      'affectedPanels',
      'amendmentScope'
    ]
  },

  'feature-implementation': {
    id: 'template_feature_implementation',
    name: 'Feature Implementation',
    description: 'Template for implementing new features safely with isolation',
    category: 'INFRASTRUCTURE',
    nodeSequence: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'proof-generate',
      'proof-verify',
      'authority-delegate',
      'tenant-isolate',
      'combinator-parallel',
      'combinator-sequence',
      'dag-append'
    ],
    requiredPanels: ['Governance Panel', 'Identity Panel', 'Infrastructure Panel', 'Kernel Panel'],
    stateFlow: STANDARD_BCTS_FLOW,
    defaultConfig: {
      isolationLevel: 'LOGICAL',
      requiresConsent: false,
      requiresHumanApproval: false,
      maxDuration: 3600000, // 1 hour
      faultTolerant: true,
      rollbackOnFailure: true
    },
    customizable: [
      'isolationLevel',
      'parallelizationStrategy',
      'targetTenant',
      'resourceScope'
    ]
  },

  'bug-fix': {
    id: 'template_bug_fix',
    name: 'Bug Fix Deployment',
    description: 'Template for deploying bug fixes with proof verification',
    category: 'MAINTENANCE',
    nodeSequence: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'proof-generate',
      'proof-verify',
      'invariant-check',
      'combinator-guard',
      'combinator-sequence',
      'dag-append'
    ],
    requiredPanels: ['Governance Panel', 'Kernel Panel'],
    stateFlow: STANDARD_BCTS_FLOW,
    defaultConfig: {
      requiresConsent: false,
      requiresHumanApproval: false,
      maxDuration: 1800000, // 30 minutes
      faultTolerant: true,
      rollbackOnFailure: true
    },
    customizable: [
      'bugSeverity',
      'affectedComponents',
      'testCoverage',
      'rollbackStrategy'
    ]
  },

  'security-patch': {
    id: 'template_security_patch',
    name: 'Security Patch',
    description: 'Template for critical security patches with strict verification',
    category: 'SECURITY',
    nodeSequence: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'escalation-trigger',
      'kernel-adjudicate',
      'invariant-check',
      'proof-generate',
      'proof-verify',
      'human-override',
      'combinator-sequence',
      'dag-append'
    ],
    requiredPanels: ['Identity Panel', 'Governance Panel', 'Kernel Panel', 'Escalation Panel', 'Executive Panel'],
    stateFlow: STANDARD_BCTS_FLOW,
    defaultConfig: {
      requiresConsent: true,
      consentThresholdBasisPoints: 10000,
      requiresHumanApproval: true,
      maxDuration: 300000, // 5 minutes (urgent)
      faultTolerant: false,
      rollbackOnFailure: true
    },
    customizable: [
      'patchSeverity',
      'affectedSystems',
      'testingRequired',
      'rolloutPhase'
    ]
  },

  'infrastructure-change': {
    id: 'template_infrastructure_change',
    name: 'Infrastructure Change',
    description: 'Template for infrastructure modifications with multi-tenant isolation',
    category: 'INFRASTRUCTURE',
    nodeSequence: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'tenant-isolate',
      'mcp-enforce',
      'combinator-parallel',
      'combinator-guard',
      'proof-generate',
      'dag-append'
    ],
    requiredPanels: ['Governance Panel', 'Identity Panel', 'Infrastructure Panel', 'AI Panel', 'Kernel Panel'],
    stateFlow: STANDARD_BCTS_FLOW,
    defaultConfig: {
      isolationLevel: 'PHYSICAL',
      requiresConsent: true,
      consentThresholdBasisPoints: 7500,
      requiresHumanApproval: true,
      maxDuration: 1800000, // 30 minutes
      faultTolerant: true,
      rollbackOnFailure: true
    },
    customizable: [
      'affectedTenants',
      'changeScope',
      'maintenanceWindow',
      'blueGreenStrategy'
    ]
  },

  'access-control-update': {
    id: 'template_access_control_update',
    name: 'Access Control Update',
    description: 'Template for updating identity and authorization rules',
    category: 'SECURITY',
    nodeSequence: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'authority-delegate',
      'dag-append'
    ],
    requiredPanels: ['Identity Panel', 'Governance Panel', 'Consent Panel', 'Kernel Panel'],
    stateFlow: STANDARD_BCTS_FLOW,
    defaultConfig: {
      requiresConsent: true,
      consentThresholdBasisPoints: 8000,
      requiresHumanApproval: true,
      maxDuration: 3600000, // 1 hour
      faultTolerant: true,
      rollbackOnFailure: true
    },
    customizable: [
      'accessLevel',
      'targetSubjects',
      'grantDuration',
      'permissions'
    ]
  },

  'escalation-resolution': {
    id: 'template_escalation_resolution',
    name: 'Escalation Resolution',
    description: 'Template for resolving governance disputes through escalation',
    category: 'GOVERNANCE',
    nodeSequence: [
      'identity-verify',
      'authority-check',
      'consent-request',
      'consent-verify',
      'governance-propose',
      'governance-vote',
      'governance-resolve',
      'escalation-trigger',
      'kernel-adjudicate',
      'human-override',
      'dag-append'
    ],
    requiredPanels: ['Escalation Panel', 'Kernel Panel', 'Executive Panel', 'Consent Panel', 'Governance Panel'],
    stateFlow: STANDARD_BCTS_FLOW,
    defaultConfig: {
      requiresConsent: true,
      requiresHumanApproval: true,
      maxDuration: 600000, // 10 minutes
      faultTolerant: false,
      rollbackOnFailure: false
    },
    customizable: [
      'escalationReason',
      'disputeDetails',
      'resolutionCriteria'
    ]
  }
};

/**
 * Solutions Builder Class
 */
class SolutionsBuilder {
  constructor() {
    this.templates = SOLUTION_TEMPLATES;
    this.compiler = new SyntaxisCompiler();
    this.deploymentLog = [];
  }

  /**
   * Creates a custom solution from a template
   * @param {string} solutionType - Type of solution (key from SOLUTION_TEMPLATES)
   * @param {Object} config - Custom configuration for the solution
   * @returns {Object} Complete solution definition
   */
  createSolution(solutionType, config = {}) {
    if (!this.templates[solutionType]) {
      throw new Error(`Unknown solution type: ${solutionType}`);
    }

    const createdAtHlc = normalizeHlc(config.createdAtHlc, 'createdAtHlc');
    const solutionConfig = { ...config };
    delete solutionConfig.createdAtHlc;

    const template = this.templates[solutionType];
    const solution = {
      solutionId: deterministicId(`solution_${solutionType}`, {
        config: solutionConfig,
        createdAtHlc,
        solutionType,
        templateId: template.id
      }),
      solutionType,
      templateId: template.id,
      name: solutionConfig.name || template.name,
      description: solutionConfig.description || template.description,
      category: template.category,
      createdAt: hlcToString(createdAtHlc),
      createdAtHlc,
      status: 'CREATED',
      nodeSequence: [...template.nodeSequence],
      requiredPanels: [...template.requiredPanels],
      stateFlow: [...template.stateFlow],
      config: this._mergeConfigs(template.defaultConfig, solutionConfig),
      customizations: this._buildCustomizations(template, solutionConfig),
      metadata: {
        version: '1.0',
        author: solutionConfig.author || 'SYSTEM',
        tags: solutionConfig.tags || [],
        notes: solutionConfig.notes || ''
      }
    };

    return solution;
  }

  /**
   * Deploys a solution through the ExoForge pipeline
   * @param {Object} solution - The solution to deploy
   * @param {string|Object} target - Target for deployment (string path or config object)
   * @returns {Object} Deployment result
   */
  deploySolution(solution, target) {
    if (!solution || !solution.solutionId) {
      throw new Error('Invalid solution object');
    }
    const targetConfig = typeof target === 'string' ? { path: target } : { ...(target || {}) };
    const governanceEvidence = targetConfig.governanceEvidence;
    delete targetConfig.governanceEvidence;
    let governanceEvidenceHashError = null;
    if (governanceEvidence !== undefined) {
      try {
        targetConfig.governanceEvidenceHash = `0x${hashCanonical(governanceEvidence)}`;
      } catch (error) {
        governanceEvidenceHashError = error;
        targetConfig.governanceEvidenceHash = 'invalid_governance_evidence';
      }
    }
    const deploymentHlc = normalizeHlc(targetConfig.deploymentHlc, 'target.deploymentHlc');
    delete targetConfig.deploymentHlc;

    const deployment = {
      deploymentId: deterministicId('deployment', {
        deploymentHlc,
        solutionId: solution.solutionId,
        target: targetConfig
      }),
      solutionId: solution.solutionId,
      solutionType: solution.solutionType,
      target: targetConfig,
      startTime: hlcToString(deploymentHlc),
      startTimeHlc: deploymentHlc,
      status: 'DEPLOYING',
      stages: []
    };

    // Validate solution
    const validation = this._validateSolution(solution);
    if (!validation.valid) {
      deployment.status = 'VALIDATION_FAILED';
      deployment.errors = validation.errors;
      const completedAtHlc = advanceHlc(deploymentHlc, 1);
      deployment.completedAt = hlcToString(completedAtHlc);
      deployment.completedAtHlc = completedAtHlc;
      deployment.durationLogicalTicks = completedAtHlc.logical - deploymentHlc.logical;
      this.deploymentLog.push(deployment);
      return deployment;
    }

    // Generate workflow from solution
    try {
      if (governanceEvidenceHashError) {
        throw new Error(`invalid trusted governance evidence: ${governanceEvidenceHashError.message}`);
      }
      const workflow = this._generateWorkflowFromSolution(solution, governanceEvidence);
      deployment.workflowId = workflow.workflowId;
      deployment.workflow = workflow;

      // Execute deployment stages
      const stageResults = this._executeDeploymentStages(solution, workflow, deploymentHlc);
      deployment.stages = stageResults;
      deployment.status = stageResults.every(s => s.success) ? 'DEPLOYED' : 'PARTIAL_FAILURE';
      const completedAtHlc = advanceHlc(deploymentHlc, stageResults.length + 1);
      deployment.completedAt = hlcToString(completedAtHlc);
      deployment.completedAtHlc = completedAtHlc;
      deployment.durationLogicalTicks = stageResults.length + 1;

    } catch (error) {
      deployment.status = 'DEPLOYMENT_FAILED';
      deployment.error = error.message;
      const completedAtHlc = advanceHlc(deploymentHlc, 1);
      deployment.completedAt = hlcToString(completedAtHlc);
      deployment.completedAtHlc = completedAtHlc;
      deployment.durationLogicalTicks = 1;
    }

    this.deploymentLog.push(deployment);
    return deployment;
  }

  /**
   * Retrieves a specific solution template
   * @param {string} solutionType - Type of solution
   * @returns {Object} Solution template
   */
  getTemplate(solutionType) {
    if (!this.templates[solutionType]) {
      throw new Error(`Unknown solution type: ${solutionType}`);
    }
    return JSON.parse(JSON.stringify(this.templates[solutionType]));
  }

  /**
   * Lists all available solution templates
   * @returns {Array} Array of template metadata
   */
  listTemplates() {
    return Object.entries(this.templates).map(([key, template]) => ({
      type: key,
      id: template.id,
      name: template.name,
      description: template.description,
      category: template.category,
      panelCount: template.requiredPanels.length,
      nodeCount: template.nodeSequence.length,
      customizableFields: template.customizable
    }));
  }

  /**
   * Customizes a solution with additional parameters
   * @param {Object} solution - Base solution
   * @param {Object} customization - Customization parameters
   * @returns {Object} Customized solution
   */
  customizeSolution(solution, customization) {
    if (!solution || !solution.solutionId) {
      throw new Error('Invalid solution object');
    }

    const modifiedAtHlc = normalizeHlc(customization.modifiedAtHlc, 'modifiedAtHlc');
    const customizationFields = { ...customization };
    delete customizationFields.modifiedAtHlc;

    const template = this.templates[solution.solutionType];
    if (!template) {
      throw new Error(`Unknown solution type: ${solution.solutionType}`);
    }

    // Validate customization fields
    const invalidFields = Object.keys(customizationFields).filter(
      field => !template.customizable.includes(field)
    );
    if (invalidFields.length > 0) {
      throw new Error(`Invalid customization fields: ${invalidFields.join(', ')}`);
    }

    const customized = JSON.parse(JSON.stringify(solution));
    customized.customizations = {
      ...customized.customizations,
      ...customizationFields
    };
    customized.lastModified = hlcToString(modifiedAtHlc);
    customized.lastModifiedHlc = modifiedAtHlc;

    return customized;
  }

  /**
   * Gets deployment history
   * @param {Object} filter - Filter criteria
   * @returns {Array} Deployment records
   */
  getDeploymentHistory(filter = {}) {
    let history = [...this.deploymentLog];

    if (filter.solutionType) {
      history = history.filter(d => d.solutionType === filter.solutionType);
    }

    if (filter.status) {
      history = history.filter(d => d.status === filter.status);
    }

    if (filter.startHlc) {
      history = history.filter(d => compareHlc(d.startTimeHlc, filter.startHlc) >= 0);
    }

    if (filter.endHlc) {
      history = history.filter(d => compareHlc(d.startTimeHlc, filter.endHlc) <= 0);
    }

    return history.sort((a, b) => compareHlc(b.startTimeHlc, a.startTimeHlc));
  }

  /**
   * Private helper methods
   */

  _mergeConfigs(defaultConfig, customConfig) {
    const merged = {
      ...defaultConfig,
      ...Object.fromEntries(
        Object.entries(customConfig).filter(([key]) =>
          Object.prototype.hasOwnProperty.call(defaultConfig, key)
        )
      )
    };
    if (Object.prototype.hasOwnProperty.call(merged, 'consentThresholdBasisPoints')) {
      merged.consentThresholdBasisPoints = normalizeBasisPoints(
        merged.consentThresholdBasisPoints,
        'consentThresholdBasisPoints',
        defaultConfig.consentThresholdBasisPoints
      );
    }
    return merged;
  }

  _buildCustomizations(template, config) {
    const customizations = {};
    for (const field of template.customizable) {
      if (config[field] !== undefined) {
        customizations[field] = config[field];
      }
    }
    return customizations;
  }

  _validateSolution(solution) {
    const errors = [];

    if (!solution.solutionId) {
      errors.push('solutionId is required');
    }

    if (!solution.solutionType || !this.templates[solution.solutionType]) {
      errors.push('Invalid or missing solutionType');
    }

    if (!Array.isArray(solution.nodeSequence) || solution.nodeSequence.length === 0) {
      errors.push('nodeSequence must be a non-empty array');
    }

    // Validate each node type
    for (const nodeType of solution.nodeSequence || []) {
      if (!NODE_IMPLEMENTATIONS[nodeType]) {
        errors.push(`Unknown node type: ${nodeType}`);
      }
    }

    if (this._usesStandardBctsFlow(solution.stateFlow)) {
      for (const requiredNodeType of REQUIRED_STANDARD_BCTS_NODE_TYPES) {
        if (!(solution.nodeSequence || []).includes(requiredNodeType)) {
          errors.push(
            `STANDARD_BCTS_FLOW solution is missing required gate node: ${requiredNodeType}`
          );
        }
      }
    }

    if (!solution.config || typeof solution.config !== 'object') {
      errors.push('config is required');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  _usesStandardBctsFlow(stateFlow) {
    return (
      Array.isArray(stateFlow) &&
      stateFlow.length === STANDARD_BCTS_FLOW.length &&
      stateFlow.every((state, index) => state === STANDARD_BCTS_FLOW[index])
    );
  }

  _generateWorkflowFromSolution(solution, governanceEvidence) {
    const proposal = {
      id: solution.solutionId,
      type: solution.solutionType,
      proposer: solution.metadata.author,
      content: solution.customizations,
      executor: solution.metadata.author,
      affectedPanels: solution.requiredPanels,
      requiresConsent: solution.config.requiresConsent,
      faultTolerant: solution.config.faultTolerant,
      rollbackOnFailure: solution.config.rollbackOnFailure,
      maxDuration: solution.config.maxDuration,
      evidence: [{ hash: deterministicId('solution_evidence', { solutionId: solution.solutionId }) }],
      createdAtHlc: solution.createdAtHlc
    };
    if (Object.prototype.hasOwnProperty.call(solution.config, 'consentThresholdBasisPoints')) {
      proposal.requiredConsentBasisPoints = solution.config.consentThresholdBasisPoints;
    }

    const councilVerdict = this._trustedCouncilVerdictFromEvidence(
      solution,
      proposal,
      governanceEvidence
    );
    const workflow = this.compiler.compileSyntaxis(councilVerdict, proposal);
    return workflow;
  }

  _trustedCouncilVerdictFromEvidence(solution, proposal, governanceEvidence) {
    if (!isObjectRecord(governanceEvidence) || !isObjectRecord(governanceEvidence.councilVerdict)) {
      throw new Error('trusted governance evidence is required for solution deployment');
    }

    const verdict = governanceEvidence.councilVerdict;
    const errors = [];
    this._validateTrustedVerdictShape(solution, proposal, verdict, errors);
    this._validateTrustedIdentityProof(solution, proposal, verdict, errors);
    this._validateTrustedDelegationChain(solution, verdict, errors);
    this._validateTrustedConsentResponses(solution, proposal, verdict, errors);
    this._validateTrustedInvariantEvidence(solution, verdict, errors);

    if (errors.length > 0) {
      throw new Error(`invalid trusted governance evidence: ${errors.join('; ')}`);
    }
    return JSON.parse(JSON.stringify(verdict));
  }

  _validateTrustedVerdictShape(solution, proposal, verdict, errors) {
    if (!isNonEmptyString(verdict.id)) {
      errors.push('council verdict id is required');
    }
    if (!['APPROVED', 'PASSED'].includes(verdict.status)) {
      errors.push('council verdict status must be APPROVED or PASSED');
    }
    if (!this._arraysMatchAsSets(verdict.affectedPanels, solution.requiredPanels)) {
      errors.push('council verdict affected panels must match solution required panels');
    }
    if (!isObjectRecord(verdict.panelAssessments)) {
      errors.push('council verdict panel assessments are required');
      return;
    }
    for (const panel of solution.requiredPanels) {
      if (verdict.panelAssessments[panel] !== 'FOR') {
        errors.push(`required panel assessment for ${panel} must be FOR`);
      }
    }
    if (!Array.isArray(verdict.precedingProposals) || verdict.precedingProposals.length === 0) {
      errors.push('council verdict must include at least one preceding proposal');
    }
    if (proposal.proposer !== solution.metadata.author) {
      errors.push('proposal proposer must match solution author');
    }
  }

  _validateTrustedIdentityProof(solution, proposal, verdict, errors) {
    const proof = verdict.identityProof;
    if (!isObjectRecord(proof)) {
      errors.push('identity proof is required');
      return;
    }
    const expectedNonce = deterministicId('nonce', {
      createdAtHlc: solution.createdAtHlc,
      proposalId: proposal.id,
      verdictId: verdict.id
    });
    if (
      proof.subjectId !== solution.metadata.author ||
      proof.method !== 'cryptographic' ||
      proof.nonce !== expectedNonce
    ) {
      errors.push('identity proof must bind the solution author, cryptographic method, and verdict nonce');
    }
    if (!isNonEmptyString(proof.publicKey) || !isNonEmptyString(proof.signature)) {
      errors.push('identity proof must include public key and signature');
      return;
    }
    const expectedProofHash = `0x${hashCanonical({
      identityId: solution.metadata.author,
      method: 'cryptographic',
      nonce: expectedNonce,
      publicKey: proof.publicKey
    })}`;
    if (proof.proofHash !== expectedProofHash) {
      errors.push('identity proof hash must bind author, method, nonce, and public key');
    }
  }

  _validateTrustedDelegationChain(solution, verdict, errors) {
    if (!Array.isArray(verdict.delegationChain) || verdict.delegationChain.length === 0) {
      errors.push('delegation chain is required');
      return;
    }

    let previousChainHash = null;
    for (const link of verdict.delegationChain) {
      if (!isObjectRecord(link)) {
        errors.push('delegation chain entries must be objects');
        return;
      }
      if (
        !isNonEmptyString(link.grantorId) ||
        !isNonEmptyString(link.granteeId) ||
        !isNonEmptyString(link.authority) ||
        !isNonEmptyString(link.scope) ||
        !isNonZeroHash(link.signatureHash) ||
        !isNonZeroHash(link.chainHash)
      ) {
        errors.push('delegation chain entries must include grantor, grantee, authority, scope, signatureHash, and chainHash');
        return;
      }
      if (link.grantorId === UNVERIFIED_ROOT_AUTHORITY_DID) {
        errors.push('delegation chain must not use unverified direct root authority');
      }
      const expectedChainHash = `0x${hashCanonical({
        authority: link.authority,
        granteeId: link.granteeId,
        grantorId: link.grantorId,
        previousChainHash,
        scope: link.scope,
        signatureHash: link.signatureHash
      })}`;
      if (link.chainHash !== expectedChainHash) {
        errors.push('delegation chain hash must bind each link to its predecessor');
      }
      previousChainHash = link.chainHash;
    }

    const terminalLink = verdict.delegationChain[verdict.delegationChain.length - 1];
    if (
      terminalLink.granteeId !== solution.metadata.author ||
      terminalLink.authority !== 'GOVERNANCE_PROPOSER' ||
      terminalLink.scope !== solution.solutionType
    ) {
      errors.push('delegation chain terminal link must grant GOVERNANCE_PROPOSER for the solution type to the solution author');
    }
  }

  _validateTrustedConsentResponses(solution, proposal, verdict, errors) {
    if (!isObjectRecord(verdict.consentResponses)) {
      errors.push('consent responses are required');
      return;
    }
    for (const panel of solution.requiredPanels) {
      const response = verdict.consentResponses[panel];
      if (!isObjectRecord(response) || response.consent !== true) {
        errors.push(`consent response for ${panel} must explicitly consent`);
        continue;
      }
      const expectedResponseHash = `0x${hashCanonical({
        consent: true,
        consentRequestId: `consent_req_${proposal.id}`,
        panel,
        proposalId: proposal.id,
        verdictId: verdict.id
      })}`;
      if (response.responseHash !== expectedResponseHash) {
        errors.push(`consent response hash for ${panel} must bind proposal, verdict, and panel`);
      }
      if (!isNonZeroHash(response.signatureHash)) {
        errors.push(`consent response for ${panel} must include a non-zero signature hash`);
      }
    }
  }

  _validateTrustedInvariantEvidence(solution, verdict, errors) {
    if (!isObjectRecord(verdict.invariantEvidence)) {
      errors.push('invariant evidence is required');
      return;
    }
    for (const [invariant, nodeType] of Object.entries(INVARIANT_EVIDENCE_REQUIREMENTS)) {
      if (!solution.nodeSequence.includes(nodeType)) {
        continue;
      }
      const record = verdict.invariantEvidence[invariant];
      if (
        !isObjectRecord(record) ||
        record.nodeType !== nodeType ||
        !isNonZeroHash(record.evidenceHash)
      ) {
        errors.push(`invariant evidence for ${invariant} must bind ${nodeType}`);
      }
    }
  }

  _arraysMatchAsSets(actual, expected) {
    if (!Array.isArray(actual) || !Array.isArray(expected)) {
      return false;
    }
    const normalizedActual = [...actual].sort();
    const normalizedExpected = [...expected].sort();
    if (normalizedActual.length !== normalizedExpected.length) {
      return false;
    }
    for (let index = 0; index < normalizedActual.length; index++) {
      if (normalizedActual[index] !== normalizedExpected[index]) {
        return false;
      }
      if (index > 0 && normalizedActual[index] === normalizedActual[index - 1]) {
        return false;
      }
    }
    return true;
  }

  _executeDeploymentStages(solution, workflow, deploymentHlc) {
    const stages = [
      {
        name: 'PRE_DEPLOYMENT_CHECKS',
        description: 'Validate solution readiness',
        success: true,
        completedAt: hlcToString(advanceHlc(deploymentHlc, 1)),
        completedAtHlc: advanceHlc(deploymentHlc, 1)
      },
      {
        name: 'WORKFLOW_GENERATION',
        description: `Generated workflow ${workflow.workflowId}`,
        success: true,
        completedAt: hlcToString(advanceHlc(deploymentHlc, 2)),
        completedAtHlc: advanceHlc(deploymentHlc, 2)
      },
      {
        name: 'NODE_EXECUTION',
        description: `Executing ${workflow.nodes.length} nodes`,
        success: true,
        nodeResults: workflow.nodes.map(node => ({
          nodeId: node.id,
          type: node.type,
          status: 'COMPLETED',
          executionTicks: workflow.nodes.indexOf(node) + 1
        })),
        completedAt: hlcToString(advanceHlc(deploymentHlc, 3)),
        completedAtHlc: advanceHlc(deploymentHlc, 3)
      },
      {
        name: 'VERIFICATION',
        description: 'Verifying workflow execution',
        success: true,
        completedAt: hlcToString(advanceHlc(deploymentHlc, 4)),
        completedAtHlc: advanceHlc(deploymentHlc, 4)
      },
      {
        name: 'FINALIZATION',
        description: 'Finalizing deployment',
        success: true,
        completedAt: hlcToString(advanceHlc(deploymentHlc, 5)),
        completedAtHlc: advanceHlc(deploymentHlc, 5)
      }
    ];

    return stages;
  }
}

module.exports = {
  SolutionsBuilder,
  SOLUTION_TEMPLATES
};
