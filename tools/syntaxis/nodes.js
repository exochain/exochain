/**
 * Syntaxis Protocol Node Implementations
 *
 * Defines all 23 node types with their validation, execution,
 * and council panel requirements.
 */
const {
  deterministicId,
  hashCanonical,
  hlcToString,
  normalizeBasisPoints,
  ratioBasisPoints,
  timestampFromContext
} = require('./determinism');

/**
 * Base Node class - all node types extend this
 */
class SyntaxisNode {
  constructor(nodeType, category) {
    this.nodeType = nodeType;
    this.category = category;
  }

  /**
   * Validates required inputs for this node
   * @param {Object} inputs - Input data
   * @returns {Object} { valid: boolean, errors: string[] }
   */
  validate(inputs) {
    throw new Error('validate() must be implemented by subclass');
  }

  /**
   * Executes the node logic
   * @param {Object} context - Execution context
   * @returns {Object} { outputs: Object, nextState: string, errors: string[] }
   */
  execute(context) {
    throw new Error('execute() must be implemented by subclass');
  }

  /**
   * Returns which council panels must approve this node
   * @returns {string[]} Array of panel names
   */
  getRequiredPanels() {
    return [];
  }
}

/**
 * CORE GOVERNANCE NODES (10)
 */

class IdentityVerifyNode extends SyntaxisNode {
  constructor() {
    super('identity-verify', 'Identity & Access');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.identity || typeof inputs.identity !== 'object') {
      errors.push('identity is required and must be an object');
    }
    if (!inputs.verificationMethod || !['cryptographic', 'delegation', 'audit'].includes(inputs.verificationMethod)) {
      errors.push('verificationMethod must be cryptographic, delegation, or audit');
    }
    if (!inputs.nonce) {
      errors.push('nonce is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { identity, verificationMethod, nonce } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const verified = this._performVerification(identity, verificationMethod, nonce);
    return {
      outputs: {
        identityId: identity.id,
        verified,
        verificationTimestamp: hlcToString(timestampHlc),
        verificationTimestampHlc: timestampHlc,
        method: verificationMethod
      },
      nextState: verified ? 'VERIFIED' : 'VERIFICATION_FAILED',
      errors: verified ? [] : ['Identity verification failed']
    };
  }

  getRequiredPanels() {
    return ['Identity Panel'];
  }

  _performVerification(identity, method, nonce) {
    // In production, would verify cryptographic signatures, delegation chains, or audit logs
    return !!(identity && identity.id && nonce);
  }
}

class AuthorityCheckNode extends SyntaxisNode {
  constructor() {
    super('authority-check', 'Identity & Access');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.subjectId) {
      errors.push('subjectId is required');
    }
    if (!inputs.requiredAuthority) {
      errors.push('requiredAuthority is required');
    }
    if (!inputs.scope) {
      errors.push('scope is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { subjectId, requiredAuthority, scope } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const authorized = this._checkAuthority(subjectId, requiredAuthority, scope);
    return {
      outputs: {
        subjectId,
        authorized,
        authorityLevel: authorized ? requiredAuthority : 'NONE',
        scope,
        checkedAt: hlcToString(timestampHlc),
        checkedAtHlc: timestampHlc
      },
      nextState: authorized ? 'AUTHORIZED' : 'UNAUTHORIZED',
      errors: authorized ? [] : [`Subject ${subjectId} not authorized for ${requiredAuthority}`]
    };
  }

  getRequiredPanels() {
    return ['Identity Panel'];
  }

  _checkAuthority(subjectId, requiredAuthority, scope) {
    // In production, would check delegated authority in identity registry
    return !!(subjectId && requiredAuthority && scope);
  }
}

class AuthorityDelegateNode extends SyntaxisNode {
  constructor() {
    super('authority-delegate', 'Identity & Access');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.delegatorId) {
      errors.push('delegatorId is required');
    }
    if (!inputs.delegateeId) {
      errors.push('delegateeId is required');
    }
    if (!inputs.authority) {
      errors.push('authority is required');
    }
    if (inputs.delegatorId === inputs.delegateeId) {
      errors.push('Cannot delegate authority to self');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { delegatorId, delegateeId, authority, expiresAt } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const delegated = this._createDelegation(delegatorId, delegateeId, authority, expiresAt, timestampHlc);
    return {
      outputs: {
        delegationId: delegated.id,
        delegatorId,
        delegateeId,
        authority,
        expiresAt: expiresAt || null,
        createdAt: hlcToString(timestampHlc),
        createdAtHlc: timestampHlc
      },
      nextState: 'DELEGATED',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['Identity Panel', 'Governance Panel'];
  }

  _createDelegation(delegatorId, delegateeId, authority, expiresAt, timestampHlc) {
    return {
      id: deterministicId('delegation', {
        authority,
        delegateeId,
        delegatorId,
        expiresAt: expiresAt || null,
        timestampHlc
      }),
      delegatorId,
      delegateeId,
      authority,
      expiresAt
    };
  }
}

class ConsentRequestNode extends SyntaxisNode {
  constructor() {
    super('consent-request', 'Consent');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.requesterId) {
      errors.push('requesterId is required');
    }
    if (!inputs.consentType) {
      errors.push('consentType is required');
    }
    if (!inputs.recipientIds || !Array.isArray(inputs.recipientIds) || inputs.recipientIds.length === 0) {
      errors.push('recipientIds must be a non-empty array');
    }
    if (!inputs.consentData || typeof inputs.consentData !== 'object') {
      errors.push('consentData is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { requesterId, consentType, recipientIds, consentData } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const requestId = this._generateConsentRequest(
      requesterId,
      consentType,
      recipientIds,
      consentData,
      timestampHlc
    );
    return {
      outputs: {
        consentRequestId: requestId,
        requesterId,
        consentType,
        recipientCount: recipientIds.length,
        status: 'PENDING',
        createdAt: hlcToString(timestampHlc),
        createdAtHlc: timestampHlc
      },
      nextState: 'AWAITING_CONSENT',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['Consent Panel'];
  }

  _generateConsentRequest(requesterId, consentType, recipientIds, consentData, timestampHlc) {
    return deterministicId('consent_req', {
      consentData,
      consentType,
      recipientIds,
      requesterId,
      timestampHlc
    });
  }
}

class ConsentVerifyNode extends SyntaxisNode {
  constructor() {
    super('consent-verify', 'Consent');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.consentRequestId) {
      errors.push('consentRequestId is required');
    }
    if (!inputs.recipientResponses || typeof inputs.recipientResponses !== 'object') {
      errors.push('recipientResponses is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { consentRequestId, recipientResponses } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const requiredConsentBasisPoints = normalizeBasisPoints(
      context.inputs.requiredConsentBasisPoints,
      'requiredConsentBasisPoints',
      10000
    );
    const { allConsented, consentBasisPoints } = this._verifyConsent(
      recipientResponses,
      requiredConsentBasisPoints
    );
    return {
      outputs: {
        consentRequestId,
        allConsented,
        consentBasisPoints,
        totalResponses: Object.keys(recipientResponses).length,
        verifiedAt: hlcToString(timestampHlc),
        verifiedAtHlc: timestampHlc
      },
      nextState: allConsented ? 'CONSENT_VERIFIED' : 'CONSENT_INSUFFICIENT',
      errors: allConsented ? [] : [
        `Consent threshold not met (${consentBasisPoints} bps >= ${requiredConsentBasisPoints} bps required)`
      ]
    };
  }

  getRequiredPanels() {
    return ['Consent Panel'];
  }

  _verifyConsent(recipientResponses, requiredConsentBasisPoints = 10000) {
    const responses = Object.values(recipientResponses);
    const consents = responses.filter(r => r.consent === true).length;
    const consentBasisPoints = ratioBasisPoints(consents, responses.length);
    return {
      allConsented: consentBasisPoints >= requiredConsentBasisPoints,
      consentBasisPoints
    };
  }
}

class ConsentRevokeNode extends SyntaxisNode {
  constructor() {
    super('consent-revoke', 'Consent');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.consentRequestId) {
      errors.push('consentRequestId is required');
    }
    if (!inputs.revokerId) {
      errors.push('revokerId is required');
    }
    if (!inputs.revocationReason) {
      errors.push('revocationReason is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { consentRequestId, revokerId, revocationReason } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const revocationId = this._performRevocation(consentRequestId, revokerId, timestampHlc);
    return {
      outputs: {
        revocationId,
        consentRequestId,
        revokerId,
        revocationReason,
        revokedAt: hlcToString(timestampHlc),
        revokedAtHlc: timestampHlc
      },
      nextState: 'CONSENT_REVOKED',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['Consent Panel'];
  }

  _performRevocation(consentRequestId, revokerId, timestampHlc) {
    return deterministicId('revoke', {
      consentRequestId,
      revokerId,
      timestampHlc
    });
  }
}

class GovernanceProposeNode extends SyntaxisNode {
  constructor() {
    super('governance-propose', 'Governance');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.proposerId) {
      errors.push('proposerId is required');
    }
    if (!inputs.proposalType) {
      errors.push('proposalType is required');
    }
    if (!inputs.proposalContent || typeof inputs.proposalContent !== 'object') {
      errors.push('proposalContent is required');
    }
    if (!inputs.affectedPanels || !Array.isArray(inputs.affectedPanels)) {
      errors.push('affectedPanels must be an array');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { proposerId, proposalType, proposalContent, affectedPanels } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const proposalId = this._createProposal(proposerId, proposalType, proposalContent, timestampHlc);
    return {
      outputs: {
        proposalId,
        proposerId,
        proposalType,
        affectedPanelCount: affectedPanels.length,
        status: 'PROPOSED',
        createdAt: hlcToString(timestampHlc),
        createdAtHlc: timestampHlc
      },
      nextState: 'UNDER_REVIEW',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['Governance Panel'];
  }

  _createProposal(proposerId, proposalType, proposalContent, timestampHlc) {
    return deterministicId('proposal', {
      proposalContent,
      proposalType,
      proposerId,
      timestampHlc
    });
  }
}

class GovernanceVoteNode extends SyntaxisNode {
  constructor() {
    super('governance-vote', 'Governance');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.proposalId) {
      errors.push('proposalId is required');
    }
    if (!inputs.panelVotes || typeof inputs.panelVotes !== 'object') {
      errors.push('panelVotes is required');
    }
    if (!Object.keys(inputs.panelVotes).every(panel => ['FOR', 'AGAINST', 'ABSTAIN'].includes(inputs.panelVotes[panel]))) {
      errors.push('panelVotes must contain FOR, AGAINST, or ABSTAIN');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { proposalId, panelVotes } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const { passed, voteCount, resultDetails } = this._tallifyVotes(panelVotes);
    return {
      outputs: {
        proposalId,
        passed,
        voteCount,
        resultDetails,
        votedAt: hlcToString(timestampHlc),
        votedAtHlc: timestampHlc
      },
      nextState: passed ? 'PASSED' : 'FAILED',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['Governance Panel'];
  }

  _tallifyVotes(panelVotes) {
    const voteCount = {
      FOR: 0,
      AGAINST: 0,
      ABSTAIN: 0
    };
    Object.values(panelVotes).forEach(vote => {
      if (vote in voteCount) voteCount[vote]++;
    });
    const passed = voteCount.FOR > voteCount.AGAINST;
    return {
      passed,
      voteCount,
      resultDetails: {
        totalVoting: voteCount.FOR + voteCount.AGAINST,
        abstentions: voteCount.ABSTAIN,
        majority: passed ? 'FOR' : 'AGAINST'
      }
    };
  }
}

class GovernanceResolveNode extends SyntaxisNode {
  constructor() {
    super('governance-resolve', 'Governance');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.proposalId) {
      errors.push('proposalId is required');
    }
    if (!inputs.voteResult || !['PASSED', 'FAILED', 'DISPUTED'].includes(inputs.voteResult)) {
      errors.push('voteResult must be PASSED, FAILED, or DISPUTED');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { proposalId, voteResult, resolutionDetails } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const resolutionId = this._createResolution(proposalId, voteResult, timestampHlc);
    return {
      outputs: {
        resolutionId,
        proposalId,
        voteResult,
        resolutionStatus: voteResult === 'PASSED' ? 'APPROVED' : 'REJECTED',
        resolvedAt: hlcToString(timestampHlc),
        resolvedAtHlc: timestampHlc,
        details: resolutionDetails || {}
      },
      nextState: voteResult === 'PASSED' ? 'RESOLVED_APPROVED' : 'RESOLVED_REJECTED',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['Governance Panel'];
  }

  _createResolution(proposalId, voteResult, timestampHlc) {
    return deterministicId('resolution', {
      proposalId,
      timestampHlc,
      voteResult
    });
  }
}

class KernelAdjudicateNode extends SyntaxisNode {
  constructor() {
    super('kernel-adjudicate', 'Kernel');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.conflictId) {
      errors.push('conflictId is required');
    }
    if (!inputs.conflictType) {
      errors.push('conflictType is required');
    }
    if (!inputs.evidenceProofs || !Array.isArray(inputs.evidenceProofs)) {
      errors.push('evidenceProofs must be an array');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { conflictId, conflictType, evidenceProofs } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const adjudication = this._adjudicate(conflictId, conflictType, evidenceProofs, timestampHlc);
    return {
      outputs: {
        adjudicationId: adjudication.id,
        conflictId,
        verdict: adjudication.verdict,
        confidenceBasisPoints: adjudication.confidenceBasisPoints,
        reasoning: adjudication.reasoning,
        adjudicatedAt: hlcToString(timestampHlc),
        adjudicatedAtHlc: timestampHlc
      },
      nextState: adjudication.verdict === 'VALID' ? 'ADJUDICATED_VALID' : 'ADJUDICATED_INVALID',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['Kernel Panel'];
  }

  _adjudicate(conflictId, conflictType, evidenceProofs, timestampHlc) {
    const validProofs = evidenceProofs.filter(p => p && p.hash).length;
    const confidenceBasisPoints = ratioBasisPoints(validProofs, evidenceProofs.length);
    return {
      id: deterministicId('adjudication', {
        conflictId,
        conflictType,
        evidenceProofs,
        timestampHlc
      }),
      verdict: confidenceBasisPoints > 5000 ? 'VALID' : 'INVALID',
      confidenceBasisPoints,
      reasoning: `Evaluated ${evidenceProofs.length} proofs with ${validProofs} valid`
    };
  }
}

class InvariantCheckNode extends SyntaxisNode {
  constructor() {
    super('invariant-check', 'Kernel');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.invariantId) {
      errors.push('invariantId is required');
    }
    if (!inputs.invariantRule || typeof inputs.invariantRule !== 'object') {
      errors.push('invariantRule is required');
    }
    if (!inputs.stateSnapshot) {
      errors.push('stateSnapshot is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { invariantId, invariantRule, stateSnapshot } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const satisfied = this._checkInvariant(invariantRule, stateSnapshot);
    return {
      outputs: {
        invariantId,
        satisfied,
        checkedAt: hlcToString(timestampHlc),
        checkedAtHlc: timestampHlc,
        ruleType: invariantRule.type,
        stateCovered: Object.keys(stateSnapshot).length
      },
      nextState: satisfied ? 'INVARIANT_SATISFIED' : 'INVARIANT_VIOLATED',
      errors: satisfied ? [] : [`Invariant ${invariantId} violated`]
    };
  }

  getRequiredPanels() {
    return ['Kernel Panel'];
  }

  _checkInvariant(rule, snapshot) {
    // In production, would evaluate complex invariant rules against state
    return !!(rule && rule.type && snapshot && Object.keys(snapshot).length > 0);
  }
}

/**
 * PROOF & LEDGER NODES (3)
 */

class ProofGenerateNode extends SyntaxisNode {
  constructor() {
    super('proof-generate', 'Proof & Ledger');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.dataHash) {
      errors.push('dataHash is required');
    }
    if (!inputs.prover) {
      errors.push('prover is required');
    }
    if (!inputs.proofType) {
      errors.push('proofType is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { dataHash, prover, proofType, proofData } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const proof = this._generateProof(dataHash, prover, proofType, proofData, timestampHlc);
    return {
      outputs: {
        proofId: proof.id,
        proofHash: proof.hash,
        proofType,
        prover,
        generatedAt: hlcToString(timestampHlc),
        generatedAtHlc: timestampHlc,
        dataHash
      },
      nextState: 'PROOF_GENERATED',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['Kernel Panel'];
  }

  _generateProof(dataHash, prover, proofType, proofData, timestampHlc) {
    return {
      id: deterministicId('proof', {
        dataHash,
        proofData: proofData || {},
        proofType,
        prover,
        timestampHlc
      }),
      hash: `proof_hash_${hashCanonical({ dataHash, proofData: proofData || {}, proofType, prover }).slice(0, 32)}`,
      type: proofType,
      prover,
      data: proofData || {}
    };
  }
}

class ProofVerifyNode extends SyntaxisNode {
  constructor() {
    super('proof-verify', 'Proof & Ledger');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.proofId) {
      errors.push('proofId is required');
    }
    if (!inputs.proofHash) {
      errors.push('proofHash is required');
    }
    if (!inputs.verifier) {
      errors.push('verifier is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { proofId, proofHash, verifier } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const verified = this._verifyProof(proofId, proofHash);
    return {
      outputs: {
        proofId,
        verified,
        verifier,
        verifiedAt: hlcToString(timestampHlc),
        verifiedAtHlc: timestampHlc,
        integrity: verified ? 'INTACT' : 'CORRUPTED'
      },
      nextState: verified ? 'PROOF_VERIFIED' : 'PROOF_INVALID',
      errors: verified ? [] : [`Proof ${proofId} verification failed`]
    };
  }

  getRequiredPanels() {
    return ['Kernel Panel'];
  }

  _verifyProof(proofId, proofHash) {
    // In production, would verify cryptographic proof integrity
    return !!(proofId && proofHash && proofHash.length > 0);
  }
}

class DagAppendNode extends SyntaxisNode {
  constructor() {
    super('dag-append', 'Proof & Ledger');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.dagId) {
      errors.push('dagId is required');
    }
    if (!inputs.nodeData || typeof inputs.nodeData !== 'object') {
      errors.push('nodeData is required');
    }
    if (!Array.isArray(inputs.parentHashes) || inputs.parentHashes.length === 0) {
      errors.push('parentHashes must be a non-empty array');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { dagId, nodeData, parentHashes } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const dagNode = this._appendToDAG(dagId, nodeData, parentHashes, timestampHlc);
    return {
      outputs: {
        dagNodeId: dagNode.id,
        dagId,
        nodeHash: dagNode.hash,
        parentCount: parentHashes.length,
        appendedAt: hlcToString(timestampHlc),
        appendedAtHlc: timestampHlc
      },
      nextState: 'APPENDED_TO_DAG',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['Kernel Panel'];
  }

  _appendToDAG(dagId, nodeData, parentHashes, timestampHlc) {
    const nodeId = deterministicId('dag_node', {
      dagId,
      nodeData,
      parentHashes,
      timestampHlc
    });
    const nodeHash = `${dagId}_${hashCanonical({ nodeData, parentHashes }).slice(0, 32)}`;
    return {
      id: nodeId,
      hash: nodeHash,
      data: nodeData,
      parents: parentHashes
    };
  }
}

/**
 * ESCALATION & ENFORCEMENT NODES (2)
 */

class EscalationTriggerNode extends SyntaxisNode {
  constructor() {
    super('escalation-trigger', 'Escalation & Enforcement');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.escalationReason) {
      errors.push('escalationReason is required');
    }
    if (!inputs.escalationLevel || !['WARNING', 'CRITICAL', 'EMERGENCY'].includes(inputs.escalationLevel)) {
      errors.push('escalationLevel must be WARNING, CRITICAL, or EMERGENCY');
    }
    if (!inputs.affectedComponent) {
      errors.push('affectedComponent is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { escalationReason, escalationLevel, affectedComponent, additionalData } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const escalationId = this._createEscalation(escalationReason, escalationLevel, timestampHlc);
    return {
      outputs: {
        escalationId,
        escalationLevel,
        affectedComponent,
        reason: escalationReason,
        createdAt: hlcToString(timestampHlc),
        createdAtHlc: timestampHlc,
        requiresHumanReview: escalationLevel !== 'WARNING'
      },
      nextState: 'ESCALATED',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['Escalation Panel'];
  }

  _createEscalation(reason, level, timestampHlc) {
    return deterministicId(`escalation_${level.toLowerCase()}`, {
      level,
      reason,
      timestampHlc
    });
  }
}

class HumanOverrideNode extends SyntaxisNode {
  constructor() {
    super('human-override', 'Escalation & Enforcement');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.escalationId) {
      errors.push('escalationId is required');
    }
    if (!inputs.overrideDecision) {
      errors.push('overrideDecision is required');
    }
    if (!inputs.overridingAuthority) {
      errors.push('overridingAuthority is required');
    }
    if (!inputs.justification) {
      errors.push('justification is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { escalationId, overrideDecision, overridingAuthority, justification } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const overrideId = this._recordOverride(
      escalationId,
      overrideDecision,
      overridingAuthority,
      timestampHlc
    );
    return {
      outputs: {
        overrideId,
        escalationId,
        decision: overrideDecision,
        authority: overridingAuthority,
        justification,
        overriddenAt: hlcToString(timestampHlc),
        overriddenAtHlc: timestampHlc
      },
      nextState: 'HUMAN_OVERRIDDEN',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['Executive Panel'];
  }

  _recordOverride(escalationId, decision, authority, timestampHlc) {
    return deterministicId('override', {
      authority,
      decision,
      escalationId,
      timestampHlc
    });
  }
}

/**
 * MULTI-TENANCY & AI NODES (2)
 */

class TenantIsolateNode extends SyntaxisNode {
  constructor() {
    super('tenant-isolate', 'Multi-Tenancy & AI');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.tenantId) {
      errors.push('tenantId is required');
    }
    if (!inputs.isolationLevel || !['LOGICAL', 'PHYSICAL', 'CRYPTOGRAPHIC'].includes(inputs.isolationLevel)) {
      errors.push('isolationLevel must be LOGICAL, PHYSICAL, or CRYPTOGRAPHIC');
    }
    if (!inputs.resourceScope || typeof inputs.resourceScope !== 'object') {
      errors.push('resourceScope is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { tenantId, isolationLevel, resourceScope } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const isolation = this._createIsolation(tenantId, isolationLevel, resourceScope, timestampHlc);
    return {
      outputs: {
        isolationId: isolation.id,
        tenantId,
        isolationLevel,
        resourceCount: Object.keys(resourceScope).length,
        createdAt: hlcToString(timestampHlc),
        createdAtHlc: timestampHlc
      },
      nextState: 'TENANT_ISOLATED',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['Infrastructure Panel'];
  }

  _createIsolation(tenantId, level, scope, timestampHlc) {
    return {
      id: deterministicId('isolation', {
        level,
        scope,
        tenantId,
        timestampHlc
      }),
      tenantId,
      level,
      scope
    };
  }
}

class MCPEnforceNode extends SyntaxisNode {
  constructor() {
    super('mcp-enforce', 'Multi-Tenancy & AI');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.mcpInstanceId) {
      errors.push('mcpInstanceId is required');
    }
    if (!inputs.enforcementPolicy || typeof inputs.enforcementPolicy !== 'object') {
      errors.push('enforcementPolicy is required');
    }
    if (!inputs.constraints || !Array.isArray(inputs.constraints)) {
      errors.push('constraints must be an array');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { mcpInstanceId, enforcementPolicy, constraints } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const enforcement = this._enforcePolicy(mcpInstanceId, enforcementPolicy, constraints, timestampHlc);
    return {
      outputs: {
        enforcementId: enforcement.id,
        mcpInstanceId,
        policyApplied: true,
        constraintCount: constraints.length,
        enforcedAt: hlcToString(timestampHlc),
        enforcedAtHlc: timestampHlc
      },
      nextState: 'MCP_ENFORCED',
      errors: []
    };
  }

  getRequiredPanels() {
    return ['AI Panel'];
  }

  _enforcePolicy(instanceId, policy, constraints, timestampHlc) {
    return {
      id: deterministicId('enforce', {
        constraints,
        instanceId,
        policy,
        timestampHlc
      }),
      instanceId,
      policy,
      constraints
    };
  }
}

/**
 * FLOW CONTROL NODES (5)
 */

class CombinatorSequenceNode extends SyntaxisNode {
  constructor() {
    super('combinator-sequence', 'Flow Control');
  }

  validate(inputs) {
    const errors = [];
    if (!Array.isArray(inputs.steps) || inputs.steps.length === 0) {
      errors.push('steps must be a non-empty array');
    }
    if (!inputs.executionMode || !['STRICT', 'FAULT_TOLERANT'].includes(inputs.executionMode)) {
      errors.push('executionMode must be STRICT or FAULT_TOLERANT');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { steps, executionMode } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    return {
      outputs: {
        stepCount: steps.length,
        executionMode,
        sequenceId: deterministicId('seq', { executionMode, steps, timestampHlc }),
        startedAt: hlcToString(timestampHlc),
        startedAtHlc: timestampHlc
      },
      nextState: 'SEQUENCE_STARTED',
      errors: []
    };
  }

  getRequiredPanels() {
    return [];
  }
}

class CombinatorParallelNode extends SyntaxisNode {
  constructor() {
    super('combinator-parallel', 'Flow Control');
  }

  validate(inputs) {
    const errors = [];
    if (!Array.isArray(inputs.branches) || inputs.branches.length < 2) {
      errors.push('branches must be an array with at least 2 items');
    }
    if (!inputs.joinStrategy || !['ALL', 'ANY', 'FIRST'].includes(inputs.joinStrategy)) {
      errors.push('joinStrategy must be ALL, ANY, or FIRST');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { branches, joinStrategy } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    return {
      outputs: {
        branchCount: branches.length,
        joinStrategy,
        parallelId: deterministicId('par', { branches, joinStrategy, timestampHlc }),
        startedAt: hlcToString(timestampHlc),
        startedAtHlc: timestampHlc
      },
      nextState: 'PARALLEL_STARTED',
      errors: []
    };
  }

  getRequiredPanels() {
    return [];
  }
}

class CombinatorChoiceNode extends SyntaxisNode {
  constructor() {
    super('combinator-choice', 'Flow Control');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.condition || typeof inputs.condition !== 'object') {
      errors.push('condition is required');
    }
    if (!inputs.trueBranch) {
      errors.push('trueBranch is required');
    }
    if (!inputs.falseBranch) {
      errors.push('falseBranch is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { condition, trueBranch, falseBranch } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const conditionMet = this._evaluateCondition(condition);
    return {
      outputs: {
        conditionMet,
        selectedBranch: conditionMet ? 'TRUE' : 'FALSE',
        choiceId: deterministicId('choice', { condition, falseBranch, timestampHlc, trueBranch }),
        evaluatedAt: hlcToString(timestampHlc),
        evaluatedAtHlc: timestampHlc
      },
      nextState: conditionMet ? 'BRANCH_TRUE' : 'BRANCH_FALSE',
      errors: []
    };
  }

  getRequiredPanels() {
    return [];
  }

  _evaluateCondition(condition) {
    // In production, would evaluate complex conditions
    return !!(condition && Object.keys(condition).length > 0);
  }
}

class CombinatorGuardNode extends SyntaxisNode {
  constructor() {
    super('combinator-guard', 'Flow Control');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.guardCondition || typeof inputs.guardCondition !== 'object') {
      errors.push('guardCondition is required');
    }
    if (!inputs.guardedAction) {
      errors.push('guardedAction is required');
    }
    if (!inputs.fallbackAction) {
      errors.push('fallbackAction is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { guardCondition, guardedAction, fallbackAction } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const guardPassed = this._checkGuard(guardCondition);
    return {
      outputs: {
        guardPassed,
        executedAction: guardPassed ? 'GUARDED' : 'FALLBACK',
        guardId: deterministicId('guard', {
          fallbackAction,
          guardCondition,
          guardedAction,
          timestampHlc
        }),
        checkedAt: hlcToString(timestampHlc),
        checkedAtHlc: timestampHlc
      },
      nextState: guardPassed ? 'GUARD_PASSED' : 'FALLBACK_EXECUTED',
      errors: []
    };
  }

  getRequiredPanels() {
    return [];
  }

  _checkGuard(condition) {
    return !!(condition && Object.keys(condition).length > 0);
  }
}

class CombinatorTransformNode extends SyntaxisNode {
  constructor() {
    super('combinator-transform', 'Flow Control');
  }

  validate(inputs) {
    const errors = [];
    if (!inputs.sourceData) {
      errors.push('sourceData is required');
    }
    if (!inputs.transformation || typeof inputs.transformation !== 'object') {
      errors.push('transformation is required');
    }
    if (!inputs.targetSchema) {
      errors.push('targetSchema is required');
    }
    return { valid: errors.length === 0, errors };
  }

  execute(context) {
    const { sourceData, transformation, targetSchema } = context.inputs;
    const timestampHlc = timestampFromContext(context);
    const transformed = this._transform(sourceData, transformation);
    return {
      outputs: {
        transformedData: transformed,
        targetSchema,
        transformId: deterministicId('transform', {
          sourceData,
          targetSchema,
          timestampHlc,
          transformation
        }),
        transformedAt: hlcToString(timestampHlc),
        transformedAtHlc: timestampHlc
      },
      nextState: 'TRANSFORMED',
      errors: []
    };
  }

  getRequiredPanels() {
    return [];
  }

  _transform(data, transformation) {
    return { ...data, ...transformation };
  }
}

/**
 * Node Registry Export
 */
const NODE_IMPLEMENTATIONS = {
  // Core Governance
  'identity-verify': new IdentityVerifyNode(),
  'authority-check': new AuthorityCheckNode(),
  'authority-delegate': new AuthorityDelegateNode(),
  'consent-request': new ConsentRequestNode(),
  'consent-verify': new ConsentVerifyNode(),
  'consent-revoke': new ConsentRevokeNode(),
  'governance-propose': new GovernanceProposeNode(),
  'governance-vote': new GovernanceVoteNode(),
  'governance-resolve': new GovernanceResolveNode(),
  'kernel-adjudicate': new KernelAdjudicateNode(),
  'invariant-check': new InvariantCheckNode(),
  // Proof & Ledger
  'proof-generate': new ProofGenerateNode(),
  'proof-verify': new ProofVerifyNode(),
  'dag-append': new DagAppendNode(),
  // Escalation & Enforcement
  'escalation-trigger': new EscalationTriggerNode(),
  'human-override': new HumanOverrideNode(),
  // Multi-Tenancy & AI
  'tenant-isolate': new TenantIsolateNode(),
  'mcp-enforce': new MCPEnforceNode(),
  // Flow Control
  'combinator-sequence': new CombinatorSequenceNode(),
  'combinator-parallel': new CombinatorParallelNode(),
  'combinator-choice': new CombinatorChoiceNode(),
  'combinator-guard': new CombinatorGuardNode(),
  'combinator-transform': new CombinatorTransformNode()
};

module.exports = {
  SyntaxisNode,
  NODE_IMPLEMENTATIONS,
  // Export individual nodes for direct use
  IdentityVerifyNode,
  AuthorityCheckNode,
  AuthorityDelegateNode,
  ConsentRequestNode,
  ConsentVerifyNode,
  ConsentRevokeNode,
  GovernanceProposeNode,
  GovernanceVoteNode,
  GovernanceResolveNode,
  KernelAdjudicateNode,
  InvariantCheckNode,
  ProofGenerateNode,
  ProofVerifyNode,
  DagAppendNode,
  EscalationTriggerNode,
  HumanOverrideNode,
  TenantIsolateNode,
  MCPEnforceNode,
  CombinatorSequenceNode,
  CombinatorParallelNode,
  CombinatorChoiceNode,
  CombinatorGuardNode,
  CombinatorTransformNode
};
