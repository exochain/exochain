'use strict';

/**
 * GSD (Get Shit Done) Control Panel — Express Router
 *
 * Backend routes for CommandBase.ai governance operations.
 * Wraps exochain service calls with governance receipts and
 * standardized JSON responses.
 *
 * Every route:
 *   1. Extracts parameters from req.body
 *   2. Calls the exochain service function(s)
 *   3. Creates a governance receipt via governance.createReceipt()
 *   4. Returns { success, data, receipt: { hash, depth } }
 *   5. Catches errors and returns 500
 */

const express = require('express');
const router = express.Router();

const exochain = require('../services/exochain');
const governanceService = require('../services/governance');

// ── Helper: initialize governance service with request-scoped db ────────────
// The governance module is a factory: module.exports = function(db, broadcast, helpers)
// We expect app-level middleware to attach req.db, req.broadcast, req.helpers.
function getGovernance(req) {
  return governanceService(req.db, req.broadcast || (() => {}), req.helpers || { localNow: () => new Date().toISOString() });
}

// ── Helper: create a receipt and extract { hash, depth } ────────────────────
function createReceipt(governance, db, actionType, entityType, entityId, actor, description, payload, projectId) {
  const receipt = governance.createReceipt(db, actionType, entityType, entityId, actor, description, payload, projectId);
  return { hash: receipt.receipt_hash, depth: receipt.chain_depth };
}

// ── Helper: standard success response ───────────────────────────────────────
function ok(res, data, receipt) {
  return res.json({ success: true, data, receipt });
}

// ── Helper: standard error response ─────────────────────────────────────────
function fail(res, err) {
  return res.status(500).json({ success: false, error: err.message || String(err) });
}

// =============================================================================
// AGENT MANAGEMENT
// =============================================================================

/**
 * POST /api/gsd/agent/verify
 * Verify an agent's authority chain and clearance level.
 * Body: { chain, nowMs, keys, actorDid, action, policy }
 */
router.post('/agent/verify', (req, res) => {
  try {
    const { chain, nowMs, keys, actorDid, action, policy } = req.body;
    const chainResult = exochain.verifyAuthorityChain(chain, nowMs, keys);
    const clearanceResult = exochain.checkClearance(actorDid, action, policy);
    const data = { authority: chainResult, clearance: clearanceResult };
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'agent_verify', 'agent', actorDid, actorDid,
      `Verified authority chain and clearance for ${actorDid}`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/agent/delegate
 * Build an authority chain from delegation links.
 * Body: { links }
 */
router.post('/agent/delegate', (req, res) => {
  try {
    const { links } = req.body;
    const data = exochain.buildAuthorityChain(links);
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'agent_delegate', 'authority_chain', data.id || 'new',
      req.body.actorDid || 'system', `Built authority chain from ${(links || []).length} delegation links`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/agent/revoke
 * Terminate a bailment (revoke agent access).
 * Body: { bailment, actorDid }
 */
router.post('/agent/revoke', (req, res) => {
  try {
    const { bailment, actorDid } = req.body;
    const data = exochain.terminateBailment(bailment, actorDid);
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'agent_revoke', 'bailment', bailment.id || 'unknown',
      actorDid, `Terminated bailment for actor ${actorDid}`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/agent/quarantine
 * Escalate PACE state to quarantine an agent.
 * Body: { state }
 */
router.post('/agent/quarantine', (req, res) => {
  try {
    const { state } = req.body;
    const data = exochain.paceEscalate(state);
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'agent_quarantine', 'pace_state', state.id || 'current',
      req.body.actorDid || 'system', 'PACE escalation: agent quarantined', data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/agent/reinstate
 * Resolve PACE and de-escalate to reinstate an agent.
 * Body: { config, state }
 */
router.post('/agent/reinstate', (req, res) => {
  try {
    const { config, state } = req.body;
    const resolved = exochain.paceResolve(config, state);
    const deescalated = exochain.paceDeescalate(state);
    const data = { resolved, deescalated };
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'agent_reinstate', 'pace_state', state.id || 'current',
      req.body.actorDid || 'system', 'PACE de-escalation: agent reinstated', data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

// =============================================================================
// DECISION LIFECYCLE
// =============================================================================

/**
 * POST /api/gsd/decision/create
 * Create a new governance decision.
 * Body: { title, decisionClass, constitutionHashHex }
 */
router.post('/decision/create', (req, res) => {
  try {
    const { title, decisionClass, constitutionHashHex } = req.body;
    const data = exochain.createDecision(title, decisionClass, constitutionHashHex);
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'decision_create', 'decision', data.id || title,
      req.body.actorDid || 'system', `Created ${decisionClass} decision: ${title}`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/decision/vote
 * Cast a vote in a deliberation session.
 * Body: { deliberation, vote }
 */
router.post('/decision/vote', (req, res) => {
  try {
    const { deliberation, vote } = req.body;
    const data = exochain.castVote(deliberation, vote);
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'decision_vote', 'deliberation', deliberation.id || 'unknown',
      vote.voter || req.body.actorDid || 'system', `Vote cast: ${vote.choice || 'unknown'}`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/decision/quorum
 * Check quorum status and verify quorum precondition.
 * Body: { registry, decision, decisionClass, eligibleVoters }
 */
router.post('/decision/quorum', (req, res) => {
  try {
    const { registry, decision, decisionClass, eligibleVoters } = req.body;
    const quorumStatus = exochain.checkQuorum(registry, decision);
    const precondition = exochain.verifyQuorumPrecondition(registry, decisionClass, eligibleVoters);
    const data = { quorum: quorumStatus, preconditionMet: precondition };
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'decision_quorum', 'decision', decision.id || 'unknown',
      req.body.actorDid || 'system', `Quorum check: ${quorumStatus.status || 'checked'}`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/decision/human-gate
 * Enforce human approval gate on a decision.
 * Body: { policy, decision }
 */
router.post('/decision/human-gate', (req, res) => {
  try {
    const { policy, decision } = req.body;
    const data = exochain.enforceHumanGate(policy, decision);
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'decision_human_gate', 'decision', decision.id || 'unknown',
      req.body.actorDid || 'system', 'Human gate enforcement check', data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/decision/challenge
 * File a challenge against a decision.
 * Body: { challengerDid, decisionId, ground, evidenceHashHex }
 */
router.post('/decision/challenge', (req, res) => {
  try {
    const { challengerDid, decisionId, ground, evidenceHashHex } = req.body;
    const data = exochain.fileChallenge(challengerDid, decisionId, ground, evidenceHashHex);
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'decision_challenge', 'challenge', data.id || decisionId,
      challengerDid, `Challenge filed against decision ${decisionId}`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

// =============================================================================
// CONSTITUTIONAL ENFORCEMENT
// =============================================================================

/**
 * POST /api/gsd/constitutional/enforce-tnc
 * Enforce all 10 TNCs and collect violations.
 * Body: { decision, flags }
 */
router.post('/constitutional/enforce-tnc', (req, res) => {
  try {
    const { decision, flags } = req.body;
    const enforcement = exochain.enforceAllTnc(decision, flags);
    const violations = exochain.collectTncViolations(decision, flags);
    const data = { enforcement, violations: violations.violations };
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'constitutional_enforce_tnc', 'decision', decision.id || 'unknown',
      req.body.actorDid || 'system',
      `TNC enforcement: ${violations.violations.length} violation(s)`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/constitutional/verify-chain
 * Verify chain of custody for evidence.
 * Body: { evidence }
 */
router.post('/constitutional/verify-chain', (req, res) => {
  try {
    const { evidence } = req.body;
    const data = exochain.verifyChainOfCustody(evidence);
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'chain_verify', 'evidence', evidence.id || 'unknown',
      req.body.actorDid || 'system',
      `Chain of custody verification: ${data.valid ? 'valid' : 'invalid'}`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/constitutional/audit
 * Verify integrity of a hash-chained audit log.
 * Body: { entries }
 */
router.post('/constitutional/audit', (req, res) => {
  try {
    const { entries } = req.body;
    const data = exochain.auditVerify(entries);
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'audit_verify', 'audit_log', 'chain',
      req.body.actorDid || 'system',
      `Audit verification: ${data.intact ? 'intact' : 'CORRUPTED'}`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/constitutional/emergency
 * Create and optionally ratify an emergency action.
 * Body: { actionType, actorDid, justification, monetaryCapCents, evidenceHashHex, policy, timestampMs, ratifyDecisionId }
 */
router.post('/constitutional/emergency', (req, res) => {
  try {
    const { actionType, actorDid, justification, monetaryCapCents, evidenceHashHex, policy, timestampMs, ratifyDecisionId } = req.body;
    const action = exochain.createEmergencyAction(
      actionType, actorDid, justification,
      monetaryCapCents || 0, evidenceHashHex, policy, timestampMs || Date.now()
    );
    let data = { action };
    if (ratifyDecisionId) {
      const ratified = exochain.ratifyEmergency(action, ratifyDecisionId, timestampMs || Date.now());
      data.ratified = ratified;
    }
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'constitutional_emergency', 'emergency_action', action.id || 'new',
      actorDid, `Emergency action created: ${justification}`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

// =============================================================================
// IDENTITY & CRYPTOGRAPHY
// =============================================================================

/**
 * POST /api/gsd/identity/generate-keypair
 * Generate an Ed25519 keypair (public key only crosses the boundary).
 * Body: { actorDid? }
 */
router.post('/identity/generate-keypair', (req, res) => {
  try {
    const data = exochain.generateKeypair();
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'identity_generate_keypair', 'keypair', data.public_key || 'new',
      req.body.actorDid || 'system', 'Generated Ed25519 keypair', { public_key: data.public_key }, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/identity/sign
 * Sign a message with a secret key.
 * Body: { message, secretHex }
 */
router.post('/identity/sign', (req, res) => {
  try {
    const { message, secretHex } = req.body;
    const data = { signature: exochain.sign(message, secretHex) };
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'identity_sign', 'signature', 'new',
      req.body.actorDid || 'system', 'Message signed with Ed25519', { signed: true }, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/identity/verify
 * Verify an Ed25519 signature.
 * Body: { message, signature, publicHex }
 */
router.post('/identity/verify', (req, res) => {
  try {
    const { message, signature, publicHex } = req.body;
    const valid = exochain.verify(message, signature, publicHex);
    const data = { valid };
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'identity_verify', 'signature', publicHex || 'unknown',
      req.body.actorDid || 'system', `Signature verification: ${valid ? 'valid' : 'invalid'}`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/identity/shamir-split
 * Split a secret using Shamir's Secret Sharing.
 * Body: { secret, threshold, shares }
 */
router.post('/identity/shamir-split', (req, res) => {
  try {
    const { secret, threshold, shares } = req.body;
    const data = { shares: exochain.shamirSplit(secret, threshold, shares) };
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'identity_shamir_split', 'shamir', 'new',
      req.body.actorDid || 'system', `Shamir split: ${threshold}-of-${shares}`, { threshold, totalShares: shares }, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * POST /api/gsd/identity/shamir-reconstruct
 * Reconstruct a secret from Shamir shares.
 * Body: { shares, threshold, totalShares }
 */
router.post('/identity/shamir-reconstruct', (req, res) => {
  try {
    const { shares, threshold, totalShares } = req.body;
    const data = exochain.shamirReconstruct(shares, threshold, totalShares);
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'identity_shamir_reconstruct', 'shamir', 'reconstruct',
      req.body.actorDid || 'system', `Shamir reconstruction: ${threshold}-of-${totalShares}`, { threshold, totalShares }, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

// =============================================================================
// HOLON MANAGEMENT
// =============================================================================

/**
 * POST /api/gsd/holon/spawn
 * Spawn a new holon (autonomous governance agent).
 * Body: { did, program }
 */
router.post('/holon/spawn', (req, res) => {
  try {
    const { did, program } = req.body;
    const data = exochain.spawnHolon(did, program);
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'holon_spawn', 'holon', did,
      req.body.actorDid || did, `Spawned holon ${did}`, data, req.body.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

/**
 * GET /api/gsd/holon/mcp-rules
 * Retrieve MCP governance rules.
 */
router.get('/holon/mcp-rules', (req, res) => {
  try {
    const data = exochain.mcpRules();
    const gov = getGovernance(req);
    const receipt = createReceipt(gov, req.db, 'holon_mcp_rules', 'mcp', 'rules',
      req.query.actorDid || 'system', 'Retrieved MCP governance rules', data, req.query.projectId);
    return ok(res, data, receipt);
  } catch (err) {
    return fail(res, err);
  }
});

module.exports = router;
