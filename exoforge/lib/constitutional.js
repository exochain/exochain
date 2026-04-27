/**
 * constitutional.js — Constitutional enforcement layer for ExoForge.
 *
 * Loads the ExoChain WASM governance kernel and exposes high-level functions
 * for TNC enforcement, invariant verification, audit-chain integrity, and
 * chain-of-custody validation.
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);

let wasm = null;

export const VALIDATION_TIMESTAMP_ISO = '2023-11-14T22:13:20.000Z';
const VALIDATION_TIMESTAMP_MS = 1_700_000_000_000;
const VALIDATION_TIMESTAMP_MS_BIGINT = 1_700_000_000_000n;
const VALIDATION_DECISION_ID = '00000000-0000-0000-0000-0000000005f0';
const VALIDATION_CONSTITUTION_HASH = '1'.repeat(64);

function repeatedByte(byte) {
  return Array(32).fill(byte);
}

function validationTimestamp() {
  return { physical_ms: VALIDATION_TIMESTAMP_MS, logical: 0 };
}

/**
 * Load the ExoChain WASM governance kernel.
 * Idempotent — subsequent calls return the cached module.
 * @returns {object} The raw WASM module exports.
 */
export function loadKernel() {
  if (wasm) return wasm;
  try {
    wasm = require('@exochain/exochain-wasm');
  } catch (err) {
    // Fall back to direct path resolution for development environments
    try {
      wasm = require('../../packages/exochain-wasm/wasm');
    } catch (err2) {
      throw new Error(
        `Failed to load ExoChain WASM kernel: ${err.message}. ` +
        `Fallback also failed: ${err2.message}`
      );
    }
  }
  return wasm;
}

/**
 * Serialize a value to JSON for WASM consumption.
 * Ensures string enum values are properly quoted.
 */
function s(v) {
  return JSON.stringify(v);
}

/**
 * Enforce all 10 Terms, Notices & Conditions against a decision + flags context.
 *
 * TNCs enforced:
 *   TNC-01: Authority chain cryptographically verified
 *   TNC-02: Human gate satisfied
 *   TNC-03: Consent verified
 *   TNC-04: Identity verified
 *   TNC-05: Delegation expiry enforced
 *   TNC-06: Constitutional binding valid
 *   TNC-07: Quorum verified
 *   TNC-08: Terminal decisions immutable
 *   TNC-09: AI delegation ceiling enforced
 *   TNC-10: Evidence bundle complete
 *
 * @param {object} state - Object containing { decision, flags } where:
 *   decision: a DecisionObject (as created by wasm_create_decision)
 *   flags: object with boolean/string fields consumed by each TNC check
 * @returns {object} { ok: true } on success, or { ok: false, violation, tnc } on failure
 */
export function enforceAllTnc(state) {
  const kernel = loadKernel();
  const { decision, flags } = state;
  try {
    const result = kernel.wasm_enforce_all_tnc(s(decision), s(flags));
    if (result && result.ok === false) {
      return { ok: false, violation: result.error || 'TNC enforcement failed', result };
    }
    return { ok: true, result };
  } catch (err) {
    return { ok: false, violation: err.message || String(err) };
  }
}

/**
 * Collect all TNC violations without short-circuiting.
 *
 * Unlike enforceAllTnc which stops at the first failure, this returns
 * every violation so callers can present a complete compliance report.
 *
 * @param {object} state - { decision, flags }
 * @returns {object} { violations: [...] } — empty array means full compliance
 */
export function collectTncViolations(state) {
  const kernel = loadKernel();
  const { decision, flags } = state;
  try {
    return kernel.wasm_collect_tnc_violations(s(decision), s(flags));
  } catch (err) {
    return { violations: [err.message || String(err)] };
  }
}

/**
 * Enforce constitutional invariants against a request context.
 *
 * The request object should match WasmInvariantRequest:
 *   { actor_did, action, resource, context, ... }
 *
 * @param {object} state - Invariant request context
 * @returns {object} { passed: bool, violations: [...] }
 */
export function verifyInvariants(state) {
  const kernel = loadKernel();
  try {
    const result = kernel.wasm_enforce_invariants(s(state));
    return { ok: true, passed: result.passed, violations: result.violations || [] };
  } catch (err) {
    return { ok: false, passed: false, violations: [err.message || String(err)] };
  }
}

/**
 * Verify the integrity of a hash-chained audit log.
 *
 * Each entry in the chain must reference the hash of its predecessor.
 * A broken link indicates tampering or data corruption.
 *
 * @param {Array} entries - Array of audit log entries (as appended by wasm_audit_append)
 * @returns {object} { valid: bool, broken_at?: number, details?: string }
 */
export function auditVerify(entries) {
  const kernel = loadKernel();
  try {
    const result = kernel.wasm_audit_verify(s(entries));
    return { ok: true, valid: true, result };
  } catch (err) {
    return { ok: false, valid: false, error: err.message || String(err) };
  }
}

/**
 * Verify chain of custody for evidence items.
 *
 * Validates that each custody transfer in the evidence's history is
 * cryptographically signed and unbroken.
 *
 * @param {Array} receipts - Array of evidence objects with custody chains
 * @returns {object} { verified: bool, results: [...] }
 */
export function verifyChainOfCustody(receipts) {
  const kernel = loadKernel();
  const results = [];
  let allValid = true;

  for (const receipt of receipts) {
    try {
      const result = kernel.wasm_verify_chain_of_custody(s(receipt));
      results.push({ id: receipt.id || receipt.evidence_id, valid: true, result });
    } catch (err) {
      allValid = false;
      results.push({
        id: receipt.id || receipt.evidence_id,
        valid: false,
        error: err.message || String(err)
      });
    }
  }

  return { verified: allValid, results };
}

/**
 * Create an audit log entry (append to hash chain).
 *
 * @param {string} actorDid - DID of the actor performing the action
 * @param {string} action - Action identifier
 * @param {string} result - Action result description
 * @param {string} evidenceHashHex - Hex-encoded evidence hash
 * @returns {object} New audit entry with hash chain link
 */
export function auditAppend(actorDid, action, result, evidenceHashHex) {
  const kernel = loadKernel();
  return kernel.wasm_audit_append(actorDid, action, result, evidenceHashHex);
}

/**
 * Get valid BCTS workflow stage names in lifecycle order.
 * @returns {Array} Stage names
 */
export function workflowStages() {
  const kernel = loadKernel();
  return kernel.wasm_workflow_stages();
}

/**
 * Hash structured JSON data using the kernel's hashing algorithm.
 * @param {object} data - Data to hash
 * @returns {string} Hex-encoded hash
 */
export function hashStructured(data) {
  const kernel = loadKernel();
  return kernel.wasm_hash_structured(s(data));
}

/**
 * Build a deterministic DecisionObject fixture that satisfies the current
 * WASM TNC enforcement schema.
 */
export function buildValidationDecision(title = 'ExoForge Validation Check') {
  const kernel = loadKernel();
  const decision = kernel.wasm_create_decision(
    VALIDATION_DECISION_ID,
    title,
    '"Routine"',
    VALIDATION_CONSTITUTION_HASH,
    VALIDATION_TIMESTAMP_MS_BIGINT,
    0
  );
  const ts = validationTimestamp();
  decision.authority_chain = [{
    actor_did: 'did:exo:validator',
    actor_kind: 'Human',
    delegation_hash: repeatedByte(2),
    timestamp: ts
  }];
  decision.evidence_bundle = [{
    hash: repeatedByte(3),
    description: 'ExoForge validation evidence',
    attached_at: ts
  }];
  return decision;
}

/**
 * Build TNC precondition flags matching `decision_forum_bindings::TncFlags`.
 */
export function buildValidationTncFlags() {
  return {
    constitutional_hash_valid: true,
    consent_verified: true,
    identity_verified: true,
    evidence_complete: true,
    quorum_met: true,
    human_gate_satisfied: true,
    authority_chain_verified: true,
    ai_ceilings_externally_verified: true
  };
}

/**
 * Build a deterministic invariant request matching `WasmInvariantRequest`.
 */
export function buildValidationInvariantRequest() {
  return {
    actor: 'did:exo:alice',
    actor_roles: [],
    bailment_state: {
      Active: {
        bailor: 'did:exo:bailor',
        bailee: 'did:exo:alice',
        scope: 'data'
      }
    },
    consent_records: [{
      subject: 'did:exo:subject',
      granted_to: 'did:exo:alice',
      scope: 'data',
      active: true
    }],
    authority_chain: {
      links: [{
        grantor: 'did:exo:bailor',
        grantee: 'did:exo:alice',
        permissions: { permissions: ['validate'] },
        signature: [1, 2, 3]
      }]
    },
    provenance: {
      actor: 'did:exo:alice',
      timestamp: VALIDATION_TIMESTAMP_ISO,
      action_hash: repeatedByte(4),
      signature: [1, 2, 3],
      voice_kind: 'Human',
      independence: 'Independent',
      review_order: 'FirstOrder'
    }
  };
}
