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
  return kernel.wasm_collect_tnc_violations(s(decision), s(flags));
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
