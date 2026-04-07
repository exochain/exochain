'use strict';

/**
 * Shared Auth Middleware — ExoChain CommandBase
 *
 * JWT-style session tokens using Ed25519 (via WASM) with HMAC-SHA256 fallback.
 *
 * Token format:  base64url(header) . base64url(payload) . base64url(signature)
 *
 * Payload fields:
 *   - did            : Decentralized Identifier of the subject
 *   - scope          : Permission scope (e.g. "governance:full")
 *   - delegationRef  : Reference to the delegation chain entry (nullable)
 *   - issued_at      : ISO-8601 timestamp
 *   - expires_at     : ISO-8601 timestamp
 */

const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Default token TTL in seconds (1 hour). */
const DEFAULT_TTL_SECONDS = 3600;

/** HMAC fallback secret — override via EXOCHAIN_AUTH_SECRET env var. */
const HMAC_SECRET = process.env.EXOCHAIN_AUTH_SECRET || 'exochain-dev-secret-change-in-production';

// ---------------------------------------------------------------------------
// WASM loader — lazy, non-fatal
// ---------------------------------------------------------------------------

let wasmModule = null;
let wasmLoadAttempted = false;

/**
 * Attempt to load the ExoChain WASM module for Ed25519 sign/verify.
 * Returns null if unavailable (startup, missing build, etc.).
 */
function loadWasm() {
  if (wasmLoadAttempted) return wasmModule;
  wasmLoadAttempted = true;
  try {
    wasmModule = require('../../packages/exochain-wasm/wasm/exochain_wasm');
    if (typeof wasmModule.wasm_ed25519_sign !== 'function' ||
        typeof wasmModule.wasm_ed25519_verify !== 'function') {
      console.warn('[auth] WASM module loaded but missing Ed25519 functions — falling back to HMAC');
      wasmModule = null;
    } else {
      console.info('[auth] WASM Ed25519 backend loaded successfully');
    }
  } catch (_err) {
    console.warn('[auth] WASM module unavailable — using HMAC-SHA256 fallback');
    wasmModule = null;
  }
  return wasmModule;
}

// ---------------------------------------------------------------------------
// Base64url helpers
// ---------------------------------------------------------------------------

function base64urlEncode(data) {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  return buf.toString('base64url');
}

function base64urlDecode(str) {
  return Buffer.from(str, 'base64url');
}

// ---------------------------------------------------------------------------
// Signing / verification backends
// ---------------------------------------------------------------------------

/**
 * Sign a message using Ed25519 (WASM) or HMAC-SHA256 (fallback).
 * @param {string} message - The message to sign (header.payload)
 * @returns {string} Base64url-encoded signature
 */
function sign(message) {
  const wasm = loadWasm();
  if (wasm) {
    // WASM Ed25519 path
    const sigBytes = wasm.wasm_ed25519_sign(Buffer.from(message, 'utf8'));
    return base64urlEncode(sigBytes);
  }
  // HMAC-SHA256 fallback
  const hmac = crypto.createHmac('sha256', HMAC_SECRET);
  hmac.update(message);
  return base64urlEncode(hmac.digest());
}

/**
 * Verify a signature against a message.
 * @param {string} message   - The signed message (header.payload)
 * @param {string} signature - Base64url-encoded signature
 * @returns {boolean}
 */
function verify(message, signature) {
  const wasm = loadWasm();
  if (wasm) {
    // WASM Ed25519 path
    const sigBytes = base64urlDecode(signature);
    return wasm.wasm_ed25519_verify(Buffer.from(message, 'utf8'), sigBytes);
  }
  // HMAC-SHA256 fallback: recompute and compare
  const expected = sign(message);
  return crypto.timingSafeEqual(
    Buffer.from(expected, 'utf8'),
    Buffer.from(signature, 'utf8')
  );
}

// ---------------------------------------------------------------------------
// Token creation & verification
// ---------------------------------------------------------------------------

/**
 * Create a signed session token.
 *
 * @param {string}  did            - Decentralized Identifier of the subject
 * @param {string}  scope          - Permission scope (e.g. "governance:full")
 * @param {string|null} delegationRef - Delegation chain reference (nullable)
 * @param {object}  [opts]         - Optional overrides
 * @param {number}  [opts.ttl]     - Token TTL in seconds (default: 3600)
 * @returns {string} Encoded token (header.payload.signature)
 */
function createToken(did, scope, delegationRef, opts) {
  const ttl = (opts && opts.ttl) || DEFAULT_TTL_SECONDS;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttl * 1000);

  const header = {
    alg: loadWasm() ? 'EdDSA' : 'HS256',
    typ: 'JWT',
  };

  const payload = {
    did,
    scope,
    delegationRef: delegationRef || null,
    issued_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
  };

  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = sign(signingInput);

  return `${signingInput}.${signature}`;
}

/**
 * Verify and decode a session token.
 *
 * @param {string} token - The encoded token (header.payload.signature)
 * @returns {{ valid: boolean, payload?: object, error?: string }}
 */
function verifyToken(token) {
  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'Token is required' };
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, error: 'Malformed token: expected 3 parts' };
  }

  const [headerB64, payloadB64, signature] = parts;
  const signingInput = `${headerB64}.${payloadB64}`;

  // Verify signature
  if (!verify(signingInput, signature)) {
    return { valid: false, error: 'Invalid signature' };
  }

  // Decode payload
  let payload;
  try {
    payload = JSON.parse(base64urlDecode(payloadB64).toString('utf8'));
  } catch (_err) {
    return { valid: false, error: 'Malformed payload' };
  }

  // Check expiration
  if (payload.expires_at) {
    const expiresAt = new Date(payload.expires_at);
    if (expiresAt <= new Date()) {
      return { valid: false, error: 'Token expired' };
    }
  }

  // Validate required fields
  if (!payload.did) {
    return { valid: false, error: 'Token missing required field: did' };
  }

  return { valid: true, payload };
}

// ---------------------------------------------------------------------------
// Express-compatible middleware
// ---------------------------------------------------------------------------

/**
 * Auth middleware for Express/Connect-style servers.
 *
 * Extracts the Bearer token from the Authorization header, verifies it,
 * and attaches the decoded payload to `req.user`.
 *
 * @param {object} req  - HTTP request
 * @param {object} res  - HTTP response
 * @param {function} next - Next middleware
 */
function authMiddleware(req, res, next) {
  const authHeader = req.headers && req.headers.authorization;

  if (!authHeader) {
    res.status(401);
    res.json({ error: 'Authorization header required' });
    return;
  }

  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    res.status(401);
    res.json({ error: 'Authorization header must use Bearer scheme' });
    return;
  }

  const token = match[1];
  const result = verifyToken(token);

  if (!result.valid) {
    res.status(401);
    res.json({ error: result.error });
    return;
  }

  // Attach decoded payload to request
  req.user = result.payload;
  next();
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  createToken,
  verifyToken,
  authMiddleware,
  // Exposed for testing
  _sign: sign,
  _verify: verify,
  _base64urlEncode: base64urlEncode,
  _base64urlDecode: base64urlDecode,
};
