// Identity Service — PACE continuity, Shamir secret sharing, risk assessment
import http from 'node:http';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const wasm = require('@exochain/exochain-wasm');
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const PORT = process.env.PORT || 3001;

function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' });
  res.end(JSON.stringify(data, null, 2));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch(e) { reject(e); } });
  });
}

export const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': '*', 'Access-Control-Allow-Headers': 'Content-Type' });
    return res.end();
  }
  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    if (url.pathname === '/health') return json(res, 200, { status: 'ok', service: 'identity-service' });

    // ── List Users ──
    if (url.pathname === '/api/users' && req.method === 'GET') {
      const { rows } = await pool.query('SELECT did, display_name, email, roles, status, pace_status FROM users');
      return json(res, 200, rows);
    }

    // ── Identity Scores ──
    if (url.pathname === '/api/scores' && req.method === 'GET') {
      const { rows } = await pool.query('SELECT i.*, u.display_name FROM identity_scores i JOIN users u ON u.did = i.did');
      return json(res, 200, rows);
    }

    // ── Enrollment Log ──
    if (url.pathname === '/api/enrollment' && req.method === 'GET') {
      const { rows } = await pool.query('SELECT * FROM enrollment_log ORDER BY timestamp DESC');
      return json(res, 200, rows);
    }

    // ── Shamir Split ──
    if (url.pathname === '/api/shamir/split' && req.method === 'POST') {
      const { secret, threshold, shares } = await parseBody(req);
      const secretBytes = new Uint8Array(Buffer.from(secret || 'demo-secret'));
      const result = wasm.wasm_shamir_split(secretBytes, threshold || 2, shares || 3);
      return json(res, 200, { shares: result, threshold: threshold || 2, total: shares || 3 });
    }

    // ── Shamir Reconstruct ──
    if (url.pathname === '/api/shamir/reconstruct' && req.method === 'POST') {
      const { shares, threshold, total } = await parseBody(req);
      const result = wasm.wasm_shamir_reconstruct(JSON.stringify(shares), threshold, total);
      return json(res, 200, result);
    }

    // ── PACE Resolve ──
    if (url.pathname === '/api/pace/resolve' && req.method === 'POST') {
      const { config, state } = await parseBody(req);
      const result = wasm.wasm_pace_resolve(JSON.stringify(config), JSON.stringify(state));
      return json(res, 200, result);
    }

    // ── PACE Escalate ──
    if (url.pathname === '/api/pace/escalate' && req.method === 'POST') {
      const { state } = await parseBody(req);
      const result = wasm.wasm_pace_escalate(JSON.stringify(state));
      return json(res, 200, { new_state: result });
    }

    // ── Risk Assessment ──
    if (url.pathname === '/api/risk/assess' && req.method === 'POST') {
      const {
        subject_did,
        attester_did,
        evidence,
        level,
        validity_ms,
        attester_secret_hex,
        timestamp_ms,
        timestamp_logical
      } = await parseBody(req);
      const missing = [];
      if (!attester_secret_hex) missing.push('attester_secret_hex');
      if (timestamp_ms === undefined || timestamp_ms === null) missing.push('timestamp_ms');
      if (missing.length > 0) {
        return json(res, 400, { error: 'missing required caller-supplied risk metadata', fields: missing });
      }
      const result = wasm.wasm_assess_risk(
        subject_did, attester_did,
        new Uint8Array(Buffer.from(evidence || '')),
        JSON.stringify(level || 'Medium'),
        JSON.stringify({
          validity_ms: validity_ms || 86400000,
          attester_secret_hex,
          now_physical_ms: Number(timestamp_ms),
          now_logical: timestamp_logical || 0
        })
      );
      return json(res, 200, result);
    }

    // ── Generate Keypair ──
    if (url.pathname === '/api/keypair' && req.method === 'POST') {
      const kp = wasm.wasm_generate_keypair();
      return json(res, 200, kp);
    }

    json(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error('Error:', e);
    json(res, 500, { error: e.message });
  }
});

if (!process.env.VITEST) {
  server.listen(PORT, () => console.log(`[identity-service] Running on :${PORT}`));
}
