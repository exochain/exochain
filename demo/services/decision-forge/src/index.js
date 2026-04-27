// Decision Forge — DecisionObject lifecycle, voting, evidence, contestation
import http from 'node:http';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const wasm = require('@exochain/exochain-wasm');
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const PORT = process.env.PORT || 3004;

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

function missingFields(input, fields) {
  return fields.filter(field => input[field] === undefined || input[field] === null || input[field] === '');
}

export const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': '*', 'Access-Control-Allow-Headers': 'Content-Type' });
    return res.end();
  }
  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    if (url.pathname === '/health') return json(res, 200, { status: 'ok', service: 'decision-forge' });

    // ── Create Decision ──
    if (url.pathname === '/api/decision/create' && req.method === 'POST') {
      const body = await parseBody(req);
      const { title, decision_class, constitution_hash, decision_id, created_at_ms, created_at_logical } = body;
      const missing = missingFields(body, ['constitution_hash', 'decision_id', 'created_at_ms', 'created_at_logical']);
      if (missing.length) return json(res, 400, { error: 'Missing required deterministic metadata', fields: missing });
      const decision = wasm.wasm_create_decision(
        decision_id,
        title,
        JSON.stringify(decision_class || 'Operational'),
        constitution_hash,
        created_at_ms,
        created_at_logical
      );
      return json(res, 201, decision);
    }

    // ── Add Vote ──
    if (url.pathname === '/api/decision/vote' && req.method === 'POST') {
      const { decision_json, vote } = await parseBody(req);
      const updated = wasm.wasm_add_vote(JSON.stringify(decision_json), JSON.stringify(vote));
      return json(res, 200, updated);
    }

    // ── Add Evidence ──
    if (url.pathname === '/api/decision/evidence' && req.method === 'POST') {
      const { decision_json, evidence } = await parseBody(req);
      const updated = wasm.wasm_add_evidence(JSON.stringify(decision_json), JSON.stringify(evidence));
      return json(res, 200, updated);
    }

    // ── Transition State ──
    if (url.pathname === '/api/decision/transition' && req.method === 'POST') {
      const body = await parseBody(req);
      const { decision_json, to_state, actor_did, timestamp_ms, timestamp_logical } = body;
      const missing = missingFields(body, ['timestamp_ms', 'timestamp_logical']);
      if (missing.length) return json(res, 400, { error: 'Missing required deterministic metadata', fields: missing });
      const updated = wasm.wasm_transition_decision(
        JSON.stringify(decision_json),
        JSON.stringify(to_state),
        actor_did,
        timestamp_ms,
        timestamp_logical
      );
      return json(res, 200, updated);
    }

    // ── Content Hash ──
    if (url.pathname === '/api/decision/hash' && req.method === 'POST') {
      const { decision_json } = await parseBody(req);
      const hash = wasm.wasm_decision_content_hash(JSON.stringify(decision_json));
      return json(res, 200, { hash });
    }

    // ── Check Terminal ──
    if (url.pathname === '/api/decision/terminal' && req.method === 'POST') {
      const { decision_json } = await parseBody(req);
      const terminal = wasm.wasm_decision_is_terminal(JSON.stringify(decision_json));
      return json(res, 200, { is_terminal: terminal });
    }

    // ── File Challenge (Contestation GOV-008) ──
    if (url.pathname === '/api/decision/challenge' && req.method === 'POST') {
      const body = await parseBody(req);
      const { challenger_did, decision_id, ground, evidence_hash, challenge_id, created_at_ms, created_at_logical } = body;
      const missing = missingFields(body, ['challenge_id', 'created_at_ms', 'created_at_logical']);
      if (missing.length) return json(res, 400, { error: 'Missing required deterministic metadata', fields: missing });
      const challenge = wasm.wasm_file_challenge(
        challenge_id,
        challenger_did,
        decision_id,
        JSON.stringify(ground),
        evidence_hash,
        created_at_ms,
        created_at_logical
      );
      return json(res, 200, challenge);
    }

    // ── Propose Accountability (GOV-012) ──
    if (url.pathname === '/api/decision/accountability' && req.method === 'POST') {
      const body = await parseBody(req);
      const { target_did, proposer_did, action_type, reason, evidence_hash, action_id, proposed_at_ms, proposed_at_logical } = body;
      const missing = missingFields(body, ['action_id', 'proposed_at_ms', 'proposed_at_logical']);
      if (missing.length) return json(res, 400, { error: 'Missing required deterministic metadata', fields: missing });
      const action = wasm.wasm_propose_accountability(
        action_id,
        target_did,
        proposer_did,
        JSON.stringify(action_type),
        reason,
        evidence_hash,
        proposed_at_ms,
        proposed_at_logical
      );
      return json(res, 200, action);
    }

    // ── Workflow Stages ──
    if (url.pathname === '/api/workflow/stages' && req.method === 'GET') {
      const stages = wasm.wasm_workflow_stages();
      return json(res, 200, { stages });
    }

    json(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error('Error:', e);
    json(res, 500, { error: e.message });
  }
});

if (!process.env.VITEST) {
  server.listen(PORT, () => console.log(`[decision-forge] Running on :${PORT}`));
}
