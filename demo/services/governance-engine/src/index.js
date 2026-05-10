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

// Governance Engine — quorum computation, clearance, conflict checking, authority chains
import http from 'node:http';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const wasm = require('@exochain/exochain-wasm');
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const PORT = process.env.PORT || 3003;

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
    if (url.pathname === '/health') return json(res, 200, { status: 'ok', service: 'governance-engine' });

    // ── Compute Quorum ──
    if (url.pathname === '/api/quorum/compute' && req.method === 'POST') {
      const { approvals, policy } = await parseBody(req);
      const result = wasm.wasm_compute_quorum(JSON.stringify(approvals), JSON.stringify(policy));
      return json(res, 200, result);
    }

    // ── Check Clearance ──
    if (url.pathname === '/api/clearance/check' && req.method === 'POST') {
      const { actor_did, action, policy } = await parseBody(req);
      const result = wasm.wasm_check_clearance(actor_did, action, JSON.stringify(policy));
      return json(res, 200, result);
    }

    // ── Check Conflicts ──
    if (url.pathname === '/api/conflicts/check' && req.method === 'POST') {
      const { actor_did, action, declarations } = await parseBody(req);
      const result = wasm.wasm_check_conflicts(actor_did, JSON.stringify(action), JSON.stringify(declarations || []));
      return json(res, 200, result);
    }

    // ── File Challenge ──
    if (url.pathname === '/api/challenge' && req.method === 'POST') {
      const { challenger_did, target_hash, ground, evidence } = await parseBody(req);
      const result = wasm.wasm_file_governance_challenge(
        challenger_did,
        target_hash,
        JSON.stringify(ground),
        new Uint8Array(Buffer.from(evidence || ''))
      );
      return json(res, 200, result);
    }

    // ── Authority Chain ──
    if (url.pathname === '/api/authority/build' && req.method === 'POST') {
      const { links } = await parseBody(req);
      const chain = wasm.wasm_build_authority_chain(JSON.stringify(links));
      return json(res, 200, chain);
    }

    // ── Evaluate Decision (full pipeline) ──
    if (url.pathname === '/api/evaluate' && req.method === 'POST') {
      const body = await parseBody(req);
      const { decision_id, actor_did } = body;

      // Load decision
      const { rows: [decision] } = await pool.query('SELECT * FROM decisions WHERE id_hash = $1', [decision_id]);
      if (!decision) return json(res, 404, { error: 'Decision not found' });

      // Load actor
      const { rows: [actor] } = await pool.query('SELECT * FROM users WHERE did = $1', [actor_did]);
      if (!actor) return json(res, 404, { error: 'Actor not found' });

      // Check clearance
      const clearancePolicy = { actions: { [decision.status]: { required_level: 'Governor' } } };
      const clearance = wasm.wasm_check_clearance(actor_did, decision.status, JSON.stringify(clearancePolicy));

      // Check conflicts
      const action = { action_id: decision_id, actor_did, affected_dids: [], description: `Evaluate ${decision_id}` };
      const conflicts = wasm.wasm_check_conflicts(actor_did, JSON.stringify(action), '[]');

      // Load delegations for authority chain
      const { rows: delegations } = await pool.query('SELECT * FROM delegations WHERE delegatee = $1 AND expires_at > $2', [actor_did, Date.now()]);

      return json(res, 200, {
        decision: { id: decision.id_hash, title: decision.title, status: decision.status, class: decision.decision_class },
        actor: { did: actor.did, name: actor.display_name, roles: actor.roles, pace: actor.pace_status },
        clearance,
        conflicts,
        delegations: delegations.length,
        evaluation: clearance.status === 'Granted' && !conflicts.must_recuse ? 'APPROVED' : 'BLOCKED',
      });
    }

    json(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error('Error:', e);
    json(res, 500, { error: e.message });
  }
});

if (!process.env.VITEST) {
  server.listen(PORT, () => console.log(`[governance-engine] Running on :${PORT}`));
}
