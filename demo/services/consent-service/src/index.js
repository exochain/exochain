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

// Consent Service — bailment management, consent anchors
import http from 'node:http';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const wasm = require('@exochain/exochain-wasm');
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const PORT = process.env.PORT || 3002;

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
    if (url.pathname === '/health') return json(res, 200, { status: 'ok', service: 'consent-service' });

    // ── List Consent Anchors ──
    if (url.pathname === '/api/anchors' && req.method === 'GET') {
      const { rows } = await pool.query('SELECT * FROM consent_anchors ORDER BY granted_at_ms DESC');
      return json(res, 200, rows);
    }

    // ── Propose Bailment ──
    if (url.pathname === '/api/bailment/propose' && req.method === 'POST') {
      const { bailor_did, bailee_did, terms, bailment_type } = await parseBody(req);
      const bailment = wasm.wasm_propose_bailment(
        bailor_did, bailee_did,
        new Uint8Array(Buffer.from(terms || '')),
        JSON.stringify(bailment_type || 'Processing')
      );
      return json(res, 200, bailment);
    }

    // ── Check Bailment Active ──
    if (url.pathname === '/api/bailment/active' && req.method === 'POST') {
      const { bailment } = await parseBody(req);
      const active = wasm.wasm_bailment_is_active(JSON.stringify(bailment));
      return json(res, 200, { active });
    }

    json(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error('Error:', e);
    json(res, 500, { error: e.message });
  }
});

if (!process.env.VITEST) {
  server.listen(PORT, () => console.log(`[consent-service] Running on :${PORT}`));
}
