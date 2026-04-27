// Provenance Writer — evidence creation, chain of custody, eDiscovery, fiduciary duty
import http from 'node:http';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const wasm = require('@exochain/exochain-wasm');
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const PORT = process.env.PORT || 3006;

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
    if (url.pathname === '/health') return json(res, 200, { status: 'ok', service: 'provenance-writer' });

    // ── Create Evidence ──
    if (url.pathname === '/api/evidence/create' && req.method === 'POST') {
      const { content, type_tag, creator_did, evidence_id, created_ms } = await parseBody(req);
      if (!evidence_id || created_ms === undefined || created_ms === null) {
        return json(res, 400, { error: 'evidence_id and created_ms are required' });
      }
      const evidence = wasm.wasm_create_evidence(
        new Uint8Array(Buffer.from(content || '')),
        type_tag || 'document',
        creator_did,
        evidence_id,
        BigInt(created_ms)
      );
      return json(res, 201, evidence);
    }

    // ── Verify Chain of Custody ──
    if (url.pathname === '/api/evidence/verify' && req.method === 'POST') {
      const { evidence } = await parseBody(req);
      const result = wasm.wasm_verify_chain_of_custody(JSON.stringify(evidence));
      return json(res, 200, result);
    }

    // ── Check Fiduciary Duty ──
    if (url.pathname === '/api/fiduciary/check' && req.method === 'POST') {
      const { duty, actions } = await parseBody(req);
      const result = wasm.wasm_check_fiduciary_duty(JSON.stringify(duty), JSON.stringify(actions));
      return json(res, 200, result);
    }

    // ── eDiscovery Search ──
    if (url.pathname === '/api/ediscovery/search' && req.method === 'POST') {
      const { request, corpus } = await parseBody(req);
      const result = wasm.wasm_ediscovery_search(JSON.stringify(request), JSON.stringify(corpus));
      return json(res, 200, result);
    }

    // ── Escalation: Evaluate Signals ──
    if (url.pathname === '/api/escalation/evaluate' && req.method === 'POST') {
      const { signals } = await parseBody(req);
      const result = wasm.wasm_evaluate_signals(JSON.stringify(signals));
      return json(res, 200, result);
    }

    json(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error('Error:', e);
    json(res, 500, { error: e.message });
  }
});

if (!process.env.VITEST) {
  server.listen(PORT, () => console.log(`[provenance-writer] Running on :${PORT}`));
}
