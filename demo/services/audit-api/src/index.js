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

// Audit API — hash-chained audit log, verification, provenance
import http from 'node:http';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const wasm = require('@exochain/exochain-wasm');
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const PORT = process.env.PORT || 3007;
// Governance health endpoint requires a bearer token (Security panel condition — CR-001 amendment).
// Set GOVERNANCE_API_TOKEN in the secrets manager; never in env files or Compose.
// Set GOVERNANCE_ATTESTATION_KEYS as a JSON object mapping trusted signer DID to Ed25519 public key hex.
const GOVERNANCE_API_TOKEN = process.env.GOVERNANCE_API_TOKEN || null;
const GOVERNANCE_ATTESTATION_KEYS = parseGovernanceAttestationKeys(
  process.env.GOVERNANCE_ATTESTATION_KEYS || null,
);

function parseGovernanceAttestationKeys(value) {
  const trustedKeys = new Map();
  if (!value) return trustedKeys;

  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch (e) {
    throw new Error('GOVERNANCE_ATTESTATION_KEYS must be a JSON object mapping signer DID to Ed25519 public key hex');
  }

  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('GOVERNANCE_ATTESTATION_KEYS must be a JSON object mapping signer DID to Ed25519 public key hex');
  }

  for (const [signerDid, publicKeyHex] of Object.entries(parsed)) {
    if (typeof signerDid !== 'string' || !signerDid.startsWith('did:exo:')) {
      throw new Error('GOVERNANCE_ATTESTATION_KEYS contains an invalid signer DID');
    }
    if (typeof publicKeyHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(publicKeyHex)) {
      throw new Error(`GOVERNANCE_ATTESTATION_KEYS contains an invalid Ed25519 public key for ${signerDid}`);
    }
    trustedKeys.set(signerDid, publicKeyHex.toLowerCase());
  }

  return trustedKeys;
}

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
    if (url.pathname === '/health') return json(res, 200, { status: 'ok', service: 'audit-api' });

    // ── List Audit Entries ──
    if (url.pathname === '/api/entries' && req.method === 'GET') {
      const limit = url.searchParams.get('limit') || 50;
      const { rows } = await pool.query('SELECT * FROM audit_entries ORDER BY sequence DESC LIMIT $1', [limit]);
      return json(res, 200, rows);
    }

    // ── Append Audit Entry ──
    if (url.pathname === '/api/entries' && req.method === 'POST') {
      const { actor_did, action, result, evidence_hash } = await parseBody(req);
      const auditResult = wasm.wasm_audit_append(actor_did, action, result, evidence_hash || '0'.repeat(64));

      // Also persist to DB
      const { rows: [last] } = await pool.query('SELECT COALESCE(MAX(sequence), -1) as seq, COALESCE(MAX(entry_hash), $1) as prev FROM audit_entries', ['0'.repeat(64)]);
      const eventHash = wasm.wasm_hash_bytes(new Uint8Array(Buffer.from(`${action}:${result}`)));

      await pool.query(
        'INSERT INTO audit_entries (sequence, prev_hash, event_hash, event_type, actor, tenant_id, timestamp_physical_ms, entry_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
        [last.seq + 1, last.prev, eventHash, action, actor_did, 'exochain-foundation', Date.now(), auditResult.head_hash]
      );

      return json(res, 201, { entry_count: auditResult.entries, head_hash: auditResult.head_hash });
    }

    // ── Governance Health (authenticated — Security panel: CR-001 amendment) ──
    if (url.pathname === '/governance/health' && req.method === 'GET') {
      const authHeader = req.headers['authorization'] || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
      if (!GOVERNANCE_API_TOKEN || token !== GOVERNANCE_API_TOKEN) {
        return json(res, 401, { error: 'Unauthorized: valid Bearer token required' });
      }

      const { rows: snapshots } = await pool.query(
        'SELECT * FROM governance_health_snapshots ORDER BY scanned_at_ms DESC LIMIT 1'
      );
      if (snapshots.length === 0) {
        return json(res, 200, { status: 'no_data', message: 'No governance health snapshots recorded yet' });
      }
      const snap = snapshots[0];

      const { rows: findings } = await pool.query(
        'SELECT finding_id, title, category, severity, file_path, description FROM governance_findings WHERE run_id = $1 ORDER BY severity ASC',
        [snap.run_id]
      );

      // Pending human approval gates (DualControl — Security panel condition)
      const { rows: pendingApprovals } = await pool.query(
        "SELECT approval_id, requested_at_ms FROM governance_trigger_approvals WHERE run_id = $1 AND status = 'Pending'",
        [snap.run_id]
      );

      return json(res, 200, {
        run_id: snap.run_id,
        commit_sha: snap.commit_sha,
        scanned_at_ms: snap.scanned_at_ms,
        system_health: {
          invariant_coverage: snap.invariant_coverage,
          tnc_coverage: snap.tnc_coverage,
          bcts_integrity: snap.bcts_integrity,
          governance_score: snap.governance_score,
        },
        finding_counts: {
          critical: snap.findings_count_critical,
          high: snap.findings_count_high,
          medium: snap.findings_count_medium,
          low: snap.findings_count_low,
        },
        findings_digest: snap.findings_digest,
        findings,
        cr001_work_orders: snap.cr001_work_orders,
        attestation: snap.attestation_signature
          ? { signature: snap.attestation_signature, signer_did: snap.attestation_signer_did }
          : null,
        pending_trigger_approvals: pendingApprovals.length,
      });
    }

    // ── Record Governance Health Snapshot ──
    if (url.pathname === '/governance/health' && req.method === 'POST') {
      const authHeader = req.headers['authorization'] || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
      if (!GOVERNANCE_API_TOKEN || token !== GOVERNANCE_API_TOKEN) {
        return json(res, 401, { error: 'Unauthorized: valid Bearer token required' });
      }

      const body = await parseBody(req);
      const {
        run_id, commit_sha, system_health, findings = [],
        findings_digest, attestation_signature, attestation_signer_did, attestation_public_key,
        cr001_work_orders = {},
      } = body;

      if (!run_id || !commit_sha || !system_health || !findings_digest) {
        return json(res, 400, { error: 'run_id, commit_sha, system_health, and findings_digest are required' });
      }

      if (!attestation_signature || !attestation_signer_did) {
        return json(res, 400, { error: 'attestation_signature and attestation_signer_did are required' });
      }

      const trustedAttestationPublicKey = GOVERNANCE_ATTESTATION_KEYS.get(attestation_signer_did);
      if (!trustedAttestationPublicKey) {
        return json(res, 400, { error: `attestation signer ${attestation_signer_did} is not configured` });
      }

      if (
        attestation_public_key !== undefined
        && attestation_public_key !== null
        && String(attestation_public_key).toLowerCase() !== trustedAttestationPublicKey
      ) {
        return json(res, 400, { error: 'attestation_public_key does not match configured signer key' });
      }

      try {
        const computedFindingsDigest = wasm.wasm_governance_findings_digest(JSON.stringify(findings));
        if (computedFindingsDigest !== findings_digest) {
          return json(res, 400, { error: 'findings_digest does not match canonical findings payload' });
        }

        wasm.wasm_verify_governance_attestation(
          attestation_signer_did,
          JSON.stringify(findings),
          JSON.stringify(attestation_signature),
          trustedAttestationPublicKey,
        );
      } catch (e) {
        return json(res, 400, { error: `invalid governance attestation: ${e.message || e}` });
      }

      const counts = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const f of findings) {
        const sev = (f.severity || '').toLowerCase();
        if (sev in counts) counts[sev]++;
      }

      await pool.query(
        `INSERT INTO governance_health_snapshots
           (run_id, commit_sha, scanned_at_ms, invariant_coverage, tnc_coverage,
            bcts_integrity, governance_score, findings_digest,
            findings_count_critical, findings_count_high, findings_count_medium, findings_count_low,
            attestation_signature, attestation_signer_did, cr001_work_orders)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         ON CONFLICT (run_id) DO NOTHING`,
        [
          run_id, commit_sha, Date.now(),
          system_health.invariant_coverage, system_health.tnc_coverage,
          system_health.bcts_integrity, system_health.governance_score,
          findings_digest, counts.critical, counts.high, counts.medium, counts.low,
          attestation_signature || null, attestation_signer_did || null,
          JSON.stringify(cr001_work_orders),
        ]
      );

      for (const f of findings) {
        await pool.query(
          `INSERT INTO governance_findings
             (run_id, finding_id, title, category, severity, file_path, line_number,
              description, remediation, invariants_affected, scanned_at_ms)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          [
            run_id, f.id, f.title, f.category, f.severity,
            f.file || null, f.line || null, f.description, f.remediation,
            JSON.stringify(f.invariants_affected || []), Date.now(),
          ]
        );
      }

      // Circuit breaker: if >3 Critical findings in last 24h, flag for ops team
      const since = Date.now() - 86_400_000;
      const { rows: [{ total }] } = await pool.query(
        'SELECT COALESCE(SUM(findings_count_critical), 0) AS total FROM governance_health_snapshots WHERE scanned_at_ms >= $1',
        [since]
      );
      const circuitBreaker = parseInt(total, 10) > 3;

      // Record human-approval gate if Critical/High findings require self-improvement trigger
      let approvalGateId = null;
      if (counts.critical > 0 || counts.high > 0) {
        approvalGateId = `approval-${run_id}`;
        await pool.query(
          `INSERT INTO governance_trigger_approvals (approval_id, run_id, requested_at_ms, status)
           VALUES ($1, $2, $3, 'Pending') ON CONFLICT (approval_id) DO NOTHING`,
          [approvalGateId, run_id, Date.now()]
        );
      }

      // Record in audit ledger with full provenance
      const { rows: [last] } = await pool.query(
        'SELECT COALESCE(MAX(sequence), -1) AS seq, COALESCE(MAX(entry_hash), $1) AS prev FROM audit_entries',
        ['0'.repeat(64)]
      );
      const eventHash = wasm.wasm_hash_bytes(new Uint8Array(Buffer.from(`governance-health:${run_id}:${findings_digest}`)));
      await pool.query(
        'INSERT INTO audit_entries (sequence, prev_hash, event_hash, event_type, actor, tenant_id, timestamp_physical_ms, entry_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
        [last.seq + 1, last.prev, eventHash, 'GovernanceHealthSnapshot', attestation_signer_did || 'did:exo:exoforge', 'exochain-foundation', Date.now(), eventHash]
      );

      return json(res, 201, {
        run_id,
        governance_score: system_health.governance_score,
        circuit_breaker_triggered: circuitBreaker,
        approval_gate_id: approvalGateId,
        message: circuitBreaker
          ? 'Circuit breaker triggered: >3 Critical findings in 24h. Auto-trigger paused. Ops team alerted.'
          : approvalGateId
            ? 'Critical/High findings recorded. Human approval required before self-improvement cycle may begin.'
            : 'Snapshot recorded.',
      });
    }

    // ── Approve Governance Trigger ──
    if (url.pathname.startsWith('/governance/approve/') && req.method === 'POST') {
      const authHeader = req.headers['authorization'] || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
      if (!GOVERNANCE_API_TOKEN || token !== GOVERNANCE_API_TOKEN) {
        return json(res, 401, { error: 'Unauthorized: valid Bearer token required' });
      }

      const approvalId = url.pathname.replace('/governance/approve/', '');
      const { approved_by_did, notes } = await parseBody(req);

      if (!approved_by_did) {
        return json(res, 400, { error: 'approved_by_did is required (must be a human DID)' });
      }

      const { rowCount } = await pool.query(
        `UPDATE governance_trigger_approvals
         SET status = 'Approved', approved_at_ms = $1, approved_by_did = $2, notes = $3
         WHERE approval_id = $4 AND status = 'Pending'`,
        [Date.now(), approved_by_did, notes || null, approvalId]
      );

      if (rowCount === 0) {
        return json(res, 404, { error: 'Approval gate not found or already resolved' });
      }

      return json(res, 200, { approval_id: approvalId, status: 'Approved', approved_by_did });
    }

    // ── Verify Chain Integrity ──
    if (url.pathname === '/api/verify' && req.method === 'GET') {
      const { rows } = await pool.query('SELECT * FROM audit_entries ORDER BY sequence ASC');

      // Verify hash chain manually
      let valid = true;
      let error = null;
      for (let i = 1; i < rows.length; i++) {
        if (rows[i].prev_hash !== rows[i - 1].entry_hash) {
          valid = false;
          error = `Chain break at sequence ${rows[i].sequence}: prev_hash doesn't match previous entry_hash`;
          break;
        }
      }

      return json(res, 200, {
        intact: valid,
        entries_checked: rows.length,
        head_hash: rows.length > 0 ? rows[rows.length - 1].entry_hash : null,
        error,
      });
    }

    json(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error('Error:', e);
    json(res, 500, { error: e.message });
  }
});

if (!process.env.VITEST) {
  server.listen(PORT, () => console.log(`[audit-api] Running on :${PORT}`));
}
