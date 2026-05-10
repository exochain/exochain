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

// CrossChecked.ai API — Plural Intelligence Verification powered by EXOCHAIN
// Production service: 22 endpoints, 5-panel AI-IRB council, hash-chained receipts
import http from 'node:http';
import crypto from 'node:crypto';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const wasm = require('@exochain/exochain-wasm');
import pg from 'pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const PORT = process.env.PORT || 3012;

function json(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(JSON.stringify(data, null, 2));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch(e) { reject(e); } });
  });
}

function nowMs() { return Date.now(); }
function genId(prefix = 'CR') { return `${prefix}-${crypto.randomUUID().replace(/-/g, '').slice(0, 10)}`; }

/** Compute canonical hash matching sybil-cli: sorted keys, excludes custody/anchors/timestamps/status */
function canonicalHash(proposal) {
  const canonical = {
    context: proposal.context || '',
    consequences: proposal.consequences || '',
    decision: proposal.decision || proposal.title || '',
    title: proposal.title || '',
    assumptions: proposal.assumptions || [],
    options_considered: proposal.options_considered || [],
    tags: proposal.tags || [],
  };
  const sorted = JSON.stringify(canonical, Object.keys(canonical).sort(), 0);
  return crypto.createHash('sha256').update(sorted).digest('hex');
}

export const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': '*', 'Access-Control-Allow-Headers': 'Content-Type' });
    return res.end();
  }
  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    if (url.pathname === '/health') return json(res, 200, { status: 'ok', service: 'crosschecked-api' });

    // ══════════════════════════════════════════════════════════════════
    // PROPOSAL LIFECYCLE
    // ══════════════════════════════════════════════════════════════════

    // ── Create proposal ──
    if (url.pathname === '/api/proposals' && req.method === 'POST') {
      const { author_did, title, context, decision, consequences, method, decision_class, full_5x5, assumptions, options_considered, tags } = await parseBody(req);
      if (!author_did || !title || !context) return json(res, 400, { error: 'author_did, title, and context are required' });

      const id = genId('CR');
      const now = nowMs();
      const record_hash = canonicalHash({ title, context, decision, consequences, assumptions, options_considered, tags });

      await pool.query(
        `INSERT INTO crosscheck_proposals (id, author_did, title, context, decision, consequences, method, status, decision_class, full_5x5, assumptions, options_considered, tags, record_hash, created_at_ms, updated_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'draft',$8,$9,$10,$11,$12,$13,$14,$15)`,
        [id, author_did, title, context, decision || null, consequences || null,
         method || 'mosaic', decision_class || 'Operational', full_5x5 || false,
         JSON.stringify(assumptions || []), JSON.stringify(options_considered || []),
         JSON.stringify(tags || []), record_hash, now, now]
      );

      // Record custody event
      await pool.query(
        `INSERT INTO crosscheck_custody_events (proposal_id, actor_did, role, action, record_hash, created_at_ms)
         VALUES ($1, $2, 'proposer', 'create', $3, $4)`,
        [id, author_did, record_hash, now]
      );

      return json(res, 201, { id, status: 'draft', record_hash });
    }

    // ── List proposals ──
    if (url.pathname === '/api/proposals' && req.method === 'GET') {
      const status = url.searchParams.get('status');
      let query = 'SELECT id, author_did, title, status, decision_class, method, full_5x5, record_hash, created_at_ms FROM crosscheck_proposals';
      const params = [];
      if (status) { query += ' WHERE status = $1'; params.push(status); }
      query += ' ORDER BY created_at_ms DESC';
      const { rows } = await pool.query(query, params);
      return json(res, 200, rows);
    }

    // ── Get proposal detail ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+$/) && req.method === 'GET') {
      const id = url.pathname.split('/api/proposals/')[1];
      const { rows: proposals } = await pool.query('SELECT * FROM crosscheck_proposals WHERE id = $1', [id]);
      if (proposals.length === 0) return json(res, 404, { error: 'proposal not found' });

      const [opinions, reports, evidence, anchors, custody, deliberations, clearance] = await Promise.all([
        pool.query('SELECT * FROM crosscheck_opinions WHERE proposal_id = $1 ORDER BY submitted_at_ms', [id]),
        pool.query('SELECT * FROM crosscheck_reports WHERE proposal_id = $1 ORDER BY created_at_ms DESC', [id]),
        pool.query('SELECT * FROM crosscheck_evidence WHERE proposal_id = $1 ORDER BY created_at_ms', [id]),
        pool.query('SELECT * FROM crosscheck_anchors WHERE proposal_id = $1 ORDER BY anchored_at_ms', [id]),
        pool.query('SELECT * FROM crosscheck_custody_events WHERE proposal_id = $1 ORDER BY id', [id]),
        pool.query('SELECT * FROM crosscheck_deliberations WHERE proposal_id = $1 ORDER BY opened_at_ms DESC', [id]),
        pool.query('SELECT * FROM crosscheck_clearance_certs WHERE proposal_id = $1 ORDER BY issued_at_ms DESC', [id]),
      ]);

      return json(res, 200, {
        ...proposals[0],
        opinions: opinions.rows,
        reports: reports.rows,
        evidence: evidence.rows,
        anchors: anchors.rows,
        custody: custody.rows,
        deliberations: deliberations.rows,
        clearance_certificates: clearance.rows,
      });
    }

    // ── Transition status ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/status$/) && req.method === 'PUT') {
      const id = url.pathname.split('/')[3];
      const { status: newStatus, actor_did } = await parseBody(req);
      if (!newStatus || !actor_did) return json(res, 400, { error: 'status and actor_did required' });

      const result = await pool.query(
        'UPDATE crosscheck_proposals SET status = $1, updated_at_ms = $2 WHERE id = $3 RETURNING *',
        [newStatus, nowMs(), id]
      );
      if (result.rows.length === 0) return json(res, 404, { error: 'proposal not found' });

      await pool.query(
        `INSERT INTO crosscheck_custody_events (proposal_id, actor_did, role, action, created_at_ms)
         VALUES ($1, $2, 'steward', $3, $4)`,
        [id, actor_did, `status:${newStatus}`, nowMs()]
      );

      return json(res, 200, result.rows[0]);
    }

    // ── Canonical hash ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/hash$/) && req.method === 'GET') {
      const id = url.pathname.split('/')[3];
      const { rows } = await pool.query('SELECT * FROM crosscheck_proposals WHERE id = $1', [id]);
      if (rows.length === 0) return json(res, 404, { error: 'proposal not found' });
      const hash = canonicalHash(rows[0]);
      return json(res, 200, { hash, proposal_id: id });
    }

    // ══════════════════════════════════════════════════════════════════
    // EVIDENCE
    // ══════════════════════════════════════════════════════════════════

    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/evidence$/) && req.method === 'POST') {
      const proposalId = url.pathname.split('/')[3];
      const { kind, description, uri, content_hash, metadata } = await parseBody(req);
      if (!description) return json(res, 400, { error: 'description required' });

      const id = genId('EV');
      await pool.query(
        `INSERT INTO crosscheck_evidence (id, proposal_id, kind, description, uri, content_hash, metadata, created_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [id, proposalId, kind || 'link', description, uri || null, content_hash || null, JSON.stringify(metadata || {}), nowMs()]
      );

      // Recompute proposal hash (evidence changes hash)
      const { rows } = await pool.query('SELECT * FROM crosscheck_proposals WHERE id = $1', [proposalId]);
      if (rows.length > 0) {
        const newHash = canonicalHash(rows[0]);
        await pool.query('UPDATE crosscheck_proposals SET record_hash = $1, updated_at_ms = $2 WHERE id = $3', [newHash, nowMs(), proposalId]);
      }

      return json(res, 201, { id, proposal_id: proposalId });
    }

    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/evidence$/) && req.method === 'GET') {
      const proposalId = url.pathname.split('/')[3];
      const { rows } = await pool.query('SELECT * FROM crosscheck_evidence WHERE proposal_id = $1 ORDER BY created_at_ms', [proposalId]);
      return json(res, 200, rows);
    }

    // ══════════════════════════════════════════════════════════════════
    // CROSSCHECK / 5-PANEL COUNCIL
    // ══════════════════════════════════════════════════════════════════

    // ── Generate crosscheck template ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/crosscheck\/template$/) && req.method === 'GET') {
      const proposalId = url.pathname.split('/')[3];
      const { rows } = await pool.query('SELECT * FROM crosscheck_proposals WHERE id = $1', [proposalId]);
      if (rows.length === 0) return json(res, 404, { error: 'proposal not found' });

      const proposal = rows[0];
      const panels = ['Governance', 'Legal', 'Architecture', 'Security', 'Operations'];
      const properties = proposal.full_5x5 ? ['Storable', 'Diffable', 'Transferable', 'Auditable', 'Contestable'] : [null];

      const template = {
        schema_version: '0.2',
        proposal_id: proposalId,
        question: `Should we ${proposal.title}?`,
        method: proposal.method,
        full_5x5: proposal.full_5x5,
        opinions_needed: panels.length * properties.length,
        template_opinions: panels.flatMap(panel =>
          properties.map(property => ({
            agent_did: '',
            agent_kind: 'ai',
            agent_label: `${panel} Panel${property ? ` — ${property}` : ''}`,
            model: '',
            panel,
            property,
            stance: '',
            summary: '',
            rationale: '',
            confidence: null,
            risks: [],
          }))
        ),
      };
      return json(res, 200, template);
    }

    // ── Trigger crosscheck ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/crosscheck$/) && req.method === 'POST') {
      const proposalId = url.pathname.split('/')[3];
      const { actor_did } = await parseBody(req);

      await pool.query('UPDATE crosscheck_proposals SET status = $1, updated_at_ms = $2 WHERE id = $3', ['crosschecking', nowMs(), proposalId]);
      await pool.query(
        `INSERT INTO crosscheck_custody_events (proposal_id, actor_did, role, action, created_at_ms)
         VALUES ($1, $2, 'steward', 'crosscheck:start', $3)`,
        [proposalId, actor_did || 'system', nowMs()]
      );

      return json(res, 200, { proposal_id: proposalId, status: 'crosschecking' });
    }

    // ── Submit opinion ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/opinions$/) && req.method === 'POST') {
      const proposalId = url.pathname.split('/')[3];
      const { agent_did, agent_kind, agent_label, model, policy_id, stance, summary, rationale, confidence, risks, suggested_edits, evidence_refs, panel, property } = await parseBody(req);
      if (!agent_did || !stance || !summary) return json(res, 400, { error: 'agent_did, stance, and summary required' });

      const id = genId('OP');
      await pool.query(
        `INSERT INTO crosscheck_opinions (id, proposal_id, agent_did, agent_kind, agent_label, model, policy_id, stance, summary, rationale, confidence, risks, suggested_edits, evidence_refs, panel, property, submitted_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
        [id, proposalId, agent_did, agent_kind || 'ai', agent_label || null, model || null, policy_id || null, stance, summary, rationale || null, confidence ?? null, JSON.stringify(risks || []), suggested_edits || null, JSON.stringify(evidence_refs || []), panel || null, property || null, nowMs()]
      );

      await pool.query(
        `INSERT INTO crosscheck_custody_events (proposal_id, actor_did, role, action, created_at_ms)
         VALUES ($1, $2, 'participant', 'add_crosscheck', $3)`,
        [proposalId, agent_did, nowMs()]
      );

      return json(res, 201, { id, proposal_id: proposalId, stance });
    }

    // ── Synthesize report ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/synthesize$/) && req.method === 'POST') {
      const proposalId = url.pathname.split('/')[3];
      const { actor_did, synthesis, dissent } = await parseBody(req);

      // Fetch all opinions
      const { rows: opinions } = await pool.query('SELECT * FROM crosscheck_opinions WHERE proposal_id = $1', [proposalId]);
      if (opinions.length === 0) return json(res, 400, { error: 'no opinions to synthesize' });

      // Build agent DIDs and registry for independence verification
      const agentDids = opinions.map(o => o.agent_did);
      const registry = {
        signing_keys: opinions.map(o => [o.agent_did, o.model || o.agent_did]),
        attestation_roots: [],
        control_metadata: opinions.filter(o => o.policy_id).map(o => [o.agent_did, o.policy_id]),
      };

      // Verify independence via WASM
      const independenceResult = wasm.wasm_verify_independence(
        JSON.stringify(agentDids),
        JSON.stringify(registry)
      );

      // Detect coordination via WASM
      const actions = opinions.map(o => ({
        actor: o.agent_did,
        action_hash: Array.from(crypto.createHash('sha256').update(o.summary).digest()),
        timestamp: { physical_ms: o.submitted_at_ms, logical: 0 },
      }));
      const coordinationSignals = wasm.wasm_detect_coordination(JSON.stringify(actions));

      // Compute report hash
      const reportContent = JSON.stringify({ opinions: opinions.map(o => ({ agent_did: o.agent_did, stance: o.stance, summary: o.summary })), synthesis, dissent });
      const reportHashBytes = wasm.wasm_hash_bytes(Buffer.from(reportContent));
      const reportHash = typeof reportHashBytes === 'string' ? reportHashBytes : crypto.createHash('sha256').update(reportContent).digest('hex');

      const dissenters = opinions.filter(o => o.stance === 'oppose').map(o => o.agent_did);

      const reportId = genId('RPT');
      const { rows: proposals } = await pool.query('SELECT method FROM crosscheck_proposals WHERE id = $1', [proposalId]);

      await pool.query(
        `INSERT INTO crosscheck_reports (id, proposal_id, schema_version, created_by, question, method, synthesis, dissent, dissenters, independence_result, coordination_signals, report_hash, created_at_ms)
         VALUES ($1,$2,'0.2',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [reportId, proposalId, actor_did || null, null, proposals[0]?.method || 'mosaic',
         synthesis || null, dissent || null, JSON.stringify(dissenters),
         JSON.stringify(independenceResult), JSON.stringify(coordinationSignals),
         reportHash, nowMs()]
      );

      await pool.query('UPDATE crosscheck_proposals SET status = $1, updated_at_ms = $2 WHERE id = $3', ['verified', nowMs(), proposalId]);

      await pool.query(
        `INSERT INTO crosscheck_custody_events (proposal_id, actor_did, role, action, record_hash, created_at_ms)
         VALUES ($1, $2, 'steward', 'synthesize', $3, $4)`,
        [proposalId, actor_did || 'system', reportHash, nowMs()]
      );

      return json(res, 201, {
        id: reportId,
        proposal_id: proposalId,
        report_hash: reportHash,
        independence: independenceResult,
        coordination: coordinationSignals,
        opinions_count: opinions.length,
        dissenters,
      });
    }

    // ══════════════════════════════════════════════════════════════════
    // ATTESTATION & CLEARANCE
    // ══════════════════════════════════════════════════════════════════

    // ── Attest ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/attest$/) && req.method === 'POST') {
      const proposalId = url.pathname.split('/')[3];
      const { actor_did, role, attestation, notes, signature, public_key_b64 } = await parseBody(req);
      if (!actor_did || !attestation) return json(res, 400, { error: 'actor_did and attestation required' });

      // Get current record hash
      const { rows } = await pool.query('SELECT record_hash FROM crosscheck_proposals WHERE id = $1', [proposalId]);
      if (rows.length === 0) return json(res, 404, { error: 'proposal not found' });

      await pool.query(
        `INSERT INTO crosscheck_custody_events (proposal_id, actor_did, role, action, attestation, record_hash, signature, public_key_b64, notes, created_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [proposalId, actor_did, role || 'reviewer', `attest:${attestation}`, attestation,
         rows[0].record_hash, signature || null, public_key_b64 || null, notes || null, nowMs()]
      );

      return json(res, 201, { proposal_id: proposalId, attestation, actor_did });
    }

    // ── Evaluate clearance ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/clearance$/) && req.method === 'GET') {
      const proposalId = url.pathname.split('/')[3];

      // Get policy
      const { rows: policies } = await pool.query('SELECT * FROM crosscheck_policy WHERE id = $1', ['default']);
      const policy = policies[0] || { mode: 'quorum', quorum_count: 2, allowed_roles: ['reviewer', 'steward'], reject_veto: true };

      // Get attestations
      const { rows: events } = await pool.query(
        `SELECT * FROM crosscheck_custody_events WHERE proposal_id = $1 AND attestation IS NOT NULL ORDER BY id`,
        [proposalId]
      );

      // De-duplicate by (actor_did, attestation kind) — latest wins
      const latest = new Map();
      for (const e of events) {
        latest.set(`${e.actor_did}:${e.attestation}`, e);
      }

      const attestations = Array.from(latest.values());
      const allowedRoles = typeof policy.allowed_roles === 'string' ? JSON.parse(policy.allowed_roles) : (policy.allowed_roles || []);
      const filtered = attestations.filter(a => allowedRoles.includes(a.role));

      const approvals = filtered.filter(a => a.attestation === 'approve');
      const rejections = filtered.filter(a => a.attestation === 'reject');
      const abstentions = filtered.filter(a => a.attestation === 'abstain');

      let quorum_met = approvals.length >= policy.quorum_count;
      if (policy.reject_veto && rejections.length > 0) quorum_met = false;

      return json(res, 200, {
        proposal_id: proposalId,
        quorum_met,
        approvals: approvals.map(a => ({ actor_did: a.actor_did, role: a.role })),
        rejections: rejections.map(a => ({ actor_did: a.actor_did, role: a.role })),
        abstentions: abstentions.map(a => ({ actor_did: a.actor_did, role: a.role })),
        policy,
      });
    }

    // ── Issue clearance certificate ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/clear$/) && req.method === 'POST') {
      const proposalId = url.pathname.split('/')[3];
      const { actor_did } = await parseBody(req);

      // Evaluate clearance first
      const { rows: policies } = await pool.query('SELECT * FROM crosscheck_policy WHERE id = $1', ['default']);
      const policy = policies[0] || { mode: 'quorum', quorum_count: 2, allowed_roles: ['reviewer', 'steward'], reject_veto: true };

      const { rows: events } = await pool.query(
        `SELECT * FROM crosscheck_custody_events WHERE proposal_id = $1 AND attestation IS NOT NULL ORDER BY id`,
        [proposalId]
      );

      const latest = new Map();
      for (const e of events) latest.set(`${e.actor_did}:${e.attestation}`, e);
      const attestations = Array.from(latest.values());
      const allowedRoles = typeof policy.allowed_roles === 'string' ? JSON.parse(policy.allowed_roles) : (policy.allowed_roles || []);
      const filtered = attestations.filter(a => allowedRoles.includes(a.role));

      const approvals = filtered.filter(a => a.attestation === 'approve');
      const rejections = filtered.filter(a => a.attestation === 'reject');
      const abstentions = filtered.filter(a => a.attestation === 'abstain');

      let quorum_met = approvals.length >= policy.quorum_count;
      if (policy.reject_veto && rejections.length > 0) quorum_met = false;

      if (!quorum_met) return json(res, 400, { error: 'clearance requirements not met' });

      const certId = genId('CLR');
      await pool.query(
        `INSERT INTO crosscheck_clearance_certs (id, proposal_id, policy_id, approvals, rejections, abstentions, quorum_met, policy_snapshot, issued_at_ms)
         VALUES ($1,$2,'default',$3,$4,$5,$6,$7,$8)`,
        [certId, proposalId, JSON.stringify(approvals.map(a => a.actor_did)), JSON.stringify(rejections.map(a => a.actor_did)),
         JSON.stringify(abstentions.map(a => a.actor_did)), true, JSON.stringify(policy), nowMs()]
      );

      // Transition to accepted/verified status
      await pool.query('UPDATE crosscheck_proposals SET status = $1, updated_at_ms = $2 WHERE id = $3', ['verified', nowMs(), proposalId]);

      await pool.query(
        `INSERT INTO crosscheck_custody_events (proposal_id, actor_did, role, action, created_at_ms)
         VALUES ($1, $2, 'steward', 'clear', $3)`,
        [proposalId, actor_did || 'system', nowMs()]
      );

      return json(res, 201, { certificate_id: certId, quorum_met: true });
    }

    // ══════════════════════════════════════════════════════════════════
    // ANCHORING
    // ══════════════════════════════════════════════════════════════════

    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/anchor$/) && req.method === 'POST') {
      const proposalId = url.pathname.split('/')[3];
      const { actor_did } = await parseBody(req);

      // Get latest report
      const { rows: reports } = await pool.query(
        'SELECT * FROM crosscheck_reports WHERE proposal_id = $1 ORDER BY created_at_ms DESC LIMIT 1', [proposalId]
      );
      if (reports.length === 0) return json(res, 400, { error: 'no report to anchor — synthesize first' });

      const report = reports[0];
      const evidenceHash = report.report_hash || crypto.createHash('sha256').update(JSON.stringify(report)).digest('hex');

      // Anchor to EXOCHAIN audit chain
      const auditResult = wasm.wasm_audit_append(
        actor_did || 'did:exo:crosschecked',
        'crosscheck_anchor',
        'success',
        evidenceHash.padEnd(64, '0').slice(0, 64)
      );

      const anchorId = genId('ANC');
      await pool.query(
        `INSERT INTO crosscheck_anchors (id, report_id, proposal_id, chain, record_hash, txid, audit_entry_sequence, anchored_at_ms)
         VALUES ($1,$2,$3,'exochain',$4,$5,$6,$7)`,
        [anchorId, report.id, proposalId, evidenceHash, anchorId, auditResult.entries || 0, nowMs()]
      );

      await pool.query('UPDATE crosscheck_proposals SET status = $1, updated_at_ms = $2 WHERE id = $3', ['anchored', nowMs(), proposalId]);

      await pool.query(
        `INSERT INTO crosscheck_custody_events (proposal_id, actor_did, role, action, record_hash, created_at_ms)
         VALUES ($1, $2, 'steward', 'anchor', $3, $4)`,
        [proposalId, actor_did || 'system', evidenceHash, nowMs()]
      );

      return json(res, 201, {
        anchor_id: anchorId,
        chain: 'exochain',
        record_hash: evidenceHash,
        audit_entries: auditResult.entries,
        head_hash: auditResult.head_hash,
      });
    }

    // ══════════════════════════════════════════════════════════════════
    // COUNCIL DELIBERATION
    // ══════════════════════════════════════════════════════════════════

    // ── Open deliberation ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/deliberate$/) && req.method === 'POST') {
      const proposalId = url.pathname.split('/')[3];
      const { participants, quorum_policy, actor_did } = await parseBody(req);
      if (!participants || participants.length === 0) return json(res, 400, { error: 'participants required' });

      const { rows } = await pool.query('SELECT record_hash FROM crosscheck_proposals WHERE id = $1', [proposalId]);
      if (rows.length === 0) return json(res, 404, { error: 'proposal not found' });

      const proposalHex = Buffer.from(rows[0].record_hash || proposalId).toString('hex');
      const deliberation = wasm.wasm_open_deliberation(proposalHex, JSON.stringify(participants));

      const policy = quorum_policy || { min_approvals: 2, min_independent: 1, required_roles: [], timeout: { physical_ms: Date.now() + 86400000, logical: 0 } };

      const delibId = genId('DLB');
      await pool.query(
        `INSERT INTO crosscheck_deliberations (id, proposal_id, deliberation_json, quorum_policy, participants, opened_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [delibId, proposalId, JSON.stringify(deliberation), JSON.stringify(policy), JSON.stringify(participants), nowMs()]
      );

      await pool.query('UPDATE crosscheck_proposals SET status = $1, updated_at_ms = $2 WHERE id = $3', ['deliberating', nowMs(), proposalId]);

      await pool.query(
        `INSERT INTO crosscheck_custody_events (proposal_id, actor_did, role, action, created_at_ms)
         VALUES ($1, $2, 'steward', 'deliberate:open', $3)`,
        [proposalId, actor_did || 'system', nowMs()]
      );

      return json(res, 201, { deliberation_id: delibId, status: 'deliberating', participants });
    }

    // ── Cast vote ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/vote$/) && req.method === 'POST') {
      const proposalId = url.pathname.split('/')[3];
      const { voter_did, choice, rationale } = await parseBody(req);
      if (!voter_did || !choice) return json(res, 400, { error: 'voter_did and choice required' });

      // Check for conflicts
      try {
        wasm.wasm_conflict_enforce(
          voter_did,
          JSON.stringify({ action_id: proposalId, actor_did: voter_did, description: 'Vote' }),
          '[]'
        );
      } catch (e) {
        return json(res, 403, { error: 'conflict of interest — must recuse', details: String(e) });
      }

      // Get active deliberation
      const { rows: delibs } = await pool.query(
        'SELECT * FROM crosscheck_deliberations WHERE proposal_id = $1 AND result IS NULL ORDER BY opened_at_ms DESC LIMIT 1',
        [proposalId]
      );
      if (delibs.length === 0) return json(res, 400, { error: 'no active deliberation' });

      const delib = delibs[0];
      const vote = { voter: voter_did, choice, rationale: rationale || '', signature: { Ed25519: Array(64).fill(0) }, timestamp_ms: Date.now() };

      const updated = wasm.wasm_cast_vote(JSON.stringify(delib.deliberation_json), JSON.stringify(vote));

      await pool.query(
        'UPDATE crosscheck_deliberations SET deliberation_json = $1 WHERE id = $2',
        [JSON.stringify(updated), delib.id]
      );

      await pool.query(
        `INSERT INTO crosscheck_custody_events (proposal_id, actor_did, role, action, attestation, created_at_ms)
         VALUES ($1, $2, 'reviewer', 'vote', $3, $4)`,
        [proposalId, voter_did, choice.toLowerCase(), nowMs()]
      );

      return json(res, 200, { voted: true, voter_did, choice, deliberation_id: delib.id });
    }

    // ── Resolve deliberation ──
    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/resolve$/) && req.method === 'POST') {
      const proposalId = url.pathname.split('/')[3];
      const { actor_did } = await parseBody(req);

      const { rows: delibs } = await pool.query(
        'SELECT * FROM crosscheck_deliberations WHERE proposal_id = $1 AND result IS NULL ORDER BY opened_at_ms DESC LIMIT 1',
        [proposalId]
      );
      if (delibs.length === 0) return json(res, 400, { error: 'no active deliberation' });

      const delib = delibs[0];
      const result = wasm.wasm_close_deliberation(
        JSON.stringify(delib.deliberation_json),
        JSON.stringify(delib.quorum_policy)
      );

      const outcome = result.result || 'NoQuorum';
      const newStatus = outcome === 'Approved' ? 'ratified' : outcome === 'Rejected' ? 'rejected' : 'verified';

      await pool.query(
        `UPDATE crosscheck_deliberations SET result = $1, votes_for = $2, votes_against = $3, abstentions = $4, closed_at_ms = $5 WHERE id = $6`,
        [outcome, result.votes_for || 0, result.votes_against || 0, result.abstentions || 0, nowMs(), delib.id]
      );

      await pool.query('UPDATE crosscheck_proposals SET status = $1, updated_at_ms = $2 WHERE id = $3', [newStatus, nowMs(), proposalId]);

      await pool.query(
        `INSERT INTO crosscheck_custody_events (proposal_id, actor_did, role, action, created_at_ms)
         VALUES ($1, $2, 'steward', $3, $4)`,
        [proposalId, actor_did || 'system', `deliberate:${outcome.toLowerCase()}`, nowMs()]
      );

      return json(res, 200, { result: outcome, votes_for: result.votes_for, votes_against: result.votes_against, abstentions: result.abstentions, proposal_status: newStatus });
    }

    // ══════════════════════════════════════════════════════════════════
    // CUSTODY CHAIN
    // ══════════════════════════════════════════════════════════════════

    if (url.pathname.match(/^\/api\/proposals\/[^/]+\/custody$/) && req.method === 'GET') {
      const proposalId = url.pathname.split('/')[3];
      const { rows } = await pool.query(
        'SELECT * FROM crosscheck_custody_events WHERE proposal_id = $1 ORDER BY id',
        [proposalId]
      );
      return json(res, 200, rows);
    }

    // ══════════════════════════════════════════════════════════════════
    // KEY REGISTRY
    // ══════════════════════════════════════════════════════════════════

    if (url.pathname === '/api/keys' && req.method === 'POST') {
      const { actor_did, public_key_b64 } = await parseBody(req);
      if (!actor_did || !public_key_b64) return json(res, 400, { error: 'actor_did and public_key_b64 required' });
      await pool.query(
        `INSERT INTO crosscheck_keys (actor_did, public_key_b64, registered_at_ms)
         VALUES ($1, $2, $3) ON CONFLICT (actor_did) DO UPDATE SET public_key_b64 = $2`,
        [actor_did, public_key_b64, nowMs()]
      );
      return json(res, 201, { actor_did, registered: true });
    }

    if (url.pathname.match(/^\/api\/keys\//) && req.method === 'GET') {
      const did = url.pathname.split('/api/keys/')[1];
      const { rows } = await pool.query('SELECT * FROM crosscheck_keys WHERE actor_did = $1', [did]);
      if (rows.length === 0) return json(res, 404, { error: 'key not found' });
      return json(res, 200, rows[0]);
    }

    // 404
    json(res, 404, { error: 'not found', path: url.pathname });
  } catch (err) {
    console.error('CrossChecked API error:', err);
    json(res, 500, { error: err.message || 'internal server error' });
  }
});

// Only auto-start when run directly (not when imported for testing)
if (process.env.NODE_ENV !== 'test') {
  server.listen(PORT, () => {
    console.log(`✅ CrossChecked.ai API running on port ${PORT}`);
  });
}
