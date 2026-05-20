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

import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest';
import supertest from 'supertest';

// ── WASM Mocks ──
const mockWasm = vi.hoisted(() => ({
  wasm_verify_independence: vi.fn(() => ({ independent_count: 3, clusters: [], suspicious_pairs: [] })),
  wasm_detect_coordination: vi.fn(() => []),
  wasm_hash_bytes: vi.fn(() => 'a'.repeat(64)),
  wasm_audit_append: vi.fn(() => ({ entries: 1, head_hash: 'b'.repeat(64) })),
  wasm_audit_verify: vi.fn(() => ({ valid: true })),
  wasm_compute_quorum: vi.fn(() => ({ status: 'Met', independent_count: 3, total_count: 3 })),
  wasm_open_deliberation: vi.fn(() => ({ id: 'delib-001', status: 'Open', votes: [], proposal_hash: 'c'.repeat(64) })),
  wasm_cast_vote: vi.fn((dJson, vJson) => ({ ...JSON.parse(dJson), votes: [...(JSON.parse(dJson).votes || []), JSON.parse(vJson)] })),
  wasm_close_deliberation: vi.fn(() => ({ result: 'Approved', votes_for: 3, votes_against: 0, abstentions: 0 })),
  wasm_conflict_enforce: vi.fn(() => ({ allowed: true })),
  wasm_check_clearance: vi.fn(() => ({ status: 'Granted' })),
  wasm_check_conflicts: vi.fn(() => ({ must_recuse: false, conflicts: [] })),
}));

vi.hoisted(() => {
  process.env.CROSSCHECKED_API_TOKENS = JSON.stringify({
    'reviewer-token': { actor_did: 'did:exo:reviewer1', role: 'reviewer' },
    'steward-token': { actor_did: 'did:exo:steward1', role: 'steward' },
  });
});

vi.mock('module', async (importOriginal) => {
  const orig = await importOriginal();
  return { ...orig, createRequire: () => (id) => { if (id === '@exochain/exochain-wasm') return mockWasm; throw new Error(`Unexpected require('${id}')`); } };
});

// ── DB Mocks ──
const mockQuery = vi.hoisted(() => vi.fn());
vi.mock('pg', () => { const P = vi.fn(() => ({ query: mockQuery })); return { default: { Pool: P } }; });

import { server } from './index.js';

let request;
beforeAll(async () => { await new Promise(r => server.listen(0, r)); request = supertest(server); });
beforeEach(() => { vi.clearAllMocks(); });
afterAll(async () => { await new Promise(r => server.close(r)); });

function withAuth(req, token = 'reviewer-token') {
  return req.set('Authorization', `Bearer ${token}`);
}

function authenticatedEvent(actor_did, role, attestation) {
  return {
    actor_did,
    role,
    attestation,
    metadata: {
      authenticated: true,
      auth_actor_did: actor_did,
      auth_role: role,
      auth_method: 'bearer-token-principal',
    },
  };
}

// ══════════════════════════════════════════════════════════════════
// HEALTH
// ══════════════════════════════════════════════════════════════════

describe('GET /health', () => {
  it('returns 200 with service name', async () => {
    const res = await request.get('/health');
    expect(res.status).toBe(200);
    expect(res.body.service).toBe('crosschecked-api');
  });
});

// ══════════════════════════════════════════════════════════════════
// PROPOSAL LIFECYCLE
// ══════════════════════════════════════════════════════════════════

describe('POST /api/proposals', () => {
  it('creates a proposal with custody event', async () => {
    mockQuery.mockResolvedValue({ rows: [] });
    const res = await withAuth(request.post('/api/proposals')).send({
      author_did: 'did:exo:alice', title: 'Test Proposal', context: 'Should we adopt X?',
    });
    expect(res.status).toBe(201);
    expect(res.body.id).toMatch(/^CR-/);
    expect(res.body.status).toBe('draft');
    expect(res.body.record_hash).toBeTruthy();
    expect(mockQuery).toHaveBeenCalledTimes(2); // proposal + custody
  });

  it('returns 400 when missing required fields', async () => {
    const res = await withAuth(request.post('/api/proposals')).send({ title: 'No context' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('required');
  });

  it('rejects unauthenticated API access before database access', async () => {
    const res = await request.post('/api/proposals').send({
      author_did: 'did:exo:attacker', title: 'Test Proposal', context: 'Should we adopt X?',
    });
    expect(res.status).toBe(401);
    expect(mockQuery).not.toHaveBeenCalled();
  });
});

describe('GET /api/proposals', () => {
  it('lists proposals', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 'CR-001', title: 'Test', status: 'draft' }] });
    const res = await withAuth(request.get('/api/proposals'));
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
  });

  it('filters by status', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await withAuth(request.get('/api/proposals?status=ratified'));
    expect(res.status).toBe(200);
    expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining('WHERE status'), ['ratified']);
  });
});

describe('GET /api/proposals/:id', () => {
  it('returns full proposal with relations', async () => {
    const resolves = [
      { rows: [{ id: 'CR-001', title: 'Test', status: 'draft' }] }, // proposal
      { rows: [] }, { rows: [] }, { rows: [] }, { rows: [] }, { rows: [] }, { rows: [] }, { rows: [] }, // relations
    ];
    resolves.forEach(r => mockQuery.mockResolvedValueOnce(r));
    const res = await withAuth(request.get('/api/proposals/CR-001'));
    expect(res.status).toBe(200);
    expect(res.body.id).toBe('CR-001');
    expect(res.body).toHaveProperty('opinions');
    expect(res.body).toHaveProperty('reports');
    expect(res.body).toHaveProperty('custody');
  });

  it('returns 404 for missing proposal', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await withAuth(request.get('/api/proposals/CR-missing'));
    expect(res.status).toBe(404);
  });
});

describe('PUT /api/proposals/:id/status', () => {
  it('transitions status with custody event', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 'CR-001', status: 'submitted' }] })
             .mockResolvedValueOnce({ rows: [] });
    const res = await withAuth(request.put('/api/proposals/CR-001/status'), 'steward-token').send({ status: 'crosschecking', actor_did: 'did:exo:alice' });
    expect(res.status).toBe(200);
  });

  it('returns 400 without required fields', async () => {
    const res = await withAuth(request.put('/api/proposals/CR-001/status'), 'steward-token').send({});
    expect(res.status).toBe(400);
  });
});

describe('GET /api/proposals/:id/hash', () => {
  it('computes canonical hash', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ title: 'Test', context: 'Context', decision: 'Decision' }] });
    const res = await withAuth(request.get('/api/proposals/CR-001/hash'));
    expect(res.status).toBe(200);
    expect(res.body.hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('returns 404 for missing proposal', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await withAuth(request.get('/api/proposals/CR-missing/hash'));
    expect(res.status).toBe(404);
  });
});

// ══════════════════════════════════════════════════════════════════
// EVIDENCE
// ══════════════════════════════════════════════════════════════════

describe('POST /api/proposals/:id/evidence', () => {
  it('adds evidence and recomputes hash', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] }) // insert
             .mockResolvedValueOnce({ rows: [{ title: 'T', context: 'C' }] }) // select for rehash
             .mockResolvedValueOnce({ rows: [] }); // update hash
    const res = await withAuth(request.post('/api/proposals/CR-001/evidence')).send({ description: 'Test doc', kind: 'doc', uri: 'https://example.com' });
    expect(res.status).toBe(201);
    expect(res.body.id).toMatch(/^EV-/);
  });

  it('returns 400 without description', async () => {
    const res = await withAuth(request.post('/api/proposals/CR-001/evidence')).send({});
    expect(res.status).toBe(400);
  });
});

describe('GET /api/proposals/:id/evidence', () => {
  it('lists evidence', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 'EV-001', kind: 'link' }] });
    const res = await withAuth(request.get('/api/proposals/CR-001/evidence'));
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
  });
});

// ══════════════════════════════════════════════════════════════════
// CROSSCHECK / 5-PANEL COUNCIL
// ══════════════════════════════════════════════════════════════════

describe('GET /api/proposals/:id/crosscheck/template', () => {
  it('generates template for standard crosscheck', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 'CR-001', title: 'Test', method: 'mosaic', full_5x5: false }] });
    const res = await withAuth(request.get('/api/proposals/CR-001/crosscheck/template'));
    expect(res.status).toBe(200);
    expect(res.body.opinions_needed).toBe(5); // 5 panels × 1 null property
    expect(res.body.template_opinions).toHaveLength(5);
  });

  it('generates 5x5 template with 25 opinions', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 'CR-001', title: 'Test', method: 'mosaic', full_5x5: true }] });
    const res = await withAuth(request.get('/api/proposals/CR-001/crosscheck/template'));
    expect(res.status).toBe(200);
    expect(res.body.opinions_needed).toBe(25); // 5 panels × 5 properties
    expect(res.body.template_opinions).toHaveLength(25);
    expect(res.body.full_5x5).toBe(true);
  });
});

describe('POST /api/proposals/:id/crosscheck', () => {
  it('sets status to crosschecking', async () => {
    mockQuery.mockResolvedValue({ rows: [] });
    const res = await withAuth(request.post('/api/proposals/CR-001/crosscheck'), 'steward-token').send({ actor_did: 'did:exo:alice' });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('crosschecking');
  });
});

describe('POST /api/proposals/:id/opinions', () => {
  it('submits opinion with panel tag', async () => {
    mockQuery.mockResolvedValue({ rows: [] });
    const res = await withAuth(request.post('/api/proposals/CR-001/opinions')).send({
      agent_did: 'did:exo:agent-gov', agent_kind: 'ai', agent_label: 'Governance Panel',
      stance: 'support', summary: 'Constitutional alignment confirmed',
      panel: 'Governance', confidence: 0.85, risks: ['delegation ambiguity'],
    });
    expect(res.status).toBe(201);
    expect(res.body.stance).toBe('support');
  });

  it('returns 400 without required fields', async () => {
    const res = await withAuth(request.post('/api/proposals/CR-001/opinions')).send({ stance: 'support' });
    expect(res.status).toBe(400);
  });
});

describe('POST /api/proposals/:id/synthesize', () => {
  it('synthesizes with independence + coordination checks', async () => {
    mockQuery
      .mockResolvedValueOnce({ rows: [ // opinions
        { agent_did: 'did:exo:a1', stance: 'support', summary: 'Good', model: 'gpt-4o', policy_id: null, submitted_at_ms: 1000 },
        { agent_did: 'did:exo:a2', stance: 'oppose', summary: 'Bad', model: 'claude-3', policy_id: null, submitted_at_ms: 2000 },
        { agent_did: 'did:exo:a3', stance: 'amend', summary: 'OK with changes', model: 'gemini', policy_id: null, submitted_at_ms: 3000 },
      ]})
      .mockResolvedValueOnce({ rows: [{ method: 'mosaic' }] }) // proposal method
      .mockResolvedValue({ rows: [] }); // inserts

    const res = await withAuth(request.post('/api/proposals/CR-001/synthesize'), 'steward-token').send({
      actor_did: 'did:exo:steward', synthesis: 'Consensus with amendments', dissent: 'Agent a2 opposes',
    });
    expect(res.status).toBe(201);
    expect(res.body.id).toMatch(/^RPT-/);
    expect(res.body.report_hash).toBeTruthy();
    expect(res.body.independence).toBeTruthy();
    expect(res.body.dissenters).toContain('did:exo:a2');
    expect(mockWasm.wasm_verify_independence).toHaveBeenCalled();
    expect(mockWasm.wasm_detect_coordination).toHaveBeenCalled();
  });

  it('returns 400 with no opinions', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await withAuth(request.post('/api/proposals/CR-001/synthesize'), 'steward-token').send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('no opinions');
  });

  it('detects Sybil clusters', async () => {
    mockWasm.wasm_verify_independence.mockReturnValueOnce({
      independent_count: 1, clusters: [{ reason: 'shared signing key', members: ['did:exo:a1', 'did:exo:a2'] }], suspicious_pairs: [],
    });
    mockQuery
      .mockResolvedValueOnce({ rows: [
        { agent_did: 'did:exo:a1', stance: 'support', summary: 'Yes', model: 'same-model', policy_id: null, submitted_at_ms: 1000 },
        { agent_did: 'did:exo:a2', stance: 'support', summary: 'Also yes', model: 'same-model', policy_id: null, submitted_at_ms: 1010 },
      ]})
      .mockResolvedValueOnce({ rows: [{ method: 'mosaic' }] })
      .mockResolvedValue({ rows: [] });

    const res = await withAuth(request.post('/api/proposals/CR-001/synthesize'), 'steward-token').send({ actor_did: 'did:exo:steward' });
    expect(res.status).toBe(201);
    expect(res.body.independence.independent_count).toBe(1);
    expect(res.body.independence.clusters).toHaveLength(1);
  });
});

// ══════════════════════════════════════════════════════════════════
// ATTESTATION & CLEARANCE
// ══════════════════════════════════════════════════════════════════

describe('POST /api/proposals/:id/attest', () => {
  it('rejects unauthenticated attestations before database access', async () => {
    mockQuery.mockResolvedValue({ rows: [{ record_hash: 'abc123' }] });
    const res = await request.post('/api/proposals/CR-001/attest').send({
      actor_did: 'did:exo:attacker',
      role: 'reviewer',
      attestation: 'approve',
    });

    expect(res.status).toBe(401);
    expect(mockQuery).not.toHaveBeenCalled();
  });

  it('binds attestations to the authenticated actor and role instead of body fields', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ record_hash: 'abc123' }] })
             .mockResolvedValueOnce({ rows: [] });

    const res = await withAuth(request.post('/api/proposals/CR-001/attest')).send({
      actor_did: 'did:exo:attacker',
      role: 'steward',
      attestation: 'approve',
      notes: 'LGTM',
    });

    expect(res.status).toBe(201);
    expect(res.body.actor_did).toBe('did:exo:reviewer1');
    expect(mockQuery.mock.calls[1][1][1]).toBe('did:exo:reviewer1');
    expect(mockQuery.mock.calls[1][1][2]).toBe('reviewer');
    expect(JSON.parse(mockQuery.mock.calls[1][1][8])).toMatchObject({
      authenticated: true,
      auth_actor_did: 'did:exo:reviewer1',
      auth_role: 'reviewer',
    });
  });

  it('records attestation with custody event', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ record_hash: 'abc123' }] }) // proposal hash
             .mockResolvedValueOnce({ rows: [] }); // insert custody
    const res = await withAuth(request.post('/api/proposals/CR-001/attest')).send({
      actor_did: 'did:exo:reviewer1', role: 'reviewer', attestation: 'approve', notes: 'LGTM',
    });
    expect(res.status).toBe(201);
    expect(res.body.attestation).toBe('approve');
  });

  it('returns 400 without required fields', async () => {
    const res = await withAuth(request.post('/api/proposals/CR-001/attest')).send({});
    expect(res.status).toBe(400);
  });

  it('returns 404 for missing proposal', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await withAuth(request.post('/api/proposals/CR-missing/attest')).send({
      actor_did: 'did:exo:reviewer', attestation: 'approve',
    });
    expect(res.status).toBe(404);
  });
});

describe('GET /api/proposals/:id/clearance', () => {
  it('evaluates quorum met', async () => {
    mockQuery
      .mockResolvedValueOnce({ rows: [{ mode: 'quorum', quorum_count: 2, allowed_roles: '["reviewer","steward"]', reject_veto: true }] })
      .mockResolvedValueOnce({ rows: [
        authenticatedEvent('did:exo:r1', 'reviewer', 'approve'),
        authenticatedEvent('did:exo:r2', 'reviewer', 'approve'),
      ]});
    const res = await withAuth(request.get('/api/proposals/CR-001/clearance'));
    expect(res.status).toBe(200);
    expect(res.body.quorum_met).toBe(true);
    expect(res.body.approvals).toHaveLength(2);
  });

  it('rejects when veto present', async () => {
    mockQuery
      .mockResolvedValueOnce({ rows: [{ mode: 'quorum', quorum_count: 2, allowed_roles: '["reviewer","steward"]', reject_veto: true }] })
      .mockResolvedValueOnce({ rows: [
        authenticatedEvent('did:exo:r1', 'reviewer', 'approve'),
        authenticatedEvent('did:exo:r2', 'reviewer', 'approve'),
        authenticatedEvent('did:exo:r3', 'reviewer', 'reject'),
      ]});
    const res = await withAuth(request.get('/api/proposals/CR-001/clearance'));
    expect(res.status).toBe(200);
    expect(res.body.quorum_met).toBe(false);
    expect(res.body.rejections).toHaveLength(1);
  });
});

describe('POST /api/proposals/:id/clear', () => {
  it('does not issue clearance from unauthenticated legacy custody rows', async () => {
    mockQuery
      .mockResolvedValueOnce({ rows: [{ mode: 'quorum', quorum_count: 2, allowed_roles: '["reviewer","steward"]', reject_veto: true }] })
      .mockResolvedValueOnce({ rows: [
        { actor_did: 'did:exo:r1', role: 'reviewer', attestation: 'approve', metadata: {} },
        { actor_did: 'did:exo:r2', role: 'steward', attestation: 'approve', metadata: {} },
      ]});

    const res = await withAuth(request.post('/api/proposals/CR-001/clear'), 'steward-token')
      .send({ actor_did: 'did:exo:attacker' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('not met');
  });

  it('issues clearance certificate when quorum met', async () => {
    mockQuery
      .mockResolvedValueOnce({ rows: [{ mode: 'quorum', quorum_count: 2, allowed_roles: '["reviewer","steward"]', reject_veto: true }] })
      .mockResolvedValueOnce({ rows: [
        authenticatedEvent('did:exo:r1', 'reviewer', 'approve'),
        authenticatedEvent('did:exo:r2', 'steward', 'approve'),
      ]})
      .mockResolvedValue({ rows: [] }); // inserts
    const res = await withAuth(request.post('/api/proposals/CR-001/clear'), 'steward-token')
      .send({ actor_did: 'did:exo:attacker' });
    expect(res.status).toBe(201);
    expect(res.body.certificate_id).toMatch(/^CLR-/);
    expect(res.body.quorum_met).toBe(true);
  });

  it('returns 400 when clearance not met', async () => {
    mockQuery
      .mockResolvedValueOnce({ rows: [{ mode: 'quorum', quorum_count: 2, allowed_roles: '["reviewer","steward"]', reject_veto: true }] })
      .mockResolvedValueOnce({ rows: [
        { actor_did: 'did:exo:r1', role: 'reviewer', attestation: 'approve' },
      ]});
    const res = await withAuth(request.post('/api/proposals/CR-001/clear'), 'steward-token').send({ actor_did: 'did:exo:steward' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('not met');
  });
});

// ══════════════════════════════════════════════════════════════════
// ANCHORING
// ══════════════════════════════════════════════════════════════════

describe('POST /api/proposals/:id/anchor', () => {
  it('anchors report to EXOCHAIN audit chain', async () => {
    mockQuery
      .mockResolvedValueOnce({ rows: [{ id: 'RPT-001', report_hash: 'd'.repeat(64) }] }) // report
      .mockResolvedValue({ rows: [] }); // inserts
    const res = await withAuth(request.post('/api/proposals/CR-001/anchor'), 'steward-token').send({ actor_did: 'did:exo:steward' });
    expect(res.status).toBe(201);
    expect(res.body.anchor_id).toMatch(/^ANC-/);
    expect(res.body.chain).toBe('exochain');
    expect(mockWasm.wasm_audit_append).toHaveBeenCalledWith(
      'did:exo:steward1', 'crosscheck_anchor', 'success', expect.any(String)
    );
  });

  it('returns 400 without report', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await withAuth(request.post('/api/proposals/CR-001/anchor'), 'steward-token').send({ actor_did: 'did:exo:steward' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('synthesize first');
  });
});

// ══════════════════════════════════════════════════════════════════
// COUNCIL DELIBERATION
// ══════════════════════════════════════════════════════════════════

describe('POST /api/proposals/:id/deliberate', () => {
  it('opens deliberation via WASM', async () => {
    mockQuery
      .mockResolvedValueOnce({ rows: [{ record_hash: 'e'.repeat(64) }] }) // proposal
      .mockResolvedValue({ rows: [] }); // inserts
    const res = await withAuth(request.post('/api/proposals/CR-001/deliberate'), 'steward-token').send({
      participants: ['did:exo:alice', 'did:exo:bob', 'did:exo:carol'],
      actor_did: 'did:exo:steward',
    });
    expect(res.status).toBe(201);
    expect(res.body.deliberation_id).toMatch(/^DLB-/);
    expect(mockWasm.wasm_open_deliberation).toHaveBeenCalled();
  });

  it('returns 400 without participants', async () => {
    const res = await withAuth(request.post('/api/proposals/CR-001/deliberate'), 'steward-token').send({});
    expect(res.status).toBe(400);
  });
});

describe('POST /api/proposals/:id/vote', () => {
  it('casts votes as the authenticated actor instead of request body voter_did', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 'DLB-001', deliberation_json: { id: 'delib', votes: [] }, result: null }] })
             .mockResolvedValue({ rows: [] });

    const res = await withAuth(request.post('/api/proposals/CR-001/vote')).send({
      voter_did: 'did:exo:attacker',
      choice: 'Approve',
      rationale: 'Good proposal',
    });

    expect(res.status).toBe(200);
    expect(res.body.voter_did).toBe('did:exo:reviewer1');
    expect(mockWasm.wasm_conflict_enforce).toHaveBeenCalledWith(
      'did:exo:reviewer1',
      expect.any(String),
      '[]',
    );
    const vote = JSON.parse(mockWasm.wasm_cast_vote.mock.calls[0][1]);
    expect(vote.voter_did).toBe('did:exo:reviewer1');
    expect(vote.signature).toBe('Empty');
    expect(vote).not.toHaveProperty('voter');
  });

  it('casts vote with conflict check', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 'DLB-001', deliberation_json: { id: 'delib', votes: [] }, result: null }] })
             .mockResolvedValue({ rows: [] });
    const res = await withAuth(request.post('/api/proposals/CR-001/vote')).send({
      voter_did: 'did:exo:alice', choice: 'Approve', rationale: 'Good proposal',
    });
    expect(res.status).toBe(200);
    expect(res.body.voted).toBe(true);
    expect(mockWasm.wasm_conflict_enforce).toHaveBeenCalled();
    expect(mockWasm.wasm_cast_vote).toHaveBeenCalled();
  });

  it('blocks vote on conflict', async () => {
    mockWasm.wasm_conflict_enforce.mockImplementationOnce(() => { throw new Error('ConflictBlocked: financial interest'); });
    const res = await withAuth(request.post('/api/proposals/CR-001/vote')).send({
      voter_did: 'did:exo:conflicted', choice: 'Approve',
    });
    expect(res.status).toBe(403);
    expect(res.body.error).toContain('conflict');
  });

  it('returns 400 without required fields', async () => {
    const res = await withAuth(request.post('/api/proposals/CR-001/vote')).send({});
    expect(res.status).toBe(400);
  });

  it('returns 400 without active deliberation', async () => {
    mockWasm.wasm_conflict_enforce.mockReturnValueOnce({ allowed: true });
    mockQuery.mockResolvedValueOnce({ rows: [] }); // no active deliberation
    const res = await withAuth(request.post('/api/proposals/CR-001/vote')).send({ voter_did: 'did:exo:alice', choice: 'Approve' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('no active deliberation');
  });
});

describe('POST /api/proposals/:id/resolve', () => {
  it('resolves deliberation as Approved', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 'DLB-001', deliberation_json: { votes: [1,2,3] }, quorum_policy: {}, result: null }] })
             .mockResolvedValue({ rows: [] });
    const res = await withAuth(request.post('/api/proposals/CR-001/resolve'), 'steward-token').send({ actor_did: 'did:exo:steward' });
    expect(res.status).toBe(200);
    expect(res.body.result).toBe('Approved');
    expect(res.body.proposal_status).toBe('ratified');
  });

  it('resolves as Rejected', async () => {
    mockWasm.wasm_close_deliberation.mockReturnValueOnce({ result: 'Rejected', votes_for: 1, votes_against: 2, abstentions: 0 });
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 'DLB-001', deliberation_json: {}, quorum_policy: {}, result: null }] })
             .mockResolvedValue({ rows: [] });
    const res = await withAuth(request.post('/api/proposals/CR-001/resolve'), 'steward-token').send({});
    expect(res.status).toBe(200);
    expect(res.body.result).toBe('Rejected');
    expect(res.body.proposal_status).toBe('rejected');
  });

  it('handles NoQuorum', async () => {
    mockWasm.wasm_close_deliberation.mockReturnValueOnce({ result: 'NoQuorum', reason: 'Insufficient votes' });
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 'DLB-001', deliberation_json: {}, quorum_policy: {}, result: null }] })
             .mockResolvedValue({ rows: [] });
    const res = await withAuth(request.post('/api/proposals/CR-001/resolve'), 'steward-token').send({});
    expect(res.status).toBe(200);
    expect(res.body.result).toBe('NoQuorum');
    expect(res.body.proposal_status).toBe('verified');
  });

  it('returns 400 without active deliberation', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await withAuth(request.post('/api/proposals/CR-001/resolve'), 'steward-token').send({});
    expect(res.status).toBe(400);
  });
});

// ══════════════════════════════════════════════════════════════════
// CUSTODY & KEYS
// ══════════════════════════════════════════════════════════════════

describe('GET /api/proposals/:id/custody', () => {
  it('returns custody chain', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [
      { id: 1, action: 'create', actor_did: 'did:exo:alice', created_at_ms: 1000 },
      { id: 2, action: 'add_crosscheck', actor_did: 'did:exo:agent', created_at_ms: 2000 },
    ]});
    const res = await withAuth(request.get('/api/proposals/CR-001/custody'));
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);
    expect(res.body[0].action).toBe('create');
  });
});

describe('POST /api/keys', () => {
  it('registers a public key', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await withAuth(request.post('/api/keys')).send({ actor_did: 'did:exo:alice', public_key_b64: 'base64encodedkey==' });
    expect(res.status).toBe(201);
    expect(res.body.registered).toBe(true);
    expect(res.body.actor_did).toBe('did:exo:reviewer1');
  });

  it('returns 400 without required fields', async () => {
    const res = await withAuth(request.post('/api/keys')).send({});
    expect(res.status).toBe(400);
  });
});

describe('GET /api/keys/:did', () => {
  it('returns key for known actor', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ actor_did: 'did:exo:alice', public_key_b64: 'key==' }] });
    const res = await withAuth(request.get('/api/keys/did:exo:alice'));
    expect(res.status).toBe(200);
    expect(res.body.public_key_b64).toBe('key==');
  });

  it('returns 404 for unknown actor', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    const res = await withAuth(request.get('/api/keys/did:exo:unknown'));
    expect(res.status).toBe(404);
  });
});

// ══════════════════════════════════════════════════════════════════
// PREFLIGHT & ERROR HANDLING
// ══════════════════════════════════════════════════════════════════

describe('OPTIONS preflight', () => {
  it('returns 204', async () => {
    const res = await request.options('/api/proposals');
    expect(res.status).toBe(204);
  });
});

describe('404 handling', () => {
  it('returns 404 for unknown routes', async () => {
    const res = await withAuth(request.get('/api/nonexistent'));
    expect(res.status).toBe(404);
  });
});
