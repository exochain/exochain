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

const mockWasm = vi.hoisted(() => ({
  wasm_compute_quorum: vi.fn(() => ({ met: true, approval_count: 3, required: 3 })),
  wasm_check_clearance: vi.fn(() => ({ status: 'Granted', level: 'Governor' })),
  wasm_check_conflicts: vi.fn(() => ({ must_recuse: false, conflicts: [] })),
  wasm_file_governance_challenge: vi.fn((challenger, target, ground) => ({ challenger_did: challenger, target_hash: target, ground: JSON.parse(ground), challenge_id: 'ch-001' })),
  wasm_build_authority_chain: vi.fn((linksJson) => ({ links: JSON.parse(linksJson), valid: true, depth: JSON.parse(linksJson).length })),
}));

vi.mock('module', async (importOriginal) => {
  const orig = await importOriginal();
  return { ...orig, createRequire: () => (id) => { if (id === '@exochain/exochain-wasm') return mockWasm; throw new Error(`Unexpected require('${id}') in test`); } };
});

vi.mock('pg', () => { const q = vi.fn(); const P = vi.fn(() => ({ query: q })); return { default: { Pool: P } }; });

import { server } from './index.js';
import pg from 'pg';

let request;
beforeAll(async () => { await new Promise((r) => server.listen(0, r)); request = supertest(server); });
beforeEach(() => { vi.clearAllMocks(); });
afterAll(async () => { await new Promise((r) => server.close(r)); });

describe('GET /health', () => {
  it('returns 200', async () => { const res = await request.get('/health'); expect(res.status).toBe(200); expect(res.body.service).toBe('governance-engine'); });
});

describe('POST /api/quorum/compute', () => {
  it('returns quorum result', async () => {
    const res = await request.post('/api/quorum/compute').send({ approvals: ['did:exo:alice', 'did:exo:bob', 'did:exo:carol'], policy: { required: 3, type: 'Absolute' } });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('met', true);
    expect(res.body.approval_count).toBe(3);
  });
});

describe('POST /api/clearance/check', () => {
  it('returns Granted for authorized actor', async () => {
    const res = await request.post('/api/clearance/check').send({ actor_did: 'did:exo:alice', action: 'Vote', policy: { actions: { Vote: { required_level: 'Governor' } } } });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('Granted');
  });

  it('returns Denied when clearance insufficient', async () => {
    mockWasm.wasm_check_clearance.mockReturnValueOnce({ status: 'Denied', reason: 'Insufficient level' });
    const res = await request.post('/api/clearance/check').send({ actor_did: 'did:exo:newbie', action: 'Enact', policy: {} });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('Denied');
  });
});

describe('POST /api/conflicts/check', () => {
  it('returns no conflict for clean actor', async () => {
    const res = await request.post('/api/conflicts/check').send({ actor_did: 'did:exo:alice', action: { action_id: 'dec-001', actor_did: 'did:exo:alice', description: 'Vote' }, declarations: [] });
    expect(res.status).toBe(200);
    expect(res.body.must_recuse).toBe(false);
  });

  it('returns must_recuse=true on conflict', async () => {
    mockWasm.wasm_check_conflicts.mockReturnValueOnce({ must_recuse: true, conflicts: ['self-interest'] });
    const res = await request.post('/api/conflicts/check').send({ actor_did: 'did:exo:bob', action: { action_id: 'dec-001' }, declarations: [{ type: 'financial' }] });
    expect(res.status).toBe(200);
    expect(res.body.must_recuse).toBe(true);
  });
});

describe('POST /api/challenge', () => {
  it('files a governance challenge', async () => {
    const res = await request.post('/api/challenge').send({ challenger_did: 'did:exo:carol', target_hash: 'a'.repeat(64), ground: 'ConstitutionalViolation', evidence: 'proof' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('challenge_id', 'ch-001');
    expect(res.body.challenger_did).toBe('did:exo:carol');
  });
});

describe('POST /api/authority/build', () => {
  it('builds authority chain from links', async () => {
    const res = await request.post('/api/authority/build').send({ links: [{ delegator: 'did:exo:root', delegatee: 'did:exo:alice' }, { delegator: 'did:exo:alice', delegatee: 'did:exo:bob' }] });
    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
    expect(res.body.depth).toBe(2);
  });
});

describe('POST /api/evaluate', () => {
  it('evaluates decision with actor', async () => {
    const pool = new pg.Pool();
    pool.query
      .mockResolvedValueOnce({ rows: [{ id_hash: 'dec-001', title: 'Test', status: 'Voting', decision_class: 'Operational' }] })
      .mockResolvedValueOnce({ rows: [{ did: 'did:exo:alice', display_name: 'Alice', roles: ['Governor'], pace_status: 'Enrolled' }] })
      .mockResolvedValueOnce({ rows: [] });
    const res = await request.post('/api/evaluate').send({ decision_id: 'dec-001', actor_did: 'did:exo:alice' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('evaluation', 'APPROVED');
  });

  it('returns 404 when decision not found', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [] });
    const res = await request.post('/api/evaluate').send({ decision_id: 'missing', actor_did: 'did:exo:alice' });
    expect(res.status).toBe(404);
  });
});

describe('OPTIONS preflight', () => {
  it('returns 204', async () => { expect((await request.options('/api/quorum/compute')).status).toBe(204); });
});
