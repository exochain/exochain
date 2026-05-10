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
  wasm_propose_bailment: vi.fn((bailor, bailee, _terms, typeJson) => ({ id: 'bail-001', bailor_did: bailor, bailee_did: bailee, bailment_type: JSON.parse(typeJson), status: 'Proposed', terms_hash: 'a'.repeat(64) })),
  wasm_bailment_is_active: vi.fn(() => true),
}));

vi.mock('module', async (importOriginal) => {
  const orig = await importOriginal();
  return { ...orig, createRequire: () => (id) => { if (id === '@exochain/exochain-wasm') return mockWasm; throw new Error(`Unexpected require('${id}') in test`); } };
});

vi.mock('pg', () => { const q = vi.fn(); const P = vi.fn(() => ({ query: q })); return { default: { Pool: P } }; });

import { server } from './index.js';
import pg from 'pg';

let request;
beforeAll(async () => {
  await new Promise((r) => server.listen(0, r));
  request = supertest(server);
});

beforeEach(() => {
  vi.clearAllMocks();
  const pool = new pg.Pool();
  pool.query.mockResolvedValue({ rows: [] });
});
afterAll(async () => { await new Promise((r) => server.close(r)); });

describe('GET /health', () => {
  it('returns 200', async () => { const res = await request.get('/health'); expect(res.status).toBe(200); expect(res.body.service).toBe('consent-service'); });
});

describe('GET /api/anchors', () => {
  it('returns consent anchor list', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [{ id: 'anc-001', bailor_did: 'did:exo:alice' }] });
    const res = await request.get('/api/anchors');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('returns empty array when no anchors', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [] });
    const res = await request.get('/api/anchors');
    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });
});

describe('POST /api/bailment/propose', () => {
  it('creates bailment record', async () => {
    const res = await request.post('/api/bailment/propose').send({ bailor_did: 'did:exo:alice', bailee_did: 'did:exo:custodian', terms: 'no redistribution', bailment_type: 'Processing' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('id', 'bail-001');
    expect(res.body.bailor_did).toBe('did:exo:alice');
    expect(res.body.bailment_type).toBe('Processing');
  });

  it('defaults bailment_type to Processing', async () => {
    const res = await request.post('/api/bailment/propose').send({ bailor_did: 'did:exo:bob', bailee_did: 'did:exo:custodian' });
    expect(res.status).toBe(200);
    expect(res.body.bailment_type).toBe('Processing');
  });
});

describe('POST /api/bailment/active', () => {
  it('returns active status', async () => {
    const res = await request.post('/api/bailment/active').send({ bailment: { id: 'bail-001', status: 'Proposed' } });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('active', true);
  });

  it('returns false when revoked', async () => {
    mockWasm.wasm_bailment_is_active.mockReturnValueOnce(false);
    const res = await request.post('/api/bailment/active').send({ bailment: { id: 'bail-002', status: 'Revoked' } });
    expect(res.status).toBe(200);
    expect(res.body.active).toBe(false);
  });
});

describe('OPTIONS / 404', () => {
  it('OPTIONS returns 204', async () => { expect((await request.options('/api/anchors')).status).toBe(204); });
  it('unknown returns 404', async () => { expect((await request.get('/api/nonexistent')).status).toBe(404); });
});
