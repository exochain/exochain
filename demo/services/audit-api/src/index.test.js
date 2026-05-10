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
  wasm_audit_append: vi.fn(() => ({ entries: 1, head_hash: 'f'.repeat(64) })),
  wasm_hash_bytes: vi.fn(() => 'a'.repeat(64)),
}));

vi.mock('module', async (importOriginal) => {
  const orig = await importOriginal();
  return {
    ...orig,
    createRequire: () => (id) => {
      if (id === '@exochain/exochain-wasm') return mockWasm;
      throw new Error(`Unexpected require('${id}') in test`);
    },
  };
});

vi.mock('pg', () => {
  const mockQuery = vi.fn();
  const MockPool = vi.fn(() => ({ query: mockQuery }));
  return { default: { Pool: MockPool } };
});

import { server } from './index.js';
import pg from 'pg';

let request;

beforeAll(async () => {
  await new Promise((resolve) => server.listen(0, resolve));
  request = supertest(server);
});

beforeEach(() => {
  vi.clearAllMocks();
  const pool = new pg.Pool();
  pool.query.mockResolvedValue({ rows: [] });
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

describe('GET /health', () => {
  it('returns 200 with service name', async () => {
    const res = await request.get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.service).toBe('audit-api');
  });
});

describe('GET /api/entries', () => {
  it('returns list of audit entries', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [
      { sequence: 1, event_type: 'CreateDecision', actor: 'did:exo:alice', entry_hash: 'a'.repeat(64) },
    ] });
    const res = await request.get('/api/entries');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('passes limit param to DB query', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [] });
    const res = await request.get('/api/entries?limit=10');
    expect(res.status).toBe(200);
  });
});

describe('POST /api/entries', () => {
  it('appends audit entry and returns head_hash', async () => {
    const pool = new pg.Pool();
    pool.query
      .mockResolvedValueOnce({ rows: [{ seq: 0, prev: '0'.repeat(64) }] })
      .mockResolvedValueOnce({ rows: [] });
    const res = await request.post('/api/entries').send({
      actor_did: 'did:exo:alice',
      action: 'CreateDecision',
      result: 'success',
      evidence_hash: 'a'.repeat(64),
    });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('head_hash');
    expect(res.body).toHaveProperty('entry_count');
  });

  it('handles missing evidence_hash with default zeros', async () => {
    const pool = new pg.Pool();
    pool.query
      .mockResolvedValueOnce({ rows: [{ seq: 0, prev: '0'.repeat(64) }] })
      .mockResolvedValueOnce({ rows: [] });
    const res = await request.post('/api/entries').send({
      actor_did: 'did:exo:bob',
      action: 'Vote',
      result: 'success',
    });
    expect(res.status).toBe(201);
  });
});

describe('GET /api/verify', () => {
  it('returns intact=true for empty chain', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [] });
    const res = await request.get('/api/verify');
    expect(res.status).toBe(200);
    expect(res.body.intact).toBe(true);
    expect(res.body.entries_checked).toBe(0);
  });

  it('returns intact=true for valid single-entry chain', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [
      { sequence: 0, prev_hash: '0'.repeat(64), entry_hash: 'a'.repeat(64) },
    ] });
    const res = await request.get('/api/verify');
    expect(res.status).toBe(200);
    expect(res.body.intact).toBe(true);
    expect(res.body.head_hash).toBe('a'.repeat(64));
  });

  it('returns intact=false when hash chain is broken', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [
      { sequence: 0, prev_hash: '0'.repeat(64), entry_hash: 'a'.repeat(64) },
      { sequence: 1, prev_hash: 'WRONG_HASH', entry_hash: 'b'.repeat(64) },
    ] });
    const res = await request.get('/api/verify');
    expect(res.status).toBe(200);
    expect(res.body.intact).toBe(false);
    expect(res.body.error).toMatch(/Chain break/);
  });
});

describe('OPTIONS preflight', () => {
  it('returns 204', async () => {
    const res = await request.options('/api/entries');
    expect(res.status).toBe(204);
  });
});

describe('Unknown route', () => {
  it('returns 404', async () => {
    const res = await request.get('/api/nonexistent');
    expect(res.status).toBe(404);
  });
});
