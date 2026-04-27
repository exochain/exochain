import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest';
import supertest from 'supertest';

const mockWasm = vi.hoisted(() => ({
  wasm_shamir_split: vi.fn((_secret, threshold, total) => Array.from({ length: total }, (_, i) => ({ index: i + 1, share: 'share-data-' + i }))),
  wasm_shamir_reconstruct: vi.fn(() => ({ secret: 'reconstructed', valid: true })),
  wasm_pace_resolve: vi.fn((_config, stateJson) => ({ ...JSON.parse(stateJson), resolved: true, next_action: 'Continue' })),
  wasm_pace_escalate: vi.fn((stateJson) => { const s = JSON.parse(stateJson); return { ...s, level: (s.level || 0) + 1 }; }),
  wasm_assess_risk: vi.fn((subject, attester, _evidence, levelJson) => ({ subject_did: subject, attester_did: attester, level: JSON.parse(levelJson), valid_until_ms: Date.now() + 86400000, attestation_hash: 'r'.repeat(64) })),
  wasm_generate_keypair: vi.fn(() => ({ public_key: 'p'.repeat(64), secret_key: 's'.repeat(64) })),
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
  it('returns 200', async () => { expect((await request.get('/health')).body.service).toBe('identity-service'); });
});

describe('GET /api/users', () => {
  it('returns user list', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [{ did: 'did:exo:alice', display_name: 'Alice', pace_status: 'Enrolled' }] });
    const res = await request.get('/api/users');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body[0].did).toBe('did:exo:alice');
  });
});

describe('GET /api/scores', () => {
  it('returns identity scores', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [{ did: 'did:exo:alice', score: 95, tier: 'Gold' }] });
    const res = await request.get('/api/scores');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

describe('GET /api/enrollment', () => {
  it('returns enrollment log', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [] });
    const res = await request.get('/api/enrollment');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

describe('POST /api/shamir/split', () => {
  it('splits secret into shares', async () => {
    const res = await request.post('/api/shamir/split').send({ secret: 'my-secret', threshold: 2, shares: 3 });
    expect(res.status).toBe(200);
    expect(res.body.shares).toHaveLength(3);
    expect(res.body.threshold).toBe(2);
    expect(res.body.total).toBe(3);
  });

  it('defaults threshold=2 shares=3', async () => {
    const res = await request.post('/api/shamir/split').send({ secret: 'test' });
    expect(res.status).toBe(200);
    expect(res.body.threshold).toBe(2);
    expect(res.body.total).toBe(3);
  });
});

describe('POST /api/shamir/reconstruct', () => {
  it('reconstructs secret from shares', async () => {
    const res = await request.post('/api/shamir/reconstruct').send({ shares: [{ index: 1, share: 'x' }, { index: 2, share: 'y' }], threshold: 2, total: 3 });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('valid', true);
  });
});

describe('POST /api/pace/resolve', () => {
  it('resolves PACE state', async () => {
    const res = await request.post('/api/pace/resolve').send({ config: { enrollment_required: true }, state: { did: 'did:exo:alice', level: 1, enrolled: true } });
    expect(res.status).toBe(200);
    expect(res.body.resolved).toBe(true);
  });
});

describe('POST /api/pace/escalate', () => {
  it('escalates PACE level', async () => {
    const res = await request.post('/api/pace/escalate').send({ state: { did: 'did:exo:alice', level: 1 } });
    expect(res.status).toBe(200);
    expect(res.body.new_state.level).toBe(2);
  });
});

describe('POST /api/risk/assess', () => {
  it('returns risk attestation', async () => {
    const res = await request.post('/api/risk/assess').send({
      subject_did: 'did:exo:alice',
      attester_did: 'did:exo:trustee',
      evidence: 'biometric',
      level: 'High',
      validity_ms: 86400000,
      attester_secret_hex: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
      timestamp_ms: 1700000000000,
      timestamp_logical: 0
    });
    expect(res.status).toBe(200);
    expect(res.body.subject_did).toBe('did:exo:alice');
    expect(res.body.level).toBe('High');
    expect(res.body).toHaveProperty('attestation_hash');
  });

  it('requires caller-supplied signer and timestamp metadata', async () => {
    const res = await request.post('/api/risk/assess').send({
      subject_did: 'did:exo:alice',
      attester_did: 'did:exo:trustee',
      evidence: 'biometric',
      level: 'High',
      validity_ms: 86400000
    });
    expect(res.status).toBe(400);
    expect(res.body.fields).toEqual(['attester_secret_hex', 'timestamp_ms']);
  });
});

describe('POST /api/keypair', () => {
  it('generates a keypair', async () => {
    const res = await request.post('/api/keypair');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('public_key');
    expect(res.body).toHaveProperty('secret_key');
  });
});

describe('OPTIONS / 404', () => {
  it('OPTIONS returns 204', async () => { expect((await request.options('/api/shamir/split')).status).toBe(204); });
  it('unknown returns 404', async () => { expect((await request.get('/api/nonexistent')).status).toBe(404); });
});
