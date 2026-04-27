import { describe, it, expect, beforeAll, afterAll, vi, beforeEach } from 'vitest';
import supertest from 'supertest';

// vi.hoisted creates the mock wasm functions before any module initialization
const mockWasm = vi.hoisted(() => ({
  wasm_hash_bytes: vi.fn(() => 'a'.repeat(64)),
  wasm_hash_structured: vi.fn(() => 'b'.repeat(64)),
  wasm_generate_keypair: vi.fn(() => ({ public_key: 'c'.repeat(64), secret_key: 'd'.repeat(64) })),
  wasm_sign: vi.fn(() => 'e'.repeat(128)),
  wasm_verify: vi.fn(() => true),
  wasm_enforce_invariants: vi.fn(() => ({ invariants: [{ id: 'CR-001', name: 'No Floats' }] })),
  wasm_mcp_rules: vi.fn(() => [{ id: 'MCP-001' }]),
  wasm_workflow_stages: vi.fn(() => ['Draft', 'Review', 'Voting', 'Enacted']),
  wasm_bcts_valid_transitions: vi.fn(() => ['Review', 'Withdrawn']),
  wasm_bcts_is_terminal: vi.fn(() => false),
  wasm_check_clearance: vi.fn(() => ({ status: 'Granted' })),
  wasm_check_conflicts: vi.fn(() => ({ must_recuse: false, conflicts: [] })),
  wasm_create_decision: vi.fn((id, title, _decClass, _hash, createdAtMs, createdAtLogical) => ({
    id,
    title,
    status: 'Draft',
    created_at: { physical_ms: createdAtMs, logical: createdAtLogical },
    votes: [],
  })),
  wasm_add_vote: vi.fn((decJson, voteJson) => ({ ...JSON.parse(decJson), votes: [JSON.parse(voteJson)] })),
  wasm_transition_decision: vi.fn((decJson, stateJson, _actor, timestampMs, timestampLogical) => ({
    ...JSON.parse(decJson),
    status: JSON.parse(stateJson),
    last_transition_at: { physical_ms: timestampMs, logical: timestampLogical },
  })),
  wasm_decision_is_terminal: vi.fn(() => false),
  wasm_shamir_split: vi.fn(() => []),
  wasm_audit_append: vi.fn(() => ({ entries: 1, head_hash: 'f'.repeat(64) })),
}));

// Mock the 'module' built-in to intercept createRequire, which services use
// to load the WASM package (bypasses standard ESM import interception)
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

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

beforeEach(async () => {
  global._backlog = undefined;
  vi.clearAllMocks();
  const pool = new pg.Pool();
  pool.query.mockImplementation((sql) => {
    if (sql === 'SELECT 1') return Promise.resolve({ rows: [{ '?column?': 1 }] });
    if (typeof sql === 'string' && sql.includes('FROM users')) return Promise.resolve({ rows: [{ did: 'did:exo:alice', display_name: 'Alice', email: 'alice@example.com', roles: ['Governor'], status: 'active', pace_status: 'Enrolled' }] });
    if (typeof sql === 'string' && sql.includes('FROM decisions')) return Promise.resolve({ rows: [] });
    if (typeof sql === 'string' && sql.includes('FROM audit_entries')) return Promise.resolve({ rows: [] });
    if (typeof sql === 'string' && sql.includes('FROM constitutions')) return Promise.resolve({ rows: [{ version: 1, payload: { name: 'ExoChain Foundation' } }] });
    return Promise.resolve({ rows: [] });
  });
  mockWasm.wasm_enforce_invariants.mockReturnValue({ invariants: [{ id: 'CR-001', name: 'No Floats' }] });
  mockWasm.wasm_mcp_rules.mockReturnValue([{ id: 'MCP-001' }]);
  mockWasm.wasm_workflow_stages.mockReturnValue(['Draft', 'Review', 'Voting', 'Enacted']);
  mockWasm.wasm_bcts_valid_transitions.mockReturnValue(['Review', 'Withdrawn']);
  mockWasm.wasm_bcts_is_terminal.mockReturnValue(false);
  mockWasm.wasm_check_clearance.mockReturnValue({ status: 'Granted' });
  mockWasm.wasm_check_conflicts.mockReturnValue({ must_recuse: false, conflicts: [] });
  mockWasm.wasm_hash_bytes.mockReturnValue('a'.repeat(64));
  mockWasm.wasm_hash_structured.mockReturnValue('b'.repeat(64));
  mockWasm.wasm_generate_keypair.mockReturnValue({ public_key: 'c'.repeat(64), secret_key: 'd'.repeat(64) });
  mockWasm.wasm_sign.mockReturnValue('e'.repeat(128));
  mockWasm.wasm_verify.mockReturnValue(true);
  mockWasm.wasm_create_decision.mockImplementation((id, title, _decClass, _hash, createdAtMs, createdAtLogical) => ({
    id,
    title,
    status: 'Draft',
    created_at: { physical_ms: createdAtMs, logical: createdAtLogical },
    votes: [],
  }));
  mockWasm.wasm_add_vote.mockImplementation((decJson, voteJson) => ({ ...JSON.parse(decJson), votes: [JSON.parse(voteJson)] }));
  mockWasm.wasm_transition_decision.mockImplementation((decJson, stateJson, _actor, timestampMs, timestampLogical) => ({
    ...JSON.parse(decJson),
    status: JSON.parse(stateJson),
    last_transition_at: { physical_ms: timestampMs, logical: timestampLogical },
  }));
  mockWasm.wasm_decision_is_terminal.mockReturnValue(false);
  mockWasm.wasm_shamir_split.mockReturnValue([]);
  mockWasm.wasm_audit_append.mockReturnValue({ entries: 1, head_hash: 'f'.repeat(64) });
});

describe('GET /health', () => {
  it('returns 200 with ok status', async () => {
    const res = await request.get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.service).toBe('gateway-api');
  });
});

describe('GET /api/system', () => {
  it('returns constitutional invariants, mcp rules, workflow stages, bcts transitions', async () => {
    const res = await request.get('/api/system');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('constitutional_invariants');
    expect(res.body).toHaveProperty('mcp_rules');
    expect(res.body).toHaveProperty('workflow_stages');
    expect(res.body).toHaveProperty('bcts_draft_transitions');
  });
});

describe('GET /api/users', () => {
  it('returns user list', async () => {
    const res = await request.get('/api/users');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

describe('GET /api/decisions', () => {
  it('returns decision list', async () => {
    const res = await request.get('/api/decisions');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

describe('POST /api/decisions', () => {
  it('creates decision for enrolled PACE author', async () => {
    const pool = new pg.Pool();
    pool.query
      .mockResolvedValueOnce({ rows: [{ did: 'did:exo:alice', pace_status: 'Enrolled' }] })
      .mockResolvedValueOnce({ rows: [{ version: 1, payload: { name: 'ExoChain' } }] })
      .mockResolvedValueOnce({ rows: [] });
    const res = await request
      .post('/api/decisions')
      .send({
        title: 'Test Decision',
        decision_class: 'Operational',
        author_did: 'did:exo:alice',
        decision_id: '00000000-0000-0000-0000-000000000001',
        created_at_ms: 1000,
        created_at_logical: 0,
      });
    expect(res.status).toBe(201);
    expect(res.body.decision).toHaveProperty('id', '00000000-0000-0000-0000-000000000001');
    expect(res.body.decision.title).toBe('Test Decision');
  });

  it('requires caller-supplied deterministic create metadata', async () => {
    const res = await request
      .post('/api/decisions')
      .send({ title: 'Test Decision', decision_class: 'Operational', author_did: 'did:exo:alice' });
    expect(res.status).toBe(400);
    expect(res.body.fields).toEqual(['decision_id', 'created_at_ms', 'created_at_logical']);
  });

  it('returns 404 when author not found', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [] });
    const res = await request
      .post('/api/decisions')
      .send({
        title: 'Test',
        author_did: 'did:exo:unknown',
        decision_id: '00000000-0000-0000-0000-000000000002',
        created_at_ms: 1100,
        created_at_logical: 0,
      });
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('Author not found');
  });

  it('returns 403 when author not PACE enrolled', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [{ did: 'did:exo:bob', pace_status: 'Pending' }] });
    const res = await request
      .post('/api/decisions')
      .send({
        title: 'Test',
        author_did: 'did:exo:bob',
        decision_id: '00000000-0000-0000-0000-000000000003',
        created_at_ms: 1200,
        created_at_logical: 0,
      });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Author not PACE enrolled');
  });
});

describe('POST /api/decisions/vote', () => {
  it('records vote with valid clearance', async () => {
    const pool = new pg.Pool();
    pool.query
      .mockResolvedValueOnce({ rows: [{ payload: { id: 'test-id-001', votes: [] } }] })
      .mockResolvedValueOnce({ rows: [] });
    const res = await request
      .post('/api/decisions/vote')
      .send({ decision_id: 'test-id-001', voter_did: 'did:exo:alice', choice: 'Approve', rationale: 'Good' });
    expect(res.status).toBe(200);
    expect(res.body.vote_recorded).toBe(true);
  });

  it('returns 404 when decision not found', async () => {
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [] });
    const res = await request
      .post('/api/decisions/vote')
      .send({ decision_id: 'missing', voter_did: 'did:exo:alice', choice: 'Approve' });
    expect(res.status).toBe(404);
  });

  it('returns 403 on conflict of interest', async () => {
    mockWasm.wasm_check_conflicts.mockReturnValueOnce({ must_recuse: true, conflicts: [] });
    const pool = new pg.Pool();
    pool.query.mockResolvedValueOnce({ rows: [{ payload: { id: 'test-id-001', votes: [] } }] });
    const res = await request
      .post('/api/decisions/vote')
      .send({ decision_id: 'test-id-001', voter_did: 'did:exo:alice', choice: 'Approve' });
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/recuse/);
  });
});

describe('POST /api/decisions/transition', () => {
  it('transitions decision state', async () => {
    const pool = new pg.Pool();
    pool.query
      .mockResolvedValueOnce({ rows: [{ payload: { id: 'test-id-001', status: 'Draft', votes: [] }, status: 'Draft' }] })
      .mockResolvedValueOnce({ rows: [] });
    const res = await request
      .post('/api/decisions/transition')
      .send({
        decision_id: 'test-id-001',
        to_state: 'Review',
        actor_did: 'did:exo:alice',
        timestamp_ms: 2000,
        timestamp_logical: 0,
      });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('new_state', 'Review');
  });

  it('requires caller-supplied transition timestamp metadata', async () => {
    const res = await request
      .post('/api/decisions/transition')
      .send({ decision_id: 'test-id-001', to_state: 'Review', actor_did: 'did:exo:alice' });
    expect(res.status).toBe(400);
    expect(res.body.fields).toEqual(['timestamp_ms', 'timestamp_logical']);
  });
});

describe('POST /api/crypto/hash', () => {
  it('returns hex hash of input data', async () => {
    const res = await request.post('/api/crypto/hash').send({ data: { foo: 'bar' } });
    expect(res.status).toBe(200);
    expect(res.body.hash).toBe('b'.repeat(64));
  });
});

describe('POST /api/crypto/keypair', () => {
  it('returns public and secret key', async () => {
    const res = await request.post('/api/crypto/keypair');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('public_key');
    expect(res.body).toHaveProperty('secret_key');
  });
});

describe('POST /api/crypto/sign', () => {
  it('returns a signature', async () => {
    const res = await request.post('/api/crypto/sign').send({ message: 'hello', secret_key: 'd'.repeat(64) });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('signature');
  });
});

describe('POST /api/crypto/verify', () => {
  it('returns validity boolean', async () => {
    const res = await request.post('/api/crypto/verify').send({ message: 'hello', signature: 'e'.repeat(128), public_key: 'c'.repeat(64) });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('valid');
  });
});

describe('GET /api/bcts/transitions', () => {
  it('returns transitions for a given state', async () => {
    const res = await request.get('/api/bcts/transitions?state=Draft');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('state', 'Draft');
    expect(Array.isArray(res.body.transitions)).toBe(true);
  });
});

describe('POST /api/identity/shamir/split', () => {
  it('returns shares array', async () => {
    const res = await request.post('/api/identity/shamir/split').send({ secret: 'my-secret', threshold: 2, shares: 3 });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('threshold', 2);
    expect(res.body).toHaveProperty('total', 3);
  });
});

describe('POST /api/feedback', () => {
  it('ingests feedback and returns feedback_id', async () => {
    const res = await request.post('/api/feedback').send({ widget: 'test-widget', type: 'bug', message: 'Something broken' });
    expect(res.status).toBe(201);
    expect(res.body.feedback_id).toMatch(/^FB-/);
    expect(res.body.status).toBe('ingested');
  });
});

describe('GET /api/backlog', () => {
  it('returns empty array when no feedback ingested', async () => {
    const res = await request.get('/api/backlog');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

describe('POST /api/backlog/vote', () => {
  it('auto-approves backlog item after 3 approvals', async () => {
    const fbRes = await request.post('/api/feedback').send({ widget: 'w1', type: 'suggestion', message: 'Improve X' });
    const itemId = fbRes.body.feedback_id;
    for (let i = 0; i < 3; i++) {
      await request.post('/api/backlog/vote').send({ id: itemId, vote: 'approve', panel: `panel-${i}` });
    }
    const backlog = await request.get('/api/backlog');
    const item = backlog.body.find(i => i.id === itemId);
    expect(item.disposition).toBe('approved');
  });

  it('returns 404 when item not found', async () => {
    await request.post('/api/feedback').send({ widget: 'w', type: 'bug', message: 'x' });
    const res = await request.post('/api/backlog/vote').send({ id: 'NONEXISTENT', vote: 'approve' });
    expect(res.status).toBe(404);
  });
});

describe('OPTIONS preflight', () => {
  it('returns 204 with CORS headers', async () => {
    const res = await request.options('/api/decisions');
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe('*');
  });
});

describe('GET /unknown-route', () => {
  it('returns 404 with available endpoints list', async () => {
    const res = await request.get('/api/nonexistent');
    expect(res.status).toBe(404);
    expect(Array.isArray(res.body.available_endpoints)).toBe(true);
  });
});
