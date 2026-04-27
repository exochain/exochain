import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest';
import supertest from 'supertest';

const mockWasm = vi.hoisted(() => ({
  wasm_create_evidence: vi.fn((_content, typeTag, creator, id, createdMs) => ({ id, type_tag: typeTag, creator_did: creator, content_hash: 'e'.repeat(64), chain_of_custody: [{ actor: creator, timestamp_ms: Number(createdMs), action: 'Created' }], created_at_ms: Number(createdMs) })),
  wasm_verify_chain_of_custody: vi.fn((evidenceJson) => ({ valid: true, evidence: JSON.parse(evidenceJson), chain_length: JSON.parse(evidenceJson).chain_of_custody?.length || 0 })),
  wasm_check_fiduciary_duty: vi.fn((_duty, actionsJson) => ({ compliant: true, actions_reviewed: JSON.parse(actionsJson).length, violations: [] })),
  wasm_ediscovery_search: vi.fn((requestJson) => ({ query: JSON.parse(requestJson).query, results: [], result_count: 0, format: 'EDRM' })),
  wasm_evaluate_signals: vi.fn((signalsJson) => ({ signals: JSON.parse(signalsJson), escalation_required: false, severity: 'Low' })),
}));

vi.mock('module', async (importOriginal) => {
  const orig = await importOriginal();
  return { ...orig, createRequire: () => (id) => { if (id === '@exochain/exochain-wasm') return mockWasm; throw new Error(`Unexpected require('${id}') in test`); } };
});

vi.mock('pg', () => { const q = vi.fn(); const P = vi.fn(() => ({ query: q })); return { default: { Pool: P } }; });

import { server } from './index.js';

let request;
beforeAll(async () => { await new Promise((r) => server.listen(0, r)); request = supertest(server); });
beforeEach(() => { vi.clearAllMocks(); });
afterAll(async () => { await new Promise((r) => server.close(r)); });

describe('GET /health', () => {
  it('returns 200', async () => { expect((await request.get('/health')).body.service).toBe('provenance-writer'); });
});

describe('POST /api/evidence/create', () => {
  it('creates evidence entry with chain-of-custody', async () => {
    const res = await request.post('/api/evidence/create').send({ content: 'doc', type_tag: 'document', creator_did: 'did:exo:alice', evidence_id: '00000000-0000-0000-0000-000000000001', created_ms: 1700000000000 });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('id', '00000000-0000-0000-0000-000000000001');
    expect(res.body.type_tag).toBe('document');
    expect(res.body.creator_did).toBe('did:exo:alice');
    expect(res.body).toHaveProperty('content_hash');
    expect(Array.isArray(res.body.chain_of_custody)).toBe(true);
  });

  it('defaults type_tag to document', async () => {
    const res = await request.post('/api/evidence/create').send({ content: 'x', creator_did: 'did:exo:bob', evidence_id: '00000000-0000-0000-0000-000000000002', created_ms: 1700000000001 });
    expect(res.status).toBe(201);
    expect(res.body.type_tag).toBe('document');
  });

  it('requires caller-supplied deterministic metadata', async () => {
    const res = await request.post('/api/evidence/create').send({ content: 'x', creator_did: 'did:exo:bob' });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('evidence_id');
  });
});

describe('POST /api/evidence/verify', () => {
  it('verifies chain of custody integrity', async () => {
    const res = await request.post('/api/evidence/verify').send({ evidence: { id: 'ev-001', content_hash: 'e'.repeat(64), chain_of_custody: [{ actor: 'did:exo:alice', action: 'Created' }] } });
    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
    expect(res.body.chain_length).toBe(1);
  });

  it('returns chain_length 0 for empty custody chain', async () => {
    const res = await request.post('/api/evidence/verify').send({ evidence: { id: 'ev-002', content_hash: 'a'.repeat(64), chain_of_custody: [] } });
    expect(res.status).toBe(200);
    expect(res.body.chain_length).toBe(0);
  });
});

describe('POST /api/fiduciary/check', () => {
  it('checks fiduciary duty compliance', async () => {
    const res = await request.post('/api/fiduciary/check').send({ duty: { type: 'Custodian' }, actions: [{ type: 'read' }, { type: 'archive' }] });
    expect(res.status).toBe(200);
    expect(res.body.compliant).toBe(true);
    expect(res.body.actions_reviewed).toBe(2);
  });
});

describe('POST /api/ediscovery/search', () => {
  it('returns results in EDRM format', async () => {
    const res = await request.post('/api/ediscovery/search').send({ request: { query: 'governance 2026', custodians: ['did:exo:alice'] }, corpus: [] });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('format', 'EDRM');
    expect(res.body.query).toBe('governance 2026');
  });
});

describe('POST /api/escalation/evaluate', () => {
  it('evaluates escalation signals', async () => {
    const res = await request.post('/api/escalation/evaluate').send({ signals: [{ type: 'anomaly', severity: 'Low' }] });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('escalation_required', false);
    expect(res.body.severity).toBe('Low');
  });

  it('returns escalation_required=true for critical signals', async () => {
    mockWasm.wasm_evaluate_signals.mockReturnValueOnce({ signals: [], escalation_required: true, severity: 'Critical' });
    const res = await request.post('/api/escalation/evaluate').send({ signals: [{ type: 'breach', severity: 'Critical' }] });
    expect(res.status).toBe(200);
    expect(res.body.escalation_required).toBe(true);
    expect(res.body.severity).toBe('Critical');
  });
});

describe('OPTIONS / 404', () => {
  it('OPTIONS returns 204', async () => { expect((await request.options('/api/evidence/create')).status).toBe(204); });
  it('unknown returns 404', async () => { expect((await request.get('/api/nonexistent')).status).toBe(404); });
});
