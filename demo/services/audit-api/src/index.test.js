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

vi.hoisted(() => {
  process.env.GOVERNANCE_API_TOKEN = 'test-token';
  process.env.GOVERNANCE_ATTESTATION_KEYS = JSON.stringify({
    'did:exo:monitor': '11'.repeat(32),
  });
  process.env.GOVERNANCE_APPROVAL_KEYS = JSON.stringify({
    'did:exo:human': '22'.repeat(32),
  });
});

const mockWasm = vi.hoisted(() => ({
  wasm_audit_append: vi.fn(() => ({ entries: 1, head_hash: 'f'.repeat(64) })),
  wasm_hash_bytes: vi.fn(() => 'a'.repeat(64)),
  wasm_governance_findings_digest: vi.fn(() => 'b'.repeat(64)),
  wasm_verify_governance_attestation_with_trusted_keys: vi.fn(() => true),
}));

const mockPg = vi.hoisted(() => {
  const query = vi.fn();
  const Pool = vi.fn(() => ({ query }));
  return { Pool, query };
});

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
  return { default: { Pool: mockPg.Pool } };
});

import { server } from './index.js';

let request;

beforeAll(async () => {
  await new Promise((resolve) => server.listen(0, resolve));
  request = supertest(server);
});

beforeEach(() => {
  vi.clearAllMocks();
  mockPg.query.mockReset();
  mockPg.query.mockResolvedValue({ rows: [] });
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
    mockPg.query.mockResolvedValueOnce({ rows: [
      { sequence: 1, event_type: 'CreateDecision', actor: 'did:exo:alice', entry_hash: 'a'.repeat(64) },
    ] });
    const res = await request.get('/api/entries');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('passes limit param to DB query', async () => {
    mockPg.query.mockResolvedValueOnce({ rows: [] });
    const res = await request.get('/api/entries?limit=10');
    expect(res.status).toBe(200);
  });
});

describe('POST /api/entries', () => {
  it('appends audit entry and returns head_hash', async () => {
    mockPg.query
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
    mockPg.query
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

describe('POST /governance/health attestation gate', () => {
  const validSnapshot = {
    run_id: 'run-1',
    commit_sha: 'abc123',
    system_health: {
      invariant_coverage: 100,
      tnc_coverage: 100,
      bcts_integrity: 100,
      governance_score: 95,
    },
    findings_digest: 'b'.repeat(64),
    findings: [{ id: 'F-001', severity: 'critical', title: 'Unsigned injection' }],
    attestation_signature: { Ed25519: Array.from({ length: 64 }, () => 1) },
    attestation_signer_did: 'did:exo:monitor',
    attestation_public_key: '11'.repeat(32),
  };

  it('rejects missing attestation before any database write', async () => {
    mockPg.query.mockResolvedValue({ rows: [] });
    const { attestation_signature, attestation_signer_did, attestation_public_key, ...unsigned } = validSnapshot;

    const res = await request
      .post('/governance/health')
      .set('Authorization', 'Bearer test-token')
      .send(unsigned);

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/attestation_signature/);
    expect(mockPg.query).not.toHaveBeenCalled();
  });

  it('rejects mismatched findings digest before persistence', async () => {
    mockPg.query.mockResolvedValue({ rows: [] });

    const res = await request
      .post('/governance/health')
      .set('Authorization', 'Bearer test-token')
      .send({ ...validSnapshot, findings_digest: 'c'.repeat(64) });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/findings_digest/);
    expect(mockPg.query).not.toHaveBeenCalled();
  });

  it('rejects invalid attestation before persistence', async () => {
    mockWasm.wasm_verify_governance_attestation_with_trusted_keys.mockImplementationOnce(() => {
      throw new Error('governance attestation rejected');
    });
    mockPg.query.mockResolvedValue({ rows: [] });

    const res = await request
      .post('/governance/health')
      .set('Authorization', 'Bearer test-token')
      .send(validSnapshot);

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid governance attestation/);
    expect(mockPg.query).not.toHaveBeenCalled();
  });

  it('rejects an unconfigured attestation signer before persistence', async () => {
    mockPg.query.mockResolvedValue({ rows: [] });

    const res = await request
      .post('/governance/health')
      .set('Authorization', 'Bearer test-token')
      .send({ ...validSnapshot, attestation_signer_did: 'did:exo:rogue' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not configured/);
    expect(mockWasm.wasm_verify_governance_attestation_with_trusted_keys).not.toHaveBeenCalled();
    expect(mockPg.query).not.toHaveBeenCalled();
  });

  it('rejects caller-supplied attestation keys that do not match configuration', async () => {
    mockPg.query.mockResolvedValue({ rows: [] });

    const res = await request
      .post('/governance/health')
      .set('Authorization', 'Bearer test-token')
      .send({ ...validSnapshot, attestation_public_key: '22'.repeat(32) });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/does not match configured signer key/);
    expect(mockWasm.wasm_verify_governance_attestation_with_trusted_keys).not.toHaveBeenCalled();
    expect(mockPg.query).not.toHaveBeenCalled();
  });

  it('uses the configured attestation key when the request omits public key material', async () => {
    const { attestation_public_key, ...snapshotWithoutCallerKey } = validSnapshot;
    mockPg.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '1' }] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ seq: 0, prev: '0'.repeat(64) }] })
      .mockResolvedValueOnce({ rows: [] });

    const res = await request
      .post('/governance/health')
      .set('Authorization', 'Bearer test-token')
      .send(snapshotWithoutCallerKey);

    expect(res.status).toBe(201);
    expect(mockWasm.wasm_verify_governance_attestation_with_trusted_keys).toHaveBeenCalledWith(
      validSnapshot.attestation_signer_did,
      JSON.stringify(validSnapshot.findings),
      JSON.stringify(validSnapshot.attestation_signature),
      JSON.stringify({ 'did:exo:monitor': '11'.repeat(32) }),
    );
    expect(mockPg.query).toHaveBeenCalled();
  });

  it('persists valid signed health snapshots after attestation verification', async () => {
    mockPg.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: '1' }] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ seq: 0, prev: '0'.repeat(64) }] })
      .mockResolvedValueOnce({ rows: [] });

    const res = await request
      .post('/governance/health')
      .set('Authorization', 'Bearer test-token')
      .send(validSnapshot);

    expect(res.status).toBe(201);
    expect(mockWasm.wasm_verify_governance_attestation_with_trusted_keys).toHaveBeenCalledWith(
      validSnapshot.attestation_signer_did,
      JSON.stringify(validSnapshot.findings),
      JSON.stringify(validSnapshot.attestation_signature),
      JSON.stringify({ 'did:exo:monitor': '11'.repeat(32) }),
    );
    expect(mockPg.query).toHaveBeenCalled();
  });
});

describe('POST /governance/approve/:approvalId human approval signature gate', () => {
  const approvalId = 'approval-run-1';
  const validApproval = {
    approved_by_did: 'did:exo:human',
    approval_signer_did: 'did:exo:human',
    approval_signature: { Ed25519: Array.from({ length: 64 }, () => 2) },
    notes: 'ship after human review',
  };
  const expectedApprovalPayload = JSON.stringify({
    approval_id: approvalId,
    approved_by_did: 'did:exo:human',
    decision: 'Approved',
    notes: 'ship after human review',
  });

  it('rejects missing human approval signature before any database write', async () => {
    const res = await request
      .post(`/governance/approve/${approvalId}`)
      .set('Authorization', 'Bearer test-token')
      .send({ approved_by_did: 'did:exo:human' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/approval_signature/);
    expect(mockPg.query).not.toHaveBeenCalled();
  });

  it('rejects approval signer DID mismatch before verification', async () => {
    const res = await request
      .post(`/governance/approve/${approvalId}`)
      .set('Authorization', 'Bearer test-token')
      .send({ ...validApproval, approval_signer_did: 'did:exo:other-human' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/match approved_by_did/);
    expect(mockWasm.wasm_verify_governance_attestation_with_trusted_keys).not.toHaveBeenCalled();
    expect(mockPg.query).not.toHaveBeenCalled();
  });

  it('rejects unconfigured human approval signers before persistence', async () => {
    const res = await request
      .post(`/governance/approve/${approvalId}`)
      .set('Authorization', 'Bearer test-token')
      .send({
        ...validApproval,
        approved_by_did: 'did:exo:rogue-human',
        approval_signer_did: 'did:exo:rogue-human',
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not configured/);
    expect(mockWasm.wasm_verify_governance_attestation_with_trusted_keys).not.toHaveBeenCalled();
    expect(mockPg.query).not.toHaveBeenCalled();
  });

  it('rejects invalid human approval signatures before persistence', async () => {
    mockWasm.wasm_verify_governance_attestation_with_trusted_keys.mockImplementationOnce(() => {
      throw new Error('approval signature rejected');
    });

    const res = await request
      .post(`/governance/approve/${approvalId}`)
      .set('Authorization', 'Bearer test-token')
      .send(validApproval);

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid governance approval/);
    expect(mockPg.query).not.toHaveBeenCalled();
  });

  it('persists approved gates only after trusted human signature verification', async () => {
    mockPg.query.mockResolvedValueOnce({ rowCount: 1 });

    const res = await request
      .post(`/governance/approve/${approvalId}`)
      .set('Authorization', 'Bearer test-token')
      .send(validApproval);

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('Approved');
    expect(res.body.approved_by_did).toBe('did:exo:human');
    expect(mockWasm.wasm_verify_governance_attestation_with_trusted_keys).toHaveBeenCalledWith(
      'did:exo:human',
      expectedApprovalPayload,
      JSON.stringify(validApproval.approval_signature),
      JSON.stringify({ 'did:exo:human': '22'.repeat(32) }),
    );
    expect(mockPg.query).toHaveBeenCalled();
  });
});

describe('GET /api/verify', () => {
  it('returns intact=true for empty chain', async () => {
    mockPg.query.mockResolvedValueOnce({ rows: [] });
    const res = await request.get('/api/verify');
    expect(res.status).toBe(200);
    expect(res.body.intact).toBe(true);
    expect(res.body.entries_checked).toBe(0);
  });

  it('returns intact=true for valid single-entry chain', async () => {
    mockPg.query.mockResolvedValueOnce({ rows: [
      { sequence: 0, prev_hash: '0'.repeat(64), entry_hash: 'a'.repeat(64) },
    ] });
    const res = await request.get('/api/verify');
    expect(res.status).toBe(200);
    expect(res.body.intact).toBe(true);
    expect(res.body.head_hash).toBe('a'.repeat(64));
  });

  it('returns intact=false when hash chain is broken', async () => {
    mockPg.query.mockResolvedValueOnce({ rows: [
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
