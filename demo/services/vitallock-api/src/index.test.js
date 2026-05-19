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

import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import supertest from 'supertest';

const mockWasm = vi.hoisted(() => ({
  wasm_death_verification_new: vi.fn(() => ({
    subject_did: 'did:exo:alice',
    initiated_by: 'did:exo:bob',
    required_confirmations: 2,
    confirmations: [],
    status: 'Pending',
  })),
  wasm_death_verification_confirm: vi.fn(() => ({
    verified: true,
    state: {
      subject_did: 'did:exo:alice',
      confirmations: [{ trustee_did: 'did:exo:carol' }],
    },
  })),
}));

vi.mock('module', async (importOriginal) => {
  const original = await importOriginal();
  return {
    ...original,
    createRequire: () => (id) => {
      if (id === '@exochain/exochain-wasm') {
        return mockWasm;
      }
      throw new Error(`unexpected require('${id}') in test`);
    },
  };
});

vi.mock('pg', () => {
  const mockQuery = vi.fn();
  const MockPool = vi.fn(() => ({ query: mockQuery }));
  return { default: { Pool: MockPool } };
});

import pg from 'pg';
import { server } from './index.js';

const OBSERVED_AT_MS = 1_779_120_000_000;
const TOO_OLD_MS = OBSERVED_AT_MS - 300_001;
const TOO_FAR_FUTURE_MS = OBSERVED_AT_MS + 300_001;

const request = supertest(server);

afterAll(async () => {
  vi.useRealTimers();
  if (server.listening) {
    await new Promise((resolve) => server.close(resolve));
  }
});

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date(OBSERVED_AT_MS));
  vi.clearAllMocks();
  const pool = new pg.Pool();
  pool.query.mockImplementation((sql) => {
    if (typeof sql === 'string' && sql.includes('FROM death_verification')) {
      return Promise.resolve({
        rows: [{
          id: 'death-claim-1',
          subject_did: 'did:exo:alice',
          required_confirmations: 2,
          status: 'pending',
          verification_state: { subject_did: 'did:exo:alice', confirmations: [] },
        }],
      });
    }
    return Promise.resolve({ rows: [] });
  });
});

describe('death verification ingress timestamp boundary', () => {
  it('accepts created_at metadata within the ingress window and stores observed audit time', async () => {
    const createdPhysicalMs = OBSERVED_AT_MS - 10;
    const res = await request.post('/api/death/initiate').send({
      subject_did: 'did:exo:alice',
      initiated_by_did: 'did:exo:bob',
      required_confirmations: 2,
      authorized_trustees: [
        { did: 'did:exo:bob', public_key_hex: '11'.repeat(32) },
        { did: 'did:exo:carol', public_key_hex: '22'.repeat(32) },
      ],
      claim_nonce_hex: 'aa'.repeat(16),
      initiator_signature_hex: 'bb'.repeat(64),
      created_physical_ms: createdPhysicalMs,
      created_logical: 0,
    });

    expect(res.status).toBe(201);
    expect(mockWasm.wasm_death_verification_new).toHaveBeenCalledWith(
      'did:exo:alice',
      'did:exo:bob',
      2,
      expect.any(String),
      'aa'.repeat(16),
      'bb'.repeat(64),
      BigInt(createdPhysicalMs),
      0,
    );
    const pool = new pg.Pool();
    const insertCall = pool.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('INSERT INTO death_verification'));
    expect(insertCall[1][7]).toBe(OBSERVED_AT_MS);
  });

  it.each([
    ['past', TOO_OLD_MS],
    ['future', TOO_FAR_FUTURE_MS],
  ])('rejects %s created_at metadata outside the trusted ingress window', async (_label, timestamp) => {
    const res = await request.post('/api/death/initiate').send({
      subject_did: 'did:exo:alice',
      initiated_by_did: 'did:exo:bob',
      required_confirmations: 2,
      authorized_trustees: [
        { did: 'did:exo:bob', public_key_hex: '11'.repeat(32) },
        { did: 'did:exo:carol', public_key_hex: '22'.repeat(32) },
      ],
      claim_nonce_hex: 'aa'.repeat(16),
      initiator_signature_hex: 'bb'.repeat(64),
      created_physical_ms: timestamp,
      created_logical: 0,
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('created_physical_ms');
    expect(mockWasm.wasm_death_verification_new).not.toHaveBeenCalled();
  });

  it('accepts confirmed_at metadata within the ingress window and stores observed resolution time', async () => {
    const confirmedPhysicalMs = OBSERVED_AT_MS + 10;
    const res = await request.post('/api/death/confirm').send({
      verification_id: 'death-claim-1',
      trustee_did: 'did:exo:carol',
      trustee_public_key_hex: '22'.repeat(32),
      signature_hex: 'cc'.repeat(64),
      confirmed_physical_ms: confirmedPhysicalMs,
      confirmed_logical: 0,
    });

    expect(res.status).toBe(200);
    expect(mockWasm.wasm_death_verification_confirm).toHaveBeenCalledWith(
      JSON.stringify({ subject_did: 'did:exo:alice', confirmations: [] }),
      'did:exo:carol',
      '22'.repeat(32),
      'cc'.repeat(64),
      BigInt(confirmedPhysicalMs),
      0,
    );
    const pool = new pg.Pool();
    const updateCall = pool.query.mock.calls.find(([sql]) =>
      typeof sql === 'string' && sql.includes('UPDATE death_verification'));
    expect(updateCall[1][3]).toBe(OBSERVED_AT_MS);
  });

  it.each([
    ['past', TOO_OLD_MS],
    ['future', TOO_FAR_FUTURE_MS],
  ])('rejects %s confirmed_at metadata outside the trusted ingress window', async (_label, timestamp) => {
    const res = await request.post('/api/death/confirm').send({
      verification_id: 'death-claim-1',
      trustee_did: 'did:exo:carol',
      trustee_public_key_hex: '22'.repeat(32),
      signature_hex: 'cc'.repeat(64),
      confirmed_physical_ms: timestamp,
      confirmed_logical: 0,
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('confirmed_physical_ms');
    expect(mockWasm.wasm_death_verification_confirm).not.toHaveBeenCalled();
  });
});
