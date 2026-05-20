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
  wasm_death_verification_new: vi.fn((
    subjectDid,
    initiatedByDid,
    requiredConfirmations,
    authorizedTrusteesJson,
  ) => ({
    subject_did: subjectDid,
    initiated_by: initiatedByDid,
    required_confirmations: requiredConfirmations,
    authorized_trustees: JSON.parse(authorizedTrusteesJson),
    confirmations: [],
    status: 'Pending',
  })),
  wasm_death_verification_confirm: vi.fn((stateJson, trusteeDid) => ({
    verified: false,
    confirmations_remaining: 1,
    state: {
      ...JSON.parse(stateJson),
      confirmations: [{ trustee_did: trusteeDid }],
      status: 'Pending',
    },
  })),
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

vi.mock('pg', () => ({ default: { Pool: mockPg.Pool } }));

import { server } from './index.js';

const request = supertest(server);

const trustedRows = [
  {
    trustee_did: 'did:exo:trusted-primary',
    trustee_ed25519_public_key_hex: '11'.repeat(32),
  },
  {
    trustee_did: 'did:exo:trusted-alternate',
    trustee_ed25519_public_key_hex: '22'.repeat(32),
  },
];

beforeEach(() => {
  vi.clearAllMocks();
  mockPg.query.mockReset();
  mockPg.query.mockResolvedValue({ rows: [] });
});

afterAll(async () => {
  if (server.listening) {
    await new Promise((resolve) => server.close(resolve));
  }
});

describe('POST /api/death/initiate trustee boundary', () => {
  it('derives authorized death trustees from accepted PACE rows instead of request body trust anchors', async () => {
    mockPg.query.mockImplementation((sql) => {
      if (String(sql).includes('FROM pace_network')) {
        return Promise.resolve({ rows: trustedRows });
      }
      return Promise.resolve({ rows: [] });
    });

    const res = await request.post('/api/death/initiate').send({
      subject_did: 'did:exo:victim',
      initiated_by_did: 'did:exo:trusted-primary',
      required_confirmations: 2,
      authorized_trustees: [
        { did: 'did:exo:attacker-one', public_key_hex: 'aa'.repeat(32) },
        { did: 'did:exo:attacker-two', public_key_hex: 'bb'.repeat(32) },
      ],
      claim_nonce_hex: 'cafe',
      initiator_signature_hex: 'dd'.repeat(64),
      created_physical_ms: 1000,
      created_logical: 0,
    });

    expect(res.status).toBe(201);
    const authorizedTrusteesJson = mockWasm.wasm_death_verification_new.mock.calls[0][3];
    expect(JSON.parse(authorizedTrusteesJson)).toEqual([
      { did: 'did:exo:trusted-primary', public_key_hex: '11'.repeat(32) },
      { did: 'did:exo:trusted-alternate', public_key_hex: '22'.repeat(32) },
    ]);
  });

  it('fails closed when accepted PACE trustees do not have enough registered signing keys', async () => {
    mockPg.query.mockImplementation((sql) => {
      if (String(sql).includes('FROM pace_network')) {
        return Promise.resolve({ rows: [trustedRows[0]] });
      }
      return Promise.resolve({ rows: [] });
    });

    const res = await request.post('/api/death/initiate').send({
      subject_did: 'did:exo:victim',
      initiated_by_did: 'did:exo:trusted-primary',
      required_confirmations: 2,
      authorized_trustees: [
        { did: 'did:exo:attacker-one', public_key_hex: 'aa'.repeat(32) },
        { did: 'did:exo:attacker-two', public_key_hex: 'bb'.repeat(32) },
      ],
      claim_nonce_hex: 'cafe',
      initiator_signature_hex: 'dd'.repeat(64),
      created_physical_ms: 1000,
      created_logical: 0,
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/accepted PACE trustees/);
    expect(mockWasm.wasm_death_verification_new).not.toHaveBeenCalled();
  });
});

describe('POST /api/death/confirm trustee boundary', () => {
  it('uses the public key bound into stored verification state instead of request body key material', async () => {
    const storedState = {
      subject_did: 'did:exo:victim',
      authorized_trustees: [
        { did: 'did:exo:trusted-alternate', public_key_hex: '22'.repeat(32) },
      ],
      confirmations: [],
      status: 'Pending',
    };

    mockPg.query
      .mockResolvedValueOnce({
        rows: [{
          id: 'death-1',
          subject_did: 'did:exo:victim',
          status: 'pending',
          required_confirmations: 2,
          verification_state: storedState,
        }],
      })
      .mockResolvedValueOnce({ rows: [] });

    const res = await request.post('/api/death/confirm').send({
      verification_id: 'death-1',
      trustee_did: 'did:exo:trusted-alternate',
      trustee_public_key_hex: 'aa'.repeat(32),
      signature_hex: 'bb'.repeat(64),
      confirmed_physical_ms: 2000,
      confirmed_logical: 0,
    });

    expect(res.status).toBe(200);
    expect(mockWasm.wasm_death_verification_confirm).toHaveBeenCalledWith(
      JSON.stringify(storedState),
      'did:exo:trusted-alternate',
      '22'.repeat(32),
      'bb'.repeat(64),
      2000n,
      0,
    );
  });
});
