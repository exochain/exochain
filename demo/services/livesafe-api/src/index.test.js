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
  wasm_generate_x25519_keypair: vi.fn(() => ({
    public_key_hex: 'a'.repeat(64),
    secret_key_hex: 'b'.repeat(64),
  })),
}));

vi.hoisted(() => {
  process.env.LIVESAFE_API_TOKENS = JSON.stringify({
    'owner-token': { actor_did: 'did:exo:owner1', role: 'owner' },
    'responder-token': { actor_did: 'did:exo:responder1', role: 'responder' },
    'admin-token': { actor_did: 'did:exo:admin1', role: 'admin' },
  });
});

vi.mock('module', async (importOriginal) => {
  const original = await importOriginal();
  return {
    ...original,
    createRequire: () => (id) => {
      if (id === '@exochain/exochain-wasm') return mockWasm;
      throw new Error(`Unexpected require('${id}')`);
    },
  };
});

const mockQuery = vi.hoisted(() => vi.fn());
vi.mock('pg', () => {
  const Pool = vi.fn(() => ({ query: mockQuery }));
  return { default: { Pool } };
});

import { server } from './index.js';

const request = supertest(server);

beforeEach(() => {
  vi.clearAllMocks();
});

afterAll(async () => {
  if (server.listening) {
    await new Promise((resolve) => server.close(resolve));
  }
});

function withAuth(req, token = 'owner-token') {
  return req.set('Authorization', `Bearer ${token}`);
}

function iceCard(ownerDid = 'did:exo:owner1') {
  return {
    id: 'card-1',
    owner_did: ownerDid,
    full_name: 'Alice Owner',
    date_of_birth: '1970-01-01',
    blood_type: 'O+',
    allergies: ['penicillin'],
    medications: ['insulin'],
    medical_conditions: ['diabetes'],
    emergency_contacts: [{ name: 'Bob', phone: '+15551234567', relationship: 'spouse' }],
    insurance_info: 'policy-123',
    organ_donor: true,
    dnr: false,
    special_instructions: 'Use blue kit',
    qr_token: 'qr-token',
    card_status: 'active',
    created_at_ms: 1_000,
  };
}

describe('LiveSafe API authentication boundary', () => {
  it('rejects unauthenticated ICE-card lookup before database access', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [iceCard()] });

    const res = await request.get('/api/ice-card/did:exo:owner1');

    expect(res.status).toBe(401);
    expect(mockQuery).not.toHaveBeenCalled();
  });

  it('rejects authenticated lookup of another owner before database access', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [iceCard('did:exo:victim')] });

    const res = await withAuth(request.get('/api/ice-card/did:exo:victim'));

    expect(res.status).toBe(403);
    expect(mockQuery).not.toHaveBeenCalled();
  });

  it('rejects unauthenticated QR scans before database access', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [iceCard()] });

    const res = await request
      .post('/api/ice-card/scan/qr-token')
      .send({ responder_did: 'did:exo:attacker' });

    expect(res.status).toBe(401);
    expect(mockQuery).not.toHaveBeenCalled();
  });

  it('binds QR scan receipts to the authenticated responder instead of the body DID', async () => {
    mockQuery
      .mockResolvedValueOnce({ rows: [iceCard()] })
      .mockResolvedValueOnce({ rows: [] });

    const res = await withAuth(
      request.post('/api/ice-card/scan/qr-token'),
      'responder-token',
    ).send({ responder_did: 'did:exo:attacker' });

    expect(res.status).toBe(200);
    expect(res.body.card.owner_did).toBe('did:exo:owner1');
    expect(mockQuery.mock.calls[1][1][3]).toBe('did:exo:responder1');
  });

  it('binds profile updates to the authenticated owner instead of the body DID', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });

    const res = await withAuth(request.post('/api/profile')).send({
      did: 'did:exo:attacker',
      display_name: 'Alice',
      email: 'alice@example.test',
      x25519_public_key_hex: 'a'.repeat(64),
    });

    expect(res.status).toBe(200);
    expect(res.body.did).toBe('did:exo:owner1');
    expect(mockQuery.mock.calls[0][1][0]).toBe('did:exo:owner1');
  });

  it('rejects authenticated emergency plan lookup for another owner before database access', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [{ owner_did: 'did:exo:victim' }] });

    const res = await withAuth(request.get('/api/plans/did:exo:victim'));

    expect(res.status).toBe(403);
    expect(mockQuery).not.toHaveBeenCalled();
  });
});
