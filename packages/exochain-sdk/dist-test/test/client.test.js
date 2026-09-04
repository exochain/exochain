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
import { test } from 'node:test';
import { rejects, strictEqual } from 'node:assert/strict';
import { ExochainClient } from '../src/client.js';
import { IdentityError, TransportError } from '../src/errors.js';
import { validateDid } from '../src/identity/did.js';
const HASH_64 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
function jsonFetch(body, status = 200) {
    const inputs = [];
    const calls = [];
    const fetchImpl = (async (input, init) => {
        inputs.push(input);
        if (init !== undefined) {
            calls.push(init);
        }
        return new Response(JSON.stringify(body), {
            status,
            headers: { 'content-type': 'application/json' },
        });
    });
    return { inputs, calls, fetch: fetchImpl };
}
const HASH_PATH_CALLS = [
    {
        context: 'consent.getBailment proposalId',
        path: `/consent/bailment/${HASH_64}`,
        invoke: (client, id) => client.consent.getBailment(id),
    },
    {
        context: 'governance.castVote decisionId',
        path: `/governance/decision/${HASH_64}/vote`,
        invoke: (client, id) => client.governance.castVote(id, {}),
    },
    {
        context: 'governance.getDecision decisionId',
        path: `/governance/decision/${HASH_64}`,
        invoke: (client, id) => client.governance.getDecision(id),
    },
    {
        context: 'authority.getChain chainId',
        path: `/authority/chain/${HASH_64}`,
        invoke: (client, id) => client.authority.getChain(id),
    },
    {
        context: 'economy.getMission id',
        path: `/api/v1/economy/missions/${HASH_64}`,
        invoke: (client, id) => client.economy.getMission(id),
    },
    {
        context: 'economy.getLegacyReceipt id',
        path: `/api/v1/economy/legacy-receipts/${HASH_64}`,
        invoke: (client, id) => client.economy.getLegacyReceipt(id),
    },
];
test('health rejects malformed gateway payloads instead of trusting casts', async () => {
    const transport = jsonFetch({ status: 'ok', version: '0.1.0', uptime: 'not-a-number' });
    const client = new ExochainClient({
        baseUrl: 'https://gateway.example',
        fetch: transport.fetch,
    });
    await rejects(() => client.health(), TransportError);
});
test('health accepts a valid gateway payload', async () => {
    const transport = jsonFetch({ status: 'ok', version: '0.1.0', uptime: 42 });
    const client = new ExochainClient({
        baseUrl: 'https://gateway.example',
        fetch: transport.fetch,
    });
    const health = await client.health();
    strictEqual(health.status, 'ok');
    strictEqual(health.version, '0.1.0');
    strictEqual(health.uptime, 42);
});
test('discover fetches and validates the public EXOCHAIN discovery document', async () => {
    const transport = jsonFetch({
        base_url: 'https://exochain.io',
        routes: {
            health: '/health',
            ready: '/ready',
            avc: {
                issue: '/api/v1/avc/issue',
                validate: '/api/v1/avc/validate',
                receipts_emit: '/api/v1/avc/receipts/emit',
                receipts_get: '/api/v1/avc/receipts/:hash',
                protocol: '/api/v1/avc/protocol',
            },
        },
        sdk: {
            rust: 'crates/exochain-sdk',
            typescript: 'packages/exochain-sdk',
            python: 'packages/exochain-py',
        },
        mcp: {
            public_transport: false,
            transports: ['stdio', 'loopback-sse'],
            capabilities: ['tools', 'resources', 'prompts'],
        },
    });
    const client = new ExochainClient({
        baseUrl: 'https://gateway.example',
        fetch: transport.fetch,
    });
    const discovery = await client.discover();
    strictEqual(String(transport.inputs[0]), 'https://gateway.example/.well-known/exochain.json');
    strictEqual(discovery.base_url, 'https://exochain.io');
    strictEqual(discovery.routes.avc.receipts_emit, '/api/v1/avc/receipts/emit');
    strictEqual(discovery.sdk.typescript, 'packages/exochain-sdk');
    strictEqual(discovery.mcp.public_transport, false);
    strictEqual(discovery.mcp.transports[1], 'loopback-sse');
    strictEqual(discovery.mcp.capabilities[2], 'prompts');
});
test('discover rejects malformed MCP discovery metadata', async () => {
    const transport = jsonFetch({
        base_url: 'https://exochain.io',
        routes: {
            health: '/health',
            ready: '/ready',
            avc: {
                issue: '/api/v1/avc/issue',
                validate: '/api/v1/avc/validate',
                receipts_emit: '/api/v1/avc/receipts/emit',
                receipts_get: '/api/v1/avc/receipts/:hash',
                protocol: '/api/v1/avc/protocol',
            },
        },
        sdk: {
            rust: 'crates/exochain-sdk',
            typescript: 'packages/exochain-sdk',
            python: 'packages/exochain-py',
        },
        mcp: {
            public_transport: 'false',
            transports: ['stdio', 'loopback-sse'],
            capabilities: ['tools', 'resources', 'prompts'],
        },
    });
    const client = new ExochainClient({
        baseUrl: 'https://gateway.example',
        fetch: transport.fetch,
    });
    await rejects(() => client.discover(), TransportError);
});
test('identity.register rejects malformed DID response payloads', async () => {
    const transport = jsonFetch({ did: 'not-a-did' });
    const client = new ExochainClient({
        baseUrl: 'https://gateway.example',
        fetch: transport.fetch,
    });
    await rejects(() => client.identity.register({ id: validateDid('did:exo:alice') }), TransportError);
});
test('identity.resolve rejects forged branded DIDs before fetch', async () => {
    for (const invalidDid of ['.', '..', '%2E', '%2E%2E', 'not-a-did']) {
        const transport = jsonFetch({});
        const client = new ExochainClient({
            baseUrl: 'https://gateway.example',
            fetch: transport.fetch,
        });
        await rejects(() => client.identity.resolve(invalidDid), IdentityError);
        strictEqual(transport.inputs.length, 0, `identity.resolve must reject ${invalidDid} before fetch`);
    }
});
test('identity.resolve preserves a validated DID on the wire', async () => {
    const transport = jsonFetch({});
    const client = new ExochainClient({
        baseUrl: 'https://gateway.example',
        fetch: transport.fetch,
    });
    await client.identity.resolve(validateDid('did:exo:alice.node'));
    strictEqual(String(transport.inputs[0]), 'https://gateway.example/identity/did/did%3Aexo%3Aalice.node');
});
test('mutating calls reject non-object request bodies before fetch', async () => {
    const transport = jsonFetch({ proposalId: HASH_64 });
    const client = new ExochainClient({
        baseUrl: 'https://gateway.example',
        fetch: transport.fetch,
    });
    await rejects(() => client.consent.proposeBailment('not-json-object'), TransportError);
    strictEqual(transport.calls.length, 0);
});
test('public hash-ID paths reject noncanonical runtime values before fetch', async () => {
    const invalidIds = [
        '.',
        '..',
        '%2E',
        '%2E%2E',
        'a'.repeat(63),
        'a'.repeat(65),
        'g'.repeat(64),
        'A'.repeat(64),
    ];
    for (const call of HASH_PATH_CALLS) {
        for (const invalidId of invalidIds) {
            const transport = jsonFetch({});
            const client = new ExochainClient({
                baseUrl: 'https://gateway.example',
                fetch: transport.fetch,
            });
            await rejects(() => call.invoke(client, invalidId), (error) => error instanceof TransportError &&
                error.message.includes(call.context) &&
                error.message.includes('64-character lowercase hex hash'));
            strictEqual(transport.inputs.length, 0, `${call.context} must reject ${invalidId} before fetch`);
        }
    }
});
test('public hash-ID paths preserve canonical IDs on the wire', async () => {
    for (const call of HASH_PATH_CALLS) {
        const transport = jsonFetch({ decisionId: HASH_64, status: 'proposed' });
        const client = new ExochainClient({
            baseUrl: 'https://gateway.example',
            fetch: transport.fetch,
        });
        await call.invoke(client, HASH_64);
        strictEqual(String(transport.inputs[0]), `https://gateway.example${call.path}`);
    }
});
test('governance.createDecision rejects malformed hash responses', async () => {
    const transport = jsonFetch({ decisionId: 'abc123' });
    const client = new ExochainClient({
        baseUrl: 'https://gateway.example',
        fetch: transport.fetch,
    });
    await rejects(() => client.governance.createDecision({ title: 'Ratify', proposer: 'did:exo:alice' }), TransportError);
});
test('governance.getDecision validates optional quorum payload shape', async () => {
    const transport = jsonFetch({
        decisionId: HASH_64,
        status: 'proposed',
        quorum: {
            met: true,
            threshold: 2,
            totalVotes: 3,
            approvals: 2,
            rejections: 0,
            abstentions: 'zero',
        },
    });
    const client = new ExochainClient({
        baseUrl: 'https://gateway.example',
        fetch: transport.fetch,
    });
    await rejects(() => client.governance.getDecision(HASH_64), TransportError);
});
//# sourceMappingURL=client.test.js.map