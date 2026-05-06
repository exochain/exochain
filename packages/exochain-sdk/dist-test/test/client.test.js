import { test } from 'node:test';
import { rejects, strictEqual } from 'node:assert/strict';
import { ExochainClient } from '../src/client.js';
import { TransportError } from '../src/errors.js';
import { validateDid } from '../src/identity/did.js';
const HASH_64 = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
function jsonFetch(body, status = 200) {
    const calls = [];
    const fetchImpl = (async (_input, init) => {
        if (init !== undefined) {
            calls.push(init);
        }
        return new Response(JSON.stringify(body), {
            status,
            headers: { 'content-type': 'application/json' },
        });
    });
    return { calls, fetch: fetchImpl };
}
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
test('identity.register rejects malformed DID response payloads', async () => {
    const transport = jsonFetch({ did: 'not-a-did' });
    const client = new ExochainClient({
        baseUrl: 'https://gateway.example',
        fetch: transport.fetch,
    });
    await rejects(() => client.identity.register({ id: validateDid('did:exo:alice') }), TransportError);
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