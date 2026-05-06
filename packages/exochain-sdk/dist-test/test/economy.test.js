import { test } from 'node:test';
import { deepEqual, rejects, strictEqual } from 'node:assert/strict';
import { ExochainClient } from '../src/client.js';
import { TransportError } from '../src/errors.js';
const HASH = '1111111111111111111111111111111111111111111111111111111111111111';
function jsonResponse(body) {
    return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
    });
}
test('EconomyApi routes mission creation through EXOCHAIN economy API', async () => {
    const calls = [];
    const fetchImpl = async (input, init) => {
        calls.push({
            url: String(input),
            method: init?.method,
            body: typeof init?.body === 'string' ? init.body : undefined,
        });
        return jsonResponse({
            object: { mission_id: HASH, name: 'mission' },
            anchor: {
                anchor_hash: HASH,
                previous_anchor_hash: HASH,
                object_kind: 'mission',
                object_id: HASH,
                object_hash: HASH,
                created_at: { physical_ms: 1, logical: 0 },
            },
        });
    };
    const client = new ExochainClient({
        baseUrl: 'https://node.example',
        fetch: fetchImpl,
    });
    const result = await client.economy.createMission({ mission_id: HASH, name: 'mission' });
    strictEqual(calls[0]?.url, 'https://node.example/api/v1/economy/missions');
    strictEqual(calls[0]?.method, 'POST');
    deepEqual(JSON.parse(calls[0]?.body ?? '{}'), { mission_id: HASH, name: 'mission' });
    strictEqual(result.anchor.object_kind, 'mission');
    strictEqual(result.object.mission_id, HASH);
});
test('EconomyApi rejects non-object mutating bodies before fetch', async () => {
    const calls = [];
    const fetchImpl = async (_input, init) => {
        if (init !== undefined)
            calls.push(init);
        return jsonResponse({
            object: { mission_id: HASH },
            anchor: {
                anchor_hash: HASH,
                previous_anchor_hash: HASH,
                object_kind: 'mission',
                object_id: HASH,
                object_hash: HASH,
                created_at: { physical_ms: 1, logical: 0 },
            },
        });
    };
    const client = new ExochainClient({
        baseUrl: 'https://node.example',
        fetch: fetchImpl,
    });
    await rejects(() => client.economy.createMission('mission'), TransportError);
    strictEqual(calls.length, 0);
});
test('EconomyApi validates creation response anchors', async () => {
    const fetchImpl = async () => jsonResponse({
        object: { mission_id: HASH },
        anchor: {
            anchor_hash: 'not-a-hash',
            previous_anchor_hash: HASH,
            object_kind: 'mission',
            object_id: HASH,
            object_hash: HASH,
            created_at: { physical_ms: 1, logical: 0 },
        },
    });
    const client = new ExochainClient({
        baseUrl: 'https://node.example',
        fetch: fetchImpl,
    });
    await rejects(() => client.economy.createMission({ mission_id: HASH }), TransportError);
});
test('EconomyApi reads legacy receipts from EXOCHAIN economy API', async () => {
    const calls = [];
    const fetchImpl = async (input) => {
        calls.push(String(input));
        return jsonResponse({ legacy_receipt_id: HASH, status: 'Proposed' });
    };
    const client = new ExochainClient({
        baseUrl: 'https://node.example/',
        fetch: fetchImpl,
    });
    const result = await client.economy.getLegacyReceipt(HASH);
    strictEqual(calls[0], `https://node.example/api/v1/economy/legacy-receipts/${HASH}`);
    strictEqual(result.legacy_receipt_id, HASH);
});
//# sourceMappingURL=economy.test.js.map