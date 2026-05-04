import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { strictEqual, ok, rejects, notStrictEqual } from 'node:assert/strict';
import { BailmentBuilder } from '../src/consent/bailment.js';
import { ConsentError, IdentityError } from '../src/errors.js';
const BAILOR = 'did:exo:alice';
const BAILEE = 'did:exo:bob';
const CREATED_AT_MS = 1_700_000_000_000;
const CREATED_AT_LOGICAL = 7;
test('BailmentBuilder happy path produces a full proposal', async () => {
    const p = await new BailmentBuilder(BAILOR, BAILEE)
        .scope('data:medical')
        .durationHours(24)
        .createdAtHlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build();
    strictEqual(p.bailor, BAILOR);
    strictEqual(p.bailee, BAILEE);
    strictEqual(p.scope, 'data:medical');
    strictEqual(p.durationHours, 24);
    strictEqual(p.proposalId.length, 64);
    ok(/^[0-9a-f]+$/.test(p.proposalId));
    strictEqual(p.createdAt, CREATED_AT_MS);
    strictEqual(p.createdAtLogical, CREATED_AT_LOGICAL);
});
test('BailmentBuilder rejects missing scope', async () => {
    await rejects(async () => new BailmentBuilder(BAILOR, BAILEE).durationHours(1).build(), ConsentError);
});
test('BailmentBuilder rejects empty scope', async () => {
    await rejects(async () => new BailmentBuilder(BAILOR, BAILEE).scope('').durationHours(1).build(), ConsentError);
});
test('BailmentBuilder rejects missing duration', async () => {
    await rejects(async () => new BailmentBuilder(BAILOR, BAILEE).scope('data').build(), ConsentError);
});
test('BailmentBuilder rejects missing caller-supplied HLC timestamp', async () => {
    await rejects(async () => new BailmentBuilder(BAILOR, BAILEE).scope('data').durationHours(1).build(), ConsentError);
});
test('BailmentBuilder rejects zero or negative duration', async () => {
    await rejects(async () => new BailmentBuilder(BAILOR, BAILEE).scope('data').durationHours(0).build(), ConsentError);
    await rejects(async () => new BailmentBuilder(BAILOR, BAILEE).scope('data').durationHours(-1).build(), ConsentError);
});
test('BailmentBuilder rejects non-integer duration', async () => {
    await rejects(async () => new BailmentBuilder(BAILOR, BAILEE).scope('data').durationHours(1.5).build(), ConsentError);
});
test('BailmentBuilder rejects durations outside JavaScript safe integer range', async () => {
    await rejects(async () => new BailmentBuilder(BAILOR, BAILEE)
        .scope('data')
        .durationHours(Number.MAX_SAFE_INTEGER + 1)
        .build(), ConsentError);
});
test('BailmentBuilder rejects invalid HLC timestamp fields', async () => {
    await rejects(async () => new BailmentBuilder(BAILOR, BAILEE)
        .scope('data')
        .durationHours(1)
        .createdAtHlc(0, 0)
        .build(), ConsentError);
    await rejects(async () => new BailmentBuilder(BAILOR, BAILEE)
        .scope('data')
        .durationHours(1)
        .createdAtHlc(CREATED_AT_MS, 0x1_0000_0000)
        .build(), ConsentError);
});
test('BailmentBuilder rejects invalid DIDs at construction', () => {
    try {
        new BailmentBuilder('not-a-did', BAILEE);
        throw new Error('should have thrown');
    }
    catch (e) {
        ok(e instanceof IdentityError);
    }
});
test('proposalId is deterministic for identical inputs', async () => {
    const p1 = await new BailmentBuilder(BAILOR, BAILEE)
        .scope('s')
        .durationHours(1)
        .createdAtHlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build();
    const p2 = await new BailmentBuilder(BAILOR, BAILEE)
        .scope('s')
        .durationHours(1)
        .createdAtHlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build();
    strictEqual(p1.proposalId, p2.proposalId);
});
test('proposalId differs when scope differs', async () => {
    const p1 = await new BailmentBuilder(BAILOR, BAILEE)
        .scope('s1')
        .durationHours(1)
        .createdAtHlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build();
    const p2 = await new BailmentBuilder(BAILOR, BAILEE)
        .scope('s2')
        .durationHours(1)
        .createdAtHlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build();
    notStrictEqual(p1.proposalId, p2.proposalId);
});
test('proposalId differs when caller-supplied HLC differs', async () => {
    const p1 = await new BailmentBuilder(BAILOR, BAILEE)
        .scope('s')
        .durationHours(1)
        .createdAtHlc(CREATED_AT_MS, CREATED_AT_LOGICAL)
        .build();
    const p2 = await new BailmentBuilder(BAILOR, BAILEE)
        .scope('s')
        .durationHours(1)
        .createdAtHlc(CREATED_AT_MS, CREATED_AT_LOGICAL + 1)
        .build();
    notStrictEqual(p1.proposalId, p2.proposalId);
});
test('BailmentBuilder source does not read wall-clock time', () => {
    const source = readFileSync(new URL('../../src/consent/bailment.ts', import.meta.url), 'utf8');
    ok(!source.includes('Date.now'));
});
//# sourceMappingURL=consent.test.js.map