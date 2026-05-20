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
import { strictEqual, ok, throws, deepStrictEqual } from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  blake3,
  blake3Hash,
  blake3Hex,
  sha256,
  sha256Hex,
  sha256Hash,
  bytesToHex,
  hexToBytes,
} from '../src/crypto/hash.js';
import { CryptoError } from '../src/errors.js';

test('sha256 of empty input produces the known digest', async () => {
  const bytes = await sha256(new Uint8Array(0));
  strictEqual(bytes.length, 32);
  strictEqual(
    bytesToHex(bytes),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );
});

test('sha256Hex matches the known "abc" digest', async () => {
  const hex = await sha256Hex(new TextEncoder().encode('abc'));
  strictEqual(hex, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('sha256Hash returns a branded Hash256 (64 chars of hex)', async () => {
  const h = await sha256Hash(new TextEncoder().encode('x'));
  strictEqual(h.length, 64);
  ok(/^[0-9a-f]+$/.test(h));
});

test('blake3 of empty input produces the known digest', () => {
  const bytes = blake3(new Uint8Array(0));
  strictEqual(bytes.length, 32);
  strictEqual(
    bytesToHex(bytes),
    'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262',
  );
});

test('blake3Hex matches the known "abc" digest prefix used for interop', () => {
  const hex = blake3Hex(new TextEncoder().encode('abc'));
  strictEqual(hex, '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85');
});

test('blake3Hash returns a branded Hash256 (64 chars of hex)', () => {
  const h = blake3Hash(new TextEncoder().encode('x'));
  strictEqual(h.length, 64);
  ok(/^[0-9a-f]+$/.test(h));
});

test('bytesToHex / hexToBytes are inverses', () => {
  const bytes = new Uint8Array([0, 1, 15, 16, 255]);
  const hex = bytesToHex(bytes);
  strictEqual(hex, '00010f10ff');
  deepStrictEqual(hexToBytes(hex), bytes);
});

test('hexToBytes rejects odd-length input', () => {
  throws(() => hexToBytes('abc'), CryptoError);
});

test('hexToBytes rejects non-hex characters', () => {
  throws(() => hexToBytes('zz'), CryptoError);
});

test('hexToBytes rejects partial-parse and signed byte aliases', () => {
  for (const input of ['f_', '1g', '+1', '-1', ' 1', '0 ']) {
    throws(() => hexToBytes(input), CryptoError, `${input} must be rejected`);
  }
});

test('hexToBytes rejects non-canonical uppercase hex', () => {
  throws(() => hexToBytes('AB'), CryptoError);
});

test('hexToBytes source does not use partial numeric parsing', () => {
  const source = readFileSync(new URL('../../src/crypto/hash.ts', import.meta.url), 'utf8');
  const forbiddenParser = ['parse', 'Int'].join('');
  ok(
    !source.includes(forbiddenParser),
    'hex decoding must not use partial numeric parser semantics',
  );
});

test('Different inputs produce different digests', async () => {
  const a = await sha256Hex(new TextEncoder().encode('a'));
  const b = await sha256Hex(new TextEncoder().encode('b'));
  ok(a !== b);
});
