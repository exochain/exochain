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

/**
 * Hashing primitives backed by the Web Crypto API.
 *
 * The Rust SDK uses BLAKE3 for content-addressing. This pure-JS reference
 * implementation uses SHA-256 instead, since BLAKE3 is not available in
 * Web Crypto. Hashes produced here are NOT interoperable with Rust-produced
 * hashes at the byte level — they serve as client-side content identifiers
 * for proposal IDs, decision IDs, and the like. For canonical fabric
 * hashes (e.g. trust receipts returned from the gateway), trust the
 * server-provided values.
 */

import { CryptoError } from '../errors.js';
import type { Hash256 } from '../types.js';

const subtle: SubtleCrypto = (() => {
  const c = globalThis.crypto;
  if (c === undefined || c.subtle === undefined) {
    throw new CryptoError(
      'Web Crypto API is unavailable. Requires Node >= 20 or a modern browser.',
    );
  }
  return c.subtle;
})();

/** Compute SHA-256 over `data` and return the raw 32-byte digest. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  try {
    // The `as BufferSource` cast is required because older TS lib defs typed
    // `digest` as accepting only `ArrayBuffer | ArrayBufferView`, which a
    // `Uint8Array` satisfies at runtime.
    const buf = await subtle.digest('SHA-256', data as BufferSource);
    return new Uint8Array(buf);
  } catch (err) {
    throw new CryptoError('SHA-256 digest failed', { cause: err });
  }
}

/** Compute SHA-256 and return a 64-character lowercase hex string. */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  const bytes = await sha256(data);
  return bytesToHex(bytes);
}

/** Compute SHA-256 and return a {@link Hash256} branded hex string. */
export async function sha256Hash(data: Uint8Array): Promise<Hash256> {
  const hex = await sha256Hex(data);
  return hex as Hash256;
}

/** Encode a byte array as a lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

/** Decode a hex string (odd length not permitted) into bytes. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new CryptoError(`hex string has odd length: ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new CryptoError(`invalid hex at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}
