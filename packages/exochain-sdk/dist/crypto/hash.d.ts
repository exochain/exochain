/**
 * Hashing primitives.
 *
 * A-050: the TS SDK now uses BLAKE3 (via @noble/hashes) to match the Rust SDK
 * and fabric. A DID derived from a public key in this SDK will be byte-identical
 * to a DID derived from the same key in the Rust or Python SDK. The SHA-256
 * helpers are retained because other parts of the SDK (proposal IDs, receipts)
 * may still want them; they are no longer used for DID derivation.
 */
import type { Hash256 } from '../types.js';
/** Compute BLAKE3 over `data` and return the raw 32-byte digest. (A-050) */
export declare function blake3(data: Uint8Array): Uint8Array;
/** Compute SHA-256 over `data` and return the raw 32-byte digest. */
export declare function sha256(data: Uint8Array): Promise<Uint8Array>;
/** Compute SHA-256 and return a 64-character lowercase hex string. */
export declare function sha256Hex(data: Uint8Array): Promise<string>;
/** Compute SHA-256 and return a {@link Hash256} branded hex string. */
export declare function sha256Hash(data: Uint8Array): Promise<Hash256>;
/** Encode a byte array as a lowercase hex string. */
export declare function bytesToHex(bytes: Uint8Array): string;
/** Decode a hex string (odd length not permitted) into bytes. */
export declare function hexToBytes(hex: string): Uint8Array;
//# sourceMappingURL=hash.d.ts.map