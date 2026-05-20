/**
 * Hashing primitives.
 *
 * BLAKE3 is used where the SDK must match Rust fabric derivations, including
 * local DID derivation. SHA-256 remains available for client-side proposal
 * IDs, decision IDs, and compatibility with existing TypeScript SDK records.
 */
import type { Hash256 } from '../types.js';
/** Compute SHA-256 over `data` and return the raw 32-byte digest. */
export declare function sha256(data: Uint8Array): Promise<Uint8Array>;
/** Compute SHA-256 and return a 64-character lowercase hex string. */
export declare function sha256Hex(data: Uint8Array): Promise<string>;
/** Compute SHA-256 and return a {@link Hash256} branded hex string. */
export declare function sha256Hash(data: Uint8Array): Promise<Hash256>;
/** Compute BLAKE3 over `data` and return the raw 32-byte digest. */
export declare function blake3(data: Uint8Array): Uint8Array;
/** Compute BLAKE3 and return a 64-character lowercase hex string. */
export declare function blake3Hex(data: Uint8Array): string;
/** Compute BLAKE3 and return a {@link Hash256} branded hex string. */
export declare function blake3Hash(data: Uint8Array): Hash256;
/** Encode a byte array as a lowercase hex string. */
export declare function bytesToHex(bytes: Uint8Array): string;
/** Decode a canonical lowercase hex string (odd length not permitted) into bytes. */
export declare function hexToBytes(hex: string): Uint8Array;
//# sourceMappingURL=hash.d.ts.map
