/**
 * Ed25519 Identity — a DID paired with a keypair.
 *
 * Built on the Web Crypto API, which supports Ed25519 natively on Node 20+
 * and modern browsers. The DID is derived deterministically from the raw
 * public-key bytes as a local SDK DID:
 *
 * ```text
 * did:exo: + first 16 hex chars of SHA-256(public_key_bytes)
 * ```
 *
 * This local DID is deterministic inside the TypeScript SDK, but it is not a
 * canonical fabric DID. For applications that need cross-SDK DIDs, obtain the
 * DID from the fabric and pass it into {@link Identity.fromResolvedKeypair}.
 */
import type { Did } from '../types.js';
/**
 * Derive `did:exo:<first 16 hex chars of SHA-256(publicKey)>`.
 * Exported for advanced callers who need the same derivation without an
 * `Identity` instance.
 */
export declare function deriveDid(publicKey: Uint8Array): Promise<Did>;
/** A DID paired with an Ed25519 keypair and a human-readable label. */
export declare class Identity {
    #private;
    readonly did: Did;
    readonly publicKeyHex: string;
    readonly label: string;
    private constructor();
    /** Generate a fresh identity with a random Ed25519 keypair. */
    static generate(label: string): Promise<Identity>;
    /**
     * Rebuild an identity from an existing raw key pair (hex-encoded 32-byte
     * seed for the private key, and 32-byte raw public key). Useful for tests
     * and deterministic fixtures.
     */
    static fromKeypair(args: {
        label: string;
        publicKeyHex: string;
        privateKeyPkcs8: Uint8Array;
    }): Promise<Identity>;
    /**
     * Rebuild an identity from an existing raw key pair while preserving a DID
     * resolved from the canonical fabric.
     *
     * This constructor does not derive a local TypeScript DID. Use it when a
     * gateway or DID-document resolver has already bound the supplied public key
     * to a canonical `did:exo:` identifier.
     */
    static fromResolvedKeypair(args: {
        label: string;
        did: Did | string;
        publicKeyHex: string;
        privateKeyPkcs8: Uint8Array;
    }): Promise<Identity>;
    /** Sign `message` with this identity's private key. Returns a 64-byte signature. */
    sign(message: Uint8Array): Promise<Uint8Array>;
    /** Verify `signature` over `message` against this identity's public key. */
    verifySelf(message: Uint8Array, signature: Uint8Array): Promise<boolean>;
    /** Verify a signature against an arbitrary raw public-key hex string. */
    static verify(publicKeyHex: string, message: Uint8Array, signature: Uint8Array): Promise<boolean>;
}
//# sourceMappingURL=keypair.d.ts.map