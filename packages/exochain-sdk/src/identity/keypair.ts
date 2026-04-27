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

import { IdentityError } from '../errors.js';
import type { Did } from '../types.js';
import { bytesToHex, hexToBytes, sha256 } from '../crypto/hash.js';
import { validateDid } from './did.js';

const ED25519: EcKeyImportParams = { name: 'Ed25519' } as unknown as EcKeyImportParams;
const KEYPAIR_PROOF_MESSAGE = new TextEncoder().encode('exo.sdk.identity.keypair.v1');

const subtle: SubtleCrypto = (() => {
  const c = globalThis.crypto;
  if (c === undefined || c.subtle === undefined) {
    throw new IdentityError(
      'Web Crypto API is unavailable. Requires Node >= 20 or a modern browser.',
    );
  }
  return c.subtle;
})();

/**
 * Derive `did:exo:<first 16 hex chars of SHA-256(publicKey)>`.
 * Exported for advanced callers who need the same derivation without an
 * `Identity` instance.
 */
export async function deriveDid(publicKey: Uint8Array): Promise<Did> {
  const digest = await sha256(publicKey);
  const first8 = digest.slice(0, 8);
  const hex = bytesToHex(first8);
  return validateDid(`did:exo:${hex}`);
}

interface ImportedIdentityKeypair {
  readonly rawPublicKey: Uint8Array;
  readonly publicKeyHex: string;
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
}

async function importIdentityKeypair(args: {
  publicKeyHex: string;
  privateKeyPkcs8: Uint8Array;
}): Promise<ImportedIdentityKeypair> {
  const rawPub = hexToBytes(args.publicKeyHex);
  if (rawPub.length !== 32) {
    throw new IdentityError(`public key must be 32 bytes, got ${rawPub.length}`);
  }
  let privateKey: CryptoKey;
  let publicKey: CryptoKey;
  try {
    privateKey = await subtle.importKey(
      'pkcs8',
      args.privateKeyPkcs8 as BufferSource,
      ED25519,
      true,
      ['sign'],
    );
    publicKey = await subtle.importKey('raw', rawPub as BufferSource, ED25519, true, [
      'verify',
    ]);
  } catch (err) {
    throw new IdentityError('failed to import keypair', { cause: err });
  }
  let matches = false;
  try {
    const proof = await subtle.sign(ED25519, privateKey, KEYPAIR_PROOF_MESSAGE);
    matches = await subtle.verify(
      ED25519,
      publicKey,
      proof,
      KEYPAIR_PROOF_MESSAGE,
    );
  } catch (err) {
    throw new IdentityError('failed to verify keypair binding', { cause: err });
  }
  if (!matches) {
    throw new IdentityError('private key does not match public key');
  }
  return {
    rawPublicKey: rawPub,
    publicKeyHex: args.publicKeyHex,
    privateKey,
    publicKey,
  };
}

/** A DID paired with an Ed25519 keypair and a human-readable label. */
export class Identity {
  public readonly did: Did;
  public readonly publicKeyHex: string;
  public readonly label: string;
  readonly #privateKey: CryptoKey;
  readonly #publicKey: CryptoKey;

  private constructor(args: {
    did: Did;
    publicKeyHex: string;
    label: string;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
  }) {
    this.did = args.did;
    this.publicKeyHex = args.publicKeyHex;
    this.label = args.label;
    this.#privateKey = args.privateKey;
    this.#publicKey = args.publicKey;
  }

  /** Generate a fresh identity with a random Ed25519 keypair. */
  public static async generate(label: string): Promise<Identity> {
    if (typeof label !== 'string') {
      throw new IdentityError('label must be a string');
    }
    let pair: CryptoKeyPair;
    try {
      pair = (await subtle.generateKey(ED25519, true, [
        'sign',
        'verify',
      ])) as CryptoKeyPair;
    } catch (err) {
      throw new IdentityError('failed to generate Ed25519 keypair', { cause: err });
    }
    const rawPub = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
    const did = await deriveDid(rawPub);
    return new Identity({
      did,
      publicKeyHex: bytesToHex(rawPub),
      label,
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
    });
  }

  /**
   * Rebuild an identity from an existing raw key pair (hex-encoded 32-byte
   * seed for the private key, and 32-byte raw public key). Useful for tests
   * and deterministic fixtures.
   */
  public static async fromKeypair(args: {
    label: string;
    publicKeyHex: string;
    privateKeyPkcs8: Uint8Array;
  }): Promise<Identity> {
    const imported = await importIdentityKeypair(args);
    const did = await deriveDid(imported.rawPublicKey);
    return new Identity({
      did,
      publicKeyHex: imported.publicKeyHex,
      label: args.label,
      privateKey: imported.privateKey,
      publicKey: imported.publicKey,
    });
  }

  /**
   * Rebuild an identity from an existing raw key pair while preserving a DID
   * resolved from the canonical fabric.
   *
   * This constructor does not derive a local TypeScript DID. Use it when a
   * gateway or DID-document resolver has already bound the supplied public key
   * to a canonical `did:exo:` identifier.
   */
  public static async fromResolvedKeypair(args: {
    label: string;
    did: Did | string;
    publicKeyHex: string;
    privateKeyPkcs8: Uint8Array;
  }): Promise<Identity> {
    const did = validateDid(args.did);
    const imported = await importIdentityKeypair(args);
    return new Identity({
      did,
      publicKeyHex: imported.publicKeyHex,
      label: args.label,
      privateKey: imported.privateKey,
      publicKey: imported.publicKey,
    });
  }

  /** Sign `message` with this identity's private key. Returns a 64-byte signature. */
  public async sign(message: Uint8Array): Promise<Uint8Array> {
    try {
      const sig = await subtle.sign(ED25519, this.#privateKey, message as BufferSource);
      return new Uint8Array(sig);
    } catch (err) {
      throw new IdentityError('signing failed', { cause: err });
    }
  }

  /** Verify `signature` over `message` against this identity's public key. */
  public async verifySelf(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    try {
      return await subtle.verify(
        ED25519,
        this.#publicKey,
        signature as BufferSource,
        message as BufferSource,
      );
    } catch {
      return false;
    }
  }

  /** Verify a signature against an arbitrary raw public-key hex string. */
  public static async verify(
    publicKeyHex: string,
    message: Uint8Array,
    signature: Uint8Array,
  ): Promise<boolean> {
    let pub: CryptoKey;
    try {
      const raw = hexToBytes(publicKeyHex);
      if (raw.length !== 32) {
        return false;
      }
      pub = await subtle.importKey('raw', raw as BufferSource, ED25519, true, ['verify']);
    } catch {
      return false;
    }
    try {
      return await subtle.verify(
        ED25519,
        pub,
        signature as BufferSource,
        message as BufferSource,
      );
    } catch {
      return false;
    }
  }
}
