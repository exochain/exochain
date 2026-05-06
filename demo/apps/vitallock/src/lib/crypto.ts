/**
 * VitalLock Crypto — Browser-side WASM wrapper for E2E encryption.
 *
 * All plaintext encryption/decryption happens in the browser via WASM.
 * The server never sees plaintext.
 */

let initialized = false;
const CRYPTO_BOUNDARY_ERROR =
  'VitalLock EXOCHAIN crypto is unavailable: this adjacent prototype has no tested browser WASM/core adapter configured';

function unavailable(): never {
  throw new Error(CRYPTO_BOUNDARY_ERROR);
}

/** Initialize the WASM module. Must be called before any crypto operation. */
export async function initCrypto(): Promise<void> {
  initialized = false;
  unavailable();
}

export function cryptoUnavailableMessage(): string {
  return CRYPTO_BOUNDARY_ERROR;
}

/** Derive an Ed25519 public key hex string from a caller-held secret key. */
export function ed25519PublicFromSecret(secretKeyHex: string): string {
  void secretKeyHex;
  return unavailable();
}

/** Check if WASM is initialized. */
export function isCryptoReady(): boolean {
  return initialized;
}

// ── Key Generation ──

export interface X25519KeyPair {
  public_key_hex: string;
  secret_key_hex: string;
}

/** Generate an X25519 keypair (for encryption key exchange). */
export function generateX25519Keypair(): X25519KeyPair {
  return unavailable();
}

// ── Message Encryption (E2E) ──

export interface EncryptedEnvelope {
  id: string;
  sender_did: string;
  recipient_did: string;
  ephemeral_public_key: number[];
  ciphertext: number[];
  content_type: string;
  signature: object;
  plaintext_hash: number[];
  release_on_death: boolean;
  release_delay_hours: number;
  created: { physical_ms: number; logical: number };
}

/**
 * Lock & Send: encrypt a message client-side.
 * Plaintext never leaves the browser.
 */
export function encryptMessage(
  plaintext: string,
  contentType: string,
  senderDid: string,
  recipientDid: string,
  senderSigningKeyHex: string,
  recipientX25519PublicHex: string,
  messageId: string,
  createdPhysicalMs: bigint,
  createdLogical: number,
  releaseOnDeath: boolean = false,
  releaseDelayHours: number = 0,
): EncryptedEnvelope {
  void [
    plaintext,
    contentType,
    senderDid,
    recipientDid,
    senderSigningKeyHex,
    recipientX25519PublicHex,
    messageId,
    createdPhysicalMs,
    createdLogical,
    releaseOnDeath,
    releaseDelayHours,
  ];
  return unavailable();
}

/**
 * Unlock: decrypt a message client-side.
 * Returns the plaintext string.
 */
export function decryptMessage(
  envelopeJson: string,
  recipientX25519SecretHex: string,
  senderEd25519PublicHex: string,
): { plaintext: string; content_type: string } {
  void [envelopeJson, recipientX25519SecretHex, senderEd25519PublicHex];
  return unavailable();
}

/** Verify the sender's signature without decrypting. */
export function verifyMessageSignature(
  envelopeJson: string,
  senderEd25519PublicHex: string,
): boolean {
  void [envelopeJson, senderEd25519PublicHex];
  return unavailable();
}

// ── Shamir Secret Sharing ──

export interface ShamirShare {
  index: number;
  data: number[];
  commitment: number[];
}

/**
 * Split a secret into Shamir shares.
 * Default: threshold=3, shares=4 (3-of-4 PACE).
 */
export function shamirSplit(
  secret: Uint8Array,
  threshold: number = 3,
  shares: number = 4,
): ShamirShare[] {
  void [secret, threshold, shares];
  return unavailable();
}

// ── Death Verification ──

export interface DeathVerificationState {
  subject_did: string;
  initiated_by: string;
  required_confirmations: number;
  authorized_trustees: Record<string, number[]>;
  claim_nonce: number[];
  confirmations: Array<{
    trustee_did: string;
    public_key: number[];
    signature: { Ed25519: number[] } | { Hybrid: unknown } | { PostQuantum: number[] } | 'Empty';
    confirmed_at: object;
  }>;
  status: 'Pending' | 'Verified' | 'Rejected';
}

export interface AuthorizedDeathVerificationTrustee {
  did: string;
  public_key_hex: string;
}

/** Compute the bytes the initiating trustee must sign for a death claim. */
export function deathVerificationInitialSigningPayload(
  subjectDid: string,
  initiatedByDid: string,
  authorizedTrustees: AuthorizedDeathVerificationTrustee[],
  claimNonceHex: string,
  requiredConfirmations: number = 3,
): Uint8Array {
  void [subjectDid, initiatedByDid, authorizedTrustees, claimNonceHex, requiredConfirmations];
  return unavailable();
}

/** Create a new death verification request. */
export function createDeathVerification(
  subjectDid: string,
  initiatedByDid: string,
  authorizedTrustees: AuthorizedDeathVerificationTrustee[],
  claimNonceHex: string,
  initiatorSignatureHex: string,
  createdPhysicalMs: bigint,
  createdLogical: number,
  requiredConfirmations: number = 3,
): DeathVerificationState {
  void [
    subjectDid,
    initiatedByDid,
    requiredConfirmations,
    authorizedTrustees,
    claimNonceHex,
    initiatorSignatureHex,
    createdPhysicalMs,
    createdLogical,
  ];
  return unavailable();
}

/** Compute the bytes a trustee must sign to confirm an existing death claim. */
export function deathVerificationConfirmationSigningPayload(
  stateJson: string,
  trusteeDid: string,
): Uint8Array {
  void [stateJson, trusteeDid];
  return unavailable();
}

/** Add a trustee confirmation to a death verification. */
export function confirmDeathVerification(
  stateJson: string,
  trusteeDid: string,
  trusteePublicKeyHex: string,
  signatureHex: string,
  confirmedPhysicalMs: bigint,
  confirmedLogical: number,
): { verified: boolean; confirmations_remaining: number; state: DeathVerificationState } {
  void [
    stateJson,
    trusteeDid,
    trusteePublicKeyHex,
    signatureHex,
    confirmedPhysicalMs,
    confirmedLogical,
  ];
  return unavailable();
}
