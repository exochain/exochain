/**
 * EXOCHAIN SDK Client — bridges LiveSafe.ai to the EXOCHAIN GraphQL gateway.
 *
 * Phase 2 integration: All sovereign identity, audit, and custody operations
 * are anchored to EXOCHAIN for immutability and verifiability.
 *
 * Gateway: http://localhost:8080/graphql (configurable via EXOCHAIN_GATEWAY_URL)
 */

const crypto = require('node:crypto');

const {
  ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SCHEMA,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
  evaluatePublicAdapterOutputAuthorization,
} = require('./public-adapter-output-authorization.js');

const EXOCHAIN_GATEWAY = process.env.EXOCHAIN_GATEWAY_URL || 'http://localhost:8080/graphql';
const EXOCHAIN_DID_PATTERN = /^did:exo:[a-z0-9_-]+:[A-Za-z0-9._:-]+$/;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const CONSENT_SCOPE_PATTERN = /^[a-z0-9][a-z0-9_:-]*$/;
const ALLOWED_AUDIT_RECEIPT_EVENT_TYPES = new Set([
  'card_scan',
  'consent_granted',
  'consent_revoked',
]);
const EXOCHAIN_TIMEOUT_ERROR = 'EXOCHAIN_TIMEOUT';
const EXOCHAIN_UNAVAILABLE_ERROR = 'EXOCHAIN_UNAVAILABLE';
const EXOCHAIN_GATEWAY_REJECTED_ERROR = 'EXOCHAIN_GATEWAY_REJECTED';
const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_ROUTE =
  '/api/v1/avc/livesafe/public-adapter-output-authorization';
const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DEFAULT_TIMEOUT_MS = 5000;
const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DEFAULT_TTL_MS = 5 * 60 * 1000;
const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_MAX_TTL_MS = 5 * 60 * 1000;
const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DEFAULT_IDEMPOTENCY_NAMESPACE =
  'livesafe-public-adapter-output';
const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_PROOF_TYPE =
  'ed25519-public-adapter-output-authorization';
const SHA256_EVIDENCE_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const STRICT_UTC_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const PUBLIC_AUTHORIZATION_IDEMPOTENCY_NAMESPACE_PATTERN =
  /^[a-z0-9][a-z0-9_.:-]{0,79}$/;

function isRequiredTransportIdentifier(value) {
  return (
    (typeof value === 'string' && value.trim().length > 0) ||
    Number.isInteger(value)
  );
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function isExochainDid(value) {
  return isNonEmptyString(value) && EXOCHAIN_DID_PATTERN.test(value);
}

function isOptionalExochainDid(value) {
  return typeof value === 'undefined' || value === null || isExochainDid(value);
}

function isOptionalEpochMilliseconds(value) {
  return (
    typeof value === 'undefined' ||
    value === null ||
    (Number.isInteger(value) && value >= 0)
  );
}

function isOptionalSha256Hex(value) {
  return typeof value === 'undefined' || value === null || SHA256_HEX_PATTERN.test(value);
}

function isOptionalConsentScope(value) {
  return (
    typeof value === 'undefined' ||
    value === null ||
    (isNonEmptyString(value) && CONSENT_SCOPE_PATTERN.test(value))
  );
}

function hasExplicitField(input, fieldName) {
  return Boolean(input) && Object.prototype.hasOwnProperty.call(input, fieldName);
}

function isTimeoutLikeError(error) {
  if (!error || typeof error !== 'object') {
    return false;
  }

  const name = typeof error.name === 'string' ? error.name.toLowerCase() : '';
  const code = typeof error.code === 'string' ? error.code.toLowerCase() : '';
  const message = typeof error.message === 'string' ? error.message.toLowerCase() : '';

  return (
    name.includes('timeout') ||
    code.includes('timeout') ||
    code === 'etimedout' ||
    message.includes('timeout') ||
    message.includes('timed out') ||
    message.includes('etimedout')
  );
}

function createTransportError(code) {
  return { data: null, errors: [{ message: code, code }] };
}

function createPublicAuthorizationDenied(state = 'rejected') {
  return { state, value: null };
}

function isObjectRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function envString(name) {
  const value = process.env[name];
  return isNonEmptyString(value) ? value.trim() : '';
}

function parsePositiveInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function parseHash256Env(value) {
  if (!SHA256_EVIDENCE_HASH_PATTERN.test(value)) {
    return null;
  }

  const hex = value.slice('sha256:'.length);
  const bytes = [];
  for (let index = 0; index < hex.length; index += 2) {
    bytes.push(Number.parseInt(hex.slice(index, index + 2), 16));
  }

  return { canonical: value, bytes };
}

function parseStrictUtcTimestampEnv(value) {
  if (!STRICT_UTC_TIMESTAMP_PATTERN.test(value)) {
    return null;
  }

  const physicalMs = Date.parse(value);
  if (!Number.isSafeInteger(physicalMs) || physicalMs < 0) {
    return null;
  }

  if (new Date(physicalMs).toISOString() !== value) {
    return null;
  }

  return {
    physical_ms: physicalMs,
    logical: 0,
  };
}

function parsePublicAuthorizationBaseUrl(value) {
  if (!isNonEmptyString(value)) {
    return null;
  }

  try {
    const parsed = new URL(value);
    if (
      (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') ||
      parsed.username ||
      parsed.password
    ) {
      return null;
    }

    return value;
  } catch {
    return null;
  }
}

function parsePublicAuthorizationNamespace(value) {
  const namespace = isNonEmptyString(value)
    ? value.trim()
    : PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DEFAULT_IDEMPOTENCY_NAMESPACE;

  return PUBLIC_AUTHORIZATION_IDEMPOTENCY_NAMESPACE_PATTERN.test(namespace)
    ? namespace
    : null;
}

function parsePublicAuthorizationTtlMs(value) {
  if (!isNonEmptyString(value)) {
    return PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DEFAULT_TTL_MS;
  }

  if (!/^[1-9][0-9]*$/.test(value)) {
    return null;
  }

  const parsed = Number.parseInt(value, 10);
  if (
    !Number.isSafeInteger(parsed) ||
    parsed <= 0 ||
    parsed > PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_MAX_TTL_MS
  ) {
    return null;
  }

  return parsed;
}

function publicAuthorizationWindowStartMs(physicalMs, ttlMs) {
  return physicalMs - (physicalMs % ttlMs);
}

function publicAuthorizationIdempotencyDigest(material) {
  const canonicalMaterial = JSON.stringify({
    audience: material.audience,
    credential_id: material.credentialId,
    evidence_hash: material.evidenceHash,
    schema: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SCHEMA,
    subject: material.subject,
    ttl_ms: material.ttlMs,
    window_start_ms: material.windowStartMs,
  });

  return crypto
    .createHash('sha256')
    .update(canonicalMaterial, 'utf8')
    .digest('hex');
}

function buildPublicAdapterOutputAuthorizationRequest({
  subject,
  audience,
  credentialId,
  credentialIdBytes,
  evidenceHash,
  evidenceHashBytes,
  currentAt,
  namespace,
  ttlMs,
}) {
  if (
    !isNonEmptyString(subject) ||
    !isNonEmptyString(audience) ||
    !SHA256_EVIDENCE_HASH_PATTERN.test(credentialId || '') ||
    !SHA256_EVIDENCE_HASH_PATTERN.test(evidenceHash || '') ||
    !isByteArrayOfLength(credentialIdBytes, 32) ||
    !isByteArrayOfLength(evidenceHashBytes, 32) ||
    !isNonEmptyString(namespace) ||
    !PUBLIC_AUTHORIZATION_IDEMPOTENCY_NAMESPACE_PATTERN.test(namespace) ||
    !Number.isSafeInteger(ttlMs) ||
    ttlMs <= 0 ||
    ttlMs > PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_MAX_TTL_MS
  ) {
    return null;
  }

  const currentTimestamp = parseStrictUtcTimestampEnv(currentAt);
  if (!currentTimestamp) {
    return null;
  }

  const windowStartMs = publicAuthorizationWindowStartMs(
    currentTimestamp.physical_ms,
    ttlMs,
  );
  const expiresPhysicalMs = windowStartMs + ttlMs;
  if (!Number.isSafeInteger(expiresPhysicalMs)) {
    return null;
  }

  const digest = publicAuthorizationIdempotencyDigest({
    subject,
    audience,
    credentialId,
    evidenceHash,
    ttlMs,
    windowStartMs,
  });

  return {
    subject,
    audience,
    credential_id: [...credentialIdBytes],
    evidence_hash: [...evidenceHashBytes],
    idempotency_key: `${namespace}:sha256:${digest}`,
    expires_at: {
      physical_ms: expiresPhysicalMs,
      logical: 0,
    },
  };
}

function getPublicAdapterOutputAuthorizationConfig() {
  const baseUrl =
    envString('EXOCHAIN_NODE_AVC_URL') || envString('EXOCHAIN_NODE_URL');
  const bearer = envString('EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_BEARER');
  const credentialId = envString('EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_ID');
  const evidenceHash = envString('EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_EVIDENCE_HASH');
  const namespace = parsePublicAuthorizationNamespace(
    envString('EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_IDEMPOTENCY_NAMESPACE'),
  );
  const ttlMs = parsePublicAuthorizationTtlMs(
    envString('EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_TTL_MS'),
  );
  const timeoutMs = parsePositiveInteger(
    envString('EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_TIMEOUT_MS'),
    PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DEFAULT_TIMEOUT_MS,
  );
  const validatedBaseUrl = parsePublicAuthorizationBaseUrl(baseUrl);
  const credentialHash = parseHash256Env(credentialId);
  const evidenceHashValue = parseHash256Env(evidenceHash);

  if (
    !validatedBaseUrl ||
    !bearer ||
    !credentialHash ||
    !evidenceHashValue ||
    !namespace ||
    !ttlMs
  ) {
    return null;
  }

  return {
    baseUrl: validatedBaseUrl,
    bearer,
    credentialId: credentialHash.canonical,
    credentialIdBytes: credentialHash.bytes,
    evidenceHash: evidenceHashValue.canonical,
    evidenceHashBytes: evidenceHashValue.bytes,
    namespace,
    ttlMs,
    timeoutMs,
  };
}

function buildPublicAdapterOutputAuthorizationUrl(baseUrl) {
  return `${baseUrl.replace(/\/+$/, '')}${PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_ROUTE}`;
}

function coreTimestampToIso(value) {
  if (isNonEmptyString(value)) {
    const milliseconds = Date.parse(value);
    return Number.isNaN(milliseconds) ? null : new Date(milliseconds).toISOString();
  }

  if (Number.isInteger(value) && value >= 0) {
    return new Date(value).toISOString();
  }

  if (isObjectRecord(value)) {
    if (Number.isInteger(value.physical_ms) && value.physical_ms >= 0) {
      return new Date(value.physical_ms).toISOString();
    }

    if (Number.isInteger(value.physicalMs) && value.physicalMs >= 0) {
      return new Date(value.physicalMs).toISOString();
    }
  }

  return null;
}

function isCoreHlcTimestamp(value) {
  if (!isObjectRecord(value)) {
    return false;
  }

  const physicalMs = Number.isInteger(value.physical_ms)
    ? value.physical_ms
    : value.physicalMs;

  return (
    Number.isInteger(physicalMs) &&
    physicalMs >= 0 &&
    Number.isInteger(value.logical) &&
    value.logical >= 0
  );
}

const RAW_SENSITIVE_FIELD_KEYS = new Set([
  'authorization_header',
  'bearer_token',
  'credential_bytes',
  'emergency_contact',
  'location',
  'medical_record',
  'patient',
  'phi',
  'pii',
  'private_key',
  'raw_authority_chain',
  'raw_credential_bytes',
  'raw_sensitive_payload',
  'scan_payload',
  'trustee_did',
  'vault',
]);
const RAW_SENSITIVE_FIELD_FRAGMENTS = [
  'authority_chain',
  'bearer',
  'consent_record',
  'custody_record',
  'legal_record',
  'private_key',
  'scan_record',
  'trustee_record',
  'vault_record',
];

function keyLooksRawSensitive(key) {
  const normalized = String(key).toLowerCase();
  return (
    RAW_SENSITIVE_FIELD_KEYS.has(normalized) ||
    normalized.startsWith('raw_') ||
    RAW_SENSITIVE_FIELD_FRAGMENTS.some((fragment) => normalized.includes(fragment))
  );
}

function containsRawSensitiveField(value) {
  if (Array.isArray(value)) {
    return value.some((entry) => containsRawSensitiveField(entry));
  }

  if (!isObjectRecord(value)) {
    return false;
  }

  return Object.entries(value).some(([key, nestedValue]) => {
    if (keyLooksRawSensitive(key)) {
      return true;
    }

    return containsRawSensitiveField(nestedValue);
  });
}

function publicAuthorizationStateFromReasons(reasons) {
  const combined = reasons.join(' ').toLowerCase();

  if (combined.includes('revoked')) {
    return 'revoked';
  }

  if (combined.includes('contradicted')) {
    return 'contradicted';
  }

  if (
    combined.includes('expired') ||
    combined.includes('not yet valid') ||
    combined.includes('stale')
  ) {
    return 'stale';
  }

  return 'rejected';
}

function publicAuthorizationTransportErrorState(error) {
  const code = typeof error?.code === 'string' ? error.code.toLowerCase() : '';

  if (code === 'econnrefused' || code === 'enotfound' || code === 'econnreset') {
    return 'unavailable';
  }

  if (error?.name === 'AbortError' || isTimeoutLikeError(error)) {
    return 'timeout';
  }

  return 'unavailable';
}

function isByteArrayOfLength(value, expectedLength) {
  return (
    Array.isArray(value) &&
    value.length === expectedLength &&
    value.every(
      (byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255,
    )
  );
}

function bytesToLowerHex(bytes) {
  return bytes
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function normalizeHash256(value) {
  if (!isByteArrayOfLength(value, 32)) {
    return null;
  }

  return `sha256:${bytesToLowerHex(value)}`;
}

function normalizePublicAuthorizationIdentifier(value) {
  if (isNonEmptyString(value)) {
    return value;
  }

  return normalizeHash256(value);
}

function normalizePublicAuthorizationSignature(signature) {
  if (!isObjectRecord(signature)) {
    return null;
  }

  const keys = Object.keys(signature);
  if (keys.length !== 1 || keys[0] !== 'Ed25519') {
    return null;
  }

  const bytes = signature.Ed25519;
  if (!isByteArrayOfLength(bytes, 64)) {
    return null;
  }

  return `ed25519:${bytesToLowerHex(bytes)}`;
}

function publicAuthorizationRevocationState(revocationStatus) {
  if (!isNonEmptyString(revocationStatus)) {
    return 'rejected';
  }

  if (revocationStatus === 'NotRevoked') {
    return 'active';
  }

  const normalized = revocationStatus
    .trim()
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[\s-]+/g, '_')
    .toLowerCase();

  if (normalized === 'revoked') {
    return 'revoked';
  }

  return 'rejected';
}

function isValidSchemaVersion(value) {
  return value === 1;
}

function adaptCorePublicAdapterOutputAuthorizationEnvelope(
  envelope,
  { subject, audience },
) {
  if (!isObjectRecord(envelope)) {
    return { state: 'rejected', value: null };
  }

  if (containsRawSensitiveField(envelope)) {
    return { state: 'rejected', value: null };
  }

  if (envelope.domain !== PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SCHEMA) {
    return { state: 'rejected', value: null };
  }

  const proof = isObjectRecord(envelope.proof) ? envelope.proof : null;
  if (!proof) {
    return { state: 'rejected', value: null };
  }

  if (
    proof.domain !== PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SCHEMA ||
    proof.subject !== subject ||
    proof.audience !== audience
  ) {
    return { state: 'rejected', value: null };
  }

  if (
    !isValidSchemaVersion(envelope.schema_version) ||
    !isValidSchemaVersion(proof.schema_version)
  ) {
    return { state: 'rejected', value: null };
  }

  const revocationState = publicAuthorizationRevocationState(
    proof.revocation_status,
  );
  if (revocationState !== 'active') {
    return { state: revocationState, value: null };
  }

  const generatedAt = coreTimestampToIso(proof.issued_at);
  const expiresAt = coreTimestampToIso(proof.expires_at);
  const evidenceHash = normalizeHash256(proof.evidence_hash);
  const actionCommitmentHash = normalizeHash256(proof.action_commitment_hash);
  const idempotencyKeyHash = normalizeHash256(proof.idempotency_key_hash);
  const proofHash = normalizeHash256(proof.proof_hash);
  const credentialId = normalizePublicAuthorizationIdentifier(proof.credential_id);
  const receiptId = normalizePublicAuthorizationIdentifier(proof.receipt_id);
  const signature = normalizePublicAuthorizationSignature(proof.signature);
  if (
    !evidenceHash ||
    !actionCommitmentHash ||
    !idempotencyKeyHash ||
    !proofHash ||
    !credentialId ||
    !receiptId ||
    !signature ||
    !isNonEmptyString(proof.signer_did)
  ) {
    return { state: 'rejected', value: null };
  }

  return {
    state: 'permit',
    value: {
      schema: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SCHEMA,
      subject: proof.subject,
      audience: proof.audience,
      ...(isCoreHlcTimestamp(proof.issued_at)
        ? { timestamp_basis: 'exochain_hlc' }
        : {}),
      claims: [...ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS],
      evidence_hash: evidenceHash,
      receipt_id: receiptId,
      proof_id: proofHash,
      proof_ref: `exochain-avc:${proofHash}`,
      generated_at: generatedAt,
      valid_from: generatedAt,
      expires_at: expiresAt,
      proof: {
        type: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_PROOF_TYPE,
        signature,
      },
    },
  };
}

class ExochainClient {
  constructor(gatewayUrl = EXOCHAIN_GATEWAY) {
    this.gatewayUrl = gatewayUrl;
    this.connected = false;
  }

  async query(operationName, query, variables = {}) {
    try {
      const response = await fetch(this.gatewayUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, variables, operationName }),
      });
      if (!response.ok) {
        console.warn(`[EXOCHAIN] Gateway returned ${response.status}`);
        return createTransportError(EXOCHAIN_GATEWAY_REJECTED_ERROR);
      }
      return await response.json();
    } catch (err) {
      console.warn('[EXOCHAIN] Gateway unreachable: redacted transport failure');
      return createTransportError(
        isTimeoutLikeError(err) ? EXOCHAIN_TIMEOUT_ERROR : EXOCHAIN_UNAVAILABLE_ERROR,
      );
    }
  }

  // ── Identity ──────────────────────────────────────────────────

  async registerIdentity(did) {
    if (!isExochainDid(did)) {
      console.warn("[EXOCHAIN] registerIdentity rejected malformed DID before query");
      return null;
    }
    console.log(`[EXOCHAIN] Registering identity: ${did}`);
    try {
      const result = await this.query('RegisterIdentity', `
        mutation RegisterIdentity($did: String!) {
          livesafe_register_identity(did: $did) {
            did
            created_at
            status
          }
        }
      `, { did });
      if (result.errors) {
        console.warn(`[EXOCHAIN] registerIdentity failed: ${result.errors[0].message}`);
        return null;
      }
      console.log(`[EXOCHAIN] Identity registered: ${did}`);
      return result.data.livesafe_register_identity;
    } catch (err) {
      console.warn(`[EXOCHAIN] registerIdentity error: ${err.message}`);
      return null;
    }
  }

  async getIdentity(did) {
    if (!isExochainDid(did)) {
      console.warn("[EXOCHAIN] getIdentity rejected malformed DID before query");
      return null;
    }
    console.log(`[EXOCHAIN] Fetching identity: ${did}`);
    try {
      const result = await this.query('GetIdentity', `
        query GetIdentity($did: String!) {
          livesafe_identity(did: $did) {
            did
            created_at
            status
          }
        }
      `, { did });
      if (result.errors) {
        console.warn(`[EXOCHAIN] getIdentity failed: ${result.errors[0].message}`);
        return null;
      }
      return result.data.livesafe_identity;
    } catch (err) {
      console.warn(`[EXOCHAIN] getIdentity error: ${err.message}`);
      return null;
    }
  }

  // ── Audit Anchoring ───────────────────────────────────────────

  async anchorAuditReceipt(subscriberDid, receiptHash, eventType) {
    if (
      !isExochainDid(subscriberDid) ||
      !isNonEmptyString(receiptHash) ||
      !SHA256_HEX_PATTERN.test(receiptHash) ||
      !isNonEmptyString(eventType) ||
      !ALLOWED_AUDIT_RECEIPT_EVENT_TYPES.has(eventType)
    ) {
      console.warn('[EXOCHAIN] anchorAuditReceipt rejected malformed audit inputs before query');
      return null;
    }

    console.log(`[EXOCHAIN] Anchoring audit receipt: ${receiptHash.substring(0, 16)}... (${eventType})`);
    try {
      const result = await this.query('AnchorAuditReceipt', `
        mutation AnchorAuditReceipt($subscriber_did: String!, $receipt_hash: String!, $event_type: String!) {
          livesafe_anchor_audit_receipt(subscriber_did: $subscriber_did, receipt_hash: $receipt_hash, event_type: $event_type)
        }
      `, { subscriber_did: subscriberDid, receipt_hash: receiptHash, event_type: eventType });
      if (result.errors) {
        console.warn(`[EXOCHAIN] anchorAuditReceipt failed: ${result.errors[0].message}`);
        return null;
      }
      const exochainHash = result.data.livesafe_anchor_audit_receipt;
      console.log(`[EXOCHAIN] Audit receipt anchored: ${exochainHash}`);
      return exochainHash;
    } catch (err) {
      console.warn(`[EXOCHAIN] anchorAuditReceipt error: ${err.message}`);
      return null;
    }
  }

  // ── Scan Anchoring ────────────────────────────────────────────

  async anchorScan(input = {}) {
    const {
      scanId,
      subscriberDid,
      responderDid,
      location,
      scannedAtMs,
      consentExpiresAtMs,
      auditReceiptHash,
    } = input;
    if (!isRequiredTransportIdentifier(scanId)) {
      console.warn('[EXOCHAIN] anchorScan rejected malformed scan identifier before query');
      return null;
    }
    if (
      !isExochainDid(subscriberDid) ||
      !isOptionalExochainDid(responderDid) ||
      !isOptionalEpochMilliseconds(scannedAtMs) ||
      !isOptionalEpochMilliseconds(consentExpiresAtMs) ||
      !isOptionalSha256Hex(auditReceiptHash)
    ) {
      console.warn('[EXOCHAIN] anchorScan rejected malformed optional scan inputs before query');
      return null;
    }
    if (hasExplicitField(input, 'location')) {
      console.warn('[EXOCHAIN] anchorScan rejected explicit raw-sensitive location before query');
      return null;
    }

    console.log(`[EXOCHAIN] Anchoring scan: ${scanId}`);
    try {
      const transportInput = {
        scan_id: String(scanId),
        subscriber_did: subscriberDid,
        responder_did: responderDid || null,
        scanned_at_ms: scannedAtMs ?? Date.now(),
        consent_expires_at_ms: consentExpiresAtMs ?? null,
        audit_receipt_hash: auditReceiptHash || null,
      };

      const result = await this.query('AnchorScan', `
        mutation AnchorScan($input: ScanInput!) {
          livesafe_anchor_scan(input: $input) {
            scan_id
            subscriber_did
            responder_did
            anchored_at
            tx_hash
          }
        }
      `, {
        input: transportInput,
      });
      if (result.errors) {
        console.warn(`[EXOCHAIN] anchorScan failed: ${result.errors[0].message}`);
        return null;
      }
      console.log(`[EXOCHAIN] Scan anchored: ${scanId}`);
      return result.data.livesafe_anchor_scan;
    } catch (err) {
      console.warn(`[EXOCHAIN] anchorScan error: ${err.message}`);
      return null;
    }
  }

  // ── Consent Anchoring ─────────────────────────────────────────

  async anchorConsent(input = {}) {
    if (!input || typeof input !== 'object') {
      console.warn('[EXOCHAIN] anchorConsent rejected missing consent input before query');
      return null;
    }

    const {
      consentId,
      subscriberDid,
      providerDid,
      scope,
      grantedAtMs,
      expiresAtMs,
    } = input;
    if (!isRequiredTransportIdentifier(consentId)) {
      console.warn('[EXOCHAIN] anchorConsent rejected malformed consent identifier before query');
      return null;
    }
    if (
      !isExochainDid(subscriberDid) ||
      !isOptionalExochainDid(providerDid) ||
      !isOptionalConsentScope(scope) ||
      !isOptionalEpochMilliseconds(grantedAtMs) ||
      !isOptionalEpochMilliseconds(expiresAtMs)
    ) {
      console.warn('[EXOCHAIN] anchorConsent rejected malformed optional consent inputs before query');
      return null;
    }

    console.log(`[EXOCHAIN] Anchoring consent: ${consentId}`);
    try {
      const result = await this.query('AnchorConsent', `
        mutation AnchorConsent($input: ConsentInput!) {
          livesafe_anchor_consent(input: $input) {
            consent_id
            subscriber_did
            provider_did
            scope
            anchored_at
            tx_hash
          }
        }
      `, {
        input: {
          consent_id: String(consentId),
          subscriber_did: subscriberDid,
          provider_did: providerDid || null,
          scope: scope || null,
          granted_at_ms: grantedAtMs ?? Date.now(),
          expires_at_ms: expiresAtMs ?? null,
        },
      });
      if (result.errors) {
        console.warn(`[EXOCHAIN] anchorConsent failed: ${result.errors[0].message}`);
        return null;
      }
      console.log(`[EXOCHAIN] Consent anchored: ${consentId}`);
      return result.data.livesafe_anchor_consent;
    } catch (err) {
      console.warn(`[EXOCHAIN] anchorConsent error: ${err.message}`);
      return null;
    }
  }

  // ── PACE Status ───────────────────────────────────────────────

  async getPaceStatus(subscriberDid) {
    if (!isExochainDid(subscriberDid)) {
      console.warn("[EXOCHAIN] getPaceStatus rejected malformed subscriber DID before query");
      return [];
    }
    console.log(`[EXOCHAIN] Fetching PACE status: ${subscriberDid}`);
    try {
      const result = await this.query('GetPaceStatus', `
        query GetPaceStatus($subscriber_did: String!) {
          livesafe_pace_status(subscriber_did: $subscriber_did) {
            trustee_did
            role
            shard_status
            last_verified_at
          }
        }
      `, { subscriber_did: subscriberDid });
      if (result.errors) {
        console.warn(`[EXOCHAIN] getPaceStatus failed: ${result.errors[0].message}`);
        return [];
      }
      return result.data.livesafe_pace_status || [];
    } catch (err) {
      console.warn(`[EXOCHAIN] getPaceStatus error: ${err.message}`);
      return [];
    }
  }

  async getPublicAdapterOutputAuthorization({ subject, audience, currentAt } = {}) {
    if (
      subject !== PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT ||
      audience !== PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE
    ) {
      console.warn('[EXOCHAIN] public adapter-output authorization rejected malformed target before transport');
      return createPublicAuthorizationDenied();
    }

    const config = getPublicAdapterOutputAuthorizationConfig();
    if (!config) {
      console.warn('[EXOCHAIN] public adapter-output authorization REST transport is unconfigured');
      return createPublicAuthorizationDenied('unavailable');
    }

    const controller =
      typeof AbortController === 'function' ? new AbortController() : null;
    const timeout =
      controller && config.timeoutMs > 0
        ? setTimeout(() => controller.abort(), config.timeoutMs)
        : null;

    try {
      const body = buildPublicAdapterOutputAuthorizationRequest({
        subject,
        audience,
        credentialId: config.credentialId,
        credentialIdBytes: config.credentialIdBytes,
        evidenceHash: config.evidenceHash,
        evidenceHashBytes: config.evidenceHashBytes,
        currentAt,
        namespace: config.namespace,
        ttlMs: config.ttlMs,
      });

      if (!body) {
        console.warn('[EXOCHAIN] public adapter-output authorization request rejected malformed freshness inputs before transport');
        return createPublicAuthorizationDenied();
      }

      const response = await fetch(
        buildPublicAdapterOutputAuthorizationUrl(config.baseUrl),
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${config.bearer}`,
          },
          body: JSON.stringify(body),
          signal: controller?.signal,
        },
      );

      if (!response.ok) {
        console.warn(
          '[EXOCHAIN] public adapter-output authorization REST transport rejected the request',
        );
        return createPublicAuthorizationDenied(
          response.status === 408 || response.status === 504
            ? 'timeout'
            : response.status >= 500
              ? 'unavailable'
              : 'rejected',
        );
      }

      const envelope = await response.json();
      const adapted = adaptCorePublicAdapterOutputAuthorizationEnvelope(
        envelope,
        {
          subject,
          audience,
        },
      );

      if (adapted.state !== 'permit') {
        console.warn('[EXOCHAIN] public adapter-output authorization REST envelope denied');
        return adapted;
      }

      if (adapted.value.evidence_hash !== config.evidenceHash) {
        console.warn('[EXOCHAIN] public adapter-output authorization evidence hash mismatch');
        return createPublicAuthorizationDenied();
      }

      const evaluation = evaluatePublicAdapterOutputAuthorization(
        {
          allowed: true,
          responseState: 'permit',
          transportCalled: true,
          value: adapted.value,
        },
        {
          currentAt,
          subject: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
          audience: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
        },
      );

      if (!evaluation.allowed) {
        console.warn('[EXOCHAIN] public adapter-output authorization evaluator denied REST envelope');
        return createPublicAuthorizationDenied(
          publicAuthorizationStateFromReasons(evaluation.reasons),
        );
      }

      return adapted;
    } catch (err) {
      console.warn('[EXOCHAIN] public adapter-output authorization REST transport failed');
      return createPublicAuthorizationDenied(publicAuthorizationTransportErrorState(err));
    } finally {
      if (timeout) {
        clearTimeout(timeout);
      }
    }
  }

  // ── Health Check ──────────────────────────────────────────────

  async healthCheck() {
    try {
      // The document must NAME the operation: sending operationName "Health"
      // with an anonymous document makes the gateway return 200 + errors
      // ("Unknown operation named Health"), which read as connected=false
      // with no transport warning.
      const result = await this.query('Health', 'query Health { __typename }');
      this.connected = !result.errors;
      return this.connected;
    } catch {
      this.connected = false;
      return false;
    }
  }
}

// Singleton instance
const exochain = new ExochainClient();

module.exports = {
  ExochainClient,
  buildPublicAdapterOutputAuthorizationRequest,
  exochain,
};
