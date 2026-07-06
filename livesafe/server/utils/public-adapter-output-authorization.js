"use strict";

const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SCHEMA =
  "livesafe.public_adapter_output_authorization.v1";
const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT = "livesafe.ai";
const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE =
  "https://livesafe.ai/api/trust/status";
const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_MAX_AGE_MS = 5 * 60 * 1000;
const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_EXOCHAIN_HLC_BASIS = "exochain_hlc";
const ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS = [
  "livesafe_public_trust_status",
  "exochain_production_evidence_verified",
  "livesafe_runtime_adapter_verified",
];
const FORBIDDEN_PUBLIC_CLAIM_TERMS = [
  "medical",
  "legal",
  "custody",
  "consent",
  "emergency",
];
const RAW_SENSITIVE_FIELD_KEYS = [
  "authorization_header",
  "bearer_token",
  "credential_bytes",
  "emergency_contact",
  "location",
  "medical_record",
  "patient",
  "phi",
  "pii",
  "private_key",
  "raw_authority_chain",
  "raw_credential_bytes",
  "raw_sensitive_payload",
  "scan_payload",
  "trustee_did",
  "vault",
];
const RAW_SENSITIVE_FIELD_PREFIXES = ["raw_"];
const RAW_SENSITIVE_FIELD_FRAGMENTS = [
  "authority_chain",
  "bearer",
  "consent_record",
  "custody_record",
  "legal_record",
  "private_key",
  "scan_record",
  "trustee_record",
  "vault_record",
];
const SHA256_EVIDENCE_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const PROOF_SIGNATURE_PATTERN = /^ed25519:[A-Za-z0-9+/_=-]{32,}$/;

const REQUIRED_EVIDENCE = [
  "Permit response from the verified EXOCHAIN public adapter-output authorization transport.",
  "Public authorization DTO with schema, subject, audience, allowed claims, evidence hash, receipt id, proof id/ref, validity window, and proof signature.",
  "Redacted public metadata excluding credential bytes, bearer tokens, private keys, raw authority chains, PII/PHI, trustee, scan, consent, vault, medical, legal, custody, and emergency fields.",
];

function isObjectRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function safeResponseState(adapterOutputAuthorization) {
  return isObjectRecord(adapterOutputAuthorization) &&
    typeof adapterOutputAuthorization.responseState === "string"
    ? adapterOutputAuthorization.responseState
    : "not-called";
}

function safeTransportCalled(adapterOutputAuthorization) {
  return (
    isObjectRecord(adapterOutputAuthorization) &&
    adapterOutputAuthorization.transportCalled === true
  );
}

function createDeniedDecision({
  reasons,
  responseState = "not-called",
  transportCalled = false,
}) {
  return {
    allowed: false,
    reasons,
    required_evidence: REQUIRED_EVIDENCE,
    responseState,
    transportCalled,
    metadata: null,
  };
}

function createAllowedDecision({ responseState, transportCalled, metadata }) {
  return {
    allowed: true,
    reasons: [],
    required_evidence: [],
    responseState,
    transportCalled,
    metadata,
  };
}

function pushOnce(target, reason) {
  if (!target.includes(reason)) {
    target.push(reason);
  }
}

function parseIsoTimestamp(value) {
  if (!isNonEmptyString(value)) {
    return null;
  }

  const milliseconds = Date.parse(value);
  return Number.isNaN(milliseconds) ? null : milliseconds;
}

function containsForbiddenPublicClaim(claim) {
  const normalized = String(claim).toLowerCase();
  return FORBIDDEN_PUBLIC_CLAIM_TERMS.some((term) => normalized.includes(term));
}

function claimsMatchAllowedSet(claims) {
  if (claims.length !== ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS.length) {
    return false;
  }

  const sortedClaims = [...claims].sort();
  const sortedAllowed = [...ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS].sort();
  return sortedClaims.every((claim, index) => claim === sortedAllowed[index]);
}

function keyLooksRawSensitive(key) {
  const normalized = String(key).toLowerCase();

  if (RAW_SENSITIVE_FIELD_KEYS.includes(normalized)) {
    return true;
  }

  if (RAW_SENSITIVE_FIELD_PREFIXES.some((prefix) => normalized.startsWith(prefix))) {
    return true;
  }

  return RAW_SENSITIVE_FIELD_FRAGMENTS.some((fragment) =>
    normalized.includes(fragment),
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

function validateClaims(claims, reasons) {
  if (!Array.isArray(claims) || claims.length === 0) {
    reasons.push("Public adapter-output authorization claims must be non-empty.");
    return;
  }

  const seenClaims = [];

  for (const claim of claims) {
    if (!isNonEmptyString(claim)) {
      pushOnce(
        reasons,
        "Public adapter-output authorization claims include unsupported public output.",
      );
      continue;
    }

    if (seenClaims.includes(claim)) {
      pushOnce(
        reasons,
        "Public adapter-output authorization claims must not contain duplicates.",
      );
    }
    seenClaims.push(claim);

    if (containsForbiddenPublicClaim(claim)) {
      pushOnce(
        reasons,
        "Public adapter-output authorization may not carry medical, legal, custody, consent, or emergency claims.",
      );
    }

    if (!ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS.includes(claim)) {
      pushOnce(
        reasons,
        "Public adapter-output authorization claims include unsupported public output.",
      );
    }
  }

  if (claims.every(isNonEmptyString) && !claimsMatchAllowedSet(claims)) {
    pushOnce(
      reasons,
      "Public adapter-output authorization claims include unsupported public output.",
    );
  }
}

function validateTimestamps({ authorization, currentAt, reasons }) {
  const currentMilliseconds = parseIsoTimestamp(currentAt);
  const generatedMilliseconds = parseIsoTimestamp(authorization.generated_at);
  const validFromMilliseconds = parseIsoTimestamp(authorization.valid_from);
  const expiresMilliseconds = parseIsoTimestamp(authorization.expires_at);
  const hasExochainHlcBasis =
    authorization.timestamp_basis ===
    PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_EXOCHAIN_HLC_BASIS;

  if (currentMilliseconds === null) {
    reasons.push(
      "Public adapter-output authorization current timestamp is required.",
    );
    return;
  }

  if (
    generatedMilliseconds === null ||
    validFromMilliseconds === null ||
    expiresMilliseconds === null
  ) {
    reasons.push(
      "Public adapter-output authorization validity timestamps are malformed.",
    );
    return;
  }

  if (currentMilliseconds > expiresMilliseconds) {
    reasons.push("Public adapter-output authorization is expired.");
  }

  if (
    currentMilliseconds < validFromMilliseconds ||
    currentMilliseconds < generatedMilliseconds
  ) {
    reasons.push("Public adapter-output authorization is not yet valid.");
  }

  if (
    !hasExochainHlcBasis &&
    currentMilliseconds - generatedMilliseconds >
      PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_MAX_AGE_MS
  ) {
    reasons.push("Public adapter-output authorization is stale.");
  }
}

function buildMetadata({ authorization, responseState, transportCalled }) {
  return {
    schema: authorization.schema,
    subject: authorization.subject,
    audience: authorization.audience,
    claims: [...authorization.claims],
    evidence_hash: authorization.evidence_hash,
    receipt_id: authorization.receipt_id,
    proof_id: authorization.proof_id,
    proof_ref: authorization.proof_ref,
    generated_at: authorization.generated_at,
    valid_from: authorization.valid_from,
    expires_at: authorization.expires_at,
    proof_type: authorization.proof.type,
    response_state: responseState,
    transport_called: transportCalled,
  };
}

function evaluatePublicAdapterOutputAuthorization(
  adapterOutputAuthorization,
  {
    currentAt,
    subject = PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
    audience = PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
  } = {},
) {
  if (!isObjectRecord(adapterOutputAuthorization)) {
    return createDeniedDecision({
      reasons: ["Public adapter-output authorization is missing."],
    });
  }

  const responseState = safeResponseState(adapterOutputAuthorization);
  const transportCalled = safeTransportCalled(adapterOutputAuthorization);
  const reasons = [];

  if (adapterOutputAuthorization.allowed !== true) {
    reasons.push(
      "Public adapter-output authorization evaluator did not allow public output.",
    );
  }

  if (responseState !== "permit") {
    reasons.push(
      "Public adapter-output authorization transport must return permit.",
    );
  }

  if (!transportCalled) {
    reasons.push(
      "Public adapter-output authorization transport must be called.",
    );
  }

  const authorization = adapterOutputAuthorization.value;

  if (!isObjectRecord(authorization)) {
    reasons.push("Public adapter-output authorization DTO is malformed.");
    return createDeniedDecision({ reasons, responseState, transportCalled });
  }

  if (containsRawSensitiveField(authorization)) {
    reasons.push(
      "Public adapter-output authorization contains raw sensitive fields.",
    );
  }

  if (authorization.schema !== PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SCHEMA) {
    reasons.push("Public adapter-output authorization schema is invalid.");
  }

  if (authorization.subject !== subject) {
    reasons.push(
      `Public adapter-output authorization subject must be ${subject}.`,
    );
  }

  if (authorization.audience !== audience) {
    reasons.push(
      `Public adapter-output authorization audience must be ${audience}.`,
    );
  }

  validateClaims(authorization.claims, reasons);

  if (!SHA256_EVIDENCE_HASH_PATTERN.test(authorization.evidence_hash || "")) {
    reasons.push(
      "Public adapter-output authorization evidence_hash must be sha256-prefixed lowercase hex.",
    );
  }

  if (!isNonEmptyString(authorization.receipt_id)) {
    reasons.push("Public adapter-output authorization requires receipt_id.");
  }

  if (
    !isNonEmptyString(authorization.proof_id) ||
    !isNonEmptyString(authorization.proof_ref)
  ) {
    reasons.push(
      "Public adapter-output authorization requires proof_id and proof_ref.",
    );
  }

  validateTimestamps({ authorization, currentAt, reasons });

  if (authorization.revoked === true) {
    reasons.push("Public adapter-output authorization is revoked.");
  }

  if (authorization.contradicted === true) {
    reasons.push("Public adapter-output authorization is contradicted.");
  }

  const proof = authorization.proof;
  if (
    !isObjectRecord(proof) ||
    !isNonEmptyString(proof.type) ||
    !PROOF_SIGNATURE_PATTERN.test(proof.signature || "")
  ) {
    reasons.push(
      "Public adapter-output authorization proof signature is malformed.",
    );
  }

  if (reasons.length > 0) {
    return createDeniedDecision({ reasons, responseState, transportCalled });
  }

  return createAllowedDecision({
    responseState,
    transportCalled,
    metadata: buildMetadata({ authorization, responseState, transportCalled }),
  });
}

module.exports = {
  ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SCHEMA,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
  evaluatePublicAdapterOutputAuthorization,
};
