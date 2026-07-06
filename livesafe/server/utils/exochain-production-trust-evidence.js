"use strict";

const crypto = require("node:crypto");

const exochainProductionTrustConfig = require("../../config/exochain-production-trust.json");
const {
  ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
} = require("./public-adapter-output-authorization");

const DID_PATTERN = /^did:exo:[A-Za-z0-9._:-]+$/;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const GIT_COMMIT_HEX_PATTERN = /^[a-f0-9]{40}$/;
const ISO_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const PUBLIC_OUTPUT_EVIDENCE_SCHEMA =
  "livesafe.public_output_evidence_summary.v1";
const PUBLIC_OUTPUT_EVIDENCE_HASH_ALGORITHM =
  "sha256.canonical_json.sorted_keys.v1";
const PUBLIC_OUTPUT_EVIDENCE_READY_STATE =
  "ready_for_avc_ceremony_binding";
const DEFAULT_PUBLIC_OUTPUT_EVIDENCE_MAX_AGE_MS = 10 * 60 * 1000;
const DEFAULT_PUBLIC_OUTPUT_EVIDENCE_GENERATED_FROM = [
  "config/exochain-production-trust.json",
  "server/utils/exochain-production-trust-evidence.js",
  "server/utils/livesafe-exochain-adapter.js",
  "server/utils/public-adapter-output-authorization.js",
];
const REQUIRED_PUBLIC_ADAPTER_OUTPUT_OPERATION =
  "getPublicAdapterOutputAuthorization";
const SENSITIVE_SUMMARY_KEY_FRAGMENTS = [
  "admin_token",
  "authorization_header",
  "bearer",
  "consent_record",
  "custody_record",
  "database_url",
  "db_url",
  "emergency_contact",
  "legal_record",
  "location",
  "medical_record",
  "patient",
  "phi",
  "pii",
  "private_key",
  "raw_authority_chain",
  "raw_credential",
  "raw_sensitive_payload",
  "scan_payload",
  "scan_record",
  "secret",
  "sensitive_livesafe_payload",
  "trustee",
  "vault",
];
const SENSITIVE_SUMMARY_VALUE_PATTERNS = [
  /bearer\s+[A-Za-z0-9._~+/-]+=*/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\//i,
  /\bsk-[A-Za-z0-9_-]{8,}/,
  /admin-token/i,
];

class PublicOutputEvidenceSummaryError extends Error {
  constructor(reasons) {
    super(reasons.join(" "));
    this.name = "PublicOutputEvidenceSummaryError";
    this.reasons = reasons;
  }
}

function hasOkStatus(payload) {
  return Boolean(payload) && payload.status === "ok";
}

function isObjectRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function isHttpsUrl(value) {
  return typeof value === "string" && value.startsWith("https://");
}

function parseExplicitIsoTimestamp(value) {
  if (!isNonEmptyString(value) || !ISO_TIMESTAMP_PATTERN.test(value)) {
    return null;
  }

  const milliseconds = Date.parse(value);
  if (Number.isNaN(milliseconds)) {
    return null;
  }

  return {
    milliseconds,
    iso: new Date(milliseconds).toISOString(),
  };
}

function hasSevenOfThirteenSignerPolicy(bundle) {
  if (!bundle || bundle.threshold !== 7 || bundle.maxSigners !== 13) {
    return false;
  }

  if (!Array.isArray(bundle.signerIds) || bundle.signerIds.length < bundle.threshold) {
    return false;
  }

  const uniqueSignerIds = new Set(bundle.signerIds);
  return (
    uniqueSignerIds.size >= bundle.threshold &&
    bundle.signerIds.every((id) => Number.isInteger(id) && id >= 1 && id <= bundle.maxSigners)
  );
}

function sentinelObservationKey(check) {
  return `production_sentinel_${String(check || "")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase()}_below_bft_minimum`;
}

function evaluateSentinels({ sentinels = [], policy = {} }) {
  const reasons = [];
  const nonBlockingObservations = [];
  const byCheck = new Map(
    sentinels
      .filter((sentinel) => sentinel && typeof sentinel.check === "string")
      .map((sentinel) => [sentinel.check, sentinel]),
  );

  for (const requiredCheck of policy.requiredHealthy || []) {
    const sentinel = byCheck.get(requiredCheck);
    if (!sentinel || sentinel.healthy !== true) {
      reasons.push(`EXOCHAIN production sentinel ${requiredCheck} is not healthy.`);
    }
  }

  for (const observedCheck of policy.nonBlockingObservations || []) {
    const sentinel = byCheck.get(observedCheck);
    if (sentinel && sentinel.healthy !== true) {
      nonBlockingObservations.push(sentinelObservationKey(observedCheck));
    }
  }

  return { reasons, nonBlockingObservations };
}

function evaluateBundle(config) {
  const bundle = config.rootTrustBundle || {};
  const verification = config.verification || {};
  const reasons = [];

  if (verification.status !== "verified" || verification.result?.verified !== true) {
    reasons.push("EXOCHAIN root trust bundle verification is not confirmed.");
  }

  if (!SHA256_HEX_PATTERN.test(bundle.bundleIdHex || "")) {
    reasons.push("EXOCHAIN root trust bundle id is missing or malformed.");
  }

  if (!SHA256_HEX_PATTERN.test(bundle.bundleSha256 || "")) {
    reasons.push("EXOCHAIN root trust bundle SHA-256 is missing or malformed.");
  }

  if (bundle.ceremonyId !== "avc-exo-ceremony-2026") {
    reasons.push("EXOCHAIN root trust ceremony id does not match the expected AVC ceremony.");
  }

  if (!hasSevenOfThirteenSignerPolicy(bundle)) {
    reasons.push("EXOCHAIN root trust bundle does not carry a verified 7-of-13 signer policy.");
  }

  if (!DID_PATTERN.test(bundle.issuerDid || "")) {
    reasons.push("EXOCHAIN root trust issuer DID is missing or malformed.");
  }

  return {
    verified: reasons.length === 0,
    reasons,
  };
}

function evaluateExochainProductionTrustEvidence({
  config = exochainProductionTrustConfig,
  health = config.latestProductionProbe?.health,
  ready = config.latestProductionProbe?.ready,
  sentinels = config.latestProductionProbe?.sentinels || [],
} = {}) {
  const reasons = [];

  if (!isHttpsUrl(config.production?.baseUrl)) {
    reasons.push("EXOCHAIN production base URL must be HTTPS.");
  }

  const productionHealthVerified = hasOkStatus(health);
  const productionReadyVerified = hasOkStatus(ready);

  if (!productionHealthVerified) {
    reasons.push("EXOCHAIN production health probe did not return ok.");
  }

  if (!productionReadyVerified) {
    reasons.push("EXOCHAIN production readiness probe did not return ok.");
  }

  const bundleDecision = evaluateBundle(config);
  reasons.push(...bundleDecision.reasons);

  const sentinelDecision = evaluateSentinels({
    sentinels,
    policy: config.sentinelPolicy,
  });
  reasons.push(...sentinelDecision.reasons);

  const evidenceVerified =
    reasons.length === 0 &&
    productionHealthVerified &&
    productionReadyVerified &&
    bundleDecision.verified;

  return {
    evidence_state: evidenceVerified ? "verified" : "blocked",
    production_base_url: config.production?.baseUrl || null,
    production_health_verified: productionHealthVerified,
    production_ready_verified: productionReadyVerified,
    root_trust_bundle_verified: bundleDecision.verified,
    root_trust_bundle_id: config.rootTrustBundle?.bundleIdHex || null,
    root_trust_ceremony_id: config.rootTrustBundle?.ceremonyId || null,
    root_trust_issuer_did: config.rootTrustBundle?.issuerDid || null,
    verifier_commit: config.verification?.verifierCommit || null,
    verified_at: config.verification?.verifiedAt || null,
    source_basis: config.sourceBasis || [],
    reasons,
    non_blocking_observations: sentinelDecision.nonBlockingObservations,
  };
}

const exochainProductionTrustEvidence =
  evaluateExochainProductionTrustEvidence();

function pushPublicOutputReason(reasons, reason) {
  if (!reasons.includes(reason)) {
    reasons.push(reason);
  }
}

function validateGeneratedFrom(generatedFrom, reasons) {
  if (!Array.isArray(generatedFrom) || generatedFrom.length === 0) {
    reasons.push("Public output evidence generated_from must be non-empty.");
    return;
  }

  for (const entry of generatedFrom) {
    if (!isNonEmptyString(entry)) {
      pushPublicOutputReason(
        reasons,
        "Public output evidence generated_from must contain only non-empty strings.",
      );
    }
  }
}

function validateProductionTrustEvidence(productionTrustEvidence, reasons) {
  if (!isObjectRecord(productionTrustEvidence)) {
    reasons.push("EXOCHAIN production evidence is required.");
    return;
  }

  if (productionTrustEvidence.evidence_state !== "verified") {
    reasons.push("EXOCHAIN production evidence must be verified.");
  }

  if (productionTrustEvidence.production_health_verified !== true) {
    reasons.push("EXOCHAIN production health evidence must be verified.");
  }

  if (productionTrustEvidence.production_ready_verified !== true) {
    reasons.push("EXOCHAIN production readiness evidence must be verified.");
  }

  if (productionTrustEvidence.root_trust_bundle_verified !== true) {
    reasons.push("EXOCHAIN root trust bundle evidence must be verified.");
  }

  if (!isHttpsUrl(productionTrustEvidence.production_base_url)) {
    reasons.push("EXOCHAIN production evidence base URL must be HTTPS.");
  }

  if (!SHA256_HEX_PATTERN.test(productionTrustEvidence.root_trust_bundle_id || "")) {
    reasons.push("EXOCHAIN root trust bundle id is missing or malformed.");
  }

  if (productionTrustEvidence.root_trust_ceremony_id !== "avc-exo-ceremony-2026") {
    reasons.push("EXOCHAIN root trust ceremony id is invalid.");
  }

  if (!DID_PATTERN.test(productionTrustEvidence.root_trust_issuer_did || "")) {
    reasons.push("EXOCHAIN root trust issuer DID is missing or malformed.");
  }

  if (!GIT_COMMIT_HEX_PATTERN.test(productionTrustEvidence.verifier_commit || "")) {
    reasons.push("EXOCHAIN root trust verifier commit is missing or malformed.");
  }
}

function validateRuntimeStatus(runtimeStatus, reasons) {
  if (!isObjectRecord(runtimeStatus)) {
    reasons.push("LiveSafe runtime adapter evidence is required.");
    return;
  }

  if (runtimeStatus.adapter_state !== "verified") {
    reasons.push("LiveSafe runtime adapter evidence must be verified.");
  }

  if (runtimeStatus.public_claims_allowed !== false) {
    reasons.push(
      "LiveSafe public claims must not already be allowed before AVC authorization.",
    );
  }

  if (runtimeStatus.can_read_exochain_core_state !== true) {
    reasons.push("LiveSafe runtime adapter read evidence must be verified.");
  }

  if (runtimeStatus.can_write_exochain_core_state !== true) {
    reasons.push("LiveSafe runtime adapter write evidence must be verified.");
  }

  if (
    !Array.isArray(runtimeStatus.wrapped_operations) ||
    !runtimeStatus.wrapped_operations.includes(
      REQUIRED_PUBLIC_ADAPTER_OUTPUT_OPERATION,
    )
  ) {
    reasons.push(
      "LiveSafe runtime adapter must include public adapter-output authorization evidence.",
    );
  }

  if (!isNonEmptyString(runtimeStatus.disablement_path)) {
    reasons.push("LiveSafe runtime adapter disablement path is required.");
  }
}

function resolvePublicOutputTimestamps({
  asOf,
  productionTrustEvidence,
  maxEvidenceAgeMs,
  reasons,
}) {
  const parsedAsOf = parseExplicitIsoTimestamp(asOf);
  const parsedEvidence = parseExplicitIsoTimestamp(
    productionTrustEvidence?.verified_at,
  );

  if (!parsedAsOf || !parsedEvidence) {
    reasons.push("Public output evidence timestamp is malformed.");
    return {
      asOfIso: null,
      evidenceIso: null,
    };
  }

  if (parsedEvidence.milliseconds > parsedAsOf.milliseconds) {
    reasons.push("Public output evidence timestamp is after as_of.");
  }

  if (parsedAsOf.milliseconds - parsedEvidence.milliseconds > maxEvidenceAgeMs) {
    reasons.push("Public output evidence timestamp is stale.");
  }

  return {
    asOfIso: parsedAsOf.iso,
    evidenceIso: parsedEvidence.iso,
  };
}

function normalizeStringArray(value) {
  return Array.isArray(value)
    ? value.filter(isNonEmptyString).map((entry) => entry.trim())
    : [];
}

function sensitiveSummaryKey(key) {
  const normalized = String(key).toLowerCase();
  return SENSITIVE_SUMMARY_KEY_FRAGMENTS.some((fragment) =>
    normalized.includes(fragment),
  );
}

function sensitiveSummaryString(value) {
  return SENSITIVE_SUMMARY_VALUE_PATTERNS.some((pattern) => pattern.test(value));
}

function assertNoSensitiveSummaryMaterial(value) {
  function visit(candidate) {
    if (typeof candidate === "string") {
      if (sensitiveSummaryString(candidate)) {
        throw new PublicOutputEvidenceSummaryError([
          "Public output evidence summary must not contain secret or sensitive material.",
        ]);
      }
      return;
    }

    if (Array.isArray(candidate)) {
      for (const entry of candidate) {
        visit(entry);
      }
      return;
    }

    if (!isObjectRecord(candidate)) {
      return;
    }

    for (const [key, nestedValue] of Object.entries(candidate)) {
      if (sensitiveSummaryKey(key)) {
        throw new PublicOutputEvidenceSummaryError([
          "Public output evidence summary must not contain secret or sensitive material.",
        ]);
      }
      visit(nestedValue);
    }
  }

  visit(value);
}

function canonicalizePublicOutputEvidenceSummary(value) {
  if (value === null) {
    return "null";
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new PublicOutputEvidenceSummaryError([
        "Public output evidence summary numbers must be safe integers.",
      ]);
    }
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(canonicalizePublicOutputEvidenceSummary).join(",")}]`;
  }

  if (isObjectRecord(value)) {
    const serializedEntries = Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalizePublicOutputEvidenceSummary(
            value[key],
          )}`,
      );
    return `{${serializedEntries.join(",")}}`;
  }

  throw new PublicOutputEvidenceSummaryError([
    "Public output evidence summary contains unsupported JSON material.",
  ]);
}

function buildPublicOutputEvidenceSummary({
  subject = PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
  audience = PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
  asOf,
  maxEvidenceAgeMs = DEFAULT_PUBLIC_OUTPUT_EVIDENCE_MAX_AGE_MS,
  exochainConnected,
  productionTrustEvidence,
  runtimeStatus,
  generatedFrom = DEFAULT_PUBLIC_OUTPUT_EVIDENCE_GENERATED_FROM,
} = {}) {
  const reasons = [];

  if (subject !== PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT) {
    reasons.push(
      `Public output evidence subject must be ${PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT}.`,
    );
  }

  if (audience !== PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE) {
    reasons.push(
      `Public output evidence audience must be ${PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE}.`,
    );
  }

  if (exochainConnected !== true) {
    reasons.push("EXOCHAIN connectivity must be verified.");
  }

  if (!Number.isSafeInteger(maxEvidenceAgeMs) || maxEvidenceAgeMs <= 0) {
    reasons.push("Public output evidence max age must be a positive integer.");
  }

  validateGeneratedFrom(generatedFrom, reasons);
  validateProductionTrustEvidence(productionTrustEvidence, reasons);
  validateRuntimeStatus(runtimeStatus, reasons);

  const { asOfIso, evidenceIso } = resolvePublicOutputTimestamps({
    asOf,
    productionTrustEvidence,
    maxEvidenceAgeMs: Number.isSafeInteger(maxEvidenceAgeMs)
      ? maxEvidenceAgeMs
      : DEFAULT_PUBLIC_OUTPUT_EVIDENCE_MAX_AGE_MS,
    reasons,
  });

  if (reasons.length > 0) {
    throw new PublicOutputEvidenceSummaryError(reasons);
  }

  const summary = {
    schema: PUBLIC_OUTPUT_EVIDENCE_SCHEMA,
    subject,
    audience,
    as_of: asOfIso,
    evidence_timestamp: evidenceIso,
    max_evidence_age_ms: maxEvidenceAgeMs,
    hash_algorithm: PUBLIC_OUTPUT_EVIDENCE_HASH_ALGORITHM,
    generated_from: normalizeStringArray(generatedFrom),
    exochain_connected: true,
    public_claims_allowed: false,
    production_evidence: {
      state: productionTrustEvidence.evidence_state,
      base_url: productionTrustEvidence.production_base_url,
      health_verified: true,
      readiness_verified: true,
      root_trust_bundle_verified: true,
      root_trust_bundle_id: productionTrustEvidence.root_trust_bundle_id,
      root_trust_ceremony_id: productionTrustEvidence.root_trust_ceremony_id,
      root_trust_issuer_did: productionTrustEvidence.root_trust_issuer_did,
      verifier_commit: productionTrustEvidence.verifier_commit,
      verified_at: evidenceIso,
      non_blocking_observations: normalizeStringArray(
        productionTrustEvidence.non_blocking_observations,
      ),
    },
    runtime_adapter_evidence: {
      state: runtimeStatus.adapter_state,
      surface_classification: runtimeStatus.surface_classification,
      can_read_exochain_core_state: true,
      can_write_exochain_core_state: true,
      public_claims_allowed: false,
      wrapped_operations: normalizeStringArray(runtimeStatus.wrapped_operations),
      disablement_path: runtimeStatus.disablement_path,
      source_basis: normalizeStringArray(runtimeStatus.source_basis),
    },
    public_output_evidence: {
      authorization_required: true,
      authorized_by_this_hash: false,
      required_claims: [...ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS],
    },
  };

  assertNoSensitiveSummaryMaterial(summary);
  return summary;
}

function hashPublicOutputEvidenceSummary(summary) {
  if (!isObjectRecord(summary)) {
    throw new PublicOutputEvidenceSummaryError([
      "Public output evidence summary is required.",
    ]);
  }

  assertNoSensitiveSummaryMaterial(summary);
  const canonicalJson = canonicalizePublicOutputEvidenceSummary(summary);
  const hex = crypto
    .createHash("sha256")
    .update(canonicalJson, "utf8")
    .digest("hex");
  return `sha256:${hex}`;
}

function buildPublicOutputEvidenceHashRecord(input) {
  const summary = buildPublicOutputEvidenceSummary(input);
  const evidenceHash = hashPublicOutputEvidenceSummary(summary);

  return {
    evidence_hash: evidenceHash,
    algorithm: PUBLIC_OUTPUT_EVIDENCE_HASH_ALGORITHM,
    subject: summary.subject,
    audience: summary.audience,
    generated_from: summary.generated_from,
    state: PUBLIC_OUTPUT_EVIDENCE_READY_STATE,
    reasons: [],
    public_claims_allowed: false,
    summary,
  };
}

module.exports = {
  DEFAULT_PUBLIC_OUTPUT_EVIDENCE_GENERATED_FROM,
  DEFAULT_PUBLIC_OUTPUT_EVIDENCE_MAX_AGE_MS,
  PUBLIC_OUTPUT_EVIDENCE_HASH_ALGORITHM,
  PUBLIC_OUTPUT_EVIDENCE_READY_STATE,
  PublicOutputEvidenceSummaryError,
  buildPublicOutputEvidenceHashRecord,
  buildPublicOutputEvidenceSummary,
  canonicalizePublicOutputEvidenceSummary,
  evaluateExochainProductionTrustEvidence,
  exochainProductionTrustConfig,
  exochainProductionTrustEvidence,
  hashPublicOutputEvidenceSummary,
};
