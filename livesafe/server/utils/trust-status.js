"use strict";

const { runtimeExochainAdapter } = require("./livesafe-exochain-adapter");
const {
  exochainProductionTrustEvidence,
} = require("./exochain-production-trust-evidence");
const {
  ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SCHEMA,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
  evaluatePublicAdapterOutputAuthorization,
} = require("./public-adapter-output-authorization");

const SOURCE_BASIS = [
  "docs/context/LIVESAFE_PRODUCTION_TRUST_ACTIVATION_GATES.md",
  "docs/context/LIVESAFE_TRUST_SIGNAL_VISUAL_LANGUAGE.md",
  "src/trust-signal.ts",
  "src/genesis-trust.ts",
  "server/utils/livesafe-exochain-adapter.js",
  "server/utils/public-adapter-output-authorization.js"
];

const NOT_VERIFIED_TOKEN = {
  state: "not-verified",
  badge_text: "AVC",
  icon: "lock-open",
  color: "red",
  css_class: "trust-signal trust-signal--red trust-signal--not-verified",
  glow_class: "trust-glow trust-glow--red",
  display_text: "THIS IS NOT YET VERIFIED",
  machine_state: "not_verified"
};

const VERIFIED_TOKEN = {
  state: "externally-verified",
  badge_text: "AVC",
  icon: "lock-check",
  color: "green",
  css_class: "trust-signal trust-signal--green trust-signal--externally-verified",
  glow_class: "trust-glow trust-glow--green",
  display_text: "VERIFIED",
  machine_state: "public_trust_claims_allowed"
};

const PUBLIC_ADAPTER_OUTPUT_METADATA_KEYS = new Set([
  "schema",
  "subject",
  "audience",
  "claims",
  "evidence_hash",
  "receipt_id",
  "proof_id",
  "proof_ref",
  "generated_at",
  "valid_from",
  "expires_at",
  "proof_type",
  "response_state",
  "transport_called",
]);
const SHA256_EVIDENCE_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;

function isObjectRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function parseIsoTimestamp(value) {
  if (!isNonEmptyString(value)) {
    return null;
  }

  const milliseconds = Date.parse(value);
  return Number.isNaN(milliseconds) ? null : milliseconds;
}

function claimsMatchAllowedSet(claims) {
  if (!Array.isArray(claims) || claims.length !== ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS.length) {
    return false;
  }

  const sortedClaims = [...claims].sort();
  const sortedAllowed = [...ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS].sort();
  return sortedClaims.every((claim, index) => claim === sortedAllowed[index]);
}

function evaluatedPermitMetadataDecision(
  adapterOutputAuthorization,
  { currentAt, subject, audience },
) {
  if (
    !isObjectRecord(adapterOutputAuthorization) ||
    adapterOutputAuthorization.allowed !== true ||
    adapterOutputAuthorization.responseState !== "permit" ||
    adapterOutputAuthorization.transportCalled !== true
  ) {
    return null;
  }

  const metadata = adapterOutputAuthorization.value;
  if (!isObjectRecord(metadata)) {
    return null;
  }

  const keys = Object.keys(metadata);
  if (!keys.every((key) => PUBLIC_ADAPTER_OUTPUT_METADATA_KEYS.has(key))) {
    return null;
  }

  const currentMilliseconds = parseIsoTimestamp(currentAt);
  const validFromMilliseconds = parseIsoTimestamp(metadata.valid_from);
  const expiresMilliseconds = parseIsoTimestamp(metadata.expires_at);

  if (
    currentMilliseconds === null ||
    validFromMilliseconds === null ||
    expiresMilliseconds === null ||
    currentMilliseconds < validFromMilliseconds ||
    currentMilliseconds > expiresMilliseconds
  ) {
    return null;
  }

  if (
    metadata.schema !== PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SCHEMA ||
    metadata.subject !== subject ||
    metadata.audience !== audience ||
    !claimsMatchAllowedSet(metadata.claims) ||
    !SHA256_EVIDENCE_HASH_PATTERN.test(metadata.evidence_hash || "") ||
    !isNonEmptyString(metadata.receipt_id) ||
    !isNonEmptyString(metadata.proof_id) ||
    !isNonEmptyString(metadata.proof_ref) ||
    !isNonEmptyString(metadata.generated_at) ||
    !isNonEmptyString(metadata.proof_type) ||
    metadata.response_state !== "permit" ||
    metadata.transport_called !== true
  ) {
    return null;
  }

  return {
    allowed: true,
    reasons: [],
    required_evidence: [],
    responseState: "permit",
    transportCalled: true,
    metadata,
  };
}

function resolvePublicAdapterOutputAuthorizationDecision(
  adapterOutputAuthorization,
  { currentAt, subject, audience },
) {
  const rawDecision = evaluatePublicAdapterOutputAuthorization(
    adapterOutputAuthorization,
    { currentAt, subject, audience },
  );

  if (rawDecision.allowed) {
    return rawDecision;
  }

  return (
    evaluatedPermitMetadataDecision(adapterOutputAuthorization, {
      currentAt,
      subject,
      audience,
    }) || rawDecision
  );
}

function isProductionEvidenceVerified(productionTrustEvidence) {
  return (
    productionTrustEvidence?.evidence_state === "verified" &&
    productionTrustEvidence.production_health_verified === true &&
    productionTrustEvidence.production_ready_verified === true &&
    productionTrustEvidence.root_trust_bundle_verified === true
  );
}

function publicClaimsReason({
  exochainConnected,
  productionEvidenceVerified,
  runtimeAdapterVerified,
  publicAdapterOutputAuthorized,
}) {
  if (!productionEvidenceVerified) {
    return "Public trust claims remain inactive until EXOCHAIN production evidence verifies.";
  }

  if (!runtimeAdapterVerified) {
    return "Public trust claims remain inactive because EXOCHAIN production evidence is verified but the LiveSafe runtime adapter remains unverified.";
  }

  if (!publicAdapterOutputAuthorized) {
    return "Public trust claims remain inactive because proof-bearing public adapter-output authorization has not been verified.";
  }

  if (!exochainConnected) {
    return "Public trust claims remain inactive until EXOCHAIN connectivity verifies.";
  }

  return "EXOCHAIN connectivity, EXOCHAIN production evidence, LiveSafe runtime adapter gates, and proof-bearing public adapter-output authorization are verified.";
}

function createTrustStatusPayload({
  exochainConnected,
  version,
  uptimeSeconds,
  generatedAt,
  runtimeStatus,
  adapterOutputAuthorization,
  productionTrustEvidence
}) {
  const defaultRuntimeStatus = runtimeExochainAdapter.getRuntimeStatus();
  const resolvedRuntimeStatus = runtimeStatus
    ? {
        ...defaultRuntimeStatus,
        ...runtimeStatus,
        wrapped_operations:
          runtimeStatus.wrapped_operations ?? defaultRuntimeStatus.wrapped_operations,
      }
    : defaultRuntimeStatus;

  const resolvedProductionTrustEvidence =
    productionTrustEvidence || exochainProductionTrustEvidence;
  const runtimeAdapterVerified =
    resolvedRuntimeStatus.adapter_state === "verified";
  const productionEvidenceVerified = isProductionEvidenceVerified(
    resolvedProductionTrustEvidence,
  );
  const publicAdapterOutputAuthorizationDecision =
    resolvePublicAdapterOutputAuthorizationDecision(adapterOutputAuthorization, {
      currentAt: generatedAt,
      subject: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
      audience: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
    });
  const publicAdapterOutputAuthorized =
    publicAdapterOutputAuthorizationDecision.allowed === true;
  const publicClaimsAllowed =
    Boolean(exochainConnected) &&
    productionEvidenceVerified &&
    runtimeAdapterVerified &&
    publicAdapterOutputAuthorized;
  const trustToken = publicClaimsAllowed ? VERIFIED_TOKEN : NOT_VERIFIED_TOKEN;
  const payload = {
    ...trustToken,
    api_surface: "api-response",
    exochain_connected: Boolean(exochainConnected),
    verified_runtime_adapter: runtimeAdapterVerified,
    runtime_adapter_state: resolvedRuntimeStatus.adapter_state,
    adapter_surface_classification: resolvedRuntimeStatus.surface_classification,
    runtime_adapter_operations: resolvedRuntimeStatus.wrapped_operations,
    adapter_disablement_path: resolvedRuntimeStatus.disablement_path,
    exochain_production_evidence_state:
      resolvedProductionTrustEvidence.evidence_state,
    exochain_production_health_verified:
      resolvedProductionTrustEvidence.production_health_verified === true,
    exochain_production_ready_verified:
      resolvedProductionTrustEvidence.production_ready_verified === true,
    exochain_root_trust_bundle_verified:
      resolvedProductionTrustEvidence.root_trust_bundle_verified === true,
    exochain_root_trust_bundle_id:
      resolvedProductionTrustEvidence.root_trust_bundle_id || null,
    exochain_root_trust_ceremony_id:
      resolvedProductionTrustEvidence.root_trust_ceremony_id || null,
    exochain_root_trust_issuer_did:
      resolvedProductionTrustEvidence.root_trust_issuer_did || null,
    exochain_root_trust_verifier_commit:
      resolvedProductionTrustEvidence.verifier_commit || null,
    exochain_root_trust_verified_at:
      resolvedProductionTrustEvidence.verified_at || null,
    production_trust_observations:
      resolvedProductionTrustEvidence.non_blocking_observations || [],
    production_trust_reasons:
      resolvedProductionTrustEvidence.reasons || [],
    internal_proof_complete: productionEvidenceVerified,
    frost_genesis_complete: productionEvidenceVerified,
    public_claims_allowed: publicClaimsAllowed,
    public_claims_reason: publicClaimsReason({
      exochainConnected: Boolean(exochainConnected),
      productionEvidenceVerified,
      runtimeAdapterVerified,
      publicAdapterOutputAuthorized,
    }),
    source_basis: [
      ...SOURCE_BASIS,
      "config/exochain-production-trust.json",
      "server/utils/exochain-production-trust-evidence.js",
    ],
    version,
    uptime_seconds: uptimeSeconds,
    generated_at: generatedAt ?? new Date().toISOString()
  };

  if (publicClaimsAllowed) {
    payload.public_adapter_output_authorization =
      publicAdapterOutputAuthorizationDecision.metadata;
  }

  return payload;
}

function resolveGeneratedAt(generatedAt) {
  return generatedAt ?? new Date().toISOString();
}

async function getPublicAdapterOutputAuthorizationDecision({
  adapter,
  currentAt,
}) {
  try {
    return await adapter.getPublicAdapterOutputAuthorization({
      currentAt,
      returnDecision: true,
    });
  } catch {
    return {
      allowed: false,
      responseState: "unavailable",
      transportCalled: true,
      value: null,
    };
  }
}

async function buildLiveTrustStatusOptions({
  adapter = runtimeExochainAdapter,
  exochainConnected,
  version,
  uptimeSeconds,
  generatedAt,
  productionTrustEvidence,
}) {
  const currentAt = resolveGeneratedAt(generatedAt);
  const runtimeStatus = adapter.getRuntimeStatus();
  const adapterOutputAuthorization =
    await getPublicAdapterOutputAuthorizationDecision({
      adapter,
      currentAt,
    });

  return {
    exochainConnected,
    version,
    uptimeSeconds,
    generatedAt: currentAt,
    runtimeStatus,
    adapterOutputAuthorization,
    productionTrustEvidence,
  };
}

function sendTrustStatusResponse(_req, res, options) {
  return res.status(200).json(createTrustStatusPayload(options));
}

async function sendLiveTrustStatusResponse(_req, res, options) {
  const payloadOptions = await buildLiveTrustStatusOptions(options);
  return sendTrustStatusResponse(_req, res, payloadOptions);
}

module.exports = {
  buildLiveTrustStatusOptions,
  createTrustStatusPayload,
  sendLiveTrustStatusResponse,
  sendTrustStatusResponse
};
