"use strict";

const {
  evaluateVerifiedPublicAdapterOutputDecision,
  runtimeExochainAdapter,
} = require("./livesafe-exochain-adapter");
const {
  exochainProductionTrustEvidence,
} = require("./exochain-production-trust-evidence");
const {
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
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

function resolvePublicAdapterOutputAuthorizationDecision(
  adapterOutputAuthorization,
  { currentAt, subject, audience },
) {
  const verifiedDecision = evaluateVerifiedPublicAdapterOutputDecision(
    adapterOutputAuthorization,
    {
      currentAt,
      subject,
      audience,
    },
  );
  if (verifiedDecision) {
    return verifiedDecision;
  }

  const deniedDecision = evaluatePublicAdapterOutputAuthorization({
    allowed: false,
    responseState: "untrusted",
    transportCalled: false,
    value: null,
  }, {
    currentAt,
    subject,
    audience,
  });
  deniedDecision.reasons.unshift(
    "Public adapter-output authorization did not originate from the configured LiveSafe runtime adapter.",
  );
  return deniedDecision;
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
