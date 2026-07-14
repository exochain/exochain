"use strict";

const exochainRegistry = require("../../config/exochain-primitives.json");
const surfaceIntake = require("../../config/surface-intake.json");
const { exochain } = require("./exochain-client");
const {
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
  PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
  evaluatePublicAdapterOutputAuthorization,
} = require("./public-adapter-output-authorization");

const VERIFIED_ADAPTER_STATE = "verified";
const PUBLIC_AUTHORIZATION_BY_ADAPTER_DECISION = new WeakMap();
const EXOCHAIN_DID_PATTERN = /^did:exo:[a-z0-9_-]+:[A-Za-z0-9._:-]+$/;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const CONSENT_SCOPE_PATTERN = /^[a-z0-9][a-z0-9_:-]*$/;
const ALLOWED_AUDIT_RECEIPT_EVENT_TYPES = new Set([
  "card_scan",
  "consent_granted",
  "consent_revoked",
]);
const DENIED_TRANSPORT_STATES = new Set([
  "deny",
  "rejected",
  "timeout",
  "unavailable",
  "not-called",
  "stale",
  "revoked",
  "contradicted",
]);
const SOURCE_BASIS = [
  "docs/TEST_PLAN.md",
  "docs/context/LIVESAFE_TO_EXOCHAIN_INTEGRATION_MAP.md",
  "docs/context/LIVESAFE_PRODUCTION_TRUST_ACTIVATION_GATES.md",
  "config/exochain-primitives.json",
  "config/surface-intake.json",
  "server/utils/exochain-client.js",
];
const WRAPPED_OPERATIONS = [
  "getIdentity",
  "registerIdentity",
  "anchorAuditReceipt",
  "anchorScan",
  "anchorConsent",
  "getPaceStatus",
  "getPublicAdapterOutputAuthorization",
];

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isExochainDid(value) {
  return isNonEmptyString(value) && EXOCHAIN_DID_PATTERN.test(value);
}

function isOptionalNonEmptyString(value) {
  return typeof value === "undefined" || value === null || isNonEmptyString(value);
}

function isOptionalConsentScope(value) {
  return (
    typeof value === "undefined" ||
    value === null ||
    (isNonEmptyString(value) && CONSENT_SCOPE_PATTERN.test(value))
  );
}

function isOptionalExochainDid(value) {
  return typeof value === "undefined" || value === null || isExochainDid(value);
}

function isDefined(value) {
  return typeof value !== "undefined" && value !== null;
}

function isRequiredIdentifier(value) {
  return (
    (isNonEmptyString(value) && value.trim().length > 0) ||
    Number.isInteger(value)
  );
}

function isOptionalEpochMilliseconds(value) {
  return (
    typeof value === "undefined" ||
    value === null ||
    (Number.isInteger(value) && value >= 0)
  );
}

function isOptionalSha256Hex(value) {
  return typeof value === "undefined" || value === null || SHA256_HEX_PATTERN.test(value);
}

function hasExplicitField(input, fieldName) {
  return Boolean(input) && Object.prototype.hasOwnProperty.call(input, fieldName);
}

function createDeniedDecision({
  reasons,
  requiredEvidence,
  responseState = "not-called",
  transportCalled = false,
}) {
  return {
    allowed: false,
    reasons,
    required_evidence: requiredEvidence,
    responseState,
    transportCalled,
    value: null,
  };
}

function normalizeTransportResult(result) {
  if (result && typeof result === "object" && typeof result.state === "string") {
    if (result.state === "permit" || DENIED_TRANSPORT_STATES.has(result.state)) {
      return {
        state: result.state,
        value: Object.prototype.hasOwnProperty.call(result, "value") ? result.value : null,
      };
    }

    return {
      state: "contradicted",
      value: null,
    };
  }

  if (result === null || typeof result === "undefined") {
    return { state: "unavailable", value: null };
  }

  return { state: "permit", value: result };
}

function isTimeoutLikeError(error) {
  if (!error || typeof error !== "object") {
    return false;
  }

  const name = typeof error.name === "string" ? error.name.toLowerCase() : "";
  const code = typeof error.code === "string" ? error.code.toLowerCase() : "";
  const message = typeof error.message === "string" ? error.message.toLowerCase() : "";

  return (
    name.includes("timeout") ||
    code.includes("timeout") ||
    code === "etimedout" ||
    message.includes("timeout") ||
    message.includes("timed out") ||
    message.includes("etimedout")
  );
}

async function invokeTransport(transport) {
  try {
    return await transport();
  } catch (error) {
    return {
      state: isTimeoutLikeError(error) ? "timeout" : "unavailable",
      value: null,
    };
  }
}

async function executeRuntimeExochainOperation({
  adapterStatus,
  operationName,
  authorityInputsWellFormed,
  containsRawSensitivePayload,
  transport,
}) {
  const requiredEvidence = [];

  if (adapterStatus !== VERIFIED_ADAPTER_STATE) {
    requiredEvidence.push(
      "Verified LiveSafe adapter path invoking the EXOCHAIN dependency.",
    );
    return createDeniedDecision({
      reasons: ["Adapter activation requires a wired EXOCHAIN dependency surface."],
      requiredEvidence,
    });
  }

  if (!authorityInputsWellFormed) {
    requiredEvidence.push(
      "Adapter input validation for credentials, signatures, consent, authority, provenance, custody, tenant, and emergency access grants.",
    );
    return createDeniedDecision({
      reasons: [
        "Credentials, signatures, consent, authority, provenance, custody, tenant, and emergency access grants must be well formed before adapter activation.",
      ],
      requiredEvidence,
    });
  }

  if (containsRawSensitivePayload) {
    requiredEvidence.push(
      "Receipt boundary proving commitments, references, policy ids, and hashes only.",
    );
    return createDeniedDecision({
      reasons: [
        "Adapter activation cannot carry raw sensitive payloads on-chain or in receipt paths.",
      ],
      requiredEvidence,
    });
  }

  const normalized = normalizeTransportResult(await invokeTransport(transport));

  if (normalized.state !== "permit") {
    requiredEvidence.push(
      "Denied, rejected, timeout, unavailable, not-called, stale, revoked, and contradicted adapter regression tests.",
    );
    return createDeniedDecision({
      reasons: [
        "EXOCHAIN adapter activation must fail closed unless EXOCHAIN returns permit.",
      ],
      requiredEvidence,
      responseState: normalized.state,
      transportCalled: true,
    });
  }

  return {
    allowed: true,
    reasons: [],
    required_evidence: [],
    responseState: normalized.state,
    transportCalled: true,
    value: normalized.value,
  };
}

function createRuntimeExochainAdapter({
  adapterStatus = exochainRegistry.runtimeAdapterStatus,
  client = exochain,
  disablementPath = surfaceIntake.disablementPath,
  surfaceClassification = surfaceIntake.classification,
} = {}) {
  function getRuntimeStatus() {
    return {
      adapter_state: adapterStatus,
      surface_classification: surfaceClassification,
      public_claims_allowed: false,
      can_read_exochain_core_state: adapterStatus === VERIFIED_ADAPTER_STATE,
      can_write_exochain_core_state: adapterStatus === VERIFIED_ADAPTER_STATE,
      wrapped_operations: WRAPPED_OPERATIONS,
      disablement_path: disablementPath,
      source_basis: SOURCE_BASIS,
    };
  }

  async function runOperation(operationName, options, transport) {
    return executeRuntimeExochainOperation({
      adapterStatus,
      operationName,
      authorityInputsWellFormed: options.authorityInputsWellFormed !== false,
      containsRawSensitivePayload: options.containsRawSensitivePayload === true,
      transport,
    });
  }

  async function evaluatePublicAuthorizationTransport(options = {}) {
    const subject = options.subject || PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT;
    const audience = options.audience || PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE;
    const currentAt = options.currentAt;
    const authorityInputsWellFormed =
      subject === PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT &&
      audience === PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE &&
      isNonEmptyString(currentAt);
    const operationDecision = await runOperation(
      "getPublicAdapterOutputAuthorization",
      {
        authorityInputsWellFormed,
        containsRawSensitivePayload: false,
      },
      async () =>
        client.getPublicAdapterOutputAuthorization({
          subject,
          audience,
          currentAt,
        }),
    );
    const evaluationInput = {
      allowed: operationDecision.allowed,
      responseState: operationDecision.responseState,
      transportCalled: operationDecision.transportCalled,
      value: operationDecision.value,
    };
    const evaluation = evaluatePublicAdapterOutputAuthorization(
      evaluationInput,
      {
        currentAt,
        subject: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
        audience: PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
      },
    );
    const publicAdapterDecision = {
      allowed: operationDecision.allowed && evaluation.allowed,
      reasons: [],
      required_evidence: [],
      responseState: operationDecision.responseState,
      transportCalled: operationDecision.transportCalled,
      value: evaluation.allowed ? evaluation.metadata : null,
      metadata: evaluation.metadata,
    };
    const reasons = [
      ...operationDecision.reasons,
      ...evaluation.reasons.filter(
        (reason) => !operationDecision.reasons.includes(reason),
      ),
    ];
    const requiredEvidence = [
      ...operationDecision.required_evidence,
      ...evaluation.required_evidence.filter(
        (evidence) => !operationDecision.required_evidence.includes(evidence),
      ),
    ];

    publicAdapterDecision.allowed = operationDecision.allowed && evaluation.allowed;
    publicAdapterDecision.reasons = reasons;
    publicAdapterDecision.required_evidence = requiredEvidence;
    PUBLIC_AUTHORIZATION_BY_ADAPTER_DECISION.set(
      publicAdapterDecision,
      operationDecision.value,
    );
    return publicAdapterDecision;
  }

  return {
    getRuntimeStatus,
    async getIdentity(did, options = {}) {
      const decision = await runOperation(
        "getIdentity",
        {
          authorityInputsWellFormed: isExochainDid(did),
          containsRawSensitivePayload: false,
          ...options,
        },
        async () => client.getIdentity(did),
      );
      return options.returnDecision ? decision : decision.value;
    },
    async registerIdentity(did, options = {}) {
      const decision = await runOperation(
        "registerIdentity",
        {
          authorityInputsWellFormed: isExochainDid(did),
          containsRawSensitivePayload: false,
          ...options,
        },
        async () => client.registerIdentity(did),
      );
      return options.returnDecision ? decision : decision.value;
    },
    async anchorAuditReceipt(subscriberDid, receiptHash, eventType, options = {}) {
      const decision = await runOperation(
        "anchorAuditReceipt",
        {
          authorityInputsWellFormed:
            isExochainDid(subscriberDid) &&
            isNonEmptyString(receiptHash) &&
            SHA256_HEX_PATTERN.test(receiptHash) &&
            isNonEmptyString(eventType) &&
            ALLOWED_AUDIT_RECEIPT_EVENT_TYPES.has(eventType),
          containsRawSensitivePayload: false,
          ...options,
        },
        async () => client.anchorAuditReceipt(subscriberDid, receiptHash, eventType),
      );
      return options.returnDecision ? decision : decision.value;
    },
    async anchorScan(input, options = {}) {
      const decision = await runOperation(
        "anchorScan",
        {
          authorityInputsWellFormed:
            Boolean(input) &&
            isRequiredIdentifier(input.scanId) &&
            isExochainDid(input.subscriberDid) &&
            isOptionalExochainDid(input.responderDid) &&
            isOptionalEpochMilliseconds(input.scannedAtMs) &&
            isOptionalEpochMilliseconds(input.consentExpiresAtMs) &&
            isOptionalSha256Hex(input.auditReceiptHash),
          containsRawSensitivePayload:
            options.containsRawSensitivePayload === true || hasExplicitField(input, "location"),
          ...options,
        },
        async () => client.anchorScan(input),
      );
      return options.returnDecision ? decision : decision.value;
    },
    async anchorConsent(input, options = {}) {
      const decision = await runOperation(
        "anchorConsent",
        {
          authorityInputsWellFormed:
            Boolean(input) &&
            isRequiredIdentifier(input.consentId) &&
            isExochainDid(input.subscriberDid) &&
            isOptionalExochainDid(input.providerDid) &&
            isOptionalConsentScope(input.scope) &&
            isOptionalEpochMilliseconds(input.grantedAtMs) &&
            isOptionalEpochMilliseconds(input.expiresAtMs),
          containsRawSensitivePayload: false,
          ...options,
        },
        async () => client.anchorConsent(input),
      );
      return options.returnDecision ? decision : decision.value;
    },
    async getPaceStatus(subscriberDid, options = {}) {
      const decision = await runOperation(
        "getPaceStatus",
        {
          authorityInputsWellFormed: isExochainDid(subscriberDid),
          containsRawSensitivePayload: false,
          ...options,
        },
        async () => client.getPaceStatus(subscriberDid),
      );
      if (options.returnDecision) {
        return decision;
      }
      return Array.isArray(decision.value) ? decision.value : [];
    },
    async getPublicAdapterOutputAuthorization(options = {}) {
      const decision = await evaluatePublicAuthorizationTransport(options);
      return options.returnDecision ? decision : decision.metadata;
    },
  };
}

const runtimeExochainAdapter = createRuntimeExochainAdapter();

function evaluateVerifiedPublicAdapterOutputDecision(decision, options) {
  const authorization = PUBLIC_AUTHORIZATION_BY_ADAPTER_DECISION.get(decision);
  if (typeof authorization === "undefined") {
    return null;
  }

  return evaluatePublicAdapterOutputAuthorization(
    {
      allowed: decision.allowed,
      responseState: decision.responseState,
      transportCalled: decision.transportCalled,
      value: authorization,
    },
    options,
  );
}

module.exports = {
  createRuntimeExochainAdapter,
  evaluateVerifiedPublicAdapterOutputDecision,
  executeRuntimeExochainOperation,
  runtimeExochainAdapter,
};
