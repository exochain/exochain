import { afterEach, describe, expect, it, vi } from "vitest";

const {
  ExochainClient,
  buildPublicAdapterOutputAuthorizationRequest,
} = require("../server/utils/exochain-client.js");

function repeatedByte(byte: number, length: number) {
  return Array.from({ length }, () => byte);
}

function repeatedHex(byte: number, length: number) {
  return byte.toString(16).padStart(2, "0").repeat(length);
}

const EVIDENCE_HASH_BYTES = repeatedByte(0xbb, 32);
const CREDENTIAL_ID_BYTES = repeatedByte(0xbc, 32);
const PROOF_HASH_BYTES = repeatedByte(0xcc, 32);
const ACTION_COMMITMENT_HASH_BYTES = repeatedByte(0xdd, 32);
const IDEMPOTENCY_KEY_HASH_BYTES = repeatedByte(0xee, 32);
const ED25519_SIGNATURE_BYTES = repeatedByte(0xaa, 64);
const RECEIPT_ID_BYTES = repeatedByte(0x6f, 32);
const EVIDENCE_HASH_HEX = repeatedHex(0xbb, 32);
const CREDENTIAL_ID_HEX = repeatedHex(0xbc, 32);
const RECEIPT_ID_HEX = repeatedHex(0x6f, 32);
const ALT_EVIDENCE_HASH_HEX = repeatedHex(0xab, 32);
const ALT_CREDENTIAL_ID_HEX = repeatedHex(0xcd, 32);
const PROOF_HASH_HEX = repeatedHex(0xcc, 32);
const ED25519_SIGNATURE_HEX = repeatedHex(0xaa, 64);

const PUBLIC_ADAPTER_AUTHORIZATION_DTO = {
  schema: "livesafe.public_adapter_output_authorization.v1",
  subject: "livesafe.ai",
  audience: "https://livesafe.ai/api/trust/status",
  claims: [
    "livesafe_public_trust_status",
    "exochain_production_evidence_verified",
    "livesafe_runtime_adapter_verified",
  ],
  evidence_hash:
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  receipt_id: "exo-receipt:public-adapter-output:2026-07-05",
  proof_id: "exo-proof:public-adapter-output:2026-07-05",
  proof_ref: "exo://receipts/public-adapter-output/2026-07-05",
  generated_at: "2026-07-05T11:59:00.000Z",
  valid_from: "2026-07-05T11:55:00.000Z",
  expires_at: "2026-07-05T12:05:00.000Z",
  proof: {
    type: "ed25519-public-adapter-output-authorization",
    signature:
      "ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  },
};

const PUBLIC_ADAPTER_AUTHORIZATION_REST_CONFIG = {
  EXOCHAIN_NODE_URL: "https://exo-node.example",
  EXOCHAIN_NODE_AVC_URL: "",
  EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_BEARER:
    "secret-public-adapter-bearer",
  EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_ID:
    `sha256:${CREDENTIAL_ID_HEX}`,
  EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_EVIDENCE_HASH: `sha256:${EVIDENCE_HASH_HEX}`,
  EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_IDEMPOTENCY_KEY:
    "idem:livesafe-public-adapter-output:2026-07-05T12:00:00Z",
  EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_IDEMPOTENCY_NAMESPACE:
    "livesafe-public-adapter-output",
  EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_EXPIRES_AT: "2026-07-05T12:05:00.000Z",
  EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_TTL_MS: "300000",
  EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_TIMEOUT_MS: "2500",
};

const PUBLIC_ADAPTER_AUTHORIZATION_RUST_CORE_ENVELOPE = {
  schema_version: 1,
  domain: "livesafe.public_adapter_output_authorization.v1",
  proof: {
    schema_version: 1,
    domain: "livesafe.public_adapter_output_authorization.v1",
    subject: "livesafe.ai",
    audience: "https://livesafe.ai/api/trust/status",
    evidence_hash: EVIDENCE_HASH_BYTES,
    credential_id: "credential:livesafe-public-adapter-output",
    receipt_id: "exo-receipt:public-adapter-output:2026-07-05",
    action_commitment_hash: ACTION_COMMITMENT_HASH_BYTES,
    idempotency_key_hash: IDEMPOTENCY_KEY_HASH_BYTES,
    issued_at: {
      physical_ms: Date.parse("2026-07-05T11:59:00.000Z"),
      logical: 3,
    },
    expires_at: {
      physical_ms: Date.parse("2026-07-05T12:05:00.000Z"),
      logical: 0,
    },
    revocation_status: "NotRevoked",
    signer_did: "did:exo:livesafe:node",
    proof_hash: PROOF_HASH_BYTES,
    signature: {
      Ed25519: ED25519_SIGNATURE_BYTES,
    },
  },
};

const PUBLIC_ADAPTER_AUTHORIZATION_DTO_FROM_RUST = {
  schema: "livesafe.public_adapter_output_authorization.v1",
  subject: "livesafe.ai",
  audience: "https://livesafe.ai/api/trust/status",
  claims: [
    "livesafe_public_trust_status",
    "exochain_production_evidence_verified",
    "livesafe_runtime_adapter_verified",
  ],
  evidence_hash: `sha256:${EVIDENCE_HASH_HEX}`,
  receipt_id: "exo-receipt:public-adapter-output:2026-07-05",
  proof_id: `sha256:${PROOF_HASH_HEX}`,
  proof_ref: `exochain-avc:sha256:${PROOF_HASH_HEX}`,
  generated_at: "2026-07-05T11:59:00.000Z",
  valid_from: "2026-07-05T11:59:00.000Z",
  expires_at: "2026-07-05T12:05:00.000Z",
  proof: {
    type: "ed25519-public-adapter-output-authorization",
    signature: `ed25519:${ED25519_SIGNATURE_HEX}`,
  },
};

const PUBLIC_ADAPTER_AUTHORIZATION_STRING_ONLY_RUST_LIKE_ENVELOPE = rustCoreEnvelope({
  proof: {
    evidence_hash: `sha256:${EVIDENCE_HASH_HEX}`,
    action_commitment_hash: `sha256:${repeatedHex(0xdd, 32)}`,
    idempotency_key_hash: `sha256:${repeatedHex(0xee, 32)}`,
    proof_hash: `sha256:${PROOF_HASH_HEX}`,
    signature: `ed25519:${ED25519_SIGNATURE_HEX}`,
  },
});

const PUBLIC_ADAPTER_AUTHORIZATION_LEGACY_FAKE_ENVELOPE = {
  envelope_schema:
    "exochain.avc.livesafe.public_adapter_output_authorization_envelope.v1",
  status: "authorized",
  subject: "livesafe.ai",
  audience: "https://livesafe.ai/api/trust/status",
  domain: "livesafe.ai",
  claims: [
    "livesafe_public_trust_status",
    "exochain_production_evidence_verified",
    "livesafe_runtime_adapter_verified",
  ],
  evidence_hash:
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  receipt: {
    id: "exo-receipt:public-adapter-output:2026-07-05",
  },
  proof: {
    id: "exo-proof:public-adapter-output:2026-07-05",
    ref: "exo://receipts/public-adapter-output/2026-07-05",
    type: "ed25519-public-adapter-output-authorization",
    signature:
      "ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  },
  issued_at: {
    physical_ms: Date.parse("2026-07-05T11:59:00.000Z"),
    logical: 3,
  },
  valid_from: {
    physical_ms: Date.parse("2026-07-05T11:55:00.000Z"),
    logical: 0,
  },
  expires_at: "2026-07-05T12:05:00.000Z",
};

function rustCoreEnvelope({
  envelope = {},
  proof = {},
}: {
  envelope?: Record<string, unknown>;
  proof?: Record<string, unknown>;
} = {}) {
  return {
    ...PUBLIC_ADAPTER_AUTHORIZATION_RUST_CORE_ENVELOPE,
    ...envelope,
    proof: {
      ...PUBLIC_ADAPTER_AUTHORIZATION_RUST_CORE_ENVELOPE.proof,
      ...proof,
    },
  };
}

const PUBLIC_ADAPTER_AUTHORIZATION_ENV_KEYS = Object.keys(
  PUBLIC_ADAPTER_AUTHORIZATION_REST_CONFIG,
);

const savedPublicAdapterAuthorizationEnv = Object.fromEntries(
  PUBLIC_ADAPTER_AUTHORIZATION_ENV_KEYS.map((key) => [key, process.env[key]]),
);

function restorePublicAdapterAuthorizationEnv() {
  for (const key of PUBLIC_ADAPTER_AUTHORIZATION_ENV_KEYS) {
    const value = savedPublicAdapterAuthorizationEnv[key];

    if (typeof value === "undefined") {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
}

function clearPublicAdapterAuthorizationEnv() {
  for (const key of PUBLIC_ADAPTER_AUTHORIZATION_ENV_KEYS) {
    delete process.env[key];
  }
}

function configurePublicAdapterAuthorizationEnv(
  overrides: Partial<typeof PUBLIC_ADAPTER_AUTHORIZATION_REST_CONFIG> = {},
) {
  clearPublicAdapterAuthorizationEnv();
  for (const [key, value] of Object.entries({
    ...PUBLIC_ADAPTER_AUTHORIZATION_REST_CONFIG,
    ...overrides,
  })) {
    if (value) {
      process.env[key] = value;
    }
  }
}

function publicAuthorizationRequestBodies(fetch: ReturnType<typeof vi.fn>) {
  return fetch.mock.calls.map(([, requestInit]) =>
    JSON.parse((requestInit as { body: string }).body),
  );
}

function mockPublicAuthorizationFetchForCurrentAts(currentAts: string[]) {
  if (currentAts.length === 0) {
    throw new Error("at least one public authorization timestamp is required");
  }

  let callIndex = 0;

  return vi.fn(async () => {
    const currentAt = currentAts[Math.min(callIndex, currentAts.length - 1)] as string;
    callIndex += 1;
    const physicalMs = Date.parse(currentAt);

    return {
      ok: true,
      json: async () =>
        rustCoreEnvelope({
          proof: {
            issued_at: {
              physical_ms: physicalMs,
              logical: 0,
            },
            expires_at: {
              physical_ms: physicalMs + 300000,
              logical: 0,
            },
          },
        }),
    };
  });
}

describe("EXOCHAIN client timestamp preservation", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    restorePublicAdapterAuthorizationEnv();
  });

  it.each([
    {
      label: "timeout-like gateway exception",
      error: Object.assign(new Error("connect ETIMEDOUT 127.0.0.1:8080"), {
        code: "ETIMEDOUT",
      }),
      expected: {
        data: null,
        errors: [
          {
            message: "EXOCHAIN_TIMEOUT",
            code: "EXOCHAIN_TIMEOUT",
          },
        ],
      },
    },
    {
      label: "unavailable gateway exception",
      error: new Error("getaddrinfo ENOTFOUND exochain.internal"),
      expected: {
        data: null,
        errors: [
          {
            message: "EXOCHAIN_UNAVAILABLE",
            code: "EXOCHAIN_UNAVAILABLE",
          },
        ],
      },
    },
  ])("redacts raw transport details for $label", async ({ error, expected }) => {
    const client = new ExochainClient("http://example.invalid/graphql");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(error));

    const result = await client.query("Health", "{ __typename }");

    expect(result).toEqual(expected);
  });

  it.each([
    {
      label: "registerIdentity",
      call: (client: InstanceType<typeof ExochainClient>) => client.registerIdentity("subscriber:test"),
      expected: null,
    },
    {
      label: "getIdentity",
      call: (client: InstanceType<typeof ExochainClient>) => client.getIdentity("subscriber:test"),
      expected: null,
    },
    {
      label: "getPaceStatus",
      call: (client: InstanceType<typeof ExochainClient>) => client.getPaceStatus("subscriber:test"),
      expected: [],
    },
  ])("fails closed before query when %s receives a malformed subscriber DID", async ({ call, expected }) => {
    const client = new ExochainClient("http://example.invalid/graphql");
    const query = vi.spyOn(client, "query").mockResolvedValue({
      data: {},
    });

    const result = await call(client);

    expect(result).toEqual(expected);
    expect(query).not.toHaveBeenCalled();
  });

  it("fails closed before query when anchorScan receives a malformed direct client identifier", async () => {
    const client = new ExochainClient("http://example.invalid/graphql");
    const query = vi.spyOn(client, "query").mockResolvedValue({
      data: {
        livesafe_anchor_scan: {
          scan_id: "scan-1",
          tx_hash: "scan-tx",
        },
      },
    });

    const result = await client.anchorScan({
      scanId: { raw: "scan-1" },
      subscriberDid: "did:exo:subscriber:test",
    });

    expect(result).toBeNull();
    expect(query).not.toHaveBeenCalled();
  });

  it.each([
    {
      label: "malformed audit subscriber DID",
      subscriberDid: "subscriber:test",
      receiptHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      eventType: "card_scan",
    },
    {
      label: "malformed audit receipt hash",
      subscriberDid: "did:exo:subscriber:test",
      receiptHash: "not-a-sha256",
      eventType: "card_scan",
    },
    {
      label: "unsupported audit event type",
      subscriberDid: "did:exo:subscriber:test",
      receiptHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      eventType: "identity_recovered",
    },
  ])("fails closed before query when anchorAuditReceipt receives $label", async ({
    subscriberDid,
    receiptHash,
    eventType,
  }) => {
    const client = new ExochainClient("http://example.invalid/graphql");
    const query = vi.spyOn(client, "query").mockResolvedValue({
      data: {
        livesafe_anchor_audit_receipt: "tx-hash",
      },
    });

    const result = await client.anchorAuditReceipt(subscriberDid, receiptHash, eventType);

    expect(result).toBeNull();
    expect(query).not.toHaveBeenCalled();
  });

  it("preserves explicit zero-valued scan timestamps in the GraphQL payload", async () => {
    const client = new ExochainClient("http://example.invalid/graphql");
    const query = vi.spyOn(client, "query").mockResolvedValue({
      data: {
        livesafe_anchor_scan: {
          scan_id: "scan-1",
          tx_hash: "scan-tx",
        },
      },
    });
    vi.spyOn(Date, "now").mockReturnValue(123456789);

    await client.anchorScan({
      scanId: "scan-1",
      subscriberDid: "did:exo:subscriber:test",
      scannedAtMs: 0,
      consentExpiresAtMs: 0,
    });

    expect(query).toHaveBeenCalledWith(
      "AnchorScan",
      expect.any(String),
      expect.objectContaining({
        input: expect.objectContaining({
          scanned_at_ms: 0,
          consent_expires_at_ms: 0,
        }),
      }),
    );
  });

  it("omits the location field entirely from metadata-only scan anchor payloads", async () => {
    const client = new ExochainClient("http://example.invalid/graphql");
    const query = vi.spyOn(client, "query").mockResolvedValue({
      data: {
        livesafe_anchor_scan: {
          scan_id: "scan-1",
          tx_hash: "scan-tx",
        },
      },
    });

    await client.anchorScan({
      scanId: "scan-1",
      subscriberDid: "did:exo:subscriber:test",
      responderDid: "did:exo:responder:test",
      scannedAtMs: 0,
      consentExpiresAtMs: 0,
      auditReceiptHash:
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    });

    const variables = query.mock.calls[0]?.[2] as
      | { input: Record<string, unknown> }
      | undefined;

    expect(variables?.input).not.toHaveProperty("location");
    expect(variables?.input).toMatchObject({
      scan_id: "scan-1",
      subscriber_did: "did:exo:subscriber:test",
      responder_did: "did:exo:responder:test",
      scanned_at_ms: 0,
      consent_expires_at_ms: 0,
      audit_receipt_hash:
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    });
  });

  it.each([
    {
      label: "malformed responder DID",
      input: {
        scanId: "scan-1",
        subscriberDid: "did:exo:subscriber:test",
        responderDid: "responder:test",
      },
    },
    {
      label: "negative scan timestamp",
      input: {
        scanId: "scan-1",
        subscriberDid: "did:exo:subscriber:test",
        scannedAtMs: -1,
      },
    },
    {
      label: "fractional consent-expiry timestamp",
      input: {
        scanId: "scan-1",
        subscriberDid: "did:exo:subscriber:test",
        consentExpiresAtMs: 1.5,
      },
    },
    {
      label: "malformed audit receipt hash",
      input: {
        scanId: "scan-1",
        subscriberDid: "did:exo:subscriber:test",
        auditReceiptHash: "not-a-sha256",
      },
    },
    {
      label: "explicit raw-sensitive location field",
      input: {
        scanId: "scan-1",
        subscriberDid: "did:exo:subscriber:test",
        location: "",
      },
    },
  ])("fails closed before query when anchorScan receives $label", async ({ input }) => {
    const client = new ExochainClient("http://example.invalid/graphql");
    const query = vi.spyOn(client, "query").mockResolvedValue({
      data: {
        livesafe_anchor_scan: {
          scan_id: "scan-1",
          tx_hash: "scan-tx",
        },
      },
    });

    const result = await client.anchorScan(input);

    expect(result).toBeNull();
    expect(query).not.toHaveBeenCalled();
  });

  it("fails closed before query when anchorConsent receives a malformed direct client identifier", async () => {
    const client = new ExochainClient("http://example.invalid/graphql");
    const query = vi.spyOn(client, "query").mockResolvedValue({
      data: {
        livesafe_anchor_consent: {
          consent_id: "consent-1",
          tx_hash: "consent-tx",
        },
      },
    });

    const result = await client.anchorConsent({
      consentId: { raw: "consent-1" },
      subscriberDid: "did:exo:subscriber:test",
    });

    expect(result).toBeNull();
    expect(query).not.toHaveBeenCalled();
  });

  it.each([
    { label: "undefined input", input: undefined },
    { label: "null input", input: null },
  ])("fails closed before query when anchorConsent receives $label", async ({ input }) => {
    const client = new ExochainClient("http://example.invalid/graphql");
    const query = vi.spyOn(client, "query").mockResolvedValue({
      data: {
        livesafe_anchor_consent: {
          consent_id: "consent-1",
          tx_hash: "consent-tx",
        },
      },
    });

    const result = await client.anchorConsent(input as never);

    expect(result).toBeNull();
    expect(query).not.toHaveBeenCalled();
  });

  it("preserves explicit zero-valued consent timestamps in the GraphQL payload", async () => {
    const client = new ExochainClient("http://example.invalid/graphql");
    const query = vi.spyOn(client, "query").mockResolvedValue({
      data: {
        livesafe_anchor_consent: {
          consent_id: "consent-1",
          tx_hash: "consent-tx",
        },
      },
    });
    vi.spyOn(Date, "now").mockReturnValue(987654321);

    await client.anchorConsent({
      consentId: "consent-1",
      subscriberDid: "did:exo:subscriber:test",
      grantedAtMs: 0,
      expiresAtMs: 0,
    });

    expect(query).toHaveBeenCalledWith(
      "AnchorConsent",
      expect.any(String),
      expect.objectContaining({
        input: expect.objectContaining({
          granted_at_ms: 0,
          expires_at_ms: 0,
        }),
      }),
    );
  });

  it.each([
    {
      label: "malformed provider DID",
      input: {
        consentId: "consent-1",
        subscriberDid: "did:exo:subscriber:test",
        providerDid: "provider:test",
      },
    },
    {
      label: "whitespace-bearing scope token",
      input: {
        consentId: "consent-1",
        subscriberDid: "did:exo:subscriber:test",
        scope: "medical release",
      },
    },
    {
      label: "negative granted timestamp",
      input: {
        consentId: "consent-1",
        subscriberDid: "did:exo:subscriber:test",
        grantedAtMs: -1,
      },
    },
    {
      label: "fractional expiry timestamp",
      input: {
        consentId: "consent-1",
        subscriberDid: "did:exo:subscriber:test",
        expiresAtMs: 1.5,
      },
    },
  ])("fails closed before query when anchorConsent receives $label", async ({ input }) => {
    const client = new ExochainClient("http://example.invalid/graphql");
    const query = vi.spyOn(client, "query").mockResolvedValue({
      data: {
        livesafe_anchor_consent: {
          consent_id: "consent-1",
          tx_hash: "consent-tx",
        },
      },
    });

    const result = await client.anchorConsent(input);

    expect(result).toBeNull();
    expect(query).not.toHaveBeenCalled();
  });

  it("fails closed without explicit node authorization configuration and never falls back to GraphQL", async () => {
    clearPublicAdapterAuthorizationEnv();
    const client = new ExochainClient("http://graphql.example/graphql");
    const query = vi.spyOn(client, "query").mockResolvedValue({
      data: {
        livesafe_public_adapter_output_authorization:
          PUBLIC_ADAPTER_AUTHORIZATION_DTO,
      },
    });
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    const result = await client.getPublicAdapterOutputAuthorization({
      subject: "livesafe.ai",
      audience: "https://livesafe.ai/api/trust/status",
      currentAt: "2026-07-05T12:00:00.000Z",
    });

    expect(result).toEqual({ state: "unavailable", value: null });
    expect(fetch).not.toHaveBeenCalled();
    expect(query).not.toHaveBeenCalled();
  });

  it("fails closed before REST transport when public adapter-output authorization subject or audience is not exact", async () => {
    configurePublicAdapterAuthorizationEnv();

    for (const input of [
      {
        subject: "www.livesafe.ai",
        audience: "https://livesafe.ai/api/trust/status",
        currentAt: "2026-07-05T12:00:00.000Z",
      },
      {
        subject: "livesafe.ai",
        audience: "https://livesafe.ai/api/health",
        currentAt: "2026-07-05T12:00:00.000Z",
      },
    ]) {
      const client = new ExochainClient("http://example.invalid/graphql");
      const fetch = vi.fn();
      vi.stubGlobal("fetch", fetch);

      const result = await client.getPublicAdapterOutputAuthorization(input);

      expect(result).toEqual({ state: "rejected", value: null });
      expect(fetch).not.toHaveBeenCalled();
    }
  });

  it.each([
    {
      label: "credential_id is not a strict sha256 hash",
      override: {
        EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_ID:
          "credential:livesafe-public-adapter-output-secret",
      },
      leaked: "livesafe-public-adapter-output-secret",
    },
    {
      label: "evidence_hash is not a strict sha256 hash",
      override: {
        EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_EVIDENCE_HASH:
          `sha256:${EVIDENCE_HASH_HEX.slice(0, 62)}secret`,
      },
      leaked: "secret",
    },
    {
      label: "bearer token is missing",
      override: {
        EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_BEARER: "",
      },
      leaked: "secret-public-adapter-bearer",
    },
    {
      label: "base URL is malformed",
      override: {
        EXOCHAIN_NODE_URL: "not-a-url-secret-host",
        EXOCHAIN_NODE_AVC_URL: "",
      },
      leaked: "secret-host",
    },
    {
      label: "ttl exceeds the evaluator freshness window",
      override: {
        EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_TTL_MS: "300001",
      },
      leaked: "secret-public-adapter-bearer",
    },
  ])("fails closed before REST transport when $label", async ({
    override,
    leaked,
  }) => {
    configurePublicAdapterAuthorizationEnv(override);
    const client = new ExochainClient("http://example.invalid/graphql");
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    const result = await client.getPublicAdapterOutputAuthorization({
      subject: "livesafe.ai",
      audience: "https://livesafe.ai/api/trust/status",
      currentAt: "2026-07-05T12:00:00.000Z",
    });

    expect(result).toEqual({ state: "unavailable", value: null });
    expect(fetch).not.toHaveBeenCalled();
    expect(JSON.stringify(warn.mock.calls)).not.toContain(leaked);
    expect(JSON.stringify(warn.mock.calls)).not.toContain(
      "secret-public-adapter-bearer",
    );
  });

  it("does not require static public adapter-output idempotency or expiry env to call EXOCHAIN", async () => {
    configurePublicAdapterAuthorizationEnv({
      EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_IDEMPOTENCY_KEY: "",
      EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_EXPIRES_AT: "",
    });
    const client = new ExochainClient("http://example.invalid/graphql");
    const fetch = mockPublicAuthorizationFetchForCurrentAts([
      "2026-07-05T12:00:00.000Z",
    ]);
    vi.stubGlobal("fetch", fetch);

    const result = await client.getPublicAdapterOutputAuthorization({
      subject: "livesafe.ai",
      audience: "https://livesafe.ai/api/trust/status",
      currentAt: "2026-07-05T12:00:00.000Z",
    });

    expect(result.state).toBe("permit");
    expect(fetch).toHaveBeenCalledTimes(1);
    const [requestBody] = publicAuthorizationRequestBodies(fetch);
    expect(requestBody.idempotency_key).toMatch(
      /^livesafe-public-adapter-output:sha256:[a-f0-9]{64}$/,
    );
    expect(requestBody.idempotency_key).not.toBe(
      "idem:livesafe-public-adapter-output:2026-07-05T12:00:00Z",
    );
    expect(requestBody.expires_at).toEqual({
      physical_ms: Date.parse("2026-07-05T12:05:00.000Z"),
      logical: 0,
    });
  });

  it("rotates public adapter-output authorization request material when currentAt leaves the freshness window", async () => {
    configurePublicAdapterAuthorizationEnv();
    const client = new ExochainClient("http://example.invalid/graphql");
    const fetch = mockPublicAuthorizationFetchForCurrentAts([
      "2026-07-05T12:00:00.000Z",
      "2026-07-05T12:06:00.000Z",
    ]);
    vi.stubGlobal("fetch", fetch);

    await client.getPublicAdapterOutputAuthorization({
      subject: "livesafe.ai",
      audience: "https://livesafe.ai/api/trust/status",
      currentAt: "2026-07-05T12:00:00.000Z",
    });
    await client.getPublicAdapterOutputAuthorization({
      subject: "livesafe.ai",
      audience: "https://livesafe.ai/api/trust/status",
      currentAt: "2026-07-05T12:06:00.000Z",
    });

    const [firstRequest, secondRequest] = publicAuthorizationRequestBodies(fetch);
    expect(firstRequest.idempotency_key).not.toBe(secondRequest.idempotency_key);
    expect(firstRequest.idempotency_key).not.toBe(
      "idem:livesafe-public-adapter-output:2026-07-05T12:00:00Z",
    );
    expect(secondRequest.expires_at).toEqual({
      physical_ms: Date.parse("2026-07-05T12:10:00.000Z"),
      logical: 0,
    });
  });

  it("binds public adapter-output request idempotency to target, credential, evidence, and stable current time window material", () => {
    const baseRequest = {
      subject: "livesafe.ai",
      audience: "https://livesafe.ai/api/trust/status",
      credentialId: `sha256:${CREDENTIAL_ID_HEX}`,
      credentialIdBytes: CREDENTIAL_ID_BYTES,
      evidenceHash: `sha256:${EVIDENCE_HASH_HEX}`,
      evidenceHashBytes: EVIDENCE_HASH_BYTES,
      currentAt: "2026-07-05T12:00:00.000Z",
      namespace: "livesafe-public-adapter-output",
      ttlMs: 300000,
    };

    const firstRequest =
      buildPublicAdapterOutputAuthorizationRequest(baseRequest);
    const sameWindowRequest = buildPublicAdapterOutputAuthorizationRequest({
      ...baseRequest,
      currentAt: "2026-07-05T12:04:59.999Z",
    });
    const nextWindowRequest = buildPublicAdapterOutputAuthorizationRequest({
      ...baseRequest,
      currentAt: "2026-07-05T12:05:00.000Z",
    });
    const evidenceChangedRequest = buildPublicAdapterOutputAuthorizationRequest({
      ...baseRequest,
      evidenceHash: `sha256:${ALT_EVIDENCE_HASH_HEX}`,
      evidenceHashBytes: repeatedByte(0xab, 32),
    });
    const credentialChangedRequest =
      buildPublicAdapterOutputAuthorizationRequest({
        ...baseRequest,
        credentialId: `sha256:${ALT_CREDENTIAL_ID_HEX}`,
        credentialIdBytes: repeatedByte(0xcd, 32),
      });
    const targetChangedRequest = buildPublicAdapterOutputAuthorizationRequest({
      ...baseRequest,
      audience: "https://livesafe.ai/api/health",
    });

    expect(firstRequest.idempotency_key).toMatch(
      /^livesafe-public-adapter-output:sha256:[a-f0-9]{64}$/,
    );
    expect(sameWindowRequest.idempotency_key).toBe(
      firstRequest.idempotency_key,
    );
    expect(sameWindowRequest.expires_at).toEqual(firstRequest.expires_at);
    expect(nextWindowRequest.idempotency_key).not.toBe(
      firstRequest.idempotency_key,
    );
    expect(nextWindowRequest.expires_at).not.toEqual(firstRequest.expires_at);
    expect(nextWindowRequest.expires_at).toEqual({
      physical_ms: Date.parse("2026-07-05T12:10:00.000Z"),
      logical: 0,
    });
    expect(evidenceChangedRequest.idempotency_key).not.toBe(
      firstRequest.idempotency_key,
    );
    expect(credentialChangedRequest.idempotency_key).not.toBe(
      firstRequest.idempotency_key,
    );
    expect(targetChangedRequest.idempotency_key).not.toBe(
      firstRequest.idempotency_key,
    );
    expect(firstRequest.idempotency_key).not.toContain(CREDENTIAL_ID_HEX);
    expect(firstRequest.idempotency_key).not.toContain(EVIDENCE_HASH_HEX);
    expect(firstRequest.idempotency_key).not.toContain(
      "secret-public-adapter-bearer",
    );
  });

  it("posts public adapter-output authorization to the configured EXOCHAIN node REST route", async () => {
    configurePublicAdapterAuthorizationEnv();
    const client = new ExochainClient("http://example.invalid/graphql");
    const query = vi.spyOn(client, "query");
    const fetch = vi.fn(async () => ({
      ok: true,
      json: async () => PUBLIC_ADAPTER_AUTHORIZATION_RUST_CORE_ENVELOPE,
    }));
    vi.stubGlobal("fetch", fetch);

    const result = await client.getPublicAdapterOutputAuthorization({
      subject: "livesafe.ai",
      audience: "https://livesafe.ai/api/trust/status",
      currentAt: "2026-07-05T12:00:00.000Z",
    });

    expect(result).toEqual({
      state: "permit",
      value: PUBLIC_ADAPTER_AUTHORIZATION_DTO_FROM_RUST,
    });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(
      "https://exo-node.example/api/v1/avc/livesafe/public-adapter-output-authorization",
      expect.objectContaining({
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer secret-public-adapter-bearer",
        },
        body: expect.any(String),
        signal: expect.any(Object),
      }),
    );
    const [, requestInit] = fetch.mock.calls[0] as unknown as [
      string,
      { body: string },
    ];
    const requestBody = JSON.parse(requestInit.body);
    expect(requestBody).toEqual({
      subject: "livesafe.ai",
      audience: "https://livesafe.ai/api/trust/status",
      credential_id: CREDENTIAL_ID_BYTES,
      evidence_hash: EVIDENCE_HASH_BYTES,
      idempotency_key: expect.stringMatching(
        /^livesafe-public-adapter-output:sha256:[a-f0-9]{64}$/,
      ),
      expires_at: {
        physical_ms: Date.parse("2026-07-05T12:05:00.000Z"),
        logical: 0,
      },
    });
    expect(requestBody).not.toHaveProperty("issued_at");
    expect(requestBody).not.toHaveProperty("generated_at");
    expect(query).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain("secret-public-adapter-bearer");
  });

  it("uses EXOCHAIN_NODE_AVC_URL when the AVC route has a dedicated base URL", async () => {
    configurePublicAdapterAuthorizationEnv({
      EXOCHAIN_NODE_AVC_URL: "https://exo-avc.example/custom-avc-root",
    });
    const client = new ExochainClient("http://example.invalid/graphql");
    const fetch = vi.fn(async () => ({
      ok: true,
      json: async () => PUBLIC_ADAPTER_AUTHORIZATION_RUST_CORE_ENVELOPE,
    }));
    vi.stubGlobal("fetch", fetch);

    const result = await client.getPublicAdapterOutputAuthorization({
      subject: "livesafe.ai",
      audience: "https://livesafe.ai/api/trust/status",
      currentAt: "2026-07-05T12:00:00.000Z",
    });

    expect(result.state).toBe("permit");
    const [requestUrl] = fetch.mock.calls[0] as unknown as [string, unknown];
    expect(requestUrl).toBe(
      "https://exo-avc.example/custom-avc-root/api/v1/avc/livesafe/public-adapter-output-authorization",
    );
  });

  it("adapts a core public adapter-output authorization envelope into the LiveSafe DTO shape", async () => {
    configurePublicAdapterAuthorizationEnv();
    const client = new ExochainClient("http://example.invalid/graphql");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () => PUBLIC_ADAPTER_AUTHORIZATION_RUST_CORE_ENVELOPE,
      })),
    );

    const result = await client.getPublicAdapterOutputAuthorization({
      subject: "livesafe.ai",
      audience: "https://livesafe.ai/api/trust/status",
      currentAt: "2026-07-05T12:00:00.000Z",
    });

    expect(result).toEqual({
      state: "permit",
      value: PUBLIC_ADAPTER_AUTHORIZATION_DTO_FROM_RUST,
    });
  });

  it("adapts Rust core byte-array credential and receipt ids in public adapter-output envelopes", async () => {
    configurePublicAdapterAuthorizationEnv();
    const client = new ExochainClient("http://example.invalid/graphql");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () =>
          rustCoreEnvelope({
            proof: {
              credential_id: CREDENTIAL_ID_BYTES,
              receipt_id: RECEIPT_ID_BYTES,
            },
          }),
      })),
    );

    const result = await client.getPublicAdapterOutputAuthorization({
      subject: "livesafe.ai",
      audience: "https://livesafe.ai/api/trust/status",
      currentAt: "2026-07-05T12:00:00.000Z",
    });

    expect(result).toEqual({
      state: "permit",
      value: {
        ...PUBLIC_ADAPTER_AUTHORIZATION_DTO_FROM_RUST,
        receipt_id: `sha256:${RECEIPT_ID_HEX}`,
      },
    });
  });

  it("redacts public adapter-output authorization REST errors and fails closed", async () => {
    configurePublicAdapterAuthorizationEnv();
    const client = new ExochainClient("http://example.invalid/graphql");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        status: 403,
        text: async () => "Bearer secret-production-token private_key=raw-key",
      })),
    );
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    const result = await client.getPublicAdapterOutputAuthorization({
      subject: "livesafe.ai",
      audience: "https://livesafe.ai/api/trust/status",
      currentAt: "2026-07-05T12:00:00.000Z",
    });

    expect(result).toEqual({ state: "rejected", value: null });
    expect(JSON.stringify(warn.mock.calls)).not.toContain(
      "secret-production-token",
    );
    expect(JSON.stringify(warn.mock.calls)).not.toContain("raw-key");
  });

  it.each([
    {
      label: "legacy fake envelope_schema status fixture",
      envelope: PUBLIC_ADAPTER_AUTHORIZATION_LEGACY_FAKE_ENVELOPE,
      expectedState: "rejected",
    },
    {
      label: "string-only Rust-like hash and signature fixture",
      envelope: PUBLIC_ADAPTER_AUTHORIZATION_STRING_ONLY_RUST_LIKE_ENVELOPE,
      expectedState: "rejected",
    },
    {
      label: "top-level schema_version 2",
      envelope: rustCoreEnvelope({ envelope: { schema_version: 2 } }),
      expectedState: "rejected",
    },
    {
      label: "nested proof schema_version 2",
      envelope: rustCoreEnvelope({ proof: { schema_version: 2 } }),
      expectedState: "rejected",
    },
    {
      label: "missing top-level domain",
      envelope: rustCoreEnvelope({ envelope: { domain: "" } }),
      expectedState: "rejected",
    },
    {
      label: "wrong top-level domain",
      envelope: rustCoreEnvelope({
        envelope: { domain: "livesafe.public_adapter_output_authorization.v0" },
      }),
      expectedState: "rejected",
    },
    {
      label: "wrong nested proof domain",
      envelope: rustCoreEnvelope({
        proof: { domain: "livesafe.public_adapter_output_authorization.v0" },
      }),
      expectedState: "rejected",
    },
    {
      label: "wrong nested proof subject",
      envelope: rustCoreEnvelope({ proof: { subject: "www.livesafe.ai" } }),
      expectedState: "rejected",
    },
    {
      label: "wrong nested proof audience",
      envelope: rustCoreEnvelope({
        proof: { audience: "https://livesafe.ai/api/health" },
      }),
      expectedState: "rejected",
    },
    {
      label: "evidence hash mismatch",
      envelope: rustCoreEnvelope({
        proof: {
          evidence_hash: repeatedByte(0xff, 32),
        },
      }),
      expectedState: "rejected",
    },
    {
      label: "evidence_hash not array",
      envelope: rustCoreEnvelope({
        proof: { evidence_hash: `sha256:${EVIDENCE_HASH_HEX}` },
      }),
      expectedState: "rejected",
    },
    {
      label: "evidence_hash wrong length",
      envelope: rustCoreEnvelope({
        proof: { evidence_hash: repeatedByte(0xbb, 31) },
      }),
      expectedState: "rejected",
    },
    {
      label: "evidence_hash non-integer byte",
      envelope: rustCoreEnvelope({
        proof: { evidence_hash: [...repeatedByte(0xbb, 31), 1.5] },
      }),
      expectedState: "rejected",
    },
    {
      label: "evidence_hash out-of-range byte",
      envelope: rustCoreEnvelope({
        proof: { evidence_hash: [...repeatedByte(0xbb, 31), 256] },
      }),
      expectedState: "rejected",
    },
    {
      label: "evidence_hash negative byte",
      envelope: rustCoreEnvelope({
        proof: { evidence_hash: [...repeatedByte(0xbb, 31), -1] },
      }),
      expectedState: "rejected",
    },
    {
      label: "proof_hash wrong length",
      envelope: rustCoreEnvelope({
        proof: { proof_hash: repeatedByte(0xcc, 31) },
      }),
      expectedState: "rejected",
    },
    {
      label: "expired nested proof",
      envelope: rustCoreEnvelope({
        proof: { expires_at: "2026-07-05T11:59:59.999Z" },
      }),
      expectedState: "stale",
    },
    {
      label: "not yet valid nested proof",
      envelope: rustCoreEnvelope({
        proof: { issued_at: "2026-07-05T12:00:01.000Z" },
      }),
      expectedState: "stale",
    },
    {
      label: "stale nested proof issued_at",
      envelope: rustCoreEnvelope({
        proof: { issued_at: "2026-07-05T11:54:59.999Z" },
      }),
      expectedState: "stale",
    },
    {
      label: "revoked revocation_status",
      envelope: rustCoreEnvelope({ proof: { revocation_status: "revoked" } }),
      expectedState: "revoked",
    },
    {
      label: "non-canonical valid revocation_status",
      envelope: rustCoreEnvelope({ proof: { revocation_status: "valid" } }),
      expectedState: "rejected",
    },
    {
      label: "non-canonical active revocation_status",
      envelope: rustCoreEnvelope({ proof: { revocation_status: "active" } }),
      expectedState: "rejected",
    },
    {
      label: "non-canonical non-revoked revocation_status",
      envelope: rustCoreEnvelope({ proof: { revocation_status: "non-revoked" } }),
      expectedState: "rejected",
    },
    {
      label: "missing receipt_id",
      envelope: rustCoreEnvelope({ proof: { receipt_id: "" } }),
      expectedState: "rejected",
    },
    {
      label: "missing proof_hash",
      envelope: rustCoreEnvelope({ proof: { proof_hash: "" } }),
      expectedState: "rejected",
    },
    {
      label: "missing signature",
      envelope: rustCoreEnvelope({ proof: { signature: "" } }),
      expectedState: "rejected",
    },
    {
      label: "signature Empty variant",
      envelope: rustCoreEnvelope({
        proof: { signature: { Empty: null } },
      }),
      expectedState: "rejected",
    },
    {
      label: "signature PostQuantum variant",
      envelope: rustCoreEnvelope({
        proof: { signature: { PostQuantum: repeatedByte(0xaa, 64) } },
      }),
      expectedState: "rejected",
    },
    {
      label: "signature Hybrid variant",
      envelope: rustCoreEnvelope({
        proof: {
          signature: {
            Hybrid: {
              ed25519: repeatedByte(0xaa, 64),
              post_quantum: repeatedByte(0xbb, 64),
            },
          },
        },
      }),
      expectedState: "rejected",
    },
    {
      label: "signature wrong Ed25519 length",
      envelope: rustCoreEnvelope({
        proof: { signature: { Ed25519: repeatedByte(0xaa, 63) } },
      }),
      expectedState: "rejected",
    },
    {
      label: "signature non-integer Ed25519 byte",
      envelope: rustCoreEnvelope({
        proof: { signature: { Ed25519: [...repeatedByte(0xaa, 63), 1.5] } },
      }),
      expectedState: "rejected",
    },
    {
      label: "signature out-of-range Ed25519 byte",
      envelope: rustCoreEnvelope({
        proof: { signature: { Ed25519: [...repeatedByte(0xaa, 63), 256] } },
      }),
      expectedState: "rejected",
    },
    {
      label: "unknown issued_at shape",
      envelope: rustCoreEnvelope({
        proof: { issued_at: { physical_time: "2026-07-05T11:59:00.000Z" } },
      }),
      expectedState: "rejected",
    },
    {
      label: "unknown expires_at shape",
      envelope: rustCoreEnvelope({
        proof: { expires_at: { physical_time: "2026-07-05T12:05:00.000Z" } },
      }),
      expectedState: "rejected",
    },
    {
      label: "raw sensitive field",
      envelope: rustCoreEnvelope({
        envelope: { bearer_token: "Bearer secret-production-token" },
      }),
      expectedState: "rejected",
    },
  ])("fails closed when public adapter-output authorization REST envelope is $label", async ({
    envelope,
    expectedState,
  }) => {
    configurePublicAdapterAuthorizationEnv();
    const malformedClient = new ExochainClient("http://example.invalid/graphql");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () => envelope,
      })),
    );

    await expect(
      malformedClient.getPublicAdapterOutputAuthorization({
        subject: "livesafe.ai",
        audience: "https://livesafe.ai/api/trust/status",
        currentAt: "2026-07-05T12:00:00.000Z",
      }),
    ).resolves.toEqual({ state: expectedState, value: null });
  });

  it("fails closed when public adapter-output authorization transport times out or is unavailable", async () => {
    configurePublicAdapterAuthorizationEnv();
    const unavailableClient = new ExochainClient("http://example.invalid/graphql");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValueOnce(
        Object.assign(new Error("Bearer secret-production-token ETIMEDOUT"), {
          name: "AbortError",
        }),
      ),
    );

    await expect(
      unavailableClient.getPublicAdapterOutputAuthorization({
        subject: "livesafe.ai",
        audience: "https://livesafe.ai/api/trust/status",
        currentAt: "2026-07-05T12:00:00.000Z",
      }),
    ).resolves.toEqual({ state: "timeout", value: null });

    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValueOnce(
        Object.assign(new Error("Bearer secret-production-token ETIMEDOUT"), {
          code: "ECONNREFUSED",
        }),
      ),
    );

    await expect(
      unavailableClient.getPublicAdapterOutputAuthorization({
        subject: "livesafe.ai",
        audience: "https://livesafe.ai/api/trust/status",
        currentAt: "2026-07-05T12:00:00.000Z",
      }),
    ).resolves.toEqual({ state: "unavailable", value: null });
  });
});
