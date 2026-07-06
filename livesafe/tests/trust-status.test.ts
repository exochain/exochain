import { describe, expect, it, vi } from "vitest";

import {
  createTrustStatusPayload,
  sendLiveTrustStatusResponse,
  sendTrustStatusResponse
} from "../server/utils/trust-status.js";
import type { TrustStatusPayloadOptions } from "../server/utils/trust-status.js";

type RuntimeStatus = NonNullable<TrustStatusPayloadOptions["runtimeStatus"]>;
type RuntimeOperations = NonNullable<RuntimeStatus["wrapped_operations"]>;

const VERIFIED_PRODUCTION_TRUST_EVIDENCE = {
  evidence_state: "verified" as const,
  production_health_verified: true,
  production_ready_verified: true,
  root_trust_bundle_verified: true,
  root_trust_bundle_id:
    "7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58",
  root_trust_ceremony_id: "avc-exo-ceremony-2026",
  root_trust_issuer_did:
    "did:exo:8EVGmqLo15JEnrbcrLo9r84qX1mtrVeBdPjHLUtb1sXX",
  verifier_commit:
    "379a45e1d9ab092ecd446d095a7b524570530efd",
  verified_at: "2026-06-03T21:26:00.000Z",
};

const VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION = {
  allowed: true,
  responseState: "permit",
  transportCalled: true,
  value: {
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
  },
};

const VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_METADATA = {
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
  proof_type: "ed25519-public-adapter-output-authorization",
  response_state: "permit",
  transport_called: true,
};

describe("trust status API contract", () => {
  it("builds an explicitly inactive machine-readable trust payload", () => {
    const payload = createTrustStatusPayload({
      exochainConnected: false,
      version: "1.0.0",
      uptimeSeconds: 42.5,
      generatedAt: "2026-05-26T09:40:00.000Z",
      productionTrustEvidence: {
        evidence_state: "blocked",
        production_health_verified: false,
        production_ready_verified: false,
        root_trust_bundle_verified: false,
        reasons: ["EXOCHAIN production evidence has not been supplied."],
      },
    });

    expect(payload).toMatchObject({
      state: "not-verified",
      badge_text: "AVC",
      display_text: "THIS IS NOT YET VERIFIED",
      machine_state: "not_verified",
      api_surface: "api-response",
      public_claims_allowed: false,
      verified_runtime_adapter: true,
      runtime_adapter_state: "verified",
      adapter_surface_classification: "adjacent-surface",
      runtime_adapter_operations: [
        "getIdentity",
        "registerIdentity",
        "anchorAuditReceipt",
        "anchorScan",
        "anchorConsent",
        "getPaceStatus",
        "getPublicAdapterOutputAuthorization",
      ],
      frost_genesis_complete: false,
      internal_proof_complete: false,
      exochain_connected: false,
      version: "1.0.0",
      generated_at: "2026-05-26T09:40:00.000Z"
    });

    expect(payload.color).toBe("red");
    expect(payload.icon).toBe("lock-open");
    expect(payload.css_class).toContain("trust-signal--not-verified");
    expect(payload.glow_class).toContain("trust-glow--red");
    expect(payload.uptime_seconds).toBeCloseTo(42.5);
    expect(payload.public_claims_reason).toContain(
      "EXOCHAIN production evidence verifies",
    );
    expect(payload.adapter_disablement_path).toContain(
      "Keep `config/exochain-primitives.json` at `runtimeAdapterStatus: not-wired`",
    );
    expect(payload.source_basis).toEqual([
      "docs/context/LIVESAFE_PRODUCTION_TRUST_ACTIVATION_GATES.md",
      "docs/context/LIVESAFE_TRUST_SIGNAL_VISUAL_LANGUAGE.md",
      "src/trust-signal.ts",
      "src/genesis-trust.ts",
      "server/utils/livesafe-exochain-adapter.js",
      "server/utils/public-adapter-output-authorization.js",
      "config/exochain-production-trust.json",
      "server/utils/exochain-production-trust-evidence.js",
    ]);
  });

  it("stays fail-closed even when EXOCHAIN connectivity is reported", () => {
    const payload = createTrustStatusPayload({
      exochainConnected: true,
      version: "1.0.0",
      uptimeSeconds: 10,
      generatedAt: "2026-05-26T09:41:00.000Z"
    });

    expect(payload.exochain_connected).toBe(true);
    expect(payload.state).toBe("not-verified");
    expect(payload.public_claims_allowed).toBe(false);
    expect(payload.verified_runtime_adapter).toBe(true);
  });

  it("derives verified runtime adapter state from the redacted adapter status", () => {
    const payload = createTrustStatusPayload({
      exochainConnected: false,
      version: "1.0.0",
      uptimeSeconds: 12,
      generatedAt: "2026-06-03T04:30:00.000Z",
      runtimeStatus: {
        adapter_state: "verified",
        surface_classification: "core-runtime-adapter",
        public_claims_allowed: false,
        can_read_exochain_core_state: true,
        can_write_exochain_core_state: true,
        disablement_path: "Disable the verified adapter route before shipping.",
        source_basis: ["server/utils/livesafe-exochain-adapter.js"],
      },
    });

    expect(payload.runtime_adapter_state).toBe("verified");
    expect(payload.verified_runtime_adapter).toBe(true);
    expect(payload.runtime_adapter_operations).toEqual([
      "getIdentity",
      "registerIdentity",
      "anchorAuditReceipt",
      "anchorScan",
      "anchorConsent",
      "getPaceStatus",
      "getPublicAdapterOutputAuthorization",
    ]);
    expect(payload.public_claims_allowed).toBe(false);
    expect(payload.public_claims_reason).toContain(
      "proof-bearing public adapter-output authorization",
    );
  });

  it("reports verified EXOCHAIN production evidence without lifting LiveSafe public claims", () => {
    const payload = createTrustStatusPayload({
      exochainConnected: true,
      version: "1.0.0",
      uptimeSeconds: 15,
      generatedAt: "2026-06-03T21:25:00.000Z",
      productionTrustEvidence: {
        evidence_state: "verified",
        production_health_verified: true,
        production_ready_verified: true,
        root_trust_bundle_verified: true,
        root_trust_bundle_id:
          "7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58",
        root_trust_ceremony_id: "avc-exo-ceremony-2026",
        root_trust_issuer_did:
          "did:exo:8EVGmqLo15JEnrbcrLo9r84qX1mtrVeBdPjHLUtb1sXX",
        verifier_commit:
          "379a45e1d9ab092ecd446d095a7b524570530efd",
        verified_at: "2026-06-03T21:25:00.000Z",
        non_blocking_observations: [
          "production_sentinel_quorum_health_below_bft_minimum",
        ],
      },
    });

    expect(payload.exochain_production_evidence_state).toBe("verified");
    expect(payload.exochain_production_health_verified).toBe(true);
    expect(payload.exochain_production_ready_verified).toBe(true);
    expect(payload.exochain_root_trust_bundle_verified).toBe(true);
    expect(payload.exochain_root_trust_bundle_id).toBe(
      "7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58",
    );
    expect(payload.exochain_root_trust_issuer_did).toBe(
      "did:exo:8EVGmqLo15JEnrbcrLo9r84qX1mtrVeBdPjHLUtb1sXX",
    );
    expect(payload.frost_genesis_complete).toBe(true);
    expect(payload.internal_proof_complete).toBe(true);
    expect(payload.public_claims_allowed).toBe(false);
    expect(payload.public_claims_reason).toContain(
      "proof-bearing public adapter-output authorization",
    );
    expect(payload.production_trust_observations).toEqual([
      "production_sentinel_quorum_health_below_bft_minimum",
    ]);
  });

  it("denies public trust status when local runtime public_claims_allowed is true without proof-bearing adapter output", () => {
    const payload = createTrustStatusPayload({
      exochainConnected: true,
      version: "1.0.0",
      uptimeSeconds: 15,
      generatedAt: "2026-07-05T12:00:00.000Z",
      runtimeStatus: {
        adapter_state: "verified",
        surface_classification: "core-runtime-adapter",
        public_claims_allowed: true,
        can_read_exochain_core_state: true,
        can_write_exochain_core_state: true,
        disablement_path:
          "Disable EXOCHAIN adapter environment variables and remove the trust-status route from the load balancer.",
        source_basis: ["server/utils/livesafe-exochain-adapter.js"],
      },
      productionTrustEvidence: VERIFIED_PRODUCTION_TRUST_EVIDENCE,
    });

    expect(payload.state).toBe("not-verified");
    expect(payload.machine_state).toBe("not_verified");
    expect(payload.public_claims_allowed).toBe(false);
    expect(payload.public_claims_reason).toContain(
      "proof-bearing public adapter-output authorization",
    );
    expect(payload).not.toHaveProperty("public_adapter_output_authorization");
  });

  it("denies verified public trust status unless the public adapter-output authorization decision and DTO are complete", () => {
    const invalidAuthorizations = [
      {
        name: "denied evaluator decision",
        adapterOutputAuthorization: {
          ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION,
          allowed: false,
        },
      },
      {
        name: "non-permit EXOCHAIN response",
        adapterOutputAuthorization: {
          ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION,
          responseState: "stale",
        },
      },
      {
        name: "uncalled transport",
        adapterOutputAuthorization: {
          ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION,
          transportCalled: false,
        },
      },
      {
        name: "wrong subject",
        adapterOutputAuthorization: {
          ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION,
          value: {
            ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION.value,
            subject: "www.livesafe.ai",
          },
        },
      },
      {
        name: "wrong audience",
        adapterOutputAuthorization: {
          ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION,
          value: {
            ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION.value,
            audience: "https://livesafe.ai/api/health",
          },
        },
      },
      {
        name: "forbidden claim",
        adapterOutputAuthorization: {
          ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION,
          value: {
            ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION.value,
            claims: [
              ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION.value.claims,
              "medical_status_verified",
            ],
          },
        },
      },
      {
        name: "missing evidence hash",
        adapterOutputAuthorization: {
          ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION,
          value: {
            ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION.value,
            evidence_hash: "",
          },
        },
      },
    ];

    for (const { adapterOutputAuthorization, name } of invalidAuthorizations) {
      const payload = createTrustStatusPayload({
        exochainConnected: true,
        version: "1.0.0",
        uptimeSeconds: 16,
        generatedAt: "2026-07-05T12:00:00.000Z",
        runtimeStatus: {
          adapter_state: "verified" as const,
          surface_classification: "core-runtime-adapter",
          public_claims_allowed: true,
          can_read_exochain_core_state: true,
          can_write_exochain_core_state: true,
          disablement_path:
            "Disable EXOCHAIN adapter environment variables and remove the trust-status route from the load balancer.",
          source_basis: ["server/utils/livesafe-exochain-adapter.js"],
        },
        adapterOutputAuthorization,
        productionTrustEvidence: VERIFIED_PRODUCTION_TRUST_EVIDENCE,
      });

      expect(payload.public_claims_allowed, name).toBe(false);
      expect(payload.state, name).toBe("not-verified");
      expect(payload.public_claims_reason, name).toContain(
        "proof-bearing public adapter-output authorization",
      );
    }
  });

  it("allows verified public trust status only with permit-backed proof-bearing public adapter-output authorization", () => {
    const payload = createTrustStatusPayload({
      exochainConnected: true,
      version: "1.0.0",
      uptimeSeconds: 16,
      generatedAt: "2026-07-05T12:00:00.000Z",
      runtimeStatus: {
        adapter_state: "verified",
        surface_classification: "core-runtime-adapter",
        public_claims_allowed: true,
        can_read_exochain_core_state: true,
        can_write_exochain_core_state: true,
        disablement_path:
          "Disable EXOCHAIN adapter environment variables and remove the trust-status route from the load balancer.",
        source_basis: ["server/utils/livesafe-exochain-adapter.js"],
      },
      adapterOutputAuthorization: VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION,
      productionTrustEvidence: VERIFIED_PRODUCTION_TRUST_EVIDENCE,
    });

    expect(payload.state).toBe("externally-verified");
    expect(payload.machine_state).toBe("public_trust_claims_allowed");
    expect(payload.display_text).toBe("VERIFIED");
    expect(payload.public_claims_allowed).toBe(true);
    expect(payload.public_claims_reason).toContain(
      "EXOCHAIN production evidence, LiveSafe runtime adapter gates, and proof-bearing public adapter-output authorization are verified",
    );
    expect(payload.public_adapter_output_authorization).toEqual({
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
      proof_type: "ed25519-public-adapter-output-authorization",
      response_state: "permit",
      transport_called: true,
    });
    expect(JSON.stringify(payload.public_adapter_output_authorization)).not.toContain(
      "signature",
    );
  });

  it("allows live trust status when the adapter returns an already evaluated permit decision", () => {
    const payload = createTrustStatusPayload({
      exochainConnected: true,
      version: "1.0.0",
      uptimeSeconds: 16,
      generatedAt: "2026-07-05T12:00:00.000Z",
      runtimeStatus: {
        adapter_state: "verified",
        surface_classification: "core-runtime-adapter",
        public_claims_allowed: true,
        can_read_exochain_core_state: true,
        can_write_exochain_core_state: true,
        disablement_path:
          "Disable EXOCHAIN adapter environment variables and remove the trust-status route from the load balancer.",
        source_basis: ["server/utils/livesafe-exochain-adapter.js"],
      },
      adapterOutputAuthorization: {
        allowed: true,
        responseState: "permit",
        transportCalled: true,
        value: VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_METADATA,
      },
      productionTrustEvidence: VERIFIED_PRODUCTION_TRUST_EVIDENCE,
    });

    expect(payload.state).toBe("externally-verified");
    expect(payload.machine_state).toBe("public_trust_claims_allowed");
    expect(payload.public_claims_allowed).toBe(true);
    expect(payload.public_adapter_output_authorization).toEqual(
      VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_METADATA,
    );
    expect(JSON.stringify(payload.public_adapter_output_authorization)).not.toContain(
      "signature",
    );
  });

  it("denies public trust status when EXOCHAIN connectivity is false even with proof authorization", () => {
    const payload = createTrustStatusPayload({
      exochainConnected: false,
      version: "1.0.0",
      uptimeSeconds: 16,
      generatedAt: "2026-07-05T12:00:00.000Z",
      runtimeStatus: {
        adapter_state: "verified",
        surface_classification: "core-runtime-adapter",
        public_claims_allowed: true,
        can_read_exochain_core_state: true,
        can_write_exochain_core_state: true,
        disablement_path:
          "Disable EXOCHAIN adapter environment variables and remove the trust-status route from the load balancer.",
        source_basis: ["server/utils/livesafe-exochain-adapter.js"],
      },
      adapterOutputAuthorization: VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION,
      productionTrustEvidence: VERIFIED_PRODUCTION_TRUST_EVIDENCE,
    });

    expect(payload.state).toBe("not-verified");
    expect(payload.public_claims_allowed).toBe(false);
    expect(payload.public_claims_reason).toContain("EXOCHAIN connectivity");
  });

  it.each([
    {
      label: "runtime public_claims_allowed false",
      runtimeStatus: {
        adapter_state: "verified" as const,
        surface_classification: "core-runtime-adapter" as const,
        public_claims_allowed: false,
        can_read_exochain_core_state: true,
        can_write_exochain_core_state: true,
        disablement_path:
          "Disable EXOCHAIN adapter environment variables and remove the trust-status route from the load balancer.",
        source_basis: ["server/utils/livesafe-exochain-adapter.js"],
      },
    },
    {
      label: "runtime public_claims_allowed absent",
      runtimeStatus: {
        adapter_state: "verified" as const,
        surface_classification: "core-runtime-adapter" as const,
        can_read_exochain_core_state: true,
        can_write_exochain_core_state: true,
        disablement_path:
          "Disable EXOCHAIN adapter environment variables and remove the trust-status route from the load balancer.",
        source_basis: ["server/utils/livesafe-exochain-adapter.js"],
      } as RuntimeStatus,
    },
  ])("allows verified public trust status with $label when proof authorization permits", ({
    runtimeStatus,
  }) => {
    const payload = createTrustStatusPayload({
      exochainConnected: true,
      version: "1.0.0",
      uptimeSeconds: 16,
      generatedAt: "2026-07-05T12:00:00.000Z",
      runtimeStatus,
      adapterOutputAuthorization: VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION,
      productionTrustEvidence: VERIFIED_PRODUCTION_TRUST_EVIDENCE,
    });

    expect(payload.state).toBe("externally-verified");
    expect(payload.machine_state).toBe("public_trust_claims_allowed");
    expect(payload.public_claims_allowed).toBe(true);
    expect(payload.public_claims_reason).toContain(
      "proof-bearing public adapter-output authorization are verified",
    );
  });

  it("returns the payload through a read-only handler", () => {
    const req = {};
    const json = vi.fn();
    const status = vi.fn(() => ({ json }));
    const res = { status };

    sendTrustStatusResponse(req, res, {
      exochainConnected: false,
      version: "1.0.0",
      uptimeSeconds: 9,
      generatedAt: "2026-05-26T09:42:00.000Z"
    });

    expect(status).toHaveBeenCalledWith(200);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({
        state: "not-verified",
        machine_state: "not_verified",
        public_claims_allowed: false
      })
    );
  });

  it("live trust status responder requests proof-bearing adapter output with the generated timestamp before sending", async () => {
    const currentAt = "2026-07-05T12:00:00.000Z";
    const getPublicAdapterOutputAuthorization = vi.fn(async () => ({
      ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION,
    }));
    const adapter = {
      getRuntimeStatus(): RuntimeStatus {
        return {
          adapter_state: "verified" as const,
          surface_classification: "core-runtime-adapter" as const,
          public_claims_allowed: true,
          can_read_exochain_core_state: true,
          can_write_exochain_core_state: true,
          wrapped_operations: [
            "getIdentity",
            "registerIdentity",
            "anchorAuditReceipt",
            "anchorScan",
            "anchorConsent",
            "getPaceStatus",
            "getPublicAdapterOutputAuthorization",
          ] as RuntimeOperations,
          disablement_path:
            "Disable EXOCHAIN adapter environment variables and remove the trust-status route from the load balancer.",
          source_basis: ["server/utils/livesafe-exochain-adapter.js"],
        };
      },
      getPublicAdapterOutputAuthorization,
    };
    const json = vi.fn();
    const response = {
      status: vi.fn(() => ({ json })),
    };

    await sendLiveTrustStatusResponse({}, response, {
      adapter,
      exochainConnected: true,
      version: "1.0.0",
      uptimeSeconds: 16,
      generatedAt: currentAt,
      productionTrustEvidence: VERIFIED_PRODUCTION_TRUST_EVIDENCE,
    });

    expect(getPublicAdapterOutputAuthorization).toHaveBeenCalledWith({
      currentAt,
      returnDecision: true,
    });
    expect(response.status).toHaveBeenCalledWith(200);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({
        generated_at: currentAt,
        public_claims_allowed: true,
        state: "externally-verified",
      }),
    );
  });

  it("live trust status responder stays fail-closed when adapter authorization denies, times out, or is unavailable", async () => {
    for (const responseState of ["deny", "timeout", "unavailable"] as const) {
      const currentAt = "2026-07-05T12:00:00.000Z";
      const adapter = {
        getRuntimeStatus(): RuntimeStatus {
          return {
            adapter_state: "verified" as const,
            surface_classification: "core-runtime-adapter" as const,
            public_claims_allowed: true,
            can_read_exochain_core_state: true,
            can_write_exochain_core_state: true,
            wrapped_operations: [
              "getIdentity",
              "registerIdentity",
              "anchorAuditReceipt",
              "anchorScan",
              "anchorConsent",
              "getPaceStatus",
              "getPublicAdapterOutputAuthorization",
            ] as RuntimeOperations,
            disablement_path:
              "Disable EXOCHAIN adapter environment variables and remove the trust-status route from the load balancer.",
            source_basis: ["server/utils/livesafe-exochain-adapter.js"],
          };
        },
        getPublicAdapterOutputAuthorization: vi.fn(async () => ({
          ...VALID_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION,
          allowed: false,
          responseState,
          value: null,
        })),
      };
      const json = vi.fn();
      const response = {
        status: vi.fn(() => ({ json })),
      };

      await sendLiveTrustStatusResponse({}, response, {
        adapter,
        exochainConnected: true,
        version: "1.0.0",
        uptimeSeconds: 16,
        generatedAt: currentAt,
        productionTrustEvidence: VERIFIED_PRODUCTION_TRUST_EVIDENCE,
      });

      expect(json, responseState).toHaveBeenCalledWith(
        expect.objectContaining({
          generated_at: currentAt,
          public_claims_allowed: false,
          state: "not-verified",
        }),
      );
      expect(JSON.stringify(json.mock.calls[0]?.[0]), responseState).not.toContain(
        "signature",
      );
    }
  });
});
