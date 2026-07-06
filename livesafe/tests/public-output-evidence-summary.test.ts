import { spawnSync } from "node:child_process";

import { afterEach, describe, expect, it, vi } from "vitest";

const SUBJECT = "livesafe.ai";
const AUDIENCE = "https://livesafe.ai/api/trust/status";
const AS_OF = "2026-07-05T12:00:00.000Z";
const OBSERVED_AT = "2026-07-05T11:59:00.000Z";
const MAX_EVIDENCE_AGE_MS = 10 * 60 * 1000;

const GENERATED_FROM = [
  "config/exochain-production-trust.json",
  "server/utils/exochain-production-trust-evidence.js",
  "server/utils/livesafe-exochain-adapter.js",
  "server/utils/public-adapter-output-authorization.js",
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

const PRODUCTION_TRUST_EVIDENCE = {
  evidence_state: "verified",
  production_base_url: "https://exochain-production.up.railway.app",
  production_health_verified: true,
  production_ready_verified: true,
  root_trust_bundle_verified: true,
  root_trust_bundle_id:
    "7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58",
  root_trust_ceremony_id: "avc-exo-ceremony-2026",
  root_trust_issuer_did:
    "did:exo:8EVGmqLo15JEnrbcrLo9r84qX1mtrVeBdPjHLUtb1sXX",
  verifier_commit: "379a45e1d9ab092ecd446d095a7b524570530efd",
  verified_at: OBSERVED_AT,
  reasons: [],
  non_blocking_observations: [
    "production_sentinel_quorum_health_below_bft_minimum",
  ],
};

const RUNTIME_STATUS = {
  adapter_state: "verified",
  surface_classification: "core-runtime-adapter",
  public_claims_allowed: false,
  can_read_exochain_core_state: true,
  can_write_exochain_core_state: true,
  wrapped_operations: WRAPPED_OPERATIONS,
  disablement_path:
    "Disable EXOCHAIN adapter environment variables and remove the trust-status route from the load balancer.",
  source_basis: ["server/utils/livesafe-exochain-adapter.js"],
};

function loadContract() {
  return require("../server/utils/exochain-production-trust-evidence.js") as {
    buildPublicOutputEvidenceHashRecord: (
      input: Record<string, unknown>,
    ) => Record<string, unknown>;
    buildPublicOutputEvidenceSummary: (
      input: Record<string, unknown>,
    ) => Record<string, unknown>;
    hashPublicOutputEvidenceSummary: (
      summary: Record<string, unknown>,
    ) => string;
  };
}

function validInput(overrides: Record<string, unknown> = {}) {
  return {
    subject: SUBJECT,
    audience: AUDIENCE,
    asOf: AS_OF,
    maxEvidenceAgeMs: MAX_EVIDENCE_AGE_MS,
    exochainConnected: true,
    productionTrustEvidence: {
      ...PRODUCTION_TRUST_EVIDENCE,
      reasons: [...PRODUCTION_TRUST_EVIDENCE.reasons],
      non_blocking_observations: [
        ...PRODUCTION_TRUST_EVIDENCE.non_blocking_observations,
      ],
    },
    runtimeStatus: {
      ...RUNTIME_STATUS,
      wrapped_operations: [...RUNTIME_STATUS.wrapped_operations],
      source_basis: [...RUNTIME_STATUS.source_basis],
    },
    generatedFrom: [...GENERATED_FROM],
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("LiveSafe public-output evidence summary hash contract", () => {
  it("canonicalizes semantically identical evidence with reordered object keys to the same hash", () => {
    const { buildPublicOutputEvidenceHashRecord } = loadContract();
    const reorderedInput = {
      generatedFrom: [...GENERATED_FROM],
      runtimeStatus: {
        source_basis: ["server/utils/livesafe-exochain-adapter.js"],
        disablement_path: RUNTIME_STATUS.disablement_path,
        wrapped_operations: [...WRAPPED_OPERATIONS],
        can_write_exochain_core_state: true,
        can_read_exochain_core_state: true,
        public_claims_allowed: false,
        surface_classification: "core-runtime-adapter",
        adapter_state: "verified",
      },
      productionTrustEvidence: {
        non_blocking_observations: [
          "production_sentinel_quorum_health_below_bft_minimum",
        ],
        reasons: [],
        verified_at: OBSERVED_AT,
        verifier_commit: "379a45e1d9ab092ecd446d095a7b524570530efd",
        root_trust_issuer_did:
          "did:exo:8EVGmqLo15JEnrbcrLo9r84qX1mtrVeBdPjHLUtb1sXX",
        root_trust_ceremony_id: "avc-exo-ceremony-2026",
        root_trust_bundle_id:
          "7d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58",
        root_trust_bundle_verified: true,
        production_ready_verified: true,
        production_health_verified: true,
        production_base_url: "https://exochain-production.up.railway.app",
        evidence_state: "verified",
      },
      maxEvidenceAgeMs: MAX_EVIDENCE_AGE_MS,
      asOf: AS_OF,
      audience: AUDIENCE,
      subject: SUBJECT,
      exochainConnected: true,
    };

    const first = buildPublicOutputEvidenceHashRecord(validInput());
    const second = buildPublicOutputEvidenceHashRecord(reorderedInput);

    expect(first.evidence_hash).toBe(second.evidence_hash);
    expect(first.summary).toEqual(second.summary);
  });

  it("changes the hash when any required public evidence field changes", () => {
    const { buildPublicOutputEvidenceHashRecord } = loadContract();
    const first = buildPublicOutputEvidenceHashRecord(validInput());
    const changed = buildPublicOutputEvidenceHashRecord(
      validInput({
        productionTrustEvidence: {
          ...PRODUCTION_TRUST_EVIDENCE,
          root_trust_bundle_id:
            "8d9954a797ef244c15ad1b733cf77598125ccef0f812a404137e827c192d6a58",
        },
      }),
    );

    expect(first.evidence_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(changed.evidence_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(changed.evidence_hash).not.toBe(first.evidence_hash);
  });

  it("rejects missing or false production, EXOCHAIN, runtime-adapter, and pre-authorization public-claim evidence", () => {
    const { buildPublicOutputEvidenceSummary } = loadContract();
    const cases = [
      {
        name: "production evidence blocked",
        input: validInput({
          productionTrustEvidence: {
            ...PRODUCTION_TRUST_EVIDENCE,
            evidence_state: "blocked",
          },
        }),
        reason: "EXOCHAIN production evidence must be verified.",
      },
      {
        name: "production health false",
        input: validInput({
          productionTrustEvidence: {
            ...PRODUCTION_TRUST_EVIDENCE,
            production_health_verified: false,
          },
        }),
        reason: "EXOCHAIN production health evidence must be verified.",
      },
      {
        name: "EXOCHAIN connectivity false",
        input: validInput({ exochainConnected: false }),
        reason: "EXOCHAIN connectivity must be verified.",
      },
      {
        name: "runtime adapter not verified",
        input: validInput({
          runtimeStatus: {
            ...RUNTIME_STATUS,
            adapter_state: "unverified",
          },
        }),
        reason: "LiveSafe runtime adapter evidence must be verified.",
      },
      {
        name: "public claims already allowed",
        input: validInput({
          runtimeStatus: {
            ...RUNTIME_STATUS,
            public_claims_allowed: true,
          },
        }),
        reason:
          "LiveSafe public claims must not already be allowed before AVC authorization.",
      },
    ];

    for (const testCase of cases) {
      expect(
        () => buildPublicOutputEvidenceSummary(testCase.input),
        testCase.name,
      ).toThrow(testCase.reason);
    }
  });

  it("rejects stale or malformed evidence timestamps using only explicit input time", () => {
    const { buildPublicOutputEvidenceSummary } = loadContract();

    expect(() =>
      buildPublicOutputEvidenceSummary(
        validInput({ asOf: "2026-07-05T12:10:01.000Z" }),
      ),
    ).toThrow("Public output evidence timestamp is stale.");

    expect(() =>
      buildPublicOutputEvidenceSummary(
        validInput({
          productionTrustEvidence: {
            ...PRODUCTION_TRUST_EVIDENCE,
            verified_at: "not-a-timestamp",
          },
        }),
      ),
    ).toThrow("Public output evidence timestamp is malformed.");

    const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => {
      throw new Error("system time must not be used for evidence freshness");
    });
    const summary = buildPublicOutputEvidenceSummary(validInput());

    expect(summary.as_of).toBe(AS_OF);
    expect(nowSpy).not.toHaveBeenCalled();
  });

  it("rejects hashes for summaries containing secrets, raw authority, database URLs, or sensitive LiveSafe payloads", () => {
    const {
      buildPublicOutputEvidenceSummary,
      hashPublicOutputEvidenceSummary,
    } = loadContract();
    const summary = buildPublicOutputEvidenceSummary(validInput());
    const sensitiveMutations = [
      { bearer_token: "bearer-secret-value" },
      { admin_token: "admin-secret-value" },
      { private_key: "-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----" },
      { raw_authority_chain: ["did:exo:livesafe:raw-authority"] },
      { database_url: "postgres://user:password@db.example/livesafe" },
      { sensitive_livesafe_payload: { medical_record: "raw PHI payload" } },
      { generated_from: ["Authorization: Bearer hidden-token"] },
    ];

    for (const mutation of sensitiveMutations) {
      expect(
        () => hashPublicOutputEvidenceSummary({ ...summary, ...mutation }),
        JSON.stringify(mutation),
      ).toThrow(
        "Public output evidence summary must not contain secret or sensitive material.",
      );
    }
  });

  it("operator command emits only non-secret machine-readable evidence hash metadata", () => {
    const command = spawnSync(
      process.execPath,
      [
        "scripts/exochain-public-output-evidence-hash.mjs",
        "--as-of",
        "2026-06-03T21:26:00.000Z",
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_BEARER:
            "super-secret-public-adapter-bearer",
          DATABASE_URL: "postgres://secret-user:secret-pass@db.example/livesafe",
          LIVESAFE_ADMIN_TOKEN: "admin-token-that-must-not-print",
        },
      },
    );

    expect(command.status, command.stderr).toBe(0);
    expect(command.stderr).toBe("");

    const output = command.stdout.trim();
    expect(output).not.toContain("super-secret-public-adapter-bearer");
    expect(output).not.toContain("postgres://secret-user");
    expect(output).not.toContain("admin-token-that-must-not-print");

    const record = JSON.parse(output) as {
      evidence_hash: string;
      algorithm: string;
      subject: string;
      audience: string;
      generated_from: string[];
      state: string;
      reasons: string[];
      public_claims_allowed: boolean;
      summary: Record<string, unknown>;
    };

    expect(record).toMatchObject({
      algorithm: "sha256.canonical_json.sorted_keys.v1",
      subject: SUBJECT,
      audience: AUDIENCE,
      generated_from: GENERATED_FROM,
      state: "ready_for_avc_ceremony_binding",
      reasons: [],
      public_claims_allowed: false,
    });
    expect(record.evidence_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(record.summary).toMatchObject({
      subject: SUBJECT,
      audience: AUDIENCE,
      public_claims_allowed: false,
    });
  });
});
