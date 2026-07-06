import { describe, expect, it } from "vitest";

const SUBJECT = "livesafe.ai";
const AUDIENCE = "https://livesafe.ai/api/trust/status";
const CURRENT_AT = "2026-07-05T12:00:00.000Z";
const ALLOWED_CLAIMS = [
  "livesafe_public_trust_status",
  "exochain_production_evidence_verified",
  "livesafe_runtime_adapter_verified",
] as const;

function loadEvaluator() {
  return require("../server/utils/public-adapter-output-authorization.js") as {
    evaluatePublicAdapterOutputAuthorization: (
      adapterOutputAuthorization: unknown,
      options: {
        currentAt: string;
        subject: string;
        audience: string;
      },
    ) => {
      allowed: boolean;
      reasons: string[];
      required_evidence: string[];
      responseState: string;
      transportCalled: boolean;
      metadata: Record<string, unknown> | null;
    };
  };
}

function validAuthorization(overrides: Record<string, unknown> = {}) {
  return {
    schema: "livesafe.public_adapter_output_authorization.v1",
    subject: SUBJECT,
    audience: AUDIENCE,
    claims: [...ALLOWED_CLAIMS],
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
    ...overrides,
  };
}

function validDecision(overrides: Record<string, unknown> = {}) {
  return {
    allowed: true,
    responseState: "permit",
    transportCalled: true,
    value: validAuthorization(),
    ...overrides,
  };
}

function evaluate(adapterOutputAuthorization: unknown) {
  const { evaluatePublicAdapterOutputAuthorization } = loadEvaluator();

  return evaluatePublicAdapterOutputAuthorization(adapterOutputAuthorization, {
    currentAt: CURRENT_AT,
    subject: SUBJECT,
    audience: AUDIENCE,
  });
}

describe("public adapter-output authorization evaluator", () => {
  it("allows a permit-backed proof-bearing public authorization and returns redacted metadata", () => {
    const decision = evaluate(validDecision());

    expect(decision).toEqual({
      allowed: true,
      reasons: [],
      required_evidence: [],
      responseState: "permit",
      transportCalled: true,
      metadata: {
        schema: "livesafe.public_adapter_output_authorization.v1",
        subject: SUBJECT,
        audience: AUDIENCE,
        claims: [...ALLOWED_CLAIMS],
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
      },
    });
    expect(JSON.stringify(decision)).not.toContain("signature");
  });

  it("denies missing authorization", () => {
    const decision = evaluate(undefined);

    expect(decision.allowed).toBe(false);
    expect(decision.responseState).toBe("not-called");
    expect(decision.reasons).toContain(
      "Public adapter-output authorization is missing.",
    );
  });

  it("denies wrong schema", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({ schema: "livesafe.public_output.v0" }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization schema is invalid.",
    );
  });

  it("denies wrong subject", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({ subject: "www.livesafe.ai" }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization subject must be livesafe.ai.",
    );
  });

  it("denies wrong audience", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({ audience: "https://livesafe.ai/api/health" }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization audience must be https://livesafe.ai/api/trust/status.",
    );
  });

  it("denies empty claims", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({ claims: [] }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization claims must be non-empty.",
    );
  });

  it("denies forbidden medical, legal, custody, consent, and emergency claims", () => {
    for (const forbiddenClaim of [
      "medical_status_verified",
      "legal_admissibility_verified",
      "custody_proof_verified",
      "consent_proof_verified",
      "emergency_access_verified",
    ]) {
      const decision = evaluate(
        validDecision({
          value: validAuthorization({ claims: [...ALLOWED_CLAIMS, forbiddenClaim] }),
        }),
      );

      expect(decision.allowed, forbiddenClaim).toBe(false);
      expect(decision.reasons, forbiddenClaim).toContain(
        "Public adapter-output authorization may not carry medical, legal, custody, consent, or emergency claims.",
      );
    }
  });

  it("denies duplicate claims", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({
          claims: [
            ...ALLOWED_CLAIMS,
            "livesafe_public_trust_status",
          ],
        }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization claims must not contain duplicates.",
    );
  });

  it("denies claims outside the allowed public claim set", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({
          claims: [...ALLOWED_CLAIMS, "subscriber_identity_verified"],
        }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization claims include unsupported public output.",
    );
  });

  it("denies malformed evidence_hash", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({ evidence_hash: "not-a-sha256-hash" }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization evidence_hash must be sha256-prefixed lowercase hex.",
    );
  });

  it("denies missing proof id or proof ref", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({ proof_id: "", proof_ref: "" }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization requires proof_id and proof_ref.",
    );
  });

  it("denies expired authorizations", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({ expires_at: "2026-07-05T11:59:59.000Z" }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization is expired.",
    );
  });

  it("denies not-yet-valid authorizations", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({ valid_from: "2026-07-05T12:00:01.000Z" }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization is not yet valid.",
    );
  });

  it("denies stale authorizations", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({ generated_at: "2026-07-05T11:54:59.999Z" }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization is stale.",
    );
  });

  it("allows EXOCHAIN HLC-backed proof timestamps without weakening wall-clock stale denial", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({
          timestamp_basis: "exochain_hlc",
          generated_at: "1970-01-01T00:16:40.000Z",
          valid_from: "1970-01-01T00:16:40.000Z",
          expires_at: "2026-07-05T12:05:00.000Z",
        }),
      }),
    );

    expect(decision.allowed).toBe(true);
    expect(decision.reasons).toEqual([]);
    expect(decision.metadata).not.toHaveProperty("timestamp_basis");
  });

  it("denies revoked authorizations", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({ revoked: true }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization is revoked.",
    );
  });

  it("denies contradicted authorizations", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({ contradicted: true }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.reasons).toContain(
      "Public adapter-output authorization is contradicted.",
    );
  });

  it("denies timeout and unavailable authorization transport states", () => {
    for (const responseState of ["timeout", "unavailable"]) {
      const decision = evaluate(
        validDecision({
          responseState,
        }),
      );

      expect(decision.allowed, responseState).toBe(false);
      expect(decision.responseState, responseState).toBe(responseState);
      expect(decision.reasons, responseState).toContain(
        "Public adapter-output authorization transport must return permit.",
      );
    }
  });

  it("denies malformed proof and signature", () => {
    const malformedProof = evaluate(
      validDecision({
        value: validAuthorization({ proof: { type: "", signature: "ed25519:abc" } }),
      }),
    );
    const missingSignature = evaluate(
      validDecision({
        value: validAuthorization({
          proof: { type: "ed25519-public-adapter-output-authorization" },
        }),
      }),
    );

    expect(malformedProof.allowed).toBe(false);
    expect(malformedProof.reasons).toContain(
      "Public adapter-output authorization proof signature is malformed.",
    );
    expect(missingSignature.allowed).toBe(false);
    expect(missingSignature.reasons).toContain(
      "Public adapter-output authorization proof signature is malformed.",
    );
  });

  it("denies and redacts raw sensitive fields", () => {
    const decision = evaluate(
      validDecision({
        value: validAuthorization({
          bearer_token: "Bearer secret-production-token",
          private_key: "raw-private-key",
        }),
      }),
    );

    expect(decision.allowed).toBe(false);
    expect(decision.metadata).toBeNull();
    expect(decision.reasons).toContain(
      "Public adapter-output authorization contains raw sensitive fields.",
    );
    expect(JSON.stringify(decision)).not.toContain("secret-production-token");
    expect(JSON.stringify(decision)).not.toContain("raw-private-key");
  });
});
