/*
 * Copyright 2026 Exochain Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  LynkConfigurationError,
  LynkValidationError,
  ReceiptEmissionError,
  buildLlmUsageReceiptIntent,
  hashProviderPayload,
  resolveReceiptPending,
  type FetchLike,
  type LlmProxyConfig,
  type UsageContext,
} from "../src/index.js";
import { releaseWithReceipt } from "../src/delivery.js";
import { emitUsageReceipt, resolveFetch } from "../src/receipt.js";
import {
  committedReceiptResponse,
  TEST_VALIDATOR_DID,
  TEST_VALIDATOR_PUBLIC_KEY,
} from "./receipt-fixture.js";

const stamp = { physical_ms: 1_700_000, logical: 0 };

function config(fetchImpl: FetchLike, mode: LlmProxyConfig["mode"] = "production"): LlmProxyConfig {
  return {
    mode,
    allowUnreceiptedOutputForDevelopment: mode === "development",
    gatewayUrl: "https://exochain.test",
    tenantId: "tenant-alpha",
    namespace: "default",
    actorDid: "did:exo:agent",
    adapterDid: "did:exo:adapter",
    trustedValidatorDid: TEST_VALIDATOR_DID,
    trustedValidatorPublicKey: TEST_VALIDATOR_PUBLIC_KEY,
    custodyPolicyHash: hashProviderPayload("policy"),
    storageMode: "receipt_minimized",
    validation: { credential: "fixture" },
    subjectSignature: "a".repeat(128),
    adapterSignature: "b".repeat(128),
    fetch: fetchImpl,
  };
}

function usageContext(): UsageContext {
  return {
    provider: "openai",
    providerEndpoint: "responses",
    modelId: "gpt-4.1-mini",
    requestPayload: { model: "gpt-4.1-mini" },
    responsePayload: { id: "resp_1" },
    idempotencyKey: "idem-delivery",
    usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2, usage_complete: true },
    createdAt: stamp,
    issuedAt: stamp,
  };
}

test("development mode can explicitly bypass receipt release", async () => {
  const fetchImpl: FetchLike = async () => new Response("unavailable", { status: 503 });
  const cfg = config(fetchImpl, "development");
  const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

  const result = await releaseWithReceipt(cfg, intent, { text: "development output" });

  assert.equal(result.status, "development_unreceipted");
  assert.deepEqual(result.output, { text: "development output" });
  assert.equal(result.receiptPending.status, "receipt_pending");
});

test("resolveReceiptPending replays the original receipt intent", async () => {
  let calls = 0;
  let responseIntent: Awaited<ReturnType<typeof buildLlmUsageReceiptIntent>> | undefined;
  const fetchImpl: FetchLike = async (_input, init) => {
    calls += 1;
    responseIntent = JSON.parse(String(init?.body)) as Awaited<
      ReturnType<typeof buildLlmUsageReceiptIntent>
    >;
    return new Response(JSON.stringify(committedReceiptResponse(responseIntent)), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const cfg = config(fetchImpl);
  const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());
  const receipt = await resolveReceiptPending(cfg, {
    status: "receipt_pending",
    idempotencyKeyHash: intent.llm_usage_evidence.evidence.idempotency_key_hash,
    receiptIntent: intent,
  });

  assert.equal(calls, 1);
  assert.equal(receipt.receipt_hash, committedReceiptResponse(intent).receipt_hash);
  assert.ok(responseIntent);
});

test("a signed response cannot be replayed across changed authorization material", async () => {
  const originalConfig = config(async () => new Response(null, { status: 204 }));
  const originalIntent = await buildLlmUsageReceiptIntent(originalConfig, usageContext());
  const capturedResponse = committedReceiptResponse(originalIntent);
  const replayConfig = config(async () => new Response(JSON.stringify(capturedResponse), {
    status: 200,
    headers: { "content-type": "application/json" },
  }));
  const substitutedIntent = {
    ...originalIntent,
    validation: { credential: "different-current-credential" },
    subject_signature: "c".repeat(128),
    adapter_signature: "d".repeat(128),
  };

  await assert.rejects(
    () => emitUsageReceipt(replayConfig, substitutedIntent),
    (error: unknown) => {
      assert.ok(error instanceof ReceiptEmissionError);
      assert.match(error.message, /malformed or untrusted/);
      return true;
    },
  );
});

test("response attestation binds the exact serialized request when nested toJSON disagrees", async () => {
  const setupConfig = config(async () => new Response(null, { status: 204 }));
  const intent = await buildLlmUsageReceiptIntent(setupConfig, usageContext());
  const deceptiveValidation = { marker: "validator-signed-object" };
  Object.defineProperty(deceptiveValidation, "toJSON", {
    enumerable: false,
    value: () => ({ marker: "transmitted-request" }),
  });
  intent.validation = {
    credential: "fixture",
    nested: deceptiveValidation,
  };
  const responseSignedForLiveObject = committedReceiptResponse(intent);
  let transmittedMarker: unknown;
  const cfg = config(async (_input, init) => {
    const transmitted = JSON.parse(String(init?.body)) as {
      validation: { nested: { marker: unknown } };
    };
    transmittedMarker = transmitted.validation.nested.marker;
    return new Response(JSON.stringify(responseSignedForLiveObject), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });

  await assert.rejects(
    () => emitUsageReceipt(cfg, intent),
    (error: unknown) => {
      assert.ok(error instanceof ReceiptEmissionError);
      assert.match(error.message, /malformed or untrusted/);
      return true;
    },
  );
  assert.equal(transmittedMarker, "transmitted-request");
});

test("response attestation cannot drop an own __proto__ request field", async () => {
  const setupConfig = config(async () => new Response(null, { status: 204 }));
  const intent = await buildLlmUsageReceiptIntent(setupConfig, usageContext());
  const validation = { credential: "fixture" } as Record<string, unknown>;
  intent.validation = validation;
  const responseWithoutProto = committedReceiptResponse(intent);
  Object.defineProperty(validation, "__proto__", {
    configurable: true,
    enumerable: true,
    value: { authorization_override: true },
    writable: true,
  });
  let sentOwnProto = false;
  const cfg = config(async (_input, init) => {
    const transmitted = JSON.parse(String(init?.body)) as {
      validation: Record<string, unknown>;
    };
    sentOwnProto = Object.prototype.hasOwnProperty.call(
      transmitted.validation,
      "__proto__",
    );
    return new Response(JSON.stringify(responseWithoutProto), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });

  await assert.rejects(
    () => emitUsageReceipt(cfg, intent),
    (error: unknown) => {
      assert.ok(error instanceof ReceiptEmissionError);
      assert.match(error.message, /malformed or untrusted/);
      return true;
    },
  );
  assert.equal(sentOwnProto, true);
});

test("receipt requests reject unpaired UTF-16 surrogates before transport", async () => {
  const cases: Array<[string, (intent: Awaited<ReturnType<typeof buildLlmUsageReceiptIntent>>) => void]> = [
    ["lone high surrogate value", (intent) => {
      intent.validation = { credential: "fixture", nested: { marker: "\ud800" } };
    }],
    ["lone low surrogate value", (intent) => {
      intent.validation = { credential: "fixture", nested: { marker: "\udc00" } };
    }],
    ["lone surrogate key", (intent) => {
      const nested = Object.create(null) as Record<string, unknown>;
      Object.defineProperty(nested, "\ud800", {
        enumerable: true,
        value: "attacker-controlled",
      });
      intent.validation = { credential: "fixture", nested };
    }],
  ];

  for (const [label, mutate] of cases) {
    let calls = 0;
    const cfg = config(async () => {
      calls += 1;
      return new Response(null, { status: 204 });
    });
    const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());
    mutate(intent);

    await assert.rejects(() => emitUsageReceipt(cfg, intent), ReceiptEmissionError, label);
    assert.equal(calls, 0, `${label} reached the LYNK transport`);
  }
});

test("receipt requests reject noncanonical raw JSON spelling before transport", async () => {
  const jsonWithRawValues = JSON as JSON & {
    rawJSON(value: string): unknown;
  };
  let calls = 0;
  const cfg = config(async () => {
    calls += 1;
    return new Response(null, { status: 204 });
  });
  const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());
  intent.validation = {
    credential: "fixture",
    nested: { integer_spelled_as_exponent: jsonWithRawValues.rawJSON("1e0") },
  };

  await assert.rejects(() => emitUsageReceipt(cfg, intent), ReceiptEmissionError);
  assert.equal(calls, 0, "noncanonical JSON reached the LYNK transport");
});

test("emitUsageReceipt uses global fetch fallback and trims gateway URL", async () => {
  const originalFetch = globalThis.fetch;
  let requestedUrl = "";
  try {
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: async (input: RequestInfo | URL, init?: RequestInit) => {
        requestedUrl = String(input);
        const responseIntent = JSON.parse(String(init?.body)) as Awaited<
          ReturnType<typeof buildLlmUsageReceiptIntent>
        >;
        return new Response(JSON.stringify(committedReceiptResponse(responseIntent)), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });
    const cfg = config(undefined as unknown as FetchLike);
    delete (cfg as { fetch?: FetchLike }).fetch;
    cfg.gatewayUrl = "https://exochain.test/";
    const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

    const receipt = await emitUsageReceipt(cfg, intent);

    assert.equal(
      requestedUrl,
      "https://exochain.test/api/v1/avc/llm-usage/receipts/emit",
    );
    assert.equal(receipt.receipt_hash, committedReceiptResponse(intent).receipt_hash);
  } finally {
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: originalFetch,
    });
  }
});

test("resolveFetch fails closed when no fetch implementation exists", () => {
  const originalFetch = globalThis.fetch;
  try {
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: undefined,
    });
    assert.throws(() => resolveFetch(), LynkConfigurationError);
  } finally {
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      value: originalFetch,
    });
  }
});

test("emitUsageReceipt exposes status code without leaking response body", async () => {
  const cfg = config(async () => new Response("secret receipt body", { status: 503 }));
  const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

  await assert.rejects(
    async () => emitUsageReceipt(cfg, intent),
    (error: unknown) => {
      assert.ok(error instanceof ReceiptEmissionError);
      assert.equal(error.statusCode, 503);
      assert.equal(error.message.includes("secret receipt body"), false);
      return true;
    },
  );
});

test("emitUsageReceipt rejects an oversized gateway error body before parsing", async () => {
  const cfg = config(async () => new Response("123456789", { status: 503 }));
  cfg.maxResponseBytes = 8;
  const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

  await assert.rejects(
    () => emitUsageReceipt(cfg, intent),
    (error: unknown) => {
      assert.ok(error instanceof LynkValidationError);
      assert.equal(error.message, "EXOCHAIN receipt response exceeds 8 bytes");
      return true;
    },
  );
});

test("non receipt emission errors are rethrown", async () => {
  const fetchImpl: FetchLike = async () => {
    throw new Error("network died before response");
  };
  const cfg = config(fetchImpl);
  const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

  await assert.rejects(
    () => releaseWithReceipt(cfg, intent, { text: "withheld" }),
    /network died before response/,
  );
});

test("production withholds output for malformed or unbound successful receipt responses", async () => {
  const validIntent = await buildLlmUsageReceiptIntent(
    config(async () => new Response(null, { status: 204 })),
    usageContext(),
  );
  const valid = committedReceiptResponse(validIntent);
  const receipt = valid.receipt as Record<string, unknown>;
  const validation = valid.validation as Record<string, unknown>;
  const malformedPayloads: unknown[] = [
    null,
    {},
    { ...valid, receipt_hash: "0".repeat(64) },
    { ...valid, receipt_hash: "not-a-hash" },
    { ...valid, exochain_finality_hash: undefined },
    { ...valid, exochain_finality_height: 0 },
    { ...valid, exochain_finality_height: 1.5 },
    { ...valid, exochain_finality_receipt_hash: valid.exochain_finality_hash },
    { ...valid, receipt: { ...receipt, receipt_id: "6".repeat(64) } },
    {
      ...valid,
      receipt: { ...receipt, receipt_id: Array.from({ length: 32 }, () => 6) },
    },
    { ...valid, receipt: { ...receipt, action_id: "7".repeat(64) } },
    {
      ...valid,
      receipt: { ...receipt, action_id: Array.from({ length: 32 }, () => 7) },
    },
    {
      ...valid,
      receipt: { ...receipt, action_commitment_hash: Array.from({ length: 32 }, () => 0) },
    },
    { ...valid, receipt: { ...receipt, previous_receipt_hash: "not-a-hash" } },
    {
      ...valid,
      receipt: { ...receipt, payment_evidence_hash: Array.from({ length: 32 }, () => 9) },
    },
    {
      ...valid,
      receipt: { ...receipt, created_at: { physical_ms: -1, logical: 0 } },
    },
    { ...valid, receipt: { ...receipt, signature: "Empty" } },
    {
      ...valid,
      receipt: { ...receipt, signature: { Ed25519: Array.from({ length: 64 }, () => 0) } },
    },
    { ...valid, receipt: { ...receipt, signature: { Unsupported: [1] } } },
    { ...valid, receipt: { ...receipt, signature: { PostQuantum: [] } } },
    {
      ...valid,
      receipt: {
        ...receipt,
        signature: {
          Hybrid: { classical: Array.from({ length: 64 }, () => 1) },
        },
      },
    },
    { ...valid, receipt: { ...receipt, external_timestamp_proof: {} } },
    { ...valid, receipt: { ...receipt, timestamp_provenance: "FixedTestTimestamp" } },
    {
      ...valid,
      receipt: {
        ...receipt,
        action_descriptor: {
          ...(receipt.action_descriptor as Record<string, unknown>),
          actor_did: "did:exo:different-actor",
        },
      },
    },
    {
      ...valid,
      receipt: {
        ...receipt,
        action_descriptor: {
          ...(receipt.action_descriptor as Record<string, unknown>),
          target_did: "did:exo:unexpected-target",
        },
      },
    },
    {
      ...valid,
      receipt: {
        ...receipt,
        action_descriptor: {
          ...(receipt.action_descriptor as Record<string, unknown>),
          estimated_risk_bp: 1,
        },
      },
    },
    { ...valid, receipt: { ...receipt, decision: "Deny" } },
    { ...valid, receipt: { ...receipt, reason_codes: ["Valid", "Expired"] } },
    { ...valid, validation: { ...validation, decision: "Deny" } },
    { ...valid, validation: { ...validation, reason_codes: ["Valid", "Expired"] } },
    {
      ...valid,
      validation: { ...validation, normalized_holder_did: "did:exo:different-holder" },
    },
    {
      ...valid,
      validation: { ...validation, credential_id: "8".repeat(64) },
    },
    { ...valid, validation: { ...validation, valid_until: "not-a-timestamp" } },
    { ...valid, validation: { ...validation, receipt: {} } },
    { ...valid, lynk_response_attestation: undefined },
    {
      ...valid,
      lynk_response_attestation: {
        ...(valid.lynk_response_attestation as Record<string, unknown>),
        signature: { Ed25519: Array.from({ length: 64 }, () => 0x7f) },
      },
    },
  ];

  for (const [index, payload] of malformedPayloads.entries()) {
    const cfg = config(async () =>
      new Response(JSON.stringify(payload), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());
    const result = await releaseWithReceipt(cfg, intent, { secret: `withheld-${index}` });

    assert.equal(result.status, "receipt_pending", `malformed payload ${index} must fail closed`);
    assert.equal("output" in result, false);
  }
});

test("production withholds output for forged receipt commitments and unknown response fields", async () => {
  const mutations: Array<(response: Record<string, unknown>) => void> = [
    (response) => {
      const receipt = response.receipt as Record<string, unknown>;
      receipt.action_commitment_hash = Array.from({ length: 32 }, () => 0x91);
      receipt.action_descriptor_hash = Array.from({ length: 32 }, () => 0x92);
      receipt.llm_usage_evidence_hash = Array.from({ length: 32 }, () => 0x93);
      receipt.validation_hash = Array.from({ length: 32 }, () => 0x94);
      receipt.signature = { Ed25519: Array.from({ length: 64 }, () => 0x95) };
    },
    (response) => {
      response.untrusted_extension = "must not cross the trust boundary";
    },
  ];

  for (const mutate of mutations) {
    const cfg = config(async (_input, init) => {
      const responseIntent = JSON.parse(String(init?.body)) as Awaited<
        ReturnType<typeof buildLlmUsageReceiptIntent>
      >;
      const response = committedReceiptResponse(responseIntent) as unknown as Record<
        string,
        unknown
      >;
      mutate(response);
      return new Response(JSON.stringify(response), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

    const result = await releaseWithReceipt(cfg, intent, { secret: "withheld" });

    assert.equal(result.status, "receipt_pending");
    assert.equal("output" in result, false);
  }
});

test("production rejects a valid receipt replayed across changed prompt evidence", async () => {
  const firstConfig = config(async () => new Response(null, { status: 204 }));
  const firstIntent = await buildLlmUsageReceiptIntent(firstConfig, usageContext());
  const replayedResponse = committedReceiptResponse(firstIntent);
  const changedContext = {
    ...usageContext(),
    requestPayload: { model: "gpt-4.1-mini", prompt: "different prompt" },
  };
  const cfg = config(async () => new Response(JSON.stringify(replayedResponse), {
    status: 200,
    headers: { "content-type": "application/json" },
  }));
  const changedIntent = await buildLlmUsageReceiptIntent(cfg, changedContext);

  const result = await releaseWithReceipt(cfg, changedIntent, { secret: "withheld" });

  assert.equal(result.status, "receipt_pending");
  assert.equal("output" in result, false);
});

test("production fails before transport without a valid explicit validator trust root", async () => {
  const invalidTrustRoots: Array<(cfg: LlmProxyConfig) => void> = [
    (cfg) => {
      delete cfg.trustedValidatorDid;
      delete cfg.trustedValidatorPublicKey;
    },
    (cfg) => {
      cfg.trustedValidatorDid = "not-a-did";
    },
    (cfg) => {
      cfg.trustedValidatorPublicKey = "11";
    },
    (cfg) => {
      cfg.trustedValidatorPublicKey = "AA".repeat(32);
    },
    (cfg) => {
      cfg.trustedValidatorPublicKey = "00".repeat(32);
    },
  ];

  for (const invalidate of invalidTrustRoots) {
    let calls = 0;
    const cfg = config(async () => {
      calls += 1;
      return new Response(null, { status: 204 });
    });
    invalidate(cfg);
    const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

    await assert.rejects(() => emitUsageReceipt(cfg, intent), LynkConfigurationError);
    assert.equal(calls, 0);
  }
});

test("production withholds output for invalid trust keys and mutated finality", async () => {
  const cases: Array<(cfg: LlmProxyConfig, response: Record<string, unknown>) => void> = [
    (cfg) => {
      cfg.trustedValidatorPublicKey = "11".repeat(32);
    },
    (cfg) => {
      cfg.trustedValidatorDid = "did:exo:other-validator";
    },
    (_cfg, response) => {
      response.exochain_finality_height = 2;
    },
    (_cfg, response) => {
      response.exochain_finality_hash = "ab".repeat(32);
    },
    (_cfg, response) => {
      const receipt = response.receipt as Record<string, unknown>;
      const descriptor = receipt.action_descriptor as Record<string, unknown>;
      descriptor.untrusted_extension = true;
    },
    (_cfg, response) => {
      const receipt = response.receipt as Record<string, unknown>;
      receipt.untrusted_extension = true;
    },
    (_cfg, response) => {
      const receipt = response.receipt as Record<string, unknown>;
      const createdAt = receipt.created_at as Record<string, unknown>;
      createdAt.untrusted_extension = true;
    },
    (_cfg, response) => {
      const receipt = response.receipt as Record<string, unknown>;
      receipt.signature = {
        ...(receipt.signature as Record<string, unknown>),
        untrusted_extension: [1],
      };
    },
    (_cfg, response) => {
      const validation = response.validation as Record<string, unknown>;
      validation.untrusted_extension = true;
    },
    (_cfg, response) => {
      const attestation = response.lynk_response_attestation as Record<string, unknown>;
      attestation.untrusted_extension = true;
    },
  ];

  for (const mutate of cases) {
    let response: Record<string, unknown> | undefined;
    const cfg = config(async (_input, init) => {
      const responseIntent = JSON.parse(String(init?.body)) as Awaited<
        ReturnType<typeof buildLlmUsageReceiptIntent>
      >;
      response = committedReceiptResponse(responseIntent) as unknown as Record<string, unknown>;
      mutate(cfg, response);
      return new Response(JSON.stringify(response), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

    const result = await releaseWithReceipt(cfg, intent, { secret: "withheld" });

    assert.equal(result.status, "receipt_pending");
    assert.equal("output" in result, false);
    assert.ok(response);
  }
});

test("production withholds output when a successful receipt body is invalid JSON", async () => {
  const cfg = config(
    async () =>
      new Response("{", {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  );
  const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

  const result = await releaseWithReceipt(cfg, intent, { secret: "withheld" });

  assert.equal(result.status, "receipt_pending");
  assert.equal("output" in result, false);
});

test("committed response validation accepts Rust signature and timestamp proof variants", async () => {
  const cases: Array<(response: Record<string, unknown>) => void> = [
    (response) => {
      const receipt = response.receipt as Record<string, unknown>;
      receipt.signature = { PostQuantum: [1] };
    },
    (response) => {
      const receipt = response.receipt as Record<string, unknown>;
      receipt.signature = {
        Hybrid: {
          classical: Array.from({ length: 64 }, () => 1),
          pq: [2],
        },
      };
    },
    (response) => {
      const receipt = response.receipt as Record<string, unknown>;
      receipt.timestamp_provenance = "ExternalTimestampAuthority";
      receipt.external_timestamp_proof = {
        authority_did: "did:exo:timestamp-authority",
        subject_hash: Array.from({ length: 32 }, () => 9),
        issued_at: receipt.created_at,
        signature: { Ed25519: Array.from({ length: 64 }, () => 3) },
      };
    },
    (response) => {
      const receipt = response.receipt as Record<string, unknown>;
      receipt.timestamp_provenance = "ExternalTimestampAuthority";
      receipt.external_timestamp_proof = {
        authority_did: "did:exo:timestamp-authority",
        subject_hash: Array.from({ length: 32 }, () => 9),
        issued_at: receipt.created_at,
        signature: "Empty",
        proof_kind: "Rfc3161",
        rfc3161: {
          message_imprint_sha256_hex: "9".repeat(64),
          token_der_base64: "AQID",
          policy_oid: "1.2.3",
          serial_number_hex: "01",
          nonce_hex: "02",
          tsa_subject: "CN=Timestamp Authority",
          tsa_public_key_spki_der_hex: "0304",
          tsa_trust_anchor_kind: "signer_spki",
          tsa_trust_anchor_spki_der_hex: "0506",
          tsa_issuer_subject: "CN=Issuer",
        },
      };
    },
  ];

  for (const mutate of cases) {
    let responseIntent: Awaited<ReturnType<typeof buildLlmUsageReceiptIntent>> | undefined;
    const cfg = config(async (_input, init) => {
      responseIntent = JSON.parse(String(init?.body)) as Awaited<
        ReturnType<typeof buildLlmUsageReceiptIntent>
      >;
      const response = committedReceiptResponse(
        responseIntent,
        mutate,
      ) as unknown as Record<string, unknown>;
      return new Response(JSON.stringify(response), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());

    const result = await releaseWithReceipt(cfg, intent, { released: true });

    assert.equal(result.status, "receipted");
    assert.ok(responseIntent);
  }
});

test("malformed external timestamp responses fail closed", async () => {
  const cfgForPayload = (mutate: (receipt: Record<string, unknown>) => void): LlmProxyConfig =>
    config(async (_input, init) => {
      const responseIntent = JSON.parse(String(init?.body)) as Awaited<
        ReturnType<typeof buildLlmUsageReceiptIntent>
      >;
      const response = committedReceiptResponse(responseIntent) as unknown as Record<
        string,
        unknown
      >;
      const receipt = response.receipt as Record<string, unknown>;
      receipt.timestamp_provenance = "ExternalTimestampAuthority";
      receipt.external_timestamp_proof = {
        authority_did: "did:exo:timestamp-authority",
        subject_hash: Array.from({ length: 32 }, () => 9),
        issued_at: receipt.created_at,
        signature: { Ed25519: Array.from({ length: 64 }, () => 3) },
      };
      mutate(receipt);
      return new Response(JSON.stringify(response), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });

  const mutations: Array<(receipt: Record<string, unknown>) => void> = [
    (receipt) => {
      receipt.external_timestamp_proof = {};
    },
    (receipt) => {
      const proof = receipt.external_timestamp_proof as Record<string, unknown>;
      proof.issued_at = { physical_ms: 1_700_002, logical: 0 };
    },
    (receipt) => {
      const proof = receipt.external_timestamp_proof as Record<string, unknown>;
      proof.proof_kind = "unsupported";
    },
    (receipt) => {
      const proof = receipt.external_timestamp_proof as Record<string, unknown>;
      proof.proof_kind = "Rfc3161";
      proof.signature = { Ed25519: Array.from({ length: 64 }, () => 3) };
      proof.rfc3161 = {};
    },
  ];

  for (const mutate of mutations) {
    const cfg = cfgForPayload(mutate);
    const intent = await buildLlmUsageReceiptIntent(cfg, usageContext());
    const result = await releaseWithReceipt(cfg, intent, { withheld: true });
    assert.equal(result.status, "receipt_pending");
    assert.equal("output" in result, false);
  }
});
