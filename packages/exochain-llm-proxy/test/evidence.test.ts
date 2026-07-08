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
  ZERO_HASH,
  assertNoForbiddenReceiptMaterial,
  buildLlmUsageEvidence,
  buildLlmUsageReceiptIntent,
  hashProviderPayload,
  maybeStoreExternalPayloads,
  stableStringify,
  type EncryptedPayloadRef,
  type LlmProxyConfig,
  type UsageContext,
} from "../src/index.js";

const stamp = { physical_ms: 1_700_000, logical: 0 };

function baseConfig(overrides: Partial<LlmProxyConfig> = {}): LlmProxyConfig {
  return {
    mode: "production",
    gatewayUrl: "https://exochain.test",
    tenantId: "tenant-alpha",
    namespace: "default",
    actorDid: "did:exo:agent",
    adapterDid: "did:exo:adapter",
    custodyPolicyHash: hashProviderPayload("policy"),
    storageMode: "receipt_minimized",
    validation: { credential: "fixture" },
    subjectSignature: "subject-signature",
    adapterSignature: "adapter-signature",
    fetch: async () => new Response("{}"),
    ...overrides,
  };
}

function usageContext(overrides: Partial<UsageContext> = {}): UsageContext {
  return {
    provider: "openai",
    providerEndpoint: "responses",
    modelId: "gpt-4.1-mini",
    requestPayload: { model: "gpt-4.1-mini", input: "placeholder input" },
    responsePayload: { id: "resp_1", output: "placeholder output" },
    idempotencyKey: "idem-evidence",
    usage: {
      input_tokens: 3,
      output_tokens: 2,
      total_tokens: 5,
      usage_complete: true,
    },
    createdAt: stamp,
    issuedAt: stamp,
    ...overrides,
  };
}

function encryptedRef(): EncryptedPayloadRef {
  return {
    ref_id_hash: hashProviderPayload("opaque-ref"),
    ciphertext_hash: hashProviderPayload("ciphertext"),
    storage_policy_hash: hashProviderPayload("storage-policy"),
    key_policy_hash: hashProviderPayload("key-policy"),
    payload_kind: "openai_request",
    byte_length: 10,
  };
}

test("stableStringify is deterministic and rejects unsupported values", () => {
  assert.equal(
    stableStringify({ b: 2, a: true, c: undefined, d: null }),
    '{"a":true,"b":2,"d":null}',
  );
  assert.equal(stableStringify(["x", 1, false]), '["x",1,false]');
  assert.throws(() => stableStringify(1.25), LynkValidationError);
  assert.throws(() => stableStringify(Symbol("unsupported")), LynkValidationError);
});

test("usage metrics reject unsafe, negative, and contradictory counters", () => {
  assert.throws(
    () =>
      buildLlmUsageEvidence(
        baseConfig(),
        usageContext({ usage: { input_tokens: -1, output_tokens: 0, total_tokens: 0, usage_complete: true } }),
      ),
    LynkValidationError,
  );
  assert.throws(
    () =>
      buildLlmUsageEvidence(
        baseConfig(),
        usageContext({ usage: { input_tokens: 1.25, output_tokens: 0, total_tokens: 2, usage_complete: true } }),
      ),
    LynkValidationError,
  );
  assert.throws(
    () =>
      buildLlmUsageEvidence(
        baseConfig(),
        usageContext({ usage: { input_tokens: 4, output_tokens: 4, total_tokens: 7, usage_complete: true } }),
      ),
    LynkValidationError,
  );
  assert.throws(
    () =>
      buildLlmUsageEvidence(
        baseConfig(),
        usageContext({
          usage: {
            input_tokens: 1,
            output_tokens: 1,
            total_tokens: 2,
            cached_input_tokens: 2,
            usage_complete: true,
          },
        }),
      ),
    LynkValidationError,
  );
  assert.throws(
    () =>
      buildLlmUsageEvidence(
        baseConfig(),
        usageContext({
          usage: {
            input_tokens: 1,
            output_tokens: 1,
            total_tokens: 2,
            reasoning_tokens: 2,
            usage_complete: true,
          },
        }),
      ),
    LynkValidationError,
  );
});

test("storage mode evidence validation is fail closed", () => {
  assert.throws(
    () =>
      buildLlmUsageEvidence(
        baseConfig({ storageMode: "receipt_minimized" }),
        usageContext({ encryptedPayloadRefs: [encryptedRef()] }),
      ),
    LynkValidationError,
  );
  assert.throws(
    () => buildLlmUsageEvidence(baseConfig({ storageMode: "external_payload_ref" }), usageContext()),
    LynkValidationError,
  );
  assert.throws(
    () =>
      buildLlmUsageEvidence(
        baseConfig({ storageMode: "dagdb_custody", custodyPolicyHash: ZERO_HASH }),
        usageContext(),
      ),
    LynkValidationError,
  );
});

test("required config and supported storage mode are enforced", () => {
  assert.throws(
    () => buildLlmUsageEvidence(baseConfig({ tenantId: " " }), usageContext()),
    LynkConfigurationError,
  );
  assert.throws(
    () =>
      buildLlmUsageEvidence(
        baseConfig({ storageMode: "unsupported" as LlmProxyConfig["storageMode"] }),
        usageContext(),
      ),
    LynkConfigurationError,
  );
});

test("receipt intent forwards async adapter signature and public keys", async () => {
  const intent = await buildLlmUsageReceiptIntent(
    baseConfig({
      adapterPublicKey: "adapter-public-key",
      subjectPublicKey: "subject-public-key",
      adapterSignature: async (envelope) => `signed:${envelope.adapter_did}`,
    }),
    usageContext({ providerRequestId: "resp_1", sessionId: "session_1" }),
  );

  assert.equal(intent.adapter_signature, "signed:did:exo:adapter");
  assert.equal(intent.adapter_public_key, "adapter-public-key");
  assert.equal(intent.subject_public_key, "subject-public-key");
  assert.equal(intent.llm_usage_evidence.evidence.provider_request_id_hash?.length, 64);
  assert.equal(intent.llm_usage_evidence.evidence.session_id_hash?.length, 64);
});

test("external payload storage requires both KMS and object store", async () => {
  await assert.rejects(
    () => maybeStoreExternalPayloads(baseConfig({ storageMode: "external_payload_ref" }), []),
    LynkConfigurationError,
  );
});

test("forbidden receipt material guard rejects raw-field keys", () => {
  assert.throws(
    () => assertNoForbiddenReceiptMaterial({ raw_prompt: "blocked" }),
    LynkValidationError,
  );
});
