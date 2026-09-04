#!/usr/bin/env node
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

import { readFile, readdir, stat } from "node:fs/promises";
import { generateKeyPairSync, sign } from "node:crypto";

const packageRoot = new URL("../packages/exochain-llm-proxy/", import.meta.url);
await assertDistFresh(packageRoot);
const {
  createReceiptedMcpProxy,
  createReceiptedOpenAIClient,
  encodeLynkReceiptResponseAttestationPayload,
  hashProviderPayload,
  stableStringify,
} = await import("../packages/exochain-llm-proxy/dist/index.js");
const requestFixture = JSON.parse(
  await readFile(
    new URL("../crates/exo-node/fixtures/lynk/typescript_receipt_emit_request_v1.json", import.meta.url),
    "utf8",
  ),
);
const responseFixture = JSON.parse(
  await readFile(
    new URL("../crates/exo-node/fixtures/lynk/rust_receipt_emit_response_v1.json", import.meta.url),
    "utf8",
  ),
);

const args = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  args.set(process.argv[index], process.argv[index + 1]);
}

const fixture = args.get("--fixture") ?? "fake-openai";
const storageMode = args.get("--storage-mode") ?? "receipt_minimized";
const expectedFailure = args.get("--expect-failure");
if (!["fake-openai", "fake-mcp"].includes(fixture)) {
  throw new Error("--fixture must be fake-openai or fake-mcp");
}
if (!["receipt_minimized", "external_payload_ref", "dagdb_custody"].includes(storageMode)) {
  throw new Error("--storage-mode must be receipt_minimized, external_payload_ref, or dagdb_custody");
}
if (
  expectedFailure &&
  ![
    "receipt_unavailable",
    "idempotency_conflict",
    "missing_custody",
    "dagdb_custody_unavailable",
    "tenant_mismatch",
    "incomplete_usage_required",
  ].includes(expectedFailure)
) {
  throw new Error("--expect-failure must name a supported smoke failure case");
}

const emittedReceipts = new Map();
const objectWrites = [];
const stamp = { physical_ms: 1_700_000, logical: 0 };
const actionId = "02".repeat(32);
const validatorDid = "did:exo:validator";
const validatorKeypair = generateKeyPairSync("ed25519");
const validatorPublicKey = validatorKeypair.publicKey
  .export({ format: "der", type: "spki" })
  .subarray(-32)
  .toString("hex");
const receiptFailureStatus =
  expectedFailure === "receipt_unavailable"
    ? 503
    : expectedFailure === "idempotency_conflict"
      ? 409
      : 200;
const expectedTenant = expectedFailure === "tenant_mismatch" ? "tenant-beta" : "tenant-alpha";

const fetchImpl = async (input, init) => {
  const url = String(input);
  const body = init?.body ? JSON.parse(String(init.body)) : undefined;
  if (url.endsWith("/api/v1/avc/llm-usage/receipts/emit")) {
    assertNoRawPayload(body, "receipt emit body");
    assertRustWireShape(body);
    if (body.llm_usage_evidence.evidence.tenant_id !== expectedTenant) {
      return jsonResponse({ error: "tenant mismatch" }, 409);
    }
    if (receiptFailureStatus !== 200) {
      return jsonResponse({ error: "receipt unavailable" }, receiptFailureStatus);
    }
    const response = committedReceiptResponse(body);
    const receiptHash = response.receipt_hash;
    emittedReceipts.set(receiptHash, response);
    return jsonResponse(emittedReceipts.get(receiptHash));
  }
  if (url.includes("/api/v1/avc/receipts/")) {
    const receiptHash = decodeURIComponent(url.split("/").pop() ?? "");
    const receipt = emittedReceipts.get(receiptHash);
    if (!receipt) {
      return jsonResponse({ error: "missing receipt" }, 404);
    }
    return jsonResponse(receipt.receipt);
  }
  if (url.endsWith("/v1/responses")) {
    if (expectedFailure === "incomplete_usage_required") {
      return jsonResponse({
        id: "resp_smoke_incomplete",
        output: [{ type: "message", content: [{ type: "output_text", text: "secret-output" }] }],
      });
    }
    return jsonResponse({
      id: "resp_smoke",
      output: [{ type: "message", content: [{ type: "output_text", text: "secret-output" }] }],
      usage: {
        input_tokens: 8,
        input_tokens_details: { cached_tokens: 1 },
        output_tokens: 3,
        output_tokens_details: { reasoning_tokens: 1 },
        total_tokens: 11,
      },
    });
  }
  if (url === "https://mcp-smoke.test") {
    return jsonResponse({
      jsonrpc: "2.0",
      id: body.id,
      result: { content: [{ type: "text", text: "secret-tool-result" }] },
    });
  }
  return jsonResponse({ error: `unexpected URL ${url}` }, 500);
};

const validation = structuredClone(requestFixture.validation);
const dataClass = {
  receipt_minimized: "Internal",
  external_payload_ref: "Confidential",
  dagdb_custody: "Restricted",
}[storageMode];
validation.action.data_class = dataClass;
validation.credential.authority_scope.data_classes = [dataClass];

const config = {
  mode: "production",
  gatewayUrl: "https://exochain-smoke.test",
  tenantId: "tenant-alpha",
  namespace: "default",
  actorDid: "did:exo:agent",
  adapterDid: "did:exo:adapter",
  trustedValidatorDid: validatorDid,
  trustedValidatorPublicKey: validatorPublicKey,
  custodyPolicyHash: hashProviderPayload("smoke-policy"),
  storageMode: expectedFailure === "missing_custody" ? undefined : storageMode,
  requireCompleteUsage: expectedFailure === "incomplete_usage_required",
  validation,
  subjectSignature: "0a".repeat(64),
  subjectPublicKey: "0d".repeat(32),
  adapterSignature: "0b".repeat(64),
  adapterPublicKey: "0e".repeat(32),
  fetch: fetchImpl,
  kms: {
    encrypt: async ({ payloadKind }) => ({
      ciphertext: `ciphertext-${payloadKind}`,
      keyPolicyId: "customer-kms-policy",
    }),
  },
  objectStore: {
    put: async ({ payloadKind }) => {
      objectWrites.push(payloadKind);
      return {
        refId: `customer://opaque/${payloadKind}`,
        storagePolicyId: "customer-object-policy",
      };
    },
  },
};

let result;
try {
  if (storageMode === "dagdb_custody") {
    throw new Error("dagdb_custody smoke requires governed DAG DB custody proof");
  }
  if (fixture === "fake-openai") {
    const client = createReceiptedOpenAIClient(config, {
      openAIBaseUrl: "https://openai-smoke.test",
    });
    result = await client.responses.create(
      { model: "gpt-4.1-mini", input: "secret-prompt" },
      { idempotencyKey: `smoke-${fixture}-${storageMode}`, actionId, createdAt: stamp },
    );
  } else {
    const proxy = createReceiptedMcpProxy(config, { serverUrl: "https://mcp-smoke.test" });
    result = await proxy.callTool(
      { name: "search", arguments: { query: "secret-tool-argument" } },
      { idempotencyKey: `smoke-${fixture}-${storageMode}`, actionId, createdAt: stamp },
    );
  }
} catch (error) {
  if (
    expectedFailure === "missing_custody" ||
    expectedFailure === "dagdb_custody_unavailable" ||
    expectedFailure === "incomplete_usage_required"
  ) {
    console.log(
      JSON.stringify({
        fixture,
        storage_mode: storageMode,
        status: "expected_failure_ok",
        failure_case: expectedFailure,
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    process.exit(0);
  }
  throw error;
}

if (expectedFailure) {
  if (
    !["receipt_unavailable", "idempotency_conflict", "tenant_mismatch"].includes(expectedFailure)
  ) {
    throw new Error(`failure case ${expectedFailure} unexpectedly succeeded`);
  }
  if (result.status !== "receipt_pending" || "output" in result) {
    throw new Error(`failure case ${expectedFailure} did not withhold output`);
  }
  assertNoRawPayload(result.receiptIntent, "pending receipt intent");
  console.log(
    JSON.stringify({
      fixture,
      storage_mode: storageMode,
      status: "expected_failure_ok",
      failure_case: expectedFailure,
      pending_idempotency: result.idempotencyKeyHash,
    }),
  );
  process.exit(0);
}

if (result.status !== "receipted") {
  throw new Error(`expected receipted smoke result, got ${result.status}`);
}

const receiptHash = result.receipt.receipt_hash;
const lookup = await fetchImpl(`https://exochain-smoke.test/api/v1/avc/receipts/${receiptHash}`);
if (!lookup.ok) {
  throw new Error("receipt lookup failed");
}
const fetchedReceipt = await lookup.json();
if (bytesToHex(fetchedReceipt.receipt_id) !== receiptHash) {
  throw new Error("receipt lookup did not return emitted receipt");
}
assertNoRawPayload(result.receiptIntent, "receipt intent");

console.log(
  JSON.stringify({
    fixture,
    storage_mode: storageMode,
    status: "ok",
    receipt_hash: receiptHash,
    encrypted_payload_refs:
      result.receiptIntent.llm_usage_evidence.evidence.encrypted_payload_refs.length,
    object_writes: objectWrites.length,
  }),
);

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function committedReceiptResponse(body) {
  const response = structuredClone(responseFixture);
  const evidence = body.llm_usage_evidence.evidence;
  response.receipt.action_id = [...evidence.action_id];
  response.receipt.action_descriptor.action_id = [...evidence.action_id];
  response.receipt.action_descriptor.actor_did = evidence.actor_did;
  response.receipt.action_descriptor.data_class = {
    receipt_minimized: "Internal",
    external_payload_ref: "Confidential",
    dagdb_custody: "Restricted",
  }[evidence.custody_mode];
  response.receipt.action_descriptor.estimated_budget_minor_units =
    evidence.usage.cost_minor_units ?? null;
  response.validation.normalized_holder_did = evidence.actor_did;
  const payload = encodeLynkReceiptResponseAttestationPayload({
    receiptHash: response.receipt_hash,
    finalityHash: response.exochain_finality_hash,
    finalityHeight: response.exochain_finality_height,
    finalityReceiptHash: response.exochain_finality_receipt_hash,
    receipt: response.receipt,
    validation: response.validation,
    evidence: body.llm_usage_evidence,
    validatorDid,
  });
  response.lynk_response_attestation = {
    domain: "exo.avc.lynk.receipt_response.attestation.v1",
    schema_version: 1,
    validator_did: validatorDid,
    signature: {
      Ed25519: [...sign(null, Buffer.from(payload), validatorKeypair.privateKey)],
    },
  };
  return response;
}

function assertRustWireShape(body) {
  const evidence = body?.llm_usage_evidence?.evidence;
  if (
    !isByteArray(evidence?.action_id, 32)
    || !isByteArray(evidence?.idempotency_key_hash, 32)
    || !isByteArray(evidence?.prompt_hash, 32)
    || !isByteArray(body?.subject_signature?.Ed25519, 64)
    || !isByteArray(body?.adapter_signature?.Ed25519, 64)
    || !isByteArray(body?.subject_public_key, 32)
    || !isByteArray(body?.adapter_public_key, 32)
    || !isByteArray(body?.validation?.action?.action_id, 32)
  ) {
    throw new Error("receipt emission did not use the Rust serde wire contract");
  }
}

function isByteArray(value, length) {
  return (
    Array.isArray(value)
    && value.length === length
    && value.every((byte) => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255)
  );
}

function bytesToHex(value) {
  if (!isByteArray(value, 32)) {
    throw new Error("receipt lookup returned a malformed receipt id");
  }
  return value.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function assertNoRawPayload(value, context) {
  const serialized = stableStringify(value);
  for (const forbidden of [
    "secret-prompt",
    "secret-output",
    "secret-tool-argument",
    "secret-tool-result",
    "provider_api_key",
    "bearer_token",
    "kms_key",
    "customer://opaque",
  ]) {
    if (serialized.includes(forbidden)) {
      throw new Error(`${context} leaked forbidden payload material: ${forbidden}`);
    }
  }
}

async function assertDistFresh(rootUrl) {
  const distIndex = new URL("dist/index.js", rootUrl);
  const distStat = await stat(distIndex);
  const newestSourceMtime = await newestMtime(new URL("src/", rootUrl));
  if (newestSourceMtime > distStat.mtimeMs) {
    throw new Error("packages/exochain-llm-proxy/dist is stale; run npm run build first");
  }
}

async function newestMtime(directoryUrl) {
  let newest = 0;
  for (const entry of await readdir(directoryUrl, { withFileTypes: true })) {
    const childUrl = new URL(entry.name, directoryUrl);
    if (entry.isDirectory()) {
      newest = Math.max(newest, await newestMtime(new URL(`${entry.name}/`, directoryUrl)));
    } else if (entry.isFile() && entry.name.endsWith(".ts")) {
      newest = Math.max(newest, (await stat(childUrl)).mtimeMs);
    }
  }
  return newest;
}
