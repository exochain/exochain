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
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  LynkValidationError,
  encodeReceiptIntentForWire,
  type LlmProxyConfig,
  type ReceiptIntent,
} from "../src/index.js";
import {
  verifyLynkReceiptResponseAttestation,
} from "../src/attestation.js";
import type { ReceiptEmitWireRequest } from "../src/wire.js";
import {
  TEST_VALIDATOR_DID,
  TEST_VALIDATOR_PUBLIC_KEY,
} from "./receipt-fixture.js";

const hash = (byte: string): string => byte.repeat(64);
const signature = (byte: string): string => byte.repeat(128);

const sharedRequestFixtureUrl = new URL(
  "../../../../crates/exo-node/fixtures/lynk/typescript_receipt_emit_request_v1.json",
  import.meta.url,
);
const sharedResponseFixtureUrl = new URL(
  "../../../../crates/exo-node/fixtures/lynk/rust_receipt_emit_response_v1.json",
  import.meta.url,
);

test("TypeScript verifies the Rust-generated canonical response attestation fixture", async () => {
  const request = JSON.parse(
    readFileSync(sharedRequestFixtureUrl, "utf8"),
  ) as ReceiptEmitWireRequest;
  const response = JSON.parse(readFileSync(sharedResponseFixtureUrl, "utf8")) as Record<
    string,
    unknown
  >;
  const attestation = response.lynk_response_attestation as {
    validator_did: string;
    signature: { Ed25519: number[] };
  };
  const input = {
    receiptHash: response.receipt_hash as string,
    finalityHash: response.exochain_finality_hash as string,
    finalityHeight: response.exochain_finality_height as number,
    finalityReceiptHash: response.exochain_finality_receipt_hash as string,
    receipt: response.receipt as Record<string, unknown>,
    validation: response.validation as Record<string, unknown>,
    request,
    validatorDid: attestation.validator_did,
  };
  const config = {
    trustedValidatorDid: TEST_VALIDATOR_DID,
    trustedValidatorPublicKey: TEST_VALIDATOR_PUBLIC_KEY,
  } as LlmProxyConfig;

  await verifyLynkReceiptResponseAttestation(
    config,
    input,
    attestation.signature.Ed25519,
  );

  const mutations: Array<[string, ReceiptEmitWireRequest]> = [];
  const changedValidation = structuredClone(request);
  (changedValidation.validation as Record<string, unknown>).now = {
    physical_ms: 1_700_001,
    logical: 0,
  };
  mutations.push(["validation", changedValidation]);
  const changedSubjectSignature = structuredClone(request);
  changedSubjectSignature.subject_signature = {
    Ed25519: Array.from({ length: 64 }, () => 0xa1),
  };
  mutations.push(["subject signature", changedSubjectSignature]);
  const changedSubjectKey = structuredClone(request);
  changedSubjectKey.subject_public_key = Array.from({ length: 32 }, () => 0xa2);
  mutations.push(["subject public key", changedSubjectKey]);
  const changedEvidence = structuredClone(request);
  changedEvidence.llm_usage_evidence.evidence.prompt_hash = Array.from(
    { length: 32 },
    () => 0xa3,
  );
  mutations.push(["LLM evidence", changedEvidence]);
  const changedAdapterSignature = structuredClone(request);
  changedAdapterSignature.adapter_signature = {
    Ed25519: Array.from({ length: 64 }, () => 0xa4),
  };
  mutations.push(["adapter signature", changedAdapterSignature]);
  const changedAdapterKey = structuredClone(request);
  changedAdapterKey.adapter_public_key = Array.from({ length: 32 }, () => 0xa5);
  mutations.push(["adapter public key", changedAdapterKey]);

  for (const [label, changedRequest] of mutations) {
    await assert.rejects(
      () => verifyLynkReceiptResponseAttestation(
        config,
        { ...input, request: changedRequest },
        attestation.signature.Ed25519,
      ),
      /signature is invalid/,
      label,
    );
  }
});

test("receipt intent encoder emits the Rust serde hash, signature, and public-key shapes", () => {
  const intent: ReceiptIntent = {
    validation: {},
    subject_signature: signature("a"),
    subject_public_key: hash("b"),
    llm_usage_evidence: {
      schema_version: 1,
      adapter_did: "did:exo:adapter",
      issued_at: { physical_ms: 1_700_000, logical: 0 },
      evidence: {
        schema_version: 1,
        tenant_id: "tenant-alpha",
        namespace: "default",
        actor_did: "did:exo:agent",
        provider: "openai",
        provider_endpoint: "responses",
        model_id: "gpt-4.1-mini",
        idempotency_key_hash: hash("1"),
        action_id: hash("2"),
        prompt_hash: hash("3"),
        usage: {
          input_tokens: 1,
          output_tokens: 1,
          total_tokens: 2,
          usage_complete: true,
        },
        custody_mode: "receipt_minimized",
        encrypted_payload_refs: [],
        custody_policy_hash: hash("4"),
        created_at: { physical_ms: 1_700_000, logical: 0 },
      },
    },
    adapter_signature: signature("c"),
    adapter_public_key: hash("d"),
  };

  const encoded = encodeReceiptIntentForWire(intent);

  assert.deepEqual(encoded.subject_signature, {
    Ed25519: Array.from({ length: 64 }, () => 0xaa),
  });
  assert.deepEqual(encoded.subject_public_key, Array.from({ length: 32 }, () => 0xbb));
  assert.deepEqual(encoded.adapter_signature, {
    Ed25519: Array.from({ length: 64 }, () => 0xcc),
  });
  assert.deepEqual(encoded.adapter_public_key, Array.from({ length: 32 }, () => 0xdd));
  assert.deepEqual(
    encoded.llm_usage_evidence.evidence.action_id,
    Array.from({ length: 32 }, () => 0x22),
  );
});

test("the TypeScript encoder exactly reproduces the fixture parsed by the Rust route DTO", () => {
  const logicalIntent: ReceiptIntent = {
    validation: {
      credential: {
        schema_version: 1,
        issuer_did: "did:exo:issuer",
        principal_did: "did:exo:principal",
        subject_did: "did:exo:agent",
        holder_did: null,
        subject_kind: {
          AiAgent: {
            model_id: "gpt-4.1-mini",
            agent_version: null,
          },
        },
        created_at: { physical_ms: 1_600_000, logical: 0 },
        expires_at: { physical_ms: 1_800_000, logical: 0 },
        delegated_intent: {
          intent_id: "01".repeat(32),
          purpose: "EXOCHAIN LYNK Protocol usage receipts",
          allowed_objectives: ["llm.usage.receipt.emit"],
          prohibited_objectives: [],
          autonomy_level: "ExecuteWithinBounds",
          delegation_allowed: false,
        },
        authority_scope: {
          permissions: ["Execute"],
          tools: ["exo.avc.lynk.llm_usage.evidence.v1"],
          data_classes: ["Internal"],
          counterparties: [],
          jurisdictions: [],
        },
        constraints: {
          max_budget_minor_units: null,
          currency_code: null,
          max_action_risk_bp: null,
          human_approval_required: false,
          approval_threshold_bp: null,
          max_delegation_depth: 0,
          allowed_time_window: null,
          forbidden_actions: [],
          emergency_stop_refs: [],
        },
        authority_chain: null,
        consent_refs: [],
        policy_refs: [],
        parent_avc_id: null,
        signature: "0c".repeat(64),
      },
      action: {
        action_id: "02".repeat(32),
        actor_did: "did:exo:agent",
        requested_permission: "Execute",
        tool: "exo.avc.lynk.llm_usage.evidence.v1",
        target_did: null,
        data_class: "Internal",
        estimated_budget_minor_units: null,
        estimated_risk_bp: null,
        human_approval: null,
        requires_human_approval: false,
        action_name: "llm.usage.receipt.emit",
      },
      now: { physical_ms: 1_700_000, logical: 0 },
    },
    subject_signature: "0a".repeat(64),
    subject_public_key: "0d".repeat(32),
    llm_usage_evidence: {
      schema_version: 1,
      adapter_did: "did:exo:adapter",
      issued_at: { physical_ms: 1_700_000, logical: 0 },
      evidence: {
        schema_version: 1,
        tenant_id: "tenant-alpha",
        namespace: "default",
        actor_did: "did:exo:agent",
        provider: "openai",
        provider_endpoint: "responses",
        model_id: "gpt-4.1-mini",
        idempotency_key_hash: "01".repeat(32),
        action_id: "02".repeat(32),
        prompt_hash: "03".repeat(32),
        usage: {
          input_tokens: 1,
          output_tokens: 1,
          total_tokens: 2,
          usage_complete: true,
        },
        custody_mode: "receipt_minimized",
        encrypted_payload_refs: [],
        custody_policy_hash: "04".repeat(32),
        created_at: { physical_ms: 1_700_000, logical: 0 },
      },
    },
    adapter_signature: "0b".repeat(64),
    adapter_public_key: "0e".repeat(32),
  };
  const expected = JSON.parse(readFileSync(sharedRequestFixtureUrl, "utf8")) as unknown;

  assert.deepEqual(encodeReceiptIntentForWire(logicalIntent), expected);
  assert.equal(logicalIntent.llm_usage_evidence.evidence.action_id, "02".repeat(32));
  assert.equal(logicalIntent.subject_signature, "0a".repeat(64));
});

test("wire encoding fails closed on noncanonical and empty signature material", () => {
  const base: ReceiptIntent = {
    validation: {},
    subject_signature: "a".repeat(128),
    llm_usage_evidence: {
      schema_version: 1,
      adapter_did: "did:exo:adapter",
      issued_at: { physical_ms: 1, logical: 0 },
      evidence: {
        schema_version: 1,
        tenant_id: "tenant",
        namespace: "namespace",
        actor_did: "did:exo:actor",
        provider: "openai",
        provider_endpoint: "responses",
        model_id: "model",
        idempotency_key_hash: "1".repeat(64),
        action_id: "2".repeat(64),
        prompt_hash: "3".repeat(64),
        usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2, usage_complete: true },
        custody_mode: "receipt_minimized",
        encrypted_payload_refs: [],
        custody_policy_hash: "4".repeat(64),
        created_at: { physical_ms: 1, logical: 0 },
      },
    },
    adapter_signature: "b".repeat(128),
  };

  for (const invalid of ["a", "A".repeat(128), "0".repeat(128)]) {
    assert.throws(
      () => encodeReceiptIntentForWire({ ...base, subject_signature: invalid }),
      LynkValidationError,
    );
  }
  assert.throws(
    () =>
      encodeReceiptIntentForWire({
        ...base,
        subject_public_key: "0".repeat(64),
      }),
    LynkValidationError,
  );
  assert.throws(
    () =>
      encodeReceiptIntentForWire({
        ...base,
        llm_usage_evidence: {
          ...base.llm_usage_evidence,
          evidence: {
            ...base.llm_usage_evidence.evidence,
            prompt_hash: "F".repeat(64),
          },
        },
      }),
    LynkValidationError,
  );
});

test("wire encoding covers nested AVC hashes, signatures, and external payload refs", () => {
  const hashValue = "1".repeat(64);
  const intent: ReceiptIntent = {
    validation: {
      credential: {
        delegated_intent: { intent_id: hashValue },
        authority_chain: { chain_hash: "2".repeat(64) },
        consent_refs: [{ consent_id: "3".repeat(64), required: true }, "preserved"],
        policy_refs: [{ policy_id: "4".repeat(64), policy_version: 1, required: true }],
        parent_avc_id: "5".repeat(64),
        signature: { PostQuantum: [7] },
      },
      action: {
        action_id: "6".repeat(64),
        human_approval: {
          signature: {
            Hybrid: {
              classical: Array.from({ length: 64 }, () => 8),
              pq: [9],
            },
          },
        },
      },
    },
    subject_signature: "a".repeat(128),
    llm_usage_evidence: {
      schema_version: 1,
      adapter_did: "did:exo:adapter",
      issued_at: { physical_ms: 1, logical: 0 },
      evidence: {
        schema_version: 1,
        tenant_id: "tenant",
        namespace: "namespace",
        actor_did: "did:exo:actor",
        provider: "mcp",
        provider_endpoint: "tools/call",
        model_id: "tool",
        provider_request_id_hash: "7".repeat(64),
        session_id_hash: "8".repeat(64),
        idempotency_key_hash: "9".repeat(64),
        action_id: "a".repeat(64),
        prompt_hash: "b".repeat(64),
        completion_hash: "c".repeat(64),
        tool_call_hash: "d".repeat(64),
        tool_result_hash: "e".repeat(64),
        usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2, usage_complete: true },
        custody_mode: "external_payload_ref",
        encrypted_payload_refs: [
          {
            ref_id_hash: "1".repeat(64),
            ciphertext_hash: "2".repeat(64),
            storage_policy_hash: "3".repeat(64),
            key_policy_hash: "4".repeat(64),
            payload_kind: "provider_exchange",
            byte_length: 2,
          },
        ],
        custody_policy_hash: "f".repeat(64),
        created_at: { physical_ms: 1, logical: 0 },
      },
    },
    adapter_signature: "b".repeat(128),
  };

  const encoded = encodeReceiptIntentForWire(intent);
  const validation = encoded.validation as Record<string, unknown>;
  const credential = validation.credential as Record<string, unknown>;
  const delegatedIntent = credential.delegated_intent as Record<string, unknown>;
  const action = validation.action as Record<string, unknown>;
  const approval = action.human_approval as Record<string, unknown>;

  assert.deepEqual(delegatedIntent.intent_id, Array.from({ length: 32 }, () => 0x11));
  assert.deepEqual(credential.signature, { PostQuantum: [7] });
  assert.deepEqual(approval.signature, {
    Hybrid: {
      classical: Array.from({ length: 64 }, () => 8),
      pq: [9],
    },
  });
  assert.equal(encoded.llm_usage_evidence.evidence.encrypted_payload_refs?.length, 1);
  assert.deepEqual(
    encoded.llm_usage_evidence.evidence.provider_request_id_hash,
    Array.from({ length: 32 }, () => 0x77),
  );
});

test("wire signature variants are bounded and unknown validation shapes remain retryable data", () => {
  const base: ReceiptIntent = {
    validation: "caller-owned-validation",
    subject_signature: "a".repeat(128),
    llm_usage_evidence: {
      schema_version: 1,
      adapter_did: "did:exo:adapter",
      issued_at: { physical_ms: 1, logical: 0 },
      evidence: {
        schema_version: 1,
        tenant_id: "tenant",
        namespace: "namespace",
        actor_did: "did:exo:actor",
        provider: "openai",
        provider_endpoint: "responses",
        model_id: "model",
        idempotency_key_hash: "1".repeat(64),
        action_id: "2".repeat(64),
        prompt_hash: "3".repeat(64),
        usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2, usage_complete: true },
        custody_mode: "receipt_minimized",
        encrypted_payload_refs: [],
        custody_policy_hash: "4".repeat(64),
        created_at: { physical_ms: 1, logical: 0 },
      },
    },
    adapter_signature: "b".repeat(128),
  };

  assert.equal(encodeReceiptIntentForWire(base).validation, "caller-owned-validation");

  const withCredentialSignature = (signatureValue: unknown): ReceiptIntent => ({
    ...base,
    validation: { credential: { signature: signatureValue } },
  });
  for (const invalid of [
    {},
    { Unknown: [1] },
    { Ed25519: [1] },
    { Ed25519: Array.from({ length: 64 }, () => 0) },
    { PostQuantum: [] },
    { PostQuantum: Array.from({ length: 3_310 }, () => 1) },
    { Hybrid: { classical: Array.from({ length: 64 }, () => 1) } },
    { Hybrid: { classical: [1], pq: [2] } },
  ]) {
    assert.throws(
      () => encodeReceiptIntentForWire(withCredentialSignature(invalid)),
      LynkValidationError,
    );
  }
  assert.throws(
    () =>
      encodeReceiptIntentForWire({
        ...base,
        validation: {
          credential: {
            delegated_intent: { intent_id: [1] },
          },
        },
      }),
    LynkValidationError,
  );
});
