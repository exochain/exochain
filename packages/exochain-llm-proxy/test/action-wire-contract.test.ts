// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { encodeCanonicalCbor, verifyAvcActionResponseAttestation } from "../src/attestation.js";
import { TEST_VALIDATOR_DID, TEST_VALIDATOR_PUBLIC_KEY } from "./receipt-fixture.js";
import type { LlmProxyConfig } from "../src/types.js";

test("TypeScript verifies the Rust-generated action receipt and rejects changed request material", async () => {
  const { request, response } = JSON.parse(readFileSync(new URL(
    "../../../../crates/exo-node/fixtures/lynk/rust_action_receipt_v1.json", import.meta.url), "utf8"));
  const config = { trustedValidatorDid: TEST_VALIDATOR_DID,
    trustedValidatorPublicKey: TEST_VALIDATOR_PUBLIC_KEY } as LlmProxyConfig;
  const input = { request, receipt: response.receipt, validation: response.validation,
    receiptHash: response.receipt_hash, finalityHash: response.exochain_finality_hash,
    finalityHeight: response.exochain_finality_height, finalityReceiptHash: response.exochain_finality_receipt_hash,
    validatorDid: TEST_VALIDATOR_DID };
  await verifyAvcActionResponseAttestation(config, input, response.action_response_attestation.signature.Ed25519);
  request.validation.action.tool = "substituted";
  await assert.rejects(verifyAvcActionResponseAttestation(config, input, response.action_response_attestation.signature.Ed25519));
});

test("new execution commitments sort Unicode keys in Rust UTF-8 order", () => {
  assert.equal(Buffer.from(encodeCanonicalCbor({ "\u{10000}": 2, "\ue000": 1 })).toString("hex"),
    "a263ee80800164f090808002");
});
