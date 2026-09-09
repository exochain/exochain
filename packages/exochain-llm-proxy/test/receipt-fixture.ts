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

import { readFileSync } from "node:fs";
import { createPrivateKey, sign } from "node:crypto";
import type { ReceiptEmissionResult, ReceiptIntent } from "../src/index.js";
import {
  LYNK_RECEIPT_RESPONSE_ATTESTATION_DOMAIN,
  LYNK_RECEIPT_RESPONSE_ATTESTATION_SCHEMA_VERSION,
  encodeLynkReceiptResponseAttestationPayload,
} from "../src/attestation.js";
import {
  encodeReceiptIntentForWire,
  type ReceiptEmitWireRequest,
} from "../src/wire.js";

export const TEST_VALIDATOR_DID = "did:exo:validator";
export const TEST_VALIDATOR_PUBLIC_KEY =
  "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce";

const TEST_VALIDATOR_PRIVATE_KEY = createPrivateKey({
  key: Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, 0x33),
  ]),
  format: "der",
  type: "pkcs8",
});

const responseFixtureUrl = new URL(
  "../../../../crates/exo-node/fixtures/lynk/rust_receipt_emit_response_v1.json",
  import.meta.url,
);

function hashBytes(hash: string | number[]): number[] {
  if (Array.isArray(hash)) {
    return [...hash];
  }
  return Array.from({ length: 32 }, (_unused, index) =>
    Number.parseInt(hash.slice(index * 2, (index * 2) + 2), 16),
  );
}

export function committedReceiptResponse(
  receiptIntent: ReceiptIntent,
  mutateBeforeAttestation?: (response: Record<string, unknown>) => void,
): ReceiptEmissionResult {
  const evidence = receiptIntent.llm_usage_evidence.evidence;
  const actionId = evidence.action_id as string | number[];
  const response = JSON.parse(readFileSync(responseFixtureUrl, "utf8")) as Record<string, unknown>;
  const receipt = response.receipt as Record<string, unknown>;
  const descriptor = receipt.action_descriptor as Record<string, unknown>;
  const validation = response.validation as Record<string, unknown>;
  receipt.action_id = hashBytes(actionId);
  descriptor.action_id = hashBytes(actionId);
  descriptor.actor_did = evidence.actor_did;
  descriptor.data_class = {
    receipt_minimized: "Internal",
    external_payload_ref: "Confidential",
    dagdb_custody: "Restricted",
  }[evidence.custody_mode];
  descriptor.estimated_budget_minor_units = evidence.usage.cost_minor_units ?? null;
  validation.normalized_holder_did = evidence.actor_did;
  mutateBeforeAttestation?.(response);
  const wireRequest = Array.isArray(evidence.action_id)
    ? receiptIntent as unknown as ReceiptEmitWireRequest
    : encodeReceiptIntentForWire(receiptIntent);
  const payload = encodeLynkReceiptResponseAttestationPayload({
    receiptHash: response.receipt_hash as string,
    finalityHash: response.exochain_finality_hash as string,
    finalityHeight: response.exochain_finality_height as number,
    finalityReceiptHash: response.exochain_finality_receipt_hash as string,
    receipt,
    validation,
    request: wireRequest,
    validatorDid: TEST_VALIDATOR_DID,
  });
  const signature = sign(null, Buffer.from(payload), TEST_VALIDATOR_PRIVATE_KEY);
  response.lynk_response_attestation = {
    domain: LYNK_RECEIPT_RESPONSE_ATTESTATION_DOMAIN,
    schema_version: LYNK_RECEIPT_RESPONSE_ATTESTATION_SCHEMA_VERSION,
    validator_did: TEST_VALIDATOR_DID,
    signature: { Ed25519: [...signature] },
  };
  return response as unknown as ReceiptEmissionResult;
}
