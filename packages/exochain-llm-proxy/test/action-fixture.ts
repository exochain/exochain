// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0
import { createPrivateKey, sign } from "node:crypto";
import { encodeAvcActionResponseAttestationPayload } from "../src/attestation.js";
import type { McpExecutionIntent, McpAuthorization } from "../src/types.js";
import { TEST_VALIDATOR_DID } from "./receipt-fixture.js";
const stamp = { physical_ms: 1_700_000, logical: 0 };
const privateKey = createPrivateKey({ key: Buffer.concat([
  Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 0x33),
]), format: "der", type: "pkcs8" });

export function actionResponse(request: any): any {
  const action = request.validation.action;
  const receipt = {
    action_id: action.action_id, decision: "Allow", validator_did: TEST_VALIDATOR_DID,
    created_at: stamp, credential_id: Array(32).fill(9),
    action_descriptor: { ...action },
  };
  const response: any = {
    receipt_hash: "a".repeat(64), exochain_finality_hash: "b".repeat(64),
    exochain_finality_height: 1, exochain_finality_receipt_hash: "c".repeat(64),
    receipt, validation: {
      decision: "Allow", normalized_holder_did: action.actor_did,
      reason_codes: ["Valid"], valid_until: { physical_ms: 1_800_000, logical: 0 },
    },
  };
  response.action_response_attestation = {
    domain: "exo.avc.action.receipt_response.attestation.v1", schema_version: 1,
    validator_did: TEST_VALIDATOR_DID,
    signature: { Ed25519: [...sign(null, encodeAvcActionResponseAttestationPayload({
      receiptHash: response.receipt_hash, finalityHash: response.exochain_finality_hash,
      finalityHeight: 1, finalityReceiptHash: response.exochain_finality_receipt_hash,
      receipt, validation: response.validation, request, validatorDid: TEST_VALIDATOR_DID,
    }), privateKey)] },
  };
  return response;
}

export function prepareAction(intent: McpExecutionIntent): any {
  return {
    validation: {
      credential: { fixture: "signed-credential-resolved-by-core" }, now: intent.now,
      action: { action_id: intent.actionId, actor_did: intent.actorDid,
        requested_permission: "Execute", tool: intent.tool, action_name: "mcp.tools.call",
        target_did: null, data_class: "Internal", estimated_budget_minor_units: 0,
        estimated_risk_bp: 0, human_approval: null, requires_human_approval: false },
    },
    subject_signature: "a".repeat(128),
  };
}


export function testAuthorization(): McpAuthorization {
  return { prepare: prepareAction, now: () => ({ ...stamp }), journal: { claim: async () => true } };
}
