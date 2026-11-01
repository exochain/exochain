// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0
import { assertNoForbiddenReceiptMaterial, hashBytes, LynkValidationError } from "./evidence.js";
import { AVC_ACTION_RESPONSE_ATTESTATION_DOMAIN, encodeCanonicalCbor, verifyAvcActionResponseAttestation } from "./attestation.js";
import { fetchBoundedResponse, parseBoundedJson, withRequestDeadline } from "./http.js";
import { encodeAvcActionReceiptForWire } from "./wire.js";
/** New protocol commitments use canonical CBOR, never serialized JSON text. */
export function executionHash(value) {
    return hashBytes(encodeCanonicalCbor(value));
}
export function requireHlc(value) {
    if (!value || !Number.isSafeInteger(value.physical_ms) || value.physical_ms <= 0
        || !Number.isSafeInteger(value.logical) || value.logical < 0) {
        throw new LynkValidationError("execution requires a valid nonzero HLC timestamp");
    }
    return { physical_ms: value.physical_ms, logical: value.logical };
}
export function checkCancellation(signal) {
    if (signal?.aborted)
        throw new LynkValidationError("execution cancelled by host");
}
export function snapshotJson(value) {
    const serialized = JSON.stringify(value);
    if (typeof serialized !== "string" || new TextEncoder().encode(serialized).length > 65536) {
        throw new LynkValidationError("execution input must be JSON no larger than 65536 bytes");
    }
    const snapshot = JSON.parse(serialized);
    // Also rejects floats, invalid Unicode and unsupported canonical values.
    encodeCanonicalCbor(snapshot);
    return snapshot;
}
function record(value) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new LynkValidationError("action authorization contains a malformed object");
    }
    return value;
}
function hash(value) {
    if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value) || /^0+$/.test(value)) {
        throw new LynkValidationError("action authorization contains a malformed commitment");
    }
    return value;
}
export async function authorizeMcpExecution(config, authorization, serverUrl, payload, options) {
    checkCancellation(options.signal);
    const now = requireHlc(authorization.now());
    const maxAgeMs = authorization.maxAgeMs ?? 5000;
    if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1 || maxAgeMs > 30000) {
        throw new LynkValidationError("authorization maxAgeMs must be an integer from 1 through 30000");
    }
    const scope = {
        tenant_id: config.tenantId, namespace: config.namespace, actor_did: config.actorDid,
        idempotency_key: options.idempotencyKey,
    };
    const serverUrlHash = executionHash(serverUrl);
    const argumentsHash = executionHash(payload.params.arguments);
    const actionId = executionHash({ domain: "exo.lynk.mcp.execution.v1", ...scope,
        server_url_hash: serverUrlHash, tool: payload.params.name, arguments_hash: argumentsHash });
    const prepared = await withRequestDeadline(config, options.signal, "MCP authority signer", async () => authorization.prepare(Object.freeze({ actionId, actorDid: config.actorDid,
        tool: payload.params.name, serverUrlHash, argumentsHash, serverUrl,
        arguments: structuredClone(payload.params.arguments), now: Object.freeze({ ...now }) })));
    checkCancellation(options.signal);
    const request = record(snapshotJson(encodeAvcActionReceiptForWire(prepared)));
    const validation = record(request.validation);
    const action = record(validation.action);
    if (executionHash(action.action_id) !== executionHash([...Buffer.from(actionId, "hex")])
        || action.actor_did !== config.actorDid || action.tool !== payload.params.name
        || action.requested_permission !== "Execute"
        || action.action_name !== (authorization.actionName ?? "mcp.tools.call")
        || executionHash(validation.now) !== executionHash(now)) {
        throw new LynkValidationError("signed action does not bind the exact MCP execution intent");
    }
    assertNoForbiddenReceiptMaterial(request);
    // Claim before contacting core: uncertain attempts remain unavailable for replay.
    const journalKey = executionHash({ domain: "exo.lynk.execution.claim.v1", ...scope });
    if (!await withRequestDeadline(config, options.signal, "MCP execution journal", () => authorization.journal.claim(journalKey))) {
        throw new LynkValidationError("execution key already claimed; reconcile instead of replaying");
    }
    checkCancellation(options.signal);
    const bounded = await fetchBoundedResponse(config, `${config.gatewayUrl.replace(/\/+$/, "")}/api/v1/avc/receipts/emit`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(request), redirect: "error", signal: options.signal,
    }, "EXOCHAIN action authorization");
    if (!bounded.response.ok)
        throw new LynkValidationError("EXOCHAIN action authorization denied");
    const response = record(parseBoundedJson(bounded, "EXOCHAIN action authorization"));
    const receipt = record(response.receipt);
    const decision = record(response.validation);
    const attestation = record(response.action_response_attestation);
    const receiptHash = hash(response.receipt_hash);
    const finalityHash = hash(response.exochain_finality_hash);
    const finalityReceiptHash = hash(response.exochain_finality_receipt_hash);
    if (receiptHash === finalityHash || receiptHash === finalityReceiptHash || finalityHash === finalityReceiptHash
        || !Number.isSafeInteger(response.exochain_finality_height) || Number(response.exochain_finality_height) <= 0
        || receipt.decision !== "Allow" || decision.decision !== "Allow"
        || executionHash(decision.reason_codes) !== executionHash(["Valid"])
        || decision.normalized_holder_did !== config.actorDid
        || receipt.validator_did !== config.trustedValidatorDid
        || executionHash(receipt.action_id) !== executionHash(action.action_id)
        || attestation.domain !== AVC_ACTION_RESPONSE_ATTESTATION_DOMAIN || attestation.schema_version !== 1) {
        throw new LynkValidationError("EXOCHAIN action authorization is not a bound finalized Allow");
    }
    const signature = record(attestation.signature).Ed25519;
    if (!Array.isArray(signature))
        throw new LynkValidationError("action authorization requires Ed25519 attestation");
    await verifyAvcActionResponseAttestation(config, {
        receiptHash, finalityHash, finalityHeight: Number(response.exochain_finality_height),
        finalityReceiptHash, receipt, validation: decision, request,
        validatorDid: String(attestation.validator_did),
    }, signature);
    const dispatchTime = requireHlc(authorization.now());
    const issued = requireHlc(receipt.created_at);
    if (compareHlc(dispatchTime, now) < 0 || compareHlc(dispatchTime, issued) < 0
        || dispatchTime.physical_ms - now.physical_ms > maxAgeMs
        || dispatchTime.physical_ms - issued.physical_ms > maxAgeMs
        || (decision.valid_until !== null && compareHlc(dispatchTime, requireHlc(decision.valid_until)) >= 0)) {
        throw new LynkValidationError("action authorization expired or HLC moved backwards");
    }
    checkCancellation(options.signal);
}
function compareHlc(left, right) {
    return left.physical_ms - right.physical_ms || left.logical - right.logical;
}
//# sourceMappingURL=action-authorization.js.map