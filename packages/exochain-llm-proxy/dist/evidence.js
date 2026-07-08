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
import { createHash } from "node:crypto";
export const AVC_SCHEMA_VERSION = 1;
export const ZERO_HASH = "0".repeat(64);
export const LYNK_EVIDENCE_DOMAIN = "exo.avc.lynk.llm_usage.evidence.v1";
export class LynkConfigurationError extends Error {
    constructor(message) {
        super(message);
        this.name = "LynkConfigurationError";
    }
}
export class LynkValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = "LynkValidationError";
    }
}
export function stableStringify(value) {
    if (value === null) {
        return "null";
    }
    if (typeof value === "string") {
        return JSON.stringify(value);
    }
    if (typeof value === "number") {
        if (!Number.isSafeInteger(value)) {
            throw new LynkValidationError("LYNK numeric values must be safe integers");
        }
        return String(value);
    }
    if (typeof value === "boolean") {
        return value ? "true" : "false";
    }
    if (Array.isArray(value)) {
        return `[${value.map((entry) => stableStringify(entry)).join(",")}]`;
    }
    if (typeof value === "object") {
        const record = value;
        const keys = Object.keys(record)
            .filter((key) => record[key] !== undefined)
            .sort();
        return `{${keys
            .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
            .join(",")}}`;
    }
    throw new LynkValidationError(`unsupported value type in canonical JSON: ${typeof value}`);
}
export function hashProviderPayload(payload) {
    return createHash("sha256").update(stableStringify(payload)).digest("hex");
}
export function hashBytes(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}
export function textBytes(value) {
    return new TextEncoder().encode(value);
}
export function assertUsageMetrics(usage) {
    for (const [name, value] of Object.entries(usage)) {
        if (typeof value === "number") {
            assertNonNegativeSafeInteger(name, value);
        }
    }
    if (usage.total_tokens < usage.input_tokens + usage.output_tokens) {
        throw new LynkValidationError("LYNK usage total_tokens must be at least input_tokens plus output_tokens");
    }
    if (usage.cached_input_tokens !== undefined && usage.cached_input_tokens > usage.input_tokens) {
        throw new LynkValidationError("LYNK cached_input_tokens must not exceed input_tokens");
    }
    if (usage.reasoning_tokens !== undefined && usage.reasoning_tokens > usage.output_tokens) {
        throw new LynkValidationError("LYNK reasoning_tokens must not exceed output_tokens");
    }
}
function assertNonNegativeSafeInteger(name, value) {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new LynkValidationError(`LYNK usage field ${name} must be a non-negative safe integer`);
    }
}
export function buildLlmUsageEvidence(config, context) {
    assertRequiredConfig(config);
    assertUsageMetrics(context.usage);
    const encryptedPayloadRefs = context.encryptedPayloadRefs ?? [];
    if (config.storageMode === "receipt_minimized" && encryptedPayloadRefs.length !== 0) {
        throw new LynkValidationError("receipt_minimized LYNK evidence must not include encrypted payload refs");
    }
    if (config.storageMode === "external_payload_ref" && encryptedPayloadRefs.length === 0) {
        throw new LynkValidationError("external_payload_ref LYNK evidence requires encrypted payload refs");
    }
    if (config.storageMode === "dagdb_custody" && config.custodyPolicyHash === ZERO_HASH) {
        throw new LynkValidationError("dagdb_custody LYNK evidence requires a custody policy hash");
    }
    return {
        schema_version: AVC_SCHEMA_VERSION,
        tenant_id: config.tenantId,
        namespace: config.namespace,
        actor_did: config.actorDid,
        provider: context.provider,
        provider_endpoint: context.providerEndpoint,
        model_id: context.modelId,
        provider_request_id_hash: context.providerRequestId
            ? hashProviderPayload(context.providerRequestId)
            : undefined,
        session_id_hash: context.sessionId ? hashProviderPayload(context.sessionId) : undefined,
        idempotency_key_hash: hashProviderPayload(context.idempotencyKey),
        action_id: context.actionId ?? hashProviderPayload(["lynk-action", context.idempotencyKey]),
        prompt_hash: hashProviderPayload(context.requestPayload),
        completion_hash: context.responsePayload === undefined ? undefined : hashProviderPayload(context.responsePayload),
        tool_call_hash: context.toolCallPayload === undefined ? undefined : hashProviderPayload(context.toolCallPayload),
        tool_result_hash: context.toolResultPayload === undefined
            ? undefined
            : hashProviderPayload(context.toolResultPayload),
        usage: context.usage,
        custody_mode: config.storageMode,
        encrypted_payload_refs: encryptedPayloadRefs,
        custody_policy_hash: config.custodyPolicyHash,
        created_at: context.createdAt,
    };
}
export async function buildLlmUsageReceiptIntent(config, context) {
    const evidence = buildLlmUsageEvidence(config, context);
    const envelope = {
        schema_version: AVC_SCHEMA_VERSION,
        adapter_did: config.adapterDid,
        issued_at: context.issuedAt,
        evidence,
    };
    const adapterSignature = typeof config.adapterSignature === "function"
        ? await config.adapterSignature(envelope)
        : config.adapterSignature;
    return {
        validation: config.validation,
        subject_signature: config.subjectSignature,
        subject_public_key: config.subjectPublicKey,
        llm_usage_evidence: envelope,
        adapter_signature: adapterSignature,
        adapter_public_key: config.adapterPublicKey,
    };
}
export async function maybeStoreExternalPayloads(config, payloads) {
    if (config.storageMode !== "external_payload_ref") {
        return [];
    }
    if (!config.kms || !config.objectStore) {
        throw new LynkConfigurationError("external_payload_ref requires both a customer KMS and object store");
    }
    const refs = [];
    for (const entry of payloads) {
        const plaintext = textBytes(stableStringify(entry.payload));
        const encrypted = await config.kms.encrypt({
            payload: plaintext,
            payloadKind: entry.payloadKind,
        });
        const ciphertext = typeof encrypted.ciphertext === "string"
            ? textBytes(encrypted.ciphertext)
            : encrypted.ciphertext;
        const stored = await config.objectStore.put({
            payloadKind: entry.payloadKind,
            ciphertext,
        });
        refs.push({
            ref_id_hash: hashProviderPayload(stored.refId),
            ciphertext_hash: hashBytes(ciphertext),
            storage_policy_hash: hashProviderPayload(stored.storagePolicyId),
            key_policy_hash: hashProviderPayload(encrypted.keyPolicyId),
            payload_kind: entry.payloadKind,
            byte_length: ciphertext.byteLength,
        });
    }
    return refs;
}
export function assertNoForbiddenReceiptMaterial(value) {
    const serialized = stableStringify(value);
    for (const forbidden of [
        "raw_prompt",
        "raw_output",
        "response_text",
        "provider_api_key",
        "bearer_token",
        "kms_key",
        "object_uri",
    ]) {
        if (serialized.includes(forbidden)) {
            throw new LynkValidationError(`receipt material contains forbidden key ${forbidden}`);
        }
    }
}
function assertRequiredConfig(config) {
    for (const [name, value] of [
        ["gatewayUrl", config.gatewayUrl],
        ["tenantId", config.tenantId],
        ["namespace", config.namespace],
        ["actorDid", config.actorDid],
        ["adapterDid", config.adapterDid],
        ["custodyPolicyHash", config.custodyPolicyHash],
        ["subjectSignature", config.subjectSignature],
    ]) {
        if (typeof value !== "string" || value.trim() === "") {
            throw new LynkConfigurationError(`LYNK config requires ${name}`);
        }
    }
    if (!["receipt_minimized", "external_payload_ref", "dagdb_custody"].includes(config.storageMode)) {
        throw new LynkConfigurationError("LYNK config requires an explicit supported storageMode");
    }
}
//# sourceMappingURL=evidence.js.map