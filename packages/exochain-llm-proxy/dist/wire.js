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
import { LynkValidationError } from "./evidence.js";
const HASH256_HEX = /^[0-9a-f]{64}$/;
const ED25519_SIGNATURE_HEX = /^[0-9a-f]{128}$/;
const ZERO_HASH256_HEX = "0".repeat(64);
const MAX_ML_DSA_65_SIGNATURE_BYTES = 3309;
/**
 * Encode the stable, retryable LYNK receipt intent into the exact JSON shape
 * consumed by Rust's serde implementations. The logical intent intentionally
 * retains printable hex strings; only this transport copy uses byte arrays and
 * tagged signature variants.
 */
export function encodeReceiptIntentForWire(intent) {
    return {
        validation: encodeValidationRequest(intent.validation),
        subject_signature: encodeSignature(intent.subject_signature, "subject_signature"),
        ...(intent.subject_public_key === undefined
            ? {}
            : {
                subject_public_key: decodeFixedHex(intent.subject_public_key, 32, "subject_public_key", true),
            }),
        llm_usage_evidence: encodeEvidenceEnvelope(intent.llm_usage_evidence),
        adapter_signature: encodeSignature(intent.adapter_signature, "adapter_signature"),
        ...(intent.adapter_public_key === undefined
            ? {}
            : {
                adapter_public_key: decodeFixedHex(intent.adapter_public_key, 32, "adapter_public_key", true),
            }),
    };
}
function encodeEvidenceEnvelope(envelope) {
    const evidence = envelope.evidence;
    return {
        schema_version: envelope.schema_version,
        adapter_did: envelope.adapter_did,
        issued_at: { ...envelope.issued_at },
        evidence: {
            schema_version: evidence.schema_version,
            tenant_id: evidence.tenant_id,
            namespace: evidence.namespace,
            actor_did: evidence.actor_did,
            provider: evidence.provider,
            provider_endpoint: evidence.provider_endpoint,
            model_id: evidence.model_id,
            ...encodeOptionalHash("provider_request_id_hash", evidence.provider_request_id_hash),
            ...encodeOptionalHash("session_id_hash", evidence.session_id_hash),
            idempotency_key_hash: encodeHash(evidence.idempotency_key_hash, "llm_usage_evidence.evidence.idempotency_key_hash"),
            action_id: encodeHash(evidence.action_id, "llm_usage_evidence.evidence.action_id"),
            prompt_hash: encodeHash(evidence.prompt_hash, "llm_usage_evidence.evidence.prompt_hash"),
            ...encodeOptionalHash("completion_hash", evidence.completion_hash),
            ...encodeOptionalHash("tool_call_hash", evidence.tool_call_hash),
            ...encodeOptionalHash("tool_result_hash", evidence.tool_result_hash),
            usage: { ...evidence.usage },
            custody_mode: evidence.custody_mode,
            ...(evidence.encrypted_payload_refs.length === 0
                ? {}
                : {
                    encrypted_payload_refs: evidence.encrypted_payload_refs.map((reference, index) => ({
                        ref_id_hash: encodeHash(reference.ref_id_hash, `llm_usage_evidence.evidence.encrypted_payload_refs[${index}].ref_id_hash`),
                        ciphertext_hash: encodeHash(reference.ciphertext_hash, `llm_usage_evidence.evidence.encrypted_payload_refs[${index}].ciphertext_hash`),
                        storage_policy_hash: encodeHash(reference.storage_policy_hash, `llm_usage_evidence.evidence.encrypted_payload_refs[${index}].storage_policy_hash`),
                        key_policy_hash: encodeHash(reference.key_policy_hash, `llm_usage_evidence.evidence.encrypted_payload_refs[${index}].key_policy_hash`),
                        payload_kind: reference.payload_kind,
                        byte_length: reference.byte_length,
                    })),
                }),
            custody_policy_hash: encodeHash(evidence.custody_policy_hash, "llm_usage_evidence.evidence.custody_policy_hash"),
            created_at: { ...evidence.created_at },
        },
    };
}
function encodeOptionalHash(name, value) {
    if (value === undefined) {
        return {};
    }
    return {
        [name]: encodeHash(value, `llm_usage_evidence.evidence.${name}`),
    };
}
function encodeValidationRequest(value) {
    if (!isRecord(value)) {
        return value;
    }
    const encoded = { ...value };
    if (isRecord(value.credential)) {
        encoded.credential = encodeCredential(value.credential);
    }
    if (isRecord(value.action)) {
        encoded.action = encodeAction(value.action);
    }
    return encoded;
}
function encodeCredential(value) {
    const encoded = { ...value };
    if (isRecord(value.delegated_intent)) {
        encoded.delegated_intent = encodeHashField(value.delegated_intent, "intent_id", "validation.credential.delegated_intent.intent_id");
    }
    if (isRecord(value.authority_chain)) {
        encoded.authority_chain = encodeHashField(value.authority_chain, "chain_hash", "validation.credential.authority_chain.chain_hash");
    }
    if (Array.isArray(value.consent_refs)) {
        encoded.consent_refs = value.consent_refs.map((entry, index) => isRecord(entry)
            ? encodeHashField(entry, "consent_id", `validation.credential.consent_refs[${index}].consent_id`)
            : entry);
    }
    if (Array.isArray(value.policy_refs)) {
        encoded.policy_refs = value.policy_refs.map((entry, index) => isRecord(entry)
            ? encodeHashField(entry, "policy_id", `validation.credential.policy_refs[${index}].policy_id`)
            : entry);
    }
    if (typeof value.parent_avc_id === "string") {
        encoded.parent_avc_id = encodeHash(value.parent_avc_id, "validation.credential.parent_avc_id");
    }
    else if (Array.isArray(value.parent_avc_id)) {
        encoded.parent_avc_id = requireByteArray(value.parent_avc_id, 32, 32, "validation.credential.parent_avc_id", true);
    }
    if (value.signature !== undefined) {
        encoded.signature = encodeSignature(value.signature, "validation.credential.signature");
    }
    return encoded;
}
function encodeAction(value) {
    let encoded = encodeHashField(value, "action_id", "validation.action.action_id");
    if (isRecord(value.human_approval)) {
        const approval = { ...value.human_approval };
        if (approval.signature !== undefined) {
            approval.signature = encodeSignature(approval.signature, "validation.action.human_approval.signature");
        }
        encoded = { ...encoded, human_approval: approval };
    }
    return encoded;
}
function encodeHashField(value, field, path) {
    const fieldValue = value[field];
    if (typeof fieldValue === "string") {
        return { ...value, [field]: encodeHash(fieldValue, path) };
    }
    if (Array.isArray(fieldValue)) {
        return {
            ...value,
            [field]: requireByteArray(fieldValue, 32, 32, path, true),
        };
    }
    return { ...value };
}
function encodeHash(value, path) {
    if (!HASH256_HEX.test(value) || value === ZERO_HASH256_HEX) {
        throw new LynkValidationError(`${path} must be a canonical nonzero Hash256 hex string`);
    }
    return decodeFixedHex(value, 32, path, true);
}
function encodeSignature(value, path) {
    if (typeof value === "string") {
        if (!ED25519_SIGNATURE_HEX.test(value)) {
            throw new LynkValidationError(`${path} must be a canonical 64-byte Ed25519 signature hex string`);
        }
        const bytes = decodeFixedHex(value, 64, path, true);
        return { Ed25519: bytes };
    }
    if (!isRecord(value) || Object.keys(value).length !== 1) {
        throw new LynkValidationError(`${path} must contain exactly one supported signature variant`);
    }
    if (Object.prototype.hasOwnProperty.call(value, "Ed25519")) {
        return { Ed25519: requireByteArray(value.Ed25519, 64, 64, `${path}.Ed25519`, true) };
    }
    if (Object.prototype.hasOwnProperty.call(value, "PostQuantum")) {
        return {
            PostQuantum: requireByteArray(value.PostQuantum, 1, MAX_ML_DSA_65_SIGNATURE_BYTES, `${path}.PostQuantum`, false),
        };
    }
    if (Object.prototype.hasOwnProperty.call(value, "Hybrid")) {
        const hybrid = value.Hybrid;
        if (!isRecord(hybrid) || Object.keys(hybrid).length !== 2) {
            throw new LynkValidationError(`${path}.Hybrid must contain classical and pq byte arrays`);
        }
        return {
            Hybrid: {
                classical: requireByteArray(hybrid.classical, 64, 64, `${path}.Hybrid.classical`, true),
                pq: requireByteArray(hybrid.pq, 1, MAX_ML_DSA_65_SIGNATURE_BYTES, `${path}.Hybrid.pq`, false),
            },
        };
    }
    throw new LynkValidationError(`${path} uses an unsupported signature variant`);
}
function decodeFixedHex(value, expectedBytes, path, rejectAllZero) {
    const expectedCharacters = expectedBytes * 2;
    const pattern = expectedBytes === 32 ? HASH256_HEX : ED25519_SIGNATURE_HEX;
    if (value.length !== expectedCharacters || !pattern.test(value)) {
        throw new LynkValidationError(`${path} must be ${expectedCharacters} lowercase hex characters`);
    }
    const bytes = Array.from({ length: expectedBytes }, (_unused, index) => Number.parseInt(value.slice(index * 2, (index * 2) + 2), 16));
    if (rejectAllZero && bytes.every((byte) => byte === 0)) {
        throw new LynkValidationError(`${path} must not be all zero`);
    }
    return bytes;
}
function requireByteArray(value, minimumLength, maximumLength, path, rejectAllZero) {
    if (!Array.isArray(value)
        || value.length < minimumLength
        || value.length > maximumLength
        || !value.every((byte) => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255)) {
        throw new LynkValidationError(`${path} must contain ${minimumLength === maximumLength ? minimumLength : `${minimumLength}-${maximumLength}`} bytes`);
    }
    if (rejectAllZero && value.every((byte) => byte === 0)) {
        throw new LynkValidationError(`${path} must not be all zero`);
    }
    return [...value];
}
function isRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
//# sourceMappingURL=wire.js.map