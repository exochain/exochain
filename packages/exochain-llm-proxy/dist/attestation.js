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
export const LYNK_RECEIPT_RESPONSE_ATTESTATION_DOMAIN = "exo.avc.lynk.receipt_response.attestation.v1";
export const LYNK_RECEIPT_RESPONSE_ATTESTATION_SCHEMA_VERSION = 1;
const ED25519 = { name: "Ed25519" };
const PUBLIC_KEY_HEX = /^[0-9a-f]{64}$/;
export function assertJsonUnicodeScalars(value) {
    if (value === null || typeof value === "boolean" || typeof value === "number") {
        return;
    }
    if (typeof value === "string") {
        assertUnicodeScalarString(value);
        return;
    }
    if (Array.isArray(value)) {
        for (const entry of value) {
            assertJsonUnicodeScalars(entry);
        }
        return;
    }
    if (typeof value === "object") {
        const record = value;
        for (const key of Object.keys(record)) {
            assertUnicodeScalarString(key);
            assertJsonUnicodeScalars(record[key]);
        }
        return;
    }
    throw new Error("LYNK JSON contains an unsupported value type");
}
function assertUnicodeScalarString(value) {
    for (let index = 0; index < value.length; index += 1) {
        const codeUnit = value.charCodeAt(index);
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const low = value.charCodeAt(index + 1);
            if (!(low >= 0xdc00 && low <= 0xdfff)) {
                throw new Error("LYNK JSON contains an unpaired UTF-16 surrogate");
            }
            index += 1;
        }
        else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            throw new Error("LYNK JSON contains an unpaired UTF-16 surrogate");
        }
    }
}
/**
 * Encode the exact signed LYNK response-attestation payload.
 *
 * Rust converts the same JSON value into recursively key-sorted
 * `ciborium::value::Value` maps before serialization. All object keys in this
 * schema are ASCII, so JavaScript lexical order and Rust UTF-8 byte order are
 * identical. Integers use CBOR's shortest-width representation.
 */
export function encodeLynkReceiptResponseAttestationPayload(input) {
    return encodeCanonicalCbor({
        decision: "Allow",
        domain: LYNK_RECEIPT_RESPONSE_ATTESTATION_DOMAIN,
        exochain_finality: {
            hash: input.finalityHash,
            height: input.finalityHeight,
            receipt_hash: input.finalityReceiptHash,
        },
        receipt_request: jsonTransportCopy(input.request),
        receipt: input.receipt,
        receipt_hash: input.receiptHash,
        schema_version: LYNK_RECEIPT_RESPONSE_ATTESTATION_SCHEMA_VERSION,
        validation: input.validation,
        validator_did: input.validatorDid,
    });
}
function jsonTransportCopy(value) {
    if (value === null || typeof value === "string" || typeof value === "boolean") {
        return value;
    }
    if (typeof value === "number") {
        if (!Number.isSafeInteger(value)) {
            throw new Error("LYNK response attestation accepts safe integers only");
        }
        return value;
    }
    if (Array.isArray(value)) {
        return value.map((entry) => {
            if (entry === undefined) {
                throw new Error("LYNK response attestation arrays must not contain undefined entries");
            }
            return jsonTransportCopy(entry);
        });
    }
    if (typeof value === "object") {
        // A null-prototype target preserves an own JSON key named `__proto__`.
        // Assigning that key on `{}` would invoke the legacy prototype setter and
        // silently change the signed request value.
        const copied = Object.create(null);
        for (const key of Object.keys(value)) {
            const entry = value[key];
            if (entry !== undefined) {
                copied[key] = jsonTransportCopy(entry);
            }
        }
        return copied;
    }
    throw new Error(`unsupported LYNK response attestation value type: ${typeof value}`);
}
export async function verifyLynkReceiptResponseAttestation(config, input, signature) {
    const trustedDid = config.trustedValidatorDid;
    const trustedPublicKey = config.trustedValidatorPublicKey;
    if (typeof trustedDid !== "string" || !/^did:[a-z0-9]+:[^\s]+$/.test(trustedDid)) {
        throw new Error("LYNK receipt verification requires trustedValidatorDid");
    }
    if (input.validatorDid !== trustedDid) {
        throw new Error("LYNK receipt validator DID does not match the configured trust root");
    }
    if (typeof trustedPublicKey !== "string"
        || !PUBLIC_KEY_HEX.test(trustedPublicKey)
        || /^0+$/.test(trustedPublicKey)) {
        throw new Error("LYNK receipt verification requires a canonical nonzero trustedValidatorPublicKey");
    }
    if (signature.length !== 64
        || !signature.every((byte) => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255)
        || signature.every((byte) => byte === 0)) {
        throw new Error("LYNK response attestation signature is malformed");
    }
    const subtle = globalThis.crypto?.subtle;
    if (subtle === undefined) {
        throw new Error("Web Crypto API is unavailable for LYNK receipt verification");
    }
    const publicKeyBytes = decodeHex(trustedPublicKey);
    let publicKey;
    try {
        publicKey = await subtle.importKey("raw", publicKeyBytes, ED25519, false, ["verify"]);
    }
    catch {
        throw new Error("trustedValidatorPublicKey is not a valid Ed25519 public key");
    }
    const payload = encodeLynkReceiptResponseAttestationPayload(input);
    let verified;
    try {
        verified = await subtle.verify(ED25519, publicKey, Uint8Array.from(signature), payload);
    }
    catch {
        throw new Error("LYNK response attestation verification failed");
    }
    if (!verified) {
        throw new Error("LYNK response attestation signature is invalid");
    }
}
function encodeCanonicalCbor(value) {
    const output = [];
    appendCanonicalCbor(value, output);
    return Uint8Array.from(output);
}
function appendCanonicalCbor(value, output) {
    if (value === null) {
        output.push(0xf6);
        return;
    }
    if (typeof value === "boolean") {
        output.push(value ? 0xf5 : 0xf4);
        return;
    }
    if (typeof value === "number") {
        if (!Number.isSafeInteger(value)) {
            throw new Error("LYNK response attestation accepts safe integers only");
        }
        if (value >= 0) {
            appendTypeAndLength(0, value, output);
        }
        else {
            appendTypeAndLength(1, -1 - value, output);
        }
        return;
    }
    if (typeof value === "string") {
        assertUnicodeScalarString(value);
        const bytes = new TextEncoder().encode(value);
        appendTypeAndLength(3, bytes.length, output);
        output.push(...bytes);
        return;
    }
    if (Array.isArray(value)) {
        appendTypeAndLength(4, value.length, output);
        for (const entry of value) {
            appendCanonicalCbor(entry, output);
        }
        return;
    }
    if (typeof value === "object") {
        const record = value;
        const keys = Object.keys(record).sort();
        appendTypeAndLength(5, keys.length, output);
        for (const key of keys) {
            assertUnicodeScalarString(key);
            const entry = record[key];
            if (entry === undefined) {
                throw new Error(`LYNK response attestation field ${key} is undefined`);
            }
            appendCanonicalCbor(key, output);
            appendCanonicalCbor(entry, output);
        }
        return;
    }
    throw new Error(`unsupported LYNK response attestation value type: ${typeof value}`);
}
function appendTypeAndLength(majorType, value, output) {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error("CBOR length or integer is outside the safe integer range");
    }
    const prefix = majorType << 5;
    if (value <= 23) {
        output.push(prefix | value);
        return;
    }
    if (value <= 0xff) {
        output.push(prefix | 24, value);
        return;
    }
    if (value <= 0xffff) {
        output.push(prefix | 25, (value >>> 8) & 0xff, value & 0xff);
        return;
    }
    if (value <= 4294967295) {
        output.push(prefix | 26, Math.floor(value / 16777216) & 0xff, Math.floor(value / 65536) & 0xff, Math.floor(value / 0x100) & 0xff, value & 0xff);
        return;
    }
    const wide = BigInt(value);
    output.push(prefix | 27);
    for (let shift = 56n; shift >= 0n; shift -= 8n) {
        output.push(Number((wide >> shift) & 0xffn));
    }
}
function decodeHex(value) {
    return Uint8Array.from({ length: value.length / 2 }, (_unused, index) => Number.parseInt(value.slice(index * 2, (index * 2) + 2), 16));
}
//# sourceMappingURL=attestation.js.map