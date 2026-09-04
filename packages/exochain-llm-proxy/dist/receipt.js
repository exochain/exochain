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
import { assertNoForbiddenReceiptMaterial } from "./evidence.js";
import { fetchBoundedResponse, parseBoundedJson } from "./http.js";
export { resolveFetch } from "./http.js";
export class ReceiptEmissionError extends Error {
    statusCode;
    idempotencyKeyHash;
    receiptIntent;
    constructor(message, idempotencyKeyHash, receiptIntent, statusCode) {
        super(message);
        this.name = "ReceiptEmissionError";
        this.statusCode = statusCode;
        this.idempotencyKeyHash = idempotencyKeyHash;
        this.receiptIntent = receiptIntent;
    }
}
export function receiptPendingFromError(error) {
    return {
        status: "receipt_pending",
        idempotencyKeyHash: error.idempotencyKeyHash,
        receiptIntent: error.receiptIntent,
    };
}
export async function emitUsageReceipt(config, receiptIntent) {
    assertNoForbiddenReceiptMaterial(receiptIntent);
    const endpoint = `${config.gatewayUrl.replace(/\/+$/, "")}/api/v1/avc/llm-usage/receipts/emit`;
    const bounded = await fetchBoundedResponse(config, endpoint, {
        method: "POST",
        headers: {
            "content-type": "application/json",
        },
        body: JSON.stringify(receiptIntent),
    }, "EXOCHAIN receipt response");
    const { response } = bounded;
    if (!response.ok) {
        throw new ReceiptEmissionError("EXOCHAIN LYNK receipt emission failed", receiptIntent.llm_usage_evidence.evidence.idempotency_key_hash, receiptIntent, response.status);
    }
    return parseBoundedJson(bounded, "EXOCHAIN receipt response");
}
export async function resolveReceiptPending(config, pending) {
    return emitUsageReceipt(config, pending.receiptIntent);
}
//# sourceMappingURL=receipt.js.map