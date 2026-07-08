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
import { emitUsageReceipt, receiptPendingFromError, ReceiptEmissionError, } from "./receipt.js";
export async function releaseWithReceipt(config, receiptIntent, output) {
    try {
        const receipt = await emitUsageReceipt(config, receiptIntent);
        const success = {
            status: "receipted",
            output,
            receipt,
            receiptIntent,
        };
        return success;
    }
    catch (error) {
        if (!(error instanceof ReceiptEmissionError)) {
            throw error;
        }
        const pending = receiptPendingFromError(error);
        if (config.mode === "development" && config.allowUnreceiptedOutputForDevelopment === true) {
            return {
                status: "development_unreceipted",
                output,
                receiptPending: pending,
            };
        }
        return pending;
    }
}
//# sourceMappingURL=delivery.js.map