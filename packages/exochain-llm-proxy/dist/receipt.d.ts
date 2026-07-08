import type { FetchLike, LlmProxyConfig, ReceiptEmissionResult, ReceiptIntent, ReceiptPending } from "./types.js";
export declare class ReceiptEmissionError extends Error {
    readonly statusCode?: number;
    readonly idempotencyKeyHash: string;
    readonly receiptIntent: ReceiptIntent;
    constructor(message: string, idempotencyKeyHash: string, receiptIntent: ReceiptIntent, statusCode?: number);
}
export declare function receiptPendingFromError(error: ReceiptEmissionError): ReceiptPending;
export declare function emitUsageReceipt(config: LlmProxyConfig, receiptIntent: ReceiptIntent): Promise<ReceiptEmissionResult>;
export declare function resolveReceiptPending(config: LlmProxyConfig, pending: ReceiptPending): Promise<ReceiptEmissionResult>;
export declare function resolveFetch(fetchImpl?: FetchLike): FetchLike;
//# sourceMappingURL=receipt.d.ts.map