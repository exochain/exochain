import type { LlmProxyConfig, ReceiptEmissionResult, ReceiptIntent, ReceiptPending } from "./types.js";
export { resolveFetch } from "./http.js";
export declare class ReceiptEmissionError extends Error {
    readonly statusCode?: number;
    readonly idempotencyKeyHash: string;
    readonly receiptIntent: ReceiptIntent;
    constructor(message: string, idempotencyKeyHash: string, receiptIntent: ReceiptIntent, statusCode?: number);
}
export declare function receiptPendingFromError(error: ReceiptEmissionError): ReceiptPending;
export declare function emitUsageReceipt(config: LlmProxyConfig, receiptIntent: ReceiptIntent): Promise<ReceiptEmissionResult>;
export declare function requireProductionValidatorTrust(config: LlmProxyConfig): void;
export declare function resolveReceiptPending(config: LlmProxyConfig, pending: ReceiptPending): Promise<ReceiptEmissionResult>;
//# sourceMappingURL=receipt.d.ts.map