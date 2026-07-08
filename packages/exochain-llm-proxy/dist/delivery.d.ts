import type { LlmProxyConfig, ReceiptIntent, ReceiptedResult } from "./types.js";
export declare function releaseWithReceipt<T>(config: LlmProxyConfig, receiptIntent: ReceiptIntent, output: T): Promise<ReceiptedResult<T>>;
//# sourceMappingURL=delivery.d.ts.map