import type { LlmProxyConfig, OpenAIProxyOptions, PerCallReceiptOptions, ProviderUsageMetrics, ReceiptedResult } from "./types.js";
type JsonRecord = Record<string, unknown>;
export interface ReceiptedOpenAIClient {
    responses: {
        create(body: JsonRecord, options: PerCallReceiptOptions): Promise<ReceiptedResult<unknown>>;
    };
    chat: {
        completions: {
            create(body: JsonRecord, options: PerCallReceiptOptions): Promise<ReceiptedResult<unknown>>;
        };
    };
}
export declare function createReceiptedOpenAIClient(config: LlmProxyConfig, openAI: OpenAIProxyOptions): ReceiptedOpenAIClient;
export declare function createReceiptedOpenAIProxy(config: LlmProxyConfig, openAI: OpenAIProxyOptions): ReceiptedOpenAIClient;
export declare function parseSseStream(text: string): JsonRecord;
export declare function usageFromResponses(payload: unknown): ProviderUsageMetrics;
export declare function usageFromChatCompletions(payload: unknown): ProviderUsageMetrics;
export {};
//# sourceMappingURL=openai.d.ts.map