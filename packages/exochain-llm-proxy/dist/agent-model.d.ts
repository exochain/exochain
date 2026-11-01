import type { LlmProxyConfig, OpenAIProxyOptions, PerCallReceiptOptions, ReceiptedResult } from "./types.js";
export interface LynkAgentModel {
    readonly id: string;
    readonly modelId: string;
    readonly actorDid: string;
    invoke(input: Record<string, unknown>, options: PerCallReceiptOptions): Promise<ReceiptedResult<unknown>>;
}
export declare function isLynkAgentModel(model: unknown): model is LynkAgentModel;
/** Live OpenAI Responses adapter; no canned reasoning or local receipt fabrication. */
export declare function createLynkAgentModel(options: {
    id: string;
    modelId: string;
    config: LlmProxyConfig;
    openAI: OpenAIProxyOptions;
    maxOutputTokens?: number;
}): LynkAgentModel;
export declare function readAgentModelJson(output: unknown): unknown;
//# sourceMappingURL=agent-model.d.ts.map