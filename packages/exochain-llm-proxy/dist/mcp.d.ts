import type { LlmProxyConfig, McpProxyOptions, McpToolCall, PerCallReceiptOptions, ReceiptedResult } from "./types.js";
export interface ReceiptedMcpProxy {
    callTool(call: McpToolCall, options: PerCallReceiptOptions): Promise<ReceiptedResult<unknown>>;
}
export declare function createReceiptedMcpProxy(config: LlmProxyConfig, mcp: McpProxyOptions): ReceiptedMcpProxy;
//# sourceMappingURL=mcp.d.ts.map