import { LynkValidationError } from "./evidence.js";
import type { LlmProxyConfig, McpProxyOptions, McpToolCall, PerCallReceiptOptions, ReceiptedResult } from "./types.js";
export declare function isGovernedMcpProxy(value: unknown): value is ReceiptedMcpProxy;
export interface ReceiptedMcpProxy {
    callTool(call: McpToolCall, options: PerCallReceiptOptions): Promise<ReceiptedResult<unknown>>;
}
/** Raised only before a tool was dispatched. Later failures may have external effects. */
export declare class McpAuthorizationError extends LynkValidationError {
    constructor();
}
export declare function createReceiptedMcpProxy(config: LlmProxyConfig, mcp: McpProxyOptions): ReceiptedMcpProxy;
//# sourceMappingURL=mcp.d.ts.map