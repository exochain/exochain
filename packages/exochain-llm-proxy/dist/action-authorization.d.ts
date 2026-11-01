import type { HlcTimestamp, LlmProxyConfig, McpAuthorization, PerCallReceiptOptions } from "./types.js";
/** New protocol commitments use canonical CBOR, never serialized JSON text. */
export declare function executionHash(value: unknown): string;
export declare function requireHlc(value: HlcTimestamp): HlcTimestamp;
export declare function checkCancellation(signal?: AbortSignal): void;
export declare function snapshotJson(value: unknown): unknown;
export declare function authorizeMcpExecution(config: LlmProxyConfig, authorization: McpAuthorization, serverUrl: string, payload: {
    params: {
        name: string;
        arguments: unknown;
    };
}, options: PerCallReceiptOptions): Promise<void>;
//# sourceMappingURL=action-authorization.d.ts.map