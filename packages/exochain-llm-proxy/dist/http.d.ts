import type { FetchLike, LlmProxyConfig } from "./types.js";
export declare const DEFAULT_MAX_RESPONSE_BYTES: number;
export declare const MAX_CONFIGURED_RESPONSE_BYTES: number;
export declare const DEFAULT_REQUEST_TIMEOUT_MS = 30000;
export declare const MAX_CONFIGURED_REQUEST_TIMEOUT_MS = 300000;
export interface BoundedHttpResponse {
    readonly response: Response;
    readonly body: Uint8Array;
    readonly text: string;
}
export declare function fetchBoundedResponse(config: LlmProxyConfig, input: string | URL | Request, init: RequestInit, label: string): Promise<BoundedHttpResponse>;
export declare function parseBoundedJson(result: BoundedHttpResponse, label: string): unknown;
export declare function resolveFetch(fetchImpl?: FetchLike): FetchLike;
//# sourceMappingURL=http.d.ts.map