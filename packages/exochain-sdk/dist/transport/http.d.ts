import type { HealthResponse } from '../types.js';
import { type JsonObject } from '../validation.js';
/** Maximum accepted HTTP response body size, measured in wire-decoded bytes. */
export declare const MAX_HTTP_RESPONSE_BYTES = 1048576;
/** Options for {@link HttpTransport}. */
export interface HttpTransportOptions {
    /** Optional API key sent as `Authorization: Bearer <apiKey>`. */
    readonly apiKey?: string;
    /** Request timeout in milliseconds. Defaults to 30_000. */
    readonly timeout?: number;
    /** Override the `fetch` implementation (useful for tests). */
    readonly fetch?: typeof fetch;
}
/** Small fetch wrapper that serializes and deserializes JSON bodies. */
export declare class HttpTransport {
    #private;
    constructor(baseUrl: string, opts?: HttpTransportOptions);
    /** Gateway `/health` probe. */
    health(): Promise<HealthResponse>;
    /** Issue a GET and parse the JSON body as untrusted data. */
    get(path: string): Promise<unknown>;
    /** Issue a POST with a JSON body and parse the JSON response as untrusted data. */
    post(path: string, body: JsonObject): Promise<unknown>;
    request(method: string, path: string, body?: JsonObject): Promise<unknown>;
}
//# sourceMappingURL=http.d.ts.map