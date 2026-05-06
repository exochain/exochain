/**
 * HTTP transport for the `exo-gateway` REST API.
 *
 * Uses the global `fetch` which is available in Node 18+ and all modern
 * browsers. No third-party HTTP library is used to keep the SDK dependency-
 * free.
 */
import { TransportError } from '../errors.js';
import { assertJsonObject, validateHealthResponse, } from '../validation.js';
/** Small fetch wrapper that serializes and deserializes JSON bodies. */
export class HttpTransport {
    #baseUrl;
    #apiKey;
    #timeout;
    #fetch;
    constructor(baseUrl, opts) {
        if (typeof baseUrl !== 'string' || baseUrl.length === 0) {
            throw new TransportError('baseUrl is required');
        }
        this.#baseUrl = baseUrl.replace(/\/+$/, '');
        if (opts?.apiKey !== undefined)
            this.#apiKey = opts.apiKey;
        this.#timeout = opts?.timeout ?? 30_000;
        const f = opts?.fetch ?? globalThis.fetch;
        if (typeof f !== 'function') {
            throw new TransportError('fetch is not available in this environment');
        }
        this.#fetch = f;
    }
    /** Gateway `/health` probe. */
    async health() {
        return validateHealthResponse(await this.get('/health'));
    }
    /** Issue a GET and parse the JSON body as untrusted data. */
    async get(path) {
        return this.request('GET', path);
    }
    /** Issue a POST with a JSON body and parse the JSON response as untrusted data. */
    async post(path, body) {
        return this.request('POST', path, assertJsonObject(body, `${path} request body`));
    }
    async #abortable() {
        const ctrl = new AbortController();
        const id = setTimeout(() => ctrl.abort(new Error('request timed out')), this.#timeout);
        return { signal: ctrl.signal, cancel: () => clearTimeout(id) };
    }
    async request(method, path, body) {
        const url = `${this.#baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
        const headers = { accept: 'application/json' };
        if (this.#apiKey !== undefined) {
            headers.authorization = `Bearer ${this.#apiKey}`;
        }
        let serialized;
        if (body !== undefined) {
            headers['content-type'] = 'application/json';
            serialized = JSON.stringify(body);
        }
        const { signal, cancel } = await this.#abortable();
        let res;
        try {
            const init = { method, headers, signal };
            if (serialized !== undefined) {
                init.body = serialized;
            }
            res = await this.#fetch(url, init);
        }
        catch (err) {
            cancel();
            throw new TransportError(`network error: ${stringifyError(err)}`, { cause: err });
        }
        cancel();
        const text = await res.text();
        if (!res.ok) {
            throw new TransportError(`HTTP ${res.status} ${res.statusText} for ${method} ${path}`, {
                status: res.status,
                body: text,
            });
        }
        if (text.length === 0) {
            return undefined;
        }
        try {
            const parsed = JSON.parse(text);
            return parsed;
        }
        catch (err) {
            throw new TransportError('failed to parse JSON response', {
                cause: err,
                body: text,
            });
        }
    }
}
function stringifyError(err) {
    if (err instanceof Error)
        return err.message;
    return String(err);
}
//# sourceMappingURL=http.js.map