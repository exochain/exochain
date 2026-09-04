// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

/**
 * HTTP transport for the `exo-gateway` REST API.
 *
 * Uses the global `fetch` which is available in Node 18+ and all modern
 * browsers. No third-party HTTP library is used to keep the SDK dependency-
 * free.
 */

import { TransportError } from '../errors.js';
import type { HealthResponse } from '../types.js';
import {
  assertJsonObject,
  validateHealthResponse,
  type JsonObject,
} from '../validation.js';

/** Maximum accepted HTTP response body size, measured in wire-decoded bytes. */
export const MAX_HTTP_RESPONSE_BYTES = 1_048_576;
const OVERSIZED_RESPONSE_MESSAGE =
  'response body exceeds the 1048576-byte limit';
const TYPED_ARRAY_BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype) as object,
  'byteLength',
)?.get;

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
export class HttpTransport {
  readonly #baseUrl: string;
  readonly #apiKey?: string;
  readonly #timeout: number;
  readonly #fetch: typeof fetch;

  constructor(baseUrl: string, opts?: HttpTransportOptions) {
    if (typeof baseUrl !== 'string' || baseUrl.length === 0) {
      throw new TransportError('baseUrl is required');
    }
    this.#baseUrl = baseUrl.replace(/\/+$/, '');
    if (opts?.apiKey !== undefined) this.#apiKey = opts.apiKey;
    this.#timeout = opts?.timeout ?? 30_000;
    const f = opts?.fetch ?? globalThis.fetch;
    if (typeof f !== 'function') {
      throw new TransportError('fetch is not available in this environment');
    }
    this.#fetch = f;
  }

  /** Gateway `/health` probe. */
  public async health(): Promise<HealthResponse> {
    return validateHealthResponse(await this.get('/health'));
  }

  /** Issue a GET and parse the JSON body as untrusted data. */
  public async get(path: string): Promise<unknown> {
    return this.request('GET', path);
  }

  /** Issue a POST with a JSON body and parse the JSON response as untrusted data. */
  public async post(path: string, body: JsonObject): Promise<unknown> {
    return this.request('POST', path, assertJsonObject(body, `${path} request body`));
  }

  async #abortable(): Promise<{ signal: AbortSignal; cancel: () => void }> {
    const ctrl = new AbortController();
    const id = setTimeout(() => ctrl.abort(new Error('request timed out')), this.#timeout);
    return { signal: ctrl.signal, cancel: () => clearTimeout(id) };
  }

  async request(method: string, path: string, body?: JsonObject): Promise<unknown> {
    const url = `${this.#baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
    const headers: Record<string, string> = { accept: 'application/json' };
    if (this.#apiKey !== undefined) {
      headers.authorization = `Bearer ${this.#apiKey}`;
    }
    let serialized: string | undefined;
    if (body !== undefined) {
      headers['content-type'] = 'application/json';
      serialized = JSON.stringify(body);
    }

    const { signal, cancel } = await this.#abortable();
    let res: Response;
    try {
      const init: RequestInit = { method, headers, signal };
      if (serialized !== undefined) {
        init.body = serialized;
      }
      res = await awaitWithAbort(this.#fetch(url, init), signal);
    } catch (err) {
      cancel();
      throw new TransportError(`network error: ${stringifyError(err)}`, { cause: err });
    }

    let text: string;
    try {
      text = await readBoundedResponseText(res, signal);
    } catch (err) {
      if (err instanceof TransportError) throw err;
      throw new TransportError(`network error: ${stringifyError(err)}`, { cause: err });
    } finally {
      cancel();
    }
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
      const parsed: unknown = JSON.parse(text);
      return parsed;
    } catch (err) {
      throw new TransportError('failed to parse JSON response', {
        cause: err,
        body: text,
      });
    }
  }
}

async function readBoundedResponseText(
  response: Response,
  signal: AbortSignal,
): Promise<string> {
  const contentLength = response.headers.get('content-length');
  let initialCapacity = 0;
  if (contentLength !== null && /^[0-9]+$/.test(contentLength)) {
    const declaredLength = BigInt(contentLength);
    if (declaredLength > BigInt(MAX_HTTP_RESPONSE_BYTES)) {
      cancelResponseBody(response.body);
      throw oversizedResponseError(response.status);
    }
    initialCapacity = Number(declaredLength);
  }

  if (response.body === null) return '';

  const reader = response.body.getReader();
  let bytes = new Uint8Array(initialCapacity);
  let totalBytes = 0;
  try {
    while (true) {
      const next = await awaitWithAbort(reader.read(), signal);
      if (next.done) break;

      const chunkLength = intrinsicUint8ArrayByteLength(next.value);
      if (chunkLength === undefined) {
        throw new TransportError('response body contained a non-byte chunk', {
          status: response.status,
        });
      }
      const nextTotal = totalBytes + chunkLength;
      if (nextTotal > MAX_HTTP_RESPONSE_BYTES) {
        throw oversizedResponseError(response.status);
      }
      if (nextTotal > bytes.byteLength) {
        const doubledCapacity = Math.max(8_192, bytes.byteLength * 2);
        const nextCapacity = Math.min(
          MAX_HTTP_RESPONSE_BYTES,
          Math.max(nextTotal, doubledCapacity),
        );
        const grown = new Uint8Array(nextCapacity);
        grown.set(bytes.subarray(0, totalBytes));
        bytes = grown;
      }
      bytes.set(next.value, totalBytes);
      totalBytes = nextTotal;
    }
  } catch (error) {
    void reader.cancel(error).catch(() => undefined);
    throw error;
  }
  return new TextDecoder().decode(bytes.subarray(0, totalBytes));
}

/** Await an operation against the same deadline even when it ignores `signal`. */
function awaitWithAbort<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(abortReason(signal));
  }

  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => {
      signal.removeEventListener('abort', onAbort);
      reject(abortReason(signal));
    };
    signal.addEventListener('abort', onAbort, { once: true });
    operation.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

function abortReason(signal: AbortSignal): unknown {
  return signal.reason === undefined ? new Error('request aborted') : signal.reason;
}

function intrinsicUint8ArrayByteLength(value: unknown): number | undefined {
  if (TYPED_ARRAY_BYTE_LENGTH_GETTER === undefined) return undefined;
  try {
    const byteLength = Reflect.apply(TYPED_ARRAY_BYTE_LENGTH_GETTER, value, []) as unknown;
    return typeof byteLength === 'number' &&
      Number.isSafeInteger(byteLength) &&
      byteLength >= 0
      ? byteLength
      : undefined;
  } catch {
    return undefined;
  }
}

function cancelResponseBody(body: ReadableStream<Uint8Array> | null): void {
  if (body !== null) void body.cancel().catch(() => undefined);
}

function oversizedResponseError(status: number): TransportError {
  return new TransportError(OVERSIZED_RESPONSE_MESSAGE, { status });
}

function stringifyError(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
