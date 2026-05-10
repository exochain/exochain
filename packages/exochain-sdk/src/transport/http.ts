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
    return this.get<HealthResponse>('/health');
  }

  /** Issue a GET and parse the JSON body as `T`. */
  public async get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  /** Issue a POST with a JSON body and parse the JSON response as `T`. */
  public async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  async #abortable(): Promise<{ signal: AbortSignal; cancel: () => void }> {
    const ctrl = new AbortController();
    const id = setTimeout(() => ctrl.abort(new Error('request timed out')), this.#timeout);
    return { signal: ctrl.signal, cancel: () => clearTimeout(id) };
  }

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
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
      res = await this.#fetch(url, init);
    } catch (err) {
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
      return undefined as unknown as T;
    }
    try {
      return JSON.parse(text) as T;
    } catch (err) {
      throw new TransportError('failed to parse JSON response', {
        cause: err,
        body: text,
      });
    }
  }
}

function stringifyError(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
