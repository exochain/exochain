/*
 * Copyright 2026 Exochain Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { LynkConfigurationError, LynkValidationError } from "./evidence.js";
import type { FetchLike, LlmProxyConfig } from "./types.js";

export const DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
export const MAX_CONFIGURED_RESPONSE_BYTES = 64 * 1024 * 1024;
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
export const MAX_CONFIGURED_REQUEST_TIMEOUT_MS = 300_000;

export interface BoundedHttpResponse {
  readonly response: Response;
  readonly body: Uint8Array;
  readonly text: string;
}

export async function fetchBoundedResponse(
  config: LlmProxyConfig,
  input: string | URL | Request,
  init: RequestInit,
  label: string,
): Promise<BoundedHttpResponse> {
  const maxResponseBytes = configuredPositiveInteger(
    "maxResponseBytes",
    config.maxResponseBytes,
    DEFAULT_MAX_RESPONSE_BYTES,
    MAX_CONFIGURED_RESPONSE_BYTES,
  );
  const requestTimeoutMs = configuredPositiveInteger(
    "requestTimeoutMs",
    config.requestTimeoutMs,
    DEFAULT_REQUEST_TIMEOUT_MS,
    MAX_CONFIGURED_REQUEST_TIMEOUT_MS,
  );
  const fetchImpl = resolveFetch(config.fetch);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);

  try {
    const response = await awaitWithAbort(
      fetchImpl(input, { ...init, signal: controller.signal }),
      controller.signal,
      label,
      requestTimeoutMs,
    );
    const body = await readBoundedBody(
      response,
      maxResponseBytes,
      controller.signal,
      label,
      requestTimeoutMs,
    );
    return {
      response,
      body,
      text: new TextDecoder().decode(body),
    };
  } finally {
    clearTimeout(timeout);
  }
}

export function parseBoundedJson(result: BoundedHttpResponse, label: string): unknown {
  try {
    return JSON.parse(result.text) as unknown;
  } catch {
    throw new LynkValidationError(`${label} was not valid JSON`);
  }
}

export function resolveFetch(fetchImpl?: FetchLike): FetchLike {
  if (fetchImpl) {
    return fetchImpl;
  }
  if (globalThis.fetch) {
    return globalThis.fetch.bind(globalThis) as FetchLike;
  }
  throw new LynkConfigurationError("LYNK proxy requires fetch");
}

function configuredPositiveInteger(
  name: "maxResponseBytes" | "requestTimeoutMs",
  value: number | undefined,
  defaultValue: number,
  maximum: number,
): number {
  const resolved = value ?? defaultValue;
  if (!Number.isSafeInteger(resolved) || resolved <= 0 || resolved > maximum) {
    throw new LynkConfigurationError(
      `LYNK ${name} must be a positive safe integer no greater than ${maximum}`,
    );
  }
  return resolved;
}

async function readBoundedBody(
  response: Response,
  maxBytes: number,
  signal: AbortSignal,
  label: string,
  timeoutMs: number,
): Promise<Uint8Array> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && /^[0-9]+$/.test(contentLength.trim())) {
    const declared = BigInt(contentLength.trim());
    if (declared > BigInt(maxBytes)) {
      void response.body?.cancel().catch(() => undefined);
      throw new LynkValidationError(`${label} Content-Length exceeds ${maxBytes} bytes`);
    }
  }

  if (response.body === null) {
    return new Uint8Array();
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await awaitWithAbort(
        reader.read(),
        signal,
        label,
        timeoutMs,
      );
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        throw new LynkValidationError(`${label} returned a non-byte response chunk`);
      }
      if (value.byteLength > maxBytes - total) {
        void reader.cancel().catch(() => undefined);
        throw new LynkValidationError(`${label} exceeds ${maxBytes} bytes`);
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } catch (error) {
    void reader.cancel().catch(() => undefined);
    throw error;
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function awaitWithAbort<T>(
  operation: Promise<T>,
  signal: AbortSignal,
  label: string,
  timeoutMs: number,
): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(
      new LynkValidationError(`${label} timed out after ${timeoutMs} ms`),
    );
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      reject(new LynkValidationError(`${label} timed out after ${timeoutMs} ms`));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    operation.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        if (signal.aborted) {
          reject(new LynkValidationError(`${label} timed out after ${timeoutMs} ms`));
        } else {
          reject(error);
        }
      },
    );
  });
}
