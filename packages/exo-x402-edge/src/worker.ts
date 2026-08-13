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

import {
  AvcDecision,
  HEADER_PAYMENT_REQUIRED,
  HEADER_PAYMENT_RESPONSE,
  HEADER_PAYMENT_SIGNATURE,
  HTTP_BAD_GATEWAY,
  authorizationChallenge,
  isNeverPaywalledPath,
  mapAuthorizationToHttp,
} from "./mapping.js";

export interface AvcValidationResult {
  decision: AvcDecision;
  reason_codes: string[];
}

export interface WorkerEnv {
  EXO_NODE_BASE_URL: string;
  EXO_ORIGIN_BASE_URL: string;
}

export interface FetchLike {
  (input: string, init?: RequestInit): Promise<Response>;
}

function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      ...headers,
    },
  });
}

function nodeUrl(env: WorkerEnv, path: string): string {
  return `${env.EXO_NODE_BASE_URL.replace(/\/$/, "")}${path}`;
}

function originUrl(env: WorkerEnv, path: string): string {
  return `${env.EXO_ORIGIN_BASE_URL.replace(/\/$/, "")}${path}`;
}

/**
 * Translate one commercially gated request.
 *
 * Fail closed: missing node config, node errors, or unpaid Allow become
 * 502/402. Constitutional paths are proxied without a payment challenge.
 */
export async function handlePaidRequest(
  request: Request,
  env: WorkerEnv,
  fetchImpl: FetchLike,
): Promise<Response> {
  if (!env.EXO_NODE_BASE_URL || !env.EXO_ORIGIN_BASE_URL) {
    return jsonResponse(HTTP_BAD_GATEWAY, {
      error: "authorization_facilitator_unconfigured",
    });
  }

  const url = new URL(request.url);
  if (isNeverPaywalledPath(url.pathname)) {
    return fetchImpl(nodeUrl(env, `${url.pathname}${url.search}`), {
      method: request.method,
      headers: request.headers,
      body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
    });
  }

  let validationBody: unknown;
  try {
    validationBody = await request.clone().json();
  } catch {
    return jsonResponse(400, { error: "invalid_json_body" });
  }

  const paymentSettled = request.headers.has(HEADER_PAYMENT_SIGNATURE);
  const validateResponse = await fetchImpl(
    nodeUrl(env, "/api/v1/avc/validate"),
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(validationBody),
    },
  ).catch(() => undefined);

  if (!validateResponse || !validateResponse.ok) {
    return jsonResponse(HTTP_BAD_GATEWAY, {
      error: "avc_validate_unavailable",
    });
  }

  const validation = (await validateResponse.json()) as AvcValidationResult;
  const mapped = mapAuthorizationToHttp(validation.decision, paymentSettled);

  if (mapped.status !== 200) {
    const headers: Record<string, string> = {};
    if (mapped.paymentRequired) {
      headers[HEADER_PAYMENT_REQUIRED] = JSON.stringify(
        authorizationChallenge(validation.decision, validation.reason_codes),
      );
    }
    return jsonResponse(
      mapped.status,
      {
        decision: validation.decision,
        reason_codes: validation.reason_codes,
      },
      headers,
    );
  }

  const originResponse = await fetchImpl(
    originUrl(env, `${url.pathname}${url.search}`),
    {
      method: request.method,
      headers: request.headers,
      body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
    },
  ).catch(() => undefined);

  if (!originResponse) {
    return jsonResponse(HTTP_BAD_GATEWAY, { error: "origin_unavailable" });
  }

  const emitResponse = await fetchImpl(
    nodeUrl(env, "/api/v1/avc/llm-usage/receipts/emit"),
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(validationBody),
    },
  ).catch(() => undefined);

  if (!emitResponse || !emitResponse.ok) {
    return jsonResponse(HTTP_BAD_GATEWAY, {
      error: "receipt_emit_unavailable",
    });
  }

  const receipt = await emitResponse.json();
  const headers = new Headers(originResponse.headers);
  if (mapped.paymentResponse) {
    headers.set(HEADER_PAYMENT_RESPONSE, JSON.stringify(receipt));
  }
  return new Response(originResponse.body, {
    status: originResponse.status,
    headers,
  });
}

export default {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    return handlePaidRequest(request, env, fetch);
  },
};
