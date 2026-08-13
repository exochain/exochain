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

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AUTHORIZATION_CHALLENGE_SCHEMA,
  HEADER_PAYMENT_REQUIRED,
  HEADER_PAYMENT_RESPONSE,
  HEADER_PAYMENT_SIGNATURE,
  HTTP_FORBIDDEN,
  HTTP_OK,
  HTTP_PAYMENT_REQUIRED,
  HTTP_PRECONDITION_REQUIRED,
  authorizationChallenge,
  isNeverPaywalledPath,
  mapAuthorizationToHttp,
} from "../src/mapping.js";
import { handlePaidRequest, type WorkerEnv } from "../src/worker.js";

test("deny maps to 403 and never 402", () => {
  const mapped = mapAuthorizationToHttp("Deny", true);
  assert.equal(mapped.status, HTTP_FORBIDDEN);
  assert.equal(mapped.paymentRequired, false);
  assert.notEqual(mapped.status, HTTP_PAYMENT_REQUIRED);
});

test("human approval maps to 428 before collection", () => {
  const mapped = mapAuthorizationToHttp("HumanApprovalRequired", false);
  assert.equal(mapped.status, HTTP_PRECONDITION_REQUIRED);
  assert.equal(mapped.paymentRequired, false);
});

test("challenge required maps to 402", () => {
  const mapped = mapAuthorizationToHttp("ChallengeRequired", false);
  assert.equal(mapped.status, HTTP_PAYMENT_REQUIRED);
  assert.equal(mapped.paymentRequired, true);
});

test("allow with settled payment maps to 200", () => {
  const mapped = mapAuthorizationToHttp("Allow", true);
  assert.equal(mapped.status, HTTP_OK);
  assert.equal(mapped.paymentResponse, true);
});

test("allow without payment fails closed to 402", () => {
  const mapped = mapAuthorizationToHttp("Allow", false);
  assert.equal(mapped.status, HTTP_PAYMENT_REQUIRED);
});

test("never paywalls validate, identity, or consent paths", () => {
  assert.equal(isNeverPaywalledPath("/api/v1/avc/validate"), true);
  assert.equal(isNeverPaywalledPath("/api/v1/0dentity/did:exo:a/score"), true);
  assert.equal(isNeverPaywalledPath("/api/v1/agents/did:exo:a/consent"), true);
  assert.equal(isNeverPaywalledPath("/mcp/tools/call"), false);
});

test("402 extension carries AVC reason codes, not x402 protocol types", () => {
  const challenge = authorizationChallenge("ChallengeRequired", [
    "PaymentEvidenceMissing",
  ]);
  assert.equal(challenge.schema, AUTHORIZATION_CHALLENGE_SCHEMA);
  assert.deepEqual(challenge.reason_codes, ["PaymentEvidenceMissing"]);
  assert.equal("accepts" in challenge, false);
});

const env: WorkerEnv = {
  EXO_NODE_BASE_URL: "https://node.example",
  EXO_ORIGIN_BASE_URL: "https://origin.example",
};

test("worker returns 403 when node denies even if payment signature is present", async () => {
  const fetchImpl: typeof fetch = async (input) => {
    const url = String(input);
    if (url.endsWith("/api/v1/avc/validate")) {
      return new Response(
        JSON.stringify({
          decision: "Deny",
          reason_codes: ["ForbiddenAction", "PaymentEvidenceMissing"],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error(`unexpected fetch ${url}`);
  };
  const request = new Request("https://edge.example/paid-tool", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      [HEADER_PAYMENT_SIGNATURE]: "facilitator-sig",
    },
    body: JSON.stringify({ commercially_gated: true }),
  });
  const response = await handlePaidRequest(request, env, fetchImpl);
  assert.equal(response.status, HTTP_FORBIDDEN);
});

test("worker returns 402 with PAYMENT-REQUIRED on ChallengeRequired", async () => {
  const fetchImpl: typeof fetch = async (input) => {
    const url = String(input);
    if (url.endsWith("/api/v1/avc/validate")) {
      return new Response(
        JSON.stringify({
          decision: "ChallengeRequired",
          reason_codes: ["PaymentEvidenceMissing"],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    throw new Error(`unexpected fetch ${url}`);
  };
  const request = new Request("https://edge.example/paid-tool", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ commercially_gated: true }),
  });
  const response = await handlePaidRequest(request, env, fetchImpl);
  assert.equal(response.status, HTTP_PAYMENT_REQUIRED);
  assert.ok(response.headers.get(HEADER_PAYMENT_REQUIRED));
  const challenge = JSON.parse(
    response.headers.get(HEADER_PAYMENT_REQUIRED) ?? "{}",
  ) as { schema: string; reason_codes: string[] };
  assert.equal(challenge.schema, AUTHORIZATION_CHALLENGE_SCHEMA);
  assert.deepEqual(challenge.reason_codes, ["PaymentEvidenceMissing"]);
});

test("worker executes origin and emits receipt on Allow when paid", async () => {
  const calls: string[] = [];
  const fetchImpl: typeof fetch = async (input) => {
    const url = String(input);
    calls.push(url);
    if (url.endsWith("/api/v1/avc/validate")) {
      return new Response(
        JSON.stringify({ decision: "Allow", reason_codes: ["Valid"] }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (url.includes("origin.example")) {
      return new Response("ok", { status: 200 });
    }
    if (url.endsWith("/api/v1/avc/llm-usage/receipts/emit")) {
      return new Response(JSON.stringify({ receipt_hash: "abc" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected fetch ${url}`);
  };
  const request = new Request("https://edge.example/paid-tool", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      [HEADER_PAYMENT_SIGNATURE]: "facilitator-sig",
    },
    body: JSON.stringify({ commercially_gated: true }),
  });
  const response = await handlePaidRequest(request, env, fetchImpl);
  assert.equal(response.status, HTTP_OK);
  assert.ok(response.headers.get(HEADER_PAYMENT_RESPONSE));
  assert.ok(calls.some((url) => url.includes("origin.example")));
  assert.ok(calls.some((url) => url.endsWith("/llm-usage/receipts/emit")));
});

test("worker fails closed when node validate is down", async () => {
  const fetchImpl: typeof fetch = async () => {
    throw new Error("network");
  };
  const request = new Request("https://edge.example/paid-tool", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ commercially_gated: true }),
  });
  const response = await handlePaidRequest(request, env, fetchImpl);
  assert.equal(response.status, 502);
});

test("worker does not 402 constitutional validate path", async () => {
  const fetchImpl: typeof fetch = async (input) => {
    const url = String(input);
    assert.ok(url.includes("/api/v1/avc/validate"));
    return new Response(JSON.stringify({ decision: "Allow" }), { status: 200 });
  };
  const request = new Request("https://edge.example/api/v1/avc/validate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ action: null }),
  });
  const response = await handlePaidRequest(request, env, fetchImpl);
  assert.equal(response.status, 200);
});
