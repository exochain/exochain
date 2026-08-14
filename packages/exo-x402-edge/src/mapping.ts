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

/** AVC decisions produced by exo-node `POST /api/v1/avc/validate`. */
export type AvcDecision =
  | "Allow"
  | "Deny"
  | "HumanApprovalRequired"
  | "ChallengeRequired";

export const HTTP_OK = 200;
export const HTTP_PAYMENT_REQUIRED = 402;
export const HTTP_FORBIDDEN = 403;
export const HTTP_PRECONDITION_REQUIRED = 428;
export const HTTP_BAD_GATEWAY = 502;

export const HEADER_PAYMENT_REQUIRED = "PAYMENT-REQUIRED";
export const HEADER_PAYMENT_SIGNATURE = "PAYMENT-SIGNATURE";
export const HEADER_PAYMENT_RESPONSE = "PAYMENT-RESPONSE";

export const AUTHORIZATION_CHALLENGE_SCHEMA =
  "exo.x402.authorization-challenge.v1";

export interface AuthorizationHttpMapping {
  status: number;
  paymentRequired: boolean;
  paymentResponse: boolean;
}

export interface AuthorizationChallenge {
  schema: string;
  avc_decision: AvcDecision;
  reason_codes: string[];
  commercially_gated: boolean;
}

/**
 * Map an AVC decision onto HTTP. Deny always outranks payment.
 * Human approval is collected before money. Unpaid Allow fails closed to 402.
 */
export function mapAuthorizationToHttp(
  decision: AvcDecision,
  paymentSettled: boolean,
): AuthorizationHttpMapping {
  switch (decision) {
    case "Deny":
      return {
        status: HTTP_FORBIDDEN,
        paymentRequired: false,
        paymentResponse: false,
      };
    case "HumanApprovalRequired":
      return {
        status: HTTP_PRECONDITION_REQUIRED,
        paymentRequired: false,
        paymentResponse: false,
      };
    case "ChallengeRequired":
      return {
        status: HTTP_PAYMENT_REQUIRED,
        paymentRequired: true,
        paymentResponse: false,
      };
    case "Allow":
      if (paymentSettled) {
        return {
          status: HTTP_OK,
          paymentRequired: false,
          paymentResponse: true,
        };
      }
      return {
        status: HTTP_PAYMENT_REQUIRED,
        paymentRequired: true,
        paymentResponse: false,
      };
    default: {
      const exhaustive: never = decision;
      return exhaustive;
    }
  }
}

/** Constitutional paths that must never be commercially gated. */
export function isNeverPaywalledPath(pathname: string): boolean {
  const path = pathname.split("?")[0] ?? pathname;
  return (
    path === "/api/v1/avc/validate" ||
    path.includes("/api/v1/0dentity/") ||
    (path.startsWith("/api/v1/agents/") && path.endsWith("/consent"))
  );
}

export function authorizationChallenge(
  decision: AvcDecision,
  reasonCodes: string[],
): AuthorizationChallenge {
  return {
    schema: AUTHORIZATION_CHALLENGE_SCHEMA,
    avc_decision: decision,
    reason_codes: reasonCodes,
    commercially_gated: true,
  };
}

const ZERO_PAYMENT_EVIDENCE_HEX = "0".repeat(64);

/**
 * Settlement is a non-zero bound payment-evidence hash, never header presence.
 * Accepts lowercase 64-hex or a 32-byte JSON array (serde of Rust `Hash256`).
 */
export function isBoundPaymentEvidenceHash(value: unknown): boolean {
  if (typeof value === "string") {
    const hex = value.trim().toLowerCase();
    return /^[0-9a-f]{64}$/.test(hex) && hex !== ZERO_PAYMENT_EVIDENCE_HEX;
  }
  if (!Array.isArray(value) || value.length !== 32) {
    return false;
  }
  let anyNonZero = false;
  for (const entry of value) {
    if (typeof entry !== "number" || !Number.isInteger(entry) || entry < 0 || entry > 255) {
      return false;
    }
    if (entry !== 0) {
      anyNonZero = true;
    }
  }
  return anyNonZero;
}

/** Prefer the AVC validation echo; fall back to `action.payment_evidence_hash`. */
export function paymentSettledFromBoundEvidence(
  validationHash: unknown,
  body: unknown,
): boolean {
  if (isBoundPaymentEvidenceHash(validationHash)) {
    return true;
  }
  if (body === null || typeof body !== "object") {
    return false;
  }
  const record = body as Record<string, unknown>;
  const action = record.action;
  if (action !== null && typeof action === "object") {
    const actionHash = (action as Record<string, unknown>).payment_evidence_hash;
    if (isBoundPaymentEvidenceHash(actionHash)) {
      return true;
    }
  }
  return isBoundPaymentEvidenceHash(record.payment_evidence_hash);
}
