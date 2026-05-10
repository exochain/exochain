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
 * Core type definitions for the EXOCHAIN SDK.
 *
 * Branded primitive aliases (`Did`, `Hash256`) make it impossible to confuse a
 * validated DID or hash with an arbitrary `string`. They are structural only
 * — there is no runtime tag, so validation happens at the boundary via the
 * factory functions in {@link ./identity/did.ts} and {@link ./crypto/hash.ts}.
 */

/** A validated `did:exo:` identifier. Construct with `validateDid`. */
export type Did = string & { readonly __did: unique symbol };

/** A 64-character lowercase hex string representing 32 bytes. */
export type Hash256 = string & { readonly __hash256: unique symbol };

/** Outcome recorded on a constitutional trust receipt. */
export type ReceiptOutcome = 'permitted' | 'denied' | 'escalated';

/**
 * Trust receipt — the immutable record emitted by the constitutional kernel
 * every time an action is evaluated. Kept small and JSON-friendly.
 */
export interface TrustReceipt {
  readonly receiptHash: Hash256;
  readonly actorDid: Did;
  readonly actionType: string;
  readonly actionHash: Hash256;
  readonly outcome: ReceiptOutcome;
  readonly timestampMs: number;
}

/** Choices a voter may cast on a decision. */
export type VoteChoiceValue = 'approve' | 'reject' | 'abstain';

/** Thin wrapper matching the shape used by the gateway API. */
export interface VoteChoice {
  readonly choice: VoteChoiceValue;
}

/** Result of checking a decision's vote tally against a quorum threshold. */
export interface QuorumResult {
  readonly met: boolean;
  readonly threshold: number;
  readonly totalVotes: number;
  readonly approvals: number;
  readonly rejections: number;
  readonly abstentions: number;
}

/** Health payload returned by the gateway `/health` endpoint. */
export interface HealthResponse {
  readonly status: string;
  readonly version: string;
  readonly uptime: number;
}
