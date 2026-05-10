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
 * Governance decisions — build, cast votes, check quorum.
 *
 * Mirrors the Rust SDK's `governance` module. Decision IDs are content-
 * addressed (SHA-256 over the canonical title/description/proposer payload),
 * votes are appended in-order, and duplicate voters are rejected.
 */

import { GovernanceError } from '../errors.js';
import type { Did, Hash256, QuorumResult } from '../types.js';
import { validateDid } from '../identity/did.js';
import { sha256, bytesToHex } from '../crypto/hash.js';
import { Vote } from './vote.js';

/** Lifecycle states a decision may be in. */
export type DecisionStatus =
  | 'proposed'
  | 'deliberating'
  | 'approved'
  | 'rejected'
  | 'challenged';

/** A full governance decision with accumulated votes. */
export class Decision {
  public readonly decisionId: Hash256;
  public readonly title: string;
  public readonly description: string;
  public readonly proposer: Did;
  public status: DecisionStatus;
  public readonly class?: string;
  readonly #votes: Vote[];

  constructor(args: {
    decisionId: Hash256;
    title: string;
    description: string;
    proposer: Did;
    status?: DecisionStatus;
    class?: string;
  }) {
    this.decisionId = args.decisionId;
    this.title = args.title;
    this.description = args.description;
    this.proposer = args.proposer;
    this.status = args.status ?? 'proposed';
    if (args.class !== undefined) {
      this.class = args.class;
    }
    this.#votes = [];
  }

  /** Read-only snapshot of votes cast so far. */
  public get votes(): readonly Vote[] {
    return this.#votes;
  }

  /**
   * Append a vote. Throws {@link GovernanceError} if the voter has already
   * voted on this decision.
   */
  public castVote(vote: Vote): void {
    for (const existing of this.#votes) {
      if (existing.voter === vote.voter) {
        throw new GovernanceError(`voter ${vote.voter} has already cast a vote`);
      }
    }
    this.#votes.push(vote);
  }

  /**
   * Tally the votes and report whether the approval count meets `threshold`.
   */
  public checkQuorum(threshold: number): QuorumResult {
    if (!Number.isInteger(threshold) || threshold < 0) {
      throw new GovernanceError('threshold must be a non-negative integer');
    }
    let approvals = 0;
    let rejections = 0;
    let abstentions = 0;
    for (const v of this.#votes) {
      if (v.choice === 'approve') approvals++;
      else if (v.choice === 'reject') rejections++;
      else abstentions++;
    }
    return {
      met: approvals >= threshold,
      threshold,
      totalVotes: this.#votes.length,
      approvals,
      rejections,
      abstentions,
    };
  }
}

/** Builder for a {@link Decision}. */
export class DecisionBuilder {
  #title: string;
  #description: string;
  #proposer: Did;
  #class?: string;

  constructor(args: {
    title: string;
    description: string;
    proposer: Did | string;
  }) {
    this.#title = args.title;
    this.#description = args.description;
    this.#proposer =
      typeof args.proposer === 'string' ? validateDid(args.proposer) : args.proposer;
  }

  /** Attach an optional decision class (free-form label). */
  public decisionClass(name: string): this {
    this.#class = name;
    return this;
  }

  /** Validate and build the {@link Decision}. */
  public async build(): Promise<Decision> {
    if (this.#title.length === 0) {
      throw new GovernanceError('title must be non-empty');
    }
    const decisionId = await computeDecisionId(
      this.#title,
      this.#description,
      this.#proposer,
    );
    const init: {
      decisionId: Hash256;
      title: string;
      description: string;
      proposer: Did;
      class?: string;
    } = {
      decisionId,
      title: this.#title,
      description: this.#description,
      proposer: this.#proposer,
    };
    if (this.#class !== undefined) {
      init.class = this.#class;
    }
    return new Decision(init);
  }
}

async function computeDecisionId(
  title: string,
  description: string,
  proposer: Did,
): Promise<Hash256> {
  const enc = new TextEncoder();
  const a = enc.encode(title);
  const b = enc.encode(description);
  const c = enc.encode(proposer);
  const payload = new Uint8Array(a.length + 1 + b.length + 1 + c.length);
  let off = 0;
  payload.set(a, off);
  off += a.length;
  payload[off++] = 0;
  payload.set(b, off);
  off += b.length;
  payload[off++] = 0;
  payload.set(c, off);
  const digest = await sha256(payload);
  return bytesToHex(digest) as Hash256;
}
