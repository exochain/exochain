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
 * High-level {@link ExochainClient} — the one-stop entry point for talking to
 * an `exo-gateway` instance. Each domain API (identity, consent, governance,
 * authority) wraps the shared {@link HttpTransport}.
 */

import { HttpTransport } from './transport/http.js';
import type { HealthResponse, Did, Hash256, QuorumResult } from './types.js';

/** Options for constructing an {@link ExochainClient}. */
export interface ExochainClientOptions {
  readonly baseUrl: string;
  readonly apiKey?: string;
  readonly timeout?: number;
  readonly fetch?: typeof fetch;
}

// -----------------------------------------------------------------------------
// Domain API surfaces
// -----------------------------------------------------------------------------

/** Identity-related gateway calls. */
export class IdentityApi {
  readonly #http: HttpTransport;
  constructor(http: HttpTransport) {
    this.#http = http;
  }

  /** Resolve a DID to its DID document via `GET /identity/did/{did}`. */
  public async resolve(did: Did): Promise<unknown> {
    return this.#http.get(`/identity/did/${encodeURIComponent(did)}`);
  }

  /** Register a DID document via `POST /identity/did`. */
  public async register(document: unknown): Promise<{ did: Did }> {
    return this.#http.post<{ did: Did }>('/identity/did', document);
  }
}

/** Consent / bailment gateway calls. */
export class ConsentApi {
  readonly #http: HttpTransport;
  constructor(http: HttpTransport) {
    this.#http = http;
  }

  /** Submit a bailment proposal for processing. */
  public async proposeBailment(body: unknown): Promise<{ proposalId: Hash256 }> {
    return this.#http.post<{ proposalId: Hash256 }>('/consent/bailment', body);
  }

  /** Fetch a bailment proposal by its content-addressed ID. */
  public async getBailment(proposalId: Hash256): Promise<unknown> {
    return this.#http.get(`/consent/bailment/${encodeURIComponent(proposalId)}`);
  }
}

/** Governance gateway calls. */
export class GovernanceApi {
  readonly #http: HttpTransport;
  constructor(http: HttpTransport) {
    this.#http = http;
  }

  /** Create a decision via `POST /governance/decision`. */
  public async createDecision(body: unknown): Promise<{ decisionId: Hash256 }> {
    return this.#http.post<{ decisionId: Hash256 }>('/governance/decision', body);
  }

  /** Cast a vote on an existing decision. */
  public async castVote(decisionId: Hash256, body: unknown): Promise<void> {
    await this.#http.post<void>(
      `/governance/decision/${encodeURIComponent(decisionId)}/vote`,
      body,
    );
  }

  /** Fetch a decision's current state (including tallied quorum). */
  public async getDecision(
    decisionId: Hash256,
  ): Promise<{ decisionId: Hash256; status: string; quorum?: QuorumResult }> {
    return this.#http.get(`/governance/decision/${encodeURIComponent(decisionId)}`);
  }
}

/** Authority chain gateway calls. */
export class AuthorityApi {
  readonly #http: HttpTransport;
  constructor(http: HttpTransport) {
    this.#http = http;
  }

  /** Submit a validated authority chain for persistence. */
  public async submitChain(chain: unknown): Promise<{ chainId: Hash256 }> {
    return this.#http.post<{ chainId: Hash256 }>('/authority/chain', chain);
  }

  /** Fetch an authority chain by id. */
  public async getChain(chainId: Hash256): Promise<unknown> {
    return this.#http.get(`/authority/chain/${encodeURIComponent(chainId)}`);
  }
}

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

/** High-level client combining all domain APIs over a shared transport. */
export class ExochainClient {
  public readonly identity: IdentityApi;
  public readonly consent: ConsentApi;
  public readonly governance: GovernanceApi;
  public readonly authority: AuthorityApi;
  readonly #http: HttpTransport;

  constructor(opts: ExochainClientOptions) {
    const transportOpts: {
      apiKey?: string;
      timeout?: number;
      fetch?: typeof fetch;
    } = {};
    if (opts.apiKey !== undefined) transportOpts.apiKey = opts.apiKey;
    if (opts.timeout !== undefined) transportOpts.timeout = opts.timeout;
    if (opts.fetch !== undefined) transportOpts.fetch = opts.fetch;
    this.#http = new HttpTransport(opts.baseUrl, transportOpts);
    this.identity = new IdentityApi(this.#http);
    this.consent = new ConsentApi(this.#http);
    this.governance = new GovernanceApi(this.#http);
    this.authority = new AuthorityApi(this.#http);
  }

  /** Gateway health probe. */
  public async health(): Promise<HealthResponse> {
    return this.#http.health();
  }
}
