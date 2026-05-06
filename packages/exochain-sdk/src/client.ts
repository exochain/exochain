/**
 * High-level {@link ExochainClient} — the one-stop entry point for talking to
 * an `exo-gateway` instance. Each domain API (identity, consent, governance,
 * authority) wraps the shared {@link HttpTransport}.
 */

import { HttpTransport } from './transport/http.js';
import type {
  AutomatedSettlementRequest,
  EconomyObjectResponse,
  HealthResponse,
  Did,
  Hash256,
  MissionSettlementRequest,
  QuorumResult,
} from './types.js';
import {
  assertJsonObject,
  validateDecisionState,
  validateDidResponse,
  validateEconomyObjectResponse,
  validateHashResponse,
  type JsonObject,
} from './validation.js';

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
  public async register(document: JsonObject): Promise<{ did: Did }> {
    const body = assertJsonObject(document, 'identity.register request body');
    return validateDidResponse(
      await this.#http.post('/identity/did', body),
      'identity.register response',
    );
  }
}

/** Consent / bailment gateway calls. */
export class ConsentApi {
  readonly #http: HttpTransport;
  constructor(http: HttpTransport) {
    this.#http = http;
  }

  /** Submit a bailment proposal for processing. */
  public async proposeBailment(body: JsonObject): Promise<{ proposalId: Hash256 }> {
    return validateHashResponse(
      await this.#http.post('/consent/bailment', body),
      'proposalId',
      'consent.proposeBailment response',
    );
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
  public async createDecision(body: JsonObject): Promise<{ decisionId: Hash256 }> {
    return validateHashResponse(
      await this.#http.post('/governance/decision', body),
      'decisionId',
      'governance.createDecision response',
    );
  }

  /** Cast a vote on an existing decision. */
  public async castVote(decisionId: Hash256, body: JsonObject): Promise<void> {
    await this.#http.post(`/governance/decision/${encodeURIComponent(decisionId)}/vote`, body);
  }

  /** Fetch a decision's current state (including tallied quorum). */
  public async getDecision(
    decisionId: Hash256,
  ): Promise<{ decisionId: Hash256; status: string; quorum?: QuorumResult }> {
    return validateDecisionState(
      await this.#http.get(`/governance/decision/${encodeURIComponent(decisionId)}`),
    );
  }
}

/** Authority chain gateway calls. */
export class AuthorityApi {
  readonly #http: HttpTransport;
  constructor(http: HttpTransport) {
    this.#http = http;
  }

  /** Submit a validated authority chain for persistence. */
  public async submitChain(chain: JsonObject): Promise<{ chainId: Hash256 }> {
    return validateHashResponse(
      await this.#http.post('/authority/chain', chain),
      'chainId',
      'authority.submitChain response',
    );
  }

  /** Fetch an authority chain by id. */
  public async getChain(chainId: Hash256): Promise<unknown> {
    return this.#http.get(`/authority/chain/${encodeURIComponent(chainId)}`);
  }
}

/** HonorGood and mission-economics calls. EXOCHAIN remains settlement authority. */
export class EconomyApi {
  readonly #http: HttpTransport;
  constructor(http: HttpTransport) {
    this.#http = http;
  }

  async #postObject<T extends JsonObject = JsonObject>(
    path: string,
    body: unknown,
    context: string,
  ): Promise<EconomyObjectResponse<T>> {
    const request = assertJsonObject(body, `${context} request body`) as T;
    return validateEconomyObjectResponse<T>(
      await this.#http.post(path, request),
      `${context} response`,
    );
  }

  async #getObject<T extends JsonObject = JsonObject>(
    path: string,
    context: string,
  ): Promise<T> {
    return assertJsonObject(await this.#http.get(path), `${context} response`) as T;
  }

  public async createMission<T extends JsonObject = JsonObject>(
    body: T,
  ): Promise<EconomyObjectResponse<T>> {
    return this.#postObject<T>('/api/v1/economy/missions', body, 'economy.createMission');
  }

  public async getMission<T extends JsonObject = JsonObject>(id: Hash256): Promise<T> {
    return this.#getObject<T>(
      `/api/v1/economy/missions/${encodeURIComponent(id)}`,
      'economy.getMission',
    );
  }

  public async createContributionReceipt<T extends JsonObject = JsonObject>(
    body: T,
  ): Promise<EconomyObjectResponse<T>> {
    return this.#postObject<T>(
      '/api/v1/economy/contribution-receipts',
      body,
      'economy.createContributionReceipt',
    );
  }

  public async createLegacyReceipt<T extends JsonObject = JsonObject>(
    body: T,
  ): Promise<EconomyObjectResponse<T>> {
    return this.#postObject<T>(
      '/api/v1/economy/legacy-receipts',
      body,
      'economy.createLegacyReceipt',
    );
  }

  public async getLegacyReceipt<T extends JsonObject = JsonObject>(id: Hash256): Promise<T> {
    return this.#getObject<T>(
      `/api/v1/economy/legacy-receipts/${encodeURIComponent(id)}`,
      'economy.getLegacyReceipt',
    );
  }

  public async createRuleset<T extends JsonObject = JsonObject>(
    body: T,
  ): Promise<EconomyObjectResponse<T>> {
    return this.#postObject<T>('/api/v1/economy/rulesets', body, 'economy.createRuleset');
  }

  public async createContributionNode<T extends JsonObject = JsonObject>(
    body: T,
  ): Promise<EconomyObjectResponse<T>> {
    return this.#postObject<T>(
      '/api/v1/economy/contribution-nodes',
      body,
      'economy.createContributionNode',
    );
  }

  public async createContributionOffer<T extends JsonObject = JsonObject>(
    body: T,
  ): Promise<EconomyObjectResponse<T>> {
    return this.#postObject<T>(
      '/api/v1/economy/contribution-offers',
      body,
      'economy.createContributionOffer',
    );
  }

  public async createContributionAcceptance<T extends JsonObject = JsonObject>(
    body: T,
  ): Promise<EconomyObjectResponse<T>> {
    return this.#postObject<T>(
      '/api/v1/economy/contribution-acceptances',
      body,
      'economy.createContributionAcceptance',
    );
  }

  public async createBailmentTerms<T extends JsonObject = JsonObject>(
    body: T,
  ): Promise<EconomyObjectResponse<T>> {
    return this.#postObject<T>(
      '/api/v1/economy/bailment-terms',
      body,
      'economy.createBailmentTerms',
    );
  }

  public async createBailmentWrapper<T extends JsonObject = JsonObject>(
    body: T,
  ): Promise<EconomyObjectResponse<T>> {
    return this.#postObject<T>(
      '/api/v1/economy/bailment-wrappers',
      body,
      'economy.createBailmentWrapper',
    );
  }

  public async createAdoptionEvent<T extends JsonObject = JsonObject>(
    body: T,
  ): Promise<EconomyObjectResponse<T>> {
    return this.#postObject<T>(
      '/api/v1/economy/adoption-events',
      body,
      'economy.createAdoptionEvent',
    );
  }

  public async createUseEvent<T extends JsonObject = JsonObject>(
    body: T,
  ): Promise<EconomyObjectResponse<T>> {
    return this.#postObject<T>('/api/v1/economy/use-events', body, 'economy.createUseEvent');
  }

  public async createValueEvent<T extends JsonObject = JsonObject>(
    body: T,
  ): Promise<EconomyObjectResponse<T>> {
    return this.#postObject<T>(
      '/api/v1/economy/value-events',
      body,
      'economy.createValueEvent',
    );
  }

  public async createMissionSettlement(
    body: MissionSettlementRequest,
  ): Promise<EconomyObjectResponse> {
    return this.#postObject(
      '/api/v1/economy/mission-settlements',
      body,
      'economy.createMissionSettlement',
    );
  }

  public async createAutomatedSettlement(
    body: AutomatedSettlementRequest,
  ): Promise<EconomyObjectResponse> {
    return this.#postObject(
      '/api/v1/economy/automated-settlements',
      body,
      'economy.createAutomatedSettlement',
    );
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
  public readonly economy: EconomyApi;
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
    this.economy = new EconomyApi(this.#http);
  }

  /** Gateway health probe. */
  public async health(): Promise<HealthResponse> {
    return this.#http.health();
  }
}
