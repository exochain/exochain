/**
 * High-level {@link ExochainClient} — the one-stop entry point for talking to
 * an `exo-gateway` instance. Each domain API (identity, consent, governance,
 * authority) wraps the shared {@link HttpTransport}.
 */
import { HttpTransport } from './transport/http.js';
import { assertJsonObject, validateDecisionState, validateDidResponse, validateEconomyObjectResponse, validateHashResponse, } from './validation.js';
// -----------------------------------------------------------------------------
// Domain API surfaces
// -----------------------------------------------------------------------------
/** Identity-related gateway calls. */
export class IdentityApi {
    #http;
    constructor(http) {
        this.#http = http;
    }
    /** Resolve a DID to its DID document via `GET /identity/did/{did}`. */
    async resolve(did) {
        return this.#http.get(`/identity/did/${encodeURIComponent(did)}`);
    }
    /** Register a DID document via `POST /identity/did`. */
    async register(document) {
        const body = assertJsonObject(document, 'identity.register request body');
        return validateDidResponse(await this.#http.post('/identity/did', body), 'identity.register response');
    }
}
/** Consent / bailment gateway calls. */
export class ConsentApi {
    #http;
    constructor(http) {
        this.#http = http;
    }
    /** Submit a bailment proposal for processing. */
    async proposeBailment(body) {
        return validateHashResponse(await this.#http.post('/consent/bailment', body), 'proposalId', 'consent.proposeBailment response');
    }
    /** Fetch a bailment proposal by its content-addressed ID. */
    async getBailment(proposalId) {
        return this.#http.get(`/consent/bailment/${encodeURIComponent(proposalId)}`);
    }
}
/** Governance gateway calls. */
export class GovernanceApi {
    #http;
    constructor(http) {
        this.#http = http;
    }
    /** Create a decision via `POST /governance/decision`. */
    async createDecision(body) {
        return validateHashResponse(await this.#http.post('/governance/decision', body), 'decisionId', 'governance.createDecision response');
    }
    /** Cast a vote on an existing decision. */
    async castVote(decisionId, body) {
        await this.#http.post(`/governance/decision/${encodeURIComponent(decisionId)}/vote`, body);
    }
    /** Fetch a decision's current state (including tallied quorum). */
    async getDecision(decisionId) {
        return validateDecisionState(await this.#http.get(`/governance/decision/${encodeURIComponent(decisionId)}`));
    }
}
/** Authority chain gateway calls. */
export class AuthorityApi {
    #http;
    constructor(http) {
        this.#http = http;
    }
    /** Submit a validated authority chain for persistence. */
    async submitChain(chain) {
        return validateHashResponse(await this.#http.post('/authority/chain', chain), 'chainId', 'authority.submitChain response');
    }
    /** Fetch an authority chain by id. */
    async getChain(chainId) {
        return this.#http.get(`/authority/chain/${encodeURIComponent(chainId)}`);
    }
}
/** HonorGood and mission-economics calls. EXOCHAIN remains settlement authority. */
export class EconomyApi {
    #http;
    constructor(http) {
        this.#http = http;
    }
    async #postObject(path, body, context) {
        const request = assertJsonObject(body, `${context} request body`);
        return validateEconomyObjectResponse(await this.#http.post(path, request), `${context} response`);
    }
    async #getObject(path, context) {
        return assertJsonObject(await this.#http.get(path), `${context} response`);
    }
    async createMission(body) {
        return this.#postObject('/api/v1/economy/missions', body, 'economy.createMission');
    }
    async getMission(id) {
        return this.#getObject(`/api/v1/economy/missions/${encodeURIComponent(id)}`, 'economy.getMission');
    }
    async createContributionReceipt(body) {
        return this.#postObject('/api/v1/economy/contribution-receipts', body, 'economy.createContributionReceipt');
    }
    async createLegacyReceipt(body) {
        return this.#postObject('/api/v1/economy/legacy-receipts', body, 'economy.createLegacyReceipt');
    }
    async getLegacyReceipt(id) {
        return this.#getObject(`/api/v1/economy/legacy-receipts/${encodeURIComponent(id)}`, 'economy.getLegacyReceipt');
    }
    async createRuleset(body) {
        return this.#postObject('/api/v1/economy/rulesets', body, 'economy.createRuleset');
    }
    async createContributionNode(body) {
        return this.#postObject('/api/v1/economy/contribution-nodes', body, 'economy.createContributionNode');
    }
    async createContributionOffer(body) {
        return this.#postObject('/api/v1/economy/contribution-offers', body, 'economy.createContributionOffer');
    }
    async createContributionAcceptance(body) {
        return this.#postObject('/api/v1/economy/contribution-acceptances', body, 'economy.createContributionAcceptance');
    }
    async createBailmentTerms(body) {
        return this.#postObject('/api/v1/economy/bailment-terms', body, 'economy.createBailmentTerms');
    }
    async createBailmentWrapper(body) {
        return this.#postObject('/api/v1/economy/bailment-wrappers', body, 'economy.createBailmentWrapper');
    }
    async createAdoptionEvent(body) {
        return this.#postObject('/api/v1/economy/adoption-events', body, 'economy.createAdoptionEvent');
    }
    async createUseEvent(body) {
        return this.#postObject('/api/v1/economy/use-events', body, 'economy.createUseEvent');
    }
    async createValueEvent(body) {
        return this.#postObject('/api/v1/economy/value-events', body, 'economy.createValueEvent');
    }
    async createMissionSettlement(body) {
        return this.#postObject('/api/v1/economy/mission-settlements', body, 'economy.createMissionSettlement');
    }
    async createAutomatedSettlement(body) {
        return this.#postObject('/api/v1/economy/automated-settlements', body, 'economy.createAutomatedSettlement');
    }
}
// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------
/** High-level client combining all domain APIs over a shared transport. */
export class ExochainClient {
    identity;
    consent;
    governance;
    authority;
    economy;
    #http;
    constructor(opts) {
        const transportOpts = {};
        if (opts.apiKey !== undefined)
            transportOpts.apiKey = opts.apiKey;
        if (opts.timeout !== undefined)
            transportOpts.timeout = opts.timeout;
        if (opts.fetch !== undefined)
            transportOpts.fetch = opts.fetch;
        this.#http = new HttpTransport(opts.baseUrl, transportOpts);
        this.identity = new IdentityApi(this.#http);
        this.consent = new ConsentApi(this.#http);
        this.governance = new GovernanceApi(this.#http);
        this.authority = new AuthorityApi(this.#http);
        this.economy = new EconomyApi(this.#http);
    }
    /** Gateway health probe. */
    async health() {
        return this.#http.health();
    }
}
//# sourceMappingURL=client.js.map