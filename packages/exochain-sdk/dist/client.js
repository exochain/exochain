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
import { validateDid } from './identity/did.js';
import { assertJsonObject, validateDecisionState, validateDidResponse, validateEconomyObjectResponse, validateExochainDiscoveryResponse, validateHash256, validateHashResponse, } from './validation.js';
function encodeHash256PathSegment(value, context) {
    return encodeURIComponent(validateHash256(value, context));
}
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
        return this.#http.get(`/identity/did/${encodeURIComponent(validateDid(did))}`);
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
        const id = encodeHash256PathSegment(proposalId, 'consent.getBailment proposalId');
        return this.#http.get(`/consent/bailment/${id}`);
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
        const id = encodeHash256PathSegment(decisionId, 'governance.castVote decisionId');
        await this.#http.post(`/governance/decision/${id}/vote`, body);
    }
    /** Fetch a decision's current state (including tallied quorum). */
    async getDecision(decisionId) {
        const id = encodeHash256PathSegment(decisionId, 'governance.getDecision decisionId');
        return validateDecisionState(await this.#http.get(`/governance/decision/${id}`));
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
        const id = encodeHash256PathSegment(chainId, 'authority.getChain chainId');
        return this.#http.get(`/authority/chain/${id}`);
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
        const missionId = encodeHash256PathSegment(id, 'economy.getMission id');
        return this.#getObject(`/api/v1/economy/missions/${missionId}`, 'economy.getMission');
    }
    async createContributionReceipt(body) {
        return this.#postObject('/api/v1/economy/contribution-receipts', body, 'economy.createContributionReceipt');
    }
    async createLegacyReceipt(body) {
        return this.#postObject('/api/v1/economy/legacy-receipts', body, 'economy.createLegacyReceipt');
    }
    async getLegacyReceipt(id) {
        const receiptId = encodeHash256PathSegment(id, 'economy.getLegacyReceipt id');
        return this.#getObject(`/api/v1/economy/legacy-receipts/${receiptId}`, 'economy.getLegacyReceipt');
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
    /** Public EXOCHAIN discovery document from `/.well-known/exochain.json`. */
    async discover() {
        return validateExochainDiscoveryResponse(await this.#http.get('/.well-known/exochain.json'));
    }
}
//# sourceMappingURL=client.js.map