/**
 * High-level {@link ExochainClient} — the one-stop entry point for talking to
 * an `exo-gateway` instance. Each domain API (identity, consent, governance,
 * authority) wraps the shared {@link HttpTransport}.
 */
import { HttpTransport } from './transport/http.js';
import type { AutomatedSettlementRequest, EconomyObjectResponse, HealthResponse, Did, Hash256, MissionSettlementRequest, QuorumResult } from './types.js';
import { type JsonObject } from './validation.js';
/** Options for constructing an {@link ExochainClient}. */
export interface ExochainClientOptions {
    readonly baseUrl: string;
    readonly apiKey?: string;
    readonly timeout?: number;
    readonly fetch?: typeof fetch;
}
/** Identity-related gateway calls. */
export declare class IdentityApi {
    #private;
    constructor(http: HttpTransport);
    /** Resolve a DID to its DID document via `GET /identity/did/{did}`. */
    resolve(did: Did): Promise<unknown>;
    /** Register a DID document via `POST /identity/did`. */
    register(document: JsonObject): Promise<{
        did: Did;
    }>;
}
/** Consent / bailment gateway calls. */
export declare class ConsentApi {
    #private;
    constructor(http: HttpTransport);
    /** Submit a bailment proposal for processing. */
    proposeBailment(body: JsonObject): Promise<{
        proposalId: Hash256;
    }>;
    /** Fetch a bailment proposal by its content-addressed ID. */
    getBailment(proposalId: Hash256): Promise<unknown>;
}
/** Governance gateway calls. */
export declare class GovernanceApi {
    #private;
    constructor(http: HttpTransport);
    /** Create a decision via `POST /governance/decision`. */
    createDecision(body: JsonObject): Promise<{
        decisionId: Hash256;
    }>;
    /** Cast a vote on an existing decision. */
    castVote(decisionId: Hash256, body: JsonObject): Promise<void>;
    /** Fetch a decision's current state (including tallied quorum). */
    getDecision(decisionId: Hash256): Promise<{
        decisionId: Hash256;
        status: string;
        quorum?: QuorumResult;
    }>;
}
/** Authority chain gateway calls. */
export declare class AuthorityApi {
    #private;
    constructor(http: HttpTransport);
    /** Submit a validated authority chain for persistence. */
    submitChain(chain: JsonObject): Promise<{
        chainId: Hash256;
    }>;
    /** Fetch an authority chain by id. */
    getChain(chainId: Hash256): Promise<unknown>;
}
/** HonorGood and mission-economics calls. EXOCHAIN remains settlement authority. */
export declare class EconomyApi {
    #private;
    constructor(http: HttpTransport);
    createMission<T extends JsonObject = JsonObject>(body: T): Promise<EconomyObjectResponse<T>>;
    getMission<T extends JsonObject = JsonObject>(id: Hash256): Promise<T>;
    createContributionReceipt<T extends JsonObject = JsonObject>(body: T): Promise<EconomyObjectResponse<T>>;
    createLegacyReceipt<T extends JsonObject = JsonObject>(body: T): Promise<EconomyObjectResponse<T>>;
    getLegacyReceipt<T extends JsonObject = JsonObject>(id: Hash256): Promise<T>;
    createRuleset<T extends JsonObject = JsonObject>(body: T): Promise<EconomyObjectResponse<T>>;
    createContributionNode<T extends JsonObject = JsonObject>(body: T): Promise<EconomyObjectResponse<T>>;
    createContributionOffer<T extends JsonObject = JsonObject>(body: T): Promise<EconomyObjectResponse<T>>;
    createContributionAcceptance<T extends JsonObject = JsonObject>(body: T): Promise<EconomyObjectResponse<T>>;
    createBailmentTerms<T extends JsonObject = JsonObject>(body: T): Promise<EconomyObjectResponse<T>>;
    createBailmentWrapper<T extends JsonObject = JsonObject>(body: T): Promise<EconomyObjectResponse<T>>;
    createAdoptionEvent<T extends JsonObject = JsonObject>(body: T): Promise<EconomyObjectResponse<T>>;
    createUseEvent<T extends JsonObject = JsonObject>(body: T): Promise<EconomyObjectResponse<T>>;
    createValueEvent<T extends JsonObject = JsonObject>(body: T): Promise<EconomyObjectResponse<T>>;
    createMissionSettlement(body: MissionSettlementRequest): Promise<EconomyObjectResponse>;
    createAutomatedSettlement(body: AutomatedSettlementRequest): Promise<EconomyObjectResponse>;
}
/** High-level client combining all domain APIs over a shared transport. */
export declare class ExochainClient {
    #private;
    readonly identity: IdentityApi;
    readonly consent: ConsentApi;
    readonly governance: GovernanceApi;
    readonly authority: AuthorityApi;
    readonly economy: EconomyApi;
    constructor(opts: ExochainClientOptions);
    /** Gateway health probe. */
    health(): Promise<HealthResponse>;
}
//# sourceMappingURL=client.d.ts.map