/**
 * Core type definitions for the EXOCHAIN SDK.
 *
 * Branded primitive aliases (`Did`, `Hash256`) make it impossible to confuse a
 * validated DID or hash with an arbitrary `string`. They are structural only
 * — there is no runtime tag, so validation happens at the boundary via the
 * factory functions in {@link ./identity/did.ts} and {@link ./crypto/hash.ts}.
 */
/** A validated `did:exo:` identifier. Construct with `validateDid`. */
export type Did = string & {
    readonly __did: unique symbol;
};
/** A 64-character lowercase hex string representing 32 bytes. */
export type Hash256 = string & {
    readonly __hash256: unique symbol;
};
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
/** EXOCHAIN economy object kinds stored behind the HonorGood adapter routes. */
export type EconomyObjectKind = 'mission' | 'contribution_receipt' | 'legacy_receipt' | 'honorgood_ruleset' | 'value_contribution_node' | 'contribution_offer' | 'contribution_acceptance' | 'bailment_terms' | 'bailment_wrapper' | 'adoption_event' | 'use_event' | 'value_event' | 'mission_settlement' | 'automated_settlement_event';
/** Hash-linked anchor returned when EXOCHAIN records an economy object. */
export interface EconomyRecordAnchor {
    readonly anchor_hash: Hash256;
    readonly previous_anchor_hash: Hash256;
    readonly object_kind: EconomyObjectKind;
    readonly object_id: Hash256;
    readonly object_hash: Hash256;
    readonly created_at: unknown;
}
/** Generic response shape for economy object creation routes. */
export interface EconomyObjectResponse<T = unknown> {
    readonly object: T;
    readonly anchor: EconomyRecordAnchor;
}
/** Request body for deterministic mission settlement creation. */
export interface MissionSettlementRequest {
    readonly mission_id: Hash256;
    readonly ruleset_id: Hash256;
    readonly gross_revenue_micro_exo: string | number;
    readonly pass_through_expenses_micro_exo: string | number;
    readonly zero_fee_reason?: string | null;
    readonly prev_settlement_hash?: Hash256 | null;
    readonly created_at: unknown;
}
/** Request body for deterministic automated value-for-value settlement. */
export interface AutomatedSettlementRequest {
    readonly value_event_id: Hash256;
    readonly automation_authority_ref: unknown;
    readonly preapproved_terms_hash: Hash256;
    readonly basis_amounts: Record<string, string | number>;
    readonly zero_fee_reason?: string | null;
    readonly preconditions: unknown;
    readonly created_at_hlc: unknown;
}
//# sourceMappingURL=types.d.ts.map