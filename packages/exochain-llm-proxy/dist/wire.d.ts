import type { EncryptedPayloadRef, LlmUsageEvidence, LlmUsageEvidenceEnvelope, ReceiptIntent } from "./types.js";
export type WireHash256 = number[];
export type WireSignature = {
    Ed25519: number[];
} | {
    PostQuantum: number[];
} | {
    Hybrid: {
        classical: number[];
        pq: number[];
    };
};
export interface WireEncryptedPayloadRef extends Omit<EncryptedPayloadRef, "ref_id_hash" | "ciphertext_hash" | "storage_policy_hash" | "key_policy_hash"> {
    ref_id_hash: WireHash256;
    ciphertext_hash: WireHash256;
    storage_policy_hash: WireHash256;
    key_policy_hash: WireHash256;
}
export interface WireLlmUsageEvidence extends Omit<LlmUsageEvidence, "provider_request_id_hash" | "session_id_hash" | "idempotency_key_hash" | "action_id" | "prompt_hash" | "completion_hash" | "tool_call_hash" | "tool_result_hash" | "encrypted_payload_refs" | "custody_policy_hash"> {
    provider_request_id_hash?: WireHash256;
    session_id_hash?: WireHash256;
    idempotency_key_hash: WireHash256;
    action_id: WireHash256;
    prompt_hash: WireHash256;
    completion_hash?: WireHash256;
    tool_call_hash?: WireHash256;
    tool_result_hash?: WireHash256;
    encrypted_payload_refs?: WireEncryptedPayloadRef[];
    custody_policy_hash: WireHash256;
}
export interface WireLlmUsageEvidenceEnvelope extends Omit<LlmUsageEvidenceEnvelope, "evidence"> {
    evidence: WireLlmUsageEvidence;
}
export interface ReceiptEmitWireRequest {
    validation: unknown;
    subject_signature: WireSignature;
    subject_public_key?: number[];
    llm_usage_evidence: WireLlmUsageEvidenceEnvelope;
    adapter_signature: WireSignature;
    adapter_public_key?: number[];
}
/**
 * Encode the stable, retryable LYNK receipt intent into the exact JSON shape
 * consumed by Rust's serde implementations. The logical intent intentionally
 * retains printable hex strings; only this transport copy uses byte arrays and
 * tagged signature variants.
 */
export declare function encodeReceiptIntentForWire(intent: ReceiptIntent): ReceiptEmitWireRequest;
//# sourceMappingURL=wire.d.ts.map