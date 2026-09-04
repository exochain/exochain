import type { LlmProxyConfig } from "./types.js";
import type { ReceiptEmitWireRequest } from "./wire.js";
export declare const LYNK_RECEIPT_RESPONSE_ATTESTATION_DOMAIN = "exo.avc.lynk.receipt_response.attestation.v1";
export declare const LYNK_RECEIPT_RESPONSE_ATTESTATION_SCHEMA_VERSION = 1;
type JsonRecord = Record<string, unknown>;
export interface LynkReceiptResponseAttestationInput {
    receiptHash: string;
    finalityHash: string;
    finalityHeight: number;
    finalityReceiptHash: string;
    receipt: JsonRecord;
    validation: JsonRecord;
    request: ReceiptEmitWireRequest;
    validatorDid: string;
}
export declare function assertJsonUnicodeScalars(value: unknown): void;
/**
 * Encode the exact signed LYNK response-attestation payload.
 *
 * Rust converts the same JSON value into recursively key-sorted
 * `ciborium::value::Value` maps before serialization. All object keys in this
 * schema are ASCII, so JavaScript lexical order and Rust UTF-8 byte order are
 * identical. Integers use CBOR's shortest-width representation.
 */
export declare function encodeLynkReceiptResponseAttestationPayload(input: LynkReceiptResponseAttestationInput): Uint8Array;
export declare function verifyLynkReceiptResponseAttestation(config: LlmProxyConfig, input: LynkReceiptResponseAttestationInput, signature: number[]): Promise<void>;
export {};
//# sourceMappingURL=attestation.d.ts.map