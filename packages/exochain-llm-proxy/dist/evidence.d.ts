import type { EncryptedPayloadRef, LlmProxyConfig, LlmUsageEvidence, ProviderUsageMetrics, ReceiptIntent, UsageContext } from "./types.js";
export declare const AVC_SCHEMA_VERSION = 1;
export declare const ZERO_HASH: string;
export declare const LYNK_EVIDENCE_DOMAIN = "exo.avc.lynk.llm_usage.evidence.v1";
export declare class LynkConfigurationError extends Error {
    constructor(message: string);
}
export declare class LynkValidationError extends Error {
    constructor(message: string);
}
export declare function stableStringify(value: unknown): string;
export declare function hashProviderPayload(payload: unknown): string;
export declare function hashBytes(bytes: Uint8Array): string;
export declare function textBytes(value: string): Uint8Array;
export declare function assertUsageMetrics(usage: ProviderUsageMetrics): void;
export declare function buildLlmUsageEvidence(config: LlmProxyConfig, context: UsageContext): LlmUsageEvidence;
export declare function buildLlmUsageReceiptIntent(config: LlmProxyConfig, context: UsageContext): Promise<ReceiptIntent>;
export declare function maybeStoreExternalPayloads(config: LlmProxyConfig, payloads: Array<{
    payloadKind: string;
    payload: unknown;
}>): Promise<EncryptedPayloadRef[]>;
export declare function assertNoForbiddenReceiptMaterial(value: unknown): void;
//# sourceMappingURL=evidence.d.ts.map