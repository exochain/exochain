import type { Did, EconomyObjectResponse, EconomyRecordAnchor, Hash256, HealthResponse, QuorumResult } from './types.js';
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | JsonObject;
export type JsonObject = {
    readonly [key: string]: JsonValue;
};
export declare function assertJsonObject(value: unknown, context: string): JsonObject;
export declare function validateHash256(value: unknown, context: string): Hash256;
export declare function validateHealthResponse(value: unknown): HealthResponse;
export declare function validateDidResponse(value: unknown, context: string): {
    did: Did;
};
export declare function validateHashResponse<K extends string>(value: unknown, key: K, context: string): {
    readonly [P in K]: Hash256;
};
export declare function validateQuorumResult(value: unknown, context: string): QuorumResult;
export declare function validateDecisionState(value: unknown): {
    readonly decisionId: Hash256;
    readonly status: string;
    readonly quorum?: QuorumResult;
};
export declare function validateEconomyRecordAnchor(value: unknown, context: string): EconomyRecordAnchor;
export declare function validateEconomyObjectResponse<T extends JsonObject = JsonObject>(value: unknown, context: string): EconomyObjectResponse<T>;
//# sourceMappingURL=validation.d.ts.map