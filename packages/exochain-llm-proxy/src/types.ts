/*
 * Copyright 2026 Exochain Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface HlcTimestamp {
  physical_ms: number;
  logical: number;
}

export type StorageMode = "receipt_minimized" | "external_payload_ref" | "dagdb_custody";

export interface ProviderUsageMetrics {
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cached_input_tokens?: number;
  reasoning_tokens?: number;
  cost_minor_units?: number;
  cost_currency?: string;
  usage_complete: boolean;
}

export interface EncryptedPayloadRef {
  ref_id_hash: string;
  ciphertext_hash: string;
  storage_policy_hash: string;
  key_policy_hash: string;
  payload_kind: string;
  byte_length: number;
}

export interface LlmUsageEvidence {
  schema_version: number;
  tenant_id: string;
  namespace: string;
  actor_did: string;
  provider: string;
  provider_endpoint: string;
  model_id: string;
  provider_request_id_hash?: string;
  session_id_hash?: string;
  idempotency_key_hash: string;
  action_id: string;
  prompt_hash: string;
  completion_hash?: string;
  tool_call_hash?: string;
  tool_result_hash?: string;
  usage: ProviderUsageMetrics;
  custody_mode: StorageMode;
  encrypted_payload_refs: EncryptedPayloadRef[];
  custody_policy_hash: string;
  created_at: HlcTimestamp;
}

export interface LlmUsageEvidenceEnvelope {
  schema_version: number;
  adapter_did: string;
  issued_at: HlcTimestamp;
  evidence: LlmUsageEvidence;
}

export interface ReceiptIntent {
  validation: unknown;
  subject_signature: string;
  subject_public_key?: string;
  llm_usage_evidence: LlmUsageEvidenceEnvelope;
  adapter_signature: string;
  adapter_public_key?: string;
}

export interface ReceiptEmissionResult {
  receipt_hash?: string;
  receipt?: unknown;
  validation?: unknown;
  exochain_finality_hash?: string;
  exochain_finality_height?: number;
  exochain_finality_receipt_hash?: string;
}

export interface ReceiptPending {
  status: "receipt_pending";
  idempotencyKeyHash: string;
  receiptIntent: ReceiptIntent;
}

export interface ReceiptedSuccess<T> {
  status: "receipted";
  output: T;
  receipt: ReceiptEmissionResult;
  receiptIntent: ReceiptIntent;
}

export interface ProviderFailure {
  status: "provider_error";
  providerStatus: number;
  receipt?: ReceiptEmissionResult;
  receiptIntent: ReceiptIntent;
}

export interface ReceiptedDevelopmentBypass<T> {
  status: "development_unreceipted";
  output: T;
  receiptPending: ReceiptPending;
}

export type ReceiptedResult<T> =
  | ReceiptedSuccess<T>
  | ReceiptPending
  | ProviderFailure
  | ReceiptedDevelopmentBypass<T>;

export interface KmsEncryptRequest {
  payload: Uint8Array;
  payloadKind: string;
}

export interface KmsEncryptResult {
  ciphertext: Uint8Array | string;
  keyPolicyId: string;
}

export interface KmsLike {
  encrypt(request: KmsEncryptRequest): Promise<KmsEncryptResult>;
}

export interface ObjectStorePutRequest {
  payloadKind: string;
  ciphertext: Uint8Array;
}

export interface ObjectStorePutResult {
  refId: string;
  storagePolicyId: string;
}

export interface ObjectStoreLike {
  put(request: ObjectStorePutRequest): Promise<ObjectStorePutResult>;
}

export interface LlmProxyConfig {
  mode: "production" | "development";
  allowUnreceiptedOutputForDevelopment?: boolean;
  gatewayUrl: string;
  tenantId: string;
  namespace: string;
  actorDid: string;
  adapterDid: string;
  adapterPublicKey?: string;
  subjectPublicKey?: string;
  custodyPolicyHash: string;
  storageMode: StorageMode;
  requireCompleteUsage?: boolean;
  validation: unknown;
  subjectSignature: string;
  adapterSignature: string | ((envelope: LlmUsageEvidenceEnvelope) => Promise<string> | string);
  fetch?: FetchLike;
  objectStore?: ObjectStoreLike;
  kms?: KmsLike;
}

export interface UsageContext {
  provider: string;
  providerEndpoint: string;
  modelId: string;
  requestPayload: unknown;
  responsePayload?: unknown;
  toolCallPayload?: unknown;
  toolResultPayload?: unknown;
  providerRequestId?: string;
  sessionId?: string;
  idempotencyKey: string;
  actionId?: string;
  usage: ProviderUsageMetrics;
  createdAt: HlcTimestamp;
  issuedAt: HlcTimestamp;
  encryptedPayloadRefs?: EncryptedPayloadRef[];
}

export interface OpenAIProxyOptions {
  openAIBaseUrl: string;
  apiKey?: string;
}

export interface PerCallReceiptOptions {
  idempotencyKey: string;
  actionId?: string;
  createdAt: HlcTimestamp;
  issuedAt?: HlcTimestamp;
  sessionId?: string;
}

export interface McpProxyOptions {
  serverUrl?: string;
}

export interface McpToolCall {
  name: string;
  arguments?: unknown;
}
