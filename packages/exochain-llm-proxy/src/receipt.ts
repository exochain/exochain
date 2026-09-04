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

import {
  assertNoForbiddenReceiptMaterial,
  LynkConfigurationError,
} from "./evidence.js";
import type {
  LlmProxyConfig,
  ReceiptEmissionResult,
  ReceiptIntent,
  ReceiptPending,
} from "./types.js";
import { fetchBoundedResponse, parseBoundedJson } from "./http.js";
import {
  LYNK_RECEIPT_RESPONSE_ATTESTATION_DOMAIN,
  LYNK_RECEIPT_RESPONSE_ATTESTATION_SCHEMA_VERSION,
  assertJsonUnicodeScalars,
  verifyLynkReceiptResponseAttestation,
} from "./attestation.js";
import {
  encodeReceiptIntentForWire,
  type ReceiptEmitWireRequest,
} from "./wire.js";
export { resolveFetch } from "./http.js";

export class ReceiptEmissionError extends Error {
  readonly statusCode?: number;
  readonly idempotencyKeyHash: string;
  readonly receiptIntent: ReceiptIntent;

  constructor(message: string, idempotencyKeyHash: string, receiptIntent: ReceiptIntent, statusCode?: number) {
    super(message);
    this.name = "ReceiptEmissionError";
    this.statusCode = statusCode;
    this.idempotencyKeyHash = idempotencyKeyHash;
    this.receiptIntent = receiptIntent;
  }
}

type JsonRecord = Record<string, unknown>;

const CANONICAL_HASH = /^[0-9a-f]{64}$/;
const ZERO_HASH = "0".repeat(64);
const LLM_USAGE_ACTION_NAME = "llm.usage.receipt.emit";
const LLM_USAGE_EVIDENCE_DOMAIN = "exo.avc.lynk.llm_usage.evidence.v1";
const MAX_ML_DSA_65_SIGNATURE_BYTES = 3_309;

export function receiptPendingFromError(error: ReceiptEmissionError): ReceiptPending {
  return {
    status: "receipt_pending",
    idempotencyKeyHash: error.idempotencyKeyHash,
    receiptIntent: error.receiptIntent,
  };
}

export async function emitUsageReceipt(
  config: LlmProxyConfig,
  receiptIntent: ReceiptIntent,
): Promise<ReceiptEmissionResult> {
  requireProductionValidatorTrust(config);
  assertNoForbiddenReceiptMaterial(receiptIntent);
  let requestBody: string;
  let attestedRequest: ReceiptEmitWireRequest;
  try {
    const wireRequest = encodeReceiptIntentForWire(receiptIntent);
    const serialized = JSON.stringify(wireRequest);
    if (typeof serialized !== "string") {
      throw new Error("LYNK receipt request did not serialize to JSON");
    }
    requestBody = serialized;
    // Attestation verification must read the exact JSON value sent on the
    // wire, not the still-live input object. This defeats toJSON, getter,
    // proxy, and post-fetch mutation differences.
    attestedRequest = JSON.parse(serialized) as ReceiptEmitWireRequest;
    assertJsonUnicodeScalars(attestedRequest);
    if (JSON.stringify(attestedRequest) !== serialized) {
      throw new Error("LYNK receipt request JSON is not in canonical transport form");
    }
  } catch {
    throw new ReceiptEmissionError(
      "EXOCHAIN LYNK receipt intent was malformed or not wire-compatible",
      receiptIntent.llm_usage_evidence.evidence.idempotency_key_hash,
      receiptIntent,
    );
  }
  const endpoint = `${config.gatewayUrl.replace(/\/+$/, "")}/api/v1/avc/llm-usage/receipts/emit`;
  const bounded = await fetchBoundedResponse(
    config,
    endpoint,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: requestBody,
    },
    "EXOCHAIN receipt response",
  );
  const { response } = bounded;
  if (!response.ok) {
    throw new ReceiptEmissionError(
      "EXOCHAIN LYNK receipt emission failed",
      receiptIntent.llm_usage_evidence.evidence.idempotency_key_hash,
      receiptIntent,
      response.status,
    );
  }
  try {
    const payload = parseBoundedJson(bounded, "EXOCHAIN receipt response");
    return await validateCommittedReceiptResponse(
      payload,
      receiptIntent,
      config,
      attestedRequest,
    );
  } catch {
    throw new ReceiptEmissionError(
      "EXOCHAIN LYNK receipt response was malformed or untrusted",
      receiptIntent.llm_usage_evidence.evidence.idempotency_key_hash,
      receiptIntent,
      response.status,
    );
  }
}

export function requireProductionValidatorTrust(config: LlmProxyConfig): void {
  if (config.mode !== "production") {
    return;
  }
  if (
    typeof config.trustedValidatorDid !== "string"
    || !/^did:[a-z0-9]+:[^\s]+$/.test(config.trustedValidatorDid)
  ) {
    throw new LynkConfigurationError(
      "production LYNK receipt release requires trustedValidatorDid",
    );
  }
  if (
    typeof config.trustedValidatorPublicKey !== "string"
    || !/^[0-9a-f]{64}$/.test(config.trustedValidatorPublicKey)
    || /^0+$/.test(config.trustedValidatorPublicKey)
  ) {
    throw new LynkConfigurationError(
      "production LYNK receipt release requires a canonical nonzero trustedValidatorPublicKey",
    );
  }
}

export async function resolveReceiptPending(
  config: LlmProxyConfig,
  pending: ReceiptPending,
): Promise<ReceiptEmissionResult> {
  return emitUsageReceipt(config, pending.receiptIntent);
}

async function validateCommittedReceiptResponse(
  payload: unknown,
  receiptIntent: ReceiptIntent,
  config: LlmProxyConfig,
  wireRequest: ReceiptEmitWireRequest,
): Promise<ReceiptEmissionResult> {
  const response = requireRecord(payload);
  requireExactKeys(response, [
    "receipt_hash",
    "exochain_finality_hash",
    "exochain_finality_height",
    "exochain_finality_receipt_hash",
    "receipt",
    "validation",
    "lynk_response_attestation",
  ]);
  const receiptHash = requireHashString(response.receipt_hash);
  const finalityHash = requireHashString(response.exochain_finality_hash);
  const finalityReceiptHash = requireHashString(response.exochain_finality_receipt_hash);
  if (
    receiptHash === finalityHash
    || receiptHash === finalityReceiptHash
    || finalityHash === finalityReceiptHash
  ) {
    throw new Error("receipt and finality hashes must identify distinct commitments");
  }
  if (
    !Number.isSafeInteger(response.exochain_finality_height)
    || (response.exochain_finality_height as number) <= 0
  ) {
    throw new Error("receipt finality height must be a positive safe integer");
  }

  const receipt = requireRecord(response.receipt);
  requireExactKeys(
    receipt,
    [
      "schema_version",
      "receipt_id",
      "credential_id",
      "action_id",
      "action_commitment_hash",
      "action_descriptor",
      "action_descriptor_hash",
      "llm_usage_evidence_hash",
      "previous_receipt_hash",
      "timestamp_provenance",
      "external_timestamp_proof",
      "validator_did",
      "decision",
      "reason_codes",
      "created_at",
      "validation_hash",
      "signature",
    ],
  );
  if (requireHashBytes(receipt.receipt_id) !== receiptHash) {
    throw new Error("receipt hash does not bind the returned receipt");
  }
  const credentialHash = requireHashBytes(receipt.credential_id);
  const evidence = receiptIntent.llm_usage_evidence.evidence;
  if (requireHashBytes(receipt.action_id) !== evidence.action_id) {
    throw new Error("receipt action does not bind the submitted evidence");
  }
  requireHashBytes(receipt.action_commitment_hash);
  requireHashBytes(receipt.action_descriptor_hash);
  requireHashBytes(receipt.llm_usage_evidence_hash);
  requireOptionalHashBytes(receipt.previous_receipt_hash);
  requireHashBytes(receipt.validation_hash);
  requireTimestamp(receipt.created_at);
  requireWireSignature(receipt.signature);
  if (
    receipt.schema_version !== 1
    || receipt.decision !== "Allow"
    || !hasValidReason(receipt.reason_codes)
    || !isNonEmptyString(receipt.validator_did)
  ) {
    throw new Error("receipt proof fields were malformed or did not allow the action");
  }
  requireTimestampProvenance(receipt);

  const descriptor = requireRecord(receipt.action_descriptor);
  requireExactKeys(descriptor, [
    "schema_version",
    "action_id",
    "actor_did",
    "requested_permission",
    "tool",
    "target_did",
    "data_class",
    "estimated_budget_minor_units",
    "estimated_risk_bp",
    "requires_human_approval",
    "human_approval_present",
    "action_name",
  ]);
  const expectedDataClass = {
    receipt_minimized: "Internal",
    external_payload_ref: "Confidential",
    dagdb_custody: "Restricted",
  }[evidence.custody_mode];
  const expectedBudget = evidence.usage.cost_minor_units ?? null;
  if (
    descriptor.schema_version !== 1
    || requireHashBytes(descriptor.action_id) !== evidence.action_id
    || descriptor.actor_did !== evidence.actor_did
    || descriptor.requested_permission !== "Execute"
    || descriptor.tool !== LLM_USAGE_EVIDENCE_DOMAIN
    || descriptor.target_did !== null
    || descriptor.data_class !== expectedDataClass
    || descriptor.estimated_budget_minor_units !== expectedBudget
    || descriptor.estimated_risk_bp !== null
    || descriptor.requires_human_approval !== false
    || descriptor.human_approval_present !== false
    || descriptor.action_name !== LLM_USAGE_ACTION_NAME
  ) {
    throw new Error("receipt descriptor does not bind the submitted evidence");
  }

  const validation = requireRecord(response.validation);
  requireExactKeys(validation, [
    "credential_id",
    "decision",
    "reason_codes",
    "normalized_holder_did",
    "valid_until",
    "receipt",
  ]);
  if (
    requireHashBytes(validation.credential_id) !== credentialHash
    || validation.decision !== "Allow"
    || !hasValidReason(validation.reason_codes)
    || validation.normalized_holder_did !== evidence.actor_did
  ) {
    throw new Error("receipt validation does not bind an allowed credential");
  }
  if (validation.valid_until !== null) {
    requireTimestamp(validation.valid_until);
  }
  if (validation.receipt !== null) {
    throw new Error("LYNK receipt validation must not contain a nested receipt");
  }

  const attestation = requireRecord(response.lynk_response_attestation);
  requireExactKeys(attestation, ["domain", "schema_version", "validator_did", "signature"]);
  if (
    attestation.domain !== LYNK_RECEIPT_RESPONSE_ATTESTATION_DOMAIN
    || attestation.schema_version !== LYNK_RECEIPT_RESPONSE_ATTESTATION_SCHEMA_VERSION
    || !isNonEmptyString(attestation.validator_did)
    || attestation.validator_did !== receipt.validator_did
  ) {
    throw new Error("LYNK response attestation identity or version was invalid");
  }
  const attestationSignature = requireEd25519Signature(attestation.signature);
  await verifyLynkReceiptResponseAttestation(
    config,
    {
      receiptHash,
      finalityHash,
      finalityHeight: response.exochain_finality_height as number,
      finalityReceiptHash,
      receipt,
      validation,
      request: wireRequest,
      validatorDid: attestation.validator_did,
    },
    attestationSignature,
  );

  return {
    receipt_hash: receiptHash,
    exochain_finality_hash: finalityHash,
    exochain_finality_height: response.exochain_finality_height as number,
    exochain_finality_receipt_hash: finalityReceiptHash,
    receipt: copyJsonValue(receipt),
    validation: copyJsonValue(validation),
    lynk_response_attestation: {
      domain: LYNK_RECEIPT_RESPONSE_ATTESTATION_DOMAIN,
      schema_version: LYNK_RECEIPT_RESPONSE_ATTESTATION_SCHEMA_VERSION,
      validator_did: attestation.validator_did,
      signature: { Ed25519: [...attestationSignature] },
    },
  };
}

function requireExactKeys(
  value: JsonRecord,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  if (
    required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))
    || keys.some((key) => !allowed.has(key))
  ) {
    throw new Error("JSON object did not match the exact LYNK response schema");
  }
}

function requireRecord(value: unknown): JsonRecord {
  if (!isRecord(value)) {
    throw new Error("expected a JSON object");
  }
  return value;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function requireHashString(value: unknown): string {
  if (typeof value !== "string" || !CANONICAL_HASH.test(value) || value === ZERO_HASH) {
    throw new Error("expected a canonical nonzero hash string");
  }
  return value;
}

function requireHashBytes(value: unknown): string {
  if (
    !Array.isArray(value)
    || value.length !== 32
    || !value.every((byte) => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255)
  ) {
    throw new Error("expected a canonical 32-byte nonzero hash");
  }
  const hash = value.map((byte) => (byte as number).toString(16).padStart(2, "0")).join("");
  if (hash === ZERO_HASH) {
    throw new Error("expected a canonical 32-byte nonzero hash");
  }
  return hash;
}

function requireOptionalHashBytes(value: unknown): void {
  if (value !== null) {
    requireHashBytes(value);
  }
}

function requireTimestamp(value: unknown): void {
  const timestamp = requireRecord(value);
  requireExactKeys(timestamp, ["physical_ms", "logical"]);
  if (
    !Number.isSafeInteger(timestamp.physical_ms)
    || (timestamp.physical_ms as number) < 0
    || !Number.isSafeInteger(timestamp.logical)
    || (timestamp.logical as number) < 0
  ) {
    throw new Error("expected a non-negative HLC timestamp");
  }
}

function requireTimestampProvenance(receipt: JsonRecord): void {
  if (receipt.timestamp_provenance === "LocalHybridLogicalClock") {
    if (receipt.external_timestamp_proof !== null) {
      throw new Error("local receipt timestamp must not carry an external proof");
    }
    return;
  }
  if (receipt.timestamp_provenance !== "ExternalTimestampAuthority") {
    throw new Error("receipt timestamp provenance was unsupported");
  }
  const proof = requireRecord(receipt.external_timestamp_proof);
  const isRfc3161 = proof.proof_kind === "Rfc3161";
  requireExactKeys(
    proof,
    ["authority_did", "subject_hash", "issued_at", "signature"],
    isRfc3161 ? ["proof_kind", "rfc3161"] : [],
  );
  if (!isNonEmptyString(proof.authority_did)) {
    throw new Error("external receipt timestamp authority was missing");
  }
  requireHashBytes(proof.subject_hash);
  requireTimestamp(proof.issued_at);
  const receiptTimestamp = requireRecord(receipt.created_at);
  const proofTimestamp = requireRecord(proof.issued_at);
  if (
    receiptTimestamp.physical_ms !== proofTimestamp.physical_ms
    || receiptTimestamp.logical !== proofTimestamp.logical
  ) {
    throw new Error("external timestamp proof does not bind the receipt timestamp");
  }
  if (proof.proof_kind === "Rfc3161") {
    if (proof.signature !== "Empty") {
      throw new Error("RFC 3161 timestamp proof was malformed");
    }
    requireRfc3161Proof(proof.rfc3161);
    return;
  }
  if (proof.proof_kind !== undefined || proof.rfc3161 !== undefined) {
    throw new Error("external timestamp proof kind was unsupported");
  }
  requireWireSignature(proof.signature);
}

function requireRfc3161Proof(value: unknown): void {
  const proof = requireRecord(value);
  requireExactKeys(
    proof,
    [
      "message_imprint_sha256_hex",
      "token_der_base64",
      "policy_oid",
      "serial_number_hex",
      "nonce_hex",
      "tsa_subject",
      "tsa_public_key_spki_der_hex",
    ],
    [
      "tsa_trust_anchor_kind",
      "tsa_trust_anchor_spki_der_hex",
      "tsa_issuer_subject",
    ],
  );
  if (
    !isCanonicalNonzeroHash(proof.message_imprint_sha256_hex)
    || !isNonEmptyString(proof.token_der_base64)
    || !isNonEmptyString(proof.policy_oid)
    || !isEvenLowerHex(proof.serial_number_hex)
    || !isEvenLowerHex(proof.nonce_hex)
    || !isNonEmptyString(proof.tsa_subject)
    || !isEvenLowerHex(proof.tsa_public_key_spki_der_hex)
  ) {
    throw new Error("RFC 3161 timestamp fields were malformed");
  }
  if (
    proof.tsa_trust_anchor_kind !== undefined
    && proof.tsa_trust_anchor_kind !== "signer_spki"
    && proof.tsa_trust_anchor_kind !== "issuing_ca_spki"
  ) {
    throw new Error("RFC 3161 trust anchor kind was unsupported");
  }
  if (
    proof.tsa_trust_anchor_spki_der_hex !== undefined
    && !isEvenLowerHex(proof.tsa_trust_anchor_spki_der_hex)
  ) {
    throw new Error("RFC 3161 trust anchor key was malformed");
  }
  if (
    proof.tsa_issuer_subject !== undefined
    && !isNonEmptyString(proof.tsa_issuer_subject)
  ) {
    throw new Error("RFC 3161 issuer subject was malformed");
  }
}

function isCanonicalNonzeroHash(value: unknown): boolean {
  return typeof value === "string" && CANONICAL_HASH.test(value) && value !== ZERO_HASH;
}

function isEvenLowerHex(value: unknown): boolean {
  return (
    typeof value === "string"
    && value.length > 0
    && value.length % 2 === 0
    && /^[0-9a-f]+$/.test(value)
  );
}

function requireWireSignature(value: unknown): void {
  const signature = requireRecord(value);
  if (Object.keys(signature).length !== 1) {
    throw new Error("signature must contain exactly one variant");
  }
  if (Object.prototype.hasOwnProperty.call(signature, "Ed25519")) {
    requireByteArray(signature.Ed25519, 64, 64, true);
    return;
  }
  if (Object.prototype.hasOwnProperty.call(signature, "PostQuantum")) {
    requireByteArray(signature.PostQuantum, 1, MAX_ML_DSA_65_SIGNATURE_BYTES, false);
    return;
  }
  if (Object.prototype.hasOwnProperty.call(signature, "Hybrid")) {
    const hybrid = requireRecord(signature.Hybrid);
    if (Object.keys(hybrid).length !== 2) {
      throw new Error("hybrid signature must contain classical and pq fields");
    }
    requireByteArray(hybrid.classical, 64, 64, true);
    requireByteArray(hybrid.pq, 1, MAX_ML_DSA_65_SIGNATURE_BYTES, false);
    return;
  }
  throw new Error("unsupported signature variant");
}

function requireEd25519Signature(value: unknown): number[] {
  const signature = requireRecord(value);
  requireExactKeys(signature, ["Ed25519"]);
  requireByteArray(signature.Ed25519, 64, 64, true);
  return [...signature.Ed25519 as number[]];
}

function requireByteArray(
  value: unknown,
  minimumLength: number,
  maximumLength: number,
  rejectAllZero: boolean,
): void {
  if (
    !Array.isArray(value)
    || value.length < minimumLength
    || value.length > maximumLength
    || !value.every((byte) => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255)
    || (rejectAllZero && value.every((byte) => byte === 0))
  ) {
    throw new Error("signature bytes were malformed or empty");
  }
}

function hasValidReason(value: unknown): boolean {
  return Array.isArray(value) && value.length === 1 && value[0] === "Valid";
}

function copyJsonValue(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("cannot copy a non-integer LYNK response value");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(copyJsonValue);
  }
  if (isRecord(value)) {
    const copied: JsonRecord = {};
    for (const key of Object.keys(value)) {
      copied[key] = copyJsonValue(value[key]);
    }
    return copied;
  }
  throw new Error("cannot copy an unsupported LYNK response value");
}
