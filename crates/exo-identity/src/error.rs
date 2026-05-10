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

//! Identity-specific error types for the EXOCHAIN identity subsystem.

use exo_core::{Did, Timestamp};

/// Errors that can occur during identity operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("DID already registered: {0}")]
    DuplicateDid(Did),

    #[error(
        "DID registry capacity exceeded: max_documents={max_documents}, attempted_documents={attempted_documents}"
    )]
    RegistryCapacityExceeded {
        max_documents: usize,
        attempted_documents: usize,
    },

    #[error("DID document for {did} has invalid field {field}: {reason}")]
    InvalidDidDocumentField {
        did: String,
        field: String,
        reason: String,
    },

    #[error("DID document for {did} exceeds {field} bound: max={max}, actual={actual}")]
    DidDocumentFieldTooLarge {
        did: String,
        field: String,
        max: usize,
        actual: usize,
    },

    #[error("DID not found: {0}")]
    DidNotFound(Did),

    #[error("DID has been revoked: {0}")]
    DidRevoked(Did),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("non-monotonic timestamp for DID {did}: current={current}, proposed={proposed}")]
    NonMonotonicTimestamp {
        did: Did,
        current: Timestamp,
        proposed: Timestamp,
    },

    #[error("invalid revocation proof for DID: {0}")]
    InvalidRevocationProof(Did),

    #[error("revocation proof payload encoding failed for DID {did}: {reason}")]
    RevocationProofPayloadEncoding { did: Did, reason: String },

    #[error("key rotation proof payload encoding failed for DID {did}: {reason}")]
    KeyRotationProofPayloadEncoding { did: Did, reason: String },

    #[error("public key not found on DID: {0}")]
    KeyNotFound(Did),

    #[error("key already revoked")]
    KeyAlreadyRevoked,

    #[error("key already rotated")]
    KeyAlreadyRotated,

    #[error("invalid Shamir config: threshold={threshold}, shares={shares}")]
    InvalidShamirConfig { threshold: u8, shares: u8 },

    #[error(
        "invalid Shamir entropy: min_bytes={min_bytes}, got_bytes={got_bytes}, reason={reason}"
    )]
    InvalidShamirEntropy {
        min_bytes: usize,
        got_bytes: usize,
        reason: String,
    },

    #[error("Shamir input {field} exceeds deterministic encoding bound: max={max}, got={got}")]
    ShamirInputTooLarge {
        field: &'static str,
        max: u64,
        got: usize,
    },

    #[error("insufficient shares: need {need}, got {got}")]
    InsufficientShares { need: u8, got: u8 },

    #[error("invalid share index: {0}")]
    InvalidShareIndex(u8),

    #[error("share index {index} exceeds configured share count {shares}")]
    ShareIndexOutOfRange { index: u8, shares: u8 },

    #[error("invalid share length for index {index}: expected {expected}, got {got}")]
    InvalidShareLength {
        index: u8,
        expected: usize,
        got: usize,
    },

    #[error("share commitment mismatch at index {index}: expected {expected:?}, got {got:?}")]
    ShareCommitmentMismatch {
        index: u8,
        expected: [u8; 32],
        got: [u8; 32],
    },

    #[error("reconstructed secret commitment mismatch: expected {expected:?}, got {got:?}")]
    ReconstructedSecretCommitmentMismatch { expected: [u8; 32], got: [u8; 32] },

    #[error(
        "invalid share value at index {index}, byte {byte_index}: expected {expected}, got {got}"
    )]
    InvalidShareValue {
        index: u8,
        byte_index: usize,
        expected: u8,
        got: u8,
    },

    #[error("duplicate share indices")]
    DuplicateShareIndices,

    #[error("invalid PACE config: {0}")]
    InvalidPaceConfig(String),

    #[error("cannot escalate: already at maximum level")]
    CannotEscalate,

    #[error("cannot de-escalate: already at Normal")]
    CannotDeescalate,

    #[error("risk attestation expired")]
    AttestationExpired,

    #[error("risk attestation signing payload encoding failed: {reason}")]
    RiskAttestationSigningPayloadEncoding { reason: String },

    #[error(
        "risk attestation expiry overflow: now_physical_ms={now_physical_ms}, validity_ms={validity_ms}"
    )]
    RiskAttestationExpiryOverflow {
        now_physical_ms: u64,
        validity_ms: u64,
    },

    #[error("duplicate DID across PACE levels: {0}")]
    DuplicatePaceDid(Did),

    #[error("vault key derivation failed: {0}")]
    VaultKeyDerivationFailed(String),

    #[error("vault encryption requires a caller-supplied nonce")]
    VaultNonceRequired,

    #[error("invalid vault nonce: {reason}")]
    InvalidVaultNonce { reason: String },

    #[error("vault encryption failed: {0}")]
    VaultEncryptionFailed(String),

    #[error("vault decryption failed: authentication or ciphertext invalid")]
    VaultDecryptionFailed,

    #[error("vault ciphertext too short")]
    VaultCiphertextTooShort,
}
