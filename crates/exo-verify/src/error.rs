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

//! Errors returned by the offline receipt verifier.
//!
//! Every failed property has its own variant so a caller (and the negative
//! test suite) can tell tampered bytes, a wrong chain position, an unknown
//! signer and a bad or missing timestamp apart.

use thiserror::Error;

/// Offline verification failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// The bundle could not be decoded or is structurally invalid.
    #[error("malformed verification bundle: {reason}")]
    MalformedBundle { reason: String },

    /// The bundle uses a format version this verifier no longer accepts.
    /// Version 1 bundles lack the chain-binding proof paths; re-fetch the
    /// proof and build a version 2 bundle.
    #[error("unsupported receipt bundle version {format}; re-fetch the proof as a v2 bundle")]
    UnsupportedBundleVersion { format: String },

    /// The receipt predates issue #897 and lacks the material needed for
    /// offline level-3 verification. Legacy receipts never pass.
    #[error("legacy receipt cannot be verified offline: {missing}")]
    LegacyReceipt { missing: &'static str },

    /// Property 1: the stored validator signed bytes do not match the
    /// receipt's signed fields or its receipt ID.
    #[error("receipt signed bytes do not match the receipt: {reason}")]
    SignedBytesMismatch { reason: String },

    /// Property 1: the validator signature does not verify over the stored
    /// signed bytes.
    #[error("receipt validator signature is invalid")]
    ValidatorSignatureInvalid,

    /// Property 1: the subject (agent) attestation does not verify or does
    /// not bind to the receipt.
    #[error("subject attestation is invalid: {reason}")]
    SubjectAttestationInvalid { reason: String },

    /// Property 2: the inclusion proof is for a different receipt.
    #[error("inclusion proof is for a different receipt")]
    InclusionProofReceiptMismatch,

    /// Property 2: the proof does not place the receipt at the claimed
    /// position under the signed tree head.
    #[error("inclusion proof does not verify at position {position} of {tree_size}")]
    InclusionProofInvalid { position: u64, tree_size: u64 },

    /// Property 2: the position is not bound to the receipt chain: the leaf
    /// before the receipt is not its `previous_receipt_hash`, or the signed
    /// chain head is not the last leaf.
    #[error("inclusion proof is not bound to the receipt chain: {reason}")]
    ChainBindingInvalid { reason: String },

    /// Property 2: the tree head signature does not verify.
    #[error("receipt tree head signature is invalid")]
    TreeHeadSignatureInvalid,

    /// Property 2: the tree head was signed by a different validator than
    /// the receipt.
    #[error("receipt tree head validator does not match the receipt validator")]
    TreeHeadValidatorMismatch,

    /// Property 2: the tree head is for a different chain than the caller
    /// expects.
    #[error("receipt tree head is for a different chain than expected")]
    ChainIdMismatch,

    /// Property 2: the proof is not against the caller's latest trusted tree
    /// head (for example, the bundle predates a rollback). Re-fetch the
    /// proof against the latest head.
    #[error(
        "inclusion proof tree head (size {proof_tree_size}) differs from the latest trusted head (size {latest_tree_size}); sizes can match when the root, chain ID or signature differ"
    )]
    StaleTreeHead {
        proof_tree_size: u64,
        latest_tree_size: u64,
    },

    /// Property 3: the signer DID is not in the key bundle.
    #[error("signer {did} is not in the key bundle")]
    UnknownSigner { did: String },

    /// Property 3: the signer DID is in the bundle, but with another key.
    #[error("signer {did} used a key that does not match the key bundle")]
    SignerKeyMismatch { did: String },

    /// Property 3: the bundle entry does not grant the required role.
    #[error("signer {did} is not a registered {role} in the key bundle")]
    SignerRoleMismatch { did: String, role: &'static str },

    /// Property 3: the key was not valid at the time it signed.
    #[error("signer {did} key is not valid at the signing time")]
    SignerKeyNotValidAtTime { did: String },

    /// Property 3/4: the agent's signed time is later than the RFC 3161 time.
    #[error("subject signed time is after the RFC 3161 trusted time")]
    SubjectTimeAfterTrustedTime,

    /// Property 4: the receipt carries no RFC 3161 timestamp.
    #[error("receipt carries no RFC 3161 timestamp")]
    TimestampMissing,

    /// Property 4: the timestamp is not an RFC 3161 token (for example an
    /// operator-signed or local clock timestamp).
    #[error("receipt timestamp is not an RFC 3161 token: {kind}")]
    TimestampNotRfc3161 { kind: String },

    /// Property 4: the RFC 3161 token does not verify against the pinned
    /// timestamp authority.
    #[error("RFC 3161 timestamp is invalid: {reason}")]
    TimestampInvalid { reason: String },

    /// Property 4: the token is valid but does not cover this receipt.
    #[error("RFC 3161 timestamp does not cover this receipt: {reason}")]
    TimestampSubjectMismatch { reason: String },
}
