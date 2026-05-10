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

//! SDK error types.
//!
//! All SDK operations that can fail return [`ExoResult<T>`], which is an alias
//! for [`std::result::Result<T, ExoError>`]. Each variant narrows the error to
//! a specific subsystem to aid programmatic handling — callers can
//! `match` on the variant rather than parsing the error string.
//!
//! # Examples
//!
//! ```
//! use exochain_sdk::consent::BailmentBuilder;
//! use exochain_sdk::error::ExoError;
//! use exo_core::Did;
//!
//! let a = Did::new("did:exo:a").expect("valid");
//! let b = Did::new("did:exo:b").expect("valid");
//! let err = BailmentBuilder::new(a, b).build().unwrap_err();
//! assert!(matches!(err, ExoError::Consent(_)));
//! ```

use thiserror::Error;

/// Errors that can be produced by the SDK.
///
/// Each variant corresponds to a subsystem of the SDK. Callers should prefer
/// matching on the variant over parsing the display string, which is intended
/// for human consumption only.
#[derive(Debug, Error)]
pub enum ExoError {
    /// An identity-related operation failed.
    ///
    /// Returned when DID derivation, key handling, or identity reconstruction
    /// encounters an unexpected condition. In practice the SDK derives DIDs
    /// deterministically, so this variant is rarely observed — it is
    /// reserved for future identity flows that could validate or reject
    /// caller-supplied material.
    #[error("identity error: {0}")]
    Identity(String),

    /// A consent/bailment-related operation failed.
    ///
    /// Returned by [`crate::consent::BailmentBuilder::build`] when required
    /// fields are missing (no scope, no duration) or invalid (empty scope,
    /// zero-hour duration).
    #[error("consent error: {0}")]
    Consent(String),

    /// A governance-related operation failed.
    ///
    /// Returned by [`crate::governance::DecisionBuilder::build`] for an
    /// empty title, and by [`crate::governance::Decision::cast_vote`] when
    /// the same voter tries to cast a second vote.
    #[error("governance error: {0}")]
    Governance(String),

    /// An authority-chain operation failed.
    ///
    /// Returned by [`crate::authority::AuthorityChainBuilder::build`] for any
    /// topology violation: an empty chain, a break in the grantor/grantee
    /// sequence between consecutive links, or a terminal mismatch.
    #[error("authority error: {0}")]
    Authority(String),

    /// The kernel denied an action.
    ///
    /// Reserved for flows that want to surface a kernel denial as a `Result`
    /// error rather than a `KernelVerdict::Denied` value. The SDK's
    /// [`crate::kernel::ConstitutionalKernel::adjudicate`] returns a verdict
    /// directly; this variant exists so higher-level wrappers can lift it
    /// into the error channel if they prefer.
    #[error("kernel denied: {0}")]
    KernelDenied(String),

    /// The kernel escalated an action for review.
    ///
    /// Counterpart to [`ExoError::KernelDenied`] for the escalation outcome.
    #[error("kernel escalated: {0}")]
    KernelEscalated(String),

    /// A cryptographic operation failed.
    ///
    /// Reserved for future crypto flows that could fail (e.g. signature
    /// parsing of untrusted input). The current BLAKE3 and Ed25519 wrappers
    /// in [`crate::crypto`] are infallible.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// A provided DID string is not valid.
    ///
    /// Returned when the SDK derives a DID whose method-specific string
    /// fails [`exo_core::Did`] validation. In practice BLAKE3-derived hex
    /// always satisfies the rules, so this variant is effectively
    /// unreachable; it is retained for completeness.
    #[error("invalid DID: {0}")]
    InvalidDid(String),

    /// Serialization or deserialization failed.
    ///
    /// Reserved for higher-level SDK flows that marshal wire payloads. The
    /// primitive `Serialize`/`Deserialize` implementations on SDK types use
    /// `serde_json::Error` directly; this variant lets downstream wrappers
    /// homogenise their error channel.
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Convenience alias for `Result<T, ExoError>`.
///
/// Every fallible SDK function returns this type.
///
/// # Examples
///
/// ```
/// use exochain_sdk::error::{ExoError, ExoResult};
///
/// fn pretend_work(ok: bool) -> ExoResult<u32> {
///     if ok { Ok(42) } else { Err(ExoError::Governance("nope".into())) }
/// }
/// assert_eq!(pretend_work(true).unwrap(), 42);
/// ```
pub type ExoResult<T> = std::result::Result<T, ExoError>;
