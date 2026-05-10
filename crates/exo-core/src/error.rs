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

//! Error types for the EXOCHAIN constitutional trust fabric.
//!
//! Every failure mode in the system has a dedicated variant ensuring
//! exhaustive error handling at compile time.

use thiserror::Error;

/// Unified error type for all `exo-core` operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExoError {
    /// A BCTS state transition was requested that violates the state machine rules.
    #[error("invalid transition from {from} to {to}")]
    InvalidTransition { from: String, to: String },

    /// A cryptographic signature failed verification.
    #[error("invalid signature: {reason}")]
    InvalidSignature { reason: String },

    /// A DID string did not conform to the required format.
    #[error("invalid DID: {value}")]
    InvalidDid { value: String },

    /// The HLC detected backward drift beyond acceptable tolerance.
    #[error("clock drift detected: physical={physical_ms}ms, tolerance={tolerance_ms}ms")]
    ClockDrift { physical_ms: u64, tolerance_ms: u64 },

    /// The HLC cannot advance because the timestamp space is exhausted.
    #[error("clock overflow: cannot advance past physical={physical_ms}ms logical={logical}")]
    ClockOverflow { physical_ms: u64, logical: u32 },

    /// The HLC wall-clock source could not produce a trustworthy timestamp.
    #[error("clock unavailable: {reason}")]
    ClockUnavailable { reason: String },

    /// A hash did not match the expected value.
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// The actor does not have authority for the requested operation.
    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    /// An operation requires consent that has not been granted.
    #[error("consent required: {scope}")]
    ConsentRequired { scope: String },

    /// A system invariant was violated.
    #[error("invariant violation: {description}")]
    InvariantViolation { description: String },

    /// Sybil-resistant identity verification failed.
    #[error("sybil detected: {evidence}")]
    SybilDetected { evidence: String },

    /// Serialization / deserialization failure.
    #[error("serialization error: {reason}")]
    SerializationError { reason: String },

    /// Cryptographic key generation or usage error.
    #[error("crypto error: {reason}")]
    CryptoError { reason: String },

    /// Merkle proof verification failed.
    #[error("invalid merkle proof")]
    InvalidMerkleProof,

    /// Receipt chain integrity check failed.
    #[error("receipt chain integrity failure at index {index}")]
    ReceiptChainBroken { index: usize },

    /// Entity not found.
    #[error("not found: {entity}")]
    NotFound { entity: String },
}

/// Convenient Result alias used throughout `exo-core`.
pub type Result<T> = std::result::Result<T, ExoError>;

impl ExoError {
    /// Returns `true` when this error indicates a security-relevant failure.
    #[must_use]
    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            ExoError::InvalidSignature { .. }
                | ExoError::Unauthorized { .. }
                | ExoError::SybilDetected { .. }
                | ExoError::HashMismatch { .. }
                | ExoError::ClockUnavailable { .. }
        )
    }
}

impl<T> From<ciborium::ser::Error<T>> for ExoError {
    fn from(e: ciborium::ser::Error<T>) -> Self {
        let reason = match e {
            ciborium::ser::Error::Io(_) => "CBOR serialization I/O error",
            ciborium::ser::Error::Value(_) => "CBOR serialization value error",
        };
        ExoError::SerializationError {
            reason: reason.into(),
        }
    }
}

impl<T> From<ciborium::de::Error<T>> for ExoError {
    fn from(e: ciborium::de::Error<T>) -> Self {
        let reason = match e {
            ciborium::de::Error::Io(_) => "CBOR deserialization I/O error",
            ciborium::de::Error::Syntax(_) => "CBOR deserialization syntax error",
            ciborium::de::Error::Semantic(_, _) => "CBOR deserialization semantic error",
            ciborium::de::Error::RecursionLimitExceeded => {
                "CBOR deserialization recursion limit exceeded"
            }
        };
        ExoError::SerializationError {
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_all_variants() {
        let cases: Vec<(ExoError, &str)> = vec![
            (
                ExoError::InvalidTransition {
                    from: "Draft".into(),
                    to: "Closed".into(),
                },
                "Draft",
            ),
            (
                ExoError::InvalidSignature {
                    reason: "bad bytes".into(),
                },
                "bad bytes",
            ),
            (
                ExoError::InvalidDid {
                    value: "garbage".into(),
                },
                "garbage",
            ),
            (
                ExoError::ClockDrift {
                    physical_ms: 5000,
                    tolerance_ms: 1000,
                },
                "5000",
            ),
            (
                ExoError::ClockUnavailable {
                    reason: "clock source failed".into(),
                },
                "clock source failed",
            ),
            (
                ExoError::HashMismatch {
                    expected: "aaa".into(),
                    actual: "bbb".into(),
                },
                "aaa",
            ),
            (
                ExoError::Unauthorized {
                    reason: "no role".into(),
                },
                "no role",
            ),
            (
                ExoError::ConsentRequired {
                    scope: "data-share".into(),
                },
                "data-share",
            ),
            (
                ExoError::InvariantViolation {
                    description: "bad state".into(),
                },
                "bad state",
            ),
            (
                ExoError::SybilDetected {
                    evidence: "dup key".into(),
                },
                "dup key",
            ),
            (
                ExoError::SerializationError {
                    reason: "cbor fail".into(),
                },
                "cbor fail",
            ),
            (
                ExoError::CryptoError {
                    reason: "rng fail".into(),
                },
                "rng fail",
            ),
            (ExoError::InvalidMerkleProof, "invalid merkle proof"),
            (ExoError::ReceiptChainBroken { index: 3 }, "3"),
            (
                ExoError::NotFound {
                    entity: "item".into(),
                },
                "item",
            ),
        ];
        for (e, expected_substr) in cases {
            assert!(e.to_string().contains(expected_substr), "failed for: {e:?}");
        }
    }

    #[test]
    fn is_security_relevant_positive() {
        assert!(ExoError::InvalidSignature { reason: "x".into() }.is_security_relevant());
        assert!(ExoError::Unauthorized { reason: "x".into() }.is_security_relevant());
        assert!(
            ExoError::SybilDetected {
                evidence: "x".into()
            }
            .is_security_relevant()
        );
        assert!(
            ExoError::HashMismatch {
                expected: "a".into(),
                actual: "b".into()
            }
            .is_security_relevant()
        );
        assert!(ExoError::ClockUnavailable { reason: "x".into() }.is_security_relevant());
    }

    #[test]
    fn is_security_relevant_negative() {
        assert!(!ExoError::InvalidDid { value: "x".into() }.is_security_relevant());
        assert!(
            !ExoError::ClockDrift {
                physical_ms: 1,
                tolerance_ms: 1
            }
            .is_security_relevant()
        );
        assert!(!ExoError::InvalidMerkleProof.is_security_relevant());
        assert!(
            !ExoError::InvariantViolation {
                description: "x".into()
            }
            .is_security_relevant()
        );
        assert!(!ExoError::NotFound { entity: "x".into() }.is_security_relevant());
    }

    #[test]
    fn clone_eq_debug() {
        let e1 = ExoError::InvalidMerkleProof;
        let e2 = e1.clone();
        assert_eq!(e1, e2);
        let dbg = format!("{e1:?}");
        assert!(dbg.contains("InvalidMerkleProof"));
    }

    #[test]
    fn cbor_error_conversion_redacts_underlying_debug_details() {
        struct LeakyIoError;

        impl core::fmt::Debug for LeakyIoError {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("tenant-secret-token")
            }
        }

        let serialized: ExoError = ciborium::ser::Error::Io(LeakyIoError).into();
        let deserialized: ExoError = ciborium::de::Error::Io(LeakyIoError).into();

        for error in [serialized, deserialized] {
            let ExoError::SerializationError { reason } = error else {
                panic!("expected serialization error");
            };
            assert!(
                !reason.contains("tenant-secret-token"),
                "underlying debug details must not be exposed in public error text: {reason}"
            );
        }
    }

    #[test]
    fn result_alias() {
        let ok: Result<u32> = Ok(42);
        assert!(ok.is_ok());
        if let Ok(val) = ok {
            assert_eq!(val, 42);
        }
    }

    #[test]
    fn error_trait_source_is_none() {
        use std::error::Error;
        let e = ExoError::InvalidMerkleProof;
        assert!(e.source().is_none());
    }
}
