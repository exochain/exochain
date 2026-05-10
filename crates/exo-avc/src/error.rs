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

//! Error types for the AVC layer.

use thiserror::Error;

/// Errors arising from AVC operations.
///
/// Every variant carries enough context to diagnose the failure without
/// access to the source code. Validation denials are not errors — they
/// flow through `AvcDecision::Deny` with reason codes. Errors here cover
/// structural, cryptographic, and registry failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AvcError {
    /// Canonical CBOR encoding for an AVC payload failed.
    #[error("AVC serialization failed: {reason}")]
    Serialization { reason: String },

    /// Required string field was empty after trimming.
    #[error("AVC field `{field}` must not be empty")]
    EmptyField { field: &'static str },

    /// Schema version is not supported by this binary.
    #[error("AVC schema version {got} is unsupported (supported: {supported})")]
    UnsupportedSchema { got: u16, supported: u16 },

    /// A basis point value was outside the legal `0..=10_000` range.
    #[error("AVC basis point field `{field}` value {value} exceeds 10_000")]
    BasisPointOutOfRange { field: &'static str, value: u32 },

    /// A timestamp invariant was violated (e.g. expired-on-issue).
    #[error("AVC timestamp invariant violated: {reason}")]
    InvalidTimestamp { reason: String },

    /// Delegation widened scope of any kind.
    #[error("AVC delegation rejected: scope widened in `{dimension}`")]
    DelegationWidens { dimension: &'static str },

    /// Delegation chain was rejected for a non-widening structural reason.
    #[error("AVC delegation rejected: {reason}")]
    DelegationRejected { reason: String },

    /// Registry write conflict (e.g. duplicate revocation or unknown key).
    #[error("AVC registry error: {reason}")]
    Registry { reason: String },

    /// Invalid input was supplied to a public function.
    #[error("AVC invalid input: {reason}")]
    InvalidInput { reason: String },
}

impl<T> From<ciborium::ser::Error<T>> for AvcError {
    fn from(_: ciborium::ser::Error<T>) -> Self {
        AvcError::Serialization {
            reason: "CBOR serialization failed".into(),
        }
    }
}

impl<T> From<ciborium::de::Error<T>> for AvcError {
    fn from(_: ciborium::de::Error<T>) -> Self {
        AvcError::Serialization {
            reason: "CBOR deserialization failed".into(),
        }
    }
}

impl From<exo_core::ExoError> for AvcError {
    fn from(value: exo_core::ExoError) -> Self {
        match value {
            exo_core::ExoError::SerializationError { reason } => AvcError::Serialization { reason },
            other => AvcError::InvalidInput {
                reason: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_covers_every_variant() {
        let cases: Vec<AvcError> = vec![
            AvcError::Serialization {
                reason: "cbor".into(),
            },
            AvcError::EmptyField { field: "purpose" },
            AvcError::UnsupportedSchema {
                got: 99,
                supported: 1,
            },
            AvcError::BasisPointOutOfRange {
                field: "risk",
                value: 99_999,
            },
            AvcError::InvalidTimestamp {
                reason: "expired".into(),
            },
            AvcError::DelegationWidens {
                dimension: "permissions",
            },
            AvcError::DelegationRejected {
                reason: "depth".into(),
            },
            AvcError::Registry {
                reason: "missing".into(),
            },
            AvcError::InvalidInput {
                reason: "bad".into(),
            },
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.is_empty(), "error display empty for {err:?}");
        }
    }

    #[test]
    fn from_exo_error_serialization_preserves_reason() {
        let inner = exo_core::ExoError::SerializationError {
            reason: "boom".into(),
        };
        let mapped: AvcError = inner.into();
        match mapped {
            AvcError::Serialization { reason } => assert_eq!(reason, "boom"),
            other => panic!("expected Serialization, got {other:?}"),
        }
    }

    #[test]
    fn from_exo_error_other_maps_to_invalid_input() {
        let inner = exo_core::ExoError::InvalidMerkleProof;
        let mapped: AvcError = inner.into();
        match mapped {
            AvcError::InvalidInput { reason } => assert!(reason.contains("invalid merkle proof")),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn ciborium_serialization_error_maps_to_serialization_variant() {
        let inner: ciborium::ser::Error<std::io::Error> = ciborium::ser::Error::Value("bad".into());
        let mapped: AvcError = inner.into();
        assert!(matches!(mapped, AvcError::Serialization { .. }));
    }

    #[test]
    fn ciborium_deserialization_error_maps_to_serialization_variant() {
        let inner: ciborium::de::Error<std::io::Error> =
            ciborium::de::Error::Semantic(None, "bad".into());
        let mapped: AvcError = inner.into();
        assert!(matches!(mapped, AvcError::Serialization { .. }));
    }

    #[test]
    fn clone_eq_debug() {
        let a = AvcError::EmptyField { field: "purpose" };
        let b = a.clone();
        assert_eq!(a, b);
        assert!(format!("{a:?}").contains("EmptyField"));
    }
}
