//! Error types for the economy layer.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EconomyError {
    /// Canonical CBOR encoding of an economy payload failed.
    #[error("economy serialization failed: {reason}")]
    Serialization { reason: String },

    /// Required string field was empty after trimming.
    #[error("economy field `{field}` must not be empty")]
    EmptyField { field: &'static str },

    /// A basis point value was outside the legal range.
    #[error("economy basis point field `{field}` value {value} exceeds {max}")]
    BasisPointOutOfRange {
        field: &'static str,
        value: u32,
        max: u32,
    },

    /// Policy floor exceeded ceiling.
    #[error("economy policy floor {floor} exceeds ceiling {ceiling}")]
    FloorAboveCeiling { floor: u128, ceiling: u128 },

    /// Quote referenced an unknown policy.
    #[error("economy policy not found: {policy_id}")]
    UnknownPolicy { policy_id: String },

    /// Quote could not be located for settlement.
    #[error("economy quote not found")]
    QuoteNotFound,

    /// Quote has expired and cannot be settled.
    #[error("economy quote expired")]
    QuoteExpired,

    /// Settlement receipt was rejected due to a hash mismatch.
    #[error("economy receipt hash mismatch")]
    ReceiptHashMismatch,

    /// Quote hash mismatched the recomputed canonical value.
    #[error("economy quote hash mismatch")]
    QuoteHashMismatch,

    /// Revenue share basis points summed to more than 10_000.
    #[error("economy revenue share sum {sum} exceeds 10_000 basis points")]
    RevenueShareOverAllocated { sum: u32 },

    /// Settlement amount cannot exceed the quote's charged amount.
    #[error("economy settlement amount {amount} exceeds charged amount {charged}")]
    SettlementOverAllocated { amount: u128, charged: u128 },

    /// Settlement signer returned an empty placeholder signature.
    #[error("economy settlement receipt `{receipt_id}` signer returned an empty signature")]
    EmptySettlementSignature { receipt_id: String },

    /// Constant-evaluation invariant in the zero-launch policy was violated.
    #[error("zero-launch invariant violated: {reason}")]
    ZeroLaunchInvariantViolated { reason: String },

    /// Generic invalid input.
    #[error("economy invalid input: {reason}")]
    InvalidInput { reason: String },
}

impl<T> From<ciborium::ser::Error<T>> for EconomyError {
    fn from(_: ciborium::ser::Error<T>) -> Self {
        EconomyError::Serialization {
            reason: "CBOR serialization failed".into(),
        }
    }
}

impl<T> From<ciborium::de::Error<T>> for EconomyError {
    fn from(_: ciborium::de::Error<T>) -> Self {
        EconomyError::Serialization {
            reason: "CBOR deserialization failed".into(),
        }
    }
}

impl From<exo_core::ExoError> for EconomyError {
    fn from(value: exo_core::ExoError) -> Self {
        match value {
            exo_core::ExoError::SerializationError { reason } => {
                EconomyError::Serialization { reason }
            }
            other => EconomyError::InvalidInput {
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
        let cases: Vec<EconomyError> = vec![
            EconomyError::Serialization { reason: "x".into() },
            EconomyError::EmptyField { field: "id" },
            EconomyError::BasisPointOutOfRange {
                field: "vig",
                value: 99_999,
                max: 10_000,
            },
            EconomyError::FloorAboveCeiling {
                floor: 100,
                ceiling: 50,
            },
            EconomyError::UnknownPolicy {
                policy_id: "abc".into(),
            },
            EconomyError::QuoteNotFound,
            EconomyError::QuoteExpired,
            EconomyError::ReceiptHashMismatch,
            EconomyError::QuoteHashMismatch,
            EconomyError::RevenueShareOverAllocated { sum: 11_000 },
            EconomyError::SettlementOverAllocated {
                amount: 10,
                charged: 5,
            },
            EconomyError::EmptySettlementSignature {
                receipt_id: "rec".into(),
            },
            EconomyError::ZeroLaunchInvariantViolated { reason: "x".into() },
            EconomyError::InvalidInput { reason: "x".into() },
        ];
        for err in cases {
            assert!(!err.to_string().is_empty(), "empty display for {err:?}");
        }
    }

    #[test]
    fn from_exo_error_serialization_preserves_reason() {
        let inner = exo_core::ExoError::SerializationError {
            reason: "boom".into(),
        };
        let mapped: EconomyError = inner.into();
        match mapped {
            EconomyError::Serialization { reason } => assert_eq!(reason, "boom"),
            other => panic!("expected Serialization, got {other:?}"),
        }
    }

    #[test]
    fn from_exo_error_other_maps_to_invalid_input() {
        let inner = exo_core::ExoError::InvalidMerkleProof;
        let mapped: EconomyError = inner.into();
        assert!(matches!(mapped, EconomyError::InvalidInput { .. }));
    }

    #[test]
    fn ciborium_serialization_error_maps_to_serialization_variant() {
        let inner: ciborium::ser::Error<std::io::Error> = ciborium::ser::Error::Value("bad".into());
        let mapped: EconomyError = inner.into();
        assert!(matches!(mapped, EconomyError::Serialization { .. }));
    }

    #[test]
    fn ciborium_deserialization_error_maps_to_serialization_variant() {
        let inner: ciborium::de::Error<std::io::Error> =
            ciborium::de::Error::Semantic(None, "bad".into());
        let mapped: EconomyError = inner.into();
        assert!(matches!(mapped, EconomyError::Serialization { .. }));
    }
}
