//! Settlement: build, sign, and chain a [`SettlementReceipt`] for a
//! validated [`SettlementQuote`].
//!
//! The settlement path performs the same fail-closed checks as the
//! quote path, plus quote freshness and quote-hash integrity. The
//! resulting receipt is content-hashed and signed by the caller.

use exo_core::{Hash256, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{
    error::EconomyError,
    quote::SettlementQuote,
    receipt::{SettlementReceipt, canonical_content_hash},
};

/// Caller-supplied settlement context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementContext {
    pub receipt_id: String,
    pub custody_transaction_hash: Hash256,
    pub prev_settlement_receipt: Hash256,
    pub now: Timestamp,
}

impl SettlementContext {
    /// Validate structural invariants on the context.
    ///
    /// # Errors
    /// Returns [`EconomyError::EmptyField`] when `receipt_id` is blank.
    pub fn validate(&self) -> Result<(), EconomyError> {
        if self.receipt_id.trim().is_empty() {
            return Err(EconomyError::EmptyField {
                field: "settlement.receipt_id",
            });
        }
        Ok(())
    }
}

/// Settle a quote: validate freshness and hash integrity, build the
/// receipt, content-hash it, and invoke the caller's `sign` closure
/// once over the canonical content hash.
///
/// # Errors
/// Returns [`EconomyError`] when the quote is expired, tampered, or the
/// context is structurally invalid.
pub fn settle<F>(
    quote: &SettlementQuote,
    context: &SettlementContext,
    sign: F,
) -> Result<SettlementReceipt, EconomyError>
where
    F: FnOnce(&[u8]) -> Signature,
{
    context.validate()?;
    if !quote.verify_hash()? {
        return Err(EconomyError::QuoteHashMismatch);
    }
    if quote.is_expired(&context.now) {
        return Err(EconomyError::QuoteExpired);
    }

    let mut receipt = SettlementReceipt {
        id: context.receipt_id.clone(),
        quote_hash: quote.quote_hash,
        actor_did: quote.actor_did.clone(),
        event_class: quote.event_class,
        charged_amount_micro_exo: quote.charged_amount_micro_exo,
        zero_fee_reason: quote.zero_fee_reason,
        revenue_shares: quote.revenue_shares.clone(),
        custody_transaction_hash: context.custody_transaction_hash,
        prev_settlement_receipt: context.prev_settlement_receipt,
        timestamp: context.now,
        content_hash: Hash256::ZERO,
        signature: Signature::empty(),
    };
    receipt.content_hash = canonical_content_hash(&receipt)?;
    let signature = sign(receipt.content_hash.as_bytes());
    if signature.is_empty() {
        return Err(EconomyError::EmptySettlementSignature {
            receipt_id: context.receipt_id.clone(),
        });
    }
    receipt.signature = signature;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use exo_core::{Did, Timestamp};

    use super::*;
    use crate::{
        policy::PricingPolicy,
        price::PricingInputs,
        quote::quote,
        types::{ActorClass, AssuranceClass, EventClass},
    };

    fn fixed_signature() -> Signature {
        Signature::from_bytes([7u8; 64])
    }

    fn baseline_inputs() -> PricingInputs {
        PricingInputs {
            actor_did: Did::new("did:exo:agent").unwrap(),
            actor_class: ActorClass::Holon,
            event_class: EventClass::HolonCommercialAction,
            assurance_class: AssuranceClass::Standard,
            declared_value_micro_exo: Some(1_000_000),
            realized_value_micro_exo: None,
            compute_units: 100,
            storage_bytes: 4_096,
            verification_ops: 5,
            network_load_bp: 10_000,
            risk_bp: 1_500,
            market_domain: None,
            timestamp: Timestamp::new(1_000_000, 0),
        }
    }

    fn baseline_context() -> SettlementContext {
        SettlementContext {
            receipt_id: "rec-1".into(),
            custody_transaction_hash: Hash256::from_bytes([0x33; 32]),
            prev_settlement_receipt: Hash256::ZERO,
            now: Timestamp::new(1_010_000, 0),
        }
    }

    #[test]
    fn settle_zero_quote_succeeds() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let receipt = settle(&q, &baseline_context(), |_| fixed_signature()).unwrap();
        assert_eq!(receipt.charged_amount_micro_exo, 0);
        assert_eq!(receipt.signature, fixed_signature());
        assert_ne!(receipt.content_hash, Hash256::ZERO);
        assert!(receipt.verify_content_hash().unwrap());
    }

    #[test]
    fn settle_chains_prev_receipt_hash_into_receipt() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let mut ctx = baseline_context();
        ctx.prev_settlement_receipt = Hash256::from_bytes([0xAB; 32]);
        let receipt = settle(&q, &ctx, |_| fixed_signature()).unwrap();
        assert_eq!(
            receipt.prev_settlement_receipt,
            Hash256::from_bytes([0xAB; 32])
        );
    }

    #[test]
    fn settle_rejects_blank_receipt_id() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let mut ctx = baseline_context();
        ctx.receipt_id = "   ".into();
        assert!(matches!(
            settle(&q, &ctx, |_| fixed_signature()).unwrap_err(),
            EconomyError::EmptyField { .. }
        ));
    }

    #[test]
    fn settle_rejects_tampered_quote() {
        let policy = PricingPolicy::zero_launch_default();
        let mut q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        q.charged_amount_micro_exo = 9_999_999;
        let err = settle(&q, &baseline_context(), |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, EconomyError::QuoteHashMismatch));
    }

    #[test]
    fn settle_rejects_expired_quote() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let mut ctx = baseline_context();
        ctx.now = Timestamp::new(q.expires_at.physical_ms + 1, q.expires_at.logical);
        let err = settle(&q, &ctx, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, EconomyError::QuoteExpired));
    }

    #[test]
    fn settle_rejects_empty_signer_output() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let err = settle(&q, &baseline_context(), |_| Signature::empty()).unwrap_err();
        assert!(matches!(
            err,
            EconomyError::EmptySettlementSignature { receipt_id } if receipt_id == "rec-1"
        ));
    }

    #[test]
    fn settle_records_zero_fee_reason_from_quote() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let receipt = settle(&q, &baseline_context(), |_| fixed_signature()).unwrap();
        assert_eq!(receipt.zero_fee_reason, q.zero_fee_reason);
    }

    #[test]
    fn settle_carries_revenue_share_lines_with_zero_amounts() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let receipt = settle(&q, &baseline_context(), |_| fixed_signature()).unwrap();
        assert!(!receipt.revenue_shares.is_empty());
        for line in &receipt.revenue_shares {
            assert_eq!(line.amount_micro_exo, 0);
        }
    }

    #[test]
    fn settle_round_trip_serialization() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let receipt = settle(&q, &baseline_context(), |_| fixed_signature()).unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&receipt, &mut buf).unwrap();
        let decoded: SettlementReceipt = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded, receipt);
    }
}
