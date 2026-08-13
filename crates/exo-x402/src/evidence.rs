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

//! Canonical payment-evidence hashing.
//!
//! This adapter hashes *generic* commercial evidence (facilitator receipt,
//! CAIP-2 network, integer amount, currency, payer, payee, resource URL
//! hash). It does not import x402, MPP, USDC, or Coinbase wire types into
//! `exo-avc`. The resulting hash is what AVC receipts bind.

use exo_avc::{AVC_PAYMENT_EVIDENCE_DOMAIN, AVC_SCHEMA_VERSION};
use exo_core::Hash256;
use serde::Serialize;

use crate::error::{Result, X402Error};

/// Generic payment evidence hashed under [`AVC_PAYMENT_EVIDENCE_DOMAIN`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentEvidence {
    /// Hash of the payment facilitator's receipt / settlement attestation.
    pub facilitator_receipt_hash: Hash256,
    /// CAIP-2 network identifier, e.g. `eip155:8453`.
    pub network: String,
    /// Amount in integer minor units. Never floating point.
    pub amount_minor_units: u64,
    /// Currency code compared against AVC budget currency.
    pub currency: String,
    /// Payer identifier (wallet address, session id, or DID).
    pub payer: String,
    /// Payee identifier.
    pub payee: String,
    /// Hash of the commercially gated resource URL.
    pub resource_url_hash: Hash256,
}

#[derive(Serialize)]
struct PaymentEvidenceSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    facilitator_receipt_hash: &'a Hash256,
    network: &'a str,
    amount_minor_units: u64,
    currency: &'a str,
    payer: &'a str,
    payee: &'a str,
    resource_url_hash: &'a Hash256,
}

fn require_non_empty(value: &str, field: &'static str) -> Result<()> {
    if value.trim().is_empty() {
        Err(X402Error::EmptyField { field })
    } else {
        Ok(())
    }
}

impl PaymentEvidence {
    /// Canonical CBOR bytes tagged with [`AVC_PAYMENT_EVIDENCE_DOMAIN`].
    ///
    /// # Errors
    /// Returns [`X402Error`] when a required field is empty, the facilitator
    /// hash is zero, or CBOR encoding fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        require_non_empty(&self.network, "network")?;
        require_non_empty(&self.currency, "currency")?;
        require_non_empty(&self.payer, "payer")?;
        require_non_empty(&self.payee, "payee")?;
        if self.facilitator_receipt_hash == Hash256::ZERO {
            return Err(X402Error::ZeroFacilitatorReceiptHash);
        }
        let payload = PaymentEvidenceSigningPayload {
            domain: AVC_PAYMENT_EVIDENCE_DOMAIN,
            schema_version: AVC_SCHEMA_VERSION,
            facilitator_receipt_hash: &self.facilitator_receipt_hash,
            network: self.network.trim(),
            amount_minor_units: self.amount_minor_units,
            currency: self.currency.trim(),
            payer: self.payer.trim(),
            payee: self.payee.trim(),
            resource_url_hash: &self.resource_url_hash,
        };
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&payload, &mut bytes).map_err(|err| {
            X402Error::Serialization {
                reason: err.to_string(),
            }
        })?;
        Ok(bytes)
    }

    /// BLAKE3 hash of the canonical payment-evidence payload.
    ///
    /// # Errors
    /// Returns [`X402Error`] when payload construction fails.
    pub fn hash(&self) -> Result<Hash256> {
        Ok(Hash256::digest(&self.signing_payload()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PaymentEvidence {
        PaymentEvidence {
            facilitator_receipt_hash: Hash256::from_bytes([0x11; 32]),
            network: "eip155:8453".into(),
            amount_minor_units: 250_000,
            currency: "USD".into(),
            payer: "0xpayer".into(),
            payee: "0xpayee".into(),
            resource_url_hash: Hash256::from_bytes([0x22; 32]),
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let left = sample().hash().unwrap();
        let right = sample().hash().unwrap();
        assert_eq!(left, right);
        assert_ne!(left, Hash256::ZERO);
    }

    #[test]
    fn hash_changes_when_amount_changes() {
        let mut changed = sample();
        changed.amount_minor_units = 250_001;
        assert_ne!(sample().hash().unwrap(), changed.hash().unwrap());
    }

    #[test]
    fn payload_uses_avc_payment_evidence_domain() {
        assert_eq!(AVC_PAYMENT_EVIDENCE_DOMAIN, "exo.avc.payment.evidence.v1");
        let bytes = sample().signing_payload().unwrap();
        let as_text = String::from_utf8_lossy(&bytes);
        assert!(as_text.contains("exo.avc.payment.evidence.v1"));
    }

    #[test]
    fn rejects_empty_currency() {
        let mut evidence = sample();
        evidence.currency = "  ".into();
        assert!(matches!(
            evidence.hash(),
            Err(X402Error::EmptyField { field: "currency" })
        ));
    }

    #[test]
    fn rejects_zero_facilitator_receipt_hash() {
        let mut evidence = sample();
        evidence.facilitator_receipt_hash = Hash256::ZERO;
        assert!(matches!(
            evidence.hash(),
            Err(X402Error::ZeroFacilitatorReceiptHash)
        ));
    }
}
