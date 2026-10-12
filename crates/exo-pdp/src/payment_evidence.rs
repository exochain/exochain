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

//! Domain-separated payment-evidence digest.
//!
//! A caller-supplied hash is payment evidence only when it equals the
//! BLAKE3 of canonical CBOR the verifier computed from evidence it can
//! see. The preimage is `hash_structured` of
//! `{domain, evidence, schema_version}` with
//! [`PAYMENT_EVIDENCE_DOMAIN`].
//!
//! JSON objects are normalized. JSON has no canonical byte encoding, so
//! the verifier parses [`PaymentEvidence`] and re-encodes it with
//! `ciborium`. Key order and whitespace cannot change the digest.
//!
//! Raw CBOR is rejected unless it is byte-identical to that encoding.
//! A non-minimal integer, a reordered map, or trailing bytes is a
//! different preimage. Normalizing those bytes would record a hash of
//! an encoding the caller did not present. The wire encoding is the
//! evidence map alone; the domain-separated preimage is not accepted
//! as `payment_evidence_cbor_hex`.
//!
//! A consistent evidence/hash pair is payment only when it names the
//! requested transaction: `amount_minor`, asset (proposed currency),
//! payee (proposed merchant), and payer (mandate principal).

use exo_core::{
    Hash256,
    hash::{hash_structured, hash256_eq_constant_time},
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{PdpError, Result},
    mandate::ProposedAction,
};

/// Domain bound into every payment-evidence digest.
pub const PAYMENT_EVIDENCE_DOMAIN: &str = "exo.x402.payment.evidence.v1";

/// Schema bound into the digest next to [`PAYMENT_EVIDENCE_DOMAIN`].
pub const PAYMENT_EVIDENCE_SCHEMA_VERSION: u16 = 1;

/// Payment facts the verifier hashes. Field order is RFC 8949 bytewise
/// key order for these short names (length, then lexicographic), which
/// is the order `ciborium` emits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentEvidence {
    pub asset: String,
    pub nonce: String,
    pub payee: String,
    pub payer: String,
    pub scheme: String,
    pub network: String,
    pub amount_minor: u64,
}

/// Requested transaction that payment evidence must name.
///
/// Amount, asset, and payee come from the proposed action. Payer is the
/// mandate principal. Absent amount, asset, or payee fails closed once
/// evidence is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentTransactionContext<'a> {
    pub amount_minor: Option<u64>,
    pub asset: Option<&'a str>,
    pub payee: Option<&'a str>,
    pub payer: &'a str,
}

impl<'a> PaymentTransactionContext<'a> {
    /// Context for the action the PDP is about to adjudicate.
    #[must_use]
    pub fn from_proposed(proposed: &'a ProposedAction, payer: &'a str) -> Self {
        Self {
            amount_minor: proposed.amount_minor,
            asset: proposed.currency.as_deref(),
            payee: proposed.merchant.as_deref(),
            payer,
        }
    }
}

#[derive(Serialize)]
struct PaymentEvidenceHashPayload<'a> {
    domain: &'static str,
    evidence: &'a PaymentEvidence,
    schema_version: u16,
}

fn hash_payload(evidence: &PaymentEvidence) -> PaymentEvidenceHashPayload<'_> {
    PaymentEvidenceHashPayload {
        domain: PAYMENT_EVIDENCE_DOMAIN,
        evidence,
        schema_version: PAYMENT_EVIDENCE_SCHEMA_VERSION,
    }
}

/// Canonical CBOR of `evidence` alone, without the domain separator.
///
/// # Errors
///
/// Returns [`PdpError::Serialization`] when CBOR encoding fails.
pub fn canonical_payment_evidence_cbor(evidence: &PaymentEvidence) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(evidence, &mut bytes).map_err(|error| {
        PdpError::Serialization(format!("payment evidence canonical CBOR: {error}"))
    })?;
    Ok(bytes)
}

/// Domain-separated canonical CBOR preimage of `evidence`.
///
/// # Errors
///
/// Returns [`PdpError::Serialization`] when CBOR encoding fails.
pub fn payment_evidence_preimage(evidence: &PaymentEvidence) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(&hash_payload(evidence), &mut bytes).map_err(|error| {
        PdpError::Serialization(format!("payment evidence canonical CBOR: {error}"))
    })?;
    Ok(bytes)
}

/// Non-zero BLAKE3 of [`payment_evidence_preimage`].
///
/// # Errors
///
/// Returns [`PdpError::Serialization`] when CBOR encoding fails, or
/// [`PdpError::BadRequest`] when the digest is the all-zero hash.
pub fn payment_evidence_digest(evidence: &PaymentEvidence) -> Result<Hash256> {
    let digest = hash_structured(&hash_payload(evidence)).map_err(|error| {
        PdpError::Serialization(format!("payment evidence canonical CBOR: {error}"))
    })?;
    if digest == Hash256::ZERO {
        return Err(PdpError::BadRequest(
            "payment evidence hash must be non-zero".into(),
        ));
    }
    Ok(digest)
}

/// Decode payment-evidence CBOR and require the canonical encoding.
///
/// # Errors
///
/// Returns [`PdpError::BadRequest`] when `bytes` is empty, is not the
/// canonical encoding of a [`PaymentEvidence`], or does not decode.
/// Returns [`PdpError::Serialization`] when re-encoding fails.
pub fn payment_evidence_from_cbor(bytes: &[u8]) -> Result<PaymentEvidence> {
    if bytes.is_empty() {
        return Err(PdpError::BadRequest(
            "payment evidence CBOR is not canonical: empty".into(),
        ));
    }
    let evidence: PaymentEvidence = ciborium::from_reader(bytes).map_err(|error| {
        PdpError::BadRequest(format!("payment evidence CBOR is not canonical: {error}"))
    })?;
    let canonical = canonical_payment_evidence_cbor(&evidence)?;
    if canonical.as_slice() != bytes {
        return Err(PdpError::BadRequest(
            "payment evidence CBOR is not canonical".into(),
        ));
    }
    Ok(evidence)
}

/// Bind a caller hash to evidence this verifier can see, and to `transaction`.
///
/// `Ok(None)` means no payment was presented. A hash without evidence,
/// evidence without its hash, a zero hash, a mismatched hash,
/// non-canonical CBOR, or evidence for a different transaction is
/// [`PdpError::BadRequest`].
///
/// The transaction check runs only after the evidence/hash pair matches.
/// Evidence must equal the proposed amount, currency (`asset`), and
/// merchant (`payee`), and the mandate principal (`payer`).
///
/// # Errors
///
/// Returns [`PdpError::BadRequest`] or [`PdpError::Serialization`] as
/// described above.
pub fn bind_payment_evidence(
    evidence: Option<PaymentEvidence>,
    evidence_cbor_hex: Option<&str>,
    claimed_hash_hex: Option<&str>,
    transaction: &PaymentTransactionContext<'_>,
) -> Result<Option<Hash256>> {
    let claimed = parse_claimed_hash(claimed_hash_hex)?;
    let from_cbor = parse_evidence_cbor(evidence_cbor_hex)?;
    let evidence = match (evidence, from_cbor) {
        (None, None) => None,
        (Some(json_evidence), None) | (None, Some(json_evidence)) => Some(json_evidence),
        (Some(json_evidence), Some(cbor_evidence)) => {
            if json_evidence != cbor_evidence {
                return Err(PdpError::BadRequest(
                    "payment evidence does not match canonical CBOR".into(),
                ));
            }
            Some(json_evidence)
        }
    };
    match (evidence, claimed) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(PdpError::BadRequest(
            "payment evidence hash requires evidence the verifier can see".into(),
        )),
        (Some(_), None) => Err(PdpError::BadRequest(
            "payment evidence requires its canonical CBOR hash".into(),
        )),
        (Some(evidence), Some(claimed)) => {
            let computed = payment_evidence_digest(&evidence)?;
            if !hash256_eq_constant_time(&computed, &claimed) {
                return Err(PdpError::BadRequest(
                    "payment evidence hash does not match canonical CBOR".into(),
                ));
            }
            require_transaction_binding(&evidence, transaction)?;
            Ok(Some(computed))
        }
    }
}

fn require_transaction_binding(
    evidence: &PaymentEvidence,
    transaction: &PaymentTransactionContext<'_>,
) -> Result<()> {
    let amount_minor = transaction
        .amount_minor
        .ok_or_else(|| transaction_mismatch("amount_minor is absent"))?;
    let asset = required_transaction_str(transaction.asset, "asset")?;
    let payee = required_transaction_str(transaction.payee, "payee")?;
    let payer = required_transaction_str(Some(transaction.payer), "payer")?;
    if evidence.amount_minor != amount_minor {
        return Err(transaction_mismatch("amount_minor"));
    }
    if evidence.asset != asset {
        return Err(transaction_mismatch("asset"));
    }
    if evidence.payee != payee {
        return Err(transaction_mismatch("payee"));
    }
    if evidence.payer != payer {
        return Err(transaction_mismatch("payer"));
    }
    Ok(())
}

fn required_transaction_str<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str> {
    match value {
        Some(item) if !item.is_empty() => Ok(item),
        _ => Err(transaction_mismatch(&format!("{field} is absent"))),
    }
}

fn transaction_mismatch(detail: &str) -> PdpError {
    PdpError::BadRequest(format!(
        "payment evidence does not match the requested transaction: {detail}"
    ))
}

fn parse_claimed_hash(hex_in: Option<&str>) -> Result<Option<Hash256>> {
    let Some(raw) = hex_in.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let bytes = hex::decode(raw)
        .map_err(|error| PdpError::BadRequest(format!("payment_evidence_hash_hex: {error}")))?;
    if bytes.len() != 32 {
        return Err(PdpError::BadRequest(
            "payment_evidence_hash_hex must be 32 bytes".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let hash = Hash256::from_bytes(arr);
    if hash == Hash256::ZERO {
        return Err(PdpError::BadRequest(
            "payment evidence hash must be non-zero".into(),
        ));
    }
    Ok(Some(hash))
}

fn parse_evidence_cbor(hex_in: Option<&str>) -> Result<Option<PaymentEvidence>> {
    let Some(raw) = hex_in.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let bytes = hex::decode(raw)
        .map_err(|error| PdpError::BadRequest(format!("payment_evidence_cbor_hex: {error}")))?;
    payment_evidence_from_cbor(&bytes).map(Some)
}

#[cfg(test)]
pub(crate) fn sample_payment_evidence() -> PaymentEvidence {
    PaymentEvidence {
        asset: "USD".into(),
        nonce: "n-1".into(),
        payee: "did:exo:merchant".into(),
        payer: "did:exo:payer".into(),
        scheme: "exact".into(),
        network: "internal".into(),
        amount_minor: 1,
    }
}

#[cfg(test)]
pub(crate) fn noncanonical_payment_evidence_cbor(evidence: &PaymentEvidence) -> Vec<u8> {
    let canonical = canonical_payment_evidence_cbor(evidence).expect("canonical evidence");
    let mut preferred = Vec::new();
    ciborium::into_writer(&evidence.amount_minor, &mut preferred).expect("amount encoding");
    let mut widened = vec![0x1b];
    widened.extend_from_slice(&evidence.amount_minor.to_be_bytes());
    assert_ne!(preferred, widened, "widened integer must differ");
    let matches = canonical
        .windows(preferred.len())
        .filter(|window| *window == preferred.as_slice())
        .count();
    assert_eq!(matches, 1, "amount encoding must appear once");
    let start = canonical
        .windows(preferred.len())
        .position(|window| window == preferred.as_slice())
        .expect("preferred amount encoding");
    let mut out = Vec::with_capacity(canonical.len() + widened.len() - preferred.len());
    out.extend_from_slice(&canonical[..start]);
    out.extend_from_slice(&widened);
    out.extend_from_slice(&canonical[start + preferred.len()..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matching_hash(evidence: &PaymentEvidence) -> String {
        payment_evidence_digest(evidence)
            .expect("digest")
            .to_string()
    }

    fn sample_tx() -> PaymentTransactionContext<'static> {
        PaymentTransactionContext {
            amount_minor: Some(1),
            asset: Some("USD"),
            payee: Some("did:exo:merchant"),
            payer: "did:exo:payer",
        }
    }

    #[test]
    fn digest_is_domain_separated_hash_structured_preimage() {
        let evidence = sample_payment_evidence();
        let preimage = payment_evidence_preimage(&evidence).expect("preimage");
        let digest = payment_evidence_digest(&evidence).expect("digest");
        assert_eq!(digest, Hash256::digest(&preimage));
        assert_eq!(
            digest,
            hash_structured(&hash_payload(&evidence)).expect("hash_structured")
        );
        assert_ne!(digest, Hash256::ZERO);
        assert!(
            preimage
                .windows(PAYMENT_EVIDENCE_DOMAIN.len())
                .any(|window| window == PAYMENT_EVIDENCE_DOMAIN.as_bytes())
        );
        let evidence_only =
            Hash256::digest(&canonical_payment_evidence_cbor(&evidence).expect("evidence cbor"));
        assert_ne!(evidence_only, digest);
        let json = serde_json::to_vec(&evidence).expect("json");
        assert_ne!(Hash256::digest(&json), digest);
    }

    #[test]
    fn digest_preimage_map_keys_are_bytewise_sorted() {
        let evidence = sample_payment_evidence();
        let preimage = payment_evidence_preimage(&evidence).expect("preimage");
        let value: ciborium::Value = ciborium::from_reader(preimage.as_slice()).expect("decode");
        assert_maps_sorted(&value);
        let evidence_cbor = canonical_payment_evidence_cbor(&evidence).expect("evidence");
        let evidence_value: ciborium::Value =
            ciborium::from_reader(evidence_cbor.as_slice()).expect("decode evidence");
        assert_maps_sorted(&evidence_value);
    }

    fn assert_maps_sorted(value: &ciborium::Value) {
        match value {
            ciborium::Value::Array(items) => {
                for item in items {
                    assert_maps_sorted(item);
                }
            }
            ciborium::Value::Map(entries) => {
                let mut previous: Option<Vec<u8>> = None;
                for (key, child) in entries {
                    let mut encoded = Vec::new();
                    ciborium::into_writer(key, &mut encoded).expect("key");
                    if let Some(previous_key) = &previous {
                        assert!(
                            previous_key.as_slice() < encoded.as_slice(),
                            "map keys must be canonical bytewise order"
                        );
                    }
                    previous = Some(encoded);
                    assert_maps_sorted(child);
                }
            }
            ciborium::Value::Tag(_, inner) => assert_maps_sorted(inner),
            _ => {}
        }
    }

    #[test]
    fn zero_hash_is_rejected_with_or_without_evidence() {
        let evidence = sample_payment_evidence();
        let zero = "00".repeat(32);
        let absent =
            bind_payment_evidence(None, None, Some(&zero), &sample_tx()).expect_err("zero hash");
        assert!(absent.to_string().contains("non-zero"));
        let present = bind_payment_evidence(Some(evidence), None, Some(&zero), &sample_tx())
            .expect_err("zero hash");
        assert!(present.to_string().contains("non-zero"));
    }

    #[test]
    fn hash_without_visible_evidence_is_rejected() {
        let claimed = hex::encode([0x11u8; 32]);
        let error =
            bind_payment_evidence(None, None, Some(&claimed), &sample_tx()).expect_err("bare hash");
        assert!(
            error
                .to_string()
                .contains("requires evidence the verifier can see")
        );
    }

    #[test]
    fn mismatched_hash_is_rejected() {
        let evidence = sample_payment_evidence();
        let error = bind_payment_evidence(
            Some(evidence),
            None,
            Some(&hex::encode([0x11u8; 32])),
            &sample_tx(),
        )
        .expect_err("mismatch");
        assert!(error.to_string().contains("does not match canonical CBOR"));
    }

    #[test]
    fn matching_canonical_hash_is_accepted() {
        let evidence = sample_payment_evidence();
        let expected = payment_evidence_digest(&evidence).expect("digest");
        let bound = bind_payment_evidence(
            Some(evidence.clone()),
            None,
            Some(&expected.to_string()),
            &sample_tx(),
        )
        .expect("bind")
        .expect("some hash");
        assert_eq!(bound, expected);

        let cbor = canonical_payment_evidence_cbor(&evidence).expect("cbor");
        let from_cbor = bind_payment_evidence(
            None,
            Some(&hex::encode(cbor)),
            Some(&expected.to_string()),
            &sample_tx(),
        )
        .expect("bind cbor")
        .expect("some hash");
        assert_eq!(from_cbor, expected);
    }

    #[test]
    fn absent_payment_is_unbound() {
        assert_eq!(
            bind_payment_evidence(None, None, None, &sample_tx()).expect("unbound"),
            None
        );
        assert_eq!(
            bind_payment_evidence(None, Some("  "), Some(""), &sample_tx()).expect("blank"),
            None
        );
    }

    #[test]
    fn json_key_order_is_normalized_to_the_same_digest() {
        let forward = r#"{"scheme":"exact","network":"internal","asset":"USD","payer":"did:exo:payer","payee":"did:exo:merchant","amount_minor":1,"nonce":"n-1"}"#;
        let reverse = r#"{"nonce":"n-1","amount_minor":1,"payee":"did:exo:merchant","payer":"did:exo:payer","asset":"USD","network":"internal","scheme":"exact"}"#;
        let left: PaymentEvidence = serde_json::from_str(forward).expect("forward");
        let right: PaymentEvidence = serde_json::from_str(reverse).expect("reverse");
        assert_eq!(
            payment_evidence_digest(&left).expect("left"),
            payment_evidence_digest(&right).expect("right")
        );
        assert_eq!(
            canonical_payment_evidence_cbor(&left).expect("left cbor"),
            canonical_payment_evidence_cbor(&right).expect("right cbor")
        );
    }

    #[test]
    fn noncanonical_cbor_is_rejected() {
        let evidence = sample_payment_evidence();
        let widened = noncanonical_payment_evidence_cbor(&evidence);
        let error = payment_evidence_from_cbor(&widened).expect_err("widened integer");
        assert!(error.to_string().contains("not canonical"));

        let canonical = canonical_payment_evidence_cbor(&evidence).expect("canonical");
        let mut value: ciborium::Value =
            ciborium::from_reader(canonical.as_slice()).expect("decode");
        let ciborium::Value::Map(entries) = &mut value else {
            panic!("evidence is a map");
        };
        entries.reverse();
        let mut reversed = Vec::new();
        ciborium::into_writer(&value, &mut reversed).expect("encode reversed");
        assert_ne!(reversed, canonical);
        let error = payment_evidence_from_cbor(&reversed).expect_err("reordered keys");
        assert!(error.to_string().contains("not canonical"));

        let mut trailing = canonical.clone();
        trailing.push(0x00);
        let error = payment_evidence_from_cbor(&trailing).expect_err("trailing");
        assert!(error.to_string().contains("not canonical"));

        let digest = matching_hash(&evidence);
        let bound = bind_payment_evidence(
            None,
            Some(&hex::encode(widened)),
            Some(&digest),
            &sample_tx(),
        )
        .expect_err("bind widened");
        assert!(bound.to_string().contains("not canonical"));
    }

    #[test]
    fn unknown_evidence_field_is_rejected() {
        let body = r#"{"asset":"USD","nonce":"n-1","payee":"did:exo:merchant","payer":"did:exo:payer","scheme":"exact","network":"internal","amount_minor":1,"extra":"hidden"}"#;
        assert!(serde_json::from_str::<PaymentEvidence>(body).is_err());
    }

    #[test]
    fn unrelated_transaction_evidence_is_rejected() {
        let evidence = sample_payment_evidence();
        let hash = matching_hash(&evidence);
        let cases = [
            (
                PaymentTransactionContext {
                    amount_minor: Some(99),
                    ..sample_tx()
                },
                "amount_minor",
            ),
            (
                PaymentTransactionContext {
                    asset: Some("EUR"),
                    ..sample_tx()
                },
                "asset",
            ),
            (
                PaymentTransactionContext {
                    payee: Some("did:exo:other"),
                    ..sample_tx()
                },
                "payee",
            ),
            (
                PaymentTransactionContext {
                    payer: "did:exo:other",
                    ..sample_tx()
                },
                "payer",
            ),
            (
                PaymentTransactionContext {
                    amount_minor: None,
                    ..sample_tx()
                },
                "amount_minor is absent",
            ),
            (
                PaymentTransactionContext {
                    asset: None,
                    ..sample_tx()
                },
                "asset is absent",
            ),
            (
                PaymentTransactionContext {
                    asset: Some(""),
                    ..sample_tx()
                },
                "asset is absent",
            ),
            (
                PaymentTransactionContext {
                    payee: None,
                    ..sample_tx()
                },
                "payee is absent",
            ),
            (
                PaymentTransactionContext {
                    payer: "",
                    ..sample_tx()
                },
                "payer is absent",
            ),
        ];
        for (transaction, detail) in cases {
            let error =
                bind_payment_evidence(Some(evidence.clone()), None, Some(&hash), &transaction)
                    .expect_err("unrelated transaction");
            let message = error.to_string();
            assert!(message.contains("requested transaction"), "{message}");
            assert!(message.contains(detail), "{message}");
        }
    }

    #[test]
    fn payment_evidence_vector_matches_golden_preimage_and_wire() {
        #[derive(Deserialize)]
        struct PaymentEvidenceVector {
            domain: String,
            schema_version: u16,
            evidence: PaymentEvidence,
            preimage_cbor_hex: String,
            wire_cbor_hex: String,
            blake3_hex: String,
        }

        let vector: PaymentEvidenceVector =
            serde_json::from_str(include_str!("../tests/vectors/payment_evidence_v1.json"))
                .expect("vector");
        assert_eq!(vector.domain, PAYMENT_EVIDENCE_DOMAIN);
        assert_eq!(vector.schema_version, PAYMENT_EVIDENCE_SCHEMA_VERSION);
        assert_eq!(vector.evidence, sample_payment_evidence());
        let preimage = payment_evidence_preimage(&vector.evidence).expect("preimage");
        assert_eq!(hex::encode(&preimage), vector.preimage_cbor_hex);
        let wire = canonical_payment_evidence_cbor(&vector.evidence).expect("wire");
        assert_eq!(hex::encode(&wire), vector.wire_cbor_hex);
        assert_ne!(vector.preimage_cbor_hex, vector.wire_cbor_hex);
        assert_eq!(
            payment_evidence_digest(&vector.evidence)
                .expect("digest")
                .to_string(),
            vector.blake3_hex
        );
        assert_eq!(
            payment_evidence_from_cbor(&wire).expect("wire accepted"),
            vector.evidence
        );
        let preimage_bytes = hex::decode(&vector.preimage_cbor_hex).expect("preimage hex");
        let rejected =
            payment_evidence_from_cbor(&preimage_bytes).expect_err("preimage is not wire");
        assert!(rejected.to_string().contains("not canonical"));
        let bound = bind_payment_evidence(
            None,
            Some(&vector.wire_cbor_hex),
            Some(&vector.blake3_hex),
            &sample_tx(),
        )
        .expect("client wire cbor")
        .expect("bound");
        assert_eq!(bound.to_string(), vector.blake3_hex);
        let replayed_preimage = bind_payment_evidence(
            None,
            Some(&vector.preimage_cbor_hex),
            Some(&vector.blake3_hex),
            &sample_tx(),
        )
        .expect_err("preimage rejected as wire");
        assert!(replayed_preimage.to_string().contains("not canonical"));
    }
}
