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

//! RFC 3161 timestamp support for AVC receipts.
//!
//! The implementation lives in `exochain-verify` (issue #897) so offline
//! verifiers can check receipt timestamp tokens without node dependencies.
//! This module re-exports the parts the node uses to request and verify
//! timestamps at emit time.

#[cfg(test)]
pub(crate) use exo_verify::rfc3161::{
    MICROSOFT_ARTIFACT_SIGNING_POLICY_OID, MICROSOFT_ARTIFACT_SIGNING_TIMESTAMP_URL,
    inspect_timestamp_response_without_spki_pin, microsoft_fixture_timestamp_token_der_base64,
};
pub(crate) use exo_verify::rfc3161::{
    Rfc3161TrustAnchorKind, Rfc3161TrustAnchors, build_timestamp_request,
    build_timestamp_request_from_imprint, verify_timestamp_response_with_trust_anchors,
};

#[cfg(test)]
mod tests {
    use exo_avc::AvcReceiptEvidenceSubject;
    use exo_core::Hash256;
    use exo_verify::rfc3161::canonical_hex;

    use super::*;

    fn evidence_subject() -> AvcReceiptEvidenceSubject {
        AvcReceiptEvidenceSubject {
            credential_id: Hash256::from_bytes([0x11; 32]),
            action_id: Hash256::from_bytes([0x22; 32]),
            action_commitment_hash: Hash256::from_bytes([0x33; 32]),
            action_descriptor_hash: Hash256::from_bytes([0x44; 32]),
            previous_receipt_hash: Some(Hash256::from_bytes([0x55; 32])),
        }
    }

    #[tokio::test]
    #[ignore = "live Microsoft TSA preflight; set EXO_AVC_RFC3161_LIVE_PREFLIGHT=1"]
    async fn live_microsoft_rfc3161_preflight_extracts_and_verifies_pinned_spki() {
        if std::env::var("EXO_AVC_RFC3161_LIVE_PREFLIGHT")
            .ok()
            .as_deref()
            != Some("1")
        {
            eprintln!(
                "skipping live Microsoft RFC 3161 preflight; set EXO_AVC_RFC3161_LIVE_PREFLIGHT=1"
            );
            return;
        }
        let subject = evidence_subject();
        let request =
            build_timestamp_request(&subject, MICROSOFT_ARTIFACT_SIGNING_POLICY_OID).unwrap();
        let response = reqwest::Client::new()
            .post(MICROSOFT_ARTIFACT_SIGNING_TIMESTAMP_URL)
            .header("Content-Type", "application/timestamp-query")
            .header("Accept", "application/timestamp-reply")
            .body(request.der)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "Microsoft TSA returned {}",
            response.status()
        );
        let response_der = response.bytes().await.unwrap();
        let verified = inspect_timestamp_response_without_spki_pin(
            &response_der,
            subject.hash().unwrap(),
            request.message_imprint_sha256,
            &request.nonce_hex,
            MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
        )
        .unwrap();
        if let Ok(existing_pin) =
            std::env::var(crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV)
        {
            let configured_pins = existing_pin
                .split(',')
                .map(|pin| {
                    canonical_hex(
                        pin.trim(),
                        crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            assert!(
                configured_pins.contains(&verified.tsa_public_key_spki_der_hex),
                "live Microsoft TSA signer SPKI was not present in configured pin set"
            );
        }
        println!(
            "{}={}",
            crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
            crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161
        );
        println!(
            "{}={}",
            crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
            MICROSOFT_ARTIFACT_SIGNING_TIMESTAMP_URL
        );
        println!(
            "{}=did:exo:microsoft-public-rsa-tsa",
            crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV
        );
        println!(
            "{}={}",
            crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
            verified.tsa_public_key_spki_der_hex
        );
        println!(
            "{}={}",
            crate::avc::AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV,
            verified.policy_oid
        );
        println!(
            "{}=true",
            crate::avc::AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY_ENV
        );
        println!("RFC3161_TSA_SUBJECT={}", verified.tsa_subject);
        println!("RFC3161_SERIAL_NUMBER={}", verified.serial_number_hex);
        println!("RFC3161_NONCE={}", verified.nonce_hex);
        println!(
            "RFC3161_MESSAGE_IMPRINT_SHA256={}",
            verified.message_imprint_sha256_hex
        );
    }
}
