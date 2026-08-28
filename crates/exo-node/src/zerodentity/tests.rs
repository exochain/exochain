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

//! Integration tests for the 0dentity module — §12.2.
//!
//! Per-module unit tests live in each sub-module's `#[cfg(test)]` block.
//! These tests exercise cross-module interactions: the complete onboarding arc,
//! HTTP handler behaviour, scoring consistency, and store contracts.
//!
//! All HTTP tests drive axum routers via `tower::ServiceExt::oneshot`.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::module_inception)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode, header},
    };
    use exo_core::{
        crypto::{self, KeyPair},
        hlc::HybridClock,
        types::{Did, Hash256, PublicKey, SecretKey, Signature},
    };
    use rand::{SeedableRng, rngs::StdRng};
    use serde_json::Value;
    use tower::ServiceExt;

    use crate::zerodentity::{
        ClaimStatus, ClaimType, IdentityClaim, IdentitySession, OTP_MAX_ATTEMPTS, OtpChallenge,
        OtpChannel, OtpState, PolarAxes, ZerodentityScore,
        api::{ApiState, zerodentity_api_router},
        attestation::{attestation_signing_payload, target_claim_id},
        onboarding::{OnboardingState, onboarding_router},
        scoring::compute_symmetry,
        store::{SharedZerodentityStore, ZerodentityStore, new_shared_store},
        types::{
            AttestationType, BehavioralSample, BehavioralSignalType, DeviceFingerprint,
            FingerprintSignal, IDENTITY_SESSION_TTL_MS,
        },
    };

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    const API_TEST_NOW_MS: u64 = 1_001_000;

    fn td(id: &str) -> Did {
        Did::new(&format!("did:exo:{id}")).unwrap()
    }

    fn h(tag: &str) -> Hash256 {
        Hash256::digest(tag.as_bytes())
    }

    #[test]
    fn module_doc_retains_device_behavioral_axes_audit_status() {
        let src = include_str!("mod.rs");
        assert!(
            src.contains("# Audit status"),
            "module doc must retain the R3 audit-status section"
        );
        assert!(
            src.contains("unaudited-zerodentity-device-behavioral-axes"),
            "module doc must name the R3 feature flag"
        );
        assert!(
            src.contains("fix-onyx-4-r3-unwired-axes.md"),
            "module doc must point at the R3 initiative"
        );
    }

    fn seeded_rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    fn keypair(seed: u8) -> (PublicKey, SecretKey) {
        let pair = crypto::KeyPair::from_secret_bytes([seed; 32]).unwrap();
        (*pair.public_key(), pair.secret_key().clone())
    }

    fn signed_attest_body(
        attester: &Did,
        target: &Did,
        attestation_type: AttestationType,
        message_hash: Option<Hash256>,
        created_ms: u64,
        public_key: &PublicKey,
        secret_key: &SecretKey,
    ) -> serde_json::Value {
        let payload = attestation_signing_payload(
            attester,
            target,
            &attestation_type,
            message_hash.as_ref(),
            created_ms,
        )
        .unwrap();
        let signature = crypto::sign(&payload, secret_key);
        serde_json::json!({
            "target_did": target.as_str(),
            "attestation_type": attestation_type.to_string(),
            "message_hash": message_hash.map(|h| hex::encode(h.as_bytes())),
            "created_ms": created_ms,
            "attester_public_key": hex::encode(public_key.as_bytes()),
            "signature": hex::encode(signature.to_bytes())
        })
    }

    fn make_claim(did: &Did, ct: ClaimType, status: ClaimStatus, ms: u64) -> IdentityClaim {
        let key = format!("{ct:?}-{ms}");
        let verified_ms = if status == ClaimStatus::Verified {
            Some(ms + 500)
        } else {
            None
        };
        IdentityClaim {
            claim_hash: h(&key),
            subject_did: did.clone(),
            claim_type: ct,
            status,
            created_ms: ms,
            verified_ms,
            expires_ms: None,
            signature: Signature::Empty,
            dag_node_hash: h(&format!("dag-{key}")),
        }
    }

    fn make_signed_claim(
        did: &Did,
        ct: ClaimType,
        status: ClaimStatus,
        ms: u64,
        signature: Signature,
    ) -> IdentityClaim {
        let mut claim = make_claim(did, ct, status, ms);
        claim.signature = signature;
        claim
    }

    fn make_fingerprint(tag: &str, captured_ms: u64) -> DeviceFingerprint {
        let mut signal_hashes = std::collections::BTreeMap::new();
        signal_hashes.insert(FingerprintSignal::UserAgent, h(&format!("{tag}-ua")));
        DeviceFingerprint {
            composite_hash: h(&format!("{tag}-composite")),
            signal_hashes,
            captured_ms,
            consistency_score_bp: Some(8_000),
        }
    }

    fn make_behavioral_sample(
        tag: &str,
        signal_type: BehavioralSignalType,
        captured_ms: u64,
    ) -> BehavioralSample {
        BehavioralSample {
            sample_hash: h(&format!("{tag}-sample")),
            signal_type,
            captured_ms,
            baseline_similarity_bp: Some(7_500),
        }
    }

    fn make_session(did: &Did, token: &str, ms: u64) -> IdentitySession {
        make_session_with_public_key(did, token, ms, vec![])
    }

    fn make_session_with_public_key(
        did: &Did,
        token: &str,
        ms: u64,
        public_key: Vec<u8>,
    ) -> IdentitySession {
        IdentitySession {
            session_token: token.to_owned(),
            subject_did: did.clone(),
            public_key,
            created_ms: ms,
            last_active_ms: ms,
            revoked: false,
        }
    }

    fn test_keypair(seed: u8) -> KeyPair {
        KeyPair::from_secret_bytes([seed; 32]).unwrap()
    }

    fn bootstrap_verify_body(
        challenge_id: &str,
        code: &str,
        subject_did: &Did,
        keypair: &KeyPair,
    ) -> Value {
        let payload = crate::zerodentity::session_auth::bootstrap_signing_payload(
            challenge_id,
            subject_did,
            keypair.public_key(),
        )
        .unwrap();
        let signature = keypair.sign(&payload);
        serde_json::json!({
            "challenge_id": challenge_id,
            "code": code,
            "public_key": hex::encode(keypair.public_key().as_bytes()),
            "bootstrap_signature": hex::encode(signature.to_bytes())
        })
    }

    fn derived_did(keypair: &KeyPair) -> Did {
        crate::zerodentity::session_auth::did_from_public_key(keypair.public_key()).unwrap()
    }

    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    fn signed_claim_body(
        subject_did: &Did,
        claim_type: &str,
        provider: Option<&str>,
        verification_channel: Option<&str>,
        created_ms: u64,
        public_keypair: &KeyPair,
        signing_keypair: &KeyPair,
    ) -> Value {
        let payload = crate::zerodentity::session_auth::claim_submission_signing_payload(
            subject_did,
            claim_type,
            provider,
            verification_channel,
            created_ms,
            public_keypair.public_key(),
        )
        .unwrap();
        let signature = signing_keypair.sign(&payload);
        serde_json::json!({
            "subject_did": subject_did.as_str(),
            "claim_type": claim_type,
            "provider": provider,
            "verification_channel": verification_channel,
            "created_ms": created_ms,
            "public_key": hex::encode(public_keypair.public_key().as_bytes()),
            "signature": hex::encode(signature.to_bytes())
        })
    }

    fn request_signature_headers(
        method: &str,
        uri: &str,
        token: &str,
        nonce: &str,
        body: &[u8],
        keypair: &KeyPair,
    ) -> (String, String) {
        let body_hash = Hash256::digest(body);
        let payload = crate::zerodentity::session_auth::request_signing_payload(
            method, uri, token, nonce, &body_hash,
        )
        .unwrap();
        let signature = keypair.sign(&payload);
        (nonce.to_owned(), hex::encode(signature.to_bytes()))
    }

    fn make_score(did: &Did, bp: u32, ms: u64) -> ZerodentityScore {
        ZerodentityScore {
            subject_did: did.clone(),
            axes: PolarAxes {
                communication: bp,
                credential_depth: bp,
                device_trust: bp,
                behavioral_signature: bp,
                network_reputation: bp,
                temporal_stability: bp,
                cryptographic_strength: bp,
                constitutional_standing: bp,
            },
            composite: bp,
            computed_ms: ms,
            dag_state_hash: h("state"),
            claim_count: 1,
            symmetry: 10_000,
        }
    }

    fn onboarding_app(store: SharedZerodentityStore) -> Router {
        onboarding_app_with_fixed_clock(store, API_TEST_NOW_MS)
    }

    fn onboarding_app_with_fixed_clock(store: SharedZerodentityStore, now_ms: u64) -> Router {
        onboarding_router(OnboardingState::new_with_clock(
            store,
            HybridClock::with_wall_clock(move || now_ms),
        ))
    }

    fn api_app(store: SharedZerodentityStore) -> Router {
        configure_test_receipt_signer(&store);
        zerodentity_api_router(ApiState::new_with_clock(
            store,
            HybridClock::with_wall_clock(|| API_TEST_NOW_MS),
        ))
    }

    fn configure_test_receipt_signer(store: &SharedZerodentityStore) {
        let keypair = KeyPair::from_secret_bytes([37u8; 32]).unwrap();
        let signer = Arc::new(move |payload: &[u8]| keypair.sign(payload));
        store
            .lock()
            .unwrap()
            .set_receipt_signer(td("test-node"), signer);
    }

    async fn post_json(app: &Router, uri: &str, body: Value) -> axum::response::Response {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    async fn get_req(app: &Router, uri: &str) -> axum::response::Response {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    async fn get_with_auth(app: &Router, uri: &str, token: &str) -> axum::response::Response {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    async fn body_json(resp: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // -----------------------------------------------------------------------
    // §12.2.1 — Scoring integration
    // -----------------------------------------------------------------------

    #[test]
    fn score_email_only_gives_3500_communication() {
        let did = td("score-01");
        let claims = vec![make_claim(
            &did,
            ClaimType::Email,
            ClaimStatus::Verified,
            1_000,
        )];
        let score = ZerodentityScore::compute(&did, &claims, &[], &[], 1_000_000);
        assert_eq!(score.axes.communication, 3_500);
    }

    #[test]
    fn score_phone_only_gives_3700_communication() {
        let did = td("score-02");
        let claims = vec![make_claim(
            &did,
            ClaimType::Phone,
            ClaimStatus::Verified,
            1_000,
        )];
        let score = ZerodentityScore::compute(&did, &claims, &[], &[], 1_000_000);
        assert_eq!(score.axes.communication, 3_700);
    }

    #[test]
    fn score_email_and_phone_gives_8700_communication() {
        let did = td("score-03");
        let claims = vec![
            make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            make_claim(&did, ClaimType::Phone, ClaimStatus::Verified, 2_000),
        ];
        let score = ZerodentityScore::compute(&did, &claims, &[], &[], 1_000_000);
        assert_eq!(score.axes.communication, 8_700, "3500+3700+1500=8700");
    }

    #[test]
    fn score_pending_claims_contribute_nothing_to_communication() {
        let did = td("score-04");
        let claims = vec![
            make_claim(&did, ClaimType::Email, ClaimStatus::Pending, 1_000),
            make_claim(&did, ClaimType::Phone, ClaimStatus::Pending, 2_000),
        ];
        let score = ZerodentityScore::compute(&did, &claims, &[], &[], 1_000_000);
        assert_eq!(score.axes.communication, 0);
    }

    #[test]
    fn score_composite_is_mean_of_axes() {
        let did = td("score-05");
        let claims = vec![
            make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            make_claim(&did, ClaimType::GovernmentId, ClaimStatus::Verified, 2_000),
        ];
        let score = ZerodentityScore::compute(&did, &claims, &[], &[], 5_000_000);
        let expected = score.axes.as_array().iter().copied().sum::<u32>() / 8;
        assert_eq!(score.composite, expected, "composite = mean(8 axes)");
    }

    #[test]
    fn score_is_fully_deterministic() {
        let did = td("score-06");
        let claims = vec![
            make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            make_claim(&did, ClaimType::GovernmentId, ClaimStatus::Verified, 2_000),
        ];
        let s1 = ZerodentityScore::compute(&did, &claims, &[], &[], 5_000_000);
        let s2 = ZerodentityScore::compute(&did, &claims, &[], &[], 5_000_000);
        assert_eq!(s1.composite, s2.composite);
        assert_eq!(s1.symmetry, s2.symmetry);
        assert_eq!(s1.dag_state_hash, s2.dag_state_hash);
    }

    #[test]
    fn score_claim_count_counts_only_verified() {
        let did = td("score-07");
        let claims = vec![
            make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            make_claim(&did, ClaimType::Phone, ClaimStatus::Pending, 2_000),
            make_claim(&did, ClaimType::DisplayName, ClaimStatus::Verified, 3_000),
        ];
        let score = ZerodentityScore::compute(&did, &claims, &[], &[], 5_000_000);
        assert_eq!(score.claim_count, 2, "only Verified claims counted");
    }

    #[test]
    fn score_zero_claims_gives_base_axes() {
        let did = td("score-08");
        // No claims — axes should reflect their base values (some have non-zero bases)
        let score = ZerodentityScore::compute(&did, &[], &[], &[], 1_000_000);
        // communication=0 (no email/phone), credential_depth=0, device_trust=0, behavioral=0
        assert_eq!(score.axes.communication, 0);
        assert_eq!(score.axes.device_trust, 0);
        assert_eq!(score.axes.behavioral_signature, 0);
        // network_reputation has base 1000, constitutional_standing has base 1000
        assert_eq!(score.axes.network_reputation, 1_000);
        assert_eq!(score.axes.constitutional_standing, 1_000);
    }

    #[test]
    fn score_dag_state_hash_unique_per_claim_set() {
        let did = td("score-09");
        let s1 = ZerodentityScore::compute(
            &did,
            &[make_claim(
                &did,
                ClaimType::Email,
                ClaimStatus::Verified,
                1_000,
            )],
            &[],
            &[],
            1_000_000,
        );
        let s2 = ZerodentityScore::compute(
            &did,
            &[
                make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
                make_claim(&did, ClaimType::Phone, ClaimStatus::Verified, 2_000),
            ],
            &[],
            &[],
            1_000_000,
        );
        assert_ne!(
            s1.dag_state_hash, s2.dag_state_hash,
            "different claims → different dag_state_hash"
        );
    }

    // -----------------------------------------------------------------------
    // §12.2.2 — Symmetry index
    // -----------------------------------------------------------------------

    #[test]
    fn symmetry_all_equal_axes_is_10000() {
        assert_eq!(compute_symmetry(&[5_000u32; 8]), 10_000);
    }

    #[test]
    fn symmetry_all_zero_is_zero() {
        assert_eq!(compute_symmetry(&[0u32; 8]), 0);
    }

    #[test]
    fn symmetry_highly_skewed_is_low() {
        let mut axes = [0u32; 8];
        axes[0] = 10_000;
        assert!(
            compute_symmetry(&axes) < 3_000,
            "one dominant axis → low symmetry"
        );
    }

    #[test]
    fn symmetry_slight_imbalance_is_high() {
        // One axis slightly off — symmetry should still be high
        let mut axes = [5_000u32; 8];
        axes[0] = 5_100;
        assert!(
            compute_symmetry(&axes) > 8_000,
            "slight imbalance → high symmetry"
        );
    }

    // -----------------------------------------------------------------------
    // §12.2.3 — Store + Scoring integration
    // -----------------------------------------------------------------------

    #[test]
    fn store_score_roundtrip_and_history() {
        let did = td("store-01");
        let mut store = ZerodentityStore::new();

        store.put_score(make_score(&did, 3_000, 1_000_000)).unwrap();
        store.put_score(make_score(&did, 5_000, 2_000_000)).unwrap();

        assert_eq!(store.get_score(&did).unwrap().composite, 5_000);
        assert_eq!(store.get_previous_score(&did).unwrap().composite, 3_000);

        let history = store.get_score_history(&did, None, None).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].composite, 3_000);
        assert_eq!(history[1].composite, 5_000);
    }

    #[test]
    fn store_100_other_dids_do_not_bleed_into_target() {
        let mut store = ZerodentityStore::new();
        let target = td("target-isolated");

        for i in 0..100u32 {
            store
                .put_score(make_score(&td(&format!("noise-{i}")), i * 100, 1_000_000))
                .unwrap();
        }

        assert!(store.get_score(&target).is_none());
        assert_eq!(store.get_claims(&target).unwrap(), vec![]);
    }

    #[test]
    fn store_score_history_time_filter_works() {
        let did = td("store-02");
        let mut store = ZerodentityStore::new();

        for (bp, ms) in [(1_000u32, 1_000u64), (2_000, 5_000), (3_000, 10_000)] {
            let mut s = make_score(&did, bp, ms);
            s.computed_ms = ms;
            store.put_score(s).unwrap();
        }

        let filtered = store
            .get_score_history(&did, Some(2_000), Some(8_000))
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].composite, 2_000);
    }

    #[test]
    fn store_otp_challenge_full_lifecycle() {
        let did = td("store-otp-01");
        let mut store = ZerodentityStore::new();
        let mut rng = seeded_rng(0xDEAD_BEEF);

        let (challenge, code) =
            OtpChallenge::new(&did, OtpChannel::Email, 1_000_000, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();

        store.insert_otp_challenge(&challenge).unwrap();

        let retrieved = store.get_otp_challenge(&cid).unwrap().unwrap();
        assert_eq!(retrieved.state, OtpState::Pending);

        let mut to_verify = retrieved;
        let result = to_verify.verify(&code, 1_001_000);
        assert_eq!(result, crate::zerodentity::OtpResult::Success);
        assert_eq!(to_verify.state, OtpState::Verified);

        store.update_otp_challenge(&to_verify).unwrap();

        let final_state = store.get_otp_challenge(&cid).unwrap().unwrap();
        assert_eq!(final_state.state, OtpState::Verified);
    }

    #[test]
    fn store_session_revoke_hides_session() {
        let did = td("store-session-01");
        let mut store = ZerodentityStore::new();
        let token = "revoke-test-token";

        store
            .insert_session(&make_session(&did, token, 1_000_000))
            .unwrap();
        assert!(store.get_session(token, 1_000_001).unwrap().is_some());

        let mut revoked = make_session(&did, token, 1_000_000);
        revoked.revoked = true;
        store.insert_session(&revoked).unwrap();

        assert!(
            store.get_session(token, 1_000_001).unwrap().is_none(),
            "revoked session must be hidden"
        );
    }

    #[test]
    fn store_session_expiry_hides_session_at_deadline() {
        let did = td("store-session-expiry");
        let mut store = ZerodentityStore::new();
        let token = "expired-test-token";
        let created_ms = 1_000_000;

        store
            .insert_session(&make_session(&did, token, created_ms))
            .unwrap();

        assert!(
            store
                .get_session(token, created_ms + IDENTITY_SESSION_TTL_MS - 1)
                .unwrap()
                .is_some(),
            "session must remain active before its absolute expiry deadline"
        );
        assert!(
            store
                .get_session(token, created_ms + IDENTITY_SESSION_TTL_MS)
                .unwrap()
                .is_none(),
            "session must be hidden at its absolute expiry deadline"
        );
    }

    #[test]
    fn store_session_expiry_fails_closed_on_deadline_overflow() {
        let did = td("store-session-overflow");
        let mut store = ZerodentityStore::new();
        let token = "overflow-test-token";
        let created_ms = u64::MAX - 1;

        store
            .insert_session(&make_session(&did, token, created_ms))
            .unwrap();

        assert!(
            store.get_session(token, created_ms).unwrap().is_none(),
            "session expiry arithmetic overflow must not create an immortal session"
        );
    }

    #[test]
    fn store_session_lookup_hides_future_created_sessions() {
        let did = td("store-session-future");
        let mut store = ZerodentityStore::new();
        let token = "future-session-token";
        let created_ms = 2_000_000;

        store
            .insert_session(&make_session(&did, token, created_ms))
            .unwrap();

        assert!(
            store.get_session(token, created_ms - 1).unwrap().is_none(),
            "sessions with future creation timestamps must fail closed"
        );
    }

    #[test]
    fn store_claims_slice_matches_tuple_vec() {
        let did = td("store-claims-01");
        let mut store = ZerodentityStore::new();

        store
            .insert_claim(
                "c1",
                &make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
        store
            .insert_claim(
                "c2",
                &make_claim(&did, ClaimType::Phone, ClaimStatus::Pending, 2_000),
            )
            .unwrap();

        let tuples = store.get_claims(&did).unwrap();
        let slice = store.get_claims_slice(&did).unwrap();
        assert_eq!(tuples.len(), slice.len());
        for ((_, c_t), c_s) in tuples.iter().zip(slice.iter()) {
            assert_eq!(c_t.claim_type, c_s.claim_type);
        }
    }

    #[test]
    fn store_get_claims_returns_canonical_created_ms_order() {
        let did = td("store-claims-canonical-order");
        let mut store = ZerodentityStore::new();

        store
            .insert_claim(
                "newer",
                &make_claim(&did, ClaimType::Phone, ClaimStatus::Verified, 2_000),
            )
            .unwrap();
        store
            .insert_claim(
                "older",
                &make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();

        let claim_ids: Vec<String> = store
            .get_claims(&did)
            .unwrap()
            .into_iter()
            .map(|(claim_id, _)| claim_id)
            .collect();

        assert_eq!(claim_ids, vec!["older".to_owned(), "newer".to_owned()]);
    }

    #[test]
    fn store_get_fingerprints_returns_canonical_captured_ms_order() {
        let did = td("store-fingerprints-canonical-order");
        let mut store = ZerodentityStore::new();

        store
            .put_fingerprint(&did, make_fingerprint("newer", 2_000))
            .unwrap();
        store
            .put_fingerprint(&did, make_fingerprint("older", 1_000))
            .unwrap();

        let captured: Vec<u64> = store
            .get_fingerprints(&did)
            .unwrap()
            .into_iter()
            .map(|fingerprint| fingerprint.captured_ms)
            .collect();

        assert_eq!(captured, vec![1_000, 2_000]);
    }

    #[test]
    fn store_get_behavioral_samples_returns_canonical_captured_ms_order() {
        let did = td("store-behavioral-canonical-order");
        let mut store = ZerodentityStore::new();

        store
            .put_behavioral(
                &did,
                make_behavioral_sample("newer", BehavioralSignalType::MouseDynamics, 2_000),
            )
            .unwrap();
        store
            .put_behavioral(
                &did,
                make_behavioral_sample("older", BehavioralSignalType::KeystrokeDynamics, 1_000),
            )
            .unwrap();

        let captured: Vec<u64> = store
            .get_behavioral_samples(&did)
            .unwrap()
            .into_iter()
            .map(|sample| sample.captured_ms)
            .collect();

        assert_eq!(captured, vec![1_000, 2_000]);
    }

    // -----------------------------------------------------------------------
    // §12.2.4 — Onboarding HTTP handlers
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[cfg(not(feature = "unaudited-zerodentity-first-touch-onboarding"))]
    async fn submit_claim_refused_without_first_touch_feature_flag() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let did = td("onb-gated-default");

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            serde_json::json!({
                "subject_did": did.as_str(),
                "claim_type": "DisplayName"
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp).await;
        assert_eq!(
            body["feature_flag"],
            "unaudited-zerodentity-first-touch-onboarding"
        );
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|text| text.contains("fix-onyx-4-r1-onboarding-auth.md")),
            "refusal body must point at the R1 initiative: {body}"
        );
        assert!(
            store.lock().unwrap().get_claims(&did).unwrap().is_empty(),
            "default-off refusal must not persist a claim"
        );
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_returns_200_and_claim_id() {
        let app = onboarding_app(new_shared_store());
        let keypair = test_keypair(30);
        let did = derived_did(&keypair);

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            signed_claim_body(
                &did,
                "DisplayName",
                None,
                None,
                1_700_000_001,
                &keypair,
                &keypair,
            ),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["status"], "Pending");
        assert!(body["claim_id"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_invalid_did_returns_400() {
        let app = onboarding_app(new_shared_store());

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            serde_json::json!({
                "subject_did": "not-a-valid-did",
                "claim_type": "Email"
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_unknown_type_returns_400() {
        let app = onboarding_app(new_shared_store());

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            serde_json::json!({
                "subject_did": "did:exo:alice",
                "claim_type": "Nonexistent"
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_with_otp_channel_returns_challenge_id_and_ttl() {
        let app = onboarding_app(new_shared_store());
        let keypair = test_keypair(31);
        let did = derived_did(&keypair);

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            signed_claim_body(
                &did,
                "Email",
                None,
                Some("Email"),
                1_700_000_002,
                &keypair,
                &keypair,
            ),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(body["challenge_id"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(body["challenge_ttl_ms"].as_u64().is_some());
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_uses_node_hlc_for_otp_dispatch_time() {
        let store = new_shared_store();
        let app = onboarding_app_with_fixed_clock(store.clone(), API_TEST_NOW_MS);
        let keypair = test_keypair(132);
        let did = derived_did(&keypair);
        let signed_created_ms = API_TEST_NOW_MS + OtpChannel::Email.ttl_ms() + 86_400_000;

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            signed_claim_body(
                &did,
                "Email",
                None,
                Some("Email"),
                signed_created_ms,
                &keypair,
                &keypair,
            ),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let challenge_id = body["challenge_id"]
            .as_str()
            .expect("challenge id is returned");
        let store = store.lock().unwrap();
        let challenge = store
            .get_otp_challenge(challenge_id)
            .unwrap()
            .expect("challenge is stored");
        assert_eq!(challenge.dispatched_ms, API_TEST_NOW_MS);
        assert_ne!(challenge.dispatched_ms, signed_created_ms);

        let claims = store.get_claims(&did).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].1.created_ms, signed_created_ms);
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_stores_claim_in_store() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let keypair = test_keypair(32);
        let did = derived_did(&keypair);
        let created_ms = 1_700_000_003;

        post_json(
            &app,
            "/api/v1/0dentity/claims",
            signed_claim_body(&did, "Phone", None, None, created_ms, &keypair, &keypair),
        )
        .await;

        let claims = store.lock().unwrap().get_claims(&did).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].1.claim_type, ClaimType::Phone);
        assert_eq!(claims[0].1.created_ms, created_ms);
        assert!(!claims[0].1.signature.is_empty());
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_rejects_missing_proof_of_possession() {
        let app = onboarding_app(new_shared_store());
        let keypair = test_keypair(33);
        let did = derived_did(&keypair);

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            serde_json::json!({
                "subject_did": did.as_str(),
                "claim_type": "DisplayName"
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_rejects_public_key_that_does_not_derive_subject_did() {
        let app = onboarding_app(new_shared_store());
        let keypair = test_keypair(34);
        let did = td("not-derived-from-key");

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            signed_claim_body(
                &did,
                "DisplayName",
                None,
                None,
                1_700_000_004,
                &keypair,
                &keypair,
            ),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_rejects_wrong_key_signature() {
        let app = onboarding_app(new_shared_store());
        let keypair = test_keypair(35);
        let wrong_keypair = test_keypair(36);
        let did = derived_did(&keypair);

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            signed_claim_body(
                &did,
                "DisplayName",
                None,
                None,
                1_700_000_005,
                &keypair,
                &wrong_keypair,
            ),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_rejects_tampered_signed_payload() {
        let app = onboarding_app(new_shared_store());
        let keypair = test_keypair(37);
        let did = derived_did(&keypair);
        let mut body = signed_claim_body(
            &did,
            "DisplayName",
            None,
            None,
            1_700_000_006,
            &keypair,
            &keypair,
        );
        body["claim_type"] = Value::String("Email".to_owned());

        let resp = post_json(&app, "/api/v1/0dentity/claims", body).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_rejects_zero_signature() {
        let app = onboarding_app(new_shared_store());
        let keypair = test_keypair(38);
        let did = derived_did(&keypair);
        let mut body = signed_claim_body(
            &did,
            "DisplayName",
            None,
            None,
            1_700_000_007,
            &keypair,
            &keypair,
        );
        body["signature"] = Value::String(hex::encode([0u8; 64]));

        let resp = post_json(&app, "/api/v1/0dentity/claims", body).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_rejects_replayed_submission() {
        let app = onboarding_app(new_shared_store());
        let keypair = test_keypair(39);
        let did = derived_did(&keypair);
        let body = signed_claim_body(
            &did,
            "DisplayName",
            None,
            None,
            1_700_000_008,
            &keypair,
            &keypair,
        );

        let first = post_json(&app, "/api/v1/0dentity/claims", body.clone()).await;
        let second = post_json(&app, "/api/v1/0dentity/claims", body).await;

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn verify_otp_correct_code_returns_verified_and_session_token() {
        let store = new_shared_store();
        let app = onboarding_app_with_fixed_clock(store.clone(), 1_001_000);
        let keypair = test_keypair(1);
        let did = derived_did(&keypair);
        let dispatched_ms = 1_000_000;

        let mut rng = seeded_rng(0xCAFE_0001);
        let (challenge, code) =
            OtpChallenge::new(&did, OtpChannel::Email, dispatched_ms, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&challenge)
            .unwrap();

        let resp = post_json(
            &app,
            "/api/v1/0dentity/verify",
            bootstrap_verify_body(&cid, &code, &did, &keypair),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["verified"], true);
        assert!(
            body["session_token"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        let session_token = body["session_token"].as_str().unwrap();
        let session = store
            .lock()
            .unwrap()
            .get_session(session_token, 1_001_000)
            .unwrap()
            .unwrap();
        assert_eq!(session.public_key, keypair.public_key().as_bytes().to_vec());
    }

    #[tokio::test]
    async fn verify_otp_replay_after_success_returns_conflict() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let keypair = test_keypair(11);
        let did = derived_did(&keypair);
        let dispatched_ms = u64::MAX / 2;

        let mut rng = seeded_rng(0xCAFE_1020);
        let (challenge, code) =
            OtpChallenge::new(&did, OtpChannel::Email, dispatched_ms, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&challenge)
            .unwrap();

        let first = post_json(
            &app,
            "/api/v1/0dentity/verify",
            bootstrap_verify_body(&cid, &code, &did, &keypair),
        )
        .await;
        let second = post_json(
            &app,
            "/api/v1/0dentity/verify",
            bootstrap_verify_body(&cid, &code, &did, &keypair),
        )
        .await;

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn verify_otp_success_without_bootstrap_signature_returns_400() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let did = td("otp-bootstrap-missing");
        let dispatched_ms = u64::MAX / 2;

        let mut rng = seeded_rng(0xCAFE_1010);
        let (challenge, code) =
            OtpChallenge::new(&did, OtpChannel::Email, dispatched_ms, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&challenge)
            .unwrap();

        let resp = post_json(
            &app,
            "/api/v1/0dentity/verify",
            serde_json::json!({
                "challenge_id": cid,
                "code": code
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn verify_otp_success_rejects_wrong_bootstrap_key() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let keypair = test_keypair(2);
        let wrong_keypair = test_keypair(3);
        let did = derived_did(&keypair);
        let dispatched_ms = u64::MAX / 2;

        let mut rng = seeded_rng(0xCAFE_1011);
        let (challenge, code) =
            OtpChallenge::new(&did, OtpChannel::Email, dispatched_ms, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&challenge)
            .unwrap();

        let payload = crate::zerodentity::session_auth::bootstrap_signing_payload(
            &cid,
            &did,
            keypair.public_key(),
        )
        .unwrap();
        let wrong_signature = wrong_keypair.sign(&payload);

        let resp = post_json(
            &app,
            "/api/v1/0dentity/verify",
            serde_json::json!({
                "challenge_id": cid,
                "code": code,
                "public_key": hex::encode(keypair.public_key().as_bytes()),
                "bootstrap_signature": hex::encode(wrong_signature.to_bytes())
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn verify_otp_rejects_bootstrap_key_that_does_not_derive_subject_did() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let did = td("otp-bootstrap-unbound-key");
        let keypair = test_keypair(4);
        let dispatched_ms = u64::MAX / 2;

        let mut rng = seeded_rng(0xCAFE_1012);
        let (challenge, code) =
            OtpChallenge::new(&did, OtpChannel::Email, dispatched_ms, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&challenge)
            .unwrap();

        let resp = post_json(
            &app,
            "/api/v1/0dentity/verify",
            bootstrap_verify_body(&cid, &code, &did, &keypair),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn verify_otp_wrong_code_returns_attempts_remaining() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let did = td("otp-wrong-01");
        let dispatched_ms = u64::MAX / 2;

        let mut rng = seeded_rng(0xCAFE_0002);
        let (challenge, _code) =
            OtpChallenge::new(&did, OtpChannel::Email, dispatched_ms, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&challenge)
            .unwrap();

        let resp = post_json(
            &app,
            "/api/v1/0dentity/verify",
            serde_json::json!({
                "challenge_id": cid,
                "code": "000000"
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["verified"], false);
        assert_eq!(
            body["attempts_remaining"].as_u64().unwrap(),
            u64::from(OTP_MAX_ATTEMPTS - 1)
        );
    }

    #[tokio::test]
    async fn verify_otp_expired_challenge_returns_410() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let did = td("otp-expired-01");
        // dispatched_ms=0 → challenge expired when wall clock > 600_000ms (year 1970+10min)
        let dispatched_ms = 0u64;

        let mut rng = seeded_rng(0xCAFE_0003);
        let (challenge, _code) =
            OtpChallenge::new(&did, OtpChannel::Email, dispatched_ms, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&challenge)
            .unwrap();

        let resp = post_json(
            &app,
            "/api/v1/0dentity/verify",
            serde_json::json!({
                "challenge_id": cid,
                "code": "123456"
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::GONE);
    }

    #[tokio::test]
    async fn verify_otp_not_found_returns_404() {
        let app = onboarding_app(new_shared_store());

        let resp = post_json(
            &app,
            "/api/v1/0dentity/verify",
            serde_json::json!({
                "challenge_id": "does-not-exist",
                "code": "000000"
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn verify_otp_lockout_after_max_attempts_returns_429() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let did = td("otp-lock-01");
        let dispatched_ms = u64::MAX / 2;

        let mut rng = seeded_rng(0xCAFE_0004);
        let (challenge, _code) =
            OtpChallenge::new(&did, OtpChannel::Email, dispatched_ms, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&challenge)
            .unwrap();

        for attempt in 0..OTP_MAX_ATTEMPTS {
            let resp = post_json(
                &app,
                "/api/v1/0dentity/verify",
                serde_json::json!({
                    "challenge_id": cid,
                    "code": "999999"
                }),
            )
            .await;

            if attempt < OTP_MAX_ATTEMPTS - 1 {
                assert_eq!(resp.status(), StatusCode::OK, "attempt {attempt}");
            } else {
                assert_eq!(
                    resp.status(),
                    StatusCode::TOO_MANY_REQUESTS,
                    "final attempt"
                );
            }
        }
    }

    #[tokio::test]
    async fn resend_otp_before_cooldown_returns_429() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let did = td("otp-resend-cooldown");
        // far-future dispatched_ms → wall clock < dispatched_ms + cooldown → resend blocked
        let dispatched_ms = u64::MAX / 2;

        let mut rng = seeded_rng(0xBEEF_0101);
        let (challenge, _) =
            OtpChallenge::new(&did, OtpChannel::Email, dispatched_ms, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&challenge)
            .unwrap();

        let resp = post_json(
            &app,
            "/api/v1/0dentity/verify/resend",
            serde_json::json!({
                "challenge_id": cid
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn resend_otp_after_cooldown_returns_new_challenge_id() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let did = td("otp-resend-ok");
        // dispatched_ms=0 → cooldown (60_000ms) already elapsed by wall clock
        let dispatched_ms = 0u64;

        let mut rng = seeded_rng(0xBEEF_0102);
        let (challenge, _) =
            OtpChallenge::new(&did, OtpChannel::Email, dispatched_ms, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&challenge)
            .unwrap();

        let resp = post_json(
            &app,
            "/api/v1/0dentity/verify/resend",
            serde_json::json!({
                "challenge_id": cid
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let new_cid = body["challenge_id"].as_str().unwrap().to_owned();
        assert_ne!(new_cid, cid, "resend must return a fresh challenge_id");
        assert!(body["ttl_ms"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn resend_otp_after_cooldown_consumes_original_challenge() {
        let store = new_shared_store();
        let app = onboarding_app_with_fixed_clock(store.clone(), 120_000);
        let did = td("otp-resend-consumes-original");

        let mut rng = seeded_rng(0xBEEF_0103);
        let (challenge, _) = OtpChallenge::new(&did, OtpChannel::Email, 1, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&challenge)
            .unwrap();

        let resp = post_json(
            &app,
            "/api/v1/0dentity/verify/resend",
            serde_json::json!({
                "challenge_id": cid
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let new_cid = body["challenge_id"].as_str().unwrap();

        let guard = store.lock().unwrap();
        let original = guard.get_otp_challenge(&cid).unwrap().unwrap();
        let replacement = guard.get_otp_challenge(new_cid).unwrap().unwrap();
        assert_eq!(original.state, OtpState::Expired);
        assert_eq!(replacement.state, OtpState::Pending);
    }

    #[tokio::test]
    async fn resend_otp_uses_injected_hlc_timestamp() {
        let store = new_shared_store();
        let app = onboarding_app_with_fixed_clock(store.clone(), 180_000);
        let did = td("otp-resend-clock");

        let mut rng = seeded_rng(0xBEEF_0104);
        let (challenge, _) = OtpChallenge::new(&did, OtpChannel::Email, 1, &mut rng).unwrap();
        let cid = challenge.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&challenge)
            .unwrap();

        let resp = post_json(
            &app,
            "/api/v1/0dentity/verify/resend",
            serde_json::json!({
                "challenge_id": cid
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let new_cid = body["challenge_id"].as_str().unwrap();
        let replacement = store
            .lock()
            .unwrap()
            .get_otp_challenge(new_cid)
            .unwrap()
            .unwrap();

        assert_eq!(replacement.dispatched_ms, 180_000);
    }

    #[tokio::test]
    async fn resend_otp_not_found_returns_404() {
        let app = onboarding_app(new_shared_store());

        let resp = post_json(
            &app,
            "/api/v1/0dentity/verify/resend",
            serde_json::json!({
                "challenge_id": "ghost-challenge"
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // §12.2.5 — API HTTP handlers
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_score_unknown_did_returns_404() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("nobody");
        let token = "score-unknown-session-token";

        store
            .lock()
            .unwrap()
            .insert_session(&make_session(&did, token, 1_000_000))
            .unwrap();

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/score", did.as_str()),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_score_without_auth_returns_401() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-score-noauth");

        store
            .lock()
            .unwrap()
            .insert_claim(
                "c1",
                &make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();

        let resp = get_req(&app, &format!("/api/v1/0dentity/{}/score", did.as_str())).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_score_wrong_did_session_returns_403() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let alice = td("api-score-403-alice");
        let bob = td("api-score-403-bob");
        let bob_token = "score-bob-session-token";

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "a-c1",
                &make_claim(&alice, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session(&bob, bob_token, 1_000_000))
                .unwrap();
        }

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/score", alice.as_str()),
            bob_token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_score_with_verified_email_phone_gives_8700_communication() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-score-01");
        let token = "score-session-token-01";

        {
            let mut s = store.lock().unwrap();
            s.insert_session(&make_session(&did, token, 1_000_000))
                .unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_claim(
                "p1",
                &make_claim(&did, ClaimType::Phone, ClaimStatus::Verified, 2_000),
            )
            .unwrap();
        }

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/score", did.as_str()),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["axes"]["communication"].as_u64().unwrap(), 8_700);
        assert!(body["composite"].as_u64().unwrap() > 0);
        assert_eq!(body["claim_count"].as_u64().unwrap(), 2);
    }

    #[tokio::test]
    async fn get_score_without_as_of_uses_latest_evidence_timestamp() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-score-evidence-time");
        let token = "score-session-evidence-time";

        {
            let mut s = store.lock().unwrap();
            s.insert_session(&make_session(&did, token, 1_000_000))
                .unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_claim(
                "p1",
                &make_claim(&did, ClaimType::Phone, ClaimStatus::Verified, 2_000),
            )
            .unwrap();
        }

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/score", did.as_str()),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["computed_ms"].as_u64().unwrap(), 2_500);
    }

    #[tokio::test]
    async fn get_score_with_as_of_uses_caller_supplied_timestamp() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-score-explicit-time");
        let token = "score-session-explicit-time";

        {
            let mut s = store.lock().unwrap();
            s.insert_session(&make_session(&did, token, 1_000_000))
                .unwrap();
            s.insert_claim(
                "c1",
                &make_claim(&did, ClaimType::DisplayName, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
        }

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/score?as_of_ms=123456", did.as_str()),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["computed_ms"].as_u64().unwrap(), 123_456);
    }

    #[tokio::test]
    async fn get_score_rejects_zero_as_of_timestamp() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-score-zero-time");
        let token = "score-session-zero-time";

        {
            let mut s = store.lock().unwrap();
            s.insert_session(&make_session(&did, token, 1_000_000))
                .unwrap();
            s.insert_claim(
                "c1",
                &make_claim(&did, ClaimType::DisplayName, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
        }

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/score?as_of_ms=0", did.as_str()),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(
            body["error"].as_str().unwrap(),
            "as_of_ms must be greater than 0"
        );
    }

    #[tokio::test]
    async fn get_score_is_invariant_to_claim_insertion_order() {
        let did = td("api-score-canonical-order");
        let token = "score-session-canonical-order";
        let older_post_quantum = make_signed_claim(
            &did,
            ClaimType::Email,
            ClaimStatus::Verified,
            1_000,
            Signature::PostQuantum(vec![9; 64]),
        );
        let newer_ed25519 = make_signed_claim(
            &did,
            ClaimType::Phone,
            ClaimStatus::Verified,
            2_000,
            Signature::Ed25519([8; 64]),
        );

        let ordered_store = new_shared_store();
        {
            let mut s = ordered_store.lock().unwrap();
            s.insert_session(&make_session(&did, token, 1_000_000))
                .unwrap();
            s.insert_claim("older", &older_post_quantum).unwrap();
            s.insert_claim("newer", &newer_ed25519).unwrap();
        }
        let ordered_app = api_app(ordered_store);

        let reversed_store = new_shared_store();
        {
            let mut s = reversed_store.lock().unwrap();
            s.insert_session(&make_session(&did, token, 1_000_000))
                .unwrap();
            s.insert_claim("newer", &newer_ed25519).unwrap();
            s.insert_claim("older", &older_post_quantum).unwrap();
        }
        let reversed_app = api_app(reversed_store);

        let ordered_resp = get_with_auth(
            &ordered_app,
            &format!("/api/v1/0dentity/{}/score", did.as_str()),
            token,
        )
        .await;
        let reversed_resp = get_with_auth(
            &reversed_app,
            &format!("/api/v1/0dentity/{}/score", did.as_str()),
            token,
        )
        .await;

        assert_eq!(ordered_resp.status(), StatusCode::OK);
        assert_eq!(reversed_resp.status(), StatusCode::OK);
        let ordered_body = body_json(ordered_resp).await;
        let reversed_body = body_json(reversed_resp).await;

        assert_eq!(
            ordered_body["axes"]["cryptographic_strength"],
            reversed_body["axes"]["cryptographic_strength"]
        );
        assert_eq!(
            ordered_body["axes"]["cryptographic_strength"]
                .as_u64()
                .unwrap(),
            4_000
        );
    }

    #[tokio::test]
    async fn get_score_includes_dag_state_hash_hex() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-score-02");
        let token = "score-session-dag-hash";

        {
            let mut s = store.lock().unwrap();
            s.insert_session(&make_session(&did, token, 1_000_000))
                .unwrap();
            s.insert_claim(
                "c1",
                &make_claim(&did, ClaimType::DisplayName, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
        }

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/score", did.as_str()),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let hash_str = body["dag_state_hash"].as_str().unwrap();
        // BLAKE3 → 32 bytes → 64 hex chars
        assert_eq!(hash_str.len(), 64, "dag_state_hash should be 64 hex chars");
    }

    #[tokio::test]
    async fn list_claims_without_auth_returns_401() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-claims-noauth");

        store
            .lock()
            .unwrap()
            .insert_claim(
                "c1",
                &make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();

        let resp = get_req(&app, &format!("/api/v1/0dentity/{}/claims", did.as_str())).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_claims_with_valid_session_returns_claims() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-claims-ok");
        let token = "valid-session-token-abc";

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "c1",
                &make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_claim(
                "c2",
                &make_claim(&did, ClaimType::Phone, ClaimStatus::Pending, 2_000),
            )
            .unwrap();
            s.insert_session(&make_session(&did, token, 1_000_000))
                .unwrap();
        }

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/claims", did.as_str()),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["total"].as_u64().unwrap(), 2);
        assert_eq!(body["offset"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn list_claims_wrong_did_session_returns_403() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let alice = td("api-403-alice");
        let bob = td("api-403-bob");
        let bob_token = "bob-session-token";

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "a-c1",
                &make_claim(&alice, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session(&bob, bob_token, 1_000_000))
                .unwrap();
        }

        // Bob's token cannot access Alice's claims
        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/claims", alice.as_str()),
            bob_token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn score_history_empty_did_returns_empty_snapshots() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("no-history");
        let token = "history-empty-session-token";

        store
            .lock()
            .unwrap()
            .insert_session(&make_session(&did, token, 1_000_000))
            .unwrap();

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/score/history", did.as_str()),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["snapshots"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn score_history_without_auth_returns_401() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-history-noauth");

        store
            .lock()
            .unwrap()
            .put_score(make_score(&did, 4_000, 1_000))
            .unwrap();

        let resp = get_req(
            &app,
            &format!("/api/v1/0dentity/{}/score/history", did.as_str()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn score_history_wrong_did_session_returns_403() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let alice = td("api-history-403-alice");
        let bob = td("api-history-403-bob");
        let bob_token = "history-bob-session-token";

        {
            let mut s = store.lock().unwrap();
            s.put_score(make_score(&alice, 4_000, 1_000)).unwrap();
            s.insert_session(&make_session(&bob, bob_token, 1_000_000))
                .unwrap();
        }

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/score/history", alice.as_str()),
            bob_token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn score_history_is_chronological_and_complete() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-history-01");
        let token = "history-session-token-01";

        {
            let mut s = store.lock().unwrap();
            s.insert_session(&make_session(&did, token, 1_000_000))
                .unwrap();
            for (bp, ms) in [(1_000u32, 1_000u64), (3_000, 5_000), (6_000, 9_000)] {
                let mut score = make_score(&did, bp, ms);
                score.computed_ms = ms;
                s.put_score(score).unwrap();
            }
        }

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/score/history", did.as_str()),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let snaps = body["snapshots"].as_array().unwrap();
        assert_eq!(snaps.len(), 3);
        // Timestamps must be non-decreasing
        let times: Vec<u64> = snaps
            .iter()
            .map(|s| s["computed_ms"].as_u64().unwrap())
            .collect();
        assert!(
            times.windows(2).all(|w| w[0] <= w[1]),
            "history must be chronological"
        );
    }

    #[cfg(not(feature = "unaudited-zerodentity-device-behavioral-axes"))]
    #[tokio::test]
    async fn list_fingerprints_refused_without_device_behavioral_feature_flag() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-fp-gated");
        let token = "fp-gated-session-token";

        store
            .lock()
            .unwrap()
            .insert_session(&make_session(&did, token, 1_000_000))
            .unwrap();

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/fingerprints", did.as_str()),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp).await;
        assert_eq!(
            body["feature_flag"],
            "unaudited-zerodentity-device-behavioral-axes"
        );
        assert_eq!(body["initiative"], "fix-onyx-4-r3-unwired-axes.md");
    }

    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[tokio::test]
    async fn list_fingerprints_without_auth_returns_401() {
        let app = api_app(new_shared_store());

        let resp = get_req(&app, "/api/v1/0dentity/did:exo:fp-noauth/fingerprints").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[tokio::test]
    async fn list_fingerprints_with_valid_session_returns_200() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-fp-ok");
        let token = "fp-session-token";

        store
            .lock()
            .unwrap()
            .insert_session(&make_session(&did, token, 1_000_000))
            .unwrap();

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/fingerprints", did.as_str()),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        // No fingerprints stored → empty list
        assert_eq!(body["fingerprints"].as_array().unwrap().len(), 0);
    }

    // -----------------------------------------------------------------------
    // §12.2.7 — peer attestation
    // -----------------------------------------------------------------------

    async fn post_with_auth(
        app: &Router,
        uri: &str,
        token: &str,
        body: serde_json::Value,
    ) -> axum::response::Response {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(body.to_string()))
            .unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    async fn post_with_signed_auth(
        app: &Router,
        uri: &str,
        token: &str,
        nonce: &str,
        body: serde_json::Value,
        keypair: &KeyPair,
    ) -> axum::response::Response {
        let body_bytes = body.to_string();
        let (nonce, signature) =
            request_signature_headers("POST", uri, token, nonce, body_bytes.as_bytes(), keypair);
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header("x-exo-nonce", nonce)
            .header("x-exo-sig", signature)
            .body(Body::from(body_bytes))
            .unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn attest_without_auth_returns_401() {
        let app = api_app(new_shared_store());
        let resp = post_json(
            &app,
            "/api/v1/0dentity/did:exo:attester/attest",
            serde_json::json!({
                "target_did": "did:exo:target",
                "attestation_type": "Identity"
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn attest_invalid_attestation_type_returns_400() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let attester = td("attest-type-err");
        let token = "attest-type-token";
        let keypair = test_keypair(11);

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&attester, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session_with_public_key(
                &attester,
                token,
                1_000_000,
                keypair.public_key().as_bytes().to_vec(),
            ))
            .unwrap();
        }

        let uri = format!("/api/v1/0dentity/{}/attest", attester.as_str());
        let resp = post_with_signed_auth(
            &app,
            &uri,
            token,
            "nonce-invalid-type",
            serde_json::json!({
                "target_did": "did:exo:target",
                "attestation_type": "NotAType"
            }),
            &keypair,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn attest_write_without_session_signature_returns_401() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let attester = td("attest-nosig");
        let target = td("attest-nosig-target");
        let token = "attest-nosig-token";
        let keypair = test_keypair(12);

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&attester, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session_with_public_key(
                &attester,
                token,
                1_000_000,
                keypair.public_key().as_bytes().to_vec(),
            ))
            .unwrap();
        }

        let resp = post_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/attest", attester.as_str()),
            token,
            serde_json::json!({
                "target_did": target.as_str(),
                "attestation_type": "Identity"
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn attest_unsigned_body_returns_400() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let attester = td("attest-unsigned-a");
        let target = td("attest-unsigned-b");
        let token = "attest-unsigned-token";
        let keypair = test_keypair(18);

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&attester, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session_with_public_key(
                &attester,
                token,
                1_000_000,
                keypair.public_key().as_bytes().to_vec(),
            ))
            .unwrap();
        }

        let resp = post_with_signed_auth(
            &app,
            &format!("/api/v1/0dentity/{}/attest", attester.as_str()),
            token,
            "nonce-unsigned-body",
            serde_json::json!({
                "target_did": target.as_str(),
                "attestation_type": "Identity"
            }),
            &keypair,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn attest_signed_write_rejects_wrong_key() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let attester = td("attest-wrong-key-a");
        let target = td("attest-wrong-key-b");
        let token = "attest-wrong-key-token";
        let session_keypair = test_keypair(13);
        let wrong_keypair = test_keypair(14);

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&attester, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session_with_public_key(
                &attester,
                token,
                1_000_000,
                session_keypair.public_key().as_bytes().to_vec(),
            ))
            .unwrap();
        }

        let uri = format!("/api/v1/0dentity/{}/attest", attester.as_str());
        let resp = post_with_signed_auth(
            &app,
            &uri,
            token,
            "nonce-wrong-key",
            serde_json::json!({
                "target_did": target.as_str(),
                "attestation_type": "Identity"
            }),
            &wrong_keypair,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn attest_wrong_public_key_returns_400() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let attester = td("attest-wrong-public-key-a");
        let target = td("attest-wrong-public-key-b");
        let token = "attest-wrong-public-key-token";
        let session_keypair = test_keypair(19);
        let (public_key, _) = keypair(45);
        let (_, signing_key) = keypair(46);

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&attester, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session_with_public_key(
                &attester,
                token,
                1_000_000,
                session_keypair.public_key().as_bytes().to_vec(),
            ))
            .unwrap();
        }

        let uri = format!("/api/v1/0dentity/{}/attest", attester.as_str());
        let resp = post_with_signed_auth(
            &app,
            &uri,
            token,
            "nonce-wrong-attestation-key",
            signed_attest_body(
                &attester,
                &target,
                AttestationType::Identity,
                None,
                1_236_000,
                &public_key,
                &signing_key,
            ),
            &session_keypair,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn attest_rejects_body_key_that_differs_from_authenticated_session_key() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let attester = td("attest-session-key-a");
        let target = td("attest-session-key-b");
        let token = "attest-session-key-token";
        let session_keypair = test_keypair(20);
        let (body_public_key, body_secret_key) = keypair(47);

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&attester, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session_with_public_key(
                &attester,
                token,
                1_000_000,
                session_keypair.public_key().as_bytes().to_vec(),
            ))
            .unwrap();
        }

        let uri = format!("/api/v1/0dentity/{}/attest", attester.as_str());
        let resp = post_with_signed_auth(
            &app,
            &uri,
            token,
            "nonce-body-key-session-mismatch",
            signed_attest_body(
                &attester,
                &target,
                AttestationType::Identity,
                None,
                1_236_500,
                &body_public_key,
                &body_secret_key,
            ),
            &session_keypair,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let guard = store.lock().unwrap();
        assert!(guard.get_claims(&target).unwrap().is_empty());
        assert!(guard.get_attestation(&attester, &target).unwrap().is_none());
    }

    #[tokio::test]
    async fn attest_valid_creates_attestation_201() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let attester = td("attest-ok-a");
        let target = td("attest-ok-b");
        let token = "attest-ok-token";
        let session_keypair = test_keypair(15);

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&attester, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session_with_public_key(
                &attester,
                token,
                1_000_000,
                session_keypair.public_key().as_bytes().to_vec(),
            ))
            .unwrap();
        }

        let uri = format!("/api/v1/0dentity/{}/attest", attester.as_str());
        let signed_created_ms = 1_234_000;
        let resp = post_with_signed_auth(
            &app,
            &uri,
            token,
            "nonce-valid-attest",
            signed_attest_body(
                &attester,
                &target,
                AttestationType::Identity,
                None,
                signed_created_ms,
                session_keypair.public_key(),
                session_keypair.secret_key(),
            ),
            &session_keypair,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_json(resp).await;
        assert!(
            body["attestation_id"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        let attestation_id = body["attestation_id"].as_str().unwrap();
        assert!(body["receipt_hash"].as_str().is_some_and(|s| s.len() == 64));

        let guard = store.lock().unwrap();
        let target_claims = guard.get_claims(&target).unwrap();
        assert_eq!(target_claims.len(), 1);
        let (claim_id, target_claim) = &target_claims[0];
        let saved_attestation = guard
            .get_attestation(&attester, &target)
            .unwrap()
            .expect("attestation stored");
        assert_eq!(saved_attestation.attestation_id, attestation_id);
        assert_eq!(saved_attestation.created_ms, signed_created_ms);
        assert_eq!(claim_id, &target_claim_id(&saved_attestation).unwrap());
        assert_eq!(target_claim.dag_node_hash, guard.dag_nodes()[0].hash);
        assert_eq!(target_claim.created_ms, API_TEST_NOW_MS);
        assert_eq!(target_claim.verified_ms, Some(API_TEST_NOW_MS));
        assert_eq!(guard.dag_nodes()[0].timestamp.physical_ms, API_TEST_NOW_MS);

        let receipts = guard.trust_receipts();
        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0];
        assert_eq!(receipt.action_type, "zerodentity.claim_verified");
        assert_eq!(receipt.action_hash, target_claim.claim_hash);
        assert_eq!(receipt.timestamp.physical_ms, API_TEST_NOW_MS);
        assert_eq!(
            body["receipt_hash"].as_str().unwrap(),
            hex::encode(receipt.receipt_hash.as_bytes())
        );
    }

    #[tokio::test]
    async fn attest_signed_write_rejects_nonce_replay() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let attester = td("attest-replay-a");
        let target = td("attest-replay-b");
        let token = "attest-replay-token";
        let session_keypair = test_keypair(16);
        let nonce = "nonce-replay";

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&attester, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session_with_public_key(
                &attester,
                token,
                1_000_000,
                session_keypair.public_key().as_bytes().to_vec(),
            ))
            .unwrap();
        }

        let uri = format!("/api/v1/0dentity/{}/attest", attester.as_str());
        let body = signed_attest_body(
            &attester,
            &target,
            AttestationType::Identity,
            None,
            1_237_000,
            session_keypair.public_key(),
            session_keypair.secret_key(),
        );
        let first =
            post_with_signed_auth(&app, &uri, token, nonce, body.clone(), &session_keypair).await;
        assert_eq!(first.status(), StatusCode::CREATED);

        let replay = post_with_signed_auth(&app, &uri, token, nonce, body, &session_keypair).await;
        assert_eq!(replay.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn attest_self_returns_400() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("attest-self");
        let token = "attest-self-token";
        let session_keypair = test_keypair(17);
        let (public_key, secret_key) = keypair(43);

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session_with_public_key(
                &did,
                token,
                1_000_000,
                session_keypair.public_key().as_bytes().to_vec(),
            ))
            .unwrap();
        }

        let uri = format!("/api/v1/0dentity/{}/attest", did.as_str());
        let resp = post_with_signed_auth(
            &app,
            &uri,
            token,
            "nonce-self",
            signed_attest_body(
                &did,
                &did,
                AttestationType::Identity,
                None,
                1_235_000,
                &public_key,
                &secret_key,
            ),
            &session_keypair,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_claims_filters_by_status() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-filter-status");
        let token = "filter-token";

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "c1",
                &make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_claim(
                "c2",
                &make_claim(&did, ClaimType::Phone, ClaimStatus::Pending, 2_000),
            )
            .unwrap();
            s.insert_session(&make_session(&did, token, 1_000_000))
                .unwrap();
        }

        let resp = get_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/claims?status=verified", did.as_str()),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(
            body["total"].as_u64().unwrap(),
            1,
            "only verified claims after filter"
        );
    }

    #[tokio::test]
    async fn get_score_invalid_did_returns_400() {
        let app = api_app(new_shared_store());
        let resp = get_req(&app, "/api/v1/0dentity/not-a-did/score").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn score_history_with_time_filter() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-hist-filter");
        let token = "history-filter-session-token";

        {
            let mut s = store.lock().unwrap();
            s.insert_session(&make_session(&did, token, 1_000_000))
                .unwrap();
            for (bp, ms) in [(1_000u32, 1_000u64), (2_000, 5_000), (3_000, 10_000)] {
                let mut score = make_score(&did, bp, ms);
                score.computed_ms = ms;
                s.put_score(score).unwrap();
            }
        }

        let resp = get_with_auth(
            &app,
            &format!(
                "/api/v1/0dentity/{}/score/history?from_ms=3000&to_ms=7000",
                did.as_str()
            ),
            token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let snaps = body["snapshots"].as_array().unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0]["composite"].as_u64().unwrap(), 2_000);
    }

    // -----------------------------------------------------------------------
    // §12.2.6 — Full onboarding arc (end-to-end)
    //
    // Exercises: DisplayName → Email OTP → verify → score 3500 →
    //            Phone OTP → verify → score 8700 → history → claims auth
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn test_full_onboarding_arc() {
        let store = new_shared_store();
        let onb = onboarding_app(store.clone());
        let api = api_app(store.clone());
        let keypair = test_keypair(21);
        let did = derived_did(&keypair);
        let did_str = did.as_str();

        // ── 1. DisplayName claim ──────────────────────────────────────────
        let resp = post_json(
            &onb,
            "/api/v1/0dentity/claims",
            signed_claim_body(&did, "DisplayName", None, None, 22_430, &keypair, &keypair),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert_eq!(b["status"], "Pending");

        assert_eq!(
            store.lock().unwrap().get_claims(&did).unwrap().len(),
            1,
            "DisplayName claim should be stored"
        );

        // ── 2. Email claim (HTTP) ─────────────────────────────────────────
        let resp = post_json(
            &onb,
            "/api/v1/0dentity/claims",
            signed_claim_body(&did, "Email", None, None, 22_440, &keypair, &keypair),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // ── 3. Email OTP — inject known node-time challenge + verify via HTTP ───────
        let dispatched_ms = API_TEST_NOW_MS;
        let mut rng1 = seeded_rng(0xABC1_0001);
        let (email_ch, email_code) =
            OtpChallenge::new(&did, OtpChannel::Email, dispatched_ms, &mut rng1).unwrap();
        let email_cid = email_ch.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&email_ch)
            .unwrap();

        let resp = post_json(
            &onb,
            "/api/v1/0dentity/verify",
            bootstrap_verify_body(&email_cid, &email_code, &did, &keypair),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert!(b["verified"].as_bool().unwrap(), "email OTP must verify");
        let session_token = b["session_token"].as_str().unwrap().to_owned();

        // ── 4. Promote Email claim to Verified in store ───────────────────
        // (claim status promotion from OTP verification is deferred to APE-72)
        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "email-verified",
                &make_claim(&did, ClaimType::Email, ClaimStatus::Verified, dispatched_ms),
            )
            .unwrap();
        }

        // ── 5. GET /score → communication = 3500 (email only) ────────────
        let resp = get_with_auth(
            &api,
            &format!("/api/v1/0dentity/{did_str}/score"),
            &session_token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert_eq!(
            b["axes"]["communication"].as_u64().unwrap(),
            3_500,
            "email-only communication axis must be 3500bp"
        );

        // ── 6. Phone claim + OTP ──────────────────────────────────────────
        let resp = post_json(
            &onb,
            "/api/v1/0dentity/claims",
            signed_claim_body(&did, "Phone", None, None, 22_450, &keypair, &keypair),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let mut rng2 = seeded_rng(0xABC1_0002);
        let (phone_ch, phone_code) =
            OtpChallenge::new(&did, OtpChannel::Sms, dispatched_ms, &mut rng2).unwrap();
        let phone_cid = phone_ch.challenge_id.clone();
        store
            .lock()
            .unwrap()
            .insert_otp_challenge(&phone_ch)
            .unwrap();

        let resp = post_json(
            &onb,
            "/api/v1/0dentity/verify",
            bootstrap_verify_body(&phone_cid, &phone_code, &did, &keypair),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert!(b["verified"].as_bool().unwrap(), "phone OTP must verify");

        // Promote Phone claim to Verified
        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "phone-verified",
                &make_claim(
                    &did,
                    ClaimType::Phone,
                    ClaimStatus::Verified,
                    dispatched_ms + 1,
                ),
            )
            .unwrap();
        }

        // ── 7. GET /score → communication = 8700 (email+phone+bonus) ─────
        let resp = get_with_auth(
            &api,
            &format!("/api/v1/0dentity/{did_str}/score"),
            &session_token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert_eq!(
            b["axes"]["communication"].as_u64().unwrap(),
            8_700,
            "email+phone communication axis must be 8700bp"
        );
        assert!(
            b["composite"].as_u64().unwrap() > 0,
            "composite must be positive"
        );

        // ── 8. Store a score snapshot and check history ───────────────────
        {
            let mut s = store.lock().unwrap();
            let claims = s.get_claims_slice(&did).unwrap();
            let score = ZerodentityScore::compute(&did, &claims, &[], &[], dispatched_ms + 2);
            s.put_score(score).unwrap();
        }

        let resp = get_with_auth(
            &api,
            &format!("/api/v1/0dentity/{did_str}/score/history"),
            &session_token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert!(
            !b["snapshots"].as_array().unwrap().is_empty(),
            "history must be non-empty after storing a score"
        );

        // ── 9. GET /claims with session token ─────────────────────────────
        let resp = get_with_auth(
            &api,
            &format!("/api/v1/0dentity/{did_str}/claims"),
            &session_token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let b = body_json(resp).await;
        assert!(
            b["total"].as_u64().unwrap() > 0,
            "claims list must be non-empty"
        );
    }

    // -----------------------------------------------------------------------
    // VCG-008 RED — created_ms freshness window (onboarding.rs submit_claim)
    // -----------------------------------------------------------------------
    //
    // `submit_claim` today only checks `created_ms != 0` (onboarding.rs:429).
    // An arbitrarily old or far-future signed payload is accepted as long as
    // the exact bytes have not been seen before (replay dedup is keyed on the
    // full signed payload + signature, not on `created_ms` freshness). These
    // two tests assert a bounded skew window is enforced against the trusted
    // session clock, mirroring `ZERODENTITY_ERASURE_MAX_FUTURE_SKEW_MS` in
    // store.rs. Both are expected to FAIL (accepted with 200 OK instead of
    // rejected) until a freshness/skew check is added.

    // A realistic wall-clock "now" (2026-01-01T00:00:00Z in epoch ms) used for
    // the freshness-window tests so that subtracting a 30-day skew stays well
    // above zero — otherwise `created_ms` could accidentally collide with the
    // pre-existing, unrelated `created_ms == 0` rejection and produce a false
    // green result.
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    const FRESHNESS_TEST_NOW_MS: u64 = 1_767_225_600_000;

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_rejects_stale_created_ms() {
        let store = new_shared_store();
        let app = onboarding_app_with_fixed_clock(store.clone(), FRESHNESS_TEST_NOW_MS);
        let keypair = test_keypair(140);
        let did = derived_did(&keypair);

        // 30 days before the trusted clock — well-formed, correctly signed,
        // but stale by any reasonable bounded skew window.
        const THIRTY_DAYS_MS: u64 = 30 * 24 * 60 * 60 * 1000;
        let stale_created_ms = FRESHNESS_TEST_NOW_MS - THIRTY_DAYS_MS;
        assert!(
            stale_created_ms > 0,
            "test fixture bug: stale_created_ms must stay positive so this test \
             exercises the freshness window, not the unrelated created_ms == 0 check"
        );

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            signed_claim_body(
                &did,
                "DisplayName",
                None,
                None,
                stale_created_ms,
                &keypair,
                &keypair,
            ),
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a claim signed 30 days in the past must be rejected as stale, \
             not accepted because created_ms != 0 and the payload bytes are novel"
        );
        assert!(
            store.lock().unwrap().get_claims(&did).unwrap().is_empty(),
            "a stale-created_ms claim must not be persisted"
        );
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_rejects_future_created_ms_beyond_skew_window() {
        let store = new_shared_store();
        let app = onboarding_app_with_fixed_clock(store.clone(), FRESHNESS_TEST_NOW_MS);
        let keypair = test_keypair(141);
        let did = derived_did(&keypair);

        // 30 days after the trusted clock — mirrors the stale-past case but
        // on the future side of the window.
        const THIRTY_DAYS_MS: u64 = 30 * 24 * 60 * 60 * 1000;
        let future_created_ms = FRESHNESS_TEST_NOW_MS + THIRTY_DAYS_MS;

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            signed_claim_body(
                &did,
                "DisplayName",
                None,
                None,
                future_created_ms,
                &keypair,
                &keypair,
            ),
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a claim signed 30 days in the future must be rejected as beyond \
             the trusted clock's bounded future-skew tolerance"
        );
        assert!(
            store.lock().unwrap().get_claims(&did).unwrap().is_empty(),
            "a future-created_ms claim beyond the skew window must not be persisted"
        );
    }

    // -----------------------------------------------------------------------
    // VCG-008 RED — bearer gate + PoP gate composition through the full router
    // -----------------------------------------------------------------------
    //
    // Every existing onboarding test above drives `onboarding_app()`, which
    // builds `onboarding_router` in isolation — it never passes through
    // `auth::require_bearer_on_writes`. Production wires the two together
    // (main.rs:1100-1136: `zerodentity_onboarding_router` merged into
    // `extra_router`, then `.layer(axum::middleware::from_fn(... auth::require_bearer_on_writes))`).
    // This test builds the router the way main.rs does, and proves both
    // gates actually compose: a request with only a valid bearer token and
    // no proof-of-possession must still be rejected (by the PoP gate inside
    // the handler), and a request with valid PoP but no bearer token must be
    // rejected at the bearer layer before it ever reaches the handler.

    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    fn full_router_with_bearer(
        store: SharedZerodentityStore,
        now_ms: u64,
        bearer_token: &str,
    ) -> Router {
        let onboarding = onboarding_app_with_fixed_clock(store, now_ms);
        let auth = crate::auth::BearerAuth::from_bearer(bearer_token);
        onboarding.layer(axum::middleware::from_fn(move |req, next| {
            let a = auth.clone();
            crate::auth::require_bearer_on_writes(a, req, next)
        }))
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn bearer_gate_and_pop_gate_compose_through_full_router() {
        const BEARER_TOKEN: &str = "vcg-008-full-router-bearer-token";
        let store = new_shared_store();
        let app = full_router_with_bearer(store.clone(), API_TEST_NOW_MS, BEARER_TOKEN);
        let keypair = test_keypair(142);
        let did = derived_did(&keypair);

        // Case 1: valid bearer token, but NO public_key/signature (no PoP).
        // The bearer layer must let this through (POST /api/v1/0dentity/claims
        // is not in the local-signed-write allowlist, so it actually requires
        // the bearer token — but the request must still fail at the PoP gate
        // inside the handler, proving the bearer token alone is insufficient).
        let bearer_only_req = Request::builder()
            .method("POST")
            .uri("/api/v1/0dentity/claims")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {BEARER_TOKEN}"))
            .body(Body::from(
                serde_json::json!({
                    "subject_did": did.as_str(),
                    "claim_type": "DisplayName"
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(bearer_only_req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "bearer token alone (no proof-of-possession) must not create a claim \
             through the composed production router"
        );
        assert!(
            store.lock().unwrap().get_claims(&did).unwrap().is_empty(),
            "bearer-only request must not persist a claim"
        );

        // Case 2: valid PoP (signed claim body), but NO bearer token at all.
        // The bearer layer must reject this before the handler's PoP check
        // ever runs.
        let pop_only_body = signed_claim_body(
            &did,
            "DisplayName",
            None,
            None,
            API_TEST_NOW_MS,
            &keypair,
            &keypair,
        );
        let pop_only_req = Request::builder()
            .method("POST")
            .uri("/api/v1/0dentity/claims")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(pop_only_body.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(pop_only_req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a request with valid proof-of-possession but no bearer token must be \
             rejected at the bearer-gate layer of the composed production router"
        );
        assert!(
            store.lock().unwrap().get_claims(&did).unwrap().is_empty(),
            "PoP-only request without a bearer token must not persist a claim"
        );
    }

    // -----------------------------------------------------------------------
    // VCG-009 RED — device/behavioral sample ingestion must be consent-scoped,
    // persisted, replay-safe, bounded, and scored from STORED evidence.
    //
    // Ledger invariant (GAP-REGISTRY.md VCG-009): "Device and behavioral
    // sample fields are rejected UNLESS consent-scoped, privacy-reviewed,
    // persisted, replay-safe, and scored from STORED evidence."
    //
    // These tests drive the real HTTP surface
    // (`onboarding_app` + `POST /api/v1/0dentity/claims`) using an extended
    // body helper that carries the spec §7.1 sample fields
    // (`device_fingerprint`, `behavioral_hash`, `signal_hashes`) which
    // `SubmitClaimRequest` does not yet accept. They are gated on
    // `unaudited-zerodentity-device-behavioral-axes` alone (Gate 23 tests
    // every unaudited feature in isolation — VCG-009's own closure gate is
    // `cargo test -p exochain-node zerodentity --features
    // unaudited-zerodentity-device-behavioral-axes`), independent of
    // `unaudited-zerodentity-first-touch-onboarding`.
    // -----------------------------------------------------------------------

    /// Test-only extended claim submission body carrying the spec §7.1
    /// device/behavioral sample fields that `SubmitClaimRequest` does not
    /// yet declare. Built independently of `signed_claim_body` (which is
    /// gated on `unaudited-zerodentity-first-touch-onboarding`, a feature
    /// this test group does not enable per Gate 23 isolation).
    ///
    /// GREEN (VCG-009 corrective) closed the proof-of-possession hole by
    /// requiring `crypto::verify` over the canonical, sample-bound
    /// `device_behavioral_submission_signing_payload` (see below). This
    /// helper now signs over that exact same payload shape locally
    /// (duplicated here per Gate 23 isolation — this test group cannot
    /// depend on the production `session_auth` module) so that callers
    /// exercising the "well-formed, self-signed, real samples" happy path
    /// continue to verify against the production handler.
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[allow(clippy::too_many_arguments)]
    fn device_behavioral_claim_body(
        subject_did: &Did,
        claim_type: &str,
        created_ms: u64,
        public_keypair: &KeyPair,
        signing_keypair: &KeyPair,
        device_fingerprint_hex: &str,
        behavioral_hash_hex: &str,
        signal_hashes: &std::collections::BTreeMap<String, String>,
        consent_receipt_id: Option<&str>,
    ) -> Value {
        let payload = device_behavioral_submission_signing_payload(
            subject_did,
            Some(device_fingerprint_hex),
            Some(behavioral_hash_hex),
            signal_hashes,
            public_keypair.public_key(),
        );
        let signature = signing_keypair.sign(&payload);
        serde_json::json!({
            "subject_did": subject_did.as_str(),
            "claim_type": claim_type,
            "created_ms": created_ms,
            "public_key": hex::encode(public_keypair.public_key().as_bytes()),
            "signature": hex::encode(signature.to_bytes()),
            "device_fingerprint": device_fingerprint_hex,
            "behavioral_hash": behavioral_hash_hex,
            "signal_hashes": signal_hashes,
            "consent_receipt_id": consent_receipt_id,
        })
    }

    // -----------------------------------------------------------------------
    // VCG-009 STRENGTHEN-RED — proof-of-possession over the sample-bound
    // payload.
    //
    // The refuted green (7a7340e8) never calls `crypto::verify` in
    // `handle_device_behavioral_ingestion`: it only checks
    // `signature.is_empty()` after confirming `public_key` derives
    // `subject_did` — but a DID and a public key are BOTH spec-classified
    // Public (docs/0DENTITY-APP-SPEC.md §7.1), so that proves nothing about
    // possession of the matching PRIVATE key. Combined with a consent gate
    // that only requires "some session exists for this DID"
    // (`has_active_session_for`), an attacker who merely knows a victim's
    // public DID + public key can submit device/behavioral samples under the
    // victim's identity with a garbage signature.
    //
    // This canonical payload is the binding GREEN must implement to close
    // the hole. Domain-separated CBOR, mirroring the existing
    // `session_auth.rs` pattern (`bootstrap_signing_payload`,
    // `claim_submission_signing_payload`) so the fix is a natural extension
    // of that module rather than a bespoke scheme:
    //
    //   DeviceBehavioralSubmissionSigningPayload {
    //       domain: "exo.zerodentity.device_behavioral_submission.v1",
    //       subject_did: &str,
    //       device_fingerprint: Option<&str>,   // hex, as received on the wire
    //       behavioral_hash: Option<&str>,      // hex, as received on the wire
    //       signal_hashes: &BTreeMap<String, String>, // sorted key order (BTreeMap)
    //       public_key: &PublicKey,
    //   }
    //   encoded via `ciborium::into_writer` (canonical CBOR, same helper
    //   shape as `encode_cbor` in session_auth.rs).
    //
    // `claim_type`/`created_ms`/`provider`/`consent_receipt_id` are
    // deliberately NOT bound into this payload: they are either routing
    // metadata (claim_type/provider feed `parse_claim_type`, which is
    // orthogonal to sample authenticity) or a capability reference
    // (consent_receipt_id, checked separately by the consent gate) rather
    // than sample content. Binding `subject_did`, the sample fields, and the
    // signer's own `public_key` is what prevents (b) cross-account replay and
    // (c) sample-substitution.
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[derive(serde::Serialize)]
    struct DeviceBehavioralSubmissionSigningPayload<'a> {
        domain: &'static str,
        subject_did: &'a str,
        device_fingerprint: Option<&'a str>,
        behavioral_hash: Option<&'a str>,
        signal_hashes: &'a std::collections::BTreeMap<String, String>,
        public_key: &'a PublicKey,
    }

    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    const DEVICE_BEHAVIORAL_SUBMISSION_SIGNING_DOMAIN: &str =
        "exo.zerodentity.device_behavioral_submission.v1";

    /// Builds the exact canonical bytes a correct GREEN handler must verify
    /// the signature over. Any GREEN implementation that binds a different
    /// byte layout will fail test (d) (the happy path) here, forcing the
    /// signing payload shape to be an explicit, negotiated contract rather
    /// than an implementation accident.
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    fn device_behavioral_submission_signing_payload(
        subject_did: &Did,
        device_fingerprint_hex: Option<&str>,
        behavioral_hash_hex: Option<&str>,
        signal_hashes: &std::collections::BTreeMap<String, String>,
        public_key: &PublicKey,
    ) -> Vec<u8> {
        let payload = DeviceBehavioralSubmissionSigningPayload {
            domain: DEVICE_BEHAVIORAL_SUBMISSION_SIGNING_DOMAIN,
            subject_did: subject_did.as_str(),
            device_fingerprint: device_fingerprint_hex,
            behavioral_hash: behavioral_hash_hex,
            signal_hashes,
            public_key,
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&payload, &mut encoded)
            .expect("canonical CBOR encoding of test payload must not fail");
        encoded
    }

    /// Like `device_behavioral_claim_body`, but signs over the REAL canonical
    /// sample-bound payload (`device_behavioral_submission_signing_payload`)
    /// with an explicit, separately-controllable signing keypair — letting
    /// tests construct a victim's real DID/public_key while signing with an
    /// attacker's key (cross-account), or sign over one sample set and
    /// submit another (sample-substitution).
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[allow(clippy::too_many_arguments)]
    fn device_behavioral_claim_body_signed_over(
        subject_did: &Did,
        claim_type: &str,
        created_ms: u64,
        public_keypair: &KeyPair,
        signing_keypair: &KeyPair,
        signed_device_fingerprint_hex: Option<&str>,
        signed_behavioral_hash_hex: Option<&str>,
        signed_signal_hashes: &std::collections::BTreeMap<String, String>,
        submitted_device_fingerprint_hex: &str,
        submitted_behavioral_hash_hex: &str,
        submitted_signal_hashes: &std::collections::BTreeMap<String, String>,
        consent_receipt_id: Option<&str>,
    ) -> Value {
        let payload = device_behavioral_submission_signing_payload(
            subject_did,
            signed_device_fingerprint_hex,
            signed_behavioral_hash_hex,
            signed_signal_hashes,
            public_keypair.public_key(),
        );
        let signature = signing_keypair.sign(&payload);
        serde_json::json!({
            "subject_did": subject_did.as_str(),
            "claim_type": claim_type,
            "created_ms": created_ms,
            "public_key": hex::encode(public_keypair.public_key().as_bytes()),
            "signature": hex::encode(signature.to_bytes()),
            "device_fingerprint": submitted_device_fingerprint_hex,
            "behavioral_hash": submitted_behavioral_hash_hex,
            "signal_hashes": submitted_signal_hashes,
            "consent_receipt_id": consent_receipt_id,
        })
    }

    /// A syntactically well-formed but cryptographically meaningless
    /// signature: parses fine via `signature_from_hex` (64 bytes of hex) but
    /// was never produced by any real Ed25519 signing operation over
    /// anything. Stands in for "attacker has no private key at all and just
    /// fills the field with junk."
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    fn garbage_signature_hex() -> String {
        hex::encode([0xAAu8; 64])
    }

    /// Always-compiled (no feature gate — runs in every build including the
    /// default no-features build and the VCG-009 axes-on gate build alike):
    /// proves the score engine's default-off behavior at the scoring layer
    /// is exactly `device_behavioral_axes_enabled()`, never hard-coded true
    /// or false. This does not touch — and must not weaken — the existing
    /// `list_fingerprints_refused_without_device_behavioral_feature_flag`
    /// HTTP refusal test; it re-asserts the same default-off invariant at
    /// the scoring layer so the guarantee holds regardless of which HTTP
    /// route a future refactor puts sample reads behind.
    #[test]
    fn device_behavioral_axes_score_tracks_feature_flag_exactly() {
        let did = td("vcg009-default-off");
        let fp = make_fingerprint("default-off", 1_000);
        let sample =
            make_behavioral_sample("default-off", BehavioralSignalType::MouseDynamics, 1_000);

        let score = ZerodentityScore::compute(&did, &[], &[fp], &[sample], 5_000);

        if crate::zerodentity::device_behavioral_axes_enabled() {
            assert!(
                score.axes.device_trust > 0,
                "device_trust must be non-zero from stored fingerprints when the axes feature is ON"
            );
            assert!(
                score.axes.behavioral_signature > 0,
                "behavioral_signature must be non-zero from stored samples when the axes feature is ON"
            );
        } else {
            assert_eq!(
                score.axes.device_trust, 0,
                "device_trust must stay 0 while unaudited-zerodentity-device-behavioral-axes is off, \
                 even when fingerprints are present in the evidence slice"
            );
            assert_eq!(
                score.axes.behavioral_signature, 0,
                "behavioral_signature must stay 0 while unaudited-zerodentity-device-behavioral-axes is off, \
                 even when behavioral samples are present in the evidence slice"
            );
        }
    }

    /// (a) A submit carrying device/behavioral sample fields WITHOUT a valid,
    /// in-scope consent record is rejected and NOTHING is persisted.
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[tokio::test]
    async fn submit_claim_with_device_behavioral_fields_without_consent_is_rejected_and_not_persisted()
     {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let keypair = test_keypair(209);
        let did = derived_did(&keypair);

        let mut signal_hashes = std::collections::BTreeMap::new();
        signal_hashes.insert("CanvasRendering".to_owned(), hex::encode([7u8; 32]));
        signal_hashes.insert("WebGLParameters".to_owned(), hex::encode([8u8; 32]));

        let body = device_behavioral_claim_body(
            &did,
            "DisplayName",
            1_700_100_001,
            &keypair,
            &keypair,
            &hex::encode([9u8; 32]),
            &hex::encode([10u8; 32]),
            &signal_hashes,
            None, // no consent receipt at all
        );

        let resp = post_json(&app, "/api/v1/0dentity/claims", body).await;
        let status = resp.status();
        let body = body_json(resp).await;

        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::BAD_REQUEST,
            "submitting device/behavioral sample fields without an in-scope consent record \
             must be refused (403/400), got {status}: {body}"
        );
        // The refusal must name consent as the reason — a generic
        // "first-touch onboarding disabled" refusal (today's actual
        // behavior under this feature alone) is not evidence that consent
        // scoping was ever evaluated.
        let error_text = body["error"].as_str().unwrap_or_default();
        let message_text = body["message"].as_str().unwrap_or_default();
        assert!(
            error_text.contains("consent") || message_text.contains("consent"),
            "the refusal for a device/behavioral submit with no consent record must cite \
             consent as the reason, got: {body}"
        );
        assert!(
            store
                .lock()
                .unwrap()
                .get_fingerprints(&did)
                .unwrap()
                .is_empty(),
            "no consent record must mean nothing is persisted to the fingerprint store"
        );
        assert!(
            store
                .lock()
                .unwrap()
                .get_behavioral_samples(&did)
                .unwrap()
                .is_empty(),
            "no consent record must mean nothing is persisted to the behavioral sample store"
        );
    }

    /// (b) A submit WITH a valid consent record persists the samples via
    /// put_fingerprint/put_behavioral, and a subsequent get_score reflects a
    /// non-zero device_trust / behavioral_signature axis derived from the
    /// STORED samples (not from the request echo).
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[tokio::test]
    async fn submit_claim_with_valid_consent_persists_samples_and_scores_from_store() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let keypair = test_keypair(210);
        let did = derived_did(&keypair);
        let token = "vcg009-consent-session-token";

        // Simulate an owner session the way other authenticated flows do —
        // GREEN must define how a consent receipt is actually registered
        // (exo_consent::gatekeeper::ConsentGate) and looked up here; this ID
        // is a placeholder for "a valid, in-scope consent record exists".
        store
            .lock()
            .unwrap()
            .insert_session(&make_session(&did, token, 1_000_000))
            .unwrap();
        let consent_receipt_id = "vcg009-valid-consent-receipt-01";

        let mut signal_hashes = std::collections::BTreeMap::new();
        signal_hashes.insert("CanvasRendering".to_owned(), hex::encode([11u8; 32]));
        signal_hashes.insert("WebGLParameters".to_owned(), hex::encode([12u8; 32]));
        signal_hashes.insert("UserAgent".to_owned(), hex::encode([13u8; 32]));

        let body = device_behavioral_claim_body(
            &did,
            "DisplayName",
            1_700_100_002,
            &keypair,
            &keypair,
            &hex::encode([14u8; 32]),
            &hex::encode([15u8; 32]),
            &signal_hashes,
            Some(consent_receipt_id),
        );

        let resp = post_json(&app, "/api/v1/0dentity/claims", body).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a submit with a valid, in-scope consent record must succeed"
        );

        let fingerprints = store.lock().unwrap().get_fingerprints(&did).unwrap();
        assert_eq!(
            fingerprints.len(),
            1,
            "a consented submit must persist exactly one device fingerprint via put_fingerprint"
        );
        let behavioral = store.lock().unwrap().get_behavioral_samples(&did).unwrap();
        assert_eq!(
            behavioral.len(),
            1,
            "a consented submit must persist exactly one behavioral sample via put_behavioral"
        );

        // Score must reflect STORED evidence, not merely echo the request.
        let claims: Vec<_> = store
            .lock()
            .unwrap()
            .get_claims(&did)
            .unwrap()
            .into_iter()
            .map(|(_, c)| c)
            .collect();
        let score = ZerodentityScore::compute(&did, &claims, &fingerprints, &behavioral, 5_000_000);
        assert!(
            score.axes.device_trust > 0,
            "device_trust axis must be non-zero once fingerprints are persisted and read back \
             from the store, got {}",
            score.axes.device_trust
        );
        assert!(
            score.axes.behavioral_signature > 0,
            "behavioral_signature axis must be non-zero once behavioral samples are persisted \
             and read back from the store, got {}",
            score.axes.behavioral_signature
        );

        // And the HTTP score endpoint (the actual production read path) must
        // report the same thing — not just the direct store/scoring call.
        let score_resp = get_with_auth(
            &app_with_api(store.clone()),
            &format!("/api/v1/0dentity/{}/score", did.as_str()),
            token,
        )
        .await;
        assert_eq!(score_resp.status(), StatusCode::OK);
        let score_body = body_json(score_resp).await;
        assert!(
            score_body["axes"]["device_trust"].as_u64().unwrap_or(0) > 0,
            "GET /score must reflect the persisted device fingerprint, got {score_body}"
        );
        assert!(
            score_body["axes"]["behavioral_signature"]
                .as_u64()
                .unwrap_or(0)
                > 0,
            "GET /score must reflect the persisted behavioral sample, got {score_body}"
        );
    }

    /// Small helper standing in for wiring the onboarding store into the
    /// score-reading `api_app` router — VCG-009 must close this loop so a
    /// consented submit through onboarding is visible through the scoring
    /// API against the SAME store.
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    fn app_with_api(store: SharedZerodentityStore) -> Router {
        api_app(store)
    }

    /// (c) Replay-safety: submitting the same sample payload twice does not
    /// double-count / inflate the score (idempotent or explicitly deduped by
    /// content hash); a stale/replayed sample is rejected or ignored.
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[tokio::test]
    async fn submit_claim_replayed_device_behavioral_sample_does_not_double_count() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let keypair = test_keypair(211);
        let did = derived_did(&keypair);
        let token = "vcg009-replay-session-token";

        store
            .lock()
            .unwrap()
            .insert_session(&make_session(&did, token, 1_000_000))
            .unwrap();
        let consent_receipt_id = "vcg009-valid-consent-receipt-02";

        let mut signal_hashes = std::collections::BTreeMap::new();
        signal_hashes.insert("CanvasRendering".to_owned(), hex::encode([21u8; 32]));

        let fingerprint_hex = hex::encode([22u8; 32]);
        let behavioral_hex = hex::encode([23u8; 32]);

        let body = device_behavioral_claim_body(
            &did,
            "DisplayName",
            1_700_100_003,
            &keypair,
            &keypair,
            &fingerprint_hex,
            &behavioral_hex,
            &signal_hashes,
            Some(consent_receipt_id),
        );

        let first = post_json(&app, "/api/v1/0dentity/claims", body.clone()).await;
        assert_eq!(first.status(), StatusCode::OK);

        // Replay the identical sample payload (same composite hashes, same
        // captured_ms semantics) a second time.
        let second = post_json(&app, "/api/v1/0dentity/claims", body).await;
        assert!(
            second.status() == StatusCode::OK || second.status() == StatusCode::CONFLICT,
            "a replayed identical sample submission must either be idempotently accepted \
             or explicitly rejected as a duplicate, got {}",
            second.status()
        );

        let fingerprints = store.lock().unwrap().get_fingerprints(&did).unwrap();
        assert_eq!(
            fingerprints.len(),
            1,
            "replaying the identical device fingerprint payload must not create a second \
             stored fingerprint entry (dedup by content hash), got {} entries",
            fingerprints.len()
        );
        let behavioral = store.lock().unwrap().get_behavioral_samples(&did).unwrap();
        assert_eq!(
            behavioral.len(),
            1,
            "replaying the identical behavioral sample payload must not create a second \
             stored behavioral entry (dedup by content hash), got {} entries",
            behavioral.len()
        );
    }

    /// (d) Bounded ingestion: oversized or over-count sample payloads are
    /// rejected (documented cap), no unbounded growth.
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[tokio::test]
    async fn submit_claim_oversized_signal_hashes_map_is_rejected() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let keypair = test_keypair(212);
        let did = derived_did(&keypair);
        let token = "vcg009-bounds-session-token";

        store
            .lock()
            .unwrap()
            .insert_session(&make_session(&did, token, 1_000_000))
            .unwrap();
        let consent_receipt_id = "vcg009-valid-consent-receipt-03";

        // FingerprintSignal only has 15 documented variants (types.rs); an
        // over-count map like this cannot correspond to real signal types
        // and must be rejected as exceeding the documented ingestion cap.
        let mut signal_hashes = std::collections::BTreeMap::new();
        for i in 0..500u32 {
            let byte = u8::try_from(i % 256).unwrap_or(0);
            signal_hashes.insert(format!("UnknownSignal{i}"), hex::encode([byte; 32]));
        }

        let body = device_behavioral_claim_body(
            &did,
            "DisplayName",
            1_700_100_004,
            &keypair,
            &keypair,
            &hex::encode([30u8; 32]),
            &hex::encode([31u8; 32]),
            &signal_hashes,
            Some(consent_receipt_id),
        );

        let resp = post_json(&app, "/api/v1/0dentity/claims", body).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "an oversized signal_hashes map must be rejected under the documented ingestion \
             cap, got {}",
            resp.status()
        );
        assert!(
            store
                .lock()
                .unwrap()
                .get_fingerprints(&did)
                .unwrap()
                .is_empty(),
            "a rejected oversized payload must not persist a partial fingerprint"
        );
    }

    // -----------------------------------------------------------------------
    // VCG-009 STRENGTHEN-RED (corrective) — crypto-verified proof-of-
    // possession. These tests FAIL against the refuted green (7a7340e8):
    // `handle_device_behavioral_ingestion` never calls `crypto::verify`, so
    // it accepts a syntactically well-formed but cryptographically
    // meaningless signature as long as `public_key` derives `subject_did`
    // (proves nothing — a DID and public key are both Public per spec §7.1)
    // and SOME session exists for that DID (self-consent, not proof of
    // possession).
    // -----------------------------------------------------------------------

    /// (a) A device/behavioral submit whose signature does NOT
    /// cryptographically verify against `subject_did`'s public key over the
    /// canonical sample-bound payload must be REJECTED (401) and must
    /// persist NOTHING — even though `public_key` correctly derives
    /// `subject_did` and a live session exists (so the current, broken
    /// consent gate alone would happily grant this).
    ///
    /// FAILS against 7a7340e8: the handler only checks
    /// `signature.is_empty()`, so 64 bytes of `0xAA` sail straight through.
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[tokio::test]
    async fn submit_claim_with_non_verifying_signature_is_rejected_and_not_persisted() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let keypair = test_keypair(220);
        let did = derived_did(&keypair);
        let token = "vcg009-pop-garbage-session-token";

        // A live session exists for this DID — proves the old consent gate
        // (has_active_session_for) is satisfied, isolating the failure to
        // the missing crypto::verify call specifically.
        store
            .lock()
            .unwrap()
            .insert_session(&make_session(&did, token, 1_000_000))
            .unwrap();
        let consent_receipt_id = "vcg009-pop-garbage-consent-receipt";

        let mut signal_hashes = std::collections::BTreeMap::new();
        signal_hashes.insert("CanvasRendering".to_owned(), hex::encode([40u8; 32]));

        let fingerprint_hex = hex::encode([41u8; 32]);
        let behavioral_hex = hex::encode([42u8; 32]);

        // Build the request body directly (not via
        // device_behavioral_claim_body_signed_over) so the `signature` field
        // is unambiguously garbage rather than a signature over some other
        // payload — this isolates "no valid signature at all" from the
        // cross-account/substitution cases below.
        let body = serde_json::json!({
            "subject_did": did.as_str(),
            "claim_type": "DisplayName",
            "created_ms": 1_700_100_010u64,
            "public_key": hex::encode(keypair.public_key().as_bytes()),
            "signature": garbage_signature_hex(),
            "device_fingerprint": fingerprint_hex,
            "behavioral_hash": behavioral_hex,
            "signal_hashes": signal_hashes,
            "consent_receipt_id": consent_receipt_id,
        });

        let resp = post_json(&app, "/api/v1/0dentity/claims", body).await;
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a device/behavioral submit whose signature does not cryptographically verify \
             must be rejected 401, got {status}: {body}"
        );

        assert!(
            store
                .lock()
                .unwrap()
                .get_fingerprints(&did)
                .unwrap()
                .is_empty(),
            "a non-verifying signature must mean nothing is persisted to the fingerprint store"
        );
        assert!(
            store
                .lock()
                .unwrap()
                .get_behavioral_samples(&did)
                .unwrap()
                .is_empty(),
            "a non-verifying signature must mean nothing is persisted to the behavioral \
             sample store"
        );
        assert!(
            store.lock().unwrap().get_claims(&did).unwrap().is_empty(),
            "a non-verifying signature must mean no claim is persisted either"
        );
    }

    /// (b) Cross-account attack: the attacker constructs the VICTIM's real
    /// `subject_did` and real `public_key` (both public, both harvestable),
    /// but signs the submission with the ATTACKER's own private key instead
    /// of the victim's. A live session exists for the victim (self-consent
    /// would otherwise grant it). This must be REJECTED and NOTHING
    /// persisted to the victim's store.
    ///
    /// FAILS against 7a7340e8: signature.is_empty() is false (the attacker's
    /// signature bytes are non-empty), so this sails through and the
    /// attacker's fabricated samples land in the victim's fingerprint/
    /// behavioral stores.
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[tokio::test]
    async fn submit_claim_signed_by_attacker_key_for_victim_did_is_rejected_and_not_persisted() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let victim_keypair = test_keypair(221);
        let victim_did = derived_did(&victim_keypair);
        let attacker_keypair = test_keypair(222);
        let token = "vcg009-pop-cross-account-session-token";

        // The victim has a live session — the exact condition the current
        // has_active_session_for-based consent gate treats as sufficient.
        store
            .lock()
            .unwrap()
            .insert_session(&make_session(&victim_did, token, 1_000_000))
            .unwrap();
        let consent_receipt_id = "vcg009-pop-cross-account-consent-receipt";

        let mut signal_hashes = std::collections::BTreeMap::new();
        signal_hashes.insert("CanvasRendering".to_owned(), hex::encode([50u8; 32]));
        let fingerprint_hex = hex::encode([51u8; 32]);
        let behavioral_hex = hex::encode([52u8; 32]);

        // The request carries the VICTIM's subject_did and public_key (so
        // `derived_did == subject_did` passes), but the payload is signed by
        // the ATTACKER's key.
        let body = device_behavioral_claim_body_signed_over(
            &victim_did,
            "DisplayName",
            1_700_100_011,
            &victim_keypair, // public_key on the wire: victim's (correct derivation)
            &attacker_keypair, // signing_keypair: attacker's — the attack
            Some(&fingerprint_hex),
            Some(&behavioral_hex),
            &signal_hashes,
            &fingerprint_hex,
            &behavioral_hex,
            &signal_hashes,
            Some(consent_receipt_id),
        );

        let resp = post_json(&app, "/api/v1/0dentity/claims", body).await;
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a submission signed by an attacker's key over a victim's subject_did/public_key \
             must be rejected 401 even though the victim holds an active session, got \
             {status}: {body}"
        );

        assert!(
            store
                .lock()
                .unwrap()
                .get_fingerprints(&victim_did)
                .unwrap()
                .is_empty(),
            "an attacker-signed submission must not persist a fingerprint into the victim's store"
        );
        assert!(
            store
                .lock()
                .unwrap()
                .get_behavioral_samples(&victim_did)
                .unwrap()
                .is_empty(),
            "an attacker-signed submission must not persist a behavioral sample into the \
             victim's store"
        );
        assert!(
            store
                .lock()
                .unwrap()
                .get_claims(&victim_did)
                .unwrap()
                .is_empty(),
            "an attacker-signed submission must not persist a claim under the victim's DID"
        );
    }

    /// (b-alt) Same cross-account attack, but the attacker doesn't even
    /// bother deriving a real key pair for the "signature" — plain garbage
    /// bytes, over the victim's real DID + public_key, with the victim's
    /// active session in place. Belt-and-suspenders alongside the dedicated
    /// attacker-keypair variant above: proves the hole isn't merely
    /// "signature must decode as 64 bytes" but "signature must verify".
    ///
    /// FAILS against 7a7340e8 for the same reason as (a).
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[tokio::test]
    async fn submit_claim_garbage_signature_over_victim_identity_is_rejected_and_not_persisted() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let victim_keypair = test_keypair(223);
        let victim_did = derived_did(&victim_keypair);
        let token = "vcg009-pop-cross-account-garbage-session-token";

        store
            .lock()
            .unwrap()
            .insert_session(&make_session(&victim_did, token, 1_000_000))
            .unwrap();
        let consent_receipt_id = "vcg009-pop-cross-account-garbage-consent-receipt";

        let mut signal_hashes = std::collections::BTreeMap::new();
        signal_hashes.insert("WebGLParameters".to_owned(), hex::encode([53u8; 32]));
        let fingerprint_hex = hex::encode([54u8; 32]);
        let behavioral_hex = hex::encode([55u8; 32]);

        let body = serde_json::json!({
            "subject_did": victim_did.as_str(),
            "claim_type": "DisplayName",
            "created_ms": 1_700_100_012u64,
            "public_key": hex::encode(victim_keypair.public_key().as_bytes()),
            "signature": garbage_signature_hex(),
            "device_fingerprint": fingerprint_hex,
            "behavioral_hash": behavioral_hex,
            "signal_hashes": signal_hashes,
            "consent_receipt_id": consent_receipt_id,
        });

        let resp = post_json(&app, "/api/v1/0dentity/claims", body).await;
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "an attacker who knows only a victim's public DID + public key, with a garbage \
             signature, must be rejected 401 even though the victim holds an active session, \
             got {status}: {body}"
        );
        assert!(
            store
                .lock()
                .unwrap()
                .get_fingerprints(&victim_did)
                .unwrap()
                .is_empty(),
            "the confirmed VCG-009 exploit path must not persist a fingerprint for the victim"
        );
        assert!(
            store
                .lock()
                .unwrap()
                .get_behavioral_samples(&victim_did)
                .unwrap()
                .is_empty(),
            "the confirmed VCG-009 exploit path must not persist a behavioral sample for the \
             victim"
        );
    }

    /// (c) Sample-substitution: a signature validly produced by the
    /// subject's own key over sample set A (fingerprint/behavioral/signal
    /// hashes A) must NOT authorize submitting a DIFFERENT sample set B on
    /// the wire. If the payload weren't sample-bound, an on-path attacker
    /// (or the subject's own compromised client) could swap in arbitrary
    /// fabricated evidence under a signature that was only ever meant to
    /// authorize the original samples.
    ///
    /// FAILS against 7a7340e8: the handler never calls crypto::verify at
    /// all, so it cannot possibly notice that the signature (whatever it
    /// covers) doesn't match the submitted sample bytes — this test is
    /// really "no sample-binding exists" wearing the substitution framing,
    /// and it fails for the same root reason as (a)/(b).
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[tokio::test]
    async fn submit_claim_signature_over_different_samples_is_rejected_and_not_persisted() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let keypair = test_keypair(224);
        let did = derived_did(&keypair);
        let token = "vcg009-pop-substitution-session-token";

        store
            .lock()
            .unwrap()
            .insert_session(&make_session(&did, token, 1_000_000))
            .unwrap();
        let consent_receipt_id = "vcg009-pop-substitution-consent-receipt";

        // Sample set A — what the signature is REALLY over.
        let mut signal_hashes_a = std::collections::BTreeMap::new();
        signal_hashes_a.insert("CanvasRendering".to_owned(), hex::encode([60u8; 32]));
        let fingerprint_hex_a = hex::encode([61u8; 32]);
        let behavioral_hex_a = hex::encode([62u8; 32]);

        // Sample set B — what actually gets submitted on the wire, under the
        // signature that was only ever produced over set A.
        let mut signal_hashes_b = std::collections::BTreeMap::new();
        signal_hashes_b.insert("WebGLParameters".to_owned(), hex::encode([63u8; 32]));
        let fingerprint_hex_b = hex::encode([64u8; 32]);
        let behavioral_hex_b = hex::encode([65u8; 32]);

        let body = device_behavioral_claim_body_signed_over(
            &did,
            "DisplayName",
            1_700_100_013,
            &keypair,
            &keypair, // subject signs with their OWN key — over set A
            Some(&fingerprint_hex_a),
            Some(&behavioral_hex_a),
            &signal_hashes_a,
            &fingerprint_hex_b, // but set B is what's actually submitted
            &behavioral_hex_b,
            &signal_hashes_b,
            Some(consent_receipt_id),
        );

        let resp = post_json(&app, "/api/v1/0dentity/claims", body).await;
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a signature validly produced over one sample set must not authorize submitting \
             a different sample set, got {status}: {body}"
        );

        assert!(
            store
                .lock()
                .unwrap()
                .get_fingerprints(&did)
                .unwrap()
                .is_empty(),
            "sample-substitution must not persist the substituted fingerprint (set B)"
        );
        assert!(
            store
                .lock()
                .unwrap()
                .get_behavioral_samples(&did)
                .unwrap()
                .is_empty(),
            "sample-substitution must not persist the substituted behavioral sample (set B)"
        );
    }

    /// (d) Happy path: a submit whose signature is a REAL Ed25519 signature
    /// by `subject_did`'s own private key, over the canonical sample-bound
    /// payload for the SAME samples actually submitted, with a valid
    /// in-scope consent record, must be ACCEPTED and persisted — and
    /// `get_score` (both the direct scoring call and the real `GET /score`
    /// HTTP surface) must reflect the stored samples. This must keep passing
    /// once GREEN closes (a)-(c); it is the control proving the fix isn't
    /// simply "reject everything".
    #[cfg(feature = "unaudited-zerodentity-device-behavioral-axes")]
    #[tokio::test]
    async fn submit_claim_with_real_signature_over_canonical_payload_is_accepted_and_scored() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let keypair = test_keypair(225);
        let did = derived_did(&keypair);
        let token = "vcg009-pop-happy-path-session-token";

        store
            .lock()
            .unwrap()
            .insert_session(&make_session(&did, token, 1_000_000))
            .unwrap();
        let consent_receipt_id = "vcg009-pop-happy-path-consent-receipt";

        let mut signal_hashes = std::collections::BTreeMap::new();
        signal_hashes.insert("CanvasRendering".to_owned(), hex::encode([70u8; 32]));
        signal_hashes.insert("WebGLParameters".to_owned(), hex::encode([71u8; 32]));
        let fingerprint_hex = hex::encode([72u8; 32]);
        let behavioral_hex = hex::encode([73u8; 32]);

        let body = device_behavioral_claim_body_signed_over(
            &did,
            "DisplayName",
            1_700_100_014,
            &keypair,
            &keypair, // real signature, subject's own key, over these exact samples
            Some(&fingerprint_hex),
            Some(&behavioral_hex),
            &signal_hashes,
            &fingerprint_hex,
            &behavioral_hex,
            &signal_hashes,
            Some(consent_receipt_id),
        );

        let resp = post_json(&app, "/api/v1/0dentity/claims", body).await;
        let status = resp.status();
        let resp_body = body_json(resp).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a submit with a real signature over the canonical sample-bound payload, matching \
             consent, must be accepted, got {status}: {resp_body}"
        );

        let fingerprints = store.lock().unwrap().get_fingerprints(&did).unwrap();
        assert_eq!(
            fingerprints.len(),
            1,
            "the verified submit must persist exactly one device fingerprint"
        );
        let behavioral = store.lock().unwrap().get_behavioral_samples(&did).unwrap();
        assert_eq!(
            behavioral.len(),
            1,
            "the verified submit must persist exactly one behavioral sample"
        );

        let claims: Vec<_> = store
            .lock()
            .unwrap()
            .get_claims(&did)
            .unwrap()
            .into_iter()
            .map(|(_, c)| c)
            .collect();
        let score = ZerodentityScore::compute(&did, &claims, &fingerprints, &behavioral, 5_000_000);
        assert!(
            score.axes.device_trust > 0,
            "device_trust axis must be non-zero once the verified fingerprint is persisted and \
             read back from the store, got {}",
            score.axes.device_trust
        );
        assert!(
            score.axes.behavioral_signature > 0,
            "behavioral_signature axis must be non-zero once the verified behavioral sample is \
             persisted and read back from the store, got {}",
            score.axes.behavioral_signature
        );

        // Real HTTP score surface must agree.
        let score_resp = get_with_auth(
            &app_with_api(store.clone()),
            &format!("/api/v1/0dentity/{}/score", did.as_str()),
            token,
        )
        .await;
        assert_eq!(score_resp.status(), StatusCode::OK);
        let score_body = body_json(score_resp).await;
        assert!(
            score_body["axes"]["device_trust"].as_u64().unwrap_or(0) > 0,
            "GET /score must reflect the persisted, crypto-verified device fingerprint, got \
             {score_body}"
        );
        assert!(
            score_body["axes"]["behavioral_signature"]
                .as_u64()
                .unwrap_or(0)
                > 0,
            "GET /score must reflect the persisted, crypto-verified behavioral sample, got \
             {score_body}"
        );
    }

    /// exo-consent must be genuinely referenced from the zerodentity module
    /// (VCG-009 requires removing it from cargo-machete's ignored list once
    /// it is actually used) — this is a source-scan guard so a future GREEN
    /// cannot satisfy the other tests in this block with a fake/local stand-
    /// in for consent scoping instead of the real exo-consent crate.
    #[test]
    fn zerodentity_module_references_exo_consent_crate() {
        let sources = [
            include_str!("onboarding.rs"),
            include_str!("api.rs"),
            include_str!("store.rs"),
            include_str!("mod.rs"),
        ];
        let references_exo_consent = sources
            .iter()
            .any(|src| src.contains("exo_consent::") || src.contains("use exo_consent"));
        assert!(
            references_exo_consent,
            "the zerodentity module must reference the exo_consent crate to gate device/\
             behavioral sample persistence on real consent scoping, not a bespoke stand-in"
        );
    }
}
