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
            FingerprintSignal,
        },
    };

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

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
            "signature": hex::encode(signature.as_bytes())
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
        onboarding_router(OnboardingState { store })
    }

    fn api_app(store: SharedZerodentityStore) -> Router {
        configure_test_receipt_signer(&store);
        zerodentity_api_router(ApiState { store })
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

        store.put_score(make_score(&did, 3_000, 1_000_000));
        store.put_score(make_score(&did, 5_000, 2_000_000));

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
            store.put_score(make_score(&td(&format!("noise-{i}")), i * 100, 1_000_000));
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
            store.put_score(s);
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
        assert!(store.get_session(token).unwrap().is_some());

        let mut revoked = make_session(&did, token, 1_000_000);
        revoked.revoked = true;
        store.insert_session(&revoked).unwrap();

        assert!(
            store.get_session(token).unwrap().is_none(),
            "revoked session must be hidden"
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
        let slice = store.get_claims_slice(&did);
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

        store.put_fingerprint(&did, make_fingerprint("newer", 2_000));
        store.put_fingerprint(&did, make_fingerprint("older", 1_000));

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

        store.put_behavioral(
            &did,
            make_behavioral_sample("newer", BehavioralSignalType::MouseDynamics, 2_000),
        );
        store.put_behavioral(
            &did,
            make_behavioral_sample("older", BehavioralSignalType::KeystrokeDynamics, 1_000),
        );

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

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            serde_json::json!({
                "subject_did": "did:exo:alice",
                "claim_type": "DisplayName"
            }),
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

        let resp = post_json(
            &app,
            "/api/v1/0dentity/claims",
            serde_json::json!({
                "subject_did": "did:exo:alice",
                "claim_type": "Email",
                "verification_channel": "Email"
            }),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(body["challenge_id"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(body["challenge_ttl_ms"].as_u64().is_some());
    }

    #[tokio::test]
    #[cfg(feature = "unaudited-zerodentity-first-touch-onboarding")]
    async fn submit_claim_stores_claim_in_store() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let did = td("onb-store-check");

        post_json(
            &app,
            "/api/v1/0dentity/claims",
            serde_json::json!({
                "subject_did": did.as_str(),
                "claim_type": "Phone"
            }),
        )
        .await;

        let claims = store.lock().unwrap().get_claims(&did).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].1.claim_type, ClaimType::Phone);
    }

    #[tokio::test]
    async fn verify_otp_correct_code_returns_verified_and_session_token() {
        let store = new_shared_store();
        let app = onboarding_app(store.clone());
        let did = td("otp-ok-01");
        let keypair = test_keypair(1);
        // Far-future dispatched_ms so TTL check won't trigger on wall clock
        let dispatched_ms = u64::MAX / 2;

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
            .get_session(session_token)
            .unwrap()
            .unwrap();
        assert_eq!(session.public_key, keypair.public_key().as_bytes().to_vec());
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
        let did = td("otp-bootstrap-wrong-key");
        let keypair = test_keypair(2);
        let wrong_keypair = test_keypair(3);
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
        let app = api_app(new_shared_store());

        let resp = get_req(&app, "/api/v1/0dentity/did:exo:nobody/score").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_score_with_verified_email_phone_gives_8700_communication() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-score-01");

        {
            let mut s = store.lock().unwrap();
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

        let resp = get_req(&app, &format!("/api/v1/0dentity/{}/score", did.as_str())).await;
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

        {
            let mut s = store.lock().unwrap();
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

        let resp = get_req(&app, &format!("/api/v1/0dentity/{}/score", did.as_str())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["computed_ms"].as_u64().unwrap(), 2_500);
    }

    #[tokio::test]
    async fn get_score_with_as_of_uses_caller_supplied_timestamp() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-score-explicit-time");

        store
            .lock()
            .unwrap()
            .insert_claim(
                "c1",
                &make_claim(&did, ClaimType::DisplayName, ClaimStatus::Verified, 1_000),
            )
            .unwrap();

        let resp = get_req(
            &app,
            &format!("/api/v1/0dentity/{}/score?as_of_ms=123456", did.as_str()),
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

        store
            .lock()
            .unwrap()
            .insert_claim(
                "c1",
                &make_claim(&did, ClaimType::DisplayName, ClaimStatus::Verified, 1_000),
            )
            .unwrap();

        let resp = get_req(
            &app,
            &format!("/api/v1/0dentity/{}/score?as_of_ms=0", did.as_str()),
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
            s.insert_claim("older", &older_post_quantum).unwrap();
            s.insert_claim("newer", &newer_ed25519).unwrap();
        }
        let ordered_app = api_app(ordered_store);

        let reversed_store = new_shared_store();
        {
            let mut s = reversed_store.lock().unwrap();
            s.insert_claim("newer", &newer_ed25519).unwrap();
            s.insert_claim("older", &older_post_quantum).unwrap();
        }
        let reversed_app = api_app(reversed_store);

        let ordered_resp = get_req(
            &ordered_app,
            &format!("/api/v1/0dentity/{}/score", did.as_str()),
        )
        .await;
        let reversed_resp = get_req(
            &reversed_app,
            &format!("/api/v1/0dentity/{}/score", did.as_str()),
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

        store
            .lock()
            .unwrap()
            .insert_claim(
                "c1",
                &make_claim(&did, ClaimType::DisplayName, ClaimStatus::Verified, 1_000),
            )
            .unwrap();

        let resp = get_req(&app, &format!("/api/v1/0dentity/{}/score", did.as_str())).await;
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
        let app = api_app(new_shared_store());

        let resp = get_req(&app, "/api/v1/0dentity/did:exo:no-history/score/history").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["snapshots"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn score_history_is_chronological_and_complete() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("api-history-01");

        {
            let mut s = store.lock().unwrap();
            for (bp, ms) in [(1_000u32, 1_000u64), (3_000, 5_000), (6_000, 9_000)] {
                let mut score = make_score(&did, bp, ms);
                score.computed_ms = ms;
                s.put_score(score);
            }
        }

        let resp = get_req(
            &app,
            &format!("/api/v1/0dentity/{}/score/history", did.as_str()),
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
    async fn attest_valid_creates_attestation_201() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let attester = td("attest-ok-a");
        let target = td("attest-ok-b");
        let token = "attest-ok-token";
        let session_keypair = test_keypair(15);
        let (public_key, secret_key) = keypair(41);

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
                &public_key,
                &secret_key,
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
        assert_eq!(claim_id, &target_claim_id(&saved_attestation).unwrap());
        assert_eq!(target_claim.dag_node_hash, guard.dag_nodes()[0].hash);
        assert_eq!(target_claim.created_ms, signed_created_ms);
        assert_eq!(target_claim.verified_ms, Some(signed_created_ms));

        let receipts = guard.trust_receipts();
        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0];
        assert_eq!(receipt.action_type, "zerodentity.claim_verified");
        assert_eq!(receipt.action_hash, target_claim.claim_hash);
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
        let (public_key, secret_key) = keypair(42);
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
            &public_key,
            &secret_key,
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

        {
            let mut s = store.lock().unwrap();
            for (bp, ms) in [(1_000u32, 1_000u64), (2_000, 5_000), (3_000, 10_000)] {
                let mut score = make_score(&did, bp, ms);
                score.computed_ms = ms;
                s.put_score(score);
            }
        }

        let resp = get_req(
            &app,
            &format!(
                "/api/v1/0dentity/{}/score/history?from_ms=3000&to_ms=7000",
                did.as_str()
            ),
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
        let did = td("arc-e2e-001");
        let did_str = did.as_str();
        let keypair = test_keypair(21);

        // ── 1. DisplayName claim ──────────────────────────────────────────
        let resp = post_json(
            &onb,
            "/api/v1/0dentity/claims",
            serde_json::json!({
                "subject_did": did_str,
                "claim_type": "DisplayName"
            }),
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
            serde_json::json!({
                "subject_did": did_str,
                "claim_type": "Email"
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // ── 3. Email OTP — inject known challenge + verify via HTTP ───────
        // Use a far-future dispatched_ms so the TTL won't expire on wall clock
        let dispatched_ms = u64::MAX / 2;
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
        let resp = get_req(&api, &format!("/api/v1/0dentity/{did_str}/score")).await;
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
            serde_json::json!({
                "subject_did": did_str,
                "claim_type": "Phone"
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let mut rng2 = seeded_rng(0xABC1_0002);
        let (phone_ch, phone_code) =
            OtpChallenge::new(&did, OtpChannel::Sms, dispatched_ms + 1, &mut rng2).unwrap();
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
        let resp = get_req(&api, &format!("/api/v1/0dentity/{did_str}/score")).await;
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
            let claims = s.get_claims_slice(&did);
            let score = ZerodentityScore::compute(&did, &claims, &[], &[], dispatched_ms + 2);
            s.put_score(score);
        }

        let resp = get_req(&api, &format!("/api/v1/0dentity/{did_str}/score/history")).await;
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
}
