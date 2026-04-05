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
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode, header},
    };
    use exo_core::types::{Did, Hash256, Signature};
    use rand::{SeedableRng, rngs::StdRng};
    use serde_json::Value;
    use tower::ServiceExt;

    use crate::zerodentity::{
        ClaimStatus, ClaimType, IdentityClaim, IdentitySession, OTP_MAX_ATTEMPTS, OtpChallenge,
        OtpChannel, OtpState, PolarAxes, ZerodentityScore,
        api::{ApiState, zerodentity_api_router},
        onboarding::{OnboardingState, onboarding_router},
        scoring::compute_symmetry,
        store::{SharedZerodentityStore, ZerodentityStore, new_shared_store},
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

    fn seeded_rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
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

    fn make_session(did: &Did, token: &str, ms: u64) -> IdentitySession {
        IdentitySession {
            session_token: token.to_owned(),
            subject_did: did.clone(),
            public_key: vec![],
            created_ms: ms,
            last_active_ms: ms,
            revoked: false,
        }
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
        zerodentity_api_router(ApiState {
            store,
            node_did: Did::new("did:exo:test-node").unwrap(),
            started_ms: 1_700_000_000_000,
        })
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

    // -----------------------------------------------------------------------
    // §12.2.4 — Onboarding HTTP handlers
    // -----------------------------------------------------------------------

    #[tokio::test]
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
            serde_json::json!({
                "challenge_id": cid,
                "code": code
            }),
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

    #[tokio::test]
    async fn list_fingerprints_without_auth_returns_401() {
        let app = api_app(new_shared_store());

        let resp = get_req(&app, "/api/v1/0dentity/did:exo:fp-noauth/fingerprints").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

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
    // §12.2.7 — server-key and peer attestation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_server_key_returns_ed25519_dh() {
        let app = api_app(new_shared_store());
        let resp = get_req(&app, "/api/v1/0dentity/server-key").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["algorithm"].as_str().unwrap(), "Ed25519-DH");
        assert_eq!(body["key_size"].as_u64().unwrap(), 256);
        assert!(
            body["public_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PUBLIC KEY"),
        );
        let hash_str = body["key_hash"].as_str().unwrap();
        assert_eq!(hash_str.len(), 64, "key_hash must be 64 hex chars");
        // Key hash is deterministic for the test node DID.
        assert_eq!(body["rotated_ms"].as_u64().unwrap(), 1_700_000_000_000,);
    }

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

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&attester, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session(&attester, token, 1_000_000))
                .unwrap();
        }

        let resp = post_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/attest", attester.as_str()),
            token,
            serde_json::json!({
                "target_did": "did:exo:target",
                "attestation_type": "NotAType"
            }),
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

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&attester, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session(&attester, token, 1_000_000))
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
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_json(resp).await;
        assert!(
            body["attestation_id"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        assert!(body["receipt_hash"].as_str().is_some_and(|s| s.len() == 64));
    }

    #[tokio::test]
    async fn attest_self_returns_400() {
        let store = new_shared_store();
        let app = api_app(store.clone());
        let did = td("attest-self");
        let token = "attest-self-token";

        {
            let mut s = store.lock().unwrap();
            s.insert_claim(
                "e1",
                &make_claim(&did, ClaimType::Email, ClaimStatus::Verified, 1_000),
            )
            .unwrap();
            s.insert_session(&make_session(&did, token, 1_000_000))
                .unwrap();
        }

        let resp = post_with_auth(
            &app,
            &format!("/api/v1/0dentity/{}/attest", did.as_str()),
            token,
            serde_json::json!({
                "target_did": did.as_str(),
                "attestation_type": "Identity"
            }),
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
    async fn test_full_onboarding_arc() {
        let store = new_shared_store();
        let onb = onboarding_app(store.clone());
        let api = api_app(store.clone());
        let did = td("arc-e2e-001");
        let did_str = did.as_str();

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
            serde_json::json!({
                "challenge_id": email_cid,
                "code": email_code
            }),
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
            serde_json::json!({
                "challenge_id": phone_cid,
                "code": phone_code
            }),
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
