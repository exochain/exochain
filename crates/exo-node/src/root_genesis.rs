//! Root genesis portal adapter.

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
};
use exo_core::{Did, Hash256};
use exo_root::{
    CeremonyEnvelope, CeremonyPayloadKind, CeremonyPhase, GenesisCeremonyConfig, PortalStore,
    RootError,
};
use serde::{Deserialize, Serialize};

/// Shared root genesis portal state.
#[derive(Clone)]
pub struct RootGenesisApiState {
    portal: Arc<Mutex<PortalStore>>,
    config: GenesisCeremonyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PortalStatusResponse {
    ceremony_id: String,
    threshold: u16,
    max_signers: u16,
    accepted_envelopes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct EnvelopeAcceptedResponse {
    envelope_id: Hash256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ErrorResponse {
    error: String,
}

impl RootGenesisApiState {
    /// Create portal state for one ceremony configuration.
    #[must_use]
    pub fn new(config: GenesisCeremonyConfig) -> Self {
        Self {
            portal: Arc::new(Mutex::new(PortalStore::new(config.clone()))),
            config,
        }
    }
}

/// Router for the server-backed root genesis portal.
pub fn root_genesis_router(state: RootGenesisApiState) -> Router {
    Router::new()
        .route("/api/v1/root-genesis/portal", get(handle_portal_status))
        .route(
            "/api/v1/root-genesis/portal/envelopes",
            post(handle_portal_envelope).get(handle_portal_envelopes_query),
        )
        .with_state(state)
}

async fn handle_portal_status(
    State(state): State<RootGenesisApiState>,
) -> Result<Json<PortalStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let portal = state.portal.lock().map_err(|_| {
        portal_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "portal store lock failed",
        )
    })?;
    Ok(Json(PortalStatusResponse {
        ceremony_id: state.config.ceremony_id,
        threshold: state.config.threshold,
        max_signers: state.config.max_signers,
        accepted_envelopes: portal.envelope_count(),
    }))
}

async fn handle_portal_envelope(
    State(state): State<RootGenesisApiState>,
    Json(envelope): Json<CeremonyEnvelope>,
) -> Result<(StatusCode, Json<EnvelopeAcceptedResponse>), (StatusCode, Json<ErrorResponse>)> {
    let mut portal = state.portal.lock().map_err(|_| {
        portal_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "portal store lock failed",
        )
    })?;
    match portal.submit(envelope) {
        Ok(envelope_id) => Ok((
            StatusCode::CREATED,
            Json(EnvelopeAcceptedResponse { envelope_id }),
        )),
        Err(error) => Err(root_error_to_response(error)),
    }
}

/// Filters for reading relay envelopes back from the portal. Each absent field
/// matches any value (e.g. `?phase=Round1` collects the round-one broadcast set;
/// `?phase=Round2&recipient_did=did:exo:...` pulls one recipient's round-two set).
/// Enum filters are taken as plain strings and parsed explicitly so query
/// decoding does not depend on enum support in the urlencoded deserializer.
#[derive(Debug, Default, Deserialize)]
struct EnvelopeQuery {
    phase: Option<String>,
    payload_kind: Option<String>,
    recipient_did: Option<String>,
}

fn parse_query_enum<T: serde::de::DeserializeOwned>(
    value: &str,
    field: &str,
) -> Result<T, (StatusCode, Json<ErrorResponse>)> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|_| portal_error(StatusCode::BAD_REQUEST, &format!("invalid {field}")))
}

async fn handle_portal_envelopes_query(
    State(state): State<RootGenesisApiState>,
    Query(query): Query<EnvelopeQuery>,
) -> Result<Json<Vec<CeremonyEnvelope>>, (StatusCode, Json<ErrorResponse>)> {
    let phase = match &query.phase {
        Some(value) => Some(parse_query_enum::<CeremonyPhase>(value, "phase")?),
        None => None,
    };
    let payload_kind = match &query.payload_kind {
        Some(value) => Some(parse_query_enum::<CeremonyPayloadKind>(
            value,
            "payload_kind",
        )?),
        None => None,
    };
    let recipient = match &query.recipient_did {
        Some(value) => Some(
            Did::new(value)
                .map_err(|_| portal_error(StatusCode::BAD_REQUEST, "invalid recipient_did"))?,
        ),
        None => None,
    };
    let portal = state.portal.lock().map_err(|_| {
        portal_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "portal store lock failed",
        )
    })?;
    Ok(Json(portal.query(phase, payload_kind, recipient.as_ref())))
}

fn portal_error(status: StatusCode, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: message.to_owned(),
        }),
    )
}

fn root_error_to_response(error: RootError) -> (StatusCode, Json<ErrorResponse>) {
    let status = match &error {
        RootError::SignatureRejected { .. } => StatusCode::UNAUTHORIZED,
        RootError::PortalRejected { reason } if reason.contains("replay") => StatusCode::CONFLICT,
        RootError::PortalRejected { reason } if reason.contains("exceeds") => {
            StatusCode::PAYLOAD_TOO_LARGE
        }
        RootError::PortalRejected { .. } | RootError::InvalidConfig { .. } => {
            StatusCode::BAD_REQUEST
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(ErrorResponse {
            error: error.to_string(),
        }),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use exo_core::{Did, SecretKey, Signature, Timestamp, crypto::KeyPair};
    use exo_root::{
        CeremonyEnvelopeDraft, CeremonyPayloadKind, CeremonyPhase, CertifierContact,
        PairwiseEncryptedPayload,
    };
    use tower::ServiceExt;

    use super::*;

    fn did(index: u16) -> Did {
        Did::new(&format!("did:exo:root-portal-module-{index:02}")).expect("valid DID")
    }

    fn certifier(index: u16) -> (CertifierContact, SecretKey) {
        let seed = [u8::try_from(index).expect("index fits"); 32];
        let keypair = KeyPair::from_secret_bytes(seed).expect("valid keypair");
        let transport_secret = [u8::try_from(index).expect("index fits"); 32];
        let transport_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(transport_secret));
        (
            CertifierContact {
                did: did(index),
                frost_identifier: index,
                signing_public_key: *keypair.public_key(),
                transport_public_key: *transport_public.as_bytes(),
            },
            keypair.secret_key().clone(),
        )
    }

    fn config() -> (GenesisCeremonyConfig, SecretKey) {
        let mut certifiers = Vec::new();
        let mut first_secret = None;
        for index in 1..=13 {
            let (contact, secret) = certifier(index);
            if index == 1 {
                first_secret = Some(secret.clone());
            }
            certifiers.push(contact);
        }
        (
            GenesisCeremonyConfig {
                ceremony_id: "exo-root-portal-module-test".into(),
                network_id: "exochain-test".into(),
                repo_commit: "d8927686a34bdc28ba36d53938f665685d2c4c04".into(),
                constitution_hash: Hash256::digest(b"constitution"),
                threshold: exo_root::ROOT_GENESIS_THRESHOLD,
                max_signers: exo_root::ROOT_GENESIS_SIGNERS,
                created_at: Timestamp::new(1_785_000_000_000, 0),
                certifiers,
            },
            first_secret.expect("first certifier secret"),
        )
    }

    fn envelope(
        config: &GenesisCeremonyConfig,
        secret: &SecretKey,
        sequence: u64,
        payload_bytes: Vec<u8>,
    ) -> CeremonyEnvelope {
        let encrypted_payload = PairwiseEncryptedPayload {
            nonce: [u8::try_from(sequence).expect("sequence fits"); 24],
            ciphertext: payload_bytes,
        };
        let mut encoded_payload = Vec::new();
        ciborium::into_writer(&encrypted_payload, &mut encoded_payload)
            .expect("encrypted payload encoding");
        CeremonyEnvelope::sign(
            CeremonyEnvelopeDraft {
                ceremony_id: config.ceremony_id.clone(),
                phase: CeremonyPhase::Round2,
                payload_kind: CeremonyPayloadKind::Round2EncryptedPackage,
                sender_did: config.certifiers[0].did.clone(),
                recipient_did: Some(config.certifiers[1].did.clone()),
                sequence,
                payload_bytes: encoded_payload,
            },
            secret,
        )
        .expect("signed envelope")
    }

    async fn post_envelope(
        router: axum::Router,
        envelope: &CeremonyEnvelope,
    ) -> axum::response::Response {
        let body = serde_json::to_vec(envelope).expect("json body");
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/root-genesis/portal/envelopes")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    async fn get_status(router: axum::Router) -> axum::response::Response {
        router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/root-genesis/portal")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    async fn get_envelopes(router: axum::Router, query: &str) -> axum::response::Response {
        router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/root-genesis/portal/envelopes?{query}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    #[tokio::test]
    async fn portal_query_returns_only_matching_envelopes() {
        let (config, secret) = config();
        let state = RootGenesisApiState::new(config.clone());
        let router = root_genesis_router(state);
        let accepted = post_envelope(
            router.clone(),
            &envelope(&config, &secret, 1, b"ct".to_vec()),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::CREATED);

        // The submitted envelope is a Round2 package; it matches a Round2 query.
        let matched = get_envelopes(router.clone(), "phase=Round2").await;
        assert_eq!(matched.status(), StatusCode::OK);
        let body = axum::body::to_bytes(matched.into_body(), 1 << 20)
            .await
            .expect("body bytes");
        let envelopes: Vec<CeremonyEnvelope> =
            serde_json::from_slice(&body).expect("envelopes json");
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].phase, CeremonyPhase::Round2);

        // A Round1 query matches nothing that was submitted.
        let empty = get_envelopes(router, "phase=Round1").await;
        let body = axum::body::to_bytes(empty.into_body(), 1 << 20)
            .await
            .expect("body bytes");
        let envelopes: Vec<CeremonyEnvelope> =
            serde_json::from_slice(&body).expect("envelopes json");
        assert!(envelopes.is_empty());
    }

    fn poison_portal_lock(state: &RootGenesisApiState) {
        let portal = Arc::clone(&state.portal);
        let _ = std::thread::spawn(move || {
            let _guard = portal.lock().expect("portal lock");
            panic!("poison portal lock");
        })
        .join();
    }

    #[tokio::test]
    async fn portal_status_reports_policy_and_accepted_envelope_count() {
        let (config, secret) = config();
        let state = RootGenesisApiState::new(config.clone());
        let router = root_genesis_router(state);
        let accepted = post_envelope(
            router.clone(),
            &envelope(&config, &secret, 1, b"ct".to_vec()),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::CREATED);

        let response = get_status(router).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("body bytes");
        let status: serde_json::Value = serde_json::from_slice(&body).expect("status json");
        assert_eq!(status["ceremony_id"], config.ceremony_id);
        assert_eq!(status["threshold"], u64::from(config.threshold));
        assert_eq!(status["max_signers"], u64::from(config.max_signers));
        assert_eq!(status["accepted_envelopes"], 1);
    }

    #[tokio::test]
    async fn portal_handlers_fail_closed_when_store_lock_is_poisoned() {
        let (config, secret) = config();
        let state = RootGenesisApiState::new(config.clone());
        poison_portal_lock(&state);
        let router = root_genesis_router(state);

        let status = get_status(router.clone()).await;
        assert_eq!(status.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let submitted = post_envelope(router, &envelope(&config, &secret, 1, b"ct".to_vec())).await;
        assert_eq!(submitted.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn portal_handler_maps_signature_and_payload_size_rejections() {
        let (config, secret) = config();
        let router = root_genesis_router(RootGenesisApiState::new(config.clone()));

        let mut unsigned = envelope(&config, &secret, 1, b"ct".to_vec());
        unsigned.signature = Signature::Empty;
        let unauthorized = post_envelope(router.clone(), &unsigned).await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let oversized = envelope(&config, &secret, 2, vec![7; 64 * 1024 + 1]);
        let too_large = post_envelope(router, &oversized).await;
        assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn portal_error_mapper_preserves_internal_error_status() {
        let (status, Json(body)) = root_error_to_response(RootError::CanonicalEncoding {
            detail: "encoder unavailable".to_owned(),
        });

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.error.contains("encoder unavailable"));
    }
}
