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

//! Thin node route for SKU A: assemble an Authorized Action Evidence Pack
//! from a stored Allow receipt. `/api/v1/avc/validate` stays free.

use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode};
use exo_avc::{
    AssembleAuthorizedActionEvidencePackInput, AuthorizedActionEvidencePack,
    assemble_authorized_action_evidence_pack,
};
use exo_core::Timestamp;
use serde::Deserialize;

use crate::avc::{AvcApiState, parse_hash, with_registry_blocking};

#[derive(Debug, Clone, Deserialize)]
pub struct AssembleEvidencePackRequest {
    pub receipt_id: String,
    #[serde(default)]
    pub commercially_gated: bool,
    pub created_at: Timestamp,
}

pub async fn handle_assemble_evidence_pack(
    State(state): State<Arc<AvcApiState>>,
    Json(request): Json<AssembleEvidencePackRequest>,
) -> Result<Json<AuthorizedActionEvidencePack>, (StatusCode, String)> {
    let receipt_id = parse_hash(&request.receipt_id)?;
    let commercially_gated = request.commercially_gated;
    let created_at = request.created_at;
    let receipt = with_registry_blocking(state, false, move |registry| {
        registry
            .get_receipt(&receipt_id)
            .ok_or((StatusCode::NOT_FOUND, "receipt not found".into()))
    })
    .await?;
    let pack =
        assemble_authorized_action_evidence_pack(&AssembleAuthorizedActionEvidencePackInput {
            receipt,
            commercially_gated,
            created_at,
        })
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    Ok(Json(pack))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{self, Body},
        http::{Method, Request},
    };
    use exo_authority::permission::Permission;
    use exo_avc::{
        AUTHORIZED_ACTION_EVIDENCE_PACK_SCHEMA, AVC_SCHEMA_VERSION, AuthorityScope, AutonomyLevel,
        AvcConstraints, AvcDraft, AvcRegistryWrite, AvcSubjectKind, AvcValidationRequest,
        DelegatedIntent, InMemoryAvcRegistry, create_trust_receipt, issue_avc, validate_avc,
    };
    use exo_core::{Did, Hash256, Timestamp, crypto::KeyPair};
    use tower::ServiceExt;

    use super::*;
    use crate::avc::{AvcApiState, AvcReceiptSigner, avc_router};

    fn did(suffix: &str) -> Did {
        Did::new(&format!("did:exo:{suffix}")).unwrap()
    }

    fn issuer_kp() -> KeyPair {
        KeyPair::from_secret_bytes([0x11; 32]).unwrap()
    }

    fn validator_kp() -> KeyPair {
        KeyPair::from_secret_bytes([0x33; 32]).unwrap()
    }

    fn test_state() -> Arc<AvcApiState> {
        let signer: AvcReceiptSigner = Arc::new(|payload: &[u8]| validator_kp().sign(payload));
        Arc::new(AvcApiState::new(did("validator"), signer))
    }

    fn stored_allow_receipt(state: &AvcApiState) -> Hash256 {
        let issuer = issuer_kp();
        let draft = AvcDraft {
            schema_version: AVC_SCHEMA_VERSION,
            issuer_did: did("issuer"),
            principal_did: did("issuer"),
            subject_did: did("agent"),
            holder_did: None,
            subject_kind: AvcSubjectKind::AiAgent {
                model_id: "alpha".into(),
                agent_version: None,
            },
            created_at: Timestamp::new(1_000, 0),
            expires_at: Some(Timestamp::new(2_000_000, 0)),
            delegated_intent: DelegatedIntent {
                intent_id: Hash256::from_bytes([0xAA; 32]),
                purpose: "research".into(),
                allowed_objectives: vec!["primary".into()],
                prohibited_objectives: vec![],
                autonomy_level: AutonomyLevel::Draft,
                delegation_allowed: false,
            },
            authority_scope: AuthorityScope {
                permissions: vec![Permission::Read],
                tools: vec![],
                data_classes: vec![],
                counterparties: vec![],
                jurisdictions: vec!["US".into()],
            },
            constraints: AvcConstraints::permissive(),
            authority_chain: None,
            consent_refs: vec![],
            policy_refs: vec![],
            parent_avc_id: None,
        };
        let credential = issue_avc(draft, |bytes| issuer.sign(bytes)).unwrap();
        let request = AvcValidationRequest {
            credential: credential.clone(),
            action: None,
            now: Timestamp::new(1_500, 0),
        };
        let mut lookup = InMemoryAvcRegistry::new();
        lookup.put_public_key(did("issuer"), issuer.public);
        let validation = validate_avc(&request, &lookup).unwrap();
        let receipt = create_trust_receipt(
            &validation,
            None,
            did("validator"),
            Timestamp::new(1_600, 0),
            |bytes| validator_kp().sign(bytes),
        )
        .unwrap();
        let receipt_id = receipt.receipt_id;
        let mut registry = state.registry.lock().unwrap();
        registry.put_public_key(did("issuer"), issuer.public);
        registry.put_receipt_validator_public_key(did("validator"), validator_kp().public);
        registry.put_credential(credential).unwrap();
        registry.put_receipt(receipt).unwrap();
        receipt_id
    }

    async fn post_assemble(
        state: Arc<AvcApiState>,
        body: serde_json::Value,
    ) -> (StatusCode, String) {
        let response = avc_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/avc/evidence-packs/assemble")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn assemble_returns_404_for_unknown_receipt() {
        let (status, body) = post_assemble(
            test_state(),
            serde_json::json!({
                "receipt_id": "11".repeat(32),
                "commercially_gated": false,
                "created_at": { "physical_ms": 1_800, "logical": 0 }
            }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("receipt not found"));
    }

    #[tokio::test]
    async fn assemble_returns_pack_for_stored_allow_receipt() {
        let state = test_state();
        let receipt_id = stored_allow_receipt(&state);
        let (status, body) = post_assemble(
            state,
            serde_json::json!({
                "receipt_id": receipt_id.to_string(),
                "commercially_gated": false,
                "created_at": { "physical_ms": 1_800, "logical": 0 }
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let pack: AuthorizedActionEvidencePack = serde_json::from_str(&body).unwrap();
        assert_eq!(pack.schema, AUTHORIZED_ACTION_EVIDENCE_PACK_SCHEMA);
        assert_eq!(pack.receipt_id, receipt_id);
    }

    #[tokio::test]
    async fn commercially_gated_assemble_fails_without_payment_evidence() {
        let state = test_state();
        let receipt_id = stored_allow_receipt(&state);
        let (status, body) = post_assemble(
            state,
            serde_json::json!({
                "receipt_id": receipt_id.to_string(),
                "commercially_gated": true,
                "created_at": { "physical_ms": 1_800, "logical": 0 }
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("payment_evidence_hash"));
    }
}
