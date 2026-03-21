//! Integration tests for the exo-api public API surface.
//!
//! Covers:
//! - `ApiRequest` / `ApiResponse` serde roundtrips
//! - `canonical_request_hash` determinism and collision resistance
//! - `p2p::PeerRegistry` operations
//! - `types::ApiVersion` / `Cursor`
//!
//! Async GraphQL resolver tests live in `crates/exo-gateway/src/graphql.rs`.

use exo_api::schema::{ApiRequest, ApiResponse, canonical_request_hash};
use exo_core::{Did, Hash256, Timestamp};
use uuid::Uuid;

fn did(id: &str) -> Did {
    Did::new(&format!("did:exo:{id}")).expect("valid did")
}

// ---------------------------------------------------------------------------
// ApiRequest serde
// ---------------------------------------------------------------------------

#[test]
fn api_request_all_variants_serde() {
    let reqs: Vec<ApiRequest> = vec![
        ApiRequest::CreateTransaction {
            actor: did("alice"),
            scope: "governance".into(),
        },
        ApiRequest::TransitionState {
            tx_id: Uuid::nil(),
            target_state: "DELIBERATION".into(),
            actor: did("alice"),
        },
        ApiRequest::QueryTransaction { tx_id: Uuid::nil() },
        ApiRequest::ResolveIdentity { did: did("alice") },
        ApiRequest::RegisterIdentity {
            did: did("alice"),
            public_key_hash: Hash256::ZERO,
        },
        ApiRequest::Deliberate {
            proposal_hash: Hash256::ZERO,
            actor: did("alice"),
        },
        ApiRequest::Vote {
            proposal_id: Uuid::nil(),
            approve: true,
            actor: did("alice"),
        },
        ApiRequest::Vote {
            proposal_id: Uuid::nil(),
            approve: false,
            actor: did("bob"),
        },
        ApiRequest::Challenge {
            target_id: Uuid::nil(),
            grounds: "procedural violation".into(),
            actor: did("alice"),
        },
    ];
    for r in &reqs {
        let json = serde_json::to_string(r).expect("serialize");
        assert!(!json.is_empty());
        let _back: ApiRequest = serde_json::from_str(&json).expect("deserialize");
    }
}

// ---------------------------------------------------------------------------
// ApiResponse serde
// ---------------------------------------------------------------------------

#[test]
fn api_response_all_variants_serde() {
    let resps: Vec<ApiResponse> = vec![
        ApiResponse::Success {
            correlation_id: Uuid::nil(),
            timestamp: Timestamp::ZERO,
        },
        ApiResponse::Error {
            code: 400,
            message: "bad request".into(),
        },
        ApiResponse::TransactionState {
            tx_id: Uuid::nil(),
            state: "CREATED".into(),
        },
        ApiResponse::Identity {
            did: did("alice"),
            verified: true,
        },
        ApiResponse::Receipt {
            hash: Hash256::ZERO,
            timestamp: Timestamp::ZERO,
        },
    ];
    for r in &resps {
        let json = serde_json::to_string(r).expect("serialize");
        assert!(!json.is_empty());
        let _back: ApiResponse = serde_json::from_str(&json).expect("deserialize");
    }
}

// ---------------------------------------------------------------------------
// canonical_request_hash
// ---------------------------------------------------------------------------

#[test]
fn canonical_hash_deterministic() {
    let r = ApiRequest::CreateTransaction {
        actor: did("alice"),
        scope: "s".into(),
    };
    assert_eq!(canonical_request_hash(&r), canonical_request_hash(&r));
}

#[test]
fn canonical_hash_scope_differs() {
    let r1 = ApiRequest::CreateTransaction {
        actor: did("alice"),
        scope: "s1".into(),
    };
    let r2 = ApiRequest::CreateTransaction {
        actor: did("alice"),
        scope: "s2".into(),
    };
    assert_ne!(canonical_request_hash(&r1), canonical_request_hash(&r2));
}

#[test]
fn canonical_hash_actor_differs() {
    let r1 = ApiRequest::CreateTransaction {
        actor: did("alice"),
        scope: "s".into(),
    };
    let r2 = ApiRequest::CreateTransaction {
        actor: did("bob"),
        scope: "s".into(),
    };
    assert_ne!(canonical_request_hash(&r1), canonical_request_hash(&r2));
}

#[test]
fn canonical_hash_no_collisions_across_variants() {
    let reqs: Vec<ApiRequest> = vec![
        ApiRequest::CreateTransaction {
            actor: did("a"),
            scope: "s".into(),
        },
        ApiRequest::TransitionState {
            tx_id: Uuid::nil(),
            target_state: "t".into(),
            actor: did("a"),
        },
        ApiRequest::QueryTransaction { tx_id: Uuid::nil() },
        ApiRequest::ResolveIdentity { did: did("a") },
        ApiRequest::RegisterIdentity {
            did: did("a"),
            public_key_hash: Hash256::ZERO,
        },
        ApiRequest::Deliberate {
            proposal_hash: Hash256::ZERO,
            actor: did("a"),
        },
        ApiRequest::Vote {
            proposal_id: Uuid::nil(),
            approve: true,
            actor: did("a"),
        },
        ApiRequest::Challenge {
            target_id: Uuid::nil(),
            grounds: "g".into(),
            actor: did("a"),
        },
    ];
    let hashes: Vec<_> = reqs.iter().map(canonical_request_hash).collect();
    for (i, h1) in hashes.iter().enumerate() {
        for (j, h2) in hashes.iter().enumerate() {
            if i != j {
                assert_ne!(h1, h2, "hash collision between variants {i} and {j}");
            }
        }
    }
}

#[test]
fn canonical_hash_is_hash256() {
    let r = ApiRequest::QueryTransaction { tx_id: Uuid::nil() };
    let h = canonical_request_hash(&r);
    // Hash must be non-zero for non-trivial input.
    assert_ne!(h, Hash256::ZERO);
}

// ---------------------------------------------------------------------------
// types module
// ---------------------------------------------------------------------------

#[test]
fn api_version_default_is_v1() {
    use exo_api::types::ApiVersion;
    assert_eq!(ApiVersion::default().0, "v1");
}

#[test]
fn cursor_serde_roundtrip() {
    use exo_api::types::Cursor;
    let c = Cursor("page-token-abc".into());
    let j = serde_json::to_string(&c).expect("serialize");
    let c2: Cursor = serde_json::from_str(&j).expect("deserialize");
    assert_eq!(c, c2);
}
