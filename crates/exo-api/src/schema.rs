//! API schema types — request/response envelopes.
use exo_core::{Did, Hash256, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ApiError, Result};

/// Incoming API request variants for the EXOCHAIN trust fabric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiRequest {
    CreateTransaction {
        actor: Did,
        scope: String,
    },
    TransitionState {
        tx_id: Uuid,
        target_state: String,
        actor: Did,
    },
    QueryTransaction {
        tx_id: Uuid,
    },
    ResolveIdentity {
        did: Did,
    },
    RegisterIdentity {
        did: Did,
        public_key_hash: Hash256,
    },
    Deliberate {
        proposal_hash: Hash256,
        actor: Did,
    },
    Vote {
        proposal_id: Uuid,
        approve: bool,
        actor: Did,
    },
    Challenge {
        target_id: Uuid,
        grounds: String,
        actor: Did,
    },
}

/// Response envelope returned by the API layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiResponse {
    Success {
        correlation_id: Uuid,
        timestamp: Timestamp,
    },
    Error {
        code: u32,
        message: String,
    },
    TransactionState {
        tx_id: Uuid,
        state: String,
    },
    Identity {
        did: Did,
        verified: bool,
    },
    Receipt {
        hash: Hash256,
        timestamp: Timestamp,
    },
}

/// Compute canonical hash for a request (CBOR -> BLAKE3).
pub fn canonical_request_hash(request: &ApiRequest) -> Result<Hash256> {
    let mut buf = Vec::new();
    write_canonical_request(request, &mut buf)?;
    Ok(Hash256::digest(&buf))
}

fn write_canonical_request<W: std::io::Write>(request: &ApiRequest, writer: W) -> Result<()> {
    ciborium::into_writer(request, writer)
        .map_err(|err| ApiError::SerializationError(err.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }

    #[test]
    fn request_variants_serde() {
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
        for r in &reqs {
            let j = serde_json::to_string(r).unwrap();
            assert!(!j.is_empty());
        }
    }
    #[test]
    fn response_variants_serde() {
        let resps: Vec<ApiResponse> = vec![
            ApiResponse::Success {
                correlation_id: Uuid::nil(),
                timestamp: Timestamp::ZERO,
            },
            ApiResponse::Error {
                code: 400,
                message: "bad".into(),
            },
            ApiResponse::TransactionState {
                tx_id: Uuid::nil(),
                state: "s".into(),
            },
            ApiResponse::Identity {
                did: did("a"),
                verified: true,
            },
            ApiResponse::Receipt {
                hash: Hash256::ZERO,
                timestamp: Timestamp::ZERO,
            },
        ];
        for r in &resps {
            let j = serde_json::to_string(r).unwrap();
            assert!(!j.is_empty());
        }
    }
    #[test]
    fn canonical_hash_deterministic() {
        let r = ApiRequest::CreateTransaction {
            actor: did("a"),
            scope: "s".into(),
        };
        assert_eq!(
            canonical_request_hash(&r).unwrap(),
            canonical_request_hash(&r).unwrap()
        );
    }
    #[test]
    fn canonical_hash_differs() {
        let r1 = ApiRequest::CreateTransaction {
            actor: did("a"),
            scope: "s1".into(),
        };
        let r2 = ApiRequest::CreateTransaction {
            actor: did("a"),
            scope: "s2".into(),
        };
        assert_ne!(
            canonical_request_hash(&r1).unwrap(),
            canonical_request_hash(&r2).unwrap()
        );
    }

    #[test]
    fn canonical_hash_writer_error_returns_error() {
        let r = ApiRequest::CreateTransaction {
            actor: did("a"),
            scope: "s".into(),
        };

        let err = write_canonical_request(&r, FailingWriter).unwrap_err();
        assert!(err.to_string().contains("serialization error"));
    }

    struct FailingWriter;

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("forced writer failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
