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

//! HTTP status mapping for the authorization facilitator.
//!
//! The constitutional JSON API on `exo-node` stays JSON. The Cloudflare
//! Worker translator uses this mapping:
//!
//! - `Deny` → 403 (payment never outranks deny)
//! - `HumanApprovalRequired` → 428 (collect approval before money)
//! - `ChallengeRequired` → 402 + `PAYMENT-REQUIRED`
//! - `Allow` and settled → 200 + `PAYMENT-RESPONSE`
//! - `Allow` but unpaid → 402 (fail closed)

use exo_avc::{AvcDecision, AvcReasonCode};
use exo_core::Hash256;
use serde::{Deserialize, Serialize};

/// HTTP 200 OK after Allow and settled payment.
pub const HTTP_OK: u16 = 200;
/// HTTP 402 Payment Required — compound commercial challenge.
pub const HTTP_PAYMENT_REQUIRED: u16 = 402;
/// HTTP 403 Forbidden — AVC Deny. Never mapped to 402.
pub const HTTP_FORBIDDEN: u16 = 403;
/// HTTP 428 Precondition Required — human approval before collection.
pub const HTTP_PRECONDITION_REQUIRED: u16 = 428;

/// x402 `PAYMENT-REQUIRED` header name.
pub const HEADER_PAYMENT_REQUIRED: &str = "PAYMENT-REQUIRED";
/// x402 `PAYMENT-SIGNATURE` header name.
pub const HEADER_PAYMENT_SIGNATURE: &str = "PAYMENT-SIGNATURE";
/// x402 `PAYMENT-RESPONSE` header name.
pub const HEADER_PAYMENT_RESPONSE: &str = "PAYMENT-RESPONSE";

/// Schema id stuffed into `PAYMENT-REQUIRED` as an AVC extension.
pub const AUTHORIZATION_CHALLENGE_SCHEMA: &str = "exo.x402.authorization-challenge.v1";

/// Mapped HTTP outcome for an AVC decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationHttpMapping {
    pub status: u16,
    pub payment_required: bool,
    pub payment_response: bool,
}

/// AVC reason codes carried as a 402 extension, not as x402 protocol types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationChallenge {
    pub schema: String,
    pub avc_decision: AvcDecision,
    pub reason_codes: Vec<AvcReasonCode>,
    pub commercially_gated: bool,
}

impl AuthorizationChallenge {
    /// Build a challenge document for a 402 response.
    #[must_use]
    pub fn from_reasons(decision: AvcDecision, reason_codes: Vec<AvcReasonCode>) -> Self {
        Self {
            schema: AUTHORIZATION_CHALLENGE_SCHEMA.into(),
            avc_decision: decision,
            reason_codes,
            commercially_gated: true,
        }
    }
}

/// Settlement is a non-zero bound payment-evidence hash.
///
/// Header presence (`PAYMENT-SIGNATURE`) is never evidence.
#[must_use]
pub fn payment_settled_from_bound_evidence(hash: Option<Hash256>) -> bool {
    hash.is_some_and(|value| value != Hash256::ZERO)
}

/// Map an AVC decision onto HTTP. Deny always outranks payment.
#[must_use]
pub fn map_authorization_to_http(
    decision: AvcDecision,
    payment_settled: bool,
) -> AuthorizationHttpMapping {
    match decision {
        AvcDecision::Deny => AuthorizationHttpMapping {
            status: HTTP_FORBIDDEN,
            payment_required: false,
            payment_response: false,
        },
        AvcDecision::HumanApprovalRequired => AuthorizationHttpMapping {
            status: HTTP_PRECONDITION_REQUIRED,
            payment_required: false,
            payment_response: false,
        },
        AvcDecision::ChallengeRequired => AuthorizationHttpMapping {
            status: HTTP_PAYMENT_REQUIRED,
            payment_required: true,
            payment_response: false,
        },
        AvcDecision::Allow if payment_settled => AuthorizationHttpMapping {
            status: HTTP_OK,
            payment_required: false,
            payment_response: true,
        },
        AvcDecision::Allow => AuthorizationHttpMapping {
            status: HTTP_PAYMENT_REQUIRED,
            payment_required: true,
            payment_response: false,
        },
    }
}

/// Paths that must never be commercially gated (doctrine lock).
#[must_use]
pub fn is_never_paywalled_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    path == "/api/v1/avc/validate"
        || path.contains("/api/v1/0dentity/")
        || (path.starts_with("/api/v1/agents/") && path.ends_with("/consent"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_maps_to_403_never_402() {
        let mapped = map_authorization_to_http(AvcDecision::Deny, true);
        assert_eq!(mapped.status, HTTP_FORBIDDEN);
        assert!(!mapped.payment_required);
        assert_ne!(mapped.status, HTTP_PAYMENT_REQUIRED);
    }

    #[test]
    fn human_approval_maps_to_428_before_collection() {
        let mapped = map_authorization_to_http(AvcDecision::HumanApprovalRequired, false);
        assert_eq!(mapped.status, HTTP_PRECONDITION_REQUIRED);
        assert!(!mapped.payment_required);
    }

    #[test]
    fn challenge_required_maps_to_402() {
        let mapped = map_authorization_to_http(AvcDecision::ChallengeRequired, false);
        assert_eq!(mapped.status, HTTP_PAYMENT_REQUIRED);
        assert!(mapped.payment_required);
    }

    #[test]
    fn allow_with_settled_payment_maps_to_200() {
        let mapped = map_authorization_to_http(AvcDecision::Allow, true);
        assert_eq!(mapped.status, HTTP_OK);
        assert!(mapped.payment_response);
    }

    #[test]
    fn allow_without_payment_fails_closed_to_402() {
        let mapped = map_authorization_to_http(AvcDecision::Allow, false);
        assert_eq!(mapped.status, HTTP_PAYMENT_REQUIRED);
        assert!(mapped.payment_required);
        assert!(!mapped.payment_response);
    }

    #[test]
    fn bound_evidence_settles_only_for_nonzero_hash() {
        assert!(!payment_settled_from_bound_evidence(None));
        assert!(!payment_settled_from_bound_evidence(Some(Hash256::ZERO)));
        assert!(payment_settled_from_bound_evidence(Some(Hash256::from_bytes(
            [0xC1; 32]
        ))));
    }

    #[test]
    fn paid_deny_still_forbidden() {
        let mapped = map_authorization_to_http(AvcDecision::Deny, true);
        assert_eq!(mapped.status, HTTP_FORBIDDEN);
    }

    #[test]
    fn never_paywalled_paths_include_validate_identity_and_consent() {
        assert!(is_never_paywalled_path("/api/v1/avc/validate"));
        assert!(is_never_paywalled_path("/api/v1/avc/validate?now=1"));
        assert!(is_never_paywalled_path(
            "/api/v1/0dentity/did:exo:agent/score"
        ));
        assert!(is_never_paywalled_path(
            "/api/v1/agents/did:exo:agent/consent"
        ));
        assert!(!is_never_paywalled_path("/mcp/tools/call"));
        assert!(!is_never_paywalled_path("/api/v1/avc/receipts/emit"));
    }

    #[test]
    fn challenge_document_carries_avc_reason_codes_not_x402_types() {
        let challenge = AuthorizationChallenge::from_reasons(
            AvcDecision::ChallengeRequired,
            vec![AvcReasonCode::PaymentEvidenceMissing],
        );
        assert_eq!(challenge.schema, AUTHORIZATION_CHALLENGE_SCHEMA);
        assert_eq!(
            challenge.reason_codes,
            vec![AvcReasonCode::PaymentEvidenceMissing]
        );
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&challenge, &mut buf).unwrap();
        let decoded: AuthorizationChallenge = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded, challenge);
    }
}
