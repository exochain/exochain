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

//! AVC revocations: signed records that block future validation of a
//! credential, regardless of expiry.

use exo_core::{Did, Hash256, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{credential::AVC_SCHEMA_VERSION, error::AvcError};

/// Domain tag for AVC revocations.
pub const AVC_REVOCATION_SIGNING_DOMAIN: &str = "exo.avc.revocation.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AvcRevocationReason {
    IssuerRevoked,
    PrincipalRevoked,
    ExpiredAuthority,
    CompromisedKey,
    PolicyViolation,
    SybilChallenge,
    EmergencyStop,
    Superseded,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcRevocation {
    pub schema_version: u16,
    pub credential_id: Hash256,
    pub revoker_did: Did,
    pub reason: AvcRevocationReason,
    pub created_at: Timestamp,
    pub signature: Signature,
}

#[derive(Serialize)]
struct RevocationSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    credential_id: &'a Hash256,
    revoker_did: &'a Did,
    reason: &'a AvcRevocationReason,
    created_at: &'a Timestamp,
}

impl AvcRevocation {
    /// Compute the canonical signing payload bytes for this revocation.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, AvcError> {
        let payload = RevocationSigningPayload {
            domain: AVC_REVOCATION_SIGNING_DOMAIN,
            schema_version: self.schema_version,
            credential_id: &self.credential_id,
            revoker_did: &self.revoker_did,
            reason: &self.reason,
            created_at: &self.created_at,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut buf)?;
        Ok(buf)
    }
}

/// Build and sign a revocation record.
///
/// The supplied `sign` closure is invoked exactly once over the
/// canonical signing payload. The returned record can be inserted into
/// any registry implementing `AvcRegistryWrite`.
///
/// # Errors
/// Returns [`AvcError`] for structural failures (e.g. empty `Other`
/// reason) or CBOR encoding failures.
pub fn revoke_avc<F>(
    credential_id: Hash256,
    revoker_did: Did,
    reason: AvcRevocationReason,
    now: Timestamp,
    sign: F,
) -> Result<AvcRevocation, AvcError>
where
    F: FnOnce(&[u8]) -> Signature,
{
    if let AvcRevocationReason::Other(text) = &reason {
        if text.trim().is_empty() {
            return Err(AvcError::EmptyField {
                field: "revocation.reason.Other",
            });
        }
    }

    let mut revocation = AvcRevocation {
        schema_version: AVC_SCHEMA_VERSION,
        credential_id,
        revoker_did,
        reason,
        created_at: now,
        signature: Signature::empty(),
    };
    let payload = revocation.signing_payload()?;
    revocation.signature = sign(&payload);
    Ok(revocation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::test_support::{did, h256, ts};

    fn fixed_signature() -> Signature {
        Signature::from_bytes([7u8; 64])
    }

    #[test]
    fn revoke_avc_signs_canonical_payload() {
        let revocation = revoke_avc(
            h256(0xAA),
            did("revoker"),
            AvcRevocationReason::IssuerRevoked,
            ts(1_000),
            |_| fixed_signature(),
        )
        .unwrap();
        assert_eq!(revocation.signature, fixed_signature());
        assert_eq!(revocation.credential_id, h256(0xAA));
        assert_eq!(revocation.schema_version, AVC_SCHEMA_VERSION);
    }

    #[test]
    fn revoke_avc_payload_contains_domain_tag() {
        let revocation = revoke_avc(
            h256(0xAA),
            did("revoker"),
            AvcRevocationReason::PrincipalRevoked,
            ts(1_000),
            |_| fixed_signature(),
        )
        .unwrap();
        let payload = revocation.signing_payload().unwrap();
        let needle = AVC_REVOCATION_SIGNING_DOMAIN.as_bytes();
        assert!(payload.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn revoke_avc_changes_payload_with_reason() {
        let r1 = revoke_avc(
            h256(0xAA),
            did("revoker"),
            AvcRevocationReason::CompromisedKey,
            ts(1_000),
            |_| fixed_signature(),
        )
        .unwrap();
        let r2 = revoke_avc(
            h256(0xAA),
            did("revoker"),
            AvcRevocationReason::Superseded,
            ts(1_000),
            |_| fixed_signature(),
        )
        .unwrap();
        assert_ne!(r1.signing_payload().unwrap(), r2.signing_payload().unwrap());
    }

    #[test]
    fn revoke_avc_rejects_empty_other_reason() {
        let err = revoke_avc(
            h256(0xAA),
            did("revoker"),
            AvcRevocationReason::Other("   ".into()),
            ts(1_000),
            |_| fixed_signature(),
        )
        .unwrap_err();
        assert!(matches!(err, AvcError::EmptyField { .. }));
    }

    #[test]
    fn revoke_avc_accepts_non_empty_other_reason() {
        let revocation = revoke_avc(
            h256(0xAA),
            did("revoker"),
            AvcRevocationReason::Other("legal hold".into()),
            ts(1_000),
            |_| fixed_signature(),
        )
        .unwrap();
        assert!(matches!(revocation.reason, AvcRevocationReason::Other(_)));
    }

    #[test]
    fn revoke_avc_covers_every_reason_variant() {
        let reasons = vec![
            AvcRevocationReason::IssuerRevoked,
            AvcRevocationReason::PrincipalRevoked,
            AvcRevocationReason::ExpiredAuthority,
            AvcRevocationReason::CompromisedKey,
            AvcRevocationReason::PolicyViolation,
            AvcRevocationReason::SybilChallenge,
            AvcRevocationReason::EmergencyStop,
            AvcRevocationReason::Superseded,
            AvcRevocationReason::Other("audit".into()),
        ];
        for reason in reasons {
            let revocation = revoke_avc(
                h256(0xAA),
                did("revoker"),
                reason.clone(),
                ts(1_000),
                |_| fixed_signature(),
            )
            .unwrap();
            assert_eq!(revocation.reason, reason);
        }
    }

    #[test]
    fn round_trip_serialization() {
        let revocation = revoke_avc(
            h256(0xAA),
            did("revoker"),
            AvcRevocationReason::EmergencyStop,
            ts(1_000),
            |_| fixed_signature(),
        )
        .unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&revocation, &mut buf).unwrap();
        let decoded: AvcRevocation = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded, revocation);
    }
}
