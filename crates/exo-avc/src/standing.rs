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

//! Signed suspend, quarantine, and resume records for one AVC credential.
//!
//! Absence of a record means the credential is active. The latest verified
//! record wins. A latest record that does not verify is not treated as a
//! resume, and an older verified record is not consulted.

use exo_core::{Did, Hash256, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{credential::AVC_SCHEMA_VERSION, error::AvcError};

/// Domain tag for AVC standing records.
pub const AVC_STANDING_SIGNING_DOMAIN: &str = "exo.avc.standing.v1";

/// Signed standing of one credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AvcStanding {
    /// Resume. The credential is active again.
    Active,
    /// The credential and its descendants must be denied.
    Suspended,
    /// The credential and its descendants must be denied.
    Quarantined,
}

/// Validation's view of standing, including the fail-closed unverified case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialStanding {
    /// No record, or the latest verified record is [`AvcStanding::Active`].
    Active,
    /// The latest verified record suspends the credential.
    Suspended,
    /// The latest verified record quarantines the credential.
    Quarantined,
    /// A record exists and its latest entry does not verify.
    Unverified,
}

/// One signed suspend, quarantine, or resume event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvcStandingRecord {
    pub schema_version: u16,
    pub credential_id: Hash256,
    pub actor_did: Did,
    pub standing: AvcStanding,
    pub created_at: Timestamp,
    pub signature: Signature,
}

#[derive(Serialize)]
struct StandingSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    credential_id: &'a Hash256,
    actor_did: &'a Did,
    standing: AvcStanding,
    created_at: &'a Timestamp,
}

impl AvcStandingRecord {
    /// Compute the canonical signing payload bytes for this record.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, AvcError> {
        let payload = StandingSigningPayload {
            domain: AVC_STANDING_SIGNING_DOMAIN,
            schema_version: self.schema_version,
            credential_id: &self.credential_id,
            actor_did: &self.actor_did,
            standing: self.standing,
            created_at: &self.created_at,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut buf)?;
        Ok(buf)
    }
}

/// Build and sign a standing record.
///
/// # Errors
/// Returns [`AvcError::Serialization`] when CBOR encoding fails.
pub fn sign_avc_standing<F>(
    credential_id: Hash256,
    actor_did: Did,
    standing: AvcStanding,
    now: Timestamp,
    sign: F,
) -> Result<AvcStandingRecord, AvcError>
where
    F: FnOnce(&[u8]) -> Signature,
{
    let mut record = AvcStandingRecord {
        schema_version: AVC_SCHEMA_VERSION,
        credential_id,
        actor_did,
        standing,
        created_at: now,
        signature: Signature::empty(),
    };
    let payload = record.signing_payload()?;
    record.signature = sign(&payload);
    Ok(record)
}

#[cfg(test)]
mod tests {
    use exo_core::{Timestamp, crypto::KeyPair};

    use super::*;
    use crate::{
        credential::{
            issue_avc,
            test_support::{baseline_draft, did},
        },
        registry::{AvcRegistryRead, AvcRegistryWrite, InMemoryAvcRegistry},
    };

    const ACTOR_SEED: [u8; 32] = [0x11; 32];

    fn actor_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(ACTOR_SEED).expect("valid seed")
    }

    fn ts(physical: u64) -> Timestamp {
        Timestamp::new(physical, 0)
    }

    fn registry_with_credential() -> (InMemoryAvcRegistry, Hash256) {
        let mut registry = InMemoryAvcRegistry::new();
        let draft = baseline_draft();
        let actor = draft.issuer_did.clone();
        registry.put_public_key(actor, actor_keypair().public);
        let credential = issue_avc(draft, |bytes| actor_keypair().sign(bytes)).unwrap();
        let id = registry.put_credential(credential).unwrap();
        (registry, id)
    }

    fn signed(id: Hash256, standing: AvcStanding, at: Timestamp) -> AvcStandingRecord {
        sign_avc_standing(id, baseline_draft().issuer_did, standing, at, |bytes| {
            actor_keypair().sign(bytes)
        })
        .unwrap()
    }

    #[test]
    fn sign_avc_standing_binds_standing_and_domain() {
        let id = Hash256::from_bytes([0xAB; 32]);
        let suspended = signed(id, AvcStanding::Suspended, ts(10));
        let resumed = signed(id, AvcStanding::Active, ts(10));
        assert_ne!(
            suspended.signing_payload().unwrap(),
            resumed.signing_payload().unwrap()
        );
        let payload = suspended.signing_payload().unwrap();
        let needle = AVC_STANDING_SIGNING_DOMAIN.as_bytes();
        assert!(payload.windows(needle.len()).any(|window| window == needle));
    }

    #[test]
    fn put_rejects_unknown_credential_unauthorized_actor_and_bad_signature() {
        let (mut registry, id) = registry_with_credential();
        let unknown = signed(
            Hash256::from_bytes([0x11; 32]),
            AvcStanding::Suspended,
            ts(10),
        );
        assert!(registry.put_standing(unknown).is_err());

        let outsider = sign_avc_standing(
            id,
            did("outsider"),
            AvcStanding::Quarantined,
            ts(10),
            |bytes| actor_keypair().sign(bytes),
        )
        .unwrap();
        assert!(registry.put_standing(outsider).is_err());
        assert!(registry.standing_audit(&id).is_empty());

        let mut forged = signed(id, AvcStanding::Active, ts(10));
        forged.signature = Signature::from_bytes([9u8; 64]);
        assert!(registry.put_standing(forged).is_err());
        assert_eq!(
            registry.credential_standing(&id),
            CredentialStanding::Active
        );
    }

    #[test]
    fn latest_standing_wins_and_unverified_latest_does_not_resume() {
        let (mut registry, id) = registry_with_credential();
        registry
            .put_standing(signed(id, AvcStanding::Suspended, ts(10)))
            .unwrap();
        registry
            .put_standing(signed(id, AvcStanding::Suspended, ts(10)))
            .unwrap();
        assert_eq!(registry.standing_audit(&id).len(), 1);
        assert_eq!(
            registry.credential_standing(&id),
            CredentialStanding::Suspended
        );

        registry
            .put_standing(signed(id, AvcStanding::Active, ts(11)))
            .unwrap();
        assert_eq!(
            registry.credential_standing(&id),
            CredentialStanding::Active
        );

        let mut state = registry.durable_state();
        let mut forged = signed(id, AvcStanding::Active, ts(12));
        forged.signature = Signature::from_bytes([9u8; 64]);
        state
            .standings
            .get_mut(&id)
            .unwrap()
            .insert(forged.created_at, forged);
        let mut restored = InMemoryAvcRegistry::from_durable_state(state).unwrap();
        restored.put_public_key(baseline_draft().issuer_did, actor_keypair().public);
        assert_eq!(
            restored.credential_standing(&id),
            CredentialStanding::Unverified
        );
        assert_eq!(restored.standing_audit(&id).len(), 3);
    }
}
