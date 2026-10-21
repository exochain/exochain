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

//! Signed emergency-stop engage and clear records.
//!
//! A credential names the stops that govern it through
//! `constraints.emergency_stop_refs`. Validation denies unless every
//! referenced stop has a latest audited record whose signature verifies
//! and whose disposition is [`EmergencyStopDisposition::Cleared`]. An
//! engaged stop denies. A missing stop, or a latest record whose
//! signature does not verify, is unknown and also denies.

use exo_core::{Did, Signature, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{credential::AVC_SCHEMA_VERSION, error::AvcError};

/// Domain tag for emergency-stop engage and clear records.
pub const AVC_EMERGENCY_STOP_SIGNING_DOMAIN: &str = "exo.avc.emergency-stop.v1";

/// Latest verified disposition of one emergency-stop reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmergencyStopDisposition {
    /// The stop is engaged. Referencing credentials must be denied.
    Engaged,
    /// The stop is cleared. Referencing credentials may proceed.
    Cleared,
}

/// One signed engage or clear event for a single stop reference.
///
/// The registry keeps every accepted record. The latest timestamp is the
/// disposition that validation reads, and only after that record's
/// signature verifies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyStopRecord {
    pub schema_version: u16,
    pub stop_ref: String,
    pub disposition: EmergencyStopDisposition,
    pub actor_did: Did,
    pub created_at: Timestamp,
    pub signature: Signature,
}

#[derive(Serialize)]
struct EmergencyStopSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    stop_ref: &'a str,
    disposition: EmergencyStopDisposition,
    actor_did: &'a Did,
    created_at: &'a Timestamp,
}

impl EmergencyStopRecord {
    /// Compute the canonical signing payload bytes for this record.
    ///
    /// # Errors
    /// Returns [`AvcError::Serialization`] when CBOR encoding fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, AvcError> {
        let payload = EmergencyStopSigningPayload {
            domain: AVC_EMERGENCY_STOP_SIGNING_DOMAIN,
            schema_version: self.schema_version,
            stop_ref: &self.stop_ref,
            disposition: self.disposition,
            actor_did: &self.actor_did,
            created_at: &self.created_at,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut buf)?;
        Ok(buf)
    }
}

/// Build and sign an engage or clear record.
///
/// The supplied `sign` closure is invoked exactly once over the canonical
/// signing payload. The returned record can be inserted into any registry
/// implementing `AvcRegistryWrite`.
///
/// # Errors
/// Returns [`AvcError::EmptyField`] when `stop_ref` is empty, or
/// [`AvcError::Serialization`] when CBOR encoding fails.
pub fn sign_emergency_stop<F>(
    stop_ref: impl Into<String>,
    disposition: EmergencyStopDisposition,
    actor_did: Did,
    now: Timestamp,
    sign: F,
) -> Result<EmergencyStopRecord, AvcError>
where
    F: FnOnce(&[u8]) -> Signature,
{
    let stop_ref = stop_ref.into();
    if stop_ref.trim().is_empty() {
        return Err(AvcError::EmptyField {
            field: "emergency_stop.stop_ref",
        });
    }

    let mut record = EmergencyStopRecord {
        schema_version: AVC_SCHEMA_VERSION,
        stop_ref,
        disposition,
        actor_did,
        created_at: now,
        signature: Signature::empty(),
    };
    let payload = record.signing_payload()?;
    record.signature = sign(&payload);
    Ok(record)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use exo_core::crypto::KeyPair;

    use super::*;
    use crate::{
        credential::test_support::{did, ts},
        registry::{AvcRegistryRead, AvcRegistryWrite, InMemoryAvcRegistry},
    };

    const ACTOR_SEED: [u8; 32] = [0x11; 32];

    fn actor_keypair() -> KeyPair {
        KeyPair::from_secret_bytes(ACTOR_SEED).expect("valid seed")
    }

    fn signed(
        stop_ref: &str,
        disposition: EmergencyStopDisposition,
        at: Timestamp,
    ) -> EmergencyStopRecord {
        sign_emergency_stop(stop_ref, disposition, did("issuer"), at, |bytes| {
            actor_keypair().sign(bytes)
        })
        .expect("signed emergency stop")
    }

    fn registry_with_actor() -> InMemoryAvcRegistry {
        let mut registry = InMemoryAvcRegistry::new();
        registry.put_public_key(did("issuer"), actor_keypair().public);
        registry
    }

    #[test]
    fn sign_emergency_stop_binds_disposition_and_domain() {
        let engaged = signed("halt", EmergencyStopDisposition::Engaged, ts(10));
        let cleared = signed("halt", EmergencyStopDisposition::Cleared, ts(10));
        assert_ne!(
            engaged.signing_payload().unwrap(),
            cleared.signing_payload().unwrap()
        );
        let payload = engaged.signing_payload().unwrap();
        let needle = AVC_EMERGENCY_STOP_SIGNING_DOMAIN.as_bytes();
        assert!(payload.windows(needle.len()).any(|window| window == needle));
    }

    #[test]
    fn sign_emergency_stop_rejects_blank_ref() {
        let err = sign_emergency_stop(
            "   ",
            EmergencyStopDisposition::Engaged,
            did("issuer"),
            ts(10),
            |_| Signature::from_bytes([7u8; 64]),
        )
        .unwrap_err();
        assert!(matches!(err, AvcError::EmptyField { .. }));
    }

    #[test]
    fn put_rejects_unresolved_actor_and_bad_signature() {
        let mut registry = InMemoryAvcRegistry::new();
        let record = signed("halt", EmergencyStopDisposition::Engaged, ts(10));
        let err = registry.put_emergency_stop(record).unwrap_err();
        assert!(matches!(err, AvcError::InvalidInput { .. }));
        assert!(registry.emergency_stop_audit("halt").is_empty());

        let mut registry = registry_with_actor();
        registry.put_receipt_validator_public_key(did("validator-only"), actor_keypair().public);
        let validator_record = sign_emergency_stop(
            "halt",
            EmergencyStopDisposition::Cleared,
            did("validator-only"),
            ts(10),
            |bytes| actor_keypair().sign(bytes),
        )
        .unwrap();
        let err = registry.put_emergency_stop(validator_record).unwrap_err();
        assert!(matches!(err, AvcError::InvalidInput { .. }));
        assert!(registry.emergency_stop_audit("halt").is_empty());

        let mut forged = signed("halt", EmergencyStopDisposition::Cleared, ts(10));
        forged.signature = Signature::from_bytes([9u8; 64]);
        let err = registry.put_emergency_stop(forged).unwrap_err();
        assert!(matches!(err, AvcError::InvalidInput { .. }));
        assert!(registry.emergency_stop_audit("halt").is_empty());
    }

    #[test]
    fn latest_record_wins_and_replays_do_not_rewrite_history() {
        let mut registry = registry_with_actor();
        let engaged = signed("halt", EmergencyStopDisposition::Engaged, ts(10));
        registry.put_emergency_stop(engaged.clone()).unwrap();
        registry.put_emergency_stop(engaged).unwrap();
        assert_eq!(registry.emergency_stop_audit("halt").len(), 1);

        let cleared = signed("halt", EmergencyStopDisposition::Cleared, ts(11));
        registry.put_emergency_stop(cleared).unwrap();
        assert_eq!(
            registry.emergency_stop_disposition("halt"),
            Some(EmergencyStopDisposition::Cleared)
        );

        let stale = signed("halt", EmergencyStopDisposition::Engaged, ts(11));
        let err = registry.put_emergency_stop(stale).unwrap_err();
        assert!(matches!(err, AvcError::InvalidInput { .. }));
        assert_eq!(registry.emergency_stop_audit("halt").len(), 2);
        assert_eq!(
            registry.emergency_stop_disposition("halt"),
            Some(EmergencyStopDisposition::Cleared)
        );

        let reengaged = signed("halt", EmergencyStopDisposition::Engaged, ts(12));
        registry.put_emergency_stop(reengaged).unwrap();
        assert_eq!(
            registry.emergency_stop_disposition("halt"),
            Some(EmergencyStopDisposition::Engaged)
        );
        assert_eq!(registry.emergency_stop_audit("halt").len(), 3);
    }

    #[test]
    fn unverifiable_latest_record_does_not_fall_through_to_an_older_clear() {
        let mut registry = registry_with_actor();
        registry
            .put_emergency_stop(signed("halt", EmergencyStopDisposition::Cleared, ts(10)))
            .unwrap();

        let mut state = registry.durable_state();
        let mut forged = signed("halt", EmergencyStopDisposition::Cleared, ts(11));
        forged.signature = Signature::from_bytes([9u8; 64]);
        state
            .emergency_stops
            .get_mut("halt")
            .expect("audit history")
            .insert(forged.created_at, forged);
        let mut restored = InMemoryAvcRegistry::from_durable_state(state).unwrap();
        restored.put_public_key(did("issuer"), actor_keypair().public);
        assert_eq!(restored.emergency_stop_disposition("halt"), None);
        assert_eq!(restored.emergency_stop_audit("halt").len(), 2);
    }

    #[test]
    fn durable_emergency_stops_round_trip_and_fail_closed_without_actor_key() {
        let mut registry = registry_with_actor();
        registry
            .put_emergency_stop(signed("halt", EmergencyStopDisposition::Engaged, ts(10)))
            .unwrap();
        let loaded = InMemoryAvcRegistry::from_durable_state(registry.durable_state()).unwrap();
        assert_eq!(loaded.emergency_stop_disposition("halt"), None);

        let mut loaded = loaded;
        loaded.put_public_key(did("issuer"), actor_keypair().public);
        assert_eq!(
            loaded.emergency_stop_disposition("halt"),
            Some(EmergencyStopDisposition::Engaged)
        );

        let mut live = registry_with_actor();
        live.apply_durable_state(loaded.durable_state()).unwrap();
        assert_eq!(
            live.emergency_stop_disposition("halt"),
            Some(EmergencyStopDisposition::Engaged)
        );
    }

    #[test]
    fn durable_load_rejects_structural_emergency_stop_corruption() {
        let mut registry = registry_with_actor();
        registry
            .put_emergency_stop(signed("halt", EmergencyStopDisposition::Engaged, ts(10)))
            .unwrap();

        let mut empty_sig = registry.durable_state();
        empty_sig
            .emergency_stops
            .get_mut("halt")
            .unwrap()
            .get_mut(&ts(10))
            .unwrap()
            .signature = Signature::empty();
        assert!(InMemoryAvcRegistry::from_durable_state(empty_sig).is_err());

        let mut mismatched_key = registry.durable_state();
        let record = mismatched_key
            .emergency_stops
            .get_mut("halt")
            .unwrap()
            .remove(&ts(10))
            .unwrap();
        mismatched_key
            .emergency_stops
            .insert("other".into(), BTreeMap::from([(ts(10), record)]));
        assert!(InMemoryAvcRegistry::from_durable_state(mismatched_key).is_err());
    }
}
