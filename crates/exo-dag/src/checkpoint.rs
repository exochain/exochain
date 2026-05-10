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

//! Checkpoint finality aggregation for the EXOCHAIN DAG.
//!
//! Aggregates MMR event root, SMT state root, finalized height, frontier tip
//! set, and multi-validator signatures into a single checkpoint payload.
//! Provides the canonical CBOR signing preimage (Spec 9.4) with domain
//! separation tag `EXOCHAIN-CHECKPOINT-v1`.

use exo_core::{Did, Hash256, Signature};
use serde::{Deserialize, Serialize};

use crate::error::{DagError, Result};

/// A checkpoint payload aggregating finality proof components.
///
/// Validators collectively attest to a finalized DAG state by signing
/// the canonical preimage computed by [`checkpoint_signing_preimage`].
#[derive(Clone, Serialize, Deserialize)]
pub struct CheckpointPayload {
    /// MMR root over finalized event IDs.
    pub event_root: Hash256,

    /// SMT root over derived state.
    pub state_root: Hash256,

    /// Height (sequence number) of this checkpoint.
    pub height: u64,

    /// Count of finalized events covered by this checkpoint.
    pub finalized_events: u64,

    /// Frontier hashes (DAG tips at checkpoint time).
    pub frontier: Vec<Hash256>,

    /// Validator signatures attesting to this checkpoint.
    pub validator_sigs: Vec<ValidatorSignature>,
}

impl std::fmt::Debug for CheckpointPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckpointPayload")
            .field("event_root", &self.event_root)
            .field("state_root", &self.state_root)
            .field("height", &self.height)
            .field("finalized_events", &self.finalized_events)
            .field("frontier", &self.frontier)
            .field("validator_sig_count", &self.validator_sigs.len())
            .finish()
    }
}

/// A single validator's attestation to a checkpoint.
#[derive(Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// DID of the validating entity.
    pub validator_did: Did,
    /// Key version used for signing.
    pub key_version: u64,
    /// Cryptographic signature over the checkpoint preimage.
    pub signature: Signature,
}

impl std::fmt::Debug for ValidatorSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatorSignature")
            .field("validator_did", &self.validator_did)
            .field("key_version", &self.key_version)
            .field("signature", &"<redacted>")
            .finish()
    }
}

/// Domain separation tag for checkpoint signing (EXOCHAIN Specification v2.2 §9.4).
pub const CHECKPOINT_SIGNING_DOMAIN: &str = "EXOCHAIN-CHECKPOINT-v1";

/// Legacy byte view of the checkpoint signing domain tag.
pub const CHECKPOINT_DOMAIN_SEP: &[u8] = CHECKPOINT_SIGNING_DOMAIN.as_bytes();

const CHECKPOINT_SIGNING_SCHEMA_VERSION: u16 = 1;

#[derive(Serialize)]
struct CheckpointSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    event_root: &'a Hash256,
    state_root: &'a Hash256,
    height: u64,
    finalized_events: u64,
    frontier: &'a [Hash256],
}

/// Compute the normative checkpoint signing preimage (EXOCHAIN Specification v2.2 §9.4).
///
/// Validators sign this domain-separated, versioned canonical CBOR payload to
/// attest to the checkpoint.
///
/// # Errors
///
/// Returns [`DagError::Serialization`] if the canonical signing payload cannot
/// be serialized.
pub fn checkpoint_signing_preimage(cp: &CheckpointPayload) -> Result<Vec<u8>> {
    let payload = CheckpointSigningPayload {
        domain: CHECKPOINT_SIGNING_DOMAIN,
        schema_version: CHECKPOINT_SIGNING_SCHEMA_VERSION,
        event_root: &cp.event_root,
        state_root: &cp.state_root,
        height: cp.height,
        finalized_events: cp.finalized_events,
        frontier: &cp.frontier,
    };
    let mut preimage = Vec::new();
    ciborium::ser::into_writer(&payload, &mut preimage).map_err(|e| {
        DagError::Serialization(format!(
            "checkpoint signing payload canonical CBOR serialization failed: {e}"
        ))
    })?;
    Ok(preimage)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::expect_used)]
mod proptests {
    use proptest::prelude::*;
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct CheckpointSigningPayloadForTest {
        domain: String,
        schema_version: u16,
        event_root: Hash256,
        state_root: Hash256,
        height: u64,
        finalized_events: u64,
        frontier: Vec<Hash256>,
    }

    fn arb_hash256() -> impl Strategy<Value = Hash256> {
        any::<[u8; 32]>().prop_map(Hash256::from_bytes)
    }

    fn arb_checkpoint() -> impl Strategy<Value = CheckpointPayload> {
        (
            arb_hash256(),
            arb_hash256(),
            any::<u64>(),
            any::<u64>(),
            prop::collection::vec(arb_hash256(), 0..=8usize),
        )
            .prop_map(
                |(event_root, state_root, height, finalized_events, frontier)| CheckpointPayload {
                    event_root,
                    state_root,
                    height,
                    finalized_events,
                    frontier,
                    validator_sigs: vec![],
                },
            )
    }

    fn preimage(cp: &CheckpointPayload) -> Vec<u8> {
        checkpoint_signing_preimage(cp).expect("test checkpoint preimage must encode")
    }

    fn decoded_preimage(cp: &CheckpointPayload) -> CheckpointSigningPayloadForTest {
        ciborium::from_reader(&preimage(cp)[..])
            .expect("checkpoint signing preimage must decode as CBOR")
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(100))]

        /// The preimage function must be pure: same input → same bytes.
        #[test]
        fn preimage_is_deterministic(cp in arb_checkpoint()) {
            let p1 = preimage(&cp);
            let p2 = preimage(&cp);
            prop_assert_eq!(p1, p2);
        }

        /// Domain separation tag must always be carried inside the CBOR payload.
        #[test]
        fn preimage_carries_domain_sep(cp in arb_checkpoint()) {
            let decoded = decoded_preimage(&cp);
            prop_assert_eq!(decoded.domain.as_bytes(), CHECKPOINT_DOMAIN_SEP);
            prop_assert_eq!(decoded.schema_version, CHECKPOINT_SIGNING_SCHEMA_VERSION);
        }

        /// The CBOR envelope must preserve every checkpoint field exactly.
        #[test]
        fn preimage_cbor_envelope_preserves_all_fields(cp in arb_checkpoint()) {
            let decoded = decoded_preimage(&cp);
            prop_assert_eq!(decoded.event_root, cp.event_root);
            prop_assert_eq!(decoded.state_root, cp.state_root);
            prop_assert_eq!(decoded.height, cp.height);
            prop_assert_eq!(decoded.finalized_events, cp.finalized_events);
            prop_assert_eq!(decoded.frontier, cp.frontier);
        }

        /// Any change to `height` must change the preimage.
        #[test]
        fn different_heights_produce_different_preimages(
            mut cp in arb_checkpoint(),
            alt_height in any::<u64>(),
        ) {
            prop_assume!(cp.height != alt_height);
            let p1 = preimage(&cp);
            cp.height = alt_height;
            let p2 = preimage(&cp);
            prop_assert_ne!(p1, p2);
        }

        /// Any change to `event_root` must change the preimage.
        #[test]
        fn different_event_roots_produce_different_preimages(
            mut cp in arb_checkpoint(),
            alt_root in arb_hash256(),
        ) {
            prop_assume!(cp.event_root != alt_root);
            let p1 = preimage(&cp);
            cp.event_root = alt_root;
            let p2 = preimage(&cp);
            prop_assert_ne!(p1, p2);
        }

        /// Any change to `state_root` must change the preimage.
        #[test]
        fn different_state_roots_produce_different_preimages(
            mut cp in arb_checkpoint(),
            alt_root in arb_hash256(),
        ) {
            prop_assume!(cp.state_root != alt_root);
            let p1 = preimage(&cp);
            cp.state_root = alt_root;
            let p2 = preimage(&cp);
            prop_assert_ne!(p1, p2);
        }

        /// Any change to `finalized_events` must change the preimage.
        #[test]
        fn different_finalized_events_produce_different_preimages(
            mut cp in arb_checkpoint(),
            alt_count in any::<u64>(),
        ) {
            prop_assume!(cp.finalized_events != alt_count);
            let p1 = preimage(&cp);
            cp.finalized_events = alt_count;
            let p2 = preimage(&cp);
            prop_assert_ne!(p1, p2);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct CheckpointSigningPayloadForTest {
        domain: String,
        schema_version: u16,
        event_root: Hash256,
        state_root: Hash256,
        height: u64,
        finalized_events: u64,
        frontier: Vec<Hash256>,
    }

    fn test_did() -> Did {
        Did::new("did:exo:validator1").expect("valid")
    }

    fn preimage(cp: &CheckpointPayload) -> Vec<u8> {
        checkpoint_signing_preimage(cp).expect("test checkpoint preimage must encode")
    }

    fn decode_signing_payload(preimage: &[u8]) -> CheckpointSigningPayloadForTest {
        ciborium::from_reader(preimage)
            .expect("checkpoint signing preimage must be a canonical CBOR payload")
    }

    #[test]
    fn preimage_deterministic() {
        let cp = CheckpointPayload {
            event_root: Hash256::digest(b"events"),
            state_root: Hash256::digest(b"state"),
            height: 42,
            finalized_events: 100,
            frontier: vec![Hash256::digest(b"tip1"), Hash256::digest(b"tip2")],
            validator_sigs: vec![],
        };

        let p1 = preimage(&cp);
        let p2 = preimage(&cp);
        assert_eq!(p1, p2, "preimage must be deterministic");
    }

    #[test]
    fn preimage_is_domain_separated_versioned_cbor() {
        let event_root = Hash256::digest(b"events");
        let state_root = Hash256::digest(b"state");
        let frontier = vec![Hash256::digest(b"tip1"), Hash256::digest(b"tip2")];
        let cp = CheckpointPayload {
            event_root,
            state_root,
            height: 42,
            finalized_events: 100,
            frontier: frontier.clone(),
            validator_sigs: vec![],
        };

        let decoded = decode_signing_payload(&preimage(&cp));

        assert_eq!(
            decoded.domain.as_bytes(),
            CHECKPOINT_DOMAIN_SEP,
            "checkpoint signing payload must carry the checkpoint domain tag"
        );
        assert_eq!(
            decoded.schema_version, 1,
            "checkpoint signing payload must carry an explicit schema version"
        );
        assert_eq!(decoded.event_root, event_root);
        assert_eq!(decoded.state_root, state_root);
        assert_eq!(decoded.height, 42);
        assert_eq!(decoded.finalized_events, 100);
        assert_eq!(decoded.frontier, frontier);
    }

    #[test]
    fn preimage_carries_domain_sep() {
        let cp = CheckpointPayload {
            event_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            height: 0,
            finalized_events: 0,
            frontier: vec![],
            validator_sigs: vec![],
        };

        let decoded = decode_signing_payload(&preimage(&cp));
        assert_eq!(decoded.domain.as_bytes(), CHECKPOINT_DOMAIN_SEP);
        assert_eq!(decoded.schema_version, CHECKPOINT_SIGNING_SCHEMA_VERSION);
    }

    #[test]
    fn preimage_includes_frontier() {
        let tip = Hash256::digest(b"frontier-tip");
        let cp_with = CheckpointPayload {
            event_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            height: 1,
            finalized_events: 1,
            frontier: vec![tip],
            validator_sigs: vec![],
        };
        let cp_without = CheckpointPayload {
            event_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            height: 1,
            finalized_events: 1,
            frontier: vec![],
            validator_sigs: vec![],
        };

        assert_ne!(
            preimage(&cp_with),
            preimage(&cp_without),
            "frontier must affect preimage"
        );
    }

    #[test]
    fn preimage_decodes_frontier_hashes_in_order() {
        let tip1 = Hash256::digest(b"frontier-tip-1");
        let tip2 = Hash256::digest(b"frontier-tip-2");
        let cp = CheckpointPayload {
            event_root: Hash256::digest(b"events"),
            state_root: Hash256::digest(b"state"),
            height: 7,
            finalized_events: 11,
            frontier: vec![tip1, tip2],
            validator_sigs: vec![],
        };

        let decoded = decode_signing_payload(&preimage(&cp));

        assert_eq!(decoded.frontier, vec![tip1, tip2]);
    }

    #[test]
    fn checkpoint_preimage_uses_cbor_instead_of_raw_concatenation() {
        let production = include_str!("checkpoint.rs");
        let preimage_section = production
            .split("pub fn checkpoint_signing_preimage")
            .nth(1)
            .expect("checkpoint_signing_preimage function must exist")
            .split("// ===========================================================================")
            .next()
            .expect("test separator must follow checkpoint_signing_preimage");

        assert!(
            !preimage_section.contains("unwrap_or(u64::MAX)"),
            "checkpoint signing preimage must fail closed instead of saturating frontier length"
        );
        assert!(
            preimage_section.contains("ciborium::ser::into_writer"),
            "checkpoint signing preimage must use canonical CBOR serialization"
        );
        assert!(
            !preimage_section.contains("extend_from_slice"),
            "checkpoint signing preimage must not use ad hoc byte concatenation"
        );
        assert!(
            !preimage_section.contains("to_le_bytes"),
            "checkpoint signing preimage must not hand-roll integer byte layouts"
        );
    }

    #[test]
    fn checkpoint_debug_redacts_validator_signature_material() {
        let checkpoint = CheckpointPayload {
            event_root: Hash256::digest(b"events"),
            state_root: Hash256::digest(b"state"),
            height: 7,
            finalized_events: 11,
            frontier: vec![Hash256::digest(b"frontier-tip")],
            validator_sigs: vec![ValidatorSignature {
                validator_did: test_did(),
                key_version: 1,
                signature: Signature::from_bytes([0xAB; 64]),
            }],
        };

        let checkpoint_debug = format!("{checkpoint:?}");
        let validator_debug = format!("{:?}", checkpoint.validator_sigs[0]);

        assert!(
            checkpoint_debug.contains("validator_sig_count: 1"),
            "Checkpoint Debug output should expose signature count, not signature bodies"
        );
        assert!(
            validator_debug.contains("signature: \"<redacted>\""),
            "ValidatorSignature Debug output must explicitly redact signature material"
        );
        assert!(
            !checkpoint_debug.contains("Signature::Ed25519")
                && !validator_debug.contains("Signature::Ed25519"),
            "Debug output must not delegate to Signature Debug for checkpoint signatures"
        );
        assert!(
            !checkpoint_debug.contains("abab") && !validator_debug.contains("abab"),
            "Debug output must not expose validator signature byte prefixes"
        );
    }

    #[test]
    fn validator_signature_construction() {
        let sig = ValidatorSignature {
            validator_did: test_did(),
            key_version: 1,
            signature: Signature::Empty,
        };
        assert_eq!(sig.key_version, 1);
    }
}
