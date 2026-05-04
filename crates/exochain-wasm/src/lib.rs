//! ExoChain WASM Bindings
//!
//! Exposes the full ExoChain governance engine to JavaScript/Node.js via WebAssembly.
//! Covers 14 crates: core, identity, consent, authority, gatekeeper, governance,
//! escalation, legal, dag, proofs, api, tenant, decision-forum, and messaging.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod authority_bindings;
pub mod catapult_bindings;
pub mod consent_bindings;
pub mod core_bindings;
pub mod decision_forum_bindings;
pub mod escalation_bindings;
pub mod gatekeeper_bindings;
pub mod governance_bindings;
pub mod identity_bindings;
pub mod legal_bindings;
pub mod messaging_bindings;
mod serde_bridge;

// Flat re-exports so integration tests and downstream rlib consumers can
// access all WASM bindings as `exochain_wasm::wasm_*` without module prefixes.
pub use authority_bindings::*;
pub use catapult_bindings::*;
pub use consent_bindings::*;
pub use core_bindings::*;
pub use decision_forum_bindings::*;
pub use escalation_bindings::*;
pub use gatekeeper_bindings::*;
pub use governance_bindings::*;
pub use identity_bindings::*;
pub use legal_bindings::*;
pub use messaging_bindings::*;

#[cfg(test)]
mod source_guard_tests {
    #[test]
    fn wasm_bridge_uses_deterministic_collections() {
        let binding_sources = [
            (
                "authority_bindings.rs",
                include_str!("authority_bindings.rs"),
            ),
            (
                "governance_bindings.rs",
                include_str!("governance_bindings.rs"),
            ),
        ];

        for (path, source) in binding_sources {
            assert!(
                !source.contains("HashMap"),
                "{path} must use deterministic BTreeMap-style collections at the WASM boundary"
            );
            assert!(
                !source.contains("HashSet"),
                "{path} must use deterministic BTreeSet-style collections at the WASM boundary"
            );
        }
    }

    #[test]
    fn wasm_consent_bridge_requires_caller_supplied_time() {
        let source = include_str!("consent_bindings.rs");
        let forbidden = [
            format!("{}{}", "Timestamp::", "now_utc()"),
            format!("{}{}", "Uuid::", "new_v4()"),
            "HybridClock::new()".to_string(),
        ];

        for pattern in forbidden {
            assert!(
                !source.contains(&pattern),
                "consent WASM bindings must receive caller-supplied IDs and HLC timestamps"
            );
        }
    }

    #[test]
    fn wasm_consent_termination_refuses_unsigned_actor_did_bridge() {
        let source = include_str!("consent_bindings.rs");
        let termination = source
            .split("pub fn wasm_terminate_bailment(")
            .nth(1)
            .and_then(|section| {
                section
                    .split("pub fn wasm_terminate_bailment_signed(")
                    .next()
            })
            .expect("wasm_terminate_bailment source");
        let signed_termination = source
            .split("pub fn wasm_terminate_bailment_signed(")
            .nth(1)
            .expect("wasm_terminate_bailment_signed source");

        assert!(
            termination.contains("unsigned bailment termination is disabled"),
            "legacy WASM bailment termination must fail closed instead of trusting actor_did"
        );
        assert!(
            !termination.contains("exo_consent::bailment::terminate(&mut bailment, &actor)"),
            "legacy WASM bailment termination must not reach the core state transition"
        );
        assert!(
            source.contains("pub fn wasm_bailment_termination_payload("),
            "WASM consent bridge must expose the canonical termination payload for external signing"
        );
        assert!(
            source.contains("pub fn wasm_terminate_bailment_signed("),
            "WASM consent bridge must keep the signed termination entrypoint fail-closed"
        );
        assert!(
            signed_termination.contains("untrusted_wasm_bailment_termination_error"),
            "WASM signed termination must fail closed instead of trusting caller-supplied key material"
        );
        assert!(
            !signed_termination.contains("terminate_verified"),
            "WASM signed termination must not call core termination without trusted DID resolution"
        );
    }

    #[test]
    fn wasm_governance_bridge_requires_caller_supplied_metadata() {
        let source = include_str!("governance_bindings.rs");
        let forbidden = [
            format!("{}{}", "Timestamp::", "now_utc()"),
            format!("{}{}", "Uuid::", "new_v4()"),
            "HybridClock::new()".to_string(),
        ];

        for pattern in forbidden {
            assert!(
                !source.contains(&pattern),
                "governance WASM bindings must receive caller-supplied IDs and HLC timestamps"
            );
        }
    }

    #[test]
    fn wasm_governance_close_uses_verified_deliberation_quorum() {
        let source = include_str!("governance_bindings.rs");
        assert!(
            source.contains("close_verified"),
            "WASM deliberation close must use cryptographically verified quorum closure"
        );
        assert!(
            !source.contains("deliberation::close(&mut delib"),
            "WASM deliberation close must not call the structural-only close path"
        );
    }

    #[test]
    fn wasm_governance_clearance_requires_caller_supplied_registry() {
        let source = include_str!("governance_bindings.rs");
        assert!(
            source.contains("registry_json"),
            "WASM clearance checks must accept caller-supplied clearance registry data"
        );
        assert!(
            !source.contains("ClearanceLevel::Governor"),
            "WASM clearance checks must not fabricate Governor clearance"
        );
    }

    #[test]
    fn wasm_governance_bridge_bounds_untrusted_collection_inputs() {
        let source = include_str!("governance_bindings.rs");
        for required in [
            "MAX_WASM_PUBLIC_KEYS",
            "MAX_WASM_CLEARANCE_REGISTRY_ENTRIES",
            "MAX_WASM_APPROVALS",
            "MAX_WASM_CONFLICT_DECLARATIONS",
            "MAX_WASM_AUDIT_ENTRIES",
            "MAX_WASM_DELIBERATION_PARTICIPANTS",
            "MAX_WASM_INDEPENDENCE_ACTORS",
            "MAX_WASM_REGISTRY_RELATIONSHIPS",
            "MAX_WASM_COORDINATION_ACTIONS",
            "MAX_WASM_PROPOSAL_BYTES",
            "MAX_WASM_CHALLENGE_EVIDENCE_BYTES",
            "parse_bounded_vec",
        ] {
            assert!(
                source.contains(required),
                "governance WASM boundary must define and use {required}"
            );
        }

        for forbidden in [
            "let key_pairs: Vec<(String, String)> = from_json_str(public_keys_json)?;",
            "let entries: Vec<WasmClearanceRegistryEntry> = from_json_str(registry_json)?;",
            "let approvals: Vec<exo_governance::quorum::Approval> = from_json_str(approvals_json)?;",
            "let entries: Vec<exo_governance::audit::AuditEntry> = from_json_str(entries_json)?;",
            "let did_strs: Vec<String> = from_json_str(participants_json)?;",
            "let did_strs: Vec<String> = from_json_str(actors_json)?;",
            "let actions: Vec<exo_governance::crosscheck::TimestampedAction> = from_json_str(actions_json)?;",
        ] {
            assert!(
                !source.contains(forbidden),
                "governance WASM boundary must not deserialize untrusted arrays without a count bound: {forbidden}"
            );
        }
    }

    #[test]
    fn wasm_non_governance_vec_inputs_use_explicit_count_bounds() {
        let required = [
            (
                "authority_bindings.rs",
                include_str!("authority_bindings.rs"),
                "MAX_WASM_AUTHORITY_LINKS",
            ),
            (
                "authority_bindings.rs",
                include_str!("authority_bindings.rs"),
                "MAX_WASM_AUTHORITY_KEYS",
            ),
            (
                "identity_bindings.rs",
                include_str!("identity_bindings.rs"),
                "MAX_WASM_SHAMIR_SHARES",
            ),
            (
                "escalation_bindings.rs",
                include_str!("escalation_bindings.rs"),
                "MAX_WASM_DETECTION_SIGNALS",
            ),
            (
                "escalation_bindings.rs",
                include_str!("escalation_bindings.rs"),
                "MAX_WASM_FEEDBACK_ENTRIES",
            ),
            (
                "escalation_bindings.rs",
                include_str!("escalation_bindings.rs"),
                "MAX_WASM_ESCALATION_CASES",
            ),
            (
                "messaging_bindings.rs",
                include_str!("messaging_bindings.rs"),
                "MAX_WASM_AUTHORIZED_TRUSTEES",
            ),
            (
                "legal_bindings.rs",
                include_str!("legal_bindings.rs"),
                "MAX_WASM_LEGAL_AUDIT_ACTIONS",
            ),
            (
                "legal_bindings.rs",
                include_str!("legal_bindings.rs"),
                "MAX_WASM_EDISCOVERY_CORPUS_ITEMS",
            ),
            (
                "legal_bindings.rs",
                include_str!("legal_bindings.rs"),
                "MAX_WASM_RETENTION_RECORDS",
            ),
        ];

        for (path, source, required_name) in required {
            assert!(
                source.contains(required_name),
                "{path} must define and use {required_name}"
            );
        }

        let forbidden = [
            (
                "authority_bindings.rs",
                include_str!("authority_bindings.rs"),
                "let links: Vec<exo_authority::AuthorityLink> = from_json_str(links_json)?;",
            ),
            (
                "authority_bindings.rs",
                include_str!("authority_bindings.rs"),
                "let key_pairs: Vec<(String, String)> = from_json_str(keys_json)?;",
            ),
            (
                "identity_bindings.rs",
                include_str!("identity_bindings.rs"),
                "let shares: Vec<exo_identity::shamir::Share> = from_json_str(shares_json)?;",
            ),
            (
                "escalation_bindings.rs",
                include_str!("escalation_bindings.rs"),
                "let signals: Vec<exo_escalation::detector::DetectionSignal> = from_json_str(signals_json)?;",
            ),
            (
                "escalation_bindings.rs",
                include_str!("escalation_bindings.rs"),
                "from_json_str(entries_json)?;",
            ),
            (
                "escalation_bindings.rs",
                include_str!("escalation_bindings.rs"),
                "let feedbacks: Vec<exo_escalation::feedback::FeedbackEntry> = from_json_str(feedbacks_json)?;",
            ),
            (
                "escalation_bindings.rs",
                include_str!("escalation_bindings.rs"),
                "let mut cases: Vec<exo_escalation::escalation::EscalationCase> = from_json_str(cases_json)?;",
            ),
            (
                "messaging_bindings.rs",
                include_str!("messaging_bindings.rs"),
                "let trustees: Vec<WasmAuthorizedTrustee> = from_json_str(authorized_trustees_json)?;",
            ),
            (
                "legal_bindings.rs",
                include_str!("legal_bindings.rs"),
                "let actions: Vec<exo_legal::fiduciary::AuditEntry> = from_json_str(actions_json)?;",
            ),
            (
                "legal_bindings.rs",
                include_str!("legal_bindings.rs"),
                "let corpus: Vec<exo_legal::evidence::Evidence> = from_json_str(corpus_json)?;",
            ),
            (
                "legal_bindings.rs",
                include_str!("legal_bindings.rs"),
                "let mut records: Vec<exo_legal::records::Record> = from_json_str(records_json)?;",
            ),
        ];

        for (path, source, forbidden_pattern) in forbidden {
            assert!(
                !source.contains(forbidden_pattern),
                "{path} must not deserialize untrusted JSON arrays without explicit count bounds: {forbidden_pattern}"
            );
        }
    }

    #[test]
    fn wasm_decision_forum_vec_inputs_use_explicit_count_bounds() {
        let source = include_str!("decision_forum_bindings.rs");

        for required in [
            "MAX_WASM_FORUM_EMERGENCY_ACTIONS",
            "MAX_WASM_FORUM_CHALLENGES",
            "MAX_WASM_FORUM_SIGNATURES",
            "MAX_WASM_FORUM_PUBLIC_KEYS",
        ] {
            assert!(
                source.contains(required),
                "decision forum WASM boundary must define and use {required}"
            );
        }

        for forbidden in [
            "let actions: Vec<decision_forum::emergency::EmergencyAction> = from_json_str(actions_json)?;",
            "from_json_str(challenges_json)?;",
            "let sig_pairs: Vec<(String, String)> = from_json_str(signatures_json)?;",
            "let key_pairs: Vec<(String, String)> = from_json_str(public_keys_json)?;",
        ] {
            assert!(
                !source.contains(forbidden),
                "decision forum WASM boundary must not deserialize untrusted arrays without a count bound: {forbidden}"
            );
        }
    }

    #[test]
    fn wasm_decision_transition_requires_kernel_adjudication() {
        let source = include_str!("decision_forum_bindings.rs");
        let legacy_transition = source
            .split("pub fn wasm_transition_decision(")
            .nth(1)
            .and_then(|section| {
                section
                    .split("pub fn wasm_transition_decision_adjudicated(")
                    .next()
            })
            .expect("legacy decision transition export source");

        assert!(
            legacy_transition.contains("unadjudicated decision transitions are disabled"),
            "legacy WASM decision transition must fail closed without a kernel verdict"
        );
        assert!(
            !legacy_transition.contains(".transition_at("),
            "legacy WASM decision transition must not reach the raw BCTS transition"
        );
        assert!(
            source.contains("Kernel::new") && source.contains(".transition_adjudicated_at("),
            "WASM decision bridge must expose a kernel-adjudicated transition entrypoint"
        );
        assert!(
            source.contains("WasmDecisionTransitionAdjudicatedRequest")
                && source.contains("request_json"),
            "WASM adjudicated decision transition must use a typed bounded request JSON instead of a wide argument list"
        );
        assert!(
            !source.contains(
                "timestamp_logical: u32,\n    constitution: &[u8],\n    invariant_set_json: &str,"
            ),
            "WASM adjudicated decision transition must not expose a clippy-wide argument list"
        );
    }

    #[test]
    fn wasm_messaging_bridge_requires_caller_supplied_envelope_metadata() {
        let source = include_str!("messaging_bindings.rs");
        assert!(
            source.contains("message_id") && source.contains("created_physical_ms"),
            "messaging WASM encryption must expose caller-supplied envelope metadata"
        );
        assert!(
            source.contains("ComposeMetadata::new"),
            "messaging WASM encryption must validate caller-supplied envelope metadata"
        );
        assert!(
            source.contains("DeathVerificationCreationMetadata::new")
                && source.contains("DeathConfirmationMetadata::new"),
            "messaging WASM death verification must validate caller-supplied state metadata"
        );

        let forbidden = [
            format!("{}{}", "Timestamp::", "now_utc()"),
            format!("{}{}", "Uuid::", "new_v4()"),
            "HybridClock::new()".to_string(),
        ];

        for pattern in forbidden {
            assert!(
                !source.contains(&pattern),
                "messaging WASM bindings must receive caller-supplied IDs and HLC timestamps"
            );
        }
    }

    #[test]
    fn wasm_messaging_bridge_does_not_export_x25519_secret_material() {
        let source = include_str!("messaging_bindings.rs");
        let forbidden = [
            ["secret", "_key_hex"].concat(),
            [".secret", ".to_hex()"].concat(),
            [".secret", ".0"].concat(),
        ];
        for pattern in forbidden {
            assert!(
                !source.contains(&pattern),
                "messaging WASM bindings must not export or tuple-access X25519 secret material via {pattern}"
            );
        }
    }

    #[test]
    fn wasm_messaging_bridge_does_not_decode_ed25519_signing_secrets() {
        let source = include_str!("messaging_bindings.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .unwrap_or(source);

        assert!(
            production.contains("wasm_prepare_encrypted_message"),
            "messaging WASM must expose unsigned encrypted envelopes plus signing bytes"
        );
        assert!(
            production.contains("wasm_attach_message_signature"),
            "messaging WASM must attach caller-produced signatures without importing sender secrets"
        );

        for pattern in [
            "parse_ed25519_signing_seed_hex",
            "sender_signing_key_hex",
            "SecretKey::from_bytes",
            "lock_and_send(",
        ] {
            assert!(
                !production.contains(pattern),
                "messaging WASM bindings must not decode or use Ed25519 signing secrets via {pattern}"
            );
        }
    }

    #[test]
    fn wasm_messaging_legacy_raw_secret_entrypoints_fail_closed() {
        let source = include_str!("messaging_bindings.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .unwrap_or(source);

        assert!(
            production
                .contains("raw X25519 secret public derivation is disabled at the WASM boundary"),
            "legacy X25519 raw-secret public derivation must fail closed"
        );
        assert!(
            production.contains("raw Ed25519 sender signing is disabled at the WASM boundary"),
            "legacy raw-secret message encryption must fail closed"
        );
    }

    #[test]
    fn wasm_identity_risk_bridge_requires_caller_supplied_signer_and_time() {
        let source = include_str!("identity_bindings.rs");
        assert!(
            source.contains("attester_secret_hex")
                && source.contains("now_physical_ms")
                && source.contains("now_logical"),
            "risk assessment must expose caller-supplied signer and HLC metadata"
        );

        let forbidden = [
            "HybridClock::new()".to_string(),
            "generate_keypair()".to_string(),
            ["Timestamp::", "now_utc()"].concat(),
        ];

        for pattern in &forbidden {
            assert!(
                !source.contains(pattern),
                "identity WASM risk binding must not fabricate signer or time with {pattern}"
            );
        }
    }

    #[test]
    fn wasm_identity_secret_metadata_has_no_debug_surface() {
        let source = include_str!("identity_bindings.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .unwrap_or(source);
        let metadata_def = production
            .split("struct RiskAssessmentMetadata")
            .next()
            .expect("risk metadata definition must exist");

        assert!(
            production.contains("attester_secret_hex"),
            "risk assessment metadata must keep the caller-supplied attester secret explicit"
        );
        assert!(
            !metadata_def.contains("Debug"),
            "secret-bearing risk metadata must not derive or expose Debug"
        );
    }

    #[test]
    fn wasm_core_event_bridge_requires_caller_supplied_metadata() {
        let source = include_str!("core_bindings.rs");
        assert!(
            source.contains("event_id")
                && source.contains("timestamp_physical_ms")
                && source.contains("timestamp_logical"),
            "signed event creation must expose caller-supplied event ID and HLC metadata"
        );

        let forbidden = [
            "CorrelationId::new()".to_string(),
            "HybridClock::new()".to_string(),
            ["Timestamp::", "now_utc()"].concat(),
        ];

        for pattern in &forbidden {
            assert!(
                !source.contains(pattern),
                "core WASM event bindings must not fabricate event metadata with {pattern}"
            );
        }
    }

    #[test]
    fn wasm_core_bridge_does_not_decode_raw_secret_keys() {
        let source = include_str!("core_bindings.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .unwrap_or(source);

        assert!(
            production.contains("wasm_event_signing_payload"),
            "core WASM events must expose canonical signing bytes for external signers"
        );
        assert!(
            production.contains("wasm_create_event_with_signature"),
            "core WASM events must accept caller-produced signatures without importing secrets"
        );

        for pattern in [
            "parse_ed25519_secret_array_hex",
            "parse_ed25519_signing_seed_hex",
            "SecretKey::from_bytes",
            "KeyPair::from_secret_bytes",
            "exo_core::events::create_signed_event",
        ] {
            assert!(
                !production.contains(pattern),
                "core WASM bindings must not decode or use raw secret keys via {pattern}"
            );
        }
    }

    #[test]
    fn wasm_core_legacy_raw_secret_entrypoints_fail_closed() {
        let source = include_str!("core_bindings.rs");
        let production = source
            .split("// ===========================================================================")
            .next()
            .unwrap_or(source);

        assert!(
            production.contains("raw secret-key signing is disabled at the WASM boundary"),
            "legacy raw-secret signing entrypoint must fail closed"
        );
        assert!(
            production
                .contains("raw secret-key public derivation is disabled at the WASM boundary"),
            "legacy raw-secret public-key derivation entrypoint must fail closed"
        );
        assert!(
            production.contains("raw secret-key event signing is disabled at the WASM boundary"),
            "legacy raw-secret event creation entrypoint must fail closed"
        );
    }

    #[test]
    fn wasm_core_merkle_bindings_bound_untrusted_arrays() {
        let source = include_str!("core_bindings.rs");
        assert!(
            source.contains("MAX_WASM_MERKLE_LEAVES"),
            "WASM Merkle root/proof bindings must cap caller-supplied leaf arrays"
        );
        assert!(
            source.contains("MAX_WASM_MERKLE_PROOF_HASHES"),
            "WASM Merkle verification must cap caller-supplied proof arrays"
        );
    }

    #[test]
    fn wasm_secret_key_decoding_zeroizes_rust_owned_buffers() {
        let sources = [("identity_bindings.rs", include_str!("identity_bindings.rs"))];

        for (path, source) in sources {
            assert!(
                source.contains("Zeroizing"),
                "{path} must wrap decoded secret-key buffers in zeroize::Zeroizing"
            );
        }
    }

    #[test]
    fn wasm_gatekeeper_boundary_redacts_internal_errors_and_state() {
        let source = include_str!("gatekeeper_bindings.rs");
        assert!(
            source.contains("gatekeeper_boundary_error"),
            "gatekeeper WASM bindings must centralize sanitized boundary errors"
        );
        assert!(
            source.contains("holon_state_label"),
            "gatekeeper WASM bindings must expose explicit lifecycle labels"
        );

        let forbidden = [
            "format!(\"Reduction error: {e}\")",
            "format!(\"Step error: {e}\")",
            "format!(\"{:?}\", holon.state)",
        ];

        for pattern in forbidden {
            assert!(
                !source.contains(pattern),
                "gatekeeper WASM boundary must not expose internal debug/error details via {pattern}"
            );
        }
    }

    #[test]
    fn wasm_escalation_kanban_validator_uses_bounded_json_bridge() {
        let source = include_str!("escalation_bindings.rs");
        assert!(
            source.contains("from_json_str(column_json)"),
            "Kanban column validation must use the bounded JSON bridge"
        );
        assert!(
            !source.contains("serde_json::from_str(column_json)"),
            "Kanban column validation must not bypass the bounded JSON bridge"
        );
        assert!(
            !source.contains("\"error\": e.to_string()"),
            "Kanban column validation must not return raw serde errors to WASM callers"
        );
    }
}
