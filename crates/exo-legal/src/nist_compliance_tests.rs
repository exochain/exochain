//! NIST AI RMF invariant compliance tests.
//!
//! Validates that ExoChain enforcement mechanisms satisfy the evidentiary
//! requirements of the NIST AI RMF 1.0. Each test corresponds to one of
//! the three invariants named in issue EXOCHAIN-REM-010 (items 6, 7, 8).

#[cfg(test)]
mod nist_compliance {
    use exo_authority::{
        AuthorityChain as ReportAuthorityChain, AuthorityLink as ReportAuthorityLink,
        DelegateeKind, Permission as ReportPermission,
    };
    use exo_core::{Did, Hash256, Signature, Timestamp, crypto::KeyPair};
    use exo_gatekeeper::{
        InvariantEngine, McpRule,
        invariants::{ConstitutionalInvariant, InvariantContext, enforce_all},
        mcp_audit::{McpAuditLog, McpEnforcementOutcome, append, create_record, verify_chain},
        types::{
            AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, GovernmentBranch,
            Permission, PermissionSet, Provenance, Role,
        },
    };
    use exo_governance::audit::{self as gov_audit, AuditLog};
    use uuid::Uuid;

    use crate::{
        ai_transparency::{
            ReportParams, VerifiedAuthorityClearance, ai_delegation_event_from_link,
            generate_report, verify_authority_clearance,
        },
        compliance_report::{
            AttestationStatus, ComplianceReportMode, build_report, redact_model_id,
        },
        nist_mapping::{NistFunction, NistMapping},
    };

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn did(s: &str) -> Did {
        Did::new(&format!("did:exo:{s}")).expect("valid DID")
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn audit_id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn verified_report_clearance(requester: &Did) -> VerifiedAuthorityClearance {
        let root = did("report-root");
        let root_key = KeyPair::generate();
        let mut link = ReportAuthorityLink {
            delegator_did: root.clone(),
            delegate_did: requester.clone(),
            scope: vec![ReportPermission::Read],
            created: ts(1_000),
            expires: None,
            signature: Signature::empty(),
            depth: 0,
            delegatee_kind: DelegateeKind::Human,
        };
        let payload = link
            .signing_payload()
            .expect("authority link signing payload");
        link.signature = root_key.sign(&payload);

        let chain = ReportAuthorityChain {
            links: vec![link],
            max_depth: 5,
        };
        verify_authority_clearance(requester, &chain, ts(2_000), |did| {
            if did == &root {
                Some(*root_key.public_key())
            } else {
                None
            }
        })
        .expect("report authority clearance must verify")
    }

    fn signed_authority_link(grantor: &Did, grantee: &Did) -> AuthorityLink {
        let (public_key, secret_key) = exo_core::crypto::generate_keypair();
        let permissions = PermissionSet::new(vec![Permission::new("read")]);

        let mut payload = Vec::new();
        payload.extend_from_slice(grantor.as_str().as_bytes());
        payload.push(0x00);
        payload.extend_from_slice(grantee.as_str().as_bytes());
        payload.push(0x00);
        for permission in &permissions.permissions {
            payload.extend_from_slice(permission.0.as_bytes());
            payload.push(0x00);
        }
        let message = Hash256::digest(&payload);
        let signature = exo_core::crypto::sign(message.as_bytes(), &secret_key);

        AuthorityLink {
            grantor: grantor.clone(),
            grantee: grantee.clone(),
            permissions,
            signature: signature.to_bytes().to_vec(),
            grantor_public_key: Some(public_key.as_bytes().to_vec()),
        }
    }

    fn signed_provenance(actor: &Did) -> Provenance {
        let (public_key, secret_key) = exo_core::crypto::generate_keypair();
        let timestamp = "2026-03-20T00:00:00Z".to_owned();
        let action_hash = vec![1, 2, 3];

        let mut payload = Vec::new();
        payload.extend_from_slice(actor.as_str().as_bytes());
        payload.push(0x00);
        payload.extend_from_slice(&action_hash);
        payload.push(0x00);
        payload.extend_from_slice(timestamp.as_bytes());
        let message = Hash256::digest(&payload);
        let signature = exo_core::crypto::sign(message.as_bytes(), &secret_key);

        Provenance {
            actor: actor.clone(),
            timestamp,
            action_hash,
            signature: signature.to_bytes().to_vec(),
            public_key: Some(public_key.as_bytes().to_vec()),
            voice_kind: None,
            independence: None,
            review_order: None,
        }
    }

    /// Build a passing InvariantContext matching the pattern in invariants.rs tests.
    fn passing_context(actor: &Did) -> InvariantContext {
        let root = did("root");
        InvariantContext {
            actor: actor.clone(),
            actor_roles: vec![Role {
                name: "operator".into(),
                branch: GovernmentBranch::Executive,
            }],
            bailment_state: BailmentState::Active {
                bailor: did("bailor"),
                bailee: actor.clone(),
                scope: "data:test".into(),
            },
            consent_records: vec![ConsentRecord {
                subject: did("bailor"),
                granted_to: actor.clone(),
                scope: "data:test".into(),
                active: true,
            }],
            authority_chain: AuthorityChain {
                links: vec![signed_authority_link(&root, actor)],
            },
            is_self_grant: false,
            human_override_preserved: true,
            kernel_modification_attempted: false,
            quorum_evidence: None,
            provenance: Some(signed_provenance(actor)),
            actor_permissions: PermissionSet::new(vec![Permission::new("read")]),
            requested_permissions: PermissionSet::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Test 1: HumanOversight → NIST Govern GV.1
    //
    // Validates:
    // (a) HumanOverride is mapped to Govern GV.1 in the canonical mapping.
    // (b) The invariant passes for valid contexts.
    // (c) The invariant FAILS detectably when human_override_preserved=false.
    // (d) The governance audit log records enforcement events with chain integrity
    //     (satisfies GV.1 evidentiary requirement).
    // (e) GDPR Art. 22 is referenced in the mapping.
    // -----------------------------------------------------------------------

    #[test]
    fn test_human_oversight_nist_compliance() {
        // 1. Verify NIST mapping covers HumanOverride under Govern GV.1.
        let mapping = NistMapping::canonical();
        let entry = mapping
            .entry_for(ConstitutionalInvariant::HumanOverride)
            .expect("HumanOverride must have a NIST mapping (EXOCHAIN-REM-010)");

        assert!(
            entry.nist_functions.contains(&NistFunction::Govern),
            "HumanOverride must map to NIST Govern function"
        );
        assert!(
            entry.nist_subcategories.iter().any(|s| s == "GV.1"),
            "HumanOverride must map to NIST subcategory GV.1"
        );

        // 2. Invariant passes for a valid context.
        let actor = did("human-operator");
        let engine = InvariantEngine::all();
        let ctx_ok = passing_context(&actor);
        assert!(
            enforce_all(&engine, &ctx_ok).is_ok(),
            "All invariants must pass for a valid context"
        );

        // 3. Invariant FAILS detectably when human override is removed.
        let mut ctx_bad = passing_context(&actor);
        ctx_bad.human_override_preserved = false;
        let violations =
            enforce_all(&engine, &ctx_bad).expect_err("HumanOverride violation must be detected");
        assert!(
            violations
                .iter()
                .any(|v| v.invariant == ConstitutionalInvariant::HumanOverride),
            "Violation report must identify HumanOverride invariant"
        );

        // 4. Record enforcement events in the governance audit log — this
        //    constitutes the GV.1 evidence record required by NIST.
        let mut audit_log = AuditLog::new();
        let e1 = gov_audit::create_entry(
            &audit_log,
            audit_id(0xE100),
            ts(40_000),
            actor.clone(),
            "human_override_check".into(),
            "pass".into(),
            [0u8; 32],
        )
        .expect("deterministic governance audit entry");
        gov_audit::append(&mut audit_log, e1).expect("audit append");

        let e2 = gov_audit::create_entry(
            &audit_log,
            audit_id(0xE101),
            ts(40_001),
            actor,
            "human_override_check".into(),
            "VIOLATION: human_override_preserved=false".into(),
            [0u8; 32],
        )
        .expect("deterministic governance audit entry");
        gov_audit::append(&mut audit_log, e2).expect("audit append");

        // 5. Chain integrity must hold — satisfies tamper-evidence requirement.
        gov_audit::verify_chain(&audit_log).expect("governance audit chain must be intact");
        assert_eq!(audit_log.len(), 2);

        // 6. GDPR Art. 22 must be referenced in the mapping.
        assert!(
            entry.regulatory_refs.iter().any(|r| r.contains("Art. 22")),
            "HumanOverride mapping must reference GDPR Art. 22 (automated decision-making)"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2: TransparencyAccountability → NIST Measure MS.2
    //
    // Validates:
    // (a) ProvenanceVerifiable maps to Measure MS.2.
    // (b) MCP audit log records enforcement outcomes with chain integrity.
    // (c) Tamper detection works on the MCP audit chain.
    // (d) Provenance invariant fails without provenance metadata.
    // (e) AiTransparencyReport captures MCP enforcement event counts.
    // (f) ComplianceReport hash is deterministic (same inputs → same hash).
    // (g) GDPR Art. 5(1)(f) is referenced in the mapping.
    // -----------------------------------------------------------------------

    #[test]
    fn test_transparency_accountability_nist_compliance() {
        // 1. Verify NIST mapping for ProvenanceVerifiable.
        let mapping = NistMapping::canonical();
        let entry = mapping
            .entry_for(ConstitutionalInvariant::ProvenanceVerifiable)
            .expect("ProvenanceVerifiable must have a NIST mapping");

        assert!(
            entry.nist_functions.contains(&NistFunction::Measure),
            "ProvenanceVerifiable must map to NIST Measure function"
        );
        assert!(
            entry.nist_subcategories.iter().any(|s| s == "MS.2"),
            "ProvenanceVerifiable must map to NIST subcategory MS.2"
        );
        assert!(
            entry.regulatory_refs.iter().any(|r| r.contains("5(1)(f)")),
            "ProvenanceVerifiable mapping must reference GDPR Art. 5(1)(f)"
        );

        // 2. Build a multi-event MCP audit log and verify chain integrity —
        //    satisfies MS.2 "AI risk measurement via documentation".
        let actor = did("ai-agent-1");
        let mut mcp_log = McpAuditLog::new();
        for (index, rule) in McpRule::all().into_iter().enumerate() {
            let offset = u128::try_from(index).expect("rule index fits u128");
            let timestamp_offset = u64::try_from(index).expect("rule index fits u64");
            let r = create_record(
                &mcp_log,
                audit_id(0xD000 + offset),
                ts(30_000 + timestamp_offset),
                rule,
                actor.clone(),
                McpEnforcementOutcome::Allowed,
                Some("EU-WEST-1".into()),
            )
            .expect("deterministic MCP audit record");
            append(&mut mcp_log, r).expect("MCP audit append");
        }
        verify_chain(&mcp_log).expect("MCP audit chain must be intact after 6 records");
        assert_eq!(mcp_log.len(), 6, "All 6 MCP rules must be recorded");

        // 3. Tamper detection: mutating any record breaks the chain.
        let mut tampered = mcp_log.clone();
        tampered.records[2].chain_hash = [0xffu8; 32];
        assert!(
            verify_chain(&tampered).is_err(),
            "Tampered MCP audit chain must be detected"
        );

        // 4. Provenance invariant fails without provenance.
        let engine = InvariantEngine::all();
        let mut ctx_no_prov = passing_context(&actor);
        ctx_no_prov.provenance = None;
        let violations = enforce_all(&engine, &ctx_no_prov)
            .expect_err("Missing provenance must produce a violation");
        assert!(
            violations
                .iter()
                .any(|v| v.invariant == ConstitutionalInvariant::ProvenanceVerifiable),
            "ProvenanceVerifiable violation must be identified"
        );

        // 5. Transparency report captures MCP enforcement events.
        let tenant = did("tenant-acme");
        let clearance = verified_report_clearance(&tenant);
        let report = generate_report(ReportParams {
            tenant_id: &tenant,
            period_start: ts(0),
            period_end: ts(u64::MAX),
            legal_jurisdiction: "EU-AI-ACT",
            mcp_log: &mcp_log,
            ai_delegation_grants: vec![],
            ai_delegation_revocations: 0,
            authority_clearance: &clearance,
        })
        .expect("transparency report generation must succeed");
        assert_eq!(
            report.ai_agent_action_count, 6,
            "All 6 MCP enforcement events must appear in transparency report"
        );

        // 6. ComplianceReport hash is deterministic.
        let cr1 = build_report(&report, &ComplianceReportMode::Full, ts(99_000))
            .expect("compliance report hash must build");
        let cr2 = build_report(&report, &ComplianceReportMode::Full, ts(99_000))
            .expect("compliance report hash must build");
        assert_eq!(
            cr1.report_hash, cr2.report_hash,
            "ComplianceReport hash must be deterministic (same inputs → same hash)"
        );

        // 7. ProvenanceVerifiable attestation is Compliant.
        let pv_att = cr1
            .attestations
            .iter()
            .find(|a| a.invariant == "ProvenanceVerifiable")
            .expect("ProvenanceVerifiable must appear in attestations");
        assert_eq!(pv_att.status, AttestationStatus::Compliant);
    }

    // -----------------------------------------------------------------------
    // Test 3: DelegationGovernance → NIST Govern GV.6
    //
    // Validates:
    // (a) AuthorityChainValid maps to Govern GV.6.
    // (b) DelegateeKind::AiAgent tagging correctly identifies AI delegations.
    // (c) Human and Unknown delegations are excluded from AI event lists.
    // (d) AiTransparencyReport records AI delegation grants and revocations.
    // (e) model_id redaction (Full/Redacted modes) works correctly.
    // (f) Different tenants produce different redacted model_ids.
    // (g) GDPR Art. 5(2) accountability is referenced in the mapping.
    // -----------------------------------------------------------------------

    #[test]
    fn test_delegation_governance_nist_compliance() {
        // 1. Verify NIST mapping for AuthorityChainValid.
        let mapping = NistMapping::canonical();
        let entry = mapping
            .entry_for(ConstitutionalInvariant::AuthorityChainValid)
            .expect("AuthorityChainValid must have a NIST mapping");

        assert!(
            entry.nist_functions.contains(&NistFunction::Govern),
            "AuthorityChainValid must map to NIST Govern function"
        );
        assert!(
            entry.nist_subcategories.iter().any(|s| s == "GV.6"),
            "AuthorityChainValid must map to NIST subcategory GV.6"
        );
        assert!(
            entry
                .regulatory_refs
                .iter()
                .any(|r| r.contains("Art. 5(2)")),
            "AuthorityChainValid mapping must reference GDPR Art. 5(2) (accountability)"
        );

        // 2. AI delegation events are extracted from AiAgent links.
        let model_id = "claude-sonnet-4-6";
        let ai_event = ai_delegation_event_from_link(
            did("principal"),
            did("ai-agent-42"),
            &DelegateeKind::AiAgent {
                model_id: model_id.to_owned(),
            },
            ts(1000),
            Some(ts(2000)),
            1,
        )
        .expect("AiAgent link must produce a delegation event");
        assert_eq!(ai_event.model_id, model_id);
        assert_eq!(ai_event.depth, 1);

        // 3. Human and Unknown links produce no AI delegation events.
        assert!(
            ai_delegation_event_from_link(
                did("principal"),
                did("human-bob"),
                &DelegateeKind::Human,
                ts(1000),
                None,
                0,
            )
            .is_none(),
            "Human delegation must not appear in AI delegation events"
        );
        assert!(
            ai_delegation_event_from_link(
                did("principal"),
                did("legacy"),
                &DelegateeKind::Unknown,
                ts(1000),
                None,
                0,
            )
            .is_none(),
            "Unknown delegation must not appear in AI delegation events"
        );

        // 4. Transparency report records AI delegation grants and revocations.
        let tenant = did("tenant-beta");
        let mcp_log = McpAuditLog::new();
        let clearance = verified_report_clearance(&tenant);
        let report = generate_report(ReportParams {
            tenant_id: &tenant,
            period_start: ts(0),
            period_end: ts(u64::MAX),
            legal_jurisdiction: "NIST-AI-RMF",
            mcp_log: &mcp_log,
            ai_delegation_grants: vec![ai_event],
            ai_delegation_revocations: 1,
            authority_clearance: &clearance,
        })
        .expect("transparency report must succeed");
        assert_eq!(report.ai_delegation_grants.len(), 1);
        assert_eq!(report.ai_delegation_revocations, 1);

        // 5. Full mode preserves plaintext model_id.
        let result_full = redact_model_id(&tenant, model_id, &ComplianceReportMode::Full);
        assert_eq!(result_full, model_id);

        // 6. Redacted mode produces a 64-char hex BLAKE3 hash.
        let salt = [7u8; 32];
        let redacted = redact_model_id(
            &tenant,
            model_id,
            &ComplianceReportMode::Redacted {
                redaction_salt: salt,
            },
        );
        assert_eq!(redacted.len(), 64, "Redacted model_id must be 64-char hex");
        assert_ne!(redacted, model_id, "Redacted must differ from plaintext");

        // 7. Different tenants produce different redacted model_ids —
        //    prevents cross-tenant correlation attacks.
        let tenant2 = did("tenant-gamma");
        let redacted2 = redact_model_id(
            &tenant2,
            model_id,
            &ComplianceReportMode::Redacted {
                redaction_salt: salt,
            },
        );
        assert_ne!(
            redacted, redacted2,
            "Different tenants must produce different redacted model_ids"
        );

        // 8. AuthorityChainValid attestation is Compliant in the report.
        let cr = build_report(
            &report,
            &ComplianceReportMode::Redacted {
                redaction_salt: salt,
            },
            ts(5000),
        )
        .expect("compliance report hash must build");
        let acv = cr
            .attestations
            .iter()
            .find(|a| a.invariant == "AuthorityChainValid")
            .expect("AuthorityChainValid must appear in attestations");
        assert_eq!(acv.status, AttestationStatus::Compliant);
        assert_eq!(cr.report_mode, "Redacted");
    }
}
