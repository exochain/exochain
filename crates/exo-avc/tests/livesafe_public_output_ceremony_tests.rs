use std::fmt::{Debug, Display};

use exo_authority::permission::Permission;
use exo_avc::{
    AVC_SCHEMA_VERSION, AuthorityScope, AvcDecision, AvcRegistryRead, AvcRegistryWrite, DataClass,
    InMemoryAvcRegistry, LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE,
    LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN,
    LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT,
    LIVESAFE_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_SUBJECT_DID,
    LivesafePublicAdapterOutputAuthorizationDraft, LivesafePublicOutputCredentialCeremonyEvidence,
    LivesafePublicOutputCredentialCeremonyInput, issue_livesafe_public_output_credential_ceremony,
    livesafe_public_adapter_output_authorization_action_commitment_hash,
    livesafe_public_adapter_output_authorization_action_request,
    livesafe_public_adapter_output_authorization_idempotency_hash,
    mint_livesafe_public_adapter_output_authorization_proof,
    parse_livesafe_public_output_evidence_sha256, validate_avc,
};
use exo_core::{Did, Hash256, Timestamp, crypto::KeyPair};

const ISSUER_SEED: [u8; 32] = [0x42; 32];
const PROOF_SIGNER_SEED: [u8; 32] = [0x24; 32];

fn must_ok<T, E: Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error}"),
    }
}

fn must_err<T: Debug, E>(result: Result<T, E>, context: &str) -> E {
    match result {
        Ok(value) => panic!("{context}: unexpectedly succeeded with {value:?}"),
        Err(error) => error,
    }
}

fn must_some<T>(option: Option<T>, context: &str) -> T {
    match option {
        Some(value) => value,
        None => panic!("{context}"),
    }
}

fn issuer_keypair() -> KeyPair {
    must_ok(
        KeyPair::from_secret_bytes(ISSUER_SEED),
        "valid issuer keypair",
    )
}

fn proof_signer_keypair() -> KeyPair {
    must_ok(
        KeyPair::from_secret_bytes(PROOF_SIGNER_SEED),
        "valid proof signer keypair",
    )
}

fn did(value: &str) -> Did {
    must_ok(Did::new(value), "valid did")
}

fn ts(ms: u64) -> Timestamp {
    Timestamp::new(ms, 0)
}

fn evidence_bytes() -> Vec<u8> {
    br#"{"surface":"livesafe.ai","contract":"public-adapter-output","version":1}"#.to_vec()
}

fn livesafe_sha256_hash() -> Hash256 {
    Hash256::from_bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
        0x11, 0x00,
    ])
}

fn livesafe_sha256_value() -> &'static str {
    "sha256:00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100"
}

fn evidence() -> LivesafePublicOutputCredentialCeremonyEvidence {
    LivesafePublicOutputCredentialCeremonyEvidence {
        sha256_hash: livesafe_sha256_hash(),
    }
}

fn issuer_scope() -> AuthorityScope {
    AuthorityScope {
        permissions: vec![Permission::Read],
        tools: vec![LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into()],
        data_classes: vec![DataClass::Public],
        counterparties: vec![],
        jurisdictions: vec!["US".into()],
    }
}

fn valid_input() -> LivesafePublicOutputCredentialCeremonyInput {
    LivesafePublicOutputCredentialCeremonyInput {
        issuer_did: did("did:exo:livesafe-public-output-issuer"),
        issuer_authority_scope: issuer_scope(),
        credential_subject_did: did(LIVESAFE_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_SUBJECT_DID),
        public_subject: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT.into(),
        public_audience: LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE.into(),
        allowed_claim_names: vec![LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into()],
        evidence: evidence(),
        not_before: ts(1_000_000),
        expires_at: ts(2_000_000),
        idempotency_key: "livesafe-public-output-ceremony-20260705".into(),
    }
}

fn issue(
    input: LivesafePublicOutputCredentialCeremonyInput,
) -> Result<exo_avc::LivesafePublicOutputCredentialCeremonyOutput, exo_avc::AvcError> {
    let issuer = issuer_keypair();
    issue_livesafe_public_output_credential_ceremony(input, |payload| issuer.sign(payload))
}

fn registry_for_issued_ceremony(
    output: &exo_avc::LivesafePublicOutputCredentialCeremonyOutput,
    issuer_did: Did,
) -> InMemoryAvcRegistry {
    let mut registry = InMemoryAvcRegistry::new();
    registry.put_public_key(issuer_did.clone(), issuer_keypair().public);
    registry.put_issuer_permission_grant(issuer_did, vec![Permission::Read]);
    let registered_id = must_ok(
        registry.put_credential(output.credential.clone()),
        "node issue path accepts ceremony credential",
    );
    assert_eq!(registered_id, output.credential_id);
    registry
}

fn authorization_draft_for(
    output: &exo_avc::LivesafePublicOutputCredentialCeremonyOutput,
    evidence_hash: Hash256,
) -> LivesafePublicAdapterOutputAuthorizationDraft {
    let idempotency_key_hash = must_ok(
        livesafe_public_adapter_output_authorization_idempotency_hash(
            &output.authorization_request.idempotency_key,
        ),
        "idempotency hash",
    );
    let issued_at = output.not_before;
    let expires_at = output.authorization_request.expires_at;
    let action_commitment_hash = must_ok(
        livesafe_public_adapter_output_authorization_action_commitment_hash(
            &output.credential,
            &output.authorization_request.subject,
            &output.authorization_request.audience,
            evidence_hash,
            idempotency_key_hash,
            &issued_at,
            &expires_at,
        ),
        "action commitment hash",
    );

    LivesafePublicAdapterOutputAuthorizationDraft {
        credential: output.credential.clone(),
        subject: output.authorization_request.subject.clone(),
        audience: output.authorization_request.audience.clone(),
        evidence_hash,
        credential_id: Some(output.credential_id),
        receipt_id: Hash256::from_bytes([0x5a; 32]),
        action_commitment_hash,
        idempotency_key_hash,
        issued_at,
        expires_at,
        signer_did: did("did:exo:livesafe-public-output-proof-signer"),
    }
}

fn cbor_map_field<'a>(
    value: &'a ciborium::value::Value,
    field: &str,
) -> Option<&'a ciborium::value::Value> {
    value.as_map()?.iter().find_map(|(key, value)| {
        if key.as_text() == Some(field) {
            Some(value)
        } else {
            None
        }
    })
}

#[test]
fn ceremony_refuses_issuer_without_public_output_authority() {
    let mut input = valid_input();
    input.issuer_authority_scope.tools.clear();

    let error = must_err(
        issue(input),
        "issuer missing public-output capability must fail",
    );

    assert!(error.to_string().contains("issuer authority"));
    assert!(
        error
            .to_string()
            .contains(LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN)
    );
}

#[test]
fn ceremony_refuses_empty_or_forbidden_claim_caps() {
    let mut empty = valid_input();
    empty.allowed_claim_names.clear();
    let empty_error = must_err(issue(empty), "empty claim cap must fail");
    assert!(empty_error.to_string().contains("allowed claim"));

    let mut forbidden = valid_input();
    forbidden.allowed_claim_names = vec!["livesafe.medical.custody.consent.emergency.v1".into()];
    let forbidden_error = must_err(issue(forbidden), "forbidden claim cap must fail");
    assert!(forbidden_error.to_string().contains("forbidden claim"));
}

#[test]
fn ceremony_binds_subject_and_audience_to_livesafe_public_adapter_output_only() {
    let mut broad_subject = valid_input();
    broad_subject.public_subject = "exochain".into();
    let subject_error = must_err(issue(broad_subject), "broad subject must fail");
    assert!(subject_error.to_string().contains("subject"));

    let mut broad_audience = valid_input();
    broad_audience.public_audience = "https://livesafe.ai/api/medical/custody".into();
    let audience_error = must_err(issue(broad_audience), "broad audience must fail");
    assert!(audience_error.to_string().contains("audience"));

    let mut wrong_subject_did = valid_input();
    wrong_subject_did.credential_subject_did = did("did:exo:livesafe-medical-custody");
    let subject_did_error = must_err(
        issue(wrong_subject_did),
        "wrong credential subject DID must fail",
    );
    assert!(
        subject_did_error
            .to_string()
            .contains("credential subject DID")
    );
}

#[test]
fn ceremony_accepts_sha256_prefixed_evidence_hash_and_propagates_bytes() {
    let parsed = must_ok(
        parse_livesafe_public_output_evidence_sha256(livesafe_sha256_value()),
        "parse LiveSafe sha256 evidence hash",
    );
    assert_eq!(parsed, livesafe_sha256_hash());

    let mut input = valid_input();
    input.evidence.sha256_hash = parsed;
    let output = must_ok(issue(input), "issue ceremony output");

    assert_eq!(output.evidence_hash, livesafe_sha256_hash());
    assert_eq!(
        output.authorization_request.evidence_hash,
        livesafe_sha256_hash()
    );
}

#[test]
fn ceremony_rejects_bare_non_sha256_or_malformed_evidence_hash_inputs() {
    for rejected in [
        "00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100",
        "blake3:00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100",
        "sha256:00112233445566778899AABBCCDDEEFFffeeddccbbaa99887766554433221100",
        "SHA256:00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100",
        "sha512:00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100",
        "sha256:abc",
    ] {
        let error = must_err(
            parse_livesafe_public_output_evidence_sha256(rejected),
            "invalid evidence hash must fail",
        );
        assert!(
            error.to_string().contains("sha256:<64 lowercase hex>"),
            "unexpected error for {rejected}: {error}"
        );
    }
}

#[test]
fn ceremony_source_does_not_recompute_or_name_blake3_evidence_hashing() {
    let source = include_str!("../src/livesafe_public_output_ceremony.rs");

    assert!(!source.contains("Hash256::digest(&evidence.material)"));
    assert!(!source.contains("BLAKE3"));
    assert!(!source.contains("blake3"));
}

#[test]
fn ceremony_uses_explicit_not_before_and_expiry_without_system_time() {
    let input = valid_input();
    let first = must_ok(issue(input.clone()), "first issue");
    let second = must_ok(issue(input.clone()), "second issue");

    assert_eq!(first.credential_id, second.credential_id);
    assert_eq!(first.credential.created_at, input.not_before);
    assert_eq!(first.credential.expires_at, Some(input.expires_at));
    assert_eq!(
        first.credential.constraints.allowed_time_window,
        Some(exo_avc::TimeWindow {
            not_before: input.not_before,
            not_after: input.expires_at,
        })
    );

    let source = include_str!("../src/livesafe_public_output_ceremony.rs");
    assert!(!source.contains("SystemTime"));
    assert!(!source.contains("Instant::now"));
}

#[test]
fn ceremony_output_redacts_signing_material_and_bearer_tokens() {
    let output = must_ok(issue(valid_input()), "issue ceremony output");
    let rendered = format!("{output:?}");
    let raw_private_seed_hex = "42".repeat(32);
    let raw_evidence = evidence_bytes();
    let raw_evidence_text = must_ok(
        std::str::from_utf8(raw_evidence.as_slice()),
        "evidence fixture is utf8",
    );

    assert!(!rendered.contains(&raw_private_seed_hex));
    assert!(!rendered.contains(raw_evidence_text));
    assert!(!rendered.contains("EXOCHAIN_ADMIN_BEARER_TOKEN"));
    assert!(!rendered.contains("Bearer "));
    assert!(!rendered.to_ascii_lowercase().contains("private_key"));
    assert!(!rendered.to_ascii_lowercase().contains("secret_key"));
}

#[test]
fn ceremony_output_is_signed_and_accepted_by_existing_avc_validation_path() {
    let input = valid_input();
    let output = must_ok(issue(input.clone()), "issue ceremony output");
    let credential = output.issue_request.credential.clone();
    assert_eq!(credential.schema_version, AVC_SCHEMA_VERSION);
    assert_eq!(
        must_ok(credential.id(), "credential id"),
        output.credential_id
    );
    assert_eq!(
        output.authorization_request.credential_id,
        output.credential_id
    );
    assert_eq!(
        output.authorization_request.evidence_hash,
        input.evidence.sha256_hash
    );

    let mut registry = InMemoryAvcRegistry::new();
    registry.put_public_key(input.issuer_did.clone(), issuer_keypair().public);
    registry.put_issuer_permission_grant(input.issuer_did, vec![Permission::Read]);
    let registered_id = must_ok(
        registry.put_credential(credential.clone()),
        "node issue path accepts credential",
    );
    assert_eq!(registered_id, output.credential_id);
    assert!(registry.get_credential(&output.credential_id).is_some());

    let action = livesafe_public_adapter_output_authorization_action_request(
        &credential,
        &output.authorization_request.subject,
        &output.authorization_request.audience,
        output.authorization_request.evidence_hash,
        output.authorization_request.idempotency_key_hash,
        &output.authorization_request.expires_at,
    );
    let action = must_ok(action, "build public-output action");
    let validation = must_ok(
        validate_avc(
            &exo_avc::AvcValidationRequest {
                credential,
                action: Some(action),
                now: input.not_before,
            },
            &registry,
        ),
        "validate credential",
    );
    assert_eq!(validation.decision, AvcDecision::Allow);
}

#[test]
fn public_output_authorization_rejects_evidence_hash_not_bound_to_ceremony_credential() {
    let input = valid_input();
    let output = must_ok(issue(input.clone()), "issue ceremony output");
    let registry = registry_for_issued_ceremony(&output, input.issuer_did);
    let forged_evidence_hash = Hash256::from_bytes([0x77; 32]);
    assert_ne!(
        forged_evidence_hash,
        output.authorization_request.evidence_hash
    );

    let error = must_err(
        mint_livesafe_public_adapter_output_authorization_proof(
            authorization_draft_for(&output, forged_evidence_hash),
            &registry,
            |payload| proof_signer_keypair().sign(payload),
        ),
        "draft evidence hash not bound into ceremony credential must fail",
    );

    assert!(
        error.to_string().contains("evidence hash"),
        "unexpected error: {error}"
    );
}

#[test]
fn public_output_authorization_rejects_livesafe_service_credential_with_wrong_subject_did() {
    let input = valid_input();
    let mut output = must_ok(issue(input.clone()), "issue ceremony output");
    let original = output.credential.clone();
    let wrong_subject_did = did("did:exo:livesafe-public-adapter-shadow");
    assert_ne!(wrong_subject_did, original.subject_did);
    let credential = must_ok(
        exo_avc::issue_avc(
            exo_avc::AvcDraft {
                schema_version: original.schema_version,
                issuer_did: original.issuer_did,
                principal_did: original.principal_did,
                subject_did: wrong_subject_did,
                holder_did: original.holder_did,
                subject_kind: original.subject_kind,
                created_at: original.created_at,
                expires_at: original.expires_at,
                delegated_intent: original.delegated_intent,
                authority_scope: original.authority_scope,
                constraints: original.constraints,
                authority_chain: original.authority_chain,
                consent_refs: original.consent_refs,
                policy_refs: original.policy_refs,
                parent_avc_id: original.parent_avc_id,
            },
            |payload| issuer_keypair().sign(payload),
        ),
        "issue signed credential with wrong subject DID",
    );
    output.credential = credential;
    output.credential_id = must_ok(output.credential.id(), "wrong subject credential id");
    output.authorization_request.credential_id = output.credential_id;
    let registry = registry_for_issued_ceremony(&output, input.issuer_did);

    let error = must_err(
        mint_livesafe_public_adapter_output_authorization_proof(
            authorization_draft_for(&output, output.authorization_request.evidence_hash),
            &registry,
            |payload| proof_signer_keypair().sign(payload),
        ),
        "credential with wrong subject DID must fail",
    );

    assert!(
        error.to_string().contains("credential subject DID"),
        "unexpected error: {error}"
    );
}

#[test]
fn ceremony_authorization_request_serializes_env_ready_sha256_values() {
    let output = must_ok(issue(valid_input()), "issue ceremony output");
    let mut bytes = Vec::new();
    must_ok(
        ciborium::ser::into_writer(&output, &mut bytes),
        "serialize ceremony output",
    );
    let value: ciborium::value::Value = must_ok(
        ciborium::de::from_reader(bytes.as_slice()),
        "decode ceremony output",
    );
    let authorization_request = must_some(
        cbor_map_field(&value, "authorization_request"),
        "authorization_request object",
    );
    let credential_id = must_some(
        cbor_map_field(authorization_request, "credential_id")
            .and_then(ciborium::value::Value::as_text),
        "credential_id string",
    );
    let evidence_hash = must_some(
        cbor_map_field(authorization_request, "evidence_hash")
            .and_then(ciborium::value::Value::as_text),
        "evidence_hash string",
    );

    assert_eq!(
        credential_id,
        format!("sha256:{}", output.authorization_request.credential_id)
    );
    assert_eq!(evidence_hash, livesafe_sha256_value());
}

#[test]
fn ceremony_docs_instruct_livesafe_env_vars_from_prefixed_authorization_request_values() {
    let docs = include_str!("../../../docs/avc/livesafe-public-output-ceremony.md");

    assert!(docs.contains(
        "export EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_CREDENTIAL_ID=\"$(jq -r '.authorization_request.credential_id'"
    ));
    assert!(docs.contains(
        "export EXOCHAIN_PUBLIC_ADAPTER_OUTPUT_EVIDENCE_HASH=\"$(jq -r '.authorization_request.evidence_hash'"
    ));
    assert!(docs.contains("sha256:<64 lowercase hex>"));
    assert!(docs.contains("not raw `Hash256` JSON arrays or plain bytes"));
}

#[test]
fn ceremony_rejects_public_output_claim_widening_even_with_valid_signature_material() {
    for forbidden in [
        "exochain.constitutional_trust.v1",
        "livesafe.medical_record_read.v1",
        "livesafe.legal_custody.v1",
        "livesafe.consent_override.v1",
        "livesafe.emergency_access.v1",
    ] {
        let mut input = valid_input();
        input.allowed_claim_names = vec![
            LIVESAFE_PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_DOMAIN.into(),
            forbidden.into(),
        ];

        let error = must_err(issue(input), "widened claim must fail");

        assert!(
            error.to_string().contains("forbidden claim")
                || error.to_string().contains("allowed claim")
        );
    }
}
