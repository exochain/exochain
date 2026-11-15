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

//! Regenerate the committed offline verification fixture.
//!
//! ```text
//! cargo run -p exochain-verify --example generate_offline_fixture -- <out-dir>
//! ```
//!
//! Requires the `openssl` CLI (3.x). It creates a throwaway test CA and RFC
//! 3161 timestamp authority in a temporary directory, has `openssl ts`
//! stamp the receipt's real timestamp request, and writes only public
//! material (certificates, token, receipt bundle, trust inputs). No private
//! key is written to `<out-dir>`. Every run produces new keys and times, so
//! regenerate only when the bundle format changes.

// Developer-only fixture generator: fixed fixture DIDs and the system clock
// cannot fail in practice, and a panic here only aborts regeneration.
#![allow(clippy::expect_used)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use exo_authority::permission::Permission;
use exo_avc::{
    AVC_SCHEMA_VERSION, AuthorityScope, AutonomyLevel, AvcActionDescriptor, AvcActionRequest,
    AvcConstraints, AvcDraft, AvcHumanApproval, AvcReceiptEvidenceSubject,
    AvcReceiptExternalTimestampProof, AvcReceiptRfc3161TimestampProof,
    AvcReceiptRfc3161TrustAnchorKind, AvcReceiptTimestampProvenance, AvcRegistryWrite,
    AvcSubjectAttestation, AvcSubjectKind, AvcTrustReceipt, AvcTrustReceiptEvidence,
    AvcValidationRequest, DataClass, DelegatedIntent, InMemoryAvcRegistry,
    avc_action_commitment_hash, avc_action_signature_payload,
    create_trust_receipt_with_subject_attestation, human_approval_signature_payload, issue_avc,
    validate_avc,
};
use exo_core::{Did, Hash256, Signature, Timestamp, crypto::KeyPair};
use exo_dag::mmr;
use exo_verify::{
    KEY_BUNDLE_FORMAT_V1, KeyBundle, KeyBundleEntry, KeyRole, RECEIPT_BUNDLE_FORMAT_V1,
    ReceiptBundle, ReceiptInclusionProof, ReceiptTreeHead, TrustInputs, TsaTrust,
    rfc3161::{
        Rfc3161TrustAnchorKind, Rfc3161TrustAnchors, build_timestamp_request,
        verify_timestamp_response_with_trust_anchors,
    },
    verify_receipt_bundle,
};

/// Example-arc OID (2.999) used as the test TSA policy.
const TEST_TSA_POLICY_OID: &str = "2.999.897.1";
/// 2026-01-01T00:00:00Z.
const KEY_VALID_FROM_MS: u64 = 1_767_225_600_000;
/// 2036-01-01T00:00:00Z.
const KEY_VALID_UNTIL_MS: u64 = 2_082_758_400_000;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn did(label: &str) -> Did {
    Did::new(&format!("did:exo:{label}")).expect("fixture DID")
}

fn ts(ms: u64) -> Timestamp {
    Timestamp::new(ms, 0)
}

fn now_ms() -> u64 {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis();
    u64::try_from(ms).expect("time fits u64")
}

fn openssl(dir: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .status()?;
    if !status.success() {
        return Err(format!("openssl {args:?} failed with {status}").into());
    }
    Ok(())
}

fn spki_der_hex(dir: &Path, cert: &str) -> Result<String> {
    let pem = Command::new("openssl")
        .current_dir(dir)
        .args(["x509", "-in", cert, "-noout", "-pubkey"])
        .output()?;
    if !pem.status.success() {
        return Err("openssl x509 -pubkey failed".into());
    }
    let pubkey_pem = dir.join(format!("{cert}.pub.pem"));
    fs::write(&pubkey_pem, &pem.stdout)?;
    let der = Command::new("openssl")
        .current_dir(dir)
        .args(["pkey", "-pubin", "-in"])
        .arg(&pubkey_pem)
        .args(["-outform", "DER"])
        .output()?;
    if !der.status.success() {
        return Err("openssl pkey -outform DER failed".into());
    }
    Ok(hex::encode(der.stdout))
}

/// Throwaway test PKI: a root CA and a TSA signing certificate.
fn create_test_tsa(dir: &Path) -> Result<()> {
    openssl(
        dir,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-days",
            "36500",
            "-subj",
            "/CN=EXOCHAIN Test TSA Root CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    )?;
    openssl(
        dir,
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-keyout",
            "tsa.key",
            "-out",
            "tsa.csr",
            "-subj",
            "/CN=EXOCHAIN Test Timestamp Authority",
        ],
    )?;
    fs::write(
        dir.join("tsa-ext.cnf"),
        "basicConstraints=critical,CA:FALSE\n\
         keyUsage=critical,digitalSignature,nonRepudiation\n\
         extendedKeyUsage=critical,timeStamping\n\
         subjectKeyIdentifier=hash\n\
         authorityKeyIdentifier=keyid\n",
    )?;
    openssl(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            "tsa.csr",
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-set_serial",
            "2",
            "-days",
            "36500",
            "-sha256",
            "-extfile",
            "tsa-ext.cnf",
            "-out",
            "tsa.crt",
        ],
    )?;
    fs::write(dir.join("tsaserial"), "01\n")?;
    fs::write(
        dir.join("ts.cnf"),
        format!(
            "[ tsa ]\n\
             default_tsa = test_tsa\n\
             [ test_tsa ]\n\
             dir = .\n\
             serial = ./tsaserial\n\
             crypto_device = builtin\n\
             signer_cert = ./tsa.crt\n\
             certs = ./ca.crt\n\
             signer_key = ./tsa.key\n\
             signer_digest = sha256\n\
             default_policy = {TEST_TSA_POLICY_OID}\n\
             digests = sha256\n\
             accuracy = secs:1\n\
             ordering = no\n\
             tsa_name = no\n\
             ess_cert_id_chain = no\n\
             ess_cert_id_alg = sha256\n"
        ),
    )?;
    Ok(())
}

struct Parties {
    issuer: KeyPair,
    agent: KeyPair,
    approver: KeyPair,
    validator: KeyPair,
}

fn credential_draft() -> AvcDraft {
    let mut constraints = AvcConstraints::permissive();
    constraints.human_approval_required = true;
    AvcDraft {
        schema_version: AVC_SCHEMA_VERSION,
        issuer_did: did("fixture-issuer"),
        principal_did: did("fixture-issuer"),
        subject_did: did("fixture-agent"),
        holder_did: None,
        subject_kind: AvcSubjectKind::AiAgent {
            model_id: "fixture-model".into(),
            agent_version: Some("1.0.0".into()),
        },
        created_at: ts(KEY_VALID_FROM_MS),
        expires_at: Some(ts(KEY_VALID_UNTIL_MS)),
        delegated_intent: DelegatedIntent {
            intent_id: Hash256::digest(b"fixture-intent"),
            purpose: "records research".into(),
            allowed_objectives: vec!["records".into()],
            prohibited_objectives: vec![],
            autonomy_level: AutonomyLevel::Draft,
            delegation_allowed: false,
        },
        authority_scope: AuthorityScope {
            permissions: vec![Permission::Read],
            tools: vec!["records.search".into()],
            data_classes: vec![DataClass::Internal],
            counterparties: vec![],
            jurisdictions: vec!["US".into()],
        },
        constraints,
        authority_chain: None,
        consent_refs: vec![],
        policy_refs: vec![],
        parent_avc_id: None,
    }
}

/// An action approved by a human and signed by the agent at `agent_now`.
fn signed_action(
    parties: &Parties,
    credential: &exo_avc::AutonomousVolitionCredential,
    action_byte: u8,
    agent_now: Timestamp,
) -> Result<(AvcActionRequest, AvcSubjectAttestation)> {
    let mut action = AvcActionRequest {
        action_id: Hash256::from_bytes([action_byte; 32]),
        actor_did: did("fixture-agent"),
        requested_permission: Permission::Read,
        tool: Some("records.search".into()),
        target_did: None,
        data_class: Some(DataClass::Internal),
        estimated_budget_minor_units: None,
        estimated_risk_bp: None,
        human_approval: None,
        requires_human_approval: true,
        action_name: Some("records:search@US".into()),
    };
    let mut approval = AvcHumanApproval {
        approver_did: did("fixture-approver"),
        approved_at: ts(agent_now.physical_ms - 60_000),
        expires_at: Some(ts(KEY_VALID_UNTIL_MS)),
        signature: Signature::empty(),
    };
    approval.signature = parties.approver.sign(&human_approval_signature_payload(
        credential, &action, &approval,
    )?);
    action.human_approval = Some(approval);
    let signed_bytes = avc_action_signature_payload(credential, &action, &agent_now)?;
    let attestation = AvcSubjectAttestation {
        subject_did: did("fixture-agent"),
        subject_public_key: parties.agent.public,
        subject_signature: parties.agent.sign(&signed_bytes),
        validation_now: agent_now,
        signed_bytes,
    };
    Ok((action, attestation))
}

fn chained_receipt(
    parties: &Parties,
    registry: &InMemoryAvcRegistry,
    credential: &exo_avc::AutonomousVolitionCredential,
    action_byte: u8,
    agent_now: Timestamp,
    created_at: Timestamp,
    previous: Option<Hash256>,
) -> Result<AvcTrustReceipt> {
    let (action, attestation) = signed_action(parties, credential, action_byte, agent_now)?;
    let validation = validate_avc(
        &AvcValidationRequest {
            credential: credential.clone(),
            action: Some(action.clone()),
            now: created_at,
        },
        registry,
    )?;
    Ok(create_trust_receipt_with_subject_attestation(
        &validation,
        Some(action.action_id),
        AvcTrustReceiptEvidence {
            action_commitment_hash: Some(avc_action_commitment_hash(
                credential, &action, &agent_now,
            )?),
            action_descriptor: Some(AvcActionDescriptor::from_action(&action)),
            previous_receipt_hash: previous,
            timestamp_provenance: Some(AvcReceiptTimestampProvenance::LocalHybridLogicalClock),
            ..AvcTrustReceiptEvidence::default()
        },
        attestation,
        did("fixture-validator"),
        created_at,
        |bytes| parties.validator.sign(bytes),
    )?)
}

fn main() -> Result<()> {
    let out_dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: generate_offline_fixture <out-dir>")?,
    );
    let work = std::env::temp_dir().join(format!("exo-verify-fixture-{}", std::process::id()));
    fs::create_dir_all(&work)?;
    create_test_tsa(&work)?;
    let ca_spki = spki_der_hex(&work, "ca.crt")?;

    let parties = Parties {
        issuer: KeyPair::generate(),
        agent: KeyPair::generate(),
        approver: KeyPair::generate(),
        validator: KeyPair::generate(),
    };
    let mut registry = InMemoryAvcRegistry::new();
    registry.put_public_key(did("fixture-issuer"), parties.issuer.public);
    registry.put_human_approval_key(did("fixture-approver"), parties.approver.public);
    let credential = issue_avc(credential_draft(), |bytes| parties.issuer.sign(bytes))?;

    // Two earlier receipts so the fixture receipt sits at position 2.
    let start = now_ms() - 600_000;
    let first = chained_receipt(
        &parties,
        &registry,
        &credential,
        0x01,
        ts(start),
        ts(start + 1_000),
        None,
    )?;
    let second = chained_receipt(
        &parties,
        &registry,
        &credential,
        0x02,
        ts(start + 2_000),
        ts(start + 3_000),
        Some(first.receipt_id),
    )?;

    // The fixture receipt: agent signs, then the TSA stamps the evidence.
    let agent_now = ts(now_ms() - 5_000);
    let (action, attestation) = signed_action(&parties, &credential, 0x03, agent_now)?;
    let action_commitment_hash = avc_action_commitment_hash(&credential, &action, &agent_now)?;
    let descriptor = AvcActionDescriptor::from_action(&action);
    let subject = AvcReceiptEvidenceSubject {
        credential_id: credential.id()?,
        action_id: action.action_id,
        action_commitment_hash,
        action_descriptor_hash: exo_avc::avc_action_descriptor_hash(&descriptor)?,
        previous_receipt_hash: Some(second.receipt_id),
    };
    let request = build_timestamp_request(&subject, TEST_TSA_POLICY_OID)?;
    fs::write(work.join("req.tsq"), &request.der)?;
    openssl(
        &work,
        &[
            "ts",
            "-reply",
            "-config",
            "ts.cnf",
            "-queryfile",
            "req.tsq",
            "-out",
            "resp.tsr",
        ],
    )?;
    let response = fs::read(work.join("resp.tsr"))?;
    let anchors = Rfc3161TrustAnchors::new(Vec::new(), vec![ca_spki.clone()])?;
    let verified = verify_timestamp_response_with_trust_anchors(
        &response,
        subject.hash()?,
        request.message_imprint_sha256,
        &request.nonce_hex,
        TEST_TSA_POLICY_OID,
        &anchors,
    )?;
    let issuer_subject = match verified.trust_anchor.kind {
        Rfc3161TrustAnchorKind::IssuingCaSpki => Some(verified.trust_anchor.subject.clone()),
        Rfc3161TrustAnchorKind::SignerSpki => None,
    };
    let external = AvcReceiptExternalTimestampProof::rfc3161(
        did("fixture-tsa"),
        verified.subject_hash,
        verified.issued_at,
        AvcReceiptRfc3161TimestampProof {
            message_imprint_sha256_hex: verified.message_imprint_sha256_hex,
            token_der_base64: verified.token_der_base64,
            policy_oid: verified.policy_oid,
            serial_number_hex: verified.serial_number_hex,
            nonce_hex: verified.nonce_hex,
            tsa_subject: verified.tsa_subject,
            tsa_public_key_spki_der_hex: verified.tsa_public_key_spki_der_hex,
            tsa_trust_anchor_kind: Some(AvcReceiptRfc3161TrustAnchorKind::IssuingCaSpki),
            tsa_trust_anchor_spki_der_hex: Some(verified.trust_anchor.spki_der_hex),
            tsa_issuer_subject: issuer_subject,
        },
    );
    let trusted_now = verified.issued_at;
    let validation = validate_avc(
        &AvcValidationRequest {
            credential: credential.clone(),
            action: Some(action.clone()),
            now: trusted_now,
        },
        &registry,
    )?;
    let receipt = create_trust_receipt_with_subject_attestation(
        &validation,
        Some(action.action_id),
        AvcTrustReceiptEvidence {
            action_commitment_hash: Some(action_commitment_hash),
            action_descriptor: Some(descriptor),
            previous_receipt_hash: Some(second.receipt_id),
            timestamp_provenance: Some(AvcReceiptTimestampProvenance::ExternalTimestampAuthority),
            external_timestamp_proof: Some(external),
            ..AvcTrustReceiptEvidence::default()
        },
        attestation,
        did("fixture-validator"),
        trusted_now,
        |bytes| parties.validator.sign(bytes),
    )?;

    // Two later receipts, then prove position 2 against the head at size 5.
    let later = trusted_now.physical_ms + 1_000;
    let fourth = chained_receipt(
        &parties,
        &registry,
        &credential,
        0x04,
        ts(later),
        ts(later + 1_000),
        Some(receipt.receipt_id),
    )?;
    let fifth = chained_receipt(
        &parties,
        &registry,
        &credential,
        0x05,
        ts(later + 2_000),
        ts(later + 3_000),
        Some(fourth.receipt_id),
    )?;
    let chain = [
        first.receipt_id,
        second.receipt_id,
        receipt.receipt_id,
        fourth.receipt_id,
        fifth.receipt_id,
    ];
    let mut tree = mmr::MerkleMountainRange::new();
    for id in chain {
        mmr::append(&mut tree, id);
    }
    let dag_proof = mmr::prove(&tree, 2)?;
    let mut tree_head = ReceiptTreeHead {
        validator_did: did("fixture-validator"),
        tree_size: 5,
        root: mmr::root(&tree),
        chain_head: fifth.receipt_id,
        signature: Signature::empty(),
    };
    tree_head.signature = parties.validator.sign(&tree_head.signing_payload()?);
    let bundle = ReceiptBundle {
        format: RECEIPT_BUNDLE_FORMAT_V1.into(),
        receipt,
        inclusion_proof: ReceiptInclusionProof {
            receipt_id: chain[2],
            leaf_index: 2,
            siblings: dag_proof.siblings,
            peak_index: u64::try_from(dag_proof.peak_index)?,
            peaks: dag_proof.peaks,
            tree_head,
        },
    };
    let entry = |label: &str, key: &KeyPair, role: KeyRole| KeyBundleEntry {
        did: did(label),
        public_key: key.public,
        roles: vec![role],
        valid_from: Some(ts(KEY_VALID_FROM_MS)),
        valid_until: Some(ts(KEY_VALID_UNTIL_MS)),
    };
    let trust = TrustInputs {
        key_bundle: KeyBundle {
            format: KEY_BUNDLE_FORMAT_V1.into(),
            version: 1,
            keys: vec![
                entry("fixture-agent", &parties.agent, KeyRole::Agent),
                entry("fixture-validator", &parties.validator, KeyRole::Validator),
            ],
        },
        tsa: TsaTrust {
            signer_spki_der_hex: Vec::new(),
            issuing_ca_spki_der_hex: vec![ca_spki],
        },
    };
    let verified = verify_receipt_bundle(&bundle, &trust)?;
    assert!(verified.human_approval_present);
    assert_ne!(verified.subject_signed_at, verified.trusted_time);

    fs::create_dir_all(out_dir.join("tsa"))?;
    let write_json = |name: &str, value: &dyn erased::Json| -> Result<()> {
        let mut text = value.to_pretty()?;
        text.push('\n');
        fs::write(out_dir.join(name), text)?;
        Ok(())
    };
    write_json("receipt-bundle.json", &bundle)?;
    write_json("trust-inputs.json", &trust)?;
    fs::copy(
        work.join("ca.crt"),
        out_dir.join("tsa/test-tsa-root-ca.crt.pem"),
    )?;
    fs::copy(
        work.join("tsa.crt"),
        out_dir.join("tsa/test-tsa-signer.crt.pem"),
    )?;
    // Convenience copies of the raw material embedded in the JSON bundle.
    let receipt = &bundle.receipt;
    fs::write(
        out_dir.join("validator-signed-bytes.cbor"),
        receipt
            .signed_payload
            .as_deref()
            .ok_or("missing signed bytes")?,
    )?;
    fs::write(
        out_dir.join("subject-signed-bytes.cbor"),
        &receipt
            .subject_attestation
            .as_ref()
            .ok_or("missing attestation")?
            .signed_bytes,
    )?;
    let token = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &receipt
            .external_timestamp_proof
            .as_ref()
            .and_then(|proof| proof.rfc3161.as_ref())
            .ok_or("missing token")?
            .token_der_base64,
    )?;
    fs::write(out_dir.join("rfc3161-timestamp-token.der"), token)?;
    fs::remove_dir_all(&work)?;
    println!("wrote offline fixture to {}", out_dir.display());
    Ok(())
}

/// Object-safe JSON pretty-printing for the two output types.
mod erased {
    pub trait Json {
        fn to_pretty(&self) -> serde_json::Result<String>;
    }
    impl<T: serde::Serialize> Json for T {
        fn to_pretty(&self) -> serde_json::Result<String> {
            serde_json::to_string_pretty(self)
        }
    }
}
