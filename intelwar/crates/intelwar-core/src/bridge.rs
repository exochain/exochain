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

//! File-backed Kernel bridge for adjacent `log-api` (PM-001).
//!
//! Each invoke runs a full CGR + IntelWar append into an ephemeral single-node
//! DAG (persistence of a multi-node DAG is PM-002). Receipt hashes still chain
//! across invokes via `previous_receipt_hash` in the state file.

use std::fs;
use std::path::Path;

use exo_core::{Did, Hash256, SecretKey, Timestamp, crypto};
use exo_dag::dag::{Dag, DeterministicDagClock};
use exo_gatekeeper::types::{
    AuthorityChain, BailmentState, ConsentRecord, TrustedAuthorityKeys, TrustedProvenanceKeys,
};
use serde::{Deserialize, Serialize};

use crate::append_flow::{
    AppendRequest, append_log_entry, development_decision_body, judicial_role, signed_authority_link,
};
use crate::consent_flow::LOG_APPEND_PERMISSION;
use crate::error::{IntelwarError, Result};
use crate::log_entry::{AgentAttestation, EntryKind, IndependenceClaim, ReviewOrder, VoiceKind};

const ACTOR_DID: &str = "did:exo:intelwar-actor";
const ROOT_DID: &str = "did:exo:intelwar-root";
const BAILOR_DID: &str = "did:exo:intelwar-bailor";

/// Request body accepted by the bridge CLI / Node spawn path.
#[derive(Debug, Clone, Deserialize)]
pub struct BridgeAppendRequest {
    pub summary: String,
    #[serde(default)]
    pub entry_id: Option<String>,
    #[serde(default)]
    pub entry_kind: Option<String>,
    #[serde(default)]
    pub voice_kind: Option<String>,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub tool: Option<String>,
}

/// Successful Kernel-adjudicated bridge response (JSON).
#[derive(Debug, Clone, Serialize)]
pub struct BridgeAppendResponse {
    pub ok: bool,
    pub simulated: bool,
    pub kernel_adjudicated: bool,
    pub dag_scope: &'static str,
    pub entry_id: String,
    pub summary: String,
    pub author_did: String,
    pub voice_kind: String,
    pub content_hash: String,
    pub dag_node_hash: String,
    pub receipt_hash: String,
    pub kernel_verdict: String,
    pub intelwar_verdict: String,
    pub previous_receipt_hash: Option<String>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BridgeState {
    actor_sk_hex: String,
    root_sk_hex: String,
    previous_receipt_hash_hex: Option<String>,
    physical_ms_base: u64,
    append_count: u64,
}

impl BridgeState {
    fn fresh() -> Self {
        let (_apk, ask) = crypto::generate_keypair();
        let (_rpk, rsk) = crypto::generate_keypair();
        Self {
            actor_sk_hex: bytes_to_hex(ask.as_bytes()),
            root_sk_hex: bytes_to_hex(rsk.as_bytes()),
            previous_receipt_hash_hex: None,
            physical_ms_base: 1_752_854_400_000,
            append_count: 0,
        }
    }
}

/// Load or initialize bridge state under `state_dir`.
fn load_or_init_state(state_dir: &Path) -> Result<BridgeState> {
    fs::create_dir_all(state_dir).map_err(|e| IntelwarError::Validation {
        reason: format!("create state dir: {e}"),
    })?;
    let path = state_dir.join("bridge_state.json");
    if path.exists() {
        let raw = fs::read_to_string(&path).map_err(|e| IntelwarError::Validation {
            reason: format!("read bridge state: {e}"),
        })?;
        serde_json::from_str(&raw).map_err(|e| IntelwarError::Validation {
            reason: format!("parse bridge state: {e}"),
        })
    } else {
        let state = BridgeState::fresh();
        save_state(state_dir, &state)?;
        Ok(state)
    }
}

fn save_state(state_dir: &Path, state: &BridgeState) -> Result<()> {
    let path = state_dir.join("bridge_state.json");
    let raw = serde_json::to_string_pretty(state).map_err(|e| IntelwarError::Serialization {
        reason: e.to_string(),
    })?;
    fs::write(&path, raw).map_err(|e| IntelwarError::Validation {
        reason: format!("write bridge state: {e}"),
    })
}

/// Run a Kernel-gated append for the adjacent bridge.
pub fn bridge_append(state_dir: &Path, req: BridgeAppendRequest) -> Result<BridgeAppendResponse> {
    if req.summary.trim().is_empty() {
        return Err(IntelwarError::Validation {
            reason: "summary must be non-empty (IW-7 StrategicUtility)".into(),
        });
    }

    let mut state = load_or_init_state(state_dir)?;
    let actor_sk = secret_from_hex(&state.actor_sk_hex)?;
    let root_sk = secret_from_hex(&state.root_sk_hex)?;
    let actor_pk = crypto::KeyPair::from_secret_bytes(*actor_sk.as_bytes())
        .map_err(|e| IntelwarError::Validation {
            reason: e.to_string(),
        })?
        .public;
    let root_pk = crypto::KeyPair::from_secret_bytes(*root_sk.as_bytes())
        .map_err(|e| IntelwarError::Validation {
            reason: e.to_string(),
        })?
        .public;

    let actor = Did::new(ACTOR_DID).map_err(|e| IntelwarError::Validation {
        reason: e.to_string(),
    })?;
    let root = Did::new(ROOT_DID).map_err(|e| IntelwarError::Validation {
        reason: e.to_string(),
    })?;
    let bailor = Did::new(BAILOR_DID).map_err(|e| IntelwarError::Validation {
        reason: e.to_string(),
    })?;

    let link = signed_authority_link(&root, &actor, &root_sk)?;
    let mut trusted_authority_keys = TrustedAuthorityKeys::default();
    trusted_authority_keys.insert(root, vec![root_pk.as_bytes().to_vec()]);
    let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
    trusted_provenance_keys.insert(actor.clone(), vec![actor_pk.as_bytes().to_vec()]);

    let voice = parse_voice(req.voice_kind.as_deref().unwrap_or("human"))?;
    let entry_id = req
        .entry_id
        .clone()
        .unwrap_or_else(|| format!("bridge-{}", state.append_count + 1));
    let physical_ms = state
        .physical_ms_base
        .saturating_add(state.append_count.saturating_mul(1_000));
    let payload = req
        .payload
        .clone()
        .unwrap_or_else(|| {
            r#"{"source":"intelwar-log-api","bridge":"pm-001"}"#.into()
        })
        .into_bytes();

    let mut body = development_decision_body(
        entry_id.clone(),
        actor.clone(),
        Timestamp::new(physical_ms, 0),
        req.summary.trim(),
        payload,
        Vec::new(),
    );
    if let Some(kind) = req.entry_kind.as_deref() {
        body.entry_kind = parse_entry_kind(kind)?;
    }
    body.voice_kind = voice;
    match voice {
        VoiceKind::Human => {
            body.independence = Some(IndependenceClaim::Independent);
            body.review_order = Some(ReviewOrder::FirstOrder);
            body.agent_attestation = None;
        }
        VoiceKind::Synthetic => {
            body.independence = None;
            body.review_order = None;
            body.agent_attestation = Some(AgentAttestation {
                model_id: req.model_id.unwrap_or_else(|| "unspecified".into()),
                session_id: req.session_id.unwrap_or_else(|| "unspecified".into()),
                tool: req.tool.unwrap_or_else(|| "intelwar-log-api".into()),
                attestation_signature: b"bridge-attestation-placeholder".to_vec(),
                avc_receipt_hash: None,
            });
        }
        VoiceKind::System => {
            body.independence = None;
            body.review_order = None;
            body.agent_attestation = None;
        }
    }

    let previous = match &state.previous_receipt_hash_hex {
        Some(hex) => Some(hash_from_hex(hex)?),
        None => None,
    };

    let request = AppendRequest {
        entry_body: body,
        actor_secret_key: actor_sk,
        actor_roles: vec![judicial_role()],
        bailment_state: BailmentState::Active {
            bailor: bailor.clone(),
            bailee: actor.clone(),
            scope: LOG_APPEND_PERMISSION.into(),
        },
        consent_records: vec![ConsentRecord {
            subject: bailor,
            granted_to: actor.clone(),
            scope: LOG_APPEND_PERMISSION.into(),
            active: true,
        }],
        authority_chain: AuthorityChain { links: vec![link] },
        trusted_authority_keys,
        trusted_provenance_keys,
        human_override_preserved: true,
        previous_receipt_hash: previous,
        crosschecks: Vec::new(),
        debate: None,
        provenance_timestamp: format!("hlc:{physical_ms}:0"),
    };

    let mut dag = Dag::new();
    let mut clock = DeterministicDagClock::with_time(physical_ms);
    let receipt = append_log_entry(&mut dag, &mut clock, request)?;

    state.append_count = state.append_count.saturating_add(1);
    state.previous_receipt_hash_hex = Some(bytes_to_hex(receipt.living_receipt_hash.as_bytes()));
    save_state(state_dir, &state)?;

    Ok(BridgeAppendResponse {
        ok: true,
        simulated: false,
        kernel_adjudicated: true,
        dag_scope: "ephemeral-single-node",
        entry_id: receipt.entry.entry_id.clone(),
        summary: receipt.entry.summary.clone(),
        author_did: receipt.entry.author_did.to_string(),
        voice_kind: voice_label(receipt.entry.voice_kind).into(),
        content_hash: bytes_to_hex(receipt.entry.content_hash.as_bytes()),
        dag_node_hash: bytes_to_hex(receipt.dag_node_hash.as_bytes()),
        receipt_hash: bytes_to_hex(receipt.living_receipt_hash.as_bytes()),
        kernel_verdict: receipt.living_receipt.kernel_verdict.clone(),
        intelwar_verdict: receipt.living_receipt.intelwar_verdict.clone(),
        previous_receipt_hash: previous.map(|h| bytes_to_hex(h.as_bytes())),
        note: "Kernel-adjudicated via intelwar-core bridge. Multi-node DAG persistence is PM-002."
            .into(),
    })
}

fn voice_label(v: VoiceKind) -> &'static str {
    match v {
        VoiceKind::Human => "human",
        VoiceKind::Synthetic => "synthetic",
        VoiceKind::System => "system",
    }
}

fn parse_voice(raw: &str) -> Result<VoiceKind> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "human" => Ok(VoiceKind::Human),
        "synthetic" => Ok(VoiceKind::Synthetic),
        "system" => Ok(VoiceKind::System),
        other => Err(IntelwarError::Validation {
            reason: format!("unsupported voice_kind: {other}"),
        }),
    }
}

fn parse_entry_kind(raw: &str) -> Result<EntryKind> {
    match raw.trim() {
        "Observation" => Ok(EntryKind::Observation),
        "Analysis" => Ok(EntryKind::Analysis),
        "DebateNote" => Ok(EntryKind::DebateNote),
        "CrossCheck" => Ok(EntryKind::CrossCheck),
        "Doctrine" => Ok(EntryKind::Doctrine),
        "ConstitutionalAmendment" => Ok(EntryKind::ConstitutionalAmendment),
        "HumanOverride" => Ok(EntryKind::HumanOverride),
        "AgentAttestation" => Ok(EntryKind::AgentAttestation),
        "DevelopmentDecision" => Ok(EntryKind::DevelopmentDecision),
        "ReceiptAnchor" => Ok(EntryKind::ReceiptAnchor),
        other => Err(IntelwarError::Validation {
            reason: format!("unsupported entry_kind: {other}"),
        }),
    }
}

fn secret_from_hex(hex: &str) -> Result<SecretKey> {
    let bytes = hex_to_32(hex)?;
    Ok(SecretKey::from_bytes(bytes))
}

fn hash_from_hex(hex: &str) -> Result<Hash256> {
    Ok(Hash256::from_bytes(hex_to_32(hex)?))
}

fn hex_to_32(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        return Err(IntelwarError::Validation {
            reason: format!("expected 64 hex chars, got {}", hex.len()),
        });
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|e| IntelwarError::Validation {
            reason: e.to_string(),
        })?;
        out[i] = u8::from_str_radix(s, 16).map_err(|e| IntelwarError::Validation {
            reason: e.to_string(),
        })?;
    }
    Ok(out)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn bridge_append_chains_receipts() {
        let dir = env::temp_dir().join(format!(
            "intelwar-bridge-{}",
            bytes_to_hex(&crypto::generate_keypair().0.as_bytes()[..8])
        ));
        let _ = fs::remove_dir_all(&dir);
        let r1 = bridge_append(
            &dir,
            BridgeAppendRequest {
                summary: "first kernel bridge append".into(),
                entry_id: None,
                entry_kind: Some("Observation".into()),
                voice_kind: Some("human".into()),
                payload: None,
                model_id: None,
                session_id: None,
                tool: None,
            },
        )
        .expect("r1");
        assert!(!r1.simulated);
        assert!(r1.kernel_adjudicated);
        assert!(r1.previous_receipt_hash.is_none());

        let r2 = bridge_append(
            &dir,
            BridgeAppendRequest {
                summary: "second kernel bridge append".into(),
                entry_id: None,
                entry_kind: Some("Observation".into()),
                voice_kind: Some("human".into()),
                payload: None,
                model_id: None,
                session_id: None,
                tool: None,
            },
        )
        .expect("r2");
        assert_eq!(
            r2.previous_receipt_hash.as_deref(),
            Some(r1.receipt_hash.as_str())
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
