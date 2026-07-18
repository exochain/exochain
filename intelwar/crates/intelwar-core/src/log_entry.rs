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

//! Living Log entry + receipt types (canonical CBOR).

use exo_core::{
    Did, Hash256, Timestamp,
    hash::hash_structured,
};
use serde::{Deserialize, Serialize};

use crate::error::{IntelwarError, Result};

/// Domain separator for entry body hashing.
pub const ENTRY_DOMAIN: &str = "intelwar.living-log.entry.v1";
/// Domain separator for receipt hashing.
pub const RECEIPT_DOMAIN: &str = "intelwar.living-log.receipt.v1";

/// Kind of Living Log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Observation,
    Analysis,
    DebateNote,
    CrossCheck,
    Doctrine,
    ConstitutionalAmendment,
    HumanOverride,
    AgentAttestation,
    DevelopmentDecision,
    ReceiptAnchor,
}

/// Multi-intelligence voice taxonomy (mirrors gatekeeper VoiceKind wire names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceKind {
    Human,
    Synthetic,
    System,
}

/// Independence claim for human voices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependenceClaim {
    Independent,
    Coordinated,
}

/// Review order for human voices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewOrder {
    FirstOrder,
    Derivative,
}

/// Explicit AI/agent attestation (IW-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAttestation {
    pub model_id: String,
    pub session_id: String,
    pub tool: String,
    pub attestation_signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avc_receipt_hash: Option<Vec<u8>>,
}

/// Hashable LogEntry body (without `content_hash`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntryBody {
    pub schema_version: u16,
    pub entry_id: String,
    pub entry_kind: EntryKind,
    pub author_did: Did,
    pub hlc_timestamp: Timestamp,
    pub parent_hashes: Vec<Hash256>,
    pub summary: String,
    pub payload: Vec<u8>,
    pub voice_kind: VoiceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub independence: Option<IndependenceClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_order: Option<ReviewOrder>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_attestation: Option<AgentAttestation>,
    pub requires_crosscheck: bool,
    pub crosscheck_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debate_ref: Option<String>,
    pub consent_scope: String,
    pub intelwar_invariants: Vec<String>,
    pub exochain_invariants: Vec<String>,
}

/// Fully addressed LogEntry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    #[serde(flatten)]
    pub body: LogEntryBody,
    pub content_hash: Hash256,
}

impl std::ops::Deref for LogEntry {
    type Target = LogEntryBody;
    fn deref(&self) -> &Self::Target {
        &self.body
    }
}

impl LogEntryBody {
    /// Compute content hash over domain-separated canonical CBOR.
    pub fn compute_content_hash(&self) -> Result<Hash256> {
        #[derive(Serialize)]
        struct HashPayload<'a> {
            domain: &'static str,
            body: &'a LogEntryBody,
        }
        hash_structured(&HashPayload {
            domain: ENTRY_DOMAIN,
            body: self,
        })
        .map_err(|e| IntelwarError::Serialization {
            reason: e.to_string(),
        })
    }

    /// Seal body into a LogEntry with content hash.
    pub fn seal(self) -> Result<LogEntry> {
        let content_hash = self.compute_content_hash()?;
        Ok(LogEntry {
            body: self,
            content_hash,
        })
    }
}

impl LogEntry {
    /// Verify content_hash matches body.
    pub fn verify_content_hash(&self) -> Result<()> {
        let computed = self.body.compute_content_hash()?;
        if computed != self.content_hash {
            return Err(IntelwarError::ContentHashMismatch {
                expected: encode_hash_bytes(self.content_hash.as_bytes()),
                computed: encode_hash_bytes(computed.as_bytes()),
            });
        }
        Ok(())
    }

    /// Canonical CBOR bytes for DAG payload.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| IntelwarError::Serialization {
            reason: e.to_string(),
        })?;
        Ok(buf)
    }
}

/// Chaining Living Log receipt (IW-2 / IW-8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivingLogReceipt {
    pub schema_version: u16,
    pub receipt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_receipt_hash: Option<Hash256>,
    pub entry_content_hash: Hash256,
    pub dag_node_hash: Hash256,
    pub action_hash: Hash256,
    pub actor_did: Did,
    pub voice_kind: VoiceKind,
    pub kernel_verdict: String,
    pub intelwar_verdict: String,
    pub signature: Vec<u8>,
}

impl LivingLogReceipt {
    /// Hash of receipt fields excluding signature (for chaining).
    pub fn unsigned_hash(&self) -> Result<Hash256> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            domain: &'static str,
            schema_version: u16,
            receipt_id: &'a str,
            previous_receipt_hash: Option<&'a Hash256>,
            entry_content_hash: &'a Hash256,
            dag_node_hash: &'a Hash256,
            action_hash: &'a Hash256,
            actor_did: &'a Did,
            voice_kind: VoiceKind,
            kernel_verdict: &'a str,
            intelwar_verdict: &'a str,
        }
        hash_structured(&Unsigned {
            domain: RECEIPT_DOMAIN,
            schema_version: self.schema_version,
            receipt_id: &self.receipt_id,
            previous_receipt_hash: self.previous_receipt_hash.as_ref(),
            entry_content_hash: &self.entry_content_hash,
            dag_node_hash: &self.dag_node_hash,
            action_hash: &self.action_hash,
            actor_did: &self.actor_did,
            voice_kind: self.voice_kind,
            kernel_verdict: &self.kernel_verdict,
            intelwar_verdict: &self.intelwar_verdict,
        })
        .map_err(|e| IntelwarError::Serialization {
            reason: e.to_string(),
        })
    }
}

fn encode_hash_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
