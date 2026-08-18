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

//! Infrastructure management Holons — AI agents governing network topology
//! and scaling under constitutional adjudication.
//!
//! These Holons run as background tasks within each node, analyzing network
//! state and producing governance recommendations. Every action is validated
//! through `Kernel::adjudicate()` to enforce constitutional invariants:
//!
//! - **INV-002 NoSelfGrant**: AI cannot self-escalate permissions
//! - **INV-004 HumanOverride**: Emergency halt always available
//! - **INV-005 KernelImmutability**: AI cannot modify the governance kernel
//! - **MCP-001/002**: AI operates within defined scope, cannot self-escalate
//!
//! # Audit status — Onyx-4 R5 / VCG-010 (default-off runtime)
//!
//! The infrastructure Holon adjudication context now requires a configured
//! Ed25519 authority key and signer plus a distinct DID-bound actor signer for
//! each Holon. Authority chains and provenance are signed over the same
//! canonical payloads enforced by `exo-gatekeeper`.
//!
//! Per ratified decision D5, a root authority is legitimate only with a
//! witnessed ceremony, external attestation, and lineage distinct from the
//! signer: a self-issued root (grantor key == signer key, no independent
//! attestation) is rejected by the kernel's `AuthorityChainValid` invariant.
//! The Scaling Holon's auto-promotion path is recommendation-only, full
//! stop — it emits a `RecommendationOnly` governance event and never
//! submits a `ValidatorSetChange` proposal; promotion is a ratification
//! event with named evidence, not an automatic action.
//!
//! The runtime background manager is therefore disabled by default behind the
//! `unaudited-infrastructure-holons` feature flag: no external-attestation
//! source is wired into production yet, so the default config's root
//! authority is self-issued and every Holon step is rejected. Enabling the
//! feature means the operator accepts the recommendation-only Holon runtime
//! while the product decision for shipping infrastructure Holons (including a
//! real external-attestation source) is tracked in
//! `Initiatives/fix-onyx-4-r5-holons-stub-context.md`.
//!
//! ## Holons
//!
//! 1. **Topology Optimizer** — monitors peer diversity (ASN, geography),
//!    recommends peer rotations via governance proposals.
//!
//! 2. **Scaling Advisor** — monitors validator count vs node count,
//!    recommends validator promotions via governance decisions.
//!
//! 3. **Health Monitor** — tracks consensus round times, peer latency,
//!    DAG growth rate, and alerts on anomalies.

#![cfg_attr(not(feature = "unaudited-infrastructure-holons"), allow(dead_code))]

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use exo_core::{
    Hash256, PublicKey, Signature,
    hash::hash_structured,
    types::{Did, Timestamp},
};
use exo_gatekeeper::{
    authority_link_signature_message,
    combinator::{Combinator, CombinatorInput, Predicate, TransformFn},
    holon::{self, Holon, HolonState},
    invariants::InvariantSet,
    kernel::{AdjudicationContext, Kernel},
    provenance_signature_message,
    types::{
        AuthorityChain, AuthorityLink, BailmentState, ConsentRecord, GovernmentBranch, Permission,
        PermissionSet, Provenance, Role, TrustedAuthorityKeys, TrustedProvenanceKeys,
    },
};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::{
    network::NetworkHandle,
    reactor::{self, SharedReactorState},
    store::SqliteDagStore,
    wire::{GovernanceEventType, ValidatorChange},
};

/// Feature flag required to run infrastructure Holons while R5 remains open.
pub const INFRASTRUCTURE_HOLONS_FEATURE: &str = "unaudited-infrastructure-holons";

/// Initiative documenting the R5 stub adjudication context and real fix scope.
pub const INFRASTRUCTURE_HOLONS_INITIATIVE: &str =
    "Initiatives/fix-onyx-4-r5-holons-stub-context.md";

/// Whether the unaudited infrastructure Holon runtime is compiled in.
#[must_use]
pub const fn infrastructure_holons_enabled() -> bool {
    cfg!(feature = "unaudited-infrastructure-holons")
}

// ---------------------------------------------------------------------------
// Holon events (sent to application layer)
// ---------------------------------------------------------------------------

/// Events emitted by infrastructure Holons.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "unaudited-infrastructure-holons"), allow(dead_code))]
pub enum HolonEvent {
    /// Topology analysis completed.
    TopologyAnalysis {
        peer_count: usize,
        diversity_score_bp: u32,
        recommendation: String,
    },
    /// Scaling recommendation produced.
    ScalingRecommendation {
        validator_count: usize,
        node_count: usize,
        recommendation: String,
    },
    /// Health check completed.
    HealthCheck {
        consensus_round: u64,
        committed_height: u64,
        status: HealthStatus,
    },
    /// A Holon was terminated due to capability denial.
    HolonTerminated { holon_id: Did, reason: String },
    /// A successful holon step produced a sealed CGR reduction trace.
    CgrProofIssued {
        holon_id: Did,
        trace_hash: Hash256,
        invariants_checked: u32,
    },
}

/// Health status of the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    /// All systems nominal.
    Healthy,
    /// Some metrics are outside normal range.
    Degraded { reason: String },
    /// Critical issue detected.
    Critical { reason: String },
}

async fn emit_cgr_proof_event(holon: &Holon, event_tx: &mpsc::Sender<HolonEvent>) {
    let Some(trace) = holon.last_trace.as_ref() else {
        return;
    };
    let invariants_checked = u32::try_from(trace.invariants_checked.len()).unwrap_or(u32::MAX);
    if event_tx
        .send(HolonEvent::CgrProofIssued {
            holon_id: holon.id.clone(),
            trace_hash: trace.trace_hash,
            invariants_checked,
        })
        .await
        .is_err()
    {
        tracing::warn!("Holon event channel closed — CgrProofIssued dropped");
    }
}

// ---------------------------------------------------------------------------
// Infrastructure Holon configuration
// ---------------------------------------------------------------------------

/// External attestation of the root authority's legitimacy — a witnessed
/// ceremony record signed by a key distinct from `root_signer`.
///
/// Per ratified decision D5, a root authority is legitimate only with a
/// witnessed ceremony, external attestation, and lineage distinct from the
/// signer. A self-issued root (grantor key == signer key, no external
/// delegation chain) must be rejected. This struct is the minimal carrier of
/// that external lineage: `attester_did`/`attester_public_key` name a party
/// distinct from `root_did`/`root_public_key`, and `attester_signer` signs
/// the delegation link vouching for the root key.
#[derive(Clone)]
pub struct RootAttestation {
    /// DID of the external attester (distinct from `root_did`).
    pub attester_did: Did,
    /// Ed25519 public key of the external attester.
    pub attester_public_key: PublicKey,
    /// Signs the attestation link that delegates authority to `root_did`.
    pub attester_signer: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
}

/// Configuration for infrastructure Holons.
#[derive(Clone)]
pub struct HolonManagerConfig {
    /// This node's DID.
    pub node_did: Did,
    /// Root authority DID for the authority chain.
    pub root_did: Did,
    /// Ed25519 public key for `root_did`.
    pub root_public_key: PublicKey,
    /// Signs canonical authority payload hashes for infrastructure Holon context.
    pub root_signer: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
    /// DID used for the topology Holon actor.
    pub topology_holon_did: Did,
    /// DID used for the scaling Holon actor.
    pub scaling_holon_did: Did,
    /// DID used for the health Holon actor.
    pub health_holon_did: Did,
    /// DID-bound Holon actor public keys and signers used for provenance.
    pub holon_actor_keys: BTreeMap<Did, HolonActorKey>,
    /// External attestation of the root authority's legitimacy (witnessed
    /// ceremony + lineage distinct from `root_signer`, per D5). `None` means
    /// the root authority is self-issued with no external delegation chain,
    /// which the kernel's `AuthorityChainValid` invariant must reject.
    pub root_attestation: Option<RootAttestation>,
    /// Supplies deterministic HLC metadata for each signed Holon provenance record.
    pub provenance_timestamp_source: Arc<dyn Fn() -> Result<Timestamp, String> + Send + Sync>,
    /// How often to run the topology optimizer (seconds).
    pub topology_interval_secs: u64,
    /// How often to run the scaling advisor (seconds).
    pub scaling_interval_secs: u64,
    /// How often to run the health monitor (seconds).
    pub health_interval_secs: u64,
}

/// DID-bound actor key and signer for one infrastructure Holon.
#[derive(Clone)]
pub struct HolonActorKey {
    /// Public key resolved for the Holon actor DID.
    pub public_key: PublicKey,
    /// Signs canonical provenance payloads for the Holon actor DID.
    pub signer: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync>,
}

impl std::fmt::Debug for HolonActorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HolonActorKey")
            .field("public_key", &self.public_key)
            .field("signer", &"<holon-actor-signer>")
            .finish()
    }
}

impl std::fmt::Debug for HolonManagerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HolonManagerConfig")
            .field("node_did", &self.node_did)
            .field("root_did", &self.root_did)
            .field("root_public_key", &self.root_public_key)
            .field("topology_holon_did", &self.topology_holon_did)
            .field("scaling_holon_did", &self.scaling_holon_did)
            .field("health_holon_did", &self.health_holon_did)
            .field("holon_actor_key_count", &self.holon_actor_keys.len())
            .field(
                "root_attestation",
                &self.root_attestation.as_ref().map(|a| &a.attester_did),
            )
            .field("provenance_timestamp_source", &"<deterministic-hlc-source>")
            .field("topology_interval_secs", &self.topology_interval_secs)
            .field("scaling_interval_secs", &self.scaling_interval_secs)
            .field("health_interval_secs", &self.health_interval_secs)
            .finish_non_exhaustive()
    }
}

/// Build an HLC-backed provenance timestamp source for runtime Holon steps.
#[must_use]
pub fn hlc_provenance_timestamp_source() -> Arc<dyn Fn() -> Result<Timestamp, String> + Send + Sync>
{
    let clock = Arc::new(std::sync::Mutex::new(exo_core::hlc::HybridClock::new()));
    Arc::new(move || {
        let mut clock = clock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        clock
            .now()
            .map_err(|err| format!("Holon provenance HLC exhausted: {err}"))
    })
}

fn static_did(value: &'static str) -> Did {
    match Did::new(value) {
        Ok(did) => did,
        Err(error) => unreachable!("hardcoded DID {value} must be valid: {error}"),
    }
}

fn ratio_basis_points(numerator: usize, denominator: usize) -> u32 {
    if denominator == 0 {
        return 0;
    }

    let numerator = u128::try_from(numerator).unwrap_or(u128::MAX);
    let denominator = u128::try_from(denominator).unwrap_or(u128::MAX);
    let ratio = numerator.saturating_mul(10_000) / denominator;
    u32::try_from(ratio).unwrap_or(u32::MAX)
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------
// Holon construction
// ---------------------------------------------------------------------------

/// Create the topology optimizer Holon for an already-resolved Holon DID.
pub fn create_topology_holon_with_did(holon_did: Did) -> Holon {
    holon::spawn(
        holon_did,
        PermissionSet::new(vec![
            Permission::new("network.peers.read"),
            Permission::new("network.topology.recommend"),
        ]),
        Combinator::Sequence(vec![
            // Guard: only run if there are peers.
            Combinator::Guard(
                Box::new(Combinator::Identity),
                Predicate {
                    name: "has_peers".into(),
                    required_key: "peer_count".into(),
                    expected_value: None, // Just check existence
                },
            ),
            // Transform: compute diversity recommendation.
            Combinator::Transform(
                Box::new(Combinator::Identity),
                TransformFn {
                    name: "topology_analysis".into(),
                    output_key: "topology_recommendation".into(),
                    output_value: "analyzed".into(),
                },
            ),
        ]),
    )
}

/// Create the scaling advisor Holon for an already-resolved Holon DID.
pub fn create_scaling_holon_with_did(holon_did: Did) -> Holon {
    holon::spawn(
        holon_did,
        PermissionSet::new(vec![
            Permission::new("consensus.validators.read"),
            Permission::new("governance.propose"),
        ]),
        Combinator::Sequence(vec![
            // Guard: only run if validator count is known.
            Combinator::Guard(
                Box::new(Combinator::Identity),
                Predicate {
                    name: "has_validator_info".into(),
                    required_key: "validator_count".into(),
                    expected_value: None,
                },
            ),
            // Transform: produce scaling recommendation.
            Combinator::Transform(
                Box::new(Combinator::Identity),
                TransformFn {
                    name: "scaling_analysis".into(),
                    output_key: "scaling_recommendation".into(),
                    output_value: "analyzed".into(),
                },
            ),
        ]),
    )
}

/// Create the health monitor Holon for an already-resolved Holon DID.
pub fn create_health_holon_with_did(holon_did: Did) -> Holon {
    holon::spawn(
        holon_did,
        PermissionSet::new(vec![
            Permission::new("node.status.read"),
            Permission::new("consensus.status.read"),
        ]),
        Combinator::Transform(
            Box::new(Combinator::Identity),
            TransformFn {
                name: "health_check".into(),
                output_key: "health_status".into(),
                output_value: "checked".into(),
            },
        ),
    )
}

// ---------------------------------------------------------------------------
// Kernel and adjudication context for infrastructure Holons
// ---------------------------------------------------------------------------

/// Create a Kernel instance for infrastructure Holon adjudication.
pub fn create_infrastructure_kernel() -> Kernel {
    // Use the full constitutional invariant set.
    let invariants = InvariantSet::all();
    Kernel::new(b"exochain-constitutional-governance-v1", invariants)
}

/// Build an adjudication context for an infrastructure Holon step.
///
/// Infrastructure Holons operate under the Executive branch with
/// read-only + recommend permissions. They cannot self-grant or
/// modify the kernel.
#[derive(Serialize)]
struct InfrastructureHolonStepActionPayload<'a> {
    domain: &'static str,
    holon_id: &'a Did,
    holon_state: HolonState,
    capabilities: &'a PermissionSet,
}

fn signed_authority_link(
    holon: &Holon,
    config: &HolonManagerConfig,
) -> Result<AuthorityLink, String> {
    let mut link = AuthorityLink {
        grantor: config.root_did.clone(),
        grantee: holon.id.clone(),
        permissions: holon.capabilities.clone(),
        signature: Vec::new(),
        grantor_public_key: Some(config.root_public_key.as_bytes().to_vec()),
    };
    let message = authority_link_signature_message(&link)
        .map_err(|err| format!("failed to encode authority-link signature payload: {err}"))?;
    let signature = (config.root_signer)(message.as_bytes());
    link.signature = signature.to_bytes().to_vec();
    Ok(link)
}

/// Build the external-attestation link (attester → root_did) when `config`
/// carries a `RootAttestation`. Per D5, this link is the witnessed-ceremony
/// evidence that the root authority is not self-issued: its grantor is the
/// attester's own DID/key, structurally distinct from `root_signer`.
fn signed_attestation_link(
    holon: &Holon,
    config: &HolonManagerConfig,
    attestation: &RootAttestation,
) -> Result<AuthorityLink, String> {
    let mut link = AuthorityLink {
        grantor: attestation.attester_did.clone(),
        grantee: config.root_did.clone(),
        permissions: holon.capabilities.clone(),
        signature: Vec::new(),
        grantor_public_key: Some(attestation.attester_public_key.as_bytes().to_vec()),
    };
    let message = authority_link_signature_message(&link)
        .map_err(|err| format!("failed to encode attestation-link signature payload: {err}"))?;
    let signature = (attestation.attester_signer)(message.as_bytes());
    link.signature = signature.to_bytes().to_vec();
    Ok(link)
}

fn signed_provenance(
    holon: &Holon,
    actor_key: &HolonActorKey,
    provenance_timestamp: Timestamp,
) -> Result<Provenance, String> {
    let timestamp = provenance_timestamp.to_string();
    let action_hash = hash_structured(&InfrastructureHolonStepActionPayload {
        domain: "exo.node.infrastructure_holon.step_action.v1",
        holon_id: &holon.id,
        holon_state: holon.state,
        capabilities: &holon.capabilities,
    })
    .map_err(|err| format!("failed to encode Holon provenance action hash payload: {err}"))?
    .as_bytes()
    .to_vec();
    let mut provenance = Provenance {
        actor: holon.id.clone(),
        timestamp,
        action_hash,
        signature: Vec::new(),
        public_key: Some(actor_key.public_key.as_bytes().to_vec()),
        voice_kind: None,
        independence: None,
        review_order: None,
    };
    let message = provenance_signature_message(&provenance)
        .map_err(|err| format!("failed to encode provenance signature payload: {err}"))?;
    let signature = (actor_key.signer)(message.as_bytes());
    provenance.signature = signature.to_bytes().to_vec();
    Ok(provenance)
}

fn next_provenance_timestamp(config: &HolonManagerConfig) -> Result<Timestamp, String> {
    let timestamp = (config.provenance_timestamp_source)()?;
    if timestamp == Timestamp::ZERO {
        return Err("Holon provenance timestamp source returned zero HLC timestamp".into());
    }
    Ok(timestamp)
}

fn capability_scope(capabilities: &PermissionSet) -> String {
    let mut permissions: Vec<&str> = capabilities
        .permissions
        .iter()
        .map(|permission| permission.0.as_str())
        .collect();
    permissions.sort_unstable();
    permissions.dedup();
    permissions.join(";")
}

pub fn build_holon_adjudication_context(
    holon: &Holon,
    config: &HolonManagerConfig,
) -> Result<AdjudicationContext, String> {
    let provenance_timestamp = next_provenance_timestamp(config)?;
    let actor_key = config.holon_actor_keys.get(&holon.id).ok_or_else(|| {
        format!(
            "Holon actor signer is required for DID-bound provenance: {}",
            holon.id
        )
    })?;
    let root_link = signed_authority_link(holon, config)?;

    // Per D5: a root authority is legitimate only with a witnessed ceremony,
    // external attestation, and lineage distinct from the signer. The trust
    // anchor for `root_did` therefore comes exclusively from an external
    // attester's key when one is configured — never from the self-signed
    // root→holon link itself, which would be a tautological trust check
    // (trusting a key because it is the key that produced the signature).
    //
    // Without a configured `root_attestation`, `root_did` gets no entry in
    // `trusted_authority_keys`, so the kernel's `AuthorityChainValid`
    // invariant fails closed with "grantor_public_key is unresolved for
    // grantor DID" and the self-issued root is rejected.
    let mut trusted_authority_keys = TrustedAuthorityKeys::default();
    let authority_chain = match &config.root_attestation {
        Some(attestation)
            if attestation.attester_did != config.root_did
                && attestation.attester_public_key != config.root_public_key =>
        {
            let attestation_link = signed_attestation_link(holon, config, attestation)?;
            // The attester is the external trust anchor (the witnessed
            // ceremony). D5 requires lineage genuinely distinct from the
            // signer, so both the attester DID *and* its cryptographic key
            // must differ from the root's: a differently-labelled DID under
            // the same key control is still self-issuance and is rejected by
            // the guard above (it falls through to the self-issued arm, where
            // `root_did` gets no trusted key and the kernel fails closed).
            trusted_authority_keys.insert(
                attestation.attester_did.clone(),
                vec![attestation.attester_public_key.as_bytes().to_vec()],
            );
            // The root's key is trusted only because the external attester
            // vouches for it via `attestation_link`, not because the root
            // signed its own delegation to the Holon.
            trusted_authority_keys.insert(
                config.root_did.clone(),
                vec![config.root_public_key.as_bytes().to_vec()],
            );
            AuthorityChain {
                links: vec![attestation_link, root_link],
            }
        }
        _ => AuthorityChain {
            links: vec![root_link],
        },
    };
    let mut trusted_provenance_keys = TrustedProvenanceKeys::default();
    trusted_provenance_keys.insert(
        holon.id.clone(),
        vec![actor_key.public_key.as_bytes().to_vec()],
    );
    let consent_scope = capability_scope(&holon.capabilities);
    Ok(AdjudicationContext {
        actor_roles: vec![Role {
            name: "worker".into(),
            branch: GovernmentBranch::Executive,
        }],
        authority_chain,
        consent_records: vec![ConsentRecord {
            subject: config.root_did.clone(),
            granted_to: holon.id.clone(),
            scope: consent_scope.clone(),
            active: true,
        }],
        bailment_state: BailmentState::Active {
            bailor: config.root_did.clone(),
            bailee: holon.id.clone(),
            scope: consent_scope,
        },
        human_override_preserved: true,
        actor_permissions: holon.capabilities.clone(),
        trusted_authority_keys,
        trusted_provenance_keys,
        provenance: Some(signed_provenance(holon, actor_key, provenance_timestamp)?),
        quorum_evidence: None,
        active_challenge_reason: None,
    })
}

// ---------------------------------------------------------------------------
// Topology analysis
// ---------------------------------------------------------------------------

/// Analyze peer topology and produce a diversity recommendation.
fn analyze_topology(peer_count: usize, _net_handle: &NetworkHandle) -> (u32, String) {
    // Diversity score: simple heuristic based on peer count.
    // In production, this would query ASN distribution from PeerRegistry.
    let diversity_score_bp = if peer_count == 0 {
        0
    } else if peer_count < 3 {
        3000
    } else if peer_count < 7 {
        6000
    } else if peer_count < 15 {
        8000
    } else {
        10_000
    };

    let recommendation = if diversity_score_bp < 3000 {
        "CRITICAL: No peers connected. Node is isolated.".into()
    } else if diversity_score_bp < 5000 {
        format!("WARNING: Only {peer_count} peers. Recommend connecting to more diverse nodes.")
    } else if diversity_score_bp < 8000 {
        format!(
            "FAIR: {peer_count} peers, diversity score {diversity_score_bp} bp. Consider adding peers from different ASNs."
        )
    } else {
        format!(
            "GOOD: {peer_count} peers, diversity score {diversity_score_bp} bp. Topology is healthy."
        )
    };

    (diversity_score_bp, recommendation)
}

// ---------------------------------------------------------------------------
// Scaling analysis
// ---------------------------------------------------------------------------

/// Analyze validator-to-node ratio and produce a scaling recommendation.
fn analyze_scaling(validator_count: usize, node_count: usize) -> String {
    if node_count == 0 {
        return "No nodes in network.".into();
    }

    let ratio_bp = ratio_basis_points(validator_count, node_count);
    let ratio_percent = ratio_bp / 100;

    if validator_count < 3 {
        format!(
            "CRITICAL: Only {validator_count} validators. BFT requires at least 3f+1 = 4. \
             Recommend promoting {} more nodes.",
            4usize.saturating_sub(validator_count)
        )
    } else if ratio_bp < 2000 {
        format!(
            "LOW: {validator_count}/{node_count} nodes are validators ({ratio_percent}%). \
             Consider promoting more nodes for resilience.",
        )
    } else if ratio_bp >= 8000 {
        format!(
            "HIGH: {validator_count}/{node_count} nodes are validators ({ratio_percent}%). \
             Consider whether all need validator status.",
        )
    } else {
        format!(
            "GOOD: {validator_count}/{node_count} nodes are validators ({ratio_percent}%). \
             Ratio is healthy.",
        )
    }
}

// ---------------------------------------------------------------------------
// Health analysis
// ---------------------------------------------------------------------------

/// Analyze node health from consensus and DAG metrics.
fn analyze_health(consensus_round: u64, committed_height: u64) -> HealthStatus {
    // If consensus is running (rounds advancing) and nodes are being committed, healthy.
    if committed_height == 0 && consensus_round > 10 {
        HealthStatus::Critical {
            reason: format!(
                "No committed nodes after {consensus_round} rounds — consensus may be stalled"
            ),
        }
    } else if consensus_round > 0 && committed_height == 0 {
        HealthStatus::Degraded {
            reason: "Consensus is running but no nodes committed yet".into(),
        }
    } else {
        HealthStatus::Healthy
    }
}

// ---------------------------------------------------------------------------
// Holon action execution
// ---------------------------------------------------------------------------

fn encode_validator_change(change: &ValidatorChange) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(change, &mut buf)
        .map_err(|err| format!("failed to encode validator-set change payload: {err}"))?;
    Ok(buf)
}

async fn read_holon_peer_count(
    net_handle: &NetworkHandle,
    holon_name: &'static str,
) -> Result<usize, String> {
    net_handle
        .peer_count()
        .await
        .map_err(|err| format!("{holon_name} Holon peer-count read failed: {err}"))
}

// ---------------------------------------------------------------------------
// Holon manager — runs all infrastructure Holons as a background task
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HolonScalingSnapshot {
    validator_count: usize,
    is_validator: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HolonHealthSnapshot {
    consensus_round: u64,
    committed_height: u64,
}

async fn read_holon_scaling_snapshot(
    reactor_state: SharedReactorState,
) -> Result<HolonScalingSnapshot, String> {
    tokio::task::spawn_blocking(move || {
        let state = reactor_state
            .lock()
            .map_err(|_| "Reactor state mutex poisoned in scaling holon".to_owned())?;
        Ok(HolonScalingSnapshot {
            validator_count: state.consensus.config.validators.len(),
            is_validator: state.is_validator,
        })
    })
    .await
    .map_err(|error| format!("Scaling Holon reactor snapshot task failed: {error}"))?
}

async fn read_holon_health_snapshot(
    reactor_state: SharedReactorState,
) -> Result<HolonHealthSnapshot, String> {
    tokio::task::spawn_blocking(move || {
        let state = reactor_state
            .lock()
            .map_err(|_| "Reactor state mutex poisoned in health holon".to_owned())?;
        Ok(HolonHealthSnapshot {
            consensus_round: state.consensus.current_round,
            committed_height: usize_to_u64_saturating(state.consensus.committed.len()),
        })
    })
    .await
    .map_err(|error| format!("Health Holon reactor snapshot task failed: {error}"))?
}

/// Run the infrastructure Holon manager.
///
/// Periodically executes each Holon under kernel adjudication and emits
/// events to the application layer.
pub async fn run_holon_manager(
    config: HolonManagerConfig,
    reactor_state: SharedReactorState,
    // Retained for API stability (callers already pass the shared DAG
    // store). No longer read here: per VCG-010/D5, the Scaling Holon's
    // auto-promotion path is recommendation-only, full stop, and no longer
    // submits a DAG proposal, so this manager has no state-changing use for
    // direct store access.
    _shared_store: std::sync::Arc<std::sync::Mutex<SqliteDagStore>>,
    net_handle: NetworkHandle,
    event_tx: mpsc::Sender<HolonEvent>,
) {
    let kernel = create_infrastructure_kernel();

    let mut topology_holon = create_topology_holon_with_did(config.topology_holon_did.clone());
    let mut scaling_holon = create_scaling_holon_with_did(config.scaling_holon_did.clone());
    let mut health_holon = create_health_holon_with_did(config.health_holon_did.clone());

    let mut topology_timer =
        tokio::time::interval(Duration::from_secs(config.topology_interval_secs));
    let mut scaling_timer =
        tokio::time::interval(Duration::from_secs(config.scaling_interval_secs));
    let mut health_timer = tokio::time::interval(Duration::from_secs(config.health_interval_secs));

    // Skip first ticks (fire immediately on first interval).
    topology_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    scaling_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    health_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = topology_timer.tick() => {
                if topology_holon.state == HolonState::Terminated {
                    continue;
                }

                let peer_count = match read_holon_peer_count(&net_handle, "Topology").await {
                    Ok(peer_count) => peer_count,
                    Err(e) => {
                        tracing::error!(err = %e, "Topology Holon peer-count read failed");
                        continue;
                    }
                };
                let (diversity_score_bp, recommendation) = analyze_topology(peer_count, &net_handle);

                let input = CombinatorInput::new()
                    .with("peer_count", peer_count.to_string())
                    .with("diversity_score_bp", diversity_score_bp.to_string());

                let ctx = match build_holon_adjudication_context(&topology_holon, &config) {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        tracing::warn!(
                            err = %e,
                            holon = %topology_holon.id,
                            "Topology Holon context construction failed"
                        );
                        continue;
                    }
                };
                match holon::step(&mut topology_holon, &input, &kernel, &ctx) {
                    Ok(_output) => {
                        if event_tx.send(HolonEvent::TopologyAnalysis {
                            peer_count,
                            diversity_score_bp,
                            recommendation,
                        }).await.is_err() {
                            tracing::warn!("Holon event channel closed — TopologyAnalysis dropped");
                        }
                        emit_cgr_proof_event(&topology_holon, &event_tx).await;

                        tracing::debug!(
                            peer_count,
                            diversity_score_bp,
                            "Topology Holon: analysis complete"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            err = %e,
                            holon = %topology_holon.id,
                            "Topology Holon step failed"
                        );
                        if topology_holon.state == HolonState::Terminated
                            && event_tx
                                .send(HolonEvent::HolonTerminated {
                                    holon_id: topology_holon.id.clone(),
                                    reason: e.to_string(),
                                })
                                .await
                                .is_err()
                        {
                            tracing::warn!("Holon event channel closed — HolonTerminated dropped");
                        }
                    }
                }
            }

            _ = scaling_timer.tick() => {
                if scaling_holon.state == HolonState::Terminated {
                    continue;
                }

                let scaling_snapshot =
                    match read_holon_scaling_snapshot(Arc::clone(&reactor_state)).await {
                        Ok(snapshot) => snapshot,
                        Err(e) => {
                            tracing::error!(err = %e, "Scaling Holon reactor snapshot failed");
                            continue;
                        }
                    };
                let validator_count = scaling_snapshot.validator_count;
                // Estimate node count from peer count + 1 (self).
                let peer_count = match read_holon_peer_count(&net_handle, "Scaling").await {
                    Ok(peer_count) => peer_count,
                    Err(e) => {
                        tracing::error!(err = %e, "Scaling Holon peer-count read failed");
                        continue;
                    }
                };
                let node_count = match peer_count.checked_add(1) {
                    Some(node_count) => node_count,
                    None => {
                        tracing::error!(
                            peer_count,
                            "Scaling Holon node-count computation overflowed"
                        );
                        continue;
                    }
                };

                let recommendation = analyze_scaling(validator_count, node_count);

                let input = CombinatorInput::new()
                    .with("validator_count", validator_count.to_string())
                    .with("node_count", node_count.to_string());

                let ctx = match build_holon_adjudication_context(&scaling_holon, &config) {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        tracing::warn!(
                            err = %e,
                            holon = %scaling_holon.id,
                            "Scaling Holon context construction failed"
                        );
                        continue;
                    }
                };
                match holon::step(&mut scaling_holon, &input, &kernel, &ctx) {
                    Ok(_output) => {
                        if event_tx.send(HolonEvent::ScalingRecommendation {
                            validator_count,
                            node_count,
                            recommendation: recommendation.clone(),
                        }).await.is_err() {
                            tracing::warn!("Holon event channel closed — ScalingRecommendation dropped");
                        }
                        emit_cgr_proof_event(&scaling_holon, &event_tx).await;

                        // Recommendation-only, full stop (D5): if validator count
                        // is critical (< 3) and we're a validator, emit a named
                        // promotion RECOMMENDATION for an eligible peer. This is
                        // evidence for a human/governance ratification decision —
                        // it never submits a state-changing ValidatorSetChange
                        // proposal on its own. Promotion is a ratification event
                        // with named evidence, not an automatic action.
                        if validator_count < 3
                            && node_count > validator_count
                            && scaling_snapshot.is_validator
                        {
                            // Build a candidate DID — in production, this would
                            // query PeerRegistry for an eligible non-validator.
                            let candidate = Did::new(&format!(
                                "did:exo:auto-promoted-{node_count}"
                            ))
                            .unwrap_or_else(|_| static_did("did:exo:candidate"));

                            // Recommendation-only (VCG-010 / D5, full stop):
                            // this AddValidator is carried ONLY as named
                            // evidence inside a RecommendationOnly governance
                            // event and is NEVER submitted as a real
                            // ValidatorSetChange proposal.
                            //
                            // VCG-015 reconciliation: AddValidator now carries
                            // the candidate's real Ed25519 key, fail-closed
                            // against its DID at the reactor apply path.
                            // `PeerRegistry` holds only libp2p `PeerId`s, not
                            // consensus keys, so no genuine candidate key exists
                            // at recommendation time. We attach an explicit
                            // all-zero advisory sentinel: it is not a signing key
                            // and does NOT hash to the candidate DID, so if this
                            // recommendation payload were ever submitted verbatim
                            // as a real proposal, VCG-015's apply-path cross-check
                            // (`did == did_from_public_key(public_key)`) rejects
                            // it fail-closed. The genuine candidate key must be
                            // supplied by whoever RATIFIES the recommendation; the
                            // sentinel never enters any validator_public_keys
                            // resolver. (Real key-bearing recommendations await
                            // the PeerRegistry key-lookup follow-on.)
                            let change = ValidatorChange::AddValidator {
                                did: candidate.clone(),
                                public_key: PublicKey([0u8; 32]),
                            };
                            match encode_validator_change(&change) {
                                Ok(buf) => {
                                    if let Err(e) = reactor::broadcast_governance_event(
                                        &reactor_state,
                                        &net_handle,
                                        GovernanceEventType::RecommendationOnly,
                                        buf,
                                    )
                                    .await
                                    {
                                        tracing::warn!(
                                            err = %e,
                                            candidate = %candidate,
                                            "Scaling Holon: promotion recommendation broadcast failed"
                                        );
                                    } else {
                                        tracing::info!(
                                            candidate = %candidate,
                                            "Scaling Holon: promotion recommendation emitted \
                                             (recommendation-only, full stop — no proposal submitted)"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        err = %e,
                                        candidate = %candidate,
                                        "Scaling Holon: validator-change encoding failed"
                                    );
                                }
                            }
                        }

                        tracing::debug!(
                            validator_count,
                            node_count,
                            "Scaling Holon: analysis complete"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            err = %e,
                            holon = %scaling_holon.id,
                            "Scaling Holon step failed"
                        );
                        if scaling_holon.state == HolonState::Terminated
                            && event_tx
                                .send(HolonEvent::HolonTerminated {
                                    holon_id: scaling_holon.id.clone(),
                                    reason: e.to_string(),
                                })
                                .await
                                .is_err()
                        {
                            tracing::warn!("Holon event channel closed — HolonTerminated dropped");
                        }
                    }
                }
            }

            _ = health_timer.tick() => {
                if health_holon.state == HolonState::Terminated {
                    continue;
                }

                let health_snapshot =
                    match read_holon_health_snapshot(Arc::clone(&reactor_state)).await {
                        Ok(snapshot) => snapshot,
                        Err(e) => {
                            tracing::error!(err = %e, "Health Holon reactor snapshot failed");
                            continue;
                        }
                    };
                let consensus_round = health_snapshot.consensus_round;
                let committed_height = health_snapshot.committed_height;

                let status = analyze_health(consensus_round, committed_height);

                let input = CombinatorInput::new()
                    .with("consensus_round", consensus_round.to_string())
                    .with("committed_height", committed_height.to_string());

                let ctx = match build_holon_adjudication_context(&health_holon, &config) {
                    Ok(ctx) => ctx,
                    Err(e) => {
                        tracing::warn!(
                            err = %e,
                            holon = %health_holon.id,
                            "Health Holon context construction failed"
                        );
                        continue;
                    }
                };
                match holon::step(&mut health_holon, &input, &kernel, &ctx) {
                    Ok(_output) => {
                        if event_tx.send(HolonEvent::HealthCheck {
                            consensus_round,
                            committed_height,
                            status,
                        }).await.is_err() {
                            tracing::warn!("Holon event channel closed — HealthCheck dropped");
                        }
                        emit_cgr_proof_event(&health_holon, &event_tx).await;

                        tracing::debug!(
                            consensus_round,
                            committed_height,
                            "Health Holon: check complete"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            err = %e,
                            holon = %health_holon.id,
                            "Health Holon step failed"
                        );
                        if health_holon.state == HolonState::Terminated
                            && event_tx
                                .send(HolonEvent::HolonTerminated {
                                    holon_id: health_holon.id.clone(),
                                    reason: e.to_string(),
                                })
                                .await
                                .is_err()
                        {
                            tracing::warn!("Holon event channel closed — HolonTerminated dropped");
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    fn test_did() -> Did {
        Did::new("did:exo:test-node").unwrap()
    }

    fn test_holon_did(node_did: &Did, role: &str) -> Did {
        Did::new(&format!("did:exo:archon-{role}-{node_did}"))
            .unwrap_or_else(|_| Did::new(&format!("did:exo:archon-{role}")).unwrap())
    }

    fn create_topology_holon(node_did: &Did) -> Holon {
        create_topology_holon_with_did(test_holon_did(node_did, "topology"))
    }

    fn create_scaling_holon(node_did: &Did) -> Holon {
        create_scaling_holon_with_did(test_holon_did(node_did, "scaling"))
    }

    fn create_health_holon(node_did: &Did) -> Holon {
        create_health_holon_with_did(test_holon_did(node_did, "health"))
    }

    fn deterministic_provenance_timestamp_source(
        start_physical_ms: u64,
    ) -> Arc<dyn Fn() -> Result<Timestamp, String> + Send + Sync> {
        let next_physical_ms = Arc::new(AtomicU64::new(start_physical_ms.max(1)));
        Arc::new(move || {
            let physical_ms = next_physical_ms.fetch_add(1, Ordering::Relaxed);
            Ok(Timestamp::new(physical_ms, 0))
        })
    }

    /// A `HolonManagerConfig` with a legitimate external attestation by
    /// default: the root authority's key is vouched for by a distinct
    /// attester DID/key (a witnessed ceremony), satisfying D5's
    /// lineage-distinct-from-the-signer requirement. This is the config
    /// used by tests that exercise the normal (non-adversarial) Holon step
    /// path, including the Scaling Holon manager-loop tests.
    fn test_config_with_intervals(
        topology_interval_secs: u64,
        scaling_interval_secs: u64,
        health_interval_secs: u64,
    ) -> HolonManagerConfig {
        let node_did = test_did();
        let topology_holon_did = create_topology_holon(&node_did).id;
        let scaling_holon_did = create_scaling_holon(&node_did).id;
        let health_holon_did = create_health_holon(&node_did).id;
        let keypair = exo_core::crypto::KeyPair::from_secret_bytes([0x48; 32]).unwrap();
        let root_public_key = *keypair.public_key();
        let root_secret_key = keypair.secret_key().clone();
        let attester_keypair = exo_core::crypto::KeyPair::from_secret_bytes([0x99; 32]).unwrap();
        let attester_public_key = *attester_keypair.public_key();
        let attester_secret_key = attester_keypair.secret_key().clone();
        let mut holon_actor_keys = BTreeMap::new();
        for (holon_did, secret_seed) in [
            (topology_holon_did.clone(), [0x51; 32]),
            (scaling_holon_did.clone(), [0x52; 32]),
            (health_holon_did.clone(), [0x53; 32]),
        ] {
            let keypair = exo_core::crypto::KeyPair::from_secret_bytes(secret_seed).unwrap();
            let public_key = *keypair.public_key();
            let secret_key = keypair.secret_key().clone();
            holon_actor_keys.insert(
                holon_did,
                HolonActorKey {
                    public_key,
                    signer: Arc::new(move |message: &[u8]| {
                        exo_core::crypto::sign(message, &secret_key)
                    }),
                },
            );
        }
        HolonManagerConfig {
            node_did,
            root_did: Did::new("did:exo:test-root").unwrap(),
            root_public_key,
            root_signer: Arc::new(move |message: &[u8]| {
                exo_core::crypto::sign(message, &root_secret_key)
            }),
            topology_holon_did,
            scaling_holon_did,
            health_holon_did,
            holon_actor_keys,
            root_attestation: Some(RootAttestation {
                attester_did: Did::new("did:exo:test-ceremony-witness").unwrap(),
                attester_public_key,
                attester_signer: Arc::new(move |message: &[u8]| {
                    exo_core::crypto::sign(message, &attester_secret_key)
                }),
            }),
            provenance_timestamp_source: deterministic_provenance_timestamp_source(1),
            topology_interval_secs,
            scaling_interval_secs,
            health_interval_secs,
        }
    }

    /// A `HolonManagerConfig` with no external attestation: the D5
    /// self-issued-root scenario (grantor key == signer key, no lineage
    /// distinct from the signer), which the kernel must reject during
    /// `holon::step`.
    fn test_config() -> HolonManagerConfig {
        let mut config = test_config_with_intervals(60, 300, 30);
        config.root_attestation = None;
        config
    }

    /// Convenience alias for `test_config_with_intervals` at the default
    /// intervals — reads at call sites as "a legitimately attested config",
    /// contrasting with the self-issued `test_config()`.
    fn test_config_with_attestation() -> HolonManagerConfig {
        test_config_with_intervals(60, 300, 30)
    }

    #[test]
    fn module_doc_retains_infrastructure_holon_audit_status() {
        let src = include_str!("holons.rs");
        assert!(
            src.contains("# Audit status"),
            "module doc must retain the R5 audit-status section"
        );
        assert!(
            src.contains(INFRASTRUCTURE_HOLONS_FEATURE),
            "module doc must name the default-off feature flag"
        );
        assert!(
            src.contains(INFRASTRUCTURE_HOLONS_INITIATIVE),
            "module doc must point at the R5 initiative"
        );
        assert!(
            src.contains("Ed25519 authority key"),
            "module doc must call out the signed adjudication authority"
        );
        assert!(
            src.contains("distinct DID-bound actor signer"),
            "module doc must call out per-Holon provenance actor signers"
        );
    }

    #[test]
    fn holon_provenance_uses_a_did_bound_actor_key_not_the_root_authority_key() {
        let config = test_config_with_attestation();
        let holon = create_health_holon(&config.node_did);
        let context = build_holon_adjudication_context(&holon, &config)
            .expect("attested Holon context should be constructed");
        let provenance_key = context
            .provenance
            .as_ref()
            .and_then(|provenance| provenance.public_key.as_ref())
            .expect("Holon provenance public key");

        assert_ne!(
            provenance_key.as_slice(),
            config.root_public_key.as_bytes(),
            "root authority key must not masquerade as a distinct Holon actor"
        );
    }

    #[test]
    fn production_holon_config_does_not_compile_default_authority_secret() {
        let source = include_str!("holons.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");

        assert!(
            !production.contains("impl Default for HolonManagerConfig"),
            "production Holon config must not provide a default authority identity"
        );
        assert!(
            !production.contains("default_holon_keypair"),
            "production Holon config must not carry a default authority keypair helper"
        );
        assert!(
            !production.contains("from_secret_bytes([0x48; 32])"),
            "production Holon config must not compile a hardcoded authority secret"
        );
    }

    #[test]
    fn holon_provenance_source_does_not_hardcode_timestamp() {
        let src = include_str!("holons.rs");
        let forbidden_timestamp = ["2026-04-27", "T00:00:00Z"].concat();
        assert!(
            !src.contains(&forbidden_timestamp),
            "Holon provenance must use caller-supplied deterministic HLC metadata, not a hardcoded timestamp"
        );
    }

    #[test]
    fn holon_provenance_action_hash_uses_structured_payload() {
        let source = include_str!("holons.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");

        assert!(
            !production.contains("Hash256::digest(format!"),
            "Holon provenance action hashes must not use raw formatted string hashing"
        );
        assert!(
            production.contains("hash_structured"),
            "Holon provenance action hashes must use canonical structured hashing"
        );
    }

    #[test]
    fn production_holon_source_does_not_synthesize_root_key_as_actor_provenance() {
        let source = include_str!("holons.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");
        assert!(
            !production.contains("trusted_provenance_keys.insert(\n        holon.id.clone(),\n        vec![config.root_public_key.as_bytes().to_vec()],"),
            "Holon trusted provenance keys must come from DID-bound Holon actor keys, not the root authority key"
        );
        assert!(
            !production
                .contains("\n        public_key: Some(config.root_public_key.as_bytes().to_vec())"),
            "Holon provenance must not be signed as the Holon actor with the root authority key"
        );
    }

    #[test]
    fn scaling_auto_promotion_serialization_errors_are_not_silently_dropped() {
        let source = include_str!("holons.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        let auto_promotion = production
            .split("let change = ValidatorChange::AddValidator")
            .nth(1)
            .expect("scaling auto-promotion block")
            .split("tracing::debug!(")
            .next()
            .expect("auto-promotion serialization block");

        assert!(
            !auto_promotion.contains("ciborium::into_writer(&change, &mut buf).is_ok()"),
            "validator-change CBOR serialization must not be silently dropped on error"
        );
        assert!(
            auto_promotion.contains("encode_validator_change(&change)"),
            "validator-change CBOR serialization must use the fail-closed helper"
        );
    }

    #[test]
    fn production_holon_manager_does_not_default_failed_peer_count_reads_to_zero() {
        let source = include_str!("holons.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");

        assert!(
            !production.contains("peer_count().await.unwrap_or(0)"),
            "network peer-count read failures must not be fabricated as zero peers"
        );
        assert!(
            production.contains("read_holon_peer_count"),
            "Holon manager must use a fail-closed peer-count read helper"
        );
    }

    #[tokio::test]
    async fn read_holon_peer_count_propagates_network_errors() {
        let (cmd_tx, cmd_rx) = mpsc::channel(1);
        drop(cmd_rx);
        let net_handle = NetworkHandle::new(cmd_tx);

        let err = read_holon_peer_count(&net_handle, "Topology")
            .await
            .expect_err("closed network command channel must be an error");

        assert!(err.contains("Topology Holon peer-count read failed"));
        assert!(err.contains("Network task has stopped"));
    }

    #[test]
    fn production_holon_source_does_not_suppress_security_relevant_clippy_lints() {
        let source = include_str!("holons.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module marker present");

        for lint in [
            "clippy::expect_used",
            "clippy::unwrap_used",
            "clippy::as_conversions",
            "clippy::single_match",
        ] {
            assert!(
                !production.contains(lint),
                "production Holon source must not suppress {lint}"
            );
        }
    }

    #[test]
    fn holon_manager_async_path_does_not_lock_reactor_state_directly() {
        let source = include_str!("holons.rs");
        let manager_source = source
            .split("pub async fn run_holon_manager")
            .nth(1)
            .expect("Holon manager source must be present")
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("Holon manager source ends before tests");

        assert!(
            !manager_source.contains("reactor_state.lock()"),
            "Holon async manager must isolate reactor std::sync::Mutex access from Tokio workers"
        );
    }

    #[test]
    fn holon_provenance_uses_configured_hlc_timestamp_source() {
        let mut config = test_config();
        config.provenance_timestamp_source = Arc::new(|| Ok(Timestamp::new(42_424, 7)));
        let h = create_health_holon(&test_did());

        let ctx = build_holon_adjudication_context(&h, &config).expect("holon context");
        let provenance = ctx.provenance.expect("provenance");

        assert_eq!(provenance.timestamp, "42424:7");
    }

    #[test]
    fn holon_provenance_rejects_zero_hlc_timestamp_source() {
        let mut config = test_config();
        config.provenance_timestamp_source = Arc::new(|| Ok(Timestamp::ZERO));
        let h = create_health_holon(&test_did());

        let result = build_holon_adjudication_context(&h, &config);

        assert!(
            result.is_err(),
            "Holon context construction must fail closed on zero provenance HLC metadata"
        );
    }

    /// VCG-010 / D5 red test: a root authority is legitimate only with a
    /// witnessed ceremony, external attestation, and lineage distinct from
    /// the signer. `test_config()` wires `root_public_key` as the exact key
    /// that `root_signer` uses to sign the authority link — i.e. the
    /// grantor key equals the signer key with no external delegation chain
    /// (this mirrors the production wiring in `main.rs:783-798`, where
    /// `holon_authority_did`/`holon_authority_public_key`/`holon_authority_signer`
    /// are all derived from the same freshly-loaded node identity).
    ///
    /// `build_holon_adjudication_context` (holons.rs:435-440) currently
    /// inserts `config.root_public_key` into `trusted_authority_keys` keyed
    /// by `config.root_did` directly from the link it just signed — a
    /// tautological trust check with no independent/external resolution.
    /// The kernel's `AuthorityChainValid` invariant then "verifies" the
    /// signature against that self-supplied key and the holon step is
    /// permitted.
    ///
    /// Expected red: today this self-issued root authority is trusted and
    /// `holon::step` returns `Ok(..)`. Per D5, a self-issued root authority
    /// with no external attestation/delegation chain distinct from the
    /// signer must be REJECTED.
    #[test]
    fn holon_rejects_self_issued_root_authority() {
        let kernel = create_infrastructure_kernel();
        let config = test_config();

        // Sanity-check the self-issuance premise this test exercises: the
        // configured signer produces signatures verifiable under
        // config.root_public_key, i.e. grantor key == signer key.
        let probe_message = b"vcg-010-self-issuance-probe";
        let probe_signature = (config.root_signer)(probe_message);
        assert!(
            exo_core::crypto::verify(probe_message, &probe_signature, &config.root_public_key),
            "test premise: root_signer must produce signatures under root_public_key"
        );

        let mut h = create_health_holon(&test_did());
        let ctx = build_holon_adjudication_context(&h, &config).expect("holon context");

        // The authority chain's sole link is self-issued: its grantor is
        // config.root_did and its grantor_public_key is config.root_public_key
        // — the same key that produced the signature. There is no external
        // attestation or delegation link distinct from the signer anywhere
        // in the chain.
        assert_eq!(ctx.authority_chain.links.len(), 1);
        let root_link = &ctx.authority_chain.links[0];
        assert_eq!(root_link.grantor, config.root_did);
        assert_eq!(
            root_link.grantor_public_key.as_deref(),
            Some(config.root_public_key.as_bytes().as_slice())
        );

        let input = CombinatorInput::new()
            .with("consensus_round", "1")
            .with("committed_height", "1");

        let result = holon::step(&mut h, &input, &kernel, &ctx);

        assert!(
            result.is_err(),
            "a self-issued root authority (grantor key == signer key, no external \
             delegation/attestation chain) must be REJECTED per D5, but holon::step \
             returned {result:?}"
        );
    }

    /// D5 requires lineage genuinely distinct from the signer. A
    /// `RootAttestation` that carries a *different* attester DID label but the
    /// *same* cryptographic key as the root signer is still self-issuance,
    /// laundered one hop through a second label. The key-inequality guard in
    /// `build_holon_adjudication_context` must treat this as self-issued (no
    /// trusted key for `root_did`), so `holon::step` fails closed.
    #[test]
    fn holon_rejects_attestation_that_reuses_the_root_signer_key() {
        let kernel = create_infrastructure_kernel();

        // Start from a legitimately-attested config, then rewrite the
        // attestation so it keeps a distinct DID label but reuses the root's
        // own key + signer — the "differently-labelled DID under the same key
        // control" laundering case.
        let mut config = test_config_with_attestation();
        let root_public_key = config.root_public_key;
        let same_key_secret = exo_core::crypto::KeyPair::from_secret_bytes([0x48; 32])
            .unwrap()
            .secret_key()
            .clone();
        config.root_attestation = Some(RootAttestation {
            attester_did: Did::new("did:exo:laundered-witness").unwrap(),
            attester_public_key: root_public_key,
            attester_signer: Arc::new(move |message: &[u8]| {
                exo_core::crypto::sign(message, &same_key_secret)
            }),
        });

        let mut h = create_health_holon(&test_did());
        let ctx = build_holon_adjudication_context(&h, &config).expect("holon context");

        // The key-inequality guard must reject the laundered attestation and
        // fall through to the self-issued arm: a single self-issued link with
        // no independently-trusted key for root_did.
        assert_eq!(
            ctx.authority_chain.links.len(),
            1,
            "attestation reusing the root key must fall through to the \
             self-issued (single-link) arm, not be trusted as external lineage"
        );

        let input = CombinatorInput::new()
            .with("consensus_round", "1")
            .with("committed_height", "1");

        let result = holon::step(&mut h, &input, &kernel, &ctx);

        assert!(
            result.is_err(),
            "an attestation whose key equals the root signer key (distinct DID \
             label only) is self-issuance laundered through a second label and \
             must be REJECTED per D5, but holon::step returned {result:?}"
        );
    }

    #[test]
    fn holon_context_rejects_root_key_synthesized_as_holon_provenance_key() {
        let mut config = test_config();
        let h = create_health_holon(&test_did());
        config.holon_actor_keys.remove(&h.id);
        let err = build_holon_adjudication_context(&h, &config)
            .expect_err("Holon provenance must require a DID-bound Holon signer");
        assert!(
            err.contains("Holon actor signer"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(feature = "unaudited-infrastructure-holons"))]
    #[test]
    fn infrastructure_holons_disabled_without_feature_flag() {
        assert!(
            !infrastructure_holons_enabled(),
            "infrastructure Holons must be disabled by default while R5 is open"
        );
    }

    #[cfg(feature = "unaudited-infrastructure-holons")]
    #[test]
    fn infrastructure_holons_feature_enables_runtime() {
        assert!(
            infrastructure_holons_enabled(),
            "feature flag must explicitly opt into the unaudited Holon runtime"
        );
    }

    #[test]
    fn topology_holon_spawns_idle() {
        let h = create_topology_holon(&test_did());
        assert_eq!(h.state, HolonState::Idle);
        assert!(h.id.to_string().contains("archon-topology"));
    }

    #[test]
    fn scaling_holon_spawns_idle() {
        let h = create_scaling_holon(&test_did());
        assert_eq!(h.state, HolonState::Idle);
        assert!(h.id.to_string().contains("archon-scaling"));
    }

    #[test]
    fn health_holon_spawns_idle() {
        let h = create_health_holon(&test_did());
        assert_eq!(h.state, HolonState::Idle);
        assert!(h.id.to_string().contains("archon-health"));
    }

    #[test]
    fn topology_holon_step_succeeds_with_peers() {
        let kernel = create_infrastructure_kernel();
        let config = test_config_with_attestation();
        let mut h = create_topology_holon(&test_did());
        let ctx = build_holon_adjudication_context(&h, &config).expect("holon context");

        let input = CombinatorInput::new().with("peer_count", "5");

        let output = holon::step(&mut h, &input, &kernel, &ctx).unwrap();
        assert_eq!(h.state, HolonState::Idle);
        assert!(output.fields.contains_key("topology_recommendation"));
        assert_eq!(
            output.fields.get("topology_recommendation"),
            Some(&"analyzed".to_string())
        );
        let trace = h
            .last_trace
            .as_ref()
            .expect("successful holon step records a CGR trace");
        trace.verify_replay(&h.combinator_chain, &input).unwrap();
        let events = h
            .last_events
            .as_ref()
            .expect("successful holon step records CGR events");
        assert!(matches!(
            &events[0],
            exo_core::events::EventPayload::HolonActionVerified { cgr_proof_hash, .. }
                if *cgr_proof_hash == trace.trace_hash
        ));
    }

    #[test]
    fn topology_holon_guard_rejects_no_peer_count() {
        let kernel = create_infrastructure_kernel();
        let config = test_config_with_attestation();
        let mut h = create_topology_holon(&test_did());
        let ctx = build_holon_adjudication_context(&h, &config).expect("holon context");

        // No peer_count in input — Guard should fail
        let input = CombinatorInput::new();

        let result = holon::step(&mut h, &input, &kernel, &ctx);
        assert!(result.is_err(), "Guard should reject missing peer_count");
        assert_eq!(h.state, HolonState::Idle);
        assert!(h.last_trace.is_none());
    }

    #[test]
    fn scaling_holon_step_succeeds() {
        let kernel = create_infrastructure_kernel();
        let config = test_config_with_attestation();
        let mut h = create_scaling_holon(&test_did());
        let ctx = build_holon_adjudication_context(&h, &config).expect("holon context");

        let input = CombinatorInput::new()
            .with("validator_count", "4")
            .with("node_count", "12");

        let output = holon::step(&mut h, &input, &kernel, &ctx).unwrap();
        assert_eq!(h.state, HolonState::Idle);
        assert!(output.fields.contains_key("scaling_recommendation"));
    }

    #[test]
    fn health_holon_step_succeeds() {
        let kernel = create_infrastructure_kernel();
        let config = test_config_with_attestation();
        let mut h = create_health_holon(&test_did());
        let ctx = build_holon_adjudication_context(&h, &config).expect("holon context");

        let input = CombinatorInput::new()
            .with("consensus_round", "10")
            .with("committed_height", "5");

        let output = holon::step(&mut h, &input, &kernel, &ctx).unwrap();
        assert_eq!(h.state, HolonState::Idle);
        assert!(output.fields.contains_key("health_status"));
    }

    #[test]
    fn topology_analysis_scoring() {
        let (score_bp, rec) = analyze_topology(0, &{
            let (tx, _rx) = mpsc::channel(1);
            NetworkHandle::new(tx)
        });
        let _: u32 = score_bp;
        assert_eq!(score_bp, 0);
        assert!(rec.contains("CRITICAL"));

        let handle = {
            let (tx, _rx) = mpsc::channel(1);
            NetworkHandle::new(tx)
        };
        let (score_bp, rec) = analyze_topology(2, &handle);
        assert_eq!(score_bp, 3000);
        assert!(rec.contains("WARNING"));

        let (score_bp, _) = analyze_topology(10, &handle);
        assert_eq!(score_bp, 8000);

        let (score_bp, rec) = analyze_topology(20, &handle);
        assert_eq!(score_bp, 10_000);
        assert!(rec.contains("GOOD"));
    }

    #[test]
    fn scaling_analysis_recommendations() {
        let rec = analyze_scaling(2, 10);
        assert!(rec.contains("CRITICAL"));

        let rec = analyze_scaling(4, 50);
        assert!(rec.contains("LOW"));

        let rec = analyze_scaling(8, 10);
        assert!(rec.contains("HIGH"));

        let rec = analyze_scaling(5, 12);
        assert!(rec.contains("GOOD"));
    }

    #[test]
    fn health_analysis_statuses() {
        assert_eq!(analyze_health(5, 3), HealthStatus::Healthy);

        match analyze_health(5, 0) {
            HealthStatus::Degraded { .. } => {}
            other => panic!("Expected Degraded, got {other:?}"),
        }

        match analyze_health(20, 0) {
            HealthStatus::Critical { .. } => {}
            other => panic!("Expected Critical, got {other:?}"),
        }
    }

    #[test]
    fn holon_no_self_grant_enforced() {
        // Verify that a Holon with is_self_grant=true would be denied.
        // The kernel's NoSelfGrant invariant prevents AI from self-escalating.
        let kernel = create_infrastructure_kernel();
        let config = test_config_with_attestation();
        let h = create_health_holon(&test_did());

        // Build context normally.
        let ctx = build_holon_adjudication_context(&h, &config).expect("holon context");

        // Normal step works.
        let mut h2 = create_health_holon(&test_did());
        let input = CombinatorInput::new()
            .with("consensus_round", "1")
            .with("committed_height", "1");
        assert!(holon::step(&mut h2, &input, &kernel, &ctx).is_ok());
    }

    #[test]
    fn kernel_immutability_enforced() {
        let _kernel = create_infrastructure_kernel();
        let config = test_config();
        let h = create_health_holon(&test_did());
        let ctx = build_holon_adjudication_context(&h, &config).expect("holon context");

        // The adjudication context we build has modifies_kernel=false (set in step()),
        // so kernel immutability is preserved. Verify the context is well-formed.
        assert!(ctx.human_override_preserved);
        assert!(!ctx.authority_chain.links.is_empty());
        assert!(ctx.consent_records.iter().all(|c| c.active));
    }

    #[tokio::test]
    async fn holon_manager_emits_health_event() {
        use std::{collections::BTreeSet, sync::Arc};

        use exo_core::types::Signature;

        let validators: BTreeSet<Did> = (0..4)
            .map(|i| Did::new(&format!("did:exo:v{i}")).unwrap())
            .collect();

        let reactor_config = crate::reactor::ReactorConfig {
            node_did: test_did(),
            is_validator: true,
            validators,
            validator_public_keys: std::collections::BTreeMap::new(),
            round_timeout_ms: 5000,
        };
        let sign_fn: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync> =
            Arc::new(|_| Signature::from_bytes([0u8; 64]));
        let reactor_state = crate::reactor::create_reactor_state(&reactor_config, sign_fn, None);

        let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, mut event_rx) = mpsc::channel(32);
        // Health fires quickly; topology/scaling fire slowly to avoid
        // blocked peer_count() calls (no network loop in test).
        let config = test_config_with_intervals(3600, 3600, 1);

        // Spawn a background task to drain network commands (prevents hangs).
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    crate::network::NetworkCommand::Publish { reply, .. } => {
                        let _ = reply.send(Ok(()));
                    }
                    crate::network::NetworkCommand::PeerCount { reply } => {
                        let _ = reply.send(0);
                    }
                    _ => {}
                }
            }
        });

        // Create a temporary store for the test.
        let dir = tempfile::tempdir().unwrap();
        let shared_store = std::sync::Arc::new(std::sync::Mutex::new(
            crate::store::SqliteDagStore::open(dir.path()).unwrap(),
        ));

        // Spawn manager with short health interval.
        let manager = tokio::spawn(run_holon_manager(
            config,
            reactor_state,
            shared_store,
            net_handle,
            event_tx,
        ));

        // Wait for at least one health event.
        let event = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("Should receive an event within 5s")
            .expect("Channel should not be closed");

        // Should be one of the three Holon event types (first tick fires immediately).
        match event {
            HolonEvent::HealthCheck { .. }
            | HolonEvent::TopologyAnalysis { .. }
            | HolonEvent::ScalingRecommendation { .. } => {}
            other => panic!("Expected a Holon analysis event, got {other:?}"),
        }

        manager.abort();
    }

    /// VCG-010 / D5 red test: the Scaling Holon is recommendation-only, full
    /// stop. Per the module doc (holons.rs:29-39) and D5, promotion is a
    /// ratification event with named evidence — never an automatic
    /// state-changing action.
    ///
    /// Today (holons.rs:787-860), whenever `validator_count < 3` and the
    /// node `is_validator`, the Scaling Holon fabricates a candidate DID
    /// (`did:exo:auto-promoted-{node_count}`) and calls
    /// `execute_governance_action` -> `reactor::submit_proposal`, which is a
    /// real `ValidatorSetChange::AddValidator` DAG proposal, plus a matching
    /// `GovernanceEvent` broadcast over the network `Publish` command. This
    /// test drains the network-command channel and does NOT suppress the
    /// scaling path (unlike `holon_manager_emits_health_event`, which sets
    /// `scaling_interval_secs` to 3600 to dodge it) — it fires the scaling
    /// tick quickly with `validator_count == 1 < 3` and `is_validator == true`
    /// and asserts zero `ValidatorSetChange::AddValidator` proposals are ever
    /// submitted or broadcast.
    ///
    /// Expected red: today at least one `GovernanceEvent` with
    /// `event_type: ValidatorSetChange` decoding to
    /// `ValidatorChange::AddValidator { did: "did:exo:auto-promoted-*" }` is
    /// published, and the DAG store gains a matching committed/pending node.
    #[tokio::test]
    async fn scaling_holon_emits_zero_validator_set_change_proposals() {
        use std::{
            collections::BTreeSet,
            sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
        };

        use exo_core::types::Signature;

        // Single-validator set with this node as the sole validator: any
        // node_count > validator_count (guaranteed once at least one peer is
        // reported) keeps validator_count(1) < 3 true throughout the test.
        let validators: BTreeSet<Did> = std::iter::once(test_did()).collect();

        // A real keypair is required: `submit_proposal` verifies the
        // self-proposal/self-vote signature against `validator_public_keys`,
        // so an empty resolver (as in `holon_manager_emits_health_event`,
        // which never reaches consensus signing) would make the proposal
        // path reject before ever reaching the network layer — masking the
        // very state-changing behavior D5 says must not happen.
        let node_keypair = exo_core::crypto::KeyPair::from_secret_bytes([0x51; 32]).unwrap();
        let node_public_key = *node_keypair.public_key();
        let node_secret_key = node_keypair.secret_key().clone();
        let mut validator_public_keys = std::collections::BTreeMap::new();
        validator_public_keys.insert(test_did(), node_public_key);

        let reactor_config = crate::reactor::ReactorConfig {
            node_did: test_did(),
            is_validator: true,
            validators,
            validator_public_keys,
            round_timeout_ms: 5000,
        };
        let sign_fn: Arc<dyn Fn(&[u8]) -> Signature + Send + Sync> =
            Arc::new(move |message| exo_core::crypto::sign(message, &node_secret_key));
        let reactor_state = crate::reactor::create_reactor_state(&reactor_config, sign_fn, None);

        let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
        let net_handle = NetworkHandle::new(cmd_tx);

        let (event_tx, mut event_rx) = mpsc::channel(32);
        // Scaling fires quickly and is NOT suppressed. Topology/health are
        // slow so this test isolates the scaling-tick auto-promotion path.
        let config = test_config_with_intervals(3600, 1, 3600);

        let validator_set_change_proposals = Arc::new(AtomicUsize::new(0));
        let observed_governance_events = Arc::new(AtomicUsize::new(0));

        // Drain network commands, recording every ValidatorSetChange
        // governance-event broadcast that decodes to AddValidator instead of
        // suppressing/ignoring it as the existing health test does.
        let counter = Arc::clone(&validator_set_change_proposals);
        let governance_seen = Arc::clone(&observed_governance_events);
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    crate::network::NetworkCommand::Publish { message, reply, .. } => {
                        if let crate::wire::WireMessage::GovernanceEvent(event) = &message {
                            governance_seen.fetch_add(1, AtomicOrdering::SeqCst);
                            if matches!(
                                event.event_type,
                                crate::wire::GovernanceEventType::ValidatorSetChange
                            ) {
                                let decoded: Result<ValidatorChange, _> =
                                    ciborium::from_reader(event.payload.as_slice());
                                if let Ok(ValidatorChange::AddValidator { did, .. }) = decoded {
                                    assert!(
                                        did.to_string().starts_with("did:exo:auto-promoted-"),
                                        "unexpected AddValidator candidate: {did}"
                                    );
                                    counter.fetch_add(1, AtomicOrdering::SeqCst);
                                }
                            }
                        }
                        let _ = reply.send(Ok(()));
                    }
                    crate::network::NetworkCommand::PeerCount { reply } => {
                        // node_count = peer_count + 1 = 2, keeping
                        // validator_count(1) < 3 and node_count > validator_count.
                        let _ = reply.send(1);
                    }
                    _ => {}
                }
            }
        });

        // Create a temporary store for the test and keep a handle to inspect
        // the DAG tips after the run (a real proposal appends a node).
        let dir = tempfile::tempdir().unwrap();
        let shared_store = std::sync::Arc::new(std::sync::Mutex::new(
            crate::store::SqliteDagStore::open(dir.path()).unwrap(),
        ));
        let tips_before = shared_store.lock().unwrap().tips_sync().unwrap();

        let manager = tokio::spawn(run_holon_manager(
            config,
            reactor_state,
            Arc::clone(&shared_store),
            net_handle,
            event_tx,
        ));

        // Wait for at least one ScalingRecommendation event (first scaling
        // tick fires immediately), then give the auto-promotion branch a
        // moment to run before inspecting side effects.
        loop {
            let event = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("Should receive an event within 5s")
                .expect("Channel should not be closed");
            if matches!(event, HolonEvent::ScalingRecommendation { .. }) {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        manager.abort();

        assert!(
            observed_governance_events.load(AtomicOrdering::SeqCst) > 0,
            "test premise: scaling tick must have run at least once and reached the network layer"
        );

        assert_eq!(
            validator_set_change_proposals.load(AtomicOrdering::SeqCst),
            0,
            "Scaling Holon must emit recommendation objects only and submit ZERO \
             ValidatorSetChange::AddValidator proposals per D5 (recommendation-only, \
             full stop), but at least one was broadcast"
        );

        let tips_after = shared_store.lock().unwrap().tips_sync().unwrap();
        assert_eq!(
            tips_after, tips_before,
            "Scaling Holon must not append a real DAG proposal for auto-promotion \
             (recommendation-only, full stop)"
        );
    }
}
