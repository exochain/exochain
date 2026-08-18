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

//! EXOCHAIN Gatekeeper — the Judicial Branch.
//!
//! This crate implements the Constitutional Governance Runtime (CGR):
//! - **Kernel** — immutable adjudicator enforcing constitutional invariants
//! - **Invariants** — the eight constitutional invariants
//! - **Combinator** — deterministic algebra for composing governance operations
//! - **Holon** — autonomous agent runtime with kernel-adjudicated steps
//! - **MCP** — Model Context Protocol enforcement for AI systems
//! - **TEE** — Trusted Execution Environment attestation
//! - **Governance Monitor** — T-14 defense: signed attestation, circuit breaker, human approval gate

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod cgr_trace;
pub mod combinator;
pub mod error;
pub mod invariants;
pub mod types;

#[cfg(all(
    feature = "runtime",
    not(target_arch = "wasm32"),
    not(target_os = "zkvm")
))]
pub mod dagdb_gate;
#[cfg(feature = "runtime")]
pub mod governance_monitor;
#[cfg(feature = "runtime")]
pub mod holon;
#[cfg(feature = "runtime")]
pub mod kernel;
#[cfg(feature = "runtime")]
pub mod mcp;
#[cfg(feature = "runtime")]
pub mod mcp_audit;
#[cfg(feature = "runtime")]
pub mod tee;

// Re-export primary types.
pub use cgr_trace::{
    CGR_TRACE_EVIDENCE_TYPE, CGR_TRACE_SPEC, CgrInvariantCheck, CgrReductionTrace, CgrTraceStep,
};
pub use combinator::{Combinator, CombinatorInput, CombinatorOutput, reduce, reduce_with_trace};
#[cfg(all(
    feature = "runtime",
    not(target_arch = "wasm32"),
    not(target_os = "zkvm")
))]
pub use dagdb_gate::{
    ConsentEngine, DagDbConsentRecord, DagDbGatekeeperService, IdentityRegistry,
    sign_write_payload, usage_event_payload_hash, verify_write_consent, verify_write_signature,
};
pub use error::GatekeeperError;
#[cfg(feature = "runtime")]
pub use governance_monitor::{
    ApprovalGate, ApprovalStatus, GovernanceAttestation, GovernanceCircuitBreaker,
    GovernanceMonitorError,
};
#[cfg(feature = "runtime")]
pub use holon::{Holon, HolonState};
pub use invariants::{
    ConstitutionalInvariant, InvariantEngine, InvariantSet, authority_link_signature_message,
    provenance_signature_message,
};
#[cfg(feature = "runtime")]
pub use kernel::{ActionRequest, AdjudicationContext, Kernel, Verdict};
#[cfg(feature = "runtime")]
pub use mcp::{McpContext, McpRule, McpViolation};
#[cfg(feature = "runtime")]
pub use mcp_audit::{McpAuditLog, McpAuditRecord, McpEnforcementOutcome};
#[cfg(feature = "runtime")]
pub use tee::{TeeAttestation, TeePlatform, TeePolicy};
