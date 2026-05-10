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

pub mod combinator;
pub mod error;
pub mod governance_monitor;
pub mod holon;
pub mod invariants;
pub mod kernel;
pub mod mcp;
pub mod mcp_audit;
pub mod tee;
pub mod types;

// Re-export primary types.
pub use combinator::{Combinator, CombinatorInput, CombinatorOutput};
pub use error::GatekeeperError;
pub use governance_monitor::{
    ApprovalGate, ApprovalStatus, GovernanceAttestation, GovernanceCircuitBreaker,
    GovernanceMonitorError,
};
pub use holon::{Holon, HolonState};
pub use invariants::{
    ConstitutionalInvariant, InvariantEngine, InvariantSet, authority_link_signature_message,
    provenance_signature_message,
};
pub use kernel::{ActionRequest, AdjudicationContext, Kernel, Verdict};
pub use mcp::{McpContext, McpRule, McpViolation};
pub use mcp_audit::{McpAuditLog, McpAuditRecord, McpEnforcementOutcome};
pub use tee::{TeeAttestation, TeePlatform, TeePolicy};
