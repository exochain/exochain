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

//! Runtime context for MCP tools — provides access to live node state.

use std::sync::{Arc, Mutex};

use crate::{network::NetworkHandle, reactor::SharedReactorState, store::SqliteDagStore};

/// Named capability profile gating any node-attached MCP mutation path.
///
/// Ratified D2 (`GAP-REGISTRY.md`, 2026-07-02) commits the MCP runtime to a
/// **standalone process behind an authenticated, read-scoped RPC bridge** as
/// the end state — the adjudicator (consensus) and the adjudicated (a
/// governance proposal submitted via MCP) must never share a process
/// boundary. That bridge is not built by this lane (VCG-004b).
///
/// Until the bridge lands, an MCP server MAY run attached to a live node
/// process (sharing its reactor state, DAG store, and network handle) only
/// under an explicitly named, interim capability profile. This enum exists
/// so that "node-attached" is never an implicit default: a caller must name
/// the interim mode, and the name is available for audit logging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum McpCapabilityProfile {
    /// Interim, explicitly-named node-attached mutation mode.
    ///
    /// `name` identifies the specific deployment/operator profile that
    /// authorized running MCP attached to a live node ahead of the D2
    /// standalone RPC bridge (e.g. `"vcg-004b-node-attached-interim"`).
    /// Mutations routed under this profile still go through
    /// `reactor::submit_proposal` — a proposal independently adjudicated by
    /// BFT consensus — so the MCP caller never adjudicates its own
    /// proposal, preserving the adjudicator/adjudicated separation even
    /// while the process boundary is not yet split out.
    ///
    /// Not yet constructed by any production call site: no node-attached
    /// `McpServer` construction path exists yet in `main.rs` (the standalone
    /// `exochain mcp` command's `mcp_node_context_from_env` deliberately
    /// leaves this `None`, keeping it fail-closed). This variant, and the
    /// `NodeContext` fields it gates, exist so the interim mutation-routing
    /// contract in `mcp/tools/governance.rs` has a concrete shape to dispatch
    /// on; wiring an actual node-attached server entry point is follow-on
    /// work, not VCG-004b's scope.
    #[allow(dead_code)]
    NodeAttachedInterim { name: String },
}

/// Operator-supplied DAG DB gateway proxy configuration for MCP tools.
///
/// Present only when the `dagdb-gateway-proxy` feature is compiled. Empty
/// fields are rejected by the DAG DB tool dispatch before any HTTP request is
/// attempted.
#[cfg(feature = "dagdb-gateway-proxy")]
#[derive(Clone, Default)]
pub struct DagDbGatewayConfig {
    /// Gateway origin, for example `https://gateway.example.com`.
    pub base_url: Option<String>,
    /// Bearer token used by the SDK transport.
    pub bearer_token: Option<zeroize::Zeroizing<String>>,
    /// Tenant id authorized for this MCP proxy context.
    pub tenant_id: Option<String>,
    /// Namespace authorized for this MCP proxy context.
    pub namespace: Option<String>,
}

#[cfg(feature = "dagdb-gateway-proxy")]
impl DagDbGatewayConfig {
    #[must_use]
    pub fn new(
        base_url: impl Into<String>,
        bearer_token: impl Into<String>,
        tenant_id: impl Into<String>,
        namespace: impl Into<String>,
    ) -> Self {
        Self {
            base_url: Some(base_url.into()),
            bearer_token: Some(zeroize::Zeroizing::new(bearer_token.into())),
            tenant_id: Some(tenant_id.into()),
            namespace: Some(namespace.into()),
        }
    }
}

/// Shared runtime context available to MCP tools.
///
/// Wraps the node's live state in a thread-safe, clonable handle that
/// tool implementations can query. All fields are optional so the MCP
/// server can also run in a pure-stdio mode without a full node.
#[derive(Clone, Default)]
pub struct NodeContext {
    /// Shared consensus reactor state (round, height, validators).
    pub reactor_state: Option<SharedReactorState>,
    /// Shared DAG store (event persistence, checkpoints).
    pub store: Option<Arc<Mutex<SqliteDagStore>>>,
    /// The node's own DID string.
    pub node_did: Option<String>,
    /// Opt-in DAG DB gateway proxy configuration.
    #[cfg(feature = "dagdb-gateway-proxy")]
    pub dagdb_gateway: Option<DagDbGatewayConfig>,
    /// Live network handle for broadcasting governance proposals.
    ///
    /// Present only in the interim node-attached mutation mode (see
    /// [`McpCapabilityProfile`]). The standalone `exochain mcp` command
    /// (`mcp_node_context_from_env` in `main.rs`) never populates this — it
    /// stays `None`, keeping that path fail-closed for all mutation tools.
    pub net_handle: Option<Arc<NetworkHandle>>,
    /// Named capability profile authorizing a node-attached mutation mode.
    ///
    /// `None` in the standalone (default, D2 committed-end-state-adjacent)
    /// path. Must be `Some(McpCapabilityProfile::NodeAttachedInterim {..})`
    /// for [`NodeContext::is_node_attached`] to return `true`.
    pub capability_profile: Option<McpCapabilityProfile>,
}

impl NodeContext {
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns whether a live reactor state is attached.
    ///
    /// Reserved for future tools that want to short-circuit when running
    /// without a reactor.
    #[must_use]
    #[allow(dead_code)]
    pub fn has_reactor(&self) -> bool {
        self.reactor_state.is_some()
    }

    #[must_use]
    pub fn has_store(&self) -> bool {
        self.store.is_some()
    }

    /// Returns whether this context is fully node-attached under the
    /// interim capability profile (VCG-004b / D2).
    ///
    /// `true` only when a live reactor state, DAG store, and network handle
    /// are ALL present AND an explicit
    /// `McpCapabilityProfile::NodeAttachedInterim` profile is recorded.
    /// Governance mutation tools consult this to decide whether to route
    /// through `reactor::submit_proposal` (node-attached) or keep refusing
    /// via `governance_runtime_unavailable` (standalone, the default).
    #[must_use]
    pub fn is_node_attached(&self) -> bool {
        self.reactor_state.is_some()
            && self.store.is_some()
            && self.net_handle.is_some()
            && matches!(
                self.capability_profile,
                Some(McpCapabilityProfile::NodeAttachedInterim { .. })
            )
    }
}
