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

//! Command-line interface for the exochain node.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub const DEFAULT_ROUND_TIMEOUT_MS: u64 = 5_000;
pub const MIN_ROUND_TIMEOUT_MS: u64 = 250;
pub const MAX_ROUND_TIMEOUT_MS: u64 = 300_000;

fn parse_round_timeout_ms(value: &str) -> Result<u64, String> {
    let timeout_ms = value
        .parse::<u64>()
        .map_err(|error| format!("round timeout must be a millisecond integer: {error}"))?;
    if !(MIN_ROUND_TIMEOUT_MS..=MAX_ROUND_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(format!(
            "round timeout must be between {MIN_ROUND_TIMEOUT_MS} and {MAX_ROUND_TIMEOUT_MS} milliseconds"
        ));
    }
    Ok(timeout_ms)
}

#[derive(Parser)]
#[command(
    name = "exochain",
    about = "EXOCHAIN distributed constitutional governance node",
    version,
    propagate_version = true
)]
/// Top-level CLI argument parser for the exochain node.
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
/// Subcommands available to the exochain node (start, join, status, peers).
pub enum Command {
    /// Start a standalone node.
    Start {
        /// HTTP API port.
        #[arg(long, default_value = None)]
        api_port: Option<u16>,

        /// HTTP API bind host. Default is `127.0.0.1` (loopback only).
        /// Set to `0.0.0.0` to expose the admin-write API on all
        /// interfaces — do so ONLY when you have a front-door TLS
        /// terminator AND your admin bearer token is appropriately
        /// scoped (see auth.rs). Exposing 0.0.0.0 with the default
        /// bearer model is equivalent to publishing your node's
        /// governance-write credential on the open internet.
        #[arg(long, default_value = "127.0.0.1")]
        api_host: String,

        /// P2P listen port.
        #[arg(long, default_value = None)]
        p2p_port: Option<u16>,

        /// Consensus round timeout in milliseconds.
        #[arg(
            long,
            default_value_t = DEFAULT_ROUND_TIMEOUT_MS,
            value_parser = parse_round_timeout_ms
        )]
        round_timeout_ms: u64,

        /// Data directory (default: ~/.exochain).
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Run as a BFT consensus validator.
        #[arg(long, default_value_t = false)]
        validator: bool,

        /// Validator DIDs for the initial validator set (comma-separated).
        /// If not provided, this node's DID is used as the sole validator.
        #[arg(long, value_delimiter = ',')]
        validators: Option<Vec<String>>,

        /// Validator public keys as `did:exo:...=<64 hex bytes>` entries.
        /// Required for every non-local validator DID because consensus
        /// proposals/votes/certificates are verified against these keys.
        #[arg(long = "validator-public-key", value_delimiter = ',')]
        validator_public_keys: Option<Vec<String>>,
    },

    /// Join an existing network via seed node(s).
    Join {
        /// Seed node addresses (e.g., seed1.exochain.io:4001).
        #[arg(long, required = true, num_args = 1..)]
        seed: Vec<String>,

        /// HTTP API port.
        #[arg(long, default_value = None)]
        api_port: Option<u16>,

        /// HTTP API bind host. Default is `127.0.0.1` (loopback only).
        /// See `Start --api-host` for rationale on 0.0.0.0.
        #[arg(long, default_value = "127.0.0.1")]
        api_host: String,

        /// P2P listen port.
        #[arg(long, default_value = None)]
        p2p_port: Option<u16>,

        /// Consensus round timeout in milliseconds.
        #[arg(
            long,
            default_value_t = DEFAULT_ROUND_TIMEOUT_MS,
            value_parser = parse_round_timeout_ms
        )]
        round_timeout_ms: u64,

        /// Data directory (default: ~/.exochain).
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Run as a BFT consensus validator.
        #[arg(long, default_value_t = false)]
        validator: bool,

        /// Validator DIDs for the initial validator set (comma-separated).
        #[arg(long, value_delimiter = ',')]
        validators: Option<Vec<String>>,

        /// Validator public keys as `did:exo:...=<64 hex bytes>` entries.
        /// Required for every non-local validator DID because consensus
        /// proposals/votes/certificates are verified against these keys.
        #[arg(long = "validator-public-key", value_delimiter = ',')]
        validator_public_keys: Option<Vec<String>>,
    },

    /// Show node status.
    Status {
        /// Data directory (default: ~/.exochain).
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// List connected peers.
    Peers {
        /// Data directory (default: ~/.exochain).
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Start the MCP (Model Context Protocol) server on stdio or HTTP+SSE.
    /// Enables AI agents to interact with the governance fabric.
    Mcp {
        /// Data directory (default: ~/.exochain).
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// DID for the MCP actor. If not provided, uses the node's identity.
        #[arg(long)]
        actor_did: Option<String>,

        /// Use HTTP+SSE transport instead of stdio. The value is the bind
        /// address (host:port). Example: `--sse 127.0.0.1:3030`.
        #[arg(long)]
        sse: Option<String>,
    },
}
