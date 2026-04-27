//! Command-line interface for the exochain node.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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

        /// Data directory (default: ~/.exochain).
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Run as a BFT consensus validator.
        #[arg(long, default_value_t = false)]
        validator: bool,

        /// Validator DIDs for the initial validator set (comma-separated).
        #[arg(long, value_delimiter = ',')]
        validators: Option<Vec<String>>,
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
