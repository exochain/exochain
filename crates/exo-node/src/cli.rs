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
}
