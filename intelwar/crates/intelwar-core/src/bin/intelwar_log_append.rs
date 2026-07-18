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

//! CLI bridge: stdin JSON → Kernel-gated Living Log append → stdout JSON.
//!
//! Env:
//! - `INTELWAR_CORE_STATE_DIR` (default: `.intelwar-bridge-state`)

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::env;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use intelwar_core::{BridgeAppendRequest, bridge_append};
use serde_json::json;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn run() -> Result<(), ExitCode> {
    let state_dir = env::var("INTELWAR_CORE_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".intelwar-bridge-state"));

    let mut stdin = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut stdin) {
        emit_err("stdin_read_failed", &err.to_string());
        return Err(ExitCode::from(2));
    }

    let req: BridgeAppendRequest = match serde_json::from_str(stdin.trim()) {
        Ok(v) => v,
        Err(err) => {
            emit_err("invalid_json", &err.to_string());
            return Err(ExitCode::from(2));
        }
    };

    match bridge_append(&state_dir, req) {
        Ok(resp) => match serde_json::to_string(&resp) {
            Ok(out) => {
                println!("{out}");
                Ok(())
            }
            Err(err) => {
                emit_err("serialize_failed", &err.to_string());
                Err(ExitCode::from(3))
            }
        },
        Err(err) => {
            emit_err("kernel_append_failed", &err.to_string());
            Err(ExitCode::from(1))
        }
    }
}

fn emit_err(error: &str, message: &str) {
    let body = json!({
        "ok": false,
        "simulated": false,
        "kernel_adjudicated": false,
        "error": error,
        "message": message,
    });
    eprintln!("{body}");
}
