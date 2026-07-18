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

//! CLI: stdin JSON → verify CrossCheckResult set → stdout JSON (PM-004).

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::process::ExitCode;

use exo_core::{Did, Hash256};
use exo_gatekeeper::types::TrustedProvenanceKeys;
use intelwar_core::{
    CrossCheckResult, CrossCheckVerdict, VoiceKind, crosschecks_satisfy,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
struct CrossCheckWire {
    checker_did: String,
    subject_entry_hash_hex: String,
    verdict: String,
    evidence_hash_hex: String,
    voice_kind: String,
    signature_hex: String,
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    author_did: String,
    subject_entry_hash_hex: String,
    crosschecks: Vec<CrossCheckWire>,
    /// DID → list of 32-byte public keys as hex.
    trusted_checker_keys_hex: BTreeMap<String, Vec<String>>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn run() -> Result<(), ExitCode> {
    let mut stdin = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut stdin) {
        emit_err("stdin_read_failed", &err.to_string());
        return Err(ExitCode::from(2));
    }

    let req: VerifyRequest = match serde_json::from_str(stdin.trim()) {
        Ok(v) => v,
        Err(err) => {
            emit_err("invalid_json", &err.to_string());
            return Err(ExitCode::from(2));
        }
    };

    let author = match Did::new(&req.author_did) {
        Ok(d) => d,
        Err(err) => {
            emit_err("invalid_author_did", &err.to_string());
            return Err(ExitCode::from(2));
        }
    };
    let subject = match hash_from_hex(&req.subject_entry_hash_hex) {
        Ok(h) => h,
        Err(err) => {
            emit_err("invalid_subject_hash", &err);
            return Err(ExitCode::from(2));
        }
    };

    let mut crosschecks = Vec::with_capacity(req.crosschecks.len());
    for (idx, wire) in req.crosschecks.iter().enumerate() {
        match wire_to_result(wire) {
            Ok(r) => crosschecks.push(r),
            Err(err) => {
                emit_err("invalid_crosscheck", &format!("index {idx}: {err}"));
                return Err(ExitCode::from(2));
            }
        }
    }

    let mut trusted = TrustedProvenanceKeys::default();
    for (did_str, key_hexes) in &req.trusted_checker_keys_hex {
        let did = match Did::new(did_str) {
            Ok(d) => d,
            Err(err) => {
                emit_err("invalid_checker_did", &err.to_string());
                return Err(ExitCode::from(2));
            }
        };
        let mut keys = Vec::new();
        for hex in key_hexes {
            match bytes_from_hex(hex) {
                Ok(b) => keys.push(b),
                Err(err) => {
                    emit_err("invalid_checker_key_hex", &err);
                    return Err(ExitCode::from(2));
                }
            }
        }
        trusted.insert(did, keys);
    }

    match crosschecks_satisfy(&author, &subject, &crosschecks, &trusted) {
        Ok(()) => {
            println!(
                "{}",
                json!({
                    "ok": true,
                    "simulated": false,
                    "core_verified": true,
                    "count": crosschecks.len(),
                })
            );
            Ok(())
        }
        Err(err) => {
            emit_err("crosscheck_verify_failed", &err.to_string());
            Err(ExitCode::from(1))
        }
    }
}

fn wire_to_result(wire: &CrossCheckWire) -> Result<CrossCheckResult, String> {
    let verdict = match wire.verdict.as_str() {
        "agree" => CrossCheckVerdict::Agree,
        "disagree" => CrossCheckVerdict::Disagree,
        "abstain" => CrossCheckVerdict::Abstain,
        other => return Err(format!("unknown verdict {other}")),
    };
    let voice_kind = match wire.voice_kind.as_str() {
        "human" => VoiceKind::Human,
        "synthetic" => VoiceKind::Synthetic,
        "system" => VoiceKind::System,
        other => return Err(format!("unknown voice_kind {other}")),
    };
    Ok(CrossCheckResult {
        checker_did: Did::new(&wire.checker_did).map_err(|e| e.to_string())?,
        subject_entry_hash: hash_from_hex(&wire.subject_entry_hash_hex)?,
        verdict,
        evidence_hash: hash_from_hex(&wire.evidence_hash_hex)?,
        voice_kind,
        signature: bytes_from_hex(&wire.signature_hex)?,
    })
}

fn emit_err(error: &str, message: &str) {
    println!(
        "{}",
        json!({
            "ok": false,
            "simulated": false,
            "core_verified": false,
            "error": error,
            "message": message,
            "fail_closed": true,
        })
    );
}

fn hash_from_hex(hex: &str) -> Result<Hash256, String> {
    let bytes = bytes_from_hex(hex)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected 32 bytes, got {}", bytes.len()))?;
    Ok(Hash256::from_bytes(arr))
}

fn bytes_from_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("hex length must be even".into());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        out.push(u8::from_str_radix(s, 16).map_err(|e| e.to_string())?);
    }
    Ok(out)
}
