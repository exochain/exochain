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

//! CLI: stdin JSON draft + secret_key_hex → signed CrossCheckResult wire JSON.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::io::{self, Read};
use std::process::ExitCode;

use exo_core::{Did, Hash256, SecretKey, crypto};
use intelwar_core::{
    CrossCheckResult, CrossCheckVerdict, VoiceKind, sign_crosscheck,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
struct SignRequest {
    checker_did: String,
    subject_entry_hash_hex: String,
    verdict: String,
    evidence_hash_hex: String,
    voice_kind: String,
    /// 64-char hex Ed25519 secret key.
    secret_key_hex: String,
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
    let req: SignRequest = match serde_json::from_str(stdin.trim()) {
        Ok(v) => v,
        Err(err) => {
            emit_err("invalid_json", &err.to_string());
            return Err(ExitCode::from(2));
        }
    };

    let checker = Did::new(&req.checker_did).map_err(|e| {
        emit_err("invalid_checker_did", &e.to_string());
        ExitCode::from(2)
    })?;
    let subject = hash_from_hex(&req.subject_entry_hash_hex).map_err(|e| {
        emit_err("invalid_subject_hash", &e);
        ExitCode::from(2)
    })?;
    let evidence = hash_from_hex(&req.evidence_hash_hex).map_err(|e| {
        emit_err("invalid_evidence_hash", &e);
        ExitCode::from(2)
    })?;
    let verdict = parse_verdict(&req.verdict).map_err(|e| {
        emit_err("invalid_verdict", &e);
        ExitCode::from(2)
    })?;
    let voice = parse_voice(&req.voice_kind).map_err(|e| {
        emit_err("invalid_voice_kind", &e);
        ExitCode::from(2)
    })?;
    let sk_bytes = hex_to_32(&req.secret_key_hex).map_err(|e| {
        emit_err("invalid_secret_key", &e);
        ExitCode::from(2)
    })?;
    let sk = SecretKey::from_bytes(sk_bytes);
    let pk = crypto::KeyPair::from_secret_bytes(sk_bytes)
        .map_err(|e| {
            emit_err("keypair_failed", &e.to_string());
            ExitCode::from(2)
        })?
        .public;

    let mut result = CrossCheckResult {
        checker_did: checker,
        subject_entry_hash: subject,
        verdict,
        evidence_hash: evidence,
        voice_kind: voice,
        signature: Vec::new(),
    };
    if let Err(err) = sign_crosscheck(&mut result, &sk) {
        emit_err("sign_failed", &err.to_string());
        return Err(ExitCode::from(1));
    }

    let out = json!({
        "ok": true,
        "simulated": false,
        "core_signed": true,
        "checker_did": result.checker_did.to_string(),
        "subject_entry_hash_hex": bytes_to_hex(result.subject_entry_hash.as_bytes()),
        "verdict": req.verdict,
        "evidence_hash_hex": bytes_to_hex(result.evidence_hash.as_bytes()),
        "voice_kind": req.voice_kind,
        "signature_hex": bytes_to_hex(&result.signature),
        "public_key_hex": bytes_to_hex(pk.as_bytes()),
    });
    println!("{out}");
    Ok(())
}

fn parse_verdict(raw: &str) -> Result<CrossCheckVerdict, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "agree" => Ok(CrossCheckVerdict::Agree),
        "disagree" => Ok(CrossCheckVerdict::Disagree),
        "abstain" => Ok(CrossCheckVerdict::Abstain),
        other => Err(format!("unsupported verdict: {other}")),
    }
}

fn parse_voice(raw: &str) -> Result<VoiceKind, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "human" => Ok(VoiceKind::Human),
        "synthetic" => Ok(VoiceKind::Synthetic),
        "system" => Ok(VoiceKind::System),
        other => Err(format!("unsupported voice_kind: {other}")),
    }
}

fn hash_from_hex(hex: &str) -> Result<Hash256, String> {
    Ok(Hash256::from_bytes(hex_to_32(hex)?))
}

fn hex_to_32(hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex_to_bytes(hex)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected 32 bytes, got {}", bytes.len()))
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
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

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn emit_err(error: &str, message: &str) {
    let body = json!({
        "ok": false,
        "simulated": false,
        "error": error,
        "message": message,
    });
    eprintln!("{body}");
}
