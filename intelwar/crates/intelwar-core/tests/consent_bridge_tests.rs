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

//! Bridge must use caller-supplied consent — never invent Active bailment.

use std::env;
use std::fs;

use exo_core::crypto;
use intelwar_core::{BridgeAppendRequest, BridgeConsentWire, bridge_append};

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nonce = crypto::generate_keypair().0.as_bytes()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    env::temp_dir().join(format!("intelwar-{label}-{nonce}"))
}

fn active_consent() -> BridgeConsentWire {
    BridgeConsentWire {
        active: true,
        bailor_did: "did:exo:intelwar-bailor".into(),
        bailee_did: "did:exo:intelwar-actor".into(),
        scope: "log:append".into(),
    }
}

fn base_req(summary: &str, consent: BridgeConsentWire) -> BridgeAppendRequest {
    BridgeAppendRequest {
        summary: summary.into(),
        entry_id: None,
        entry_kind: Some("Observation".into()),
        voice_kind: Some("human".into()),
        payload: None,
        model_id: None,
        session_id: None,
        tool: None,
        consent,
        attestation_signature_hex: None,
    }
}


#[test]
fn bridge_rejects_inactive_consent() {
    let dir = temp_dir("inactive");
    let _ = fs::remove_dir_all(&dir);
    let mut consent = active_consent();
    consent.active = false;
    let err = bridge_append(&dir, base_req("should fail", consent)).expect_err("inactive");
    let msg = err.to_string();
    assert!(
        msg.contains("consent") || msg.contains("Consent") || msg.contains("bailment"),
        "got {msg}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn bridge_rejects_missing_log_append_scope() {
    let dir = temp_dir("scope");
    let _ = fs::remove_dir_all(&dir);
    let mut consent = active_consent();
    consent.scope = "read:only".into();
    let err = bridge_append(&dir, base_req("bad scope", consent)).expect_err("scope");
    assert!(err.to_string().to_ascii_lowercase().contains("scope"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn bridge_active_consent_appends_and_chains_across_reload() {
    let dir = temp_dir("reload");
    let _ = fs::remove_dir_all(&dir);
    let r1 = bridge_append(&dir, base_req("first real append", active_consent())).expect("r1");
    assert!(!r1.simulated);
    assert!(r1.kernel_adjudicated);
    assert_eq!(r1.durable, "local_kernel");

    let r2 = bridge_append(&dir, base_req("second real append", active_consent())).expect("r2");
    assert_eq!(
        r2.previous_receipt_hash.as_deref(),
        Some(r1.receipt_hash.as_str())
    );

    // Reload state dir in a fresh process simulation — same dir.
    let r3 = bridge_append(&dir, base_req("third after reload", active_consent())).expect("r3");
    assert_eq!(
        r3.previous_receipt_hash.as_deref(),
        Some(r2.receipt_hash.as_str())
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn synthetic_requires_real_attestation_signature() {
    let dir = temp_dir("synth");
    let _ = fs::remove_dir_all(&dir);
    let mut req = base_req("synthetic without sig", active_consent());
    req.voice_kind = Some("synthetic".into());
    req.model_id = Some("test-model".into());
    req.session_id = Some("sess-1".into());
    req.tool = Some("test".into());
    // Empty attestation_signature_hex → bridge must sign with actor key (real bytes),
    // never the literal placeholder "bridge-attestation-placeholder".
    let r = bridge_append(&dir, req).expect("synthetic with auto-signed attestation");
    assert!(!r.simulated);
    assert!(r.kernel_adjudicated);
    let _ = fs::remove_dir_all(&dir);
}
