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

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! Offline evidence-pack verification for JS / CommandBase.

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

/// Independently verify an `exochain-evidence-pack-v1` JSON document.
///
/// Does not talk to a node and never moves money. Returns
/// `{ok: true, ...}` or `{ok: false, error: "..."}`.
#[wasm_bindgen]
pub fn wasm_verify_evidence_pack(pack_json: &str) -> Result<JsValue, JsValue> {
    let pack: exo_pdp::EvidencePack = from_json_str(pack_json)?;
    match pack.verify() {
        Ok(()) => to_js_value(&serde_json::json!({
            "ok": true,
            "independently_verifiable": true,
            "never_moves_money": true,
            "spec": pack.spec,
            "entries": pack.entries.len(),
            "article_26": pack.article_26,
            "tip": pack.tip_hex,
        })),
        Err(e) => to_js_value(&serde_json::json!({
            "ok": false,
            "error": e.to_string(),
            "never_moves_money": true,
        })),
    }
}
