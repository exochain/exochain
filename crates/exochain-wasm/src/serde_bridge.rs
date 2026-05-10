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

//! Serde bridge: JSON string ↔ Rust types ↔ JsValue

use serde::{Serialize, de::DeserializeOwned};
use wasm_bindgen::prelude::*;

pub const MAX_JSON_INPUT_BYTES: usize = 1_048_576;

#[cfg(all(test, not(target_arch = "wasm32")))]
fn bridge_error(_message: &str) -> JsValue {
    JsValue::NULL
}

#[cfg(not(all(test, not(target_arch = "wasm32"))))]
fn bridge_error(message: &str) -> JsValue {
    JsValue::from_str(message)
}

pub fn from_json_str<T: DeserializeOwned>(json: &str) -> Result<T, JsValue> {
    if json.len() > MAX_JSON_INPUT_BYTES {
        return Err(bridge_error("JSON input exceeds maximum size"));
    }
    serde_json::from_str(json).map_err(|_| bridge_error("JSON parse error"))
}

pub fn from_json_bounded_vec<T: DeserializeOwned>(
    json: &str,
    label: &str,
    max_items: usize,
) -> Result<Vec<T>, JsValue> {
    let values: Vec<T> = from_json_str(json)?;
    if values.len() > max_items {
        return Err(bridge_error(&format!(
            "{label} contains {} items, maximum is {max_items}",
            values.len()
        )));
    }
    Ok(values)
}

pub fn to_js_value<T: Serialize>(val: &T) -> Result<JsValue, JsValue> {
    // Go through JSON string → js_sys::JSON::parse to get plain JS objects (not Maps)
    let json = serde_json::to_string(val).map_err(|_| bridge_error("Serialization error"))?;
    js_sys::JSON::parse(&json)
}

// ===========================================================================
// Tests — native Rust (no wasm32 target required)
//
// Tests for from_json_str use serde_json directly, matching the same code
// path used by the bridge.  to_js_value cannot be tested natively because
// js_sys::JSON::parse is WASM-only; those tests belong in wasm-pack tests.
// ===========================================================================

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    /// Call the deserialization half of the bridge through serde_json,
    /// exercising the same error path as `from_json_str`.
    fn round_trip_deserialize<
        T: for<'de> Deserialize<'de> + Serialize + PartialEq + std::fmt::Debug,
    >(
        value: &T,
    ) -> T {
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Simple {
        name: String,
        value: u64,
    }

    #[test]
    fn round_trip_simple_struct() {
        let original = Simple {
            name: "exochain".to_string(),
            value: 42,
        };
        assert_eq!(round_trip_deserialize(&original), original);
    }

    #[test]
    fn deserialize_invalid_json_returns_error() {
        let result: Result<Simple, _> = serde_json::from_str("{not valid json}");
        assert!(result.is_err(), "invalid JSON must return an error");
    }

    #[test]
    fn deserialize_wrong_type_returns_error() {
        // `value` field expects u64 but is given a string
        let result: Result<Simple, _> = serde_json::from_str(r#"{"name":"x","value":"oops"}"#);
        assert!(result.is_err(), "type mismatch must return an error");
    }

    #[test]
    fn deserialize_missing_field_returns_error() {
        let result: Result<Simple, _> = serde_json::from_str(r#"{"name":"x"}"#);
        assert!(
            result.is_err(),
            "missing required field must return an error"
        );
    }

    #[test]
    fn from_json_str_rejects_oversized_inputs_before_deserialization() {
        let oversized = format!("[{}0]", "0,".repeat(600_000));
        let result: Result<Vec<u8>, _> = super::from_json_str(&oversized);
        assert!(result.is_err(), "oversized JSON must be rejected");
    }

    #[test]
    fn from_json_bounded_vec_accepts_limit_and_rejects_excess_items() {
        let at_limit = serde_json::to_string(&vec!["item"; 4]).expect("serialize");
        let accepted: Vec<String> =
            super::from_json_bounded_vec(&at_limit, "test items", 4).expect("at limit");
        assert_eq!(accepted.len(), 4);

        let over_limit = serde_json::to_string(&vec!["item"; 5]).expect("serialize");
        let rejected: Result<Vec<String>, _> =
            super::from_json_bounded_vec(&over_limit, "test items", 4);
        assert!(
            rejected.is_err(),
            "one item over the limit must fail closed"
        );
    }

    #[test]
    fn from_json_str_does_not_forward_serde_error_details() {
        let source = include_str!("serde_bridge.rs");
        assert!(
            !source.contains("format!(\"JSON parse error"),
            "serde_json error details must not cross the WASM boundary"
        );
    }

    #[test]
    fn serialize_produces_valid_json() {
        let val = Simple {
            name: "test".to_string(),
            value: 1,
        };
        let json = serde_json::to_string(&val).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["name"], "test");
        assert_eq!(parsed["value"], 1u64);
    }

    #[test]
    fn round_trip_vec_of_structs() {
        let items = vec![
            Simple {
                name: "a".into(),
                value: 1,
            },
            Simple {
                name: "b".into(),
                value: 2,
            },
        ];
        assert_eq!(round_trip_deserialize(&items), items);
    }

    #[test]
    fn round_trip_option_some() {
        let val: Option<Simple> = Some(Simple {
            name: "x".into(),
            value: 0,
        });
        assert_eq!(round_trip_deserialize(&val), val);
    }

    #[test]
    fn round_trip_option_none() {
        let val: Option<Simple> = None;
        assert_eq!(round_trip_deserialize(&val), val);
    }

    /// Verify that gatekeeper types used across the WASM bridge round-trip
    /// through JSON without loss.
    #[test]
    fn gatekeeper_permission_set_round_trips() {
        use exo_gatekeeper::types::{Permission, PermissionSet};
        let ps = PermissionSet::new(vec![Permission::new("read"), Permission::new("write")]);
        let json = serde_json::to_string(&ps).expect("serialize");
        let restored: PermissionSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ps, restored);
    }

    #[test]
    fn gatekeeper_authority_chain_round_trips() {
        use exo_gatekeeper::types::AuthorityChain;
        let chain = AuthorityChain::default();
        let json = serde_json::to_string(&chain).expect("serialize");
        let restored: AuthorityChain = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(chain, restored);
    }

    #[test]
    fn gatekeeper_bailment_state_round_trips() {
        use exo_core::Did;
        use exo_gatekeeper::types::BailmentState;
        let state = BailmentState::Active {
            bailor: Did::new("did:exo:bailor").expect("valid"),
            bailee: Did::new("did:exo:bailee").expect("valid"),
            scope: "data".to_string(),
        };
        let json = serde_json::to_string(&state).expect("serialize");
        let restored: BailmentState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, restored);
    }
}
