//! Serde bridge: JSON string ↔ Rust types ↔ JsValue

use serde::{Serialize, de::DeserializeOwned};
use wasm_bindgen::prelude::*;

pub fn from_json_str<T: DeserializeOwned>(json: &str) -> Result<T, JsValue> {
    serde_json::from_str(json).map_err(|e| JsValue::from_str(&format!("JSON parse error: {e}")))
}

pub fn to_js_value<T: Serialize>(val: &T) -> Result<JsValue, JsValue> {
    // Go through JSON string → js_sys::JSON::parse to get plain JS objects (not Maps)
    let json = serde_json::to_string(val)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))?;
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
