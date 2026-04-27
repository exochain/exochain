//! Shared API types — re-exports and API-specific additions.
pub use exo_core::{Did, Hash256, Signature, Timestamp};
use serde::{Deserialize, Serialize};

/// An API version identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiVersion(pub String);

impl Default for ApiVersion {
    fn default() -> Self {
        Self("v1".into())
    }
}

/// Pagination cursor for list endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor(pub String);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn api_version_default() {
        assert_eq!(ApiVersion::default().0, "v1");
    }
    #[test]
    fn cursor_serde() {
        let c = Cursor("abc".into());
        let j = serde_json::to_string(&c).unwrap();
        let r: Cursor = serde_json::from_str(&j).unwrap();
        assert_eq!(r, c);
    }
}
