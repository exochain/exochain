//! `exochain://constitution` — the constitutional text hashed as the kernel hash.
//!
//! The kernel in [`crate::mcp::middleware::ConstitutionalMiddleware`] initializes
//! its BLAKE3 hash over this exact byte sequence. This resource exposes that same
//! text so clients can verify the hash end-to-end.

use crate::mcp::{
    context::NodeContext,
    protocol::{ResourceContent, ResourceDefinition},
};

/// The canonical constitution text hashed by the CGR Kernel.
///
/// IMPORTANT: this must match `ConstitutionalMiddleware::new` exactly or
/// the kernel integrity check will fail.
pub const CONSTITUTION_TEXT: &[u8] = b"EXOCHAIN Constitutional Trust Fabric";

/// Build the resource definition.
#[must_use]
pub fn definition() -> ResourceDefinition {
    ResourceDefinition {
        uri: "exochain://constitution".into(),
        name: "EXOCHAIN Constitution".into(),
        description: Some(
            "The canonical constitutional text hashed by the CGR Kernel as the \
             root of trust for the EXOCHAIN fabric. Clients can BLAKE3-hash this \
             text to independently verify the kernel's constitutional hash."
                .into(),
        ),
        mime_type: Some("text/plain".into()),
    }
}

/// Read the resource contents.
#[must_use]
pub fn read(_context: &NodeContext) -> ResourceContent {
    // Safe: CONSTITUTION_TEXT is a compile-time ASCII literal.
    let text = std::str::from_utf8(CONSTITUTION_TEXT)
        .unwrap_or("EXOCHAIN Constitutional Trust Fabric")
        .to_string();

    ResourceContent {
        uri: "exochain://constitution".into(),
        mime_type: Some("text/plain".into()),
        text: Some(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_has_uri_and_name() {
        let def = definition();
        assert_eq!(def.uri, "exochain://constitution");
        assert!(!def.name.is_empty());
        assert_eq!(def.mime_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn read_returns_non_empty_text() {
        let content = read(&NodeContext::empty());
        assert_eq!(content.uri, "exochain://constitution");
        let text = content.text.expect("text present");
        assert!(!text.is_empty());
        assert_eq!(text.as_bytes(), CONSTITUTION_TEXT);
    }

    #[test]
    fn constitution_hash_matches_kernel() {
        // The same bytes are passed to `Kernel::new(...)` — any drift will
        // break every kernel integrity check on startup.
        let expected = exo_core::Hash256::digest(CONSTITUTION_TEXT);
        let other = exo_core::Hash256::digest(b"EXOCHAIN Constitutional Trust Fabric");
        assert_eq!(expected, other);
    }
}
