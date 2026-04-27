//! # EXOCHAIN zero-knowledge proof skeleton — **UNAUDITED**.
//!
//! ## ⚠️ NOT PRODUCTION CRYPTOGRAPHY
//!
//! This crate is a pedagogical / structural implementation demonstrating
//! the *shape* of a SNARK / STARK / ZKML proof system. It uses blake3
//! "stand-ins" for elliptic curve points and has not been reviewed by a
//! cryptographer. **Do not rely on it for any production trust claim.**
//!
//! By constitutional rule (EXOCHAIN "never stub" doctrine), every public
//! entry point refuses to execute unless the opt-in Cargo feature
//! `unaudited-pedagogical-proofs` is enabled. Callers who accidentally
//! depend on this crate will fail loudly with
//! [`error::ProofError::UnauditedImplementation`] instead of silently
//! trusting a fake proof.
//!
//! When a production-hardened proof backend lands, remove the feature
//! flag and delete the `UnauditedImplementation` variant.
//!
//! ## Modules
//!
//! - R1CS circuit abstraction (`circuit`)
//! - SNARK proof generation/verification (`snark`) — skeleton
//! - STARK proof system (`stark`) — skeleton
//! - Zero-knowledge ML verification (`zkml`) — skeleton
//! - Unified proof verifier (`verifier`)
//!
//! ## Usage
//!
//! ```toml
//! # Cargo.toml — for tests/demos only
//! [dependencies]
//! exo-proofs = { path = "...", features = ["unaudited-pedagogical-proofs"] }
//! ```
//!
//! Without the feature, every call returns `Err(UnauditedImplementation)`.
//! This is intentional.

pub mod circuit;
pub mod error;
pub mod snark;
pub mod stark;
pub mod verifier;
pub mod zkml;

/// Internal guard used by every public entry point. Returns an error
/// unless the `unaudited-pedagogical-proofs` feature is enabled.
#[doc(hidden)]
#[inline]
pub fn guard_unaudited(api: &'static str) -> Result<(), error::ProofError> {
    #[cfg(feature = "unaudited-pedagogical-proofs")]
    {
        let _ = api;
        Ok(())
    }
    #[cfg(not(feature = "unaudited-pedagogical-proofs"))]
    {
        Err(error::ProofError::UnauditedImplementation { api })
    }
}
