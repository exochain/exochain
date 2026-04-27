//! # EXOCHAIN SDK — Rust
//!
//! Ergonomic Rust API for the **EXOCHAIN constitutional governance fabric** — a
//! substrate for AI agents and data sovereignty built around decentralized
//! identifiers (DIDs), scoped consent (bailments), authority-chain delegation,
//! quorum-based governance, and a constitutional kernel that enforces policy
//! *before* action rather than auditing it after.
//!
//! This crate re-exports and wraps the underlying `exo-*` workspace crates
//! behind a single, developer-friendly surface so that applications built on
//! EXOCHAIN can depend on one crate and use one coherent API. Each domain lives
//! in its own module:
//!
//! - [`identity`] — DID-backed Ed25519 identities with sign/verify.
//! - [`consent`] — scoped, time-bounded bailments (consent tokens).
//! - [`governance`] — decisions, voting, quorum checks.
//! - [`authority`] — validated delegation chains.
//! - [`kernel`] — the Constitutional Governance Runtime (CGR) kernel.
//! - [`crypto`] — hash / sign / verify primitives (BLAKE3 + Ed25519).
//! - [`error`] — the single [`error::ExoError`] type returned by fallible ops.
//!
//! ## Why use this SDK
//!
//! EXOCHAIN turns policy into a *precondition* of action. Instead of shipping
//! agents that do things and asking an auditor to catch violations, you
//! express identity, consent, and delegation as first-class cryptographic
//! objects and ask the kernel whether an action is permitted. If the
//! [`kernel::ConstitutionalKernel`] denies an action, the action never runs.
//!
//! This SDK gives you:
//!
//! - Deterministic, content-addressed IDs for every object (bailments,
//!   decisions, chains) so two parties independently building the same object
//!   get the same ID.
//! - Builder APIs that validate on `build()` so invalid states are not
//!   representable downstream.
//! - Pure types (no I/O) suitable for offline governance, test vectors, and
//!   cross-language interop with the TypeScript and Python SDKs.
//!
//! ## End-to-end example
//!
//! The canonical lifecycle: two identities negotiate a bailment, propose a
//! decision, reach quorum, build a delegation chain, and submit an action to
//! the kernel for adjudication.
//!
//! ```
//! use exochain_sdk::prelude::*;
//! use exochain_sdk::governance::VoteChoice;
//!
//! // 1. Create identities for alice and bob.
//! let alice = Identity::generate("alice");
//! let bob = Identity::generate("bob");
//! assert!(alice.did().as_str().starts_with("did:exo:"));
//! assert_ne!(alice.did(), bob.did());
//!
//! // 2. Alice proposes a scoped bailment to bob.
//! let proposal = BailmentBuilder::new(alice.did().clone(), bob.did().clone())
//!     .scope("data:medical")
//!     .duration_hours(24)
//!     .build()?;
//! assert_eq!(proposal.scope, "data:medical");
//! assert_eq!(proposal.proposal_id.len(), 16);
//!
//! // 3. Alice proposes a decision; bob and a third voter approve.
//! let carol = Identity::generate("carol");
//! let mut decision = DecisionBuilder::new(
//!     "Ratify bailment",
//!     "Allow bob to read medical records for 24h",
//!     alice.did().clone(),
//! )
//! .build()?;
//! decision.cast_vote(Vote::new(bob.did().clone(), VoteChoice::Approve))?;
//! decision.cast_vote(Vote::new(carol.did().clone(), VoteChoice::Approve))?;
//! let quorum = decision.check_quorum(2);
//! assert!(quorum.met);
//! assert_eq!(quorum.approvals, 2);
//!
//! // 4. Build an authority chain: root -> alice -> bob.
//! let root = Identity::generate("root");
//! let chain = AuthorityChainBuilder::new()
//!     .add_link(root.did().clone(), alice.did().clone(), vec!["delegate".into()])
//!     .add_link(alice.did().clone(), bob.did().clone(), vec!["read".into()])
//!     .build(bob.did())?;
//! assert_eq!(chain.depth, 2);
//! assert_eq!(&chain.terminal, bob.did());
//!
//! // 5. Ask the kernel whether bob may perform the action.
//! // The SDK kernel requires caller-supplied authority signing material.
//! let kernel = ConstitutionalKernel::with_authority_identity(root);
//! let verdict = kernel.adjudicate(bob.did(), "data:medical:read");
//! assert!(verdict.is_permitted(), "expected Permitted, got {verdict:?}");
//! # Ok::<(), exochain_sdk::error::ExoError>(())
//! ```
//!
//! ## Prelude
//!
//! Most applications want the common builders, [`Identity`](identity::Identity),
//! the error type, and the kernel facade. Import the [`prelude`]:
//!
//! ```
//! use exochain_sdk::prelude::*;
//!
//! let id = Identity::generate("agent");
//! let sig = id.sign(b"payload");
//! assert!(id.verify(b"payload", &sig));
//! ```
//!
//! ## Error handling
//!
//! All fallible operations return [`error::ExoResult<T>`], an alias for
//! `Result<T, ExoError>`. Each [`error::ExoError`] variant narrows the failure
//! to a subsystem (consent, governance, authority, kernel, crypto, serialization)
//! so callers can pattern-match without parsing strings.
//!
//! ```
//! use exochain_sdk::prelude::*;
//! use exochain_sdk::error::ExoError;
//! # use exo_core::Did;
//!
//! let alice = Did::new("did:exo:alice").expect("valid");
//! let bob = Did::new("did:exo:bob").expect("valid");
//!
//! // Forgetting to set `scope` produces a Consent error:
//! let err = BailmentBuilder::new(alice, bob)
//!     .duration_hours(1)
//!     .build()
//!     .unwrap_err();
//! assert!(matches!(err, ExoError::Consent(_)));
//! ```
//!
//! ## Cross-language notes
//!
//! The SDK distinguishes local deterministic IDs from canonical fabric IDs.
//! [`identity::Identity::generate`] and [`identity::Identity::from_keypair`]
//! derive local Rust SDK DIDs from `BLAKE3(public_key)[..8]`. Other language
//! SDKs may use different local-only derivation primitives for zero-dependency
//! client operation.
//!
//! Applications that need canonical DIDs across languages should resolve the
//! DID from the fabric, then construct the local signing handle with
//! [`identity::Identity::from_resolved_keypair`]. That path preserves the
//! fabric DID and verifies that the supplied secret key matches the supplied
//! public key before constructing the identity.

#![deny(missing_docs)]

/// Fabric protocol version this SDK speaks (A-066).
///
/// Applications may probe a target gateway on init and warn when the
/// server reports a different major/minor so users can distinguish
/// protocol skew from transport errors. All three SDKs (Rust, TypeScript,
/// Python) expose a matching `PROTOCOL_VERSION` constant.
pub const PROTOCOL_VERSION: &str = "0.1.0-beta";

pub mod authority;
pub mod consent;
pub mod crypto;
pub mod error;
pub mod governance;
pub mod identity;
pub mod kernel;

/// Prelude — the symbols most applications want.
///
/// ```
/// use exochain_sdk::prelude::*;
///
/// let id = Identity::generate("agent");
/// let sig = id.sign(b"hello");
/// assert!(id.verify(b"hello", &sig));
/// ```
pub mod prelude {
    pub use crate::{
        authority::AuthorityChainBuilder,
        consent::BailmentBuilder,
        crypto::{hash, sign, verify},
        error::{ExoError, ExoResult},
        governance::{Decision, DecisionBuilder, Vote},
        identity::Identity,
        kernel::ConstitutionalKernel,
    };
}

#[cfg(test)]
mod tests {
    use super::PROTOCOL_VERSION;

    #[test]
    fn protocol_version_is_stable() {
        assert_eq!(PROTOCOL_VERSION, "0.1.0-beta");
    }
}
