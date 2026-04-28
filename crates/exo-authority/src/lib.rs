//! EXOCHAIN Authority Chain Verification and Delegation Management
//!
//! Authority chains track the delegation of permissions from root to leaf.
//! Scope can only narrow through delegation, never widen.

pub mod cache;
pub mod chain;
pub mod delegation;
pub mod error;
pub mod permission;

pub use cache::ChainCache;
pub use chain::{AuthorityChain, AuthorityLink, DelegateeKind};
pub use delegation::{AuthorityRevocation, DelegationRegistry, DelegationRevocationGrant};
pub use error::AuthorityError;
pub use permission::{Permission, PermissionSet};
