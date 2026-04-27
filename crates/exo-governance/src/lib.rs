//! EXOCHAIN constitutional trust fabric — legislative legitimacy.
//!
//! This crate provides governance primitives: quorum computation with
//! independence-aware counting, clearance enforcement, crosscheck verification,
//! challenge mechanisms, deliberation processes, conflict detection,
//! hash-chained audit trails, typed custody chains, and shared governance types.

pub mod audit;
pub mod challenge;
pub mod clearance;
pub mod conflict;
pub mod constitution;
pub mod crosscheck;
pub mod custody;
pub mod delegation;
pub mod deliberation;
pub mod errors;
pub mod quorum;
pub mod succession;
pub mod types;

pub use errors::GovernanceError;
