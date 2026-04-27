//! # decision-forum
//!
//! EXOCHAIN decision.forum — the USER-FACING governance application that
//! orchestrates all lower-level exochain primitives into a complete
//! constitutional decision governance system.
//!
//! ## Modules
//!
//! - [`decision_object`] — Core domain type with 14-state BCTS lifecycle
//! - [`constitution`] — Per-tenant machine-readable constitutional corpus
//! - [`authority`] — Forum authority verification
//! - [`authority_matrix`] — Real-time delegated authority matrix (GOV-003)
//! - [`human_gate`] — Human oversight enforcement (GOV-007, TNC-02)
//! - [`contestation`] — Structured contestation and reversal (GOV-008)
//! - [`emergency`] — Emergency action protocol (GOV-009)
//! - [`quorum`] — Quorum management (GOV-010, TNC-07)
//! - [`accountability`] — Accountability mechanisms (GOV-012)
//! - [`self_governance`] — Recursive self-governance (GOV-013)
//! - [`tnc_enforcer`] — Trust-Critical Non-Negotiable Controls (TNC-01–10)
//! - [`metrics`] — Production monitoring metrics (M1–M12)
//! - [`workflow`] — Syntaxis workflow integration
//! - [`terms`] — Terms & conditions management
//! - [`error`] — Error types

pub mod accountability;
pub mod authority;
pub mod authority_matrix;
pub mod constitution;
pub mod contestation;
pub mod decision_object;
pub mod emergency;
pub mod error;
pub mod fiduciary_package;
pub mod human_gate;
pub mod metrics;
pub mod quorum;
pub mod self_governance;
pub mod terms;
pub mod tnc_enforcer;
pub mod workflow;

#[cfg(test)]
mod audit_tests {
    fn production_source(source: &str) -> &str {
        source.split("#[cfg(test)]").next().unwrap_or(source)
    }

    #[test]
    fn scope_r1_constructors_do_not_fabricate_identity_or_clock_metadata() {
        for (module, source) in [
            ("decision_object", include_str!("decision_object.rs")),
            ("contestation", include_str!("contestation.rs")),
            ("accountability", include_str!("accountability.rs")),
            ("emergency", include_str!("emergency.rs")),
            ("self_governance", include_str!("self_governance.rs")),
            ("workflow", include_str!("workflow.rs")),
        ] {
            let production = production_source(source);
            assert!(
                !production.contains("Uuid::new_v4"),
                "{module} production code must not fabricate UUIDs"
            );
            assert!(
                !production.contains("HybridClock::new()"),
                "{module} production code must not fabricate HLC clocks"
            );
        }
    }
}
