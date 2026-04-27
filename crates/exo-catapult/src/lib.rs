//! # exo-catapult
//!
//! Franchise business incubator for the EXOCHAIN constitutional trust fabric.
//!
//! Catapult provisions governed "newco" entities from franchise blueprints,
//! staffing each with an Operational Detachment Alpha (ODA) — a 12-agent team
//! modeled on FM 3-05 Army Special Operations doctrine, elegantly adapted for
//! autonomous business operations.
//!
//! Each newco starts with two founding agents — **HR** (assessment & selection)
//! and **Deep Researcher** (intelligence) — who recruit the remaining team
//! through a governed hiring pipeline.
//!
//! **Determinism contract**: this crate inherits exo-core's guarantees.
//! - No floating-point arithmetic.
//! - `DeterministicMap` only — no `HashMap`.
//! - Integer cents for budget, basis points for thresholds.
//! - HLC timestamps for all temporal ordering.

pub mod agent;
pub mod budget;
pub mod error;
pub mod franchise;
pub mod goal;
pub mod heartbeat;
pub mod integration;
pub mod newco;
pub mod oda;
pub mod phase;
pub mod receipt;

// Re-export the most commonly used items at crate root.
pub use agent::{AgentRoster, AgentStatus, CatapultAgent, CatapultAgentInput};
pub use budget::{
    BudgetLedger, BudgetPolicy, BudgetScope, BudgetVerdict, CostEvent, CostEventInput,
};
pub use error::{CatapultError, Result};
pub use franchise::{
    BusinessModel, FranchiseBlueprint, FranchiseBlueprintInput, FranchiseRegistry,
};
pub use goal::{Goal, GoalInput, GoalLevel, GoalStatus, GoalTree};
pub use heartbeat::{HeartbeatMonitor, HeartbeatRecord, HeartbeatRecordInput, HeartbeatStatus};
pub use newco::{Newco, NewcoInput, NewcoStatus};
pub use oda::{MosCode, OdaSlot};
pub use phase::OperationalPhase;
pub use receipt::{FranchiseOperation, FranchiseReceipt, FranchiseReceiptInput, ReceiptChain};
