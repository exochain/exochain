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

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! EXOCHAIN policy decision point.
//!
//! Runtime authority for agent actions and payments:
//! verify a signed mandate, apply policy, fail-closed deny, emit a
//! third-party-verifiable evidence pack. Never moves money.
//!
//! Deny always outranks a valid payment payload. Sit this crate at or
//! before the x402 `/verify` hop; emit/consume AP2-shaped mandates via
//! [`mandate::WireMandate`].

pub mod error;
pub mod evidence;
#[cfg(feature = "http")]
pub mod http;
pub mod mandate;
pub mod pack;
pub mod policy;
pub mod reservation;
pub mod revocation;
pub mod service;
pub mod x402;

pub use error::{PdpError, Result};
pub use evidence::{Decision, EvidenceDraft, EvidenceEntry, EvidenceLog};
pub use mandate::{Caveat, Mandate, MandateAdapter, MandateKind, ProposedAction, WireMandate};
pub use pack::{
    ART26_RETENTION_DAYS, Article26Record, EVIDENCE_PACK_SPEC, EvidencePack, MS_PER_DAY,
};
pub use policy::{DecisionRequest, PolicyVerdict};
pub use reservation::{Reservation, ReservationBook, ReservationState};
pub use revocation::{Revocation, RevocationSet, RevocationTarget};
pub use service::{DecideOutcome, DecideResponse, PolicyDecisionPoint, SharedPdp};
pub use x402::{X402VerifyRequest, X402VerifyResponse};
