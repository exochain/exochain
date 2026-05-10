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

//! EXOCHAIN constitutional trust fabric — legislative legitimacy.
//!
//! This crate provides governance primitives: quorum computation with
//! independence-aware counting, clearance enforcement, crosscheck verification,
//! challenge mechanisms, deliberation processes, conflict detection,
//! hash-chained audit trails, typed custody chains, and shared governance types.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

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
