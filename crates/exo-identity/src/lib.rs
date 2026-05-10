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

//! EXOCHAIN constitutional trust fabric — privacy-preserving identity adjudication.
//!
//! This crate provides:
//!
//! - **DID management** (`did`) — Decentralized Identity documents, registration, revocation, key rotation
//! - **DID verification** (`did_verification`) — Signature verification against DID documents, key rotation with lifecycle management
//! - **Risk attestation** (`risk`) — Signed risk assessments with expiry and policy enforcement
//! - **Shamir secret sharing** (`shamir`) — Sybil-defense secret splitting over GF(256)
//! - **PACE operator continuity** (`pace`) — Primary/Alternate/Contingency/Emergency escalation
//! - **Key management** (`key_management`) — Key lifecycle tracking: create, rotate, revoke

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod did;
pub mod did_verification;
pub mod error;
pub mod key_management;
pub mod pace;
pub mod registry;
pub mod risk;
pub mod shamir;
pub mod vault;
pub mod verification;
