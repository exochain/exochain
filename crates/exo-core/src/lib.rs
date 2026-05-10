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

//! # exo-core
//!
//! Foundational crate for the EXOCHAIN constitutional trust fabric.
//!
//! **Determinism contract**: this crate enforces absolute determinism.
//! - No floating-point arithmetic.
//! - `BTreeMap` only — `HashMap` is never exposed.
//! - Canonical CBOR serialization for all hashing.
//! - Hybrid Logical Clock for causal ordering.
//!
//! All other EXOCHAIN crates depend on `exo-core`.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod bcts;
pub mod crypto;
pub mod error;
pub mod events;
pub mod hash;
pub mod hlc;
pub mod invariants;
pub mod types;

// Re-export the most commonly used items at crate root for ergonomics.
pub use error::{ExoError, Result};
pub use types::{
    CorrelationId, DeterministicMap, Did, Hash256, PqPublicKey, PqSecretKey, PublicKey,
    SIGNER_PREFIX_AI, SIGNER_PREFIX_HUMAN, SecretKey, Signature, SignerType, Timestamp, Version,
};
