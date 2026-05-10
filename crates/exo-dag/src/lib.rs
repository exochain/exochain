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

//! EXOCHAIN append-only DAG with BFT consensus and Merkle structures.
//!
//! This crate provides:
//! - An append-only directed acyclic graph (`dag`)
//! - Validated persistent-store append with Byzantine clock defense (`append`)
//! - Checkpoint finality aggregation (`checkpoint`)
//! - BFT consensus over the DAG (`consensus`)
//! - Sparse Merkle Tree for authenticated key-value storage (`smt`)
//! - Merkle Mountain Range for append-only accumulation (`mmr`)
//! - Storage abstraction (`store`)

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod append;
pub mod checkpoint;
pub mod consensus;
pub mod dag;
pub mod error;
pub mod mmr;
#[cfg(feature = "postgres")]
pub mod pg_store;
pub mod smt;
pub mod store;
