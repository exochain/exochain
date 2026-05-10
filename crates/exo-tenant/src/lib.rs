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

//! EXOCHAIN constitutional trust fabric — multi-tenant isolation, cold storage, sharding.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod cold;
pub mod cold_storage;
pub mod error;
pub mod shard;
pub mod sharding;
pub mod store;
pub mod tenant;
