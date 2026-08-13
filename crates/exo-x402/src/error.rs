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

//! Error types for the authorization-facilitator adapter.

use thiserror::Error;

/// Errors arising from payment-evidence hashing or HTTP mapping.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum X402Error {
    /// Canonical CBOR encoding of payment evidence failed.
    #[error("x402 payment-evidence serialization failed: {reason}")]
    Serialization { reason: String },

    /// Required string field was empty after trimming.
    #[error("x402 payment-evidence field `{field}` must not be empty")]
    EmptyField { field: &'static str },

    /// Facilitator receipt hash was the all-zero sentinel.
    #[error("x402 payment-evidence facilitator receipt hash must not be Hash256::ZERO")]
    ZeroFacilitatorReceiptHash,
}

/// Convenience alias for results that may fail with an [`X402Error`].
pub type Result<T> = std::result::Result<T, X402Error>;
