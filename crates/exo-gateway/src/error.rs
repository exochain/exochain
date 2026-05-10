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

//! Gateway-specific errors.
use thiserror::Error;

/// Errors returned by gateway operations.
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("authentication failed: {reason}")]
    AuthenticationFailed { reason: String },
    #[error("consent denied: {reason}")]
    ConsentDenied { reason: String },
    #[error("governance denied: {reason}")]
    GovernanceDenied { reason: String },
    #[error("not found: {0}")]
    NotFound(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("bad request: {0}")]
    BadRequest(String),
}
/// Convenience alias for `Result<T, GatewayError>`.
pub type Result<T> = std::result::Result<T, GatewayError>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_display() {
        let es: Vec<GatewayError> = vec![
            GatewayError::AuthenticationFailed { reason: "x".into() },
            GatewayError::ConsentDenied { reason: "x".into() },
            GatewayError::GovernanceDenied { reason: "x".into() },
            GatewayError::NotFound("x".into()),
            GatewayError::Internal("x".into()),
            GatewayError::BadRequest("x".into()),
        ];
        for e in &es {
            assert!(!e.to_string().is_empty());
        }
    }
    #[test]
    fn result_alias() {
        let ok: Result<u32> = Ok(1);
        assert!(ok.is_ok());
    }
}
