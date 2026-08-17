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

//! Policy-decision-point errors.

use thiserror::Error;

/// Failures produced by mandate verification, policy evaluation, or evidence.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum PdpError {
    #[error("invalid mandate: {0}")]
    InvalidMandate(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("mandate expired")]
    Expired,

    #[error("mandate revoked")]
    Revoked,

    #[error("mandate already consumed")]
    AlreadyConsumed,

    #[error("mandate already reserved")]
    AlreadyReserved,

    #[error("reservation not found: {0}")]
    ReservationNotFound(String),

    #[error("reservation not in expected state")]
    ReservationState,

    #[error("policy denied: {0}")]
    Denied(String),

    #[error("caveat failed: {0}")]
    CaveatFailed(String),

    #[error("delegation required")]
    DelegationRequired,

    #[error("scope widening is forbidden")]
    ScopeWidening,

    #[error("unknown principal or agent: {0}")]
    UnknownActor(String),

    #[error("evidence not found")]
    EvidenceNotFound,

    #[error("evidence chain broken")]
    EvidenceBroken,

    #[error("lock poisoned")]
    LockPoisoned,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("canonical serialization failed: {0}")]
    Serialization(String),

    #[error("durable state persistence failed: {0}")]
    Persistence(String),

    #[error("authority: {0}")]
    Authority(String),
}

impl From<exo_authority::AuthorityError> for PdpError {
    fn from(e: exo_authority::AuthorityError) -> Self {
        Self::Authority(e.to_string())
    }
}

impl From<exo_core::ExoError> for PdpError {
    fn from(e: exo_core::ExoError) -> Self {
        Self::BadRequest(e.to_string())
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, PdpError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_covers_variants() {
        let errs = [
            PdpError::InvalidMandate("x".into()),
            PdpError::InvalidSignature,
            PdpError::Expired,
            PdpError::Revoked,
            PdpError::AlreadyConsumed,
            PdpError::AlreadyReserved,
            PdpError::ReservationNotFound("h".into()),
            PdpError::ReservationState,
            PdpError::Denied("no".into()),
            PdpError::CaveatFailed("amt".into()),
            PdpError::DelegationRequired,
            PdpError::ScopeWidening,
            PdpError::UnknownActor("a".into()),
            PdpError::EvidenceNotFound,
            PdpError::EvidenceBroken,
            PdpError::LockPoisoned,
            PdpError::BadRequest("b".into()),
            PdpError::Serialization("s".into()),
            PdpError::Persistence("p".into()),
            PdpError::Authority("c".into()),
        ];
        for e in errs {
            assert!(!e.to_string().is_empty());
        }
    }
}
