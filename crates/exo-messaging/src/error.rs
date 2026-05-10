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

//! Messaging-specific error types.

/// Errors that can occur during messaging operations.
#[derive(Debug, thiserror::Error)]
pub enum MessagingError {
    #[error("key exchange failed: {0}")]
    KeyExchangeFailed(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: ciphertext invalid or wrong key")]
    DecryptionFailed,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("death-trigger confirmation payload encoding failed: {0}")]
    DeathConfirmationPayloadEncoding(String),

    #[error("envelope signing payload encoding failed: {0}")]
    EnvelopeSigningPayloadEncoding(String),

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("identity error: {0}")]
    Identity(#[from] exo_identity::error::IdentityError),

    #[error("death trigger already resolved")]
    DeathTriggerAlreadyResolved,

    #[error("invalid death verification: {0}")]
    InvalidDeathVerification(String),

    #[error("insufficient confirmations: need {need}, got {got}")]
    InsufficientConfirmations { need: u8, got: u8 },

    #[error("unauthorized death-trigger trustee: {0}")]
    UnauthorizedTrustee(String),

    #[error("duplicate confirmation from: {0}")]
    DuplicateConfirmation(String),
}
