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

//! EXOCHAIN constitutional trust fabric — end-to-end encrypted messaging.
//!
//! This crate provides:
//!
//! - **Key exchange** (`kex`) — X25519 Diffie-Hellman with caller-supplied key material
//! - **Message envelopes** (`envelope`) — Encrypted message container types
//! - **Compose & lock** (`compose`) — Sender-side: encrypt + sign → Lock & Send
//! - **Open & verify** (`open`) — Recipient-side: decrypt + verify signature
//! - **Death triggers** (`death_trigger`) — Afterlife message release state machine

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod compose;
pub mod death_trigger;
pub mod envelope;
pub mod error;
pub mod kex;
pub mod open;

pub use compose::{
    ComposeMetadata, attach_verified_signature, lock_and_send, lock_and_send_with_ephemeral,
    prepare_envelope_for_signing, prepare_envelope_for_signing_with_ephemeral,
    sign_prepared_envelope,
};
pub use envelope::{ContentType, EncryptedEnvelope};
pub use error::MessagingError;
pub use kex::{X25519KeyPair, X25519PublicKey, X25519SecretKey};
pub use open::unlock;
