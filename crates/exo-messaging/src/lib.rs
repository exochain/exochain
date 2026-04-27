//! EXOCHAIN constitutional trust fabric — end-to-end encrypted messaging.
//!
//! This crate provides:
//!
//! - **Key exchange** (`kex`) — X25519 Diffie-Hellman ephemeral key exchange
//! - **Message envelopes** (`envelope`) — Encrypted message container types
//! - **Compose & lock** (`compose`) — Sender-side: encrypt + sign → Lock & Send
//! - **Open & verify** (`open`) — Recipient-side: decrypt + verify signature
//! - **Death triggers** (`death_trigger`) — Afterlife message release state machine

pub mod compose;
pub mod death_trigger;
pub mod envelope;
pub mod error;
pub mod kex;
pub mod open;

pub use compose::{ComposeMetadata, lock_and_send};
pub use envelope::{ContentType, EncryptedEnvelope};
pub use error::MessagingError;
pub use kex::{X25519KeyPair, X25519PublicKey, X25519SecretKey};
pub use open::unlock;
