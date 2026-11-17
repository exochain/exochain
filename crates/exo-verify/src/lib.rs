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

//! Offline verifier for EXOCHAIN AVC trust receipts.
//!
//! Given a receipt bundle and a caller-supplied key bundle, this crate checks
//! the four level-3 properties with no network access:
//!
//! 1. the validator and subject signatures over the exact stored bytes;
//! 2. the receipt's inclusion and position in the sealed receipt chain,
//!    against a validator-signed tree head;
//! 3. signer identity: each key resolves to a known `did:exo` identity in a
//!    versioned key bundle;
//! 4. trusted time from an RFC 3161 timestamp token, verified against a
//!    pinned timestamp authority key.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod error;
pub mod inclusion;
pub mod key_bundle;
pub mod rfc3161;
pub mod verify;

pub use error::VerifyError;
pub use inclusion::{
    AVC_RECEIPT_TREE_HEAD_DOMAIN, LeafPath, ReceiptInclusionProof, ReceiptTreeHead,
};
pub use key_bundle::{KEY_BUNDLE_FORMAT_V1, KeyBundle, KeyBundleEntry, KeyRole};
pub use verify::{
    RECEIPT_BUNDLE_FORMAT_V1, ReceiptBundle, TrustInputs, TsaTrust, VerifiedReceipt,
    verify_receipt_bundle,
};
