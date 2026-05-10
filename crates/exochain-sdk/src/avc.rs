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

//! SDK re-exports for the Autonomous Volition Credential layer.
//!
//! See the `exo-avc` crate documentation for the determinism contract,
//! validation rules, delegation invariants, and signing domain tags.
//!
//! ```
//! use exochain_sdk::avc::{
//!     AVC_SCHEMA_VERSION, AVC_CREDENTIAL_SIGNING_DOMAIN, AvcDecision, AvcReasonCode,
//! };
//! assert_eq!(AVC_SCHEMA_VERSION, 1);
//! assert!(AVC_CREDENTIAL_SIGNING_DOMAIN.contains(".v1"));
//! assert_ne!(AvcDecision::Allow, AvcDecision::Deny);
//! assert_ne!(AvcReasonCode::Valid, AvcReasonCode::Expired);
//! ```
//!
//! See `exo-avc`'s crate-level doctest for a full issue → validate flow.

pub use exo_avc::{
    AVC_CREDENTIAL_SIGNING_DOMAIN, AVC_RECEIPT_SIGNING_DOMAIN, AVC_REVOCATION_SIGNING_DOMAIN,
    AVC_SCHEMA_VERSION, AVC_SIGNING_DOMAINS, AuthorityChainRef, AuthorityScope,
    AutonomousVolitionCredential, AutonomyLevel, AvcActionRequest, AvcConstraints, AvcDecision,
    AvcDraft, AvcError, AvcReasonCode, AvcRegistryRead, AvcRegistryWrite, AvcRevocation,
    AvcRevocationReason, AvcSubjectKind, AvcTrustReceipt, AvcValidationRequest,
    AvcValidationResult, ConsentRef, DataClass, DelegatedIntent, InMemoryAvcRegistry,
    MAX_BASIS_POINTS, PolicyRef, TimeWindow, create_trust_receipt, delegate_avc, issue_avc,
    parent_id_of, revoke_avc, validate_avc,
};
