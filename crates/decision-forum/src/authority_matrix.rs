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

//! Real-time delegated authority matrix (GOV-003, GOV-004).
//!
//! Maps Actor -> `Vec<DelegatedAuthority>`. Each delegation is signed,
//! scoped, time-bound, and revocable. Auto-expiry enforcement (TNC-05),
//! sub-delegation control, and sunset/renewal tracking with 90/60/30/14/7-day
//! expiry warnings.

use exo_core::{
    crypto,
    hash::{hash_structured, hash256_eq_constant_time},
    types::{DeterministicMap, Did, Hash256, PublicKey, Signature, Timestamp},
};
use serde::{Deserialize, Serialize};

use crate::{
    decision_object::DecisionClass,
    error::{ForumError, Result},
};

const DELEGATION_SIGNATURE_DOMAIN: &str = "decision.forum.authority_matrix.delegation.v1";
const DELEGATION_SIGNATURE_HASH_DOMAIN: &str =
    "decision.forum.authority_matrix.delegation_signature_hash.v1";

#[derive(Debug, Clone, Serialize)]
struct DelegationSignaturePayload<'a> {
    domain: &'static str,
    delegation_id: &'a str,
    delegator: &'a Did,
    delegate: &'a Did,
    scope: &'a DelegationScope,
    granted_at: &'a Timestamp,
    expires_at: &'a Timestamp,
    revoked: bool,
    allows_sub_delegation: bool,
}

#[derive(Debug, Clone, Serialize)]
struct DelegationSignatureHashPayload<'a> {
    domain: &'static str,
    signature: &'a Signature,
}

/// Scope of a delegation — what actions the delegate can perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationScope {
    pub decision_classes: Vec<DecisionClass>,
    pub description: String,
}

impl DelegationScope {
    /// Check whether this scope is a non-empty subset of `parent`.
    #[must_use]
    pub fn is_subset_of(&self, parent: &Self) -> bool {
        !self.decision_classes.is_empty()
            && self
                .decision_classes
                .iter()
                .all(|class| parent.decision_classes.contains(class))
    }
}

/// A single delegated authority record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedAuthority {
    pub id: String,
    pub delegator: Did,
    pub delegate: Did,
    pub scope: DelegationScope,
    pub granted_at: Timestamp,
    pub expires_at: Timestamp,
    pub revoked: bool,
    pub allows_sub_delegation: bool,
    pub signature_hash: Hash256,
}

impl DelegatedAuthority {
    /// Validate delegation metadata before it can enter an authority matrix.
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(ForumError::AuthorityInvalid {
                reason: "delegation id must not be empty".into(),
            });
        }
        if self.delegator.as_str().trim().is_empty() {
            return Err(ForumError::AuthorityInvalid {
                reason: "delegator DID must not be empty".into(),
            });
        }
        if self.delegate.as_str().trim().is_empty() {
            return Err(ForumError::AuthorityInvalid {
                reason: "delegate DID must not be empty".into(),
            });
        }
        if self.scope.decision_classes.is_empty() {
            return Err(ForumError::AuthorityInvalid {
                reason: "delegation scope must include at least one decision class".into(),
            });
        }
        if self.scope.description.trim().is_empty() {
            return Err(ForumError::AuthorityInvalid {
                reason: "delegation scope description must not be empty".into(),
            });
        }
        if self.signature_hash == Hash256::ZERO {
            return Err(ForumError::AuthorityInvalid {
                reason: "delegation signature hash must not be zero".into(),
            });
        }
        if self.expires_at <= self.granted_at {
            return Err(ForumError::AuthorityInvalid {
                reason: "delegation expiry must be after grant timestamp".into(),
            });
        }
        Ok(())
    }

    /// Check whether this delegation is currently active at the given time.
    #[must_use]
    pub fn is_active(&self, now: &Timestamp) -> bool {
        !self.revoked && !self.expires_at.is_expired(now)
    }

    /// Check whether this delegation covers a given decision class.
    #[must_use]
    pub fn covers_class(&self, class: DecisionClass) -> bool {
        self.scope.decision_classes.contains(&class)
    }

    /// Calculate days until expiry from a given timestamp.
    /// Returns 0 if already expired.
    #[must_use]
    pub fn days_until_expiry(&self, now: &Timestamp) -> u64 {
        if self.expires_at.physical_ms <= now.physical_ms {
            return 0;
        }
        let diff_ms = self.expires_at.physical_ms - now.physical_ms;
        diff_ms / (24 * 60 * 60 * 1000)
    }
}

/// Canonical message bytes that a delegator signs for an authority delegation.
///
/// The payload is domain-separated and CBOR-hashed before signing. The stored
/// `signature_hash` is intentionally excluded to avoid a circular signature
/// dependency; callers bind the supplied signature separately with
/// [`delegation_signature_hash`].
pub fn delegation_signature_message(delegation: &DelegatedAuthority) -> Result<Vec<u8>> {
    let digest = hash_structured(&DelegationSignaturePayload {
        domain: DELEGATION_SIGNATURE_DOMAIN,
        delegation_id: &delegation.id,
        delegator: &delegation.delegator,
        delegate: &delegation.delegate,
        scope: &delegation.scope,
        granted_at: &delegation.granted_at,
        expires_at: &delegation.expires_at,
        revoked: delegation.revoked,
        allows_sub_delegation: delegation.allows_sub_delegation,
    })?;
    Ok(digest.as_ref().to_vec())
}

/// Canonical hash of the supplied delegation signature.
pub fn delegation_signature_hash(signature: &Signature) -> Result<Hash256> {
    Ok(hash_structured(&DelegationSignatureHashPayload {
        domain: DELEGATION_SIGNATURE_HASH_DOMAIN,
        signature,
    })?)
}

/// Verify that a delegation is authorized by its delegator's trusted key.
///
/// The caller is responsible for resolving `delegator_public_key` from a
/// trusted identity registry for `delegation.delegator`. This function enforces
/// the local signature and stored-hash boundary before the delegation may enter
/// an authority matrix.
pub fn verify_delegation_signature(
    delegation: &DelegatedAuthority,
    signature: &Signature,
    delegator_public_key: &PublicKey,
) -> Result<()> {
    delegation.validate()?;
    if signature.is_empty() || signature.ed25519_component_is_zero() {
        return Err(ForumError::AuthorityInvalid {
            reason: format!("delegation {} signature must not be empty", delegation.id),
        });
    }

    let expected_hash = delegation_signature_hash(signature)?;
    if !hash256_eq_constant_time(&expected_hash, &delegation.signature_hash) {
        return Err(ForumError::AuthorityInvalid {
            reason: format!(
                "delegation {} signature hash does not match supplied signature",
                delegation.id
            ),
        });
    }

    let message = delegation_signature_message(delegation)?;
    if !crypto::verify(&message, signature, delegator_public_key) {
        return Err(ForumError::AuthorityInvalid {
            reason: format!(
                "delegation {} signature verification failed for delegator {}",
                delegation.id, delegation.delegator
            ),
        });
    }

    Ok(())
}

/// Warning thresholds for delegation expiry (days).
pub const EXPIRY_WARNING_DAYS: &[u64] = &[90, 60, 30, 14, 7];

/// The authority matrix for a tenant — maps actors to their delegations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityMatrix {
    pub delegations: DeterministicMap<String, Vec<DelegatedAuthority>>,
}

impl AuthorityMatrix {
    /// Create an empty authority matrix.
    #[must_use]
    pub fn new() -> Self {
        Self {
            delegations: DeterministicMap::new(),
        }
    }

    /// Grant a new delegation.
    pub fn grant(&mut self, delegation: DelegatedAuthority) -> Result<()> {
        delegation.validate()?;
        Err(ForumError::AuthorityInvalid {
            reason: format!(
                "delegation {} requires grant_verified with a trusted delegator public key",
                delegation.id
            ),
        })
    }

    /// Grant a new delegation after verifying the delegator's signature.
    pub fn grant_verified(
        &mut self,
        delegation: DelegatedAuthority,
        signature: &Signature,
        delegator_public_key: &PublicKey,
    ) -> Result<()> {
        verify_delegation_signature(&delegation, signature, delegator_public_key)?;
        self.insert_validated_delegation(delegation)
    }

    fn insert_validated_delegation(&mut self, delegation: DelegatedAuthority) -> Result<()> {
        if self.contains_delegation_id(&delegation.id) {
            return Err(ForumError::AuthorityInvalid {
                reason: format!("delegation {} already exists", delegation.id),
            });
        }

        let key = delegation.delegate.as_str().to_owned();
        let entries = self.delegations.get(&key).cloned().unwrap_or_default();
        let mut entries = entries;
        entries.push(delegation);
        self.delegations.insert(key, entries);
        Ok(())
    }

    fn contains_delegation_id(&self, delegation_id: &str) -> bool {
        self.delegations
            .iter()
            .any(|(_, entries)| entries.iter().any(|entry| entry.id == delegation_id))
    }

    /// Revoke a delegation by ID for a specific delegate DID.
    pub fn revoke(&mut self, delegate_did: &Did, delegation_id: &str) -> Result<()> {
        let key = delegate_did.as_str().to_owned();
        if let Some(entries) = self.delegations.get(&key) {
            let mut entries = entries.clone();
            let mut found = false;
            for entry in &mut entries {
                if entry.id == delegation_id {
                    entry.revoked = true;
                    found = true;
                }
            }
            if !found {
                return Err(ForumError::AuthorityInvalid {
                    reason: format!("delegation {delegation_id} not found"),
                });
            }
            self.delegations.insert(key, entries);
            Ok(())
        } else {
            Err(ForumError::AuthorityInvalid {
                reason: format!("no delegations for {delegate_did}"),
            })
        }
    }

    /// Get all active delegations for a delegate at a given time.
    #[must_use]
    pub fn active_delegations(
        &self,
        delegate_did: &Did,
        now: &Timestamp,
    ) -> Vec<&DelegatedAuthority> {
        let key = delegate_did.as_str().to_owned();
        self.delegations
            .get(&key)
            .map(|entries| entries.iter().filter(|d| d.is_active(now)).collect())
            .unwrap_or_default()
    }

    /// Check if an actor has authority for a given decision class at a given time.
    #[must_use]
    pub fn has_authority(&self, actor: &Did, class: DecisionClass, now: &Timestamp) -> bool {
        self.active_delegations(actor, now)
            .iter()
            .any(|d| d.covers_class(class))
    }

    /// Purge all expired delegations. Returns the number removed.
    pub fn purge_expired(&mut self, now: &Timestamp) -> usize {
        let mut count = 0;
        let keys: Vec<String> = self.delegations.keys().cloned().collect();
        for key in keys {
            if let Some(entries) = self.delegations.get(&key) {
                let before = entries.len();
                let remaining: Vec<DelegatedAuthority> = entries
                    .iter()
                    .filter(|d| d.is_active(now))
                    .cloned()
                    .collect();
                count += before - remaining.len();
                self.delegations.insert(key, remaining);
            }
        }
        count
    }

    /// Collect all delegations approaching expiry within any warning threshold.
    #[must_use]
    pub fn expiry_warnings(&self, now: &Timestamp) -> Vec<(&DelegatedAuthority, u64)> {
        let mut warnings = Vec::new();
        for (_, entries) in self.delegations.iter() {
            for d in entries {
                if !d.is_active(now) {
                    continue;
                }
                let days = d.days_until_expiry(now);
                for &threshold in EXPIRY_WARNING_DAYS {
                    if days <= threshold {
                        warnings.push((d, days));
                        break;
                    }
                }
            }
        }
        warnings
    }

    /// Attempt sub-delegation: a delegate creating a new delegation.
    pub fn sub_delegate(
        &mut self,
        _parent_delegate: &Did,
        _parent_delegation_id: &str,
        new_delegation: DelegatedAuthority,
        _now: &Timestamp,
    ) -> Result<()> {
        new_delegation.validate()?;
        Err(ForumError::AuthorityInvalid {
            reason: format!(
                "delegation {} requires sub_delegate_verified with a trusted delegator public key",
                new_delegation.id
            ),
        })
    }

    /// Attempt sub-delegation after verifying the child delegation signature.
    pub fn sub_delegate_verified(
        &mut self,
        parent_delegate: &Did,
        parent_delegation_id: &str,
        new_delegation: DelegatedAuthority,
        signature: &Signature,
        delegator_public_key: &PublicKey,
        now: &Timestamp,
    ) -> Result<()> {
        verify_delegation_signature(&new_delegation, signature, delegator_public_key)?;

        let key = parent_delegate.as_str().to_owned();
        let parent = self
            .delegations
            .get(&key)
            .and_then(|entries| entries.iter().find(|d| d.id == parent_delegation_id))
            .ok_or_else(|| ForumError::AuthorityInvalid {
                reason: "parent delegation not found".into(),
            })?;

        if !parent.is_active(now) {
            return Err(ForumError::DelegationExpired);
        }
        if !parent.allows_sub_delegation {
            return Err(ForumError::SubDelegationNotPermitted);
        }

        if new_delegation.delegator != *parent_delegate {
            return Err(ForumError::AuthorityInvalid {
                reason: format!(
                    "child delegator {} must match parent delegate {parent_delegate}",
                    new_delegation.delegator
                ),
            });
        }
        if new_delegation.granted_at < parent.granted_at {
            return Err(ForumError::AuthorityInvalid {
                reason: "child grant timestamp must not precede parent grant timestamp".into(),
            });
        }
        if new_delegation.expires_at > parent.expires_at {
            return Err(ForumError::AuthorityInvalid {
                reason: "child expiry must not exceed parent expiry".into(),
            });
        }
        if !new_delegation.scope.is_subset_of(&parent.scope) {
            return Err(ForumError::DelegationScopeExceeded {
                reason: "child scope must be a non-empty subset of parent scope".into(),
            });
        }

        self.insert_validated_delegation(new_delegation)
    }
}

impl Default for AuthorityMatrix {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).expect("valid")
    }
    fn now() -> Timestamp {
        Timestamp::new(1_000_000_000, 0)
    }
    fn future() -> Timestamp {
        Timestamp::new(1_100_000_000, 0)
    } // ~1.16 days from now
    fn further_future() -> Timestamp {
        Timestamp::new(1_200_000_000, 0)
    }
    fn past() -> Timestamp {
        Timestamp::new(500_000_000, 0)
    }
    fn earlier_past() -> Timestamp {
        Timestamp::new(400_000_000, 0)
    }

    fn make_delegation(id: &str, delegator: &str, delegate: &str, sub: bool) -> DelegatedAuthority {
        DelegatedAuthority {
            id: id.into(),
            delegator: did(delegator),
            delegate: did(delegate),
            scope: DelegationScope {
                decision_classes: vec![DecisionClass::Routine, DecisionClass::Operational],
                description: "test".into(),
            },
            granted_at: past(),
            expires_at: future(),
            revoked: false,
            allows_sub_delegation: sub,
            signature_hash: Hash256::digest(id.as_bytes()),
        }
    }

    fn keypair(seed: u8) -> crypto::KeyPair {
        crypto::KeyPair::from_secret_bytes([seed; 32]).expect("deterministic test keypair")
    }

    fn sign_delegation_for_test(
        delegation: &mut DelegatedAuthority,
        signer: &crypto::KeyPair,
    ) -> Signature {
        let message =
            delegation_signature_message(delegation).expect("canonical delegation message");
        let signature = crypto::sign(&message, signer.secret_key());
        delegation.signature_hash =
            delegation_signature_hash(&signature).expect("canonical signature hash");
        signature
    }

    fn grant_signed(
        matrix: &mut AuthorityMatrix,
        mut delegation: DelegatedAuthority,
        signer: &crypto::KeyPair,
    ) {
        let signature = sign_delegation_for_test(&mut delegation, signer);
        matrix
            .grant_verified(delegation, &signature, signer.public_key())
            .expect("verified grant");
    }

    fn signed_delegation(
        mut delegation: DelegatedAuthority,
        signer: &crypto::KeyPair,
    ) -> (DelegatedAuthority, Signature) {
        let signature = sign_delegation_for_test(&mut delegation, signer);
        (delegation, signature)
    }

    #[test]
    fn authority_matrix_rejects_unverified_signature_hash_grant() {
        let mut m = AuthorityMatrix::new();
        let err = m
            .grant(make_delegation("forged", "root", "alice", false))
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("alice"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn authority_matrix_rejects_unverified_signature_hash_sub_delegation() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        grant_signed(
            &mut m,
            make_delegation("parent", "root", "alice", true),
            &root,
        );
        let err = m
            .sub_delegate(
                &did("alice"),
                "parent",
                make_delegation("forged-child", "alice", "bob", false),
                &now(),
            )
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("bob"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn delegation_signature_message_binds_authority_fields() {
        let base = make_delegation("d1", "root", "alice", true);
        let base_message =
            delegation_signature_message(&base).expect("base delegation signature message");

        let mut changed_id = base.clone();
        changed_id.id = "d2".into();
        assert_ne!(
            base_message,
            delegation_signature_message(&changed_id).expect("changed id message")
        );

        let mut changed_delegator = base.clone();
        changed_delegator.delegator = did("mallory");
        assert_ne!(
            base_message,
            delegation_signature_message(&changed_delegator).expect("changed delegator message")
        );

        let mut changed_delegate = base.clone();
        changed_delegate.delegate = did("bob");
        assert_ne!(
            base_message,
            delegation_signature_message(&changed_delegate).expect("changed delegate message")
        );

        let mut changed_scope = base.clone();
        changed_scope.scope.decision_classes = vec![DecisionClass::Routine];
        assert_ne!(
            base_message,
            delegation_signature_message(&changed_scope).expect("changed scope message")
        );

        let mut changed_grant_time = base.clone();
        changed_grant_time.granted_at = Timestamp::new(base.granted_at.physical_ms + 1, 0);
        assert_ne!(
            base_message,
            delegation_signature_message(&changed_grant_time).expect("changed grant time message")
        );

        let mut changed_expiry = base.clone();
        changed_expiry.expires_at = Timestamp::new(base.expires_at.physical_ms + 1, 0);
        assert_ne!(
            base_message,
            delegation_signature_message(&changed_expiry).expect("changed expiry message")
        );

        let mut changed_revoked = base.clone();
        changed_revoked.revoked = true;
        assert_ne!(
            base_message,
            delegation_signature_message(&changed_revoked).expect("changed revoked message")
        );

        let mut changed_sub_delegation = base;
        changed_sub_delegation.allows_sub_delegation = false;
        assert_ne!(
            base_message,
            delegation_signature_message(&changed_sub_delegation)
                .expect("changed sub-delegation message")
        );
    }

    #[test]
    fn grant_and_query() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        grant_signed(&mut m, make_delegation("d1", "root", "alice", false), &root);
        assert!(m.has_authority(&did("alice"), DecisionClass::Routine, &now()));
        assert!(!m.has_authority(&did("alice"), DecisionClass::Strategic, &now()));
        assert!(!m.has_authority(&did("bob"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn revoke() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        grant_signed(&mut m, make_delegation("d1", "root", "alice", false), &root);
        m.revoke(&did("alice"), "d1").expect("ok");
        assert!(!m.has_authority(&did("alice"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn revoke_not_found() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        grant_signed(&mut m, make_delegation("d1", "root", "alice", false), &root);
        assert!(m.revoke(&did("alice"), "d99").is_err());
    }

    #[test]
    fn expired_delegation_inactive() {
        let mut d = make_delegation("d1", "root", "alice", false);
        d.expires_at = past();
        assert!(!d.is_active(&now()));
    }

    #[test]
    fn purge_expired() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let mut d = make_delegation("d1", "root", "alice", false);
        d.granted_at = earlier_past();
        d.expires_at = past();
        grant_signed(&mut m, d, &root);
        grant_signed(&mut m, make_delegation("d2", "root", "alice", false), &root);
        let purged = m.purge_expired(&now());
        assert_eq!(purged, 1);
        assert_eq!(m.active_delegations(&did("alice"), &now()).len(), 1);
    }

    #[test]
    fn sub_delegation_ok() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let alice = keypair(12);
        grant_signed(&mut m, make_delegation("d1", "root", "alice", true), &root);
        let sub = DelegatedAuthority {
            id: "d2".into(),
            delegator: did("alice"),
            delegate: did("bob"),
            scope: DelegationScope {
                decision_classes: vec![DecisionClass::Routine],
                description: "sub".into(),
            },
            granted_at: now(),
            expires_at: future(),
            revoked: false,
            allows_sub_delegation: false,
            signature_hash: Hash256::digest(b"d2"),
        };
        let (sub, signature) = signed_delegation(sub, &alice);
        m.sub_delegate_verified(
            &did("alice"),
            "d1",
            sub,
            &signature,
            alice.public_key(),
            &now(),
        )
        .expect("ok");
        assert!(m.has_authority(&did("bob"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn grant_verified_rejects_signature_hash_mismatch() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let (mut d, signature) =
            signed_delegation(make_delegation("d1", "root", "alice", false), &root);
        d.signature_hash = Hash256::digest(b"not-the-supplied-signature");
        let err = m
            .grant_verified(d, &signature, root.public_key())
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("alice"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn grant_verified_rejects_payload_tampering_after_signature() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let (mut d, signature) =
            signed_delegation(make_delegation("d1", "root", "alice", false), &root);
        d.delegate = did("mallory");
        let err = m
            .grant_verified(d, &signature, root.public_key())
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("alice"), DecisionClass::Routine, &now()));
        assert!(!m.has_authority(&did("mallory"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn grant_verified_rejects_wrong_public_key() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let wrong = keypair(99);
        let (d, signature) =
            signed_delegation(make_delegation("d1", "root", "alice", false), &root);
        let err = m
            .grant_verified(d, &signature, wrong.public_key())
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("alice"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn sub_delegation_not_permitted() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let alice = keypair(12);
        grant_signed(&mut m, make_delegation("d1", "root", "alice", false), &root);
        let sub = make_delegation("d2", "alice", "bob", false);
        let (sub, signature) = signed_delegation(sub, &alice);
        let err = m
            .sub_delegate_verified(
                &did("alice"),
                "d1",
                sub,
                &signature,
                alice.public_key(),
                &now(),
            )
            .unwrap_err();
        assert!(matches!(err, ForumError::SubDelegationNotPermitted));
    }

    #[test]
    fn sub_delegation_scope_exceeded() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let alice = keypair(12);
        grant_signed(&mut m, make_delegation("d1", "root", "alice", true), &root);
        let mut sub = make_delegation("d2", "alice", "bob", false);
        sub.scope.decision_classes = vec![DecisionClass::Strategic];
        let (sub, signature) = signed_delegation(sub, &alice);
        let err = m
            .sub_delegate_verified(
                &did("alice"),
                "d1",
                sub,
                &signature,
                alice.public_key(),
                &now(),
            )
            .unwrap_err();
        assert!(matches!(err, ForumError::DelegationScopeExceeded { .. }));
    }

    #[test]
    fn delegation_scope_subset_requires_non_empty_child_and_parent_coverage() {
        let parent = DelegationScope {
            decision_classes: vec![DecisionClass::Routine, DecisionClass::Operational],
            description: "parent scope".into(),
        };
        let child = DelegationScope {
            decision_classes: vec![DecisionClass::Routine],
            description: "child scope".into(),
        };
        let wider_child = DelegationScope {
            decision_classes: vec![DecisionClass::Strategic],
            description: "wider child".into(),
        };
        let empty_child = DelegationScope {
            decision_classes: Vec::new(),
            description: "empty child".into(),
        };

        assert!(child.is_subset_of(&parent));
        assert!(!wider_child.is_subset_of(&parent));
        assert!(!empty_child.is_subset_of(&parent));
    }

    #[test]
    fn grant_rejects_duplicate_delegation_id_across_matrix() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        grant_signed(&mut m, make_delegation("d1", "root", "alice", false), &root);
        let (d, signature) = signed_delegation(make_delegation("d1", "root", "bob", false), &root);
        let err = m
            .grant_verified(d, &signature, root.public_key())
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("bob"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn grant_rejects_empty_delegation_id() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let (d, signature) = signed_delegation(make_delegation("", "root", "alice", false), &root);
        let err = m
            .grant_verified(d, &signature, root.public_key())
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("alice"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn grant_rejects_empty_scope_classes() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let mut d = make_delegation("d1", "root", "alice", false);
        d.scope.decision_classes = Vec::new();
        let (d, signature) = signed_delegation(d, &root);
        let err = m
            .grant_verified(d, &signature, root.public_key())
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("alice"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn grant_rejects_empty_scope_description() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let mut d = make_delegation("d1", "root", "alice", false);
        d.scope.description.clear();
        let (d, signature) = signed_delegation(d, &root);
        let err = m
            .grant_verified(d, &signature, root.public_key())
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("alice"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn grant_rejects_zero_signature_hash() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let mut d = make_delegation("d1", "root", "alice", false);
        let signature = sign_delegation_for_test(&mut d, &root);
        d.signature_hash = Hash256::ZERO;
        let err = m
            .grant_verified(d, &signature, root.public_key())
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("alice"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn grant_rejects_non_forward_time_bounds() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let mut d = make_delegation("d1", "root", "alice", false);
        d.expires_at = d.granted_at;
        let (d, signature) = signed_delegation(d, &root);
        let err = m
            .grant_verified(d, &signature, root.public_key())
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("alice"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn sub_delegation_rejects_child_delegator_mismatch() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let mallory = keypair(13);
        grant_signed(&mut m, make_delegation("d1", "root", "alice", true), &root);
        let sub = make_delegation("d2", "mallory", "bob", false);
        let (sub, signature) = signed_delegation(sub, &mallory);
        let err = m
            .sub_delegate_verified(
                &did("alice"),
                "d1",
                sub,
                &signature,
                mallory.public_key(),
                &now(),
            )
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("bob"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn sub_delegation_rejects_child_grant_before_parent_grant() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let alice = keypair(12);
        grant_signed(&mut m, make_delegation("d1", "root", "alice", true), &root);
        let mut sub = make_delegation("d2", "alice", "bob", false);
        sub.granted_at = earlier_past();
        let (sub, signature) = signed_delegation(sub, &alice);
        let err = m
            .sub_delegate_verified(
                &did("alice"),
                "d1",
                sub,
                &signature,
                alice.public_key(),
                &now(),
            )
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("bob"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn sub_delegation_rejects_child_expiry_after_parent_expiry() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let alice = keypair(12);
        grant_signed(&mut m, make_delegation("d1", "root", "alice", true), &root);
        let mut sub = make_delegation("d2", "alice", "bob", false);
        sub.expires_at = further_future();
        let (sub, signature) = signed_delegation(sub, &alice);
        let err = m
            .sub_delegate_verified(
                &did("alice"),
                "d1",
                sub,
                &signature,
                alice.public_key(),
                &now(),
            )
            .unwrap_err();

        assert!(matches!(err, ForumError::AuthorityInvalid { .. }));
        assert!(!m.has_authority(&did("bob"), DecisionClass::Routine, &now()));
    }

    #[test]
    fn days_until_expiry() {
        let d = make_delegation("d1", "root", "alice", false);
        let days = d.days_until_expiry(&now());
        // future() is 2_000_000ms, now() is 1_000_000ms => ~11 days
        assert!(days > 0);
    }

    #[test]
    fn expiry_warnings() {
        let mut m = AuthorityMatrix::new();
        let root = keypair(11);
        let mut d = make_delegation("d1", "root", "alice", false);
        // Expires in 5 days from now
        let five_days_ms = 5 * 24 * 60 * 60 * 1000;
        d.expires_at = Timestamp::new(now().physical_ms + five_days_ms, 0);
        grant_signed(&mut m, d, &root);
        let warnings = m.expiry_warnings(&now());
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].1, 5);
    }

    #[test]
    fn default() {
        let m = AuthorityMatrix::default();
        assert!(m.delegations.is_empty());
    }
}
