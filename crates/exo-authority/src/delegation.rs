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

//! Delegation management — tracks active delegations and resolves chains.

use std::collections::{BTreeMap, BTreeSet};

use exo_core::{Did, Hash256, PublicKey, Signature, Timestamp, crypto, hash::hash_structured};

use crate::{
    chain::{self, AuthorityChain, AuthorityLink, DEFAULT_MAX_DEPTH, DelegateeKind},
    error::AuthorityError,
    permission::Permission,
};

/// Domain tag for authority delegation revocation signatures.
pub const AUTHORITY_REVOCATION_SIGNING_DOMAIN: &str = "exo.authority.revocation.v1";
const AUTHORITY_REVOCATION_SIGNING_SCHEMA_VERSION: u16 = 1;
const DELEGATION_AUDIT_EVENT_DOMAIN: &str = "exo.authority.delegation_audit_event.v1";
const DELEGATION_AUDIT_EVENT_SCHEMA_VERSION: u16 = 1;

/// Registry of all active delegations.
#[derive(Debug, Default)]
pub struct DelegationRegistry {
    /// Links indexed by their hash ID.
    links: BTreeMap<Hash256, AuthorityLink>,
    /// Forward index: delegator DID -> list of link IDs.
    by_delegator: BTreeMap<String, Vec<Hash256>>,
    /// Reverse index: delegate DID -> list of link IDs.
    by_delegate: BTreeMap<String, Vec<Hash256>>,
    /// Public key that verified each active link's original delegator signature.
    link_delegator_public_keys: BTreeMap<Hash256, PublicKey>,
    /// Append-only audit events for registry mutations.
    audit_events: Vec<DelegationAuditEvent>,
}

/// Audited registry mutation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DelegationAuditAction {
    Granted,
    Revoked,
}

/// Hash-chained audit event for a delegation registry mutation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DelegationAuditEvent {
    pub sequence: u64,
    pub action: DelegationAuditAction,
    pub link_id: Hash256,
    pub delegator_did: Did,
    pub delegate_did: Did,
    pub timestamp: Timestamp,
    pub previous_event_hash: Hash256,
    pub event_hash: Hash256,
}

#[derive(serde::Serialize)]
struct DelegationAuditEventHashPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    sequence: u64,
    action: DelegationAuditAction,
    link_id: &'a Hash256,
    delegator_did: &'a Did,
    delegate_did: &'a Did,
    timestamp: &'a Timestamp,
    previous_event_hash: &'a Hash256,
}

/// Caller-supplied fields for a signed delegation grant.
pub struct DelegationGrant<'a> {
    pub from: &'a Did,
    pub to: &'a Did,
    pub scope: &'a [Permission],
    pub expires: Timestamp,
    pub now: &'a Timestamp,
    /// Selected parent link for delegated authority, or `None` for a self-root grant.
    pub parent_link_id: Option<&'a Hash256>,
    pub delegatee_kind: DelegateeKind,
    pub delegator_public_key: &'a PublicKey,
}

/// Caller-supplied fields for a signed delegation revocation.
pub struct DelegationRevocationGrant<'a> {
    pub link_id: &'a Hash256,
    pub revoker: &'a Did,
    pub revoked_at: &'a Timestamp,
}

#[derive(serde::Serialize)]
struct AuthorityRevocationSigningPayload<'a> {
    domain: &'static str,
    schema_version: u16,
    revoked_link_hash: &'a Hash256,
    revoker_did: &'a Did,
    revoked_at: &'a Timestamp,
}

/// Signed evidence that an authority link was revoked by its delegator.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorityRevocation {
    pub revoked_link: AuthorityLink,
    pub revoked_link_hash: Hash256,
    pub revoker_did: Did,
    pub revoked_at: Timestamp,
    pub signature: Signature,
}

impl AuthorityRevocation {
    /// Create and verify a signed revocation artifact for an authority link.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] when the revoker is not the original
    /// delegator, the revocation timestamp is invalid, canonical payload
    /// encoding fails, or the revocation signature does not verify.
    pub fn for_link(
        revoked_link: AuthorityLink,
        revoker: &Did,
        revoked_at: &Timestamp,
        revoker_public_key: &PublicKey,
        sign_fn: impl FnOnce(&[u8]) -> Signature,
    ) -> Result<Self, AuthorityError> {
        let revoked_link_hash = revoked_link.id()?;
        let mut revocation = Self {
            revoked_link,
            revoked_link_hash,
            revoker_did: revoker.clone(),
            revoked_at: *revoked_at,
            signature: Signature::empty(),
        };

        revocation.validate_structure()?;
        let payload = revocation.signing_payload()?;
        let signature = sign_fn(&payload);
        if signature.is_empty() {
            return Err(AuthorityError::InvalidSignature { index: 0 });
        }
        if !crypto::verify(&payload, &signature, revoker_public_key) {
            return Err(AuthorityError::InvalidSignature { index: 0 });
        }
        revocation.signature = signature;
        Ok(revocation)
    }

    /// Compute the deterministic ID for this revocation.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::SigningPayloadEncoding`] if canonical CBOR
    /// encoding of the signed payload fails.
    pub fn id(&self) -> Result<Hash256, AuthorityError> {
        Ok(Hash256::digest(&self.signing_payload()?))
    }

    /// Canonical revocation payload signed by the revoker.
    ///
    /// The payload is domain-separated CBOR and excludes the signature itself.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::SigningPayloadEncoding`] if canonical CBOR
    /// encoding fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>, AuthorityError> {
        let payload = AuthorityRevocationSigningPayload {
            domain: AUTHORITY_REVOCATION_SIGNING_DOMAIN,
            schema_version: AUTHORITY_REVOCATION_SIGNING_SCHEMA_VERSION,
            revoked_link_hash: &self.revoked_link_hash,
            revoker_did: &self.revoker_did,
            revoked_at: &self.revoked_at,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut buf).map_err(|e| {
            AuthorityError::SigningPayloadEncoding {
                reason: e.to_string(),
            }
        })?;
        Ok(buf)
    }

    /// Verify this revocation and the revoked authority link.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] when the artifact is structurally invalid,
    /// the revocation signature is missing or forged, or the revoked link's
    /// original delegation signature cannot be verified.
    pub fn verify<F>(&self, resolve_key: F) -> Result<(), AuthorityError>
    where
        F: Fn(&Did) -> Option<PublicKey>,
    {
        self.validate_structure()?;

        if self.signature.is_empty() {
            return Err(AuthorityError::InvalidSignature { index: 0 });
        }
        let revoker_public_key =
            resolve_key(&self.revoker_did).ok_or(AuthorityError::InvalidSignature { index: 0 })?;
        let payload = self.signing_payload()?;
        if !crypto::verify(&payload, &self.signature, &revoker_public_key) {
            return Err(AuthorityError::InvalidSignature { index: 0 });
        }

        if self.revoked_link.signature.is_empty() {
            return Err(AuthorityError::InvalidSignature {
                index: self.revoked_link.depth,
            });
        }
        let delegator_public_key = resolve_key(&self.revoked_link.delegator_did).ok_or(
            AuthorityError::InvalidSignature {
                index: self.revoked_link.depth,
            },
        )?;
        let link_payload = self.revoked_link.signing_payload()?;
        if !crypto::verify(
            &link_payload,
            &self.revoked_link.signature,
            &delegator_public_key,
        ) {
            return Err(AuthorityError::InvalidSignature {
                index: self.revoked_link.depth,
            });
        }

        Ok(())
    }

    fn validate_structure(&self) -> Result<(), AuthorityError> {
        if self.revoked_at == Timestamp::ZERO {
            return Err(AuthorityError::InvalidDelegation {
                reason: "revocation timestamp must be non-zero".into(),
            });
        }
        if self.revoked_at < self.revoked_link.created {
            return Err(AuthorityError::InvalidDelegation {
                reason: "revocation timestamp must not precede delegation creation".into(),
            });
        }
        if let Some(expires) = &self.revoked_link.expires {
            if expires.is_expired(&self.revoked_at) {
                return Err(AuthorityError::ExpiredLink {
                    index: self.revoked_link.depth,
                });
            }
        }
        if self.revoker_did != self.revoked_link.delegator_did {
            return Err(AuthorityError::PermissionDenied(format!(
                "revoker {} is not delegator {} for revoked link",
                self.revoker_did.as_str(),
                self.revoked_link.delegator_did.as_str()
            )));
        }

        let computed_link_hash = self.revoked_link.id()?;
        if computed_link_hash != self.revoked_link_hash {
            return Err(AuthorityError::InvalidDelegation {
                reason: format!(
                    "revoked link hash mismatch: expected {}, computed {}",
                    self.revoked_link_hash, computed_link_hash
                ),
            });
        }

        Ok(())
    }
}

impl DelegationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the append-only delegation audit trail.
    #[must_use]
    pub fn audit_events(&self) -> &[DelegationAuditEvent] {
        &self.audit_events
    }

    /// Verify the delegation audit trail's sequence, linkage, and event hashes.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::AuditChainBroken`] at the first broken event,
    /// or [`AuthorityError::AuditHashEncoding`] if canonical hashing fails.
    pub fn verify_audit_chain(&self) -> Result<(), AuthorityError> {
        let mut previous_event_hash = Hash256::ZERO;
        for (index, event) in self.audit_events.iter().enumerate() {
            let sequence = u64::try_from(index)
                .map_err(|_| AuthorityError::AuditChainBroken { sequence: u64::MAX })?;
            if event.sequence != sequence
                || event.previous_event_hash != previous_event_hash
                || event.timestamp == Timestamp::ZERO
                || event.event_hash != delegation_audit_event_hash(event)?
            {
                return Err(AuthorityError::AuditChainBroken { sequence });
            }
            previous_event_hash = event.event_hash;
        }
        Ok(())
    }

    fn build_delegation_audit_event(
        &self,
        action: DelegationAuditAction,
        link_id: Hash256,
        link: &AuthorityLink,
        timestamp: Timestamp,
    ) -> Result<DelegationAuditEvent, AuthorityError> {
        if timestamp == Timestamp::ZERO {
            return Err(AuthorityError::InvalidDelegation {
                reason: "delegation audit event timestamp must be non-zero".into(),
            });
        }
        let sequence = u64::try_from(self.audit_events.len()).map_err(|_| {
            AuthorityError::InvalidDelegation {
                reason: "delegation audit log length does not fit u64 sequence".into(),
            }
        })?;
        let previous_event_hash = self
            .audit_events
            .last()
            .map_or(Hash256::ZERO, |event| event.event_hash);
        let mut event = DelegationAuditEvent {
            sequence,
            action,
            link_id,
            delegator_did: link.delegator_did.clone(),
            delegate_did: link.delegate_did.clone(),
            timestamp,
            previous_event_hash,
            event_hash: Hash256::ZERO,
        };
        event.event_hash = delegation_audit_event_hash(&event)?;
        Ok(event)
    }

    /// Create a delegation from one DID to another.
    ///
    /// # Errors
    /// Returns `CircularDelegation` if this would create a cycle.
    pub fn delegate(
        &mut self,
        grant: DelegationGrant<'_>,
        sign_fn: impl FnOnce(&[u8]) -> Signature,
    ) -> Result<AuthorityLink, AuthorityError> {
        let DelegationGrant {
            from,
            to,
            scope,
            expires,
            now,
            parent_link_id,
            delegatee_kind,
            delegator_public_key,
        } = grant;

        // Detect circular: if `to` already delegates (directly or transitively) to `from`
        if self.has_path(to, from) {
            return Err(AuthorityError::CircularDelegation(format!(
                "{} -> {} would create a cycle",
                from, to
            )));
        }

        if *now == Timestamp::ZERO {
            return Err(AuthorityError::InvalidDelegation {
                reason: "created timestamp must be non-zero".into(),
            });
        }
        if expires <= *now {
            return Err(AuthorityError::InvalidDelegation {
                reason: "expiration must be later than created timestamp".into(),
            });
        }
        match &delegatee_kind {
            DelegateeKind::Human => {}
            DelegateeKind::AiAgent { model_id } => {
                if model_id.trim().is_empty() {
                    return Err(AuthorityError::InvalidDelegation {
                        reason: "AI-agent delegatee kind requires a non-empty model_id".into(),
                    });
                }
            }
            DelegateeKind::Unknown => {
                return Err(AuthorityError::InvalidDelegation {
                    reason: "delegatee kind must be Human or AiAgent for new delegations".into(),
                });
            }
        }

        let scope = canonical_scope(scope)?;
        let depth = self.compute_depth(from, parent_link_id, &scope, now)?;

        let mut link = AuthorityLink {
            delegator_did: from.clone(),
            delegate_did: to.clone(),
            scope,
            created: *now,
            expires: Some(expires),
            signature: Signature::empty(),
            depth,
            delegatee_kind,
        };

        let payload = link.signing_payload()?;
        let signature = sign_fn(&payload);
        if signature.is_empty() || signature_is_all_zero(&signature) {
            return Err(AuthorityError::InvalidSignature { index: depth });
        }
        if !crypto::verify(&payload, &signature, delegator_public_key) {
            return Err(AuthorityError::InvalidSignature { index: depth });
        }
        link.signature = signature;

        let id = link.id()?;
        if self.links.contains_key(&id) {
            return Err(AuthorityError::DuplicateDelegation { id: id.to_string() });
        }
        let audit_event = self.build_delegation_audit_event(
            DelegationAuditAction::Granted,
            id,
            &link,
            link.created,
        )?;
        self.links.insert(id, link.clone());
        self.link_delegator_public_keys
            .insert(id, *delegator_public_key);
        self.by_delegator
            .entry(from.as_str().to_owned())
            .or_default()
            .push(id);
        self.by_delegate
            .entry(to.as_str().to_owned())
            .or_default()
            .push(id);
        self.audit_events.push(audit_event);

        Ok(link)
    }

    fn remove_delegation_link(&mut self, link_id: &Hash256) -> Result<(), AuthorityError> {
        let link = self
            .links
            .remove(link_id)
            .ok_or_else(|| AuthorityError::NotFound(link_id.to_string()))?;

        if let Some(ids) = self.by_delegator.get_mut(link.delegator_did.as_str()) {
            ids.retain(|id| id != link_id);
        }
        if let Some(ids) = self.by_delegate.get_mut(link.delegate_did.as_str()) {
            ids.retain(|id| id != link_id);
        }
        self.link_delegator_public_keys.remove(link_id);

        Ok(())
    }

    /// Revoke a delegation by its link ID and return signed revocation evidence.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::NotFound`] if the link does not exist, or
    /// signature/validation errors when the revocation artifact cannot be
    /// verified before removal.
    pub fn revoke_delegation_signed(
        &mut self,
        grant: DelegationRevocationGrant<'_>,
        sign_fn: impl FnOnce(&[u8]) -> Signature,
    ) -> Result<AuthorityRevocation, AuthorityError> {
        let DelegationRevocationGrant {
            link_id,
            revoker,
            revoked_at,
        } = grant;

        let link = self
            .links
            .get(link_id)
            .cloned()
            .ok_or_else(|| AuthorityError::NotFound(link_id.to_string()))?;
        let revoker_public_key = self
            .link_delegator_public_keys
            .get(link_id)
            .copied()
            .ok_or(AuthorityError::InvalidSignature { index: link.depth })?;

        let revocation =
            AuthorityRevocation::for_link(link, revoker, revoked_at, &revoker_public_key, sign_fn)?;
        let audit_event = self.build_delegation_audit_event(
            DelegationAuditAction::Revoked,
            *link_id,
            &revocation.revoked_link,
            *revoked_at,
        )?;
        self.remove_delegation_link(link_id)?;
        self.audit_events.push(audit_event);
        Ok(revocation)
    }

    /// Find a delegation chain from `from` to `to`.
    #[must_use]
    pub fn find_chain(&self, from: &Did, to: &Did) -> Option<AuthorityChain> {
        let mut path = Vec::new();
        if self.find_path_dfs(from, to, &mut path, 0, DEFAULT_MAX_DEPTH) {
            chain::build_chain(&path).ok()
        } else {
            None
        }
    }

    /// Number of active delegations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// Is the registry empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    // -- Private helpers --

    fn has_path(&self, from: &Did, to: &Did) -> bool {
        if from == to {
            return true;
        }
        let mut visited = BTreeSet::new();
        let mut stack = vec![from.as_str().to_owned()];

        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(ids) = self.by_delegator.get(current.as_str()) {
                for id in ids.iter().rev() {
                    if let Some(link) = self.links.get(id) {
                        if link.delegate_did == *to {
                            return true;
                        }
                        if !visited.contains(link.delegate_did.as_str()) {
                            stack.push(link.delegate_did.as_str().to_owned());
                        }
                    }
                }
            }
        }

        false
    }

    fn find_path_dfs(
        &self,
        current: &Did,
        target: &Did,
        path: &mut Vec<AuthorityLink>,
        depth: usize,
        max_depth: usize,
    ) -> bool {
        if depth >= max_depth {
            return false;
        }
        if let Some(ids) = self.by_delegator.get(current.as_str()) {
            for id in ids {
                if let Some(link) = self.links.get(id) {
                    path.push(link.clone());
                    if link.delegate_did == *target {
                        return true;
                    }
                    if self.find_path_dfs(&link.delegate_did, target, path, depth + 1, max_depth) {
                        return true;
                    }
                    path.pop();
                }
            }
        }
        false
    }

    fn compute_depth(
        &self,
        did: &Did,
        parent_link_id: Option<&Hash256>,
        scope: &[Permission],
        now: &Timestamp,
    ) -> Result<usize, AuthorityError> {
        let Some(parent_link_id) = parent_link_id else {
            return Ok(0);
        };

        let parent = self
            .links
            .get(parent_link_id)
            .ok_or_else(|| AuthorityError::NotFound(parent_link_id.to_string()))?;
        if parent.delegate_did != *did {
            return Err(AuthorityError::PermissionDenied(format!(
                "parent link {} delegates to {}, not {}",
                parent_link_id,
                parent.delegate_did.as_str(),
                did.as_str()
            )));
        }
        if let Some(expires) = &parent.expires {
            if expires.is_expired(now) {
                return Err(AuthorityError::ExpiredLink {
                    index: parent.depth,
                });
            }
        }

        let parent_scope = parent.scope.iter().copied().collect::<BTreeSet<_>>();
        let child_scope = scope.iter().copied().collect::<BTreeSet<_>>();
        if !child_scope.is_subset(&parent_scope) {
            return Err(AuthorityError::InvalidDelegation {
                reason: "delegation scope must not exceed selected parent link scope".into(),
            });
        }

        let depth = parent
            .depth
            .checked_add(1)
            .ok_or(AuthorityError::DepthExceeded {
                depth: parent.depth,
                max_depth: DEFAULT_MAX_DEPTH,
            })?;
        let chain_depth = depth.checked_add(1).ok_or(AuthorityError::DepthExceeded {
            depth,
            max_depth: DEFAULT_MAX_DEPTH,
        })?;
        if chain_depth > DEFAULT_MAX_DEPTH {
            return Err(AuthorityError::DepthExceeded {
                depth: chain_depth,
                max_depth: DEFAULT_MAX_DEPTH,
            });
        }
        Ok(depth)
    }
}

fn canonical_scope(scope: &[Permission]) -> Result<Vec<Permission>, AuthorityError> {
    let scope: BTreeSet<Permission> = scope.iter().copied().collect();
    if scope.is_empty() {
        return Err(AuthorityError::InvalidDelegation {
            reason: "scope must contain at least one permission".into(),
        });
    }
    Ok(scope.into_iter().collect())
}

fn signature_is_all_zero(signature: &Signature) -> bool {
    signature.ed25519_component_is_zero()
}

fn delegation_audit_event_hash(event: &DelegationAuditEvent) -> Result<Hash256, AuthorityError> {
    hash_structured(&DelegationAuditEventHashPayload {
        domain: DELEGATION_AUDIT_EVENT_DOMAIN,
        schema_version: DELEGATION_AUDIT_EVENT_SCHEMA_VERSION,
        sequence: event.sequence,
        action: event.action,
        link_id: &event.link_id,
        delegator_did: &event.delegator_did,
        delegate_did: &event.delegate_did,
        timestamp: &event.timestamp,
        previous_event_hash: &event.previous_event_hash,
    })
    .map_err(|e| AuthorityError::AuditHashEncoding {
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use exo_core::{
        PublicKey,
        crypto::{self, KeyPair},
    };

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(&format!("did:exo:{name}")).unwrap()
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }
    fn now() -> Timestamp {
        ts(5000)
    }
    fn public_key(keypair: &KeyPair) -> PublicKey {
        *keypair.public_key()
    }
    fn signed_delegate(
        reg: &mut DelegationRegistry,
        from: &str,
        to: &str,
        scope: &[Permission],
        signer: &KeyPair,
    ) -> Result<AuthorityLink, AuthorityError> {
        signed_delegate_with_parent(reg, from, to, scope, None, signer)
    }
    fn signed_delegate_with_parent(
        reg: &mut DelegationRegistry,
        from: &str,
        to: &str,
        scope: &[Permission],
        parent_link_id: Option<&Hash256>,
        signer: &KeyPair,
    ) -> Result<AuthorityLink, AuthorityError> {
        let public_key = public_key(signer);
        let from = did(from);
        let to = did(to);
        reg.delegate(
            DelegationGrant {
                from: &from,
                to: &to,
                scope,
                expires: ts(10000),
                now: &now(),
                parent_link_id,
                delegatee_kind: DelegateeKind::Human,
                delegator_public_key: &public_key,
            },
            |payload| signer.sign(payload),
        )
    }
    fn signed_revoke(
        reg: &mut DelegationRegistry,
        link_id: &Hash256,
        revoker: &str,
        signer: &KeyPair,
    ) -> Result<AuthorityRevocation, AuthorityError> {
        let revoker = did(revoker);
        reg.revoke_delegation_signed(
            DelegationRevocationGrant {
                link_id,
                revoker: &revoker,
                revoked_at: &ts(6_000),
            },
            |payload| signer.sign(payload),
        )
    }

    fn raw_link(from: &str, to: &str, depth: usize) -> AuthorityLink {
        AuthorityLink {
            delegator_did: did(from),
            delegate_did: did(to),
            scope: vec![Permission::Read],
            created: now(),
            expires: Some(ts(10000)),
            signature: Signature::Empty,
            depth,
            delegatee_kind: DelegateeKind::Human,
        }
    }

    fn insert_raw_link(reg: &mut DelegationRegistry, link: AuthorityLink) {
        let id = link.id().expect("raw authority link id");
        reg.by_delegator
            .entry(link.delegator_did.as_str().to_owned())
            .or_default()
            .push(id);
        reg.by_delegate
            .entry(link.delegate_did.as_str().to_owned())
            .or_default()
            .push(id);
        reg.links.insert(id, link);
    }

    #[test]
    fn delegate_signs_link_with_delegator_key() {
        let mut reg = DelegationRegistry::new();
        let keypair = KeyPair::generate();
        let public_key = public_key(&keypair);
        let link =
            signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &keypair).unwrap();

        assert!(!link.signature.is_empty());
        let payload = link.signing_payload().unwrap();
        assert!(crypto::verify(&payload, &link.signature, &public_key));
    }

    #[test]
    fn delegate_appends_hash_chained_audit_event() {
        let mut reg = DelegationRegistry::new();
        let keypair = KeyPair::generate();

        let link =
            signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &keypair).unwrap();

        let events = reg.audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sequence, 0);
        assert_eq!(events[0].action, DelegationAuditAction::Granted);
        assert_eq!(events[0].link_id, link.id().unwrap());
        assert_eq!(events[0].delegator_did, link.delegator_did);
        assert_eq!(events[0].delegate_did, link.delegate_did);
        assert_eq!(events[0].timestamp, link.created);
        assert_eq!(events[0].previous_event_hash, Hash256::ZERO);
        assert_ne!(events[0].event_hash, Hash256::ZERO);
        reg.verify_audit_chain()
            .expect("delegation audit event must verify");
    }

    #[test]
    fn delegation_audit_chain_detects_tampering() {
        let mut reg = DelegationRegistry::new();
        let keypair = KeyPair::generate();
        signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &keypair).unwrap();

        reg.audit_events[0].delegate_did = did("mallory");

        assert!(matches!(
            reg.verify_audit_chain(),
            Err(AuthorityError::AuditChainBroken { sequence: 0 })
        ));
    }

    #[test]
    fn delegation_registry_has_no_public_auditless_revoke() {
        let source = include_str!("delegation.rs");
        let forbidden = concat!("pub fn ", "revoke_delegation(");

        assert!(
            !source.contains(forbidden),
            "revocation must pass through signed evidence and delegation audit"
        );
    }

    #[test]
    fn delegate_rejects_wrong_key_signature() {
        let mut reg = DelegationRegistry::new();
        let signer = KeyPair::generate();
        let wrong_key = KeyPair::generate();
        let wrong_public_key = public_key(&wrong_key);
        let from = did("alice");
        let to = did("bob");

        let result = reg.delegate(
            DelegationGrant {
                from: &from,
                to: &to,
                scope: &[Permission::Read],
                expires: ts(10000),
                now: &now(),
                parent_link_id: None,
                delegatee_kind: DelegateeKind::Human,
                delegator_public_key: &wrong_public_key,
            },
            |payload| signer.sign(payload),
        );

        assert!(matches!(
            result,
            Err(AuthorityError::InvalidSignature { index: 0 })
        ));
    }

    #[test]
    fn delegate_rejects_empty_signature() {
        let mut reg = DelegationRegistry::new();
        let keypair = KeyPair::generate();
        let public_key = public_key(&keypair);
        let from = did("alice");
        let to = did("bob");

        let result = reg.delegate(
            DelegationGrant {
                from: &from,
                to: &to,
                scope: &[Permission::Read],
                expires: ts(10000),
                now: &now(),
                parent_link_id: None,
                delegatee_kind: DelegateeKind::Human,
                delegator_public_key: &public_key,
            },
            |_payload| Signature::Empty,
        );

        assert!(matches!(
            result,
            Err(AuthorityError::InvalidSignature { index: 0 })
        ));
    }

    #[test]
    fn delegate_rejects_unknown_delegatee_kind_for_new_grants() {
        let mut reg = DelegationRegistry::new();
        let keypair = KeyPair::generate();
        let public_key = public_key(&keypair);
        let from = did("alice");
        let to = did("bob");

        let result = reg.delegate(
            DelegationGrant {
                from: &from,
                to: &to,
                scope: &[Permission::Read],
                expires: ts(10000),
                now: &now(),
                parent_link_id: None,
                delegatee_kind: DelegateeKind::Unknown,
                delegator_public_key: &public_key,
            },
            |payload| keypair.sign(payload),
        );

        assert!(matches!(
            result,
            Err(AuthorityError::InvalidDelegation { reason })
                if reason.contains("delegatee kind")
        ));
    }

    #[test]
    fn delegate_accepts_ai_agent_delegatee_kind_with_model_id() {
        let mut reg = DelegationRegistry::new();
        let keypair = KeyPair::generate();
        let public_key = public_key(&keypair);
        let from = did("alice");
        let to = did("agent");

        let link = reg
            .delegate(
                DelegationGrant {
                    from: &from,
                    to: &to,
                    scope: &[Permission::Read],
                    expires: ts(10000),
                    now: &now(),
                    parent_link_id: None,
                    delegatee_kind: DelegateeKind::AiAgent {
                        model_id: "exo-agent-v1".to_owned(),
                    },
                    delegator_public_key: &public_key,
                },
                |payload| keypair.sign(payload),
            )
            .expect("valid AI-agent delegation");

        assert_eq!(
            link.delegatee_kind,
            DelegateeKind::AiAgent {
                model_id: "exo-agent-v1".to_owned()
            }
        );
    }

    #[test]
    fn delegate_rejects_all_zero_signature() {
        let mut reg = DelegationRegistry::new();
        let keypair = KeyPair::generate();
        let public_key = public_key(&keypair);
        let from = did("alice");
        let to = did("bob");

        let result = reg.delegate(
            DelegationGrant {
                from: &from,
                to: &to,
                scope: &[Permission::Read],
                expires: ts(10000),
                now: &now(),
                parent_link_id: None,
                delegatee_kind: DelegateeKind::Human,
                delegator_public_key: &public_key,
            },
            |_payload| Signature::from_bytes([0u8; 64]),
        );

        assert!(matches!(
            result,
            Err(AuthorityError::InvalidSignature { index: 0 })
        ));
    }

    #[test]
    fn delegate_rejects_duplicate_grant() {
        let mut reg = DelegationRegistry::new();
        let keypair = KeyPair::generate();
        signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &keypair).unwrap();

        let result = signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &keypair);

        assert!(matches!(
            result,
            Err(AuthorityError::DuplicateDelegation { .. })
        ));
    }

    #[test]
    fn find_chain_returns_cryptographically_valid_chain() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let bob_key = KeyPair::generate();
        let alice_to_bob = signed_delegate(
            &mut reg,
            "alice",
            "bob",
            &[Permission::Read, Permission::Write],
            &alice_key,
        )
        .unwrap();
        let alice_to_bob_id = alice_to_bob.id().unwrap();
        signed_delegate_with_parent(
            &mut reg,
            "bob",
            "charlie",
            &[Permission::Read],
            Some(&alice_to_bob_id),
            &bob_key,
        )
        .unwrap();

        let chain = reg
            .find_chain(&did("alice"), &did("charlie"))
            .expect("chain should resolve");
        let keys = std::collections::BTreeMap::from([
            (did("alice").as_str().to_owned(), public_key(&alice_key)),
            (did("bob").as_str().to_owned(), public_key(&bob_key)),
        ]);

        assert!(chain::verify_chain(&chain, &now(), |did| keys.get(did.as_str()).copied()).is_ok());
    }

    #[test]
    fn find_chain_subchain_preserves_signed_depth_and_verifies() {
        let mut reg = DelegationRegistry::new();
        let root_key = KeyPair::generate();
        let alice_key = KeyPair::generate();
        let root_to_alice = signed_delegate(
            &mut reg,
            "root",
            "alice",
            &[Permission::Read, Permission::Write],
            &root_key,
        )
        .unwrap();
        let root_to_alice_id = root_to_alice.id().unwrap();
        let alice_to_bob = signed_delegate_with_parent(
            &mut reg,
            "alice",
            "bob",
            &[Permission::Read],
            Some(&root_to_alice_id),
            &alice_key,
        )
        .unwrap();
        assert_eq!(alice_to_bob.depth, 1);

        let chain = reg
            .find_chain(&did("alice"), &did("bob"))
            .expect("subchain should resolve");
        assert_eq!(chain.links[0].depth, 1);
        let keys = std::collections::BTreeMap::from([(
            did("alice").as_str().to_owned(),
            public_key(&alice_key),
        )]);

        assert!(chain::verify_chain(&chain, &now(), |did| keys.get(did.as_str()).copied()).is_ok());
    }

    #[test]
    fn find_chain_source_does_not_mutate_signed_link_depths() {
        let source = include_str!("delegation.rs");
        let find_chain_source = source
            .split("pub fn find_chain")
            .nth(1)
            .expect("find_chain source present")
            .split("/// Number of active delegations")
            .next()
            .expect("find_chain source end");

        assert!(
            !find_chain_source.contains(".depth ="),
            "find_chain must not mutate signed depth values while assembling a chain"
        );
    }

    #[test]
    fn delegate_creates_link() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let link = signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key);
        assert!(link.is_ok());
        let l = link.unwrap();
        assert_eq!(l.delegator_did, did("alice"));
        assert_eq!(l.delegate_did, did("bob"));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn delegate_detects_circular() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let bob_key = KeyPair::generate();
        signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).ok();
        let result = signed_delegate(&mut reg, "bob", "alice", &[Permission::Read], &bob_key);
        assert!(matches!(result, Err(AuthorityError::CircularDelegation(_))));
    }

    #[test]
    fn delegate_detects_transitive_circular() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let bob_key = KeyPair::generate();
        let charlie_key = KeyPair::generate();
        signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).ok();
        signed_delegate(&mut reg, "bob", "charlie", &[Permission::Read], &bob_key).ok();
        let result = signed_delegate(
            &mut reg,
            "charlie",
            "alice",
            &[Permission::Read],
            &charlie_key,
        );
        assert!(matches!(result, Err(AuthorityError::CircularDelegation(_))));
    }

    #[test]
    fn cycle_detection_uses_iterative_traversal() {
        let production = include_str!("delegation.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section");

        assert!(
            !production.contains("fn has_path_inner("),
            "cycle detection must not recurse on attacker-controlled graph depth"
        );
        assert!(
            !production.contains("self.has_path_inner("),
            "cycle detection must not recurse on attacker-controlled graph depth"
        );
    }

    #[test]
    fn cycle_detection_handles_long_existing_paths() {
        let mut reg = DelegationRegistry::new();

        for i in 0..512 {
            insert_raw_link(
                &mut reg,
                raw_link(&format!("node-{i}"), &format!("node-{}", i + 1), i),
            );
        }

        assert!(reg.has_path(&did("node-0"), &did("node-512")));
        assert!(!reg.has_path(&did("node-0"), &did("missing")));
    }

    #[test]
    fn delegate_uses_selected_parent_depth_for_multi_parent_delegator() {
        let mut reg = DelegationRegistry::new();
        let key = KeyPair::generate();

        let shallow_parent =
            signed_delegate(&mut reg, "root-a", "shared", &[Permission::Read], &key).unwrap();
        let shallow_parent_id = shallow_parent.id().unwrap();
        let root_to_mid =
            signed_delegate(&mut reg, "root-b", "mid", &[Permission::Read], &key).unwrap();
        let root_to_mid_id = root_to_mid.id().unwrap();
        let mid_to_deep = signed_delegate_with_parent(
            &mut reg,
            "mid",
            "deep",
            &[Permission::Read],
            Some(&root_to_mid_id),
            &key,
        )
        .unwrap();
        let mid_to_deep_id = mid_to_deep.id().unwrap();
        let deep_parent = signed_delegate_with_parent(
            &mut reg,
            "deep",
            "shared",
            &[Permission::Read],
            Some(&mid_to_deep_id),
            &key,
        )
        .unwrap();
        let deep_parent_id = deep_parent.id().unwrap();

        let shallow_link = signed_delegate_with_parent(
            &mut reg,
            "shared",
            "leaf-shallow",
            &[Permission::Read],
            Some(&shallow_parent_id),
            &key,
        )
        .unwrap();
        let deep_link = signed_delegate_with_parent(
            &mut reg,
            "shared",
            "leaf-deep",
            &[Permission::Read],
            Some(&deep_parent_id),
            &key,
        )
        .unwrap();

        assert_eq!(shallow_link.depth, 1);
        assert_eq!(deep_link.depth, 3);
    }

    #[test]
    fn delegate_rejects_parent_link_that_does_not_delegate_to_grantor() {
        let mut reg = DelegationRegistry::new();
        let key = KeyPair::generate();
        let parent = signed_delegate(&mut reg, "root", "alice", &[Permission::Read], &key)
            .expect("parent delegation");
        let parent_id = parent.id().unwrap();

        let result = signed_delegate_with_parent(
            &mut reg,
            "bob",
            "charlie",
            &[Permission::Read],
            Some(&parent_id),
            &key,
        );

        assert!(matches!(result, Err(AuthorityError::PermissionDenied(_))));
    }

    #[test]
    fn delegate_rejects_missing_parent_link() {
        let mut reg = DelegationRegistry::new();
        let key = KeyPair::generate();
        let missing_parent_id = Hash256::digest(b"missing-parent-link");

        let result = signed_delegate_with_parent(
            &mut reg,
            "bob",
            "charlie",
            &[Permission::Read],
            Some(&missing_parent_id),
            &key,
        );

        assert!(matches!(result, Err(AuthorityError::NotFound(_))));
    }

    #[test]
    fn delegate_rejects_scope_widening_under_selected_parent() {
        let mut reg = DelegationRegistry::new();
        let key = KeyPair::generate();
        let parent = signed_delegate(&mut reg, "root", "bob", &[Permission::Read], &key)
            .expect("parent delegation");
        let parent_id = parent.id().unwrap();

        let result = signed_delegate_with_parent(
            &mut reg,
            "bob",
            "charlie",
            &[Permission::Write],
            Some(&parent_id),
            &key,
        );

        assert!(matches!(
            result,
            Err(AuthorityError::InvalidDelegation { reason }) if reason.contains("scope")
        ));
    }

    #[test]
    fn unilateral_incoming_depth_cannot_squat_self_root_delegation() {
        let mut reg = DelegationRegistry::new();
        let key = KeyPair::generate();

        let mut parent_link_id = None;
        for i in 0..DEFAULT_MAX_DEPTH {
            let next = if i + 1 == DEFAULT_MAX_DEPTH {
                "victim".to_owned()
            } else {
                format!("attacker-{}", i + 1)
            };
            let link = signed_delegate_with_parent(
                &mut reg,
                &format!("attacker-{i}"),
                next.as_str(),
                &[Permission::Read],
                parent_link_id.as_ref(),
                &key,
            )
            .unwrap();
            parent_link_id = Some(link.id().unwrap());
        }

        let link = signed_delegate(&mut reg, "victim", "leaf", &[Permission::Read], &key)
            .expect("unaccepted incoming delegations must not block self-root grants");

        assert_eq!(
            link.depth, 0,
            "self-root grants must not inherit unilateral incoming depth"
        );
    }

    #[test]
    fn delegate_rejects_chain_beyond_default_max_depth() {
        let mut reg = DelegationRegistry::new();
        let key = KeyPair::generate();

        let mut parent_link_id = None;
        for i in 0..DEFAULT_MAX_DEPTH {
            let link = signed_delegate_with_parent(
                &mut reg,
                &format!("node-{i}"),
                &format!("node-{}", i + 1),
                &[Permission::Read],
                parent_link_id.as_ref(),
                &key,
            )
            .unwrap();
            parent_link_id = Some(link.id().unwrap());
        }

        let result = signed_delegate_with_parent(
            &mut reg,
            &format!("node-{DEFAULT_MAX_DEPTH}"),
            "too-deep",
            &[Permission::Read],
            parent_link_id.as_ref(),
            &key,
        );

        assert!(matches!(
            result,
            Err(AuthorityError::DepthExceeded {
                depth: 6,
                max_depth: DEFAULT_MAX_DEPTH
            })
        ));
    }

    #[test]
    fn signed_revoke_delegation_removes_link() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let link =
            signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).unwrap();
        let id = link.id().unwrap();
        assert!(signed_revoke(&mut reg, &id, "alice", &alice_key).is_ok());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn signed_revoke_delegation_returns_verifiable_revocation() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let alice = did("alice");
        let alice_public_key = public_key(&alice_key);
        let link =
            signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).unwrap();
        let id = link.id().unwrap();

        let revocation = reg
            .revoke_delegation_signed(
                DelegationRevocationGrant {
                    link_id: &id,
                    revoker: &alice,
                    revoked_at: &ts(6_000),
                },
                |payload| alice_key.sign(payload),
            )
            .unwrap();

        assert_eq!(revocation.revoked_link_hash, id);
        assert!(!revocation.signature.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(
            revocation
                .verify(|did| {
                    if did == &alice {
                        Some(alice_public_key)
                    } else {
                        None
                    }
                })
                .is_ok()
        );
    }

    #[test]
    fn signed_revoke_delegation_appends_hash_chained_audit_event() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let alice = did("alice");
        let link =
            signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).unwrap();
        let id = link.id().unwrap();
        let grant_event_hash = reg.audit_events()[0].event_hash;

        reg.revoke_delegation_signed(
            DelegationRevocationGrant {
                link_id: &id,
                revoker: &alice,
                revoked_at: &ts(6_000),
            },
            |payload| alice_key.sign(payload),
        )
        .unwrap();

        let events = reg.audit_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].sequence, 1);
        assert_eq!(events[1].action, DelegationAuditAction::Revoked);
        assert_eq!(events[1].link_id, id);
        assert_eq!(events[1].delegator_did, did("alice"));
        assert_eq!(events[1].delegate_did, did("bob"));
        assert_eq!(events[1].timestamp, ts(6_000));
        assert_eq!(events[1].previous_event_hash, grant_event_hash);
        assert_ne!(events[1].event_hash, Hash256::ZERO);
        reg.verify_audit_chain()
            .expect("signed revocation audit event must verify");
    }

    #[test]
    fn signed_revoke_delegation_rejects_wrong_key_signature() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let wrong_key = KeyPair::generate();
        let alice = did("alice");
        let link =
            signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).unwrap();
        let id = link.id().unwrap();

        let result = reg.revoke_delegation_signed(
            DelegationRevocationGrant {
                link_id: &id,
                revoker: &alice,
                revoked_at: &ts(6_000),
            },
            |payload| wrong_key.sign(payload),
        );

        assert!(matches!(
            result,
            Err(AuthorityError::InvalidSignature { index: 0 })
        ));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn signed_revoke_delegation_rejects_attacker_supplied_revoker_key() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let attacker_key = KeyPair::generate();
        let alice = did("alice");
        let link =
            signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).unwrap();
        let id = link.id().unwrap();

        let result = reg.revoke_delegation_signed(
            DelegationRevocationGrant {
                link_id: &id,
                revoker: &alice,
                revoked_at: &ts(6_000),
            },
            |payload| attacker_key.sign(payload),
        );

        assert!(matches!(
            result,
            Err(AuthorityError::InvalidSignature { index: 0 })
        ));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn signed_revocation_source_does_not_trust_caller_public_key() {
        let source = include_str!("delegation.rs");
        let grant_source = source
            .split("pub struct DelegationRevocationGrant")
            .nth(1)
            .expect("revocation grant source present")
            .split("}")
            .next()
            .expect("revocation grant body present");
        let revoke_source = source
            .split("pub fn revoke_delegation_signed")
            .nth(1)
            .expect("signed revocation source present")
            .split("/// Find a delegation chain")
            .next()
            .expect("signed revocation source end");

        assert!(
            !grant_source.contains("revoker_public_key"),
            "revocation callers must not supply the public key used to verify their own signature"
        );
        assert!(
            revoke_source.contains("link_delegator_public_keys"),
            "signed revocation must verify against the public key bound to the original link"
        );
    }

    #[test]
    fn signed_revoke_delegation_rejects_non_delegator_revoker() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let bob_key = KeyPair::generate();
        let bob = did("bob");
        let link =
            signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).unwrap();
        let id = link.id().unwrap();

        let result = reg.revoke_delegation_signed(
            DelegationRevocationGrant {
                link_id: &id,
                revoker: &bob,
                revoked_at: &ts(6_000),
            },
            |payload| bob_key.sign(payload),
        );

        assert!(matches!(result, Err(AuthorityError::PermissionDenied(_))));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn revoke_nonexistent() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let fake = Hash256::digest(b"fake");
        assert!(matches!(
            signed_revoke(&mut reg, &fake, "alice", &alice_key),
            Err(AuthorityError::NotFound(_))
        ));
    }

    #[test]
    fn missing_revocation_reports_stable_hash_label() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let fake = Hash256::digest(b"missing-revocation");

        let result = signed_revoke(&mut reg, &fake, "alice", &alice_key);

        match result {
            Err(AuthorityError::NotFound(id)) => {
                assert_eq!(id, fake.to_string());
                assert!(
                    !id.contains("Hash256("),
                    "missing-link labels must not depend on Debug output"
                );
            }
            other => panic!("expected NotFound with stable hash label, got {other:?}"),
        }
    }

    #[test]
    fn missing_signed_revocation_reports_stable_hash_label() {
        let mut reg = DelegationRegistry::new();
        let fake = Hash256::digest(b"missing-signed-revocation");
        let alice = did("alice");
        let alice_key = KeyPair::generate();

        let result = reg.revoke_delegation_signed(
            DelegationRevocationGrant {
                link_id: &fake,
                revoker: &alice,
                revoked_at: &ts(6_000),
            },
            |payload| alice_key.sign(payload),
        );

        match result {
            Err(AuthorityError::NotFound(id)) => {
                assert_eq!(id, fake.to_string());
                assert!(
                    !id.contains("Hash256("),
                    "missing signed-revocation labels must not depend on Debug output"
                );
            }
            other => panic!("expected NotFound with stable hash label, got {other:?}"),
        }
    }

    #[test]
    fn find_chain_direct() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).ok();
        let chain = reg.find_chain(&did("alice"), &did("bob"));
        assert!(chain.is_some());
        assert_eq!(chain.unwrap().depth(), 1);
    }

    #[test]
    fn find_chain_transitive() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let bob_key = KeyPair::generate();
        let alice_to_bob = signed_delegate(
            &mut reg,
            "alice",
            "bob",
            &[Permission::Read, Permission::Write],
            &alice_key,
        )
        .ok();
        let alice_to_bob_id = alice_to_bob.unwrap().id().unwrap();
        signed_delegate_with_parent(
            &mut reg,
            "bob",
            "charlie",
            &[Permission::Read],
            Some(&alice_to_bob_id),
            &bob_key,
        )
        .ok();
        let chain = reg.find_chain(&did("alice"), &did("charlie"));
        assert!(chain.is_some());
        assert_eq!(chain.unwrap().depth(), 2);
    }

    #[test]
    fn find_chain_nonexistent() {
        let reg = DelegationRegistry::new();
        assert!(reg.find_chain(&did("alice"), &did("bob")).is_none());
    }

    #[test]
    fn find_chain_no_path() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).ok();
        assert!(reg.find_chain(&did("alice"), &did("charlie")).is_none());
    }

    #[test]
    fn is_empty_initially() {
        let reg = DelegationRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn revoke_cleans_indexes() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let l = signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).unwrap();
        signed_revoke(&mut reg, &l.id().unwrap(), "alice", &alice_key).ok();
        // After revocation, chain should not be found
        assert!(reg.find_chain(&did("alice"), &did("bob")).is_none());
    }

    #[test]
    fn multiple_delegations_from_same_source() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).ok();
        signed_delegate(
            &mut reg,
            "alice",
            "charlie",
            &[Permission::Write],
            &alice_key,
        )
        .ok();
        assert_eq!(reg.len(), 2);
        assert!(reg.find_chain(&did("alice"), &did("bob")).is_some());
        assert!(reg.find_chain(&did("alice"), &did("charlie")).is_some());
    }

    #[test]
    fn self_delegation_detected_as_circular() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let result = signed_delegate(&mut reg, "alice", "alice", &[Permission::Read], &alice_key);
        assert!(matches!(result, Err(AuthorityError::CircularDelegation(_))));
    }
}
