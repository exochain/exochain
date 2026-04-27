//! Delegation management — tracks active delegations and resolves chains.

use std::collections::{BTreeMap, BTreeSet};

use exo_core::{Did, Hash256, PublicKey, Signature, Timestamp, crypto};

use crate::{
    chain::{self, AuthorityChain, AuthorityLink, DEFAULT_MAX_DEPTH, DelegateeKind},
    error::AuthorityError,
    permission::Permission,
};

/// Registry of all active delegations.
#[derive(Debug, Default)]
pub struct DelegationRegistry {
    /// Links indexed by their hash ID.
    links: BTreeMap<Hash256, AuthorityLink>,
    /// Forward index: delegator DID -> list of link IDs.
    by_delegator: BTreeMap<String, Vec<Hash256>>,
    /// Reverse index: delegate DID -> list of link IDs.
    by_delegate: BTreeMap<String, Vec<Hash256>>,
}

/// Caller-supplied fields for a signed delegation grant.
pub struct DelegationGrant<'a> {
    pub from: &'a Did,
    pub to: &'a Did,
    pub scope: &'a [Permission],
    pub expires: Timestamp,
    pub now: &'a Timestamp,
    pub delegatee_kind: DelegateeKind,
    pub delegator_public_key: &'a PublicKey,
}

impl DelegationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        if let DelegateeKind::AiAgent { model_id } = &delegatee_kind {
            if model_id.trim().is_empty() {
                return Err(AuthorityError::InvalidDelegation {
                    reason: "AI-agent delegatee kind requires a non-empty model_id".into(),
                });
            }
        }

        let scope = canonical_scope(scope)?;
        let depth = self.compute_depth(from);

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
        self.links.insert(id, link.clone());
        self.by_delegator
            .entry(from.as_str().to_owned())
            .or_default()
            .push(id);
        self.by_delegate
            .entry(to.as_str().to_owned())
            .or_default()
            .push(id);

        Ok(link)
    }

    /// Revoke a delegation by its link ID.
    ///
    /// # Errors
    /// Returns `NotFound` if the link doesn't exist.
    pub fn revoke_delegation(&mut self, link_id: &Hash256) -> Result<(), AuthorityError> {
        let link = self
            .links
            .remove(link_id)
            .ok_or_else(|| AuthorityError::NotFound(format!("{link_id:?}")))?;

        if let Some(ids) = self.by_delegator.get_mut(link.delegator_did.as_str()) {
            ids.retain(|id| id != link_id);
        }
        if let Some(ids) = self.by_delegate.get_mut(link.delegate_did.as_str()) {
            ids.retain(|id| id != link_id);
        }

        Ok(())
    }

    /// Find a delegation chain from `from` to `to`.
    #[must_use]
    pub fn find_chain(&self, from: &Did, to: &Did) -> Option<AuthorityChain> {
        let mut path = Vec::new();
        if self.find_path_dfs(from, to, &mut path, 0, DEFAULT_MAX_DEPTH) {
            // Re-number depths
            for (i, link) in path.iter_mut().enumerate() {
                link.depth = i;
            }
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
        let mut visited = std::collections::BTreeSet::new();
        self.has_path_inner(from, to, &mut visited)
    }

    fn has_path_inner(
        &self,
        current: &Did,
        target: &Did,
        visited: &mut std::collections::BTreeSet<String>,
    ) -> bool {
        if current == target {
            return true;
        }
        if !visited.insert(current.as_str().to_owned()) {
            return false;
        }
        if let Some(ids) = self.by_delegator.get(current.as_str()) {
            for id in ids {
                if let Some(link) = self.links.get(id) {
                    if self.has_path_inner(&link.delegate_did, target, visited) {
                        return true;
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

    fn compute_depth(&self, did: &Did) -> usize {
        // Depth = number of links in the chain to this DID as delegate
        if let Some(ids) = self.by_delegate.get(did.as_str()) {
            if let Some(id) = ids.first() {
                if let Some(link) = self.links.get(id) {
                    return link.depth + 1;
                }
            }
        }
        0
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
    let raw = signature.as_bytes();
    !raw.is_empty() && raw.iter().all(|b| *b == 0)
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
                delegatee_kind: DelegateeKind::Human,
                delegator_public_key: &public_key,
            },
            |payload| signer.sign(payload),
        )
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
        signed_delegate(
            &mut reg,
            "alice",
            "bob",
            &[Permission::Read, Permission::Write],
            &alice_key,
        )
        .unwrap();
        signed_delegate(&mut reg, "bob", "charlie", &[Permission::Read], &bob_key).unwrap();

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
    fn revoke_delegation() {
        let mut reg = DelegationRegistry::new();
        let alice_key = KeyPair::generate();
        let link =
            signed_delegate(&mut reg, "alice", "bob", &[Permission::Read], &alice_key).unwrap();
        let id = link.id().unwrap();
        assert!(reg.revoke_delegation(&id).is_ok());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn revoke_nonexistent() {
        let mut reg = DelegationRegistry::new();
        let fake = Hash256::digest(b"fake");
        assert!(matches!(
            reg.revoke_delegation(&fake),
            Err(AuthorityError::NotFound(_))
        ));
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
        signed_delegate(
            &mut reg,
            "alice",
            "bob",
            &[Permission::Read, Permission::Write],
            &alice_key,
        )
        .ok();
        signed_delegate(&mut reg, "bob", "charlie", &[Permission::Read], &bob_key).ok();
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
        reg.revoke_delegation(&l.id().unwrap()).ok();
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
