//! Delegation management — tracks active delegations and resolves chains.

use std::collections::BTreeMap;

use exo_core::{Did, Hash256, Signature, Timestamp};

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
        from: &Did,
        to: &Did,
        scope: &[Permission],
        expires: Timestamp,
        now: &Timestamp,
        delegatee_kind: DelegateeKind,
    ) -> Result<AuthorityLink, AuthorityError> {
        // Detect circular: if `to` already delegates (directly or transitively) to `from`
        if self.has_path(to, from) {
            return Err(AuthorityError::CircularDelegation(format!(
                "{} -> {} would create a cycle",
                from, to
            )));
        }

        let depth = self.compute_depth(from);

        let link = AuthorityLink {
            delegator_did: from.clone(),
            delegate_did: to.clone(),
            scope: scope.to_vec(),
            created: *now,
            expires: Some(expires),
            signature: Signature::from_bytes([1u8; 64]), // placeholder
            depth,
            delegatee_kind,
        };

        let id = link.id();
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

#[cfg(test)]
mod tests {
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

    #[test]
    fn delegate_creates_link() {
        let mut reg = DelegationRegistry::new();
        let link = reg.delegate(
            &did("alice"),
            &did("bob"),
            &[Permission::Read],
            ts(10000),
            &now(),
            DelegateeKind::Human,
        );
        assert!(link.is_ok());
        let l = link.unwrap();
        assert_eq!(l.delegator_did, did("alice"));
        assert_eq!(l.delegate_did, did("bob"));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn delegate_detects_circular() {
        let mut reg = DelegationRegistry::new();
        reg.delegate(
            &did("alice"),
            &did("bob"),
            &[Permission::Read],
            ts(10000),
            &now(),
            DelegateeKind::Human,
        )
        .ok();
        let result = reg.delegate(
            &did("bob"),
            &did("alice"),
            &[Permission::Read],
            ts(10000),
            &now(),
            DelegateeKind::Human,
        );
        assert!(matches!(result, Err(AuthorityError::CircularDelegation(_))));
    }

    #[test]
    fn delegate_detects_transitive_circular() {
        let mut reg = DelegationRegistry::new();
        reg.delegate(
            &did("alice"),
            &did("bob"),
            &[Permission::Read],
            ts(10000),
            &now(),
            DelegateeKind::Human,
        )
        .ok();
        reg.delegate(
            &did("bob"),
            &did("charlie"),
            &[Permission::Read],
            ts(10000),
            &now(),
            DelegateeKind::Human,
        )
        .ok();
        let result = reg.delegate(
            &did("charlie"),
            &did("alice"),
            &[Permission::Read],
            ts(10000),
            &now(),
            DelegateeKind::Human,
        );
        assert!(matches!(result, Err(AuthorityError::CircularDelegation(_))));
    }

    #[test]
    fn revoke_delegation() {
        let mut reg = DelegationRegistry::new();
        let link = reg
            .delegate(
                &did("alice"),
                &did("bob"),
                &[Permission::Read],
                ts(10000),
                &now(),
                DelegateeKind::Human,
            )
            .unwrap();
        let id = link.id();
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
        reg.delegate(
            &did("alice"),
            &did("bob"),
            &[Permission::Read],
            ts(10000),
            &now(),
            DelegateeKind::Human,
        )
        .ok();
        let chain = reg.find_chain(&did("alice"), &did("bob"));
        assert!(chain.is_some());
        assert_eq!(chain.unwrap().depth(), 1);
    }

    #[test]
    fn find_chain_transitive() {
        let mut reg = DelegationRegistry::new();
        reg.delegate(
            &did("alice"),
            &did("bob"),
            &[Permission::Read, Permission::Write],
            ts(10000),
            &now(),
            DelegateeKind::Human,
        )
        .ok();
        reg.delegate(
            &did("bob"),
            &did("charlie"),
            &[Permission::Read],
            ts(10000),
            &now(),
            DelegateeKind::Human,
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
        reg.delegate(
            &did("alice"),
            &did("bob"),
            &[Permission::Read],
            ts(10000),
            &now(),
            DelegateeKind::Human,
        )
        .ok();
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
        let l = reg
            .delegate(
                &did("alice"),
                &did("bob"),
                &[Permission::Read],
                ts(10000),
                &now(),
                DelegateeKind::Human,
            )
            .unwrap();
        reg.revoke_delegation(&l.id()).ok();
        // After revocation, chain should not be found
        assert!(reg.find_chain(&did("alice"), &did("bob")).is_none());
    }

    #[test]
    fn multiple_delegations_from_same_source() {
        let mut reg = DelegationRegistry::new();
        reg.delegate(
            &did("alice"),
            &did("bob"),
            &[Permission::Read],
            ts(10000),
            &now(),
            DelegateeKind::Human,
        )
        .ok();
        reg.delegate(
            &did("alice"),
            &did("charlie"),
            &[Permission::Write],
            ts(10000),
            &now(),
            DelegateeKind::Human,
        )
        .ok();
        assert_eq!(reg.len(), 2);
        assert!(reg.find_chain(&did("alice"), &did("bob")).is_some());
        assert!(reg.find_chain(&did("alice"), &did("charlie")).is_some());
    }

    #[test]
    fn self_delegation_detected_as_circular() {
        let mut reg = DelegationRegistry::new();
        let result = reg.delegate(
            &did("alice"),
            &did("alice"),
            &[Permission::Read],
            ts(10000),
            &now(),
            DelegateeKind::Human,
        );
        assert!(matches!(result, Err(AuthorityError::CircularDelegation(_))));
    }
}
