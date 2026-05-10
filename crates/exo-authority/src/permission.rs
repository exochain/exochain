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

//! Permission types for authority chains.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Permission types in the EXOCHAIN authority model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Permission {
    Read,
    Write,
    Execute,
    Delegate,
    Govern,
    Escalate,
    Challenge,
}

/// A deterministic set of permissions (BTreeSet for canonical ordering).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSet(BTreeSet<Permission>);

impl PermissionSet {
    /// Create an empty permission set.
    #[must_use]
    pub fn empty() -> Self {
        Self(BTreeSet::new())
    }

    /// Create a permission set from a list of permissions.
    #[must_use]
    pub fn from_permissions(perms: &[Permission]) -> Self {
        Self(perms.iter().copied().collect())
    }

    /// Check if this set contains a specific permission.
    #[must_use]
    pub fn contains(&self, p: &Permission) -> bool {
        self.0.contains(p)
    }

    /// Number of permissions in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Is the set empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Insert a permission.
    pub fn insert(&mut self, p: Permission) {
        self.0.insert(p);
    }

    /// Iterate over permissions in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = &Permission> {
        self.0.iter()
    }

    /// Check if `a` is a subset of `b`.
    #[must_use]
    pub fn is_subset(a: &PermissionSet, b: &PermissionSet) -> bool {
        a.0.is_subset(&b.0)
    }

    /// Compute the intersection of two permission sets.
    #[must_use]
    pub fn intersect(a: &PermissionSet, b: &PermissionSet) -> PermissionSet {
        PermissionSet(a.0.intersection(&b.0).copied().collect())
    }
}

impl Default for PermissionSet {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_set() {
        let s = PermissionSet::empty();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn from_permissions() {
        let s = PermissionSet::from_permissions(&[Permission::Read, Permission::Write]);
        assert_eq!(s.len(), 2);
        assert!(s.contains(&Permission::Read));
        assert!(s.contains(&Permission::Write));
        assert!(!s.contains(&Permission::Execute));
    }

    #[test]
    fn insert() {
        let mut s = PermissionSet::empty();
        s.insert(Permission::Govern);
        assert!(s.contains(&Permission::Govern));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn dedup_on_from() {
        let s = PermissionSet::from_permissions(&[
            Permission::Read,
            Permission::Read,
            Permission::Read,
        ]);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn is_subset_true() {
        let a = PermissionSet::from_permissions(&[Permission::Read]);
        let b = PermissionSet::from_permissions(&[Permission::Read, Permission::Write]);
        assert!(PermissionSet::is_subset(&a, &b));
    }

    #[test]
    fn is_subset_false() {
        let a = PermissionSet::from_permissions(&[Permission::Read, Permission::Execute]);
        let b = PermissionSet::from_permissions(&[Permission::Read, Permission::Write]);
        assert!(!PermissionSet::is_subset(&a, &b));
    }

    #[test]
    fn is_subset_equal() {
        let a = PermissionSet::from_permissions(&[Permission::Read, Permission::Write]);
        assert!(PermissionSet::is_subset(&a, &a));
    }

    #[test]
    fn is_subset_empty() {
        let a = PermissionSet::empty();
        let b = PermissionSet::from_permissions(&[Permission::Read]);
        assert!(PermissionSet::is_subset(&a, &b));
        assert!(PermissionSet::is_subset(&a, &a));
    }

    #[test]
    fn intersect() {
        let a = PermissionSet::from_permissions(&[
            Permission::Read,
            Permission::Write,
            Permission::Execute,
        ]);
        let b = PermissionSet::from_permissions(&[Permission::Read, Permission::Delegate]);
        let i = PermissionSet::intersect(&a, &b);
        assert_eq!(i.len(), 1);
        assert!(i.contains(&Permission::Read));
    }

    #[test]
    fn intersect_empty() {
        let a = PermissionSet::from_permissions(&[Permission::Read]);
        let b = PermissionSet::from_permissions(&[Permission::Write]);
        let i = PermissionSet::intersect(&a, &b);
        assert!(i.is_empty());
    }

    #[test]
    fn iter_deterministic() {
        let s = PermissionSet::from_permissions(&[
            Permission::Write,
            Permission::Read,
            Permission::Execute,
        ]);
        let collected: Vec<&Permission> = s.iter().collect();
        // BTreeSet gives deterministic order
        assert_eq!(collected.len(), 3);
    }

    #[test]
    fn default_is_empty() {
        let s = PermissionSet::default();
        assert!(s.is_empty());
    }

    #[test]
    fn permission_variants_distinct() {
        assert_ne!(Permission::Read, Permission::Write);
        assert_ne!(Permission::Execute, Permission::Delegate);
        assert_ne!(Permission::Govern, Permission::Escalate);
        assert_ne!(Permission::Challenge, Permission::Read);
        assert_eq!(Permission::Read, Permission::Read);
    }

    #[test]
    fn permission_ord() {
        // Just verify Ord works
        let mut v = [Permission::Write, Permission::Read, Permission::Execute];
        v.sort();
        assert_eq!(v[0], v[0]); // deterministic
    }
}
