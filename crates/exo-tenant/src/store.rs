//! Tenant-aware storage abstraction.
use std::collections::BTreeMap;

use exo_core::{Did, Hash256};
use uuid::Uuid;

use crate::error::{Result, TenantError};

/// A tenant-scoped data item.
#[derive(Debug, Clone)]
pub struct TenantData {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub owner: Did,
    pub content_hash: Hash256,
}

/// Tenant-aware key-value store with isolation guarantees.
#[derive(Debug, Default)]
pub struct TenantStore {
    data: BTreeMap<Uuid, BTreeMap<Uuid, TenantData>>,
}

impl TenantStore {
    /// Create an empty tenant store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    /// Store an item under the given tenant, enforcing tenant-ID consistency.
    pub fn put(&mut self, tenant_id: Uuid, item: TenantData) -> Result<()> {
        if item.tenant_id != tenant_id {
            return Err(TenantError::StorageError {
                reason: "tenant_id mismatch".into(),
            });
        }
        self.data
            .entry(tenant_id)
            .or_default()
            .insert(item.id, item);
        Ok(())
    }

    /// Retrieve an item by tenant and item ID.
    #[must_use]
    pub fn get(&self, tenant_id: &Uuid, item_id: &Uuid) -> Option<&TenantData> {
        self.data.get(tenant_id)?.get(item_id)
    }

    /// Remove an item, returning it on success or an error if not found.
    pub fn delete(&mut self, tenant_id: &Uuid, item_id: &Uuid) -> Result<TenantData> {
        self.data
            .get_mut(tenant_id)
            .and_then(|m| m.remove(item_id))
            .ok_or(TenantError::StorageError {
                reason: format!("item {item_id} not found in tenant {tenant_id}"),
            })
    }

    /// Cross-tenant access is forbidden — this returns None for wrong tenant.
    #[must_use]
    pub fn get_isolated(&self, tenant_id: &Uuid, item_id: &Uuid) -> Option<&TenantData> {
        let item = self.get(tenant_id, item_id)?;
        if item.tenant_id == *tenant_id {
            Some(item)
        } else {
            None
        }
    }

    /// Return the number of items stored for a tenant.
    #[must_use]
    pub fn count(&self, tenant_id: &Uuid) -> usize {
        self.data.get(tenant_id).map_or(0, |m| m.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn td(tid: Uuid) -> TenantData {
        TenantData {
            id: Uuid::new_v4(),
            tenant_id: tid,
            owner: Did::new("did:exo:owner").unwrap(),
            content_hash: Hash256::ZERO,
        }
    }

    #[test]
    fn put_and_get() {
        let mut s = TenantStore::new();
        let tid = Uuid::new_v4();
        let item = td(tid);
        let iid = item.id;
        s.put(tid, item).unwrap();
        assert!(s.get(&tid, &iid).is_some());
    }
    #[test]
    fn put_mismatch() {
        let mut s = TenantStore::new();
        let item = td(Uuid::new_v4());
        assert!(s.put(Uuid::new_v4(), item).is_err());
    }
    #[test]
    fn delete_ok() {
        let mut s = TenantStore::new();
        let tid = Uuid::new_v4();
        let item = td(tid);
        let iid = item.id;
        s.put(tid, item).unwrap();
        s.delete(&tid, &iid).unwrap();
        assert_eq!(s.count(&tid), 0);
    }
    #[test]
    fn delete_not_found() {
        let mut s = TenantStore::new();
        assert!(s.delete(&Uuid::nil(), &Uuid::nil()).is_err());
    }
    #[test]
    fn isolation() {
        let mut s = TenantStore::new();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let item = td(t1);
        let iid = item.id;
        s.put(t1, item).unwrap();
        assert!(s.get(&t2, &iid).is_none());
    }
    #[test]
    fn get_isolated() {
        let mut s = TenantStore::new();
        let tid = Uuid::new_v4();
        let item = td(tid);
        let iid = item.id;
        s.put(tid, item).unwrap();
        assert!(s.get_isolated(&tid, &iid).is_some());
    }
    #[test]
    fn count() {
        let mut s = TenantStore::new();
        let tid = Uuid::new_v4();
        s.put(tid, td(tid)).unwrap();
        s.put(tid, td(tid)).unwrap();
        assert_eq!(s.count(&tid), 2);
    }
    #[test]
    fn default() {
        assert_eq!(TenantStore::default().count(&Uuid::nil()), 0);
    }
}
