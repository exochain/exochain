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
        Self::validate_item(&tenant_id, &item)?;
        if item.tenant_id != tenant_id {
            return Err(TenantError::StorageError {
                reason: "tenant_id mismatch".into(),
            });
        }
        let item_id = item.id;
        let tenant_items = self.data.entry(tenant_id).or_default();
        if tenant_items.contains_key(&item_id) {
            return Err(TenantError::StorageRecordAlreadyExists { tenant_id, item_id });
        }
        tenant_items.insert(item_id, item);
        Ok(())
    }

    fn validate_item(tenant_id: &Uuid, item: &TenantData) -> Result<()> {
        if *tenant_id == Uuid::nil() {
            return Err(TenantError::StorageError {
                reason: "tenant id must not be nil".into(),
            });
        }
        if item.tenant_id == Uuid::nil() {
            return Err(TenantError::StorageError {
                reason: "item tenant id must not be nil".into(),
            });
        }
        if item.id == Uuid::nil() {
            return Err(TenantError::StorageError {
                reason: "item id must not be nil".into(),
            });
        }
        if item.content_hash == Hash256::ZERO {
            return Err(TenantError::StorageError {
                reason: "content hash must not be zero".into(),
            });
        }
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
            .ok_or(TenantError::StorageRecordNotFound {
                tenant_id: *tenant_id,
                item_id: *item_id,
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

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn td(tid: Uuid, item_id: Uuid) -> TenantData {
        TenantData {
            id: item_id,
            tenant_id: tid,
            owner: Did::new("did:exo:owner").unwrap(),
            content_hash: Hash256::digest(format!("{tid}:{item_id}").as_bytes()),
        }
    }

    #[test]
    fn put_and_get() {
        let mut s = TenantStore::new();
        let tid = uuid(1);
        let item = td(tid, uuid(10));
        let iid = item.id;
        s.put(tid, item).unwrap();
        assert!(s.get(&tid, &iid).is_some());
    }
    #[test]
    fn put_mismatch() {
        let mut s = TenantStore::new();
        let item = td(uuid(1), uuid(10));
        assert!(s.put(uuid(2), item).is_err());
    }

    #[test]
    fn put_rejects_nil_tenant_id() {
        let mut s = TenantStore::new();
        assert!(s.put(Uuid::nil(), td(Uuid::nil(), uuid(10))).is_err());
    }

    #[test]
    fn put_rejects_nil_item_id() {
        let mut s = TenantStore::new();
        assert!(s.put(uuid(1), td(uuid(1), Uuid::nil())).is_err());
    }

    #[test]
    fn put_rejects_zero_content_hash() {
        let mut s = TenantStore::new();
        let mut item = td(uuid(1), uuid(10));
        item.content_hash = Hash256::ZERO;
        assert!(s.put(uuid(1), item).is_err());
    }

    #[test]
    fn put_rejects_duplicate_item_in_same_tenant() {
        let mut s = TenantStore::new();
        let tid = uuid(1);
        let iid = uuid(10);
        s.put(tid, td(tid, iid)).unwrap();
        assert!(s.put(tid, td(tid, iid)).is_err());
    }

    #[test]
    fn delete_ok() {
        let mut s = TenantStore::new();
        let tid = uuid(1);
        let item = td(tid, uuid(10));
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
        let t1 = uuid(1);
        let t2 = uuid(2);
        let item = td(t1, uuid(10));
        let iid = item.id;
        s.put(t1, item).unwrap();
        assert!(s.get(&t2, &iid).is_none());
    }

    #[test]
    fn same_item_id_can_exist_in_different_tenants_without_cross_read() {
        let mut s = TenantStore::new();
        let t1 = uuid(1);
        let t2 = uuid(2);
        let item_id = uuid(10);
        s.put(t1, td(t1, item_id)).unwrap();
        s.put(t2, td(t2, item_id)).unwrap();
        assert_eq!(s.get(&t1, &item_id).unwrap().tenant_id, t1);
        assert_eq!(s.get(&t2, &item_id).unwrap().tenant_id, t2);
    }

    #[test]
    fn get_isolated() {
        let mut s = TenantStore::new();
        let tid = uuid(1);
        let item = td(tid, uuid(10));
        let iid = item.id;
        s.put(tid, item).unwrap();
        assert!(s.get_isolated(&tid, &iid).is_some());
    }
    #[test]
    fn count() {
        let mut s = TenantStore::new();
        let tid = uuid(1);
        s.put(tid, td(tid, uuid(10))).unwrap();
        s.put(tid, td(tid, uuid(11))).unwrap();
        assert_eq!(s.count(&tid), 2);
    }
    #[test]
    fn default() {
        assert_eq!(TenantStore::default().count(&Uuid::nil()), 0);
    }
}
