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

//! Tenant-aware storage abstraction.
use std::collections::BTreeMap;

use exo_core::{Did, Hash256};
use uuid::Uuid;

use crate::error::{Result, TenantError};

/// A tenant-scoped data item.
///
/// `content_hash` and `byte_len` are private and derived exclusively from the
/// real payload by [`TenantData::new`] — there is no way for a caller (or a
/// meter) to construct a `TenantData` that claims a `byte_len` different from
/// the actual payload length. This is what makes byte-total reconciliation
/// (`TenantStore::total_bytes`) a genuine check against real stored state
/// rather than against a self-reported, forgeable number.
#[derive(Debug, Clone)]
pub struct TenantData {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub owner: Did,
    content_hash: Hash256,
    byte_len: u64,
}

impl TenantData {
    /// Construct a tenant item from its real payload. `content_hash` is the
    /// BLAKE3 digest of `payload` and `byte_len` is `payload.len()` — both
    /// are computed here and cannot be supplied or overridden by the caller,
    /// so a meter cannot inflate/deflate the store's authoritative byte size.
    #[must_use]
    pub fn new(id: Uuid, tenant_id: Uuid, owner: Did, payload: &[u8]) -> Self {
        Self {
            id,
            tenant_id,
            owner,
            content_hash: Hash256::digest(payload),
            byte_len: u64::try_from(payload.len()).unwrap_or(u64::MAX),
        }
    }

    /// The BLAKE3 content hash of the payload this item was created from.
    #[must_use]
    pub fn content_hash(&self) -> Hash256 {
        self.content_hash
    }

    /// The real byte length of the payload this item was created from.
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }
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

    /// Return the sum of the recorded, actual byte lengths of every item
    /// stored for `tenant_id`. This is the store's own authoritative byte
    /// total — computed directly from durably recorded `TenantData::byte_len`
    /// values, not from any externally reported counter — so callers can
    /// reconcile a meter's self-reported usage against genuine stored state.
    /// The compatibility total saturates at `u64::MAX`; checked callers
    /// should use [`Self::try_total_bytes`].
    #[must_use]
    pub fn total_bytes(&self, tenant_id: &Uuid) -> u64 {
        self.data.get(tenant_id).map_or(0, |m| {
            m.values()
                .map(|item| item.byte_len)
                .fold(0, u64::saturating_add)
        })
    }

    /// Return the checked sum of actual recorded byte lengths for a tenant.
    ///
    /// # Errors
    /// Returns [`TenantError::UsageTotalOverflow`] when the mathematical
    /// total cannot be represented as a `u64`.
    pub fn try_total_bytes(&self, tenant_id: &Uuid) -> Result<u64> {
        self.data.get(tenant_id).map_or(Ok(0), |items| {
            items.values().try_fold(0u64, |total, item| {
                total
                    .checked_add(item.byte_len)
                    .ok_or(TenantError::UsageTotalOverflow {
                        tenant_id: *tenant_id,
                        field: "store_total_bytes",
                    })
            })
        })
    }

    /// Return the actual recorded byte length of a single stored item, or
    /// `None` if it is not present for the given tenant.
    #[must_use]
    pub fn item_bytes(&self, tenant_id: &Uuid, item_id: &Uuid) -> Option<u64> {
        self.get(tenant_id, item_id).map(|item| item.byte_len)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn td(tid: Uuid, item_id: Uuid) -> TenantData {
        // Real payload seeded by the ids so content_hash is distinct per item
        // and byte_len is genuinely derived (never hand-set).
        let payload = format!("{tid}:{item_id}").into_bytes();
        TenantData::new(item_id, tid, Did::new("did:exo:owner").unwrap(), &payload)
    }

    /// A `TenantData` whose stored `byte_len` is exactly `len`, backed by a
    /// real payload of that length — no field is hand-set.
    fn td_sized(tid: Uuid, item_id: Uuid, len: usize) -> TenantData {
        TenantData::new(
            item_id,
            tid,
            Did::new("did:exo:owner").unwrap(),
            &vec![0u8; len],
        )
    }

    pub(crate) fn store_with_byte_lengths(tenant_id: Uuid, byte_lengths: [u64; 2]) -> TenantStore {
        let mut store = TenantStore::new();
        for (offset, byte_len) in byte_lengths.into_iter().enumerate() {
            let mut item = td_sized(tenant_id, uuid(100 + offset as u8), 1);
            item.byte_len = byte_len;
            store.put(tenant_id, item).expect("persist test item");
        }
        store
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
        // Deliberately corrupt the (in-module-accessible) hash to exercise the
        // store's defensive validation branch. External modules cannot do this
        // — `TenantData::new` always derives a non-zero digest — so this path
        // is only reachable in the store's own tests.
        item.content_hash = Hash256::ZERO;
        assert!(s.put(uuid(1), item).is_err());
    }

    #[test]
    fn byte_len_is_derived_from_payload_and_cannot_be_forged() {
        // `byte_len` is derived by `TenantData::new` from the real payload
        // length, and the field is private with no setter — there is no API
        // by which a caller could store a `byte_len` that disagrees with the
        // data it wrote. This is the invariant that makes `total_bytes`
        // reconciliation genuine rather than self-reported.
        let item = TenantData::new(
            uuid(10),
            uuid(1),
            Did::new("did:exo:owner").unwrap(),
            &vec![0u8; 4096],
        );
        assert_eq!(item.byte_len(), 4096);

        let empty = TenantData::new(uuid(11), uuid(1), Did::new("did:exo:owner").unwrap(), &[]);
        assert_eq!(empty.byte_len(), 0);
        assert_ne!(empty.content_hash(), Hash256::ZERO);
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

    #[test]
    fn total_bytes_sums_actual_recorded_lengths() {
        let mut s = TenantStore::new();
        let tid = uuid(1);
        let a = td_sized(tid, uuid(10), 128);
        let b = td_sized(tid, uuid(11), 256);
        s.put(tid, a).unwrap();
        s.put(tid, b).unwrap();
        assert_eq!(s.total_bytes(&tid), 128 + 256);
    }

    #[test]
    fn total_bytes_is_zero_for_unknown_tenant() {
        let s = TenantStore::new();
        assert_eq!(s.total_bytes(&Uuid::nil()), 0);
    }

    #[test]
    fn total_bytes_overflow_saturates_for_compatibility() {
        let tenant = uuid(1);
        let store = store_with_byte_lengths(tenant, [u64::MAX, 1]);

        assert_eq!(store.total_bytes(&tenant), u64::MAX);
    }

    #[test]
    fn try_total_bytes_overflow_returns_contextual_error() {
        let tenant = uuid(1);
        let store = store_with_byte_lengths(tenant, [u64::MAX, 1]);

        assert!(matches!(
            store.try_total_bytes(&tenant),
            Err(TenantError::UsageTotalOverflow {
                tenant_id,
                field: "store_total_bytes",
            }) if tenant_id == tenant
        ));
    }

    #[test]
    fn item_bytes_returns_recorded_length() {
        let mut s = TenantStore::new();
        let tid = uuid(1);
        let iid = uuid(10);
        let item = td_sized(tid, iid, 42);
        s.put(tid, item).unwrap();
        assert_eq!(s.item_bytes(&tid, &iid), Some(42));
    }

    #[test]
    fn item_bytes_none_for_missing_item() {
        let s = TenantStore::new();
        assert_eq!(s.item_bytes(&Uuid::nil(), &Uuid::nil()), None);
    }
}
