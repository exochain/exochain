//! Tenant management — CRUD operations with lifecycle.
use std::collections::BTreeMap;

use exo_core::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Result, TenantError};

/// Lifecycle status of a tenant (active, suspended, or archived).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TenantStatus {
    Active,
    Suspended,
    Archived,
}

/// Resource limits and quota configuration for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantConfig {
    pub max_storage_bytes: u64,
    pub max_users: u32,
}
impl Default for TenantConfig {
    fn default() -> Self {
        Self {
            max_storage_bytes: 1_073_741_824,
            max_users: 100,
        }
    }
}

/// A tenant entity with identity, configuration, and lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub config: TenantConfig,
    pub created: Timestamp,
    pub status: TenantStatus,
}

/// In-memory registry of tenants with CRUD and lifecycle operations.
#[derive(Debug, Clone, Default)]
pub struct TenantRegistry {
    pub tenants: BTreeMap<Uuid, Tenant>,
}

impl TenantRegistry {
    /// Create an empty tenant registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tenants: BTreeMap::new(),
        }
    }

    /// Create a new tenant with the given name and config, returning its UUID.
    pub fn create(&mut self, name: &str, config: TenantConfig) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let t = Tenant {
            id,
            name: name.into(),
            config,
            created: Timestamp::ZERO,
            status: TenantStatus::Active,
        };
        self.tenants.insert(id, t);
        Ok(id)
    }

    /// Look up a tenant by ID.
    #[must_use]
    pub fn get(&self, id: &Uuid) -> Option<&Tenant> {
        self.tenants.get(id)
    }
    /// Look up a tenant by ID, returning a mutable reference.
    #[must_use]
    pub fn get_mut(&mut self, id: &Uuid) -> Option<&mut Tenant> {
        self.tenants.get_mut(id)
    }

    /// Transition a tenant to a new status, validating the state machine rules.
    pub fn update_status(&mut self, id: &Uuid, status: TenantStatus) -> Result<()> {
        let t = self
            .tenants
            .get_mut(id)
            .ok_or(TenantError::TenantNotFound(*id))?;
        // Validate transitions
        match (&t.status, &status) {
            (TenantStatus::Active, TenantStatus::Suspended)
            | (TenantStatus::Active, TenantStatus::Archived)
            | (TenantStatus::Suspended, TenantStatus::Active)
            | (TenantStatus::Suspended, TenantStatus::Archived) => {}
            _ => {
                return Err(TenantError::InvalidStateTransition {
                    reason: format!("{:?} -> {status:?}", t.status),
                });
            }
        }
        t.status = status;
        Ok(())
    }

    /// Remove a tenant from the registry, returning the removed tenant.
    pub fn delete(&mut self, id: &Uuid) -> Result<Tenant> {
        self.tenants
            .remove(id)
            .ok_or(TenantError::TenantNotFound(*id))
    }

    /// Return the number of registered tenants.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tenants.len()
    }
    /// Return `true` if no tenants are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tenants.is_empty()
    }
    /// List all tenants in the registry.
    #[must_use]
    pub fn list(&self) -> Vec<&Tenant> {
        self.tenants.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn create_and_get() {
        let mut r = TenantRegistry::new();
        let id = r.create("t", TenantConfig::default()).unwrap();
        assert!(r.get(&id).is_some());
        assert_eq!(r.len(), 1);
    }
    #[test]
    fn delete() {
        let mut r = TenantRegistry::new();
        let id = r.create("t", TenantConfig::default()).unwrap();
        r.delete(&id).unwrap();
        assert!(r.is_empty());
    }
    #[test]
    fn delete_not_found() {
        let mut r = TenantRegistry::new();
        assert!(r.delete(&Uuid::nil()).is_err());
    }
    #[test]
    fn suspend() {
        let mut r = TenantRegistry::new();
        let id = r.create("t", TenantConfig::default()).unwrap();
        r.update_status(&id, TenantStatus::Suspended).unwrap();
        assert_eq!(r.get(&id).unwrap().status, TenantStatus::Suspended);
    }
    #[test]
    fn reactivate() {
        let mut r = TenantRegistry::new();
        let id = r.create("t", TenantConfig::default()).unwrap();
        r.update_status(&id, TenantStatus::Suspended).unwrap();
        r.update_status(&id, TenantStatus::Active).unwrap();
        assert_eq!(r.get(&id).unwrap().status, TenantStatus::Active);
    }
    #[test]
    fn archive_from_active() {
        let mut r = TenantRegistry::new();
        let id = r.create("t", TenantConfig::default()).unwrap();
        r.update_status(&id, TenantStatus::Archived).unwrap();
    }
    #[test]
    fn invalid_transition() {
        let mut r = TenantRegistry::new();
        let id = r.create("t", TenantConfig::default()).unwrap();
        r.update_status(&id, TenantStatus::Archived).unwrap();
        assert!(r.update_status(&id, TenantStatus::Active).is_err());
    }
    #[test]
    fn update_not_found() {
        let mut r = TenantRegistry::new();
        assert!(r.update_status(&Uuid::nil(), TenantStatus::Active).is_err());
    }
    #[test]
    fn list() {
        let mut r = TenantRegistry::new();
        r.create("a", TenantConfig::default()).unwrap();
        r.create("b", TenantConfig::default()).unwrap();
        assert_eq!(r.list().len(), 2);
    }
    #[test]
    fn default() {
        assert!(TenantRegistry::default().is_empty());
    }
    #[test]
    fn status_serde() {
        for s in [
            TenantStatus::Active,
            TenantStatus::Suspended,
            TenantStatus::Archived,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let r: TenantStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(r, s);
        }
    }
    #[test]
    fn tenant_serde() {
        let mut r = TenantRegistry::new();
        let id = r.create("t", TenantConfig::default()).unwrap();
        let t = r.get(&id).unwrap();
        let j = serde_json::to_string(t).unwrap();
        let rt: Tenant = serde_json::from_str(&j).unwrap();
        assert_eq!(rt.name, "t");
    }
    #[test]
    fn get_mut() {
        let mut r = TenantRegistry::new();
        let id = r.create("t", TenantConfig::default()).unwrap();
        r.get_mut(&id).unwrap().name = "updated".into();
        assert_eq!(r.get(&id).unwrap().name, "updated");
    }
}
