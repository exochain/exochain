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

/// Caller-supplied tenant creation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRegistration {
    pub id: Uuid,
    pub name: String,
    pub config: TenantConfig,
    pub created: Timestamp,
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

    /// Create a new tenant from caller-supplied identity and HLC metadata.
    pub fn create(&mut self, registration: TenantRegistration) -> Result<Uuid> {
        Self::validate_registration(&registration)?;
        if self.tenants.contains_key(&registration.id) {
            return Err(TenantError::TenantAlreadyExists(registration.id));
        }
        let id = registration.id;
        let t = Tenant {
            id,
            name: registration.name,
            config: registration.config,
            created: registration.created,
            status: TenantStatus::Active,
        };
        self.tenants.insert(id, t);
        Ok(id)
    }

    fn validate_registration(registration: &TenantRegistration) -> Result<()> {
        if registration.id == Uuid::nil() {
            return Err(TenantError::InvalidTenant {
                reason: "tenant id must not be nil".into(),
            });
        }
        if registration.name.trim().is_empty() {
            return Err(TenantError::InvalidTenant {
                reason: "tenant name must not be empty".into(),
            });
        }
        if registration.created == Timestamp::ZERO {
            return Err(TenantError::InvalidTenant {
                reason: "created timestamp must be caller-supplied HLC".into(),
            });
        }
        if registration.config.max_storage_bytes == 0 {
            return Err(TenantError::InvalidTenant {
                reason: "max storage bytes must be greater than zero".into(),
            });
        }
        if registration.config.max_users == 0 {
            return Err(TenantError::InvalidTenant {
                reason: "max users must be greater than zero".into(),
            });
        }
        Ok(())
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

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn registration(id: Uuid, name: &str, created: Timestamp) -> TenantRegistration {
        TenantRegistration {
            id,
            name: name.into(),
            config: TenantConfig::default(),
            created,
        }
    }

    #[test]
    fn create_and_get() {
        let mut r = TenantRegistry::new();
        let id = uuid(1);
        let created = ts(1_700_000_000_000);
        let returned = r.create(registration(id, "t", created)).unwrap();
        assert_eq!(returned, id);
        assert!(r.get(&id).is_some());
        assert_eq!(r.get(&id).unwrap().created, created);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn create_rejects_nil_tenant_id() {
        let mut r = TenantRegistry::new();
        assert!(
            r.create(registration(Uuid::nil(), "tenant", ts(1_700_000_000_000)))
                .is_err()
        );
    }

    #[test]
    fn create_rejects_zero_created_timestamp() {
        let mut r = TenantRegistry::new();
        assert!(
            r.create(registration(uuid(1), "tenant", Timestamp::ZERO))
                .is_err()
        );
    }

    #[test]
    fn create_rejects_empty_name() {
        let mut r = TenantRegistry::new();
        assert!(
            r.create(registration(uuid(1), "   ", ts(1_700_000_000_000)))
                .is_err()
        );
    }

    #[test]
    fn create_rejects_duplicate_tenant_id() {
        let mut r = TenantRegistry::new();
        let id = uuid(1);
        r.create(registration(id, "tenant-a", ts(1_700_000_000_000)))
            .unwrap();
        assert!(
            r.create(registration(id, "tenant-b", ts(1_700_000_000_001)))
                .is_err()
        );
    }

    #[test]
    fn delete() {
        let mut r = TenantRegistry::new();
        let id = r
            .create(registration(uuid(1), "t", ts(1_700_000_000_000)))
            .unwrap();
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
        let id = r
            .create(registration(uuid(1), "t", ts(1_700_000_000_000)))
            .unwrap();
        r.update_status(&id, TenantStatus::Suspended).unwrap();
        assert_eq!(r.get(&id).unwrap().status, TenantStatus::Suspended);
    }
    #[test]
    fn reactivate() {
        let mut r = TenantRegistry::new();
        let id = r
            .create(registration(uuid(1), "t", ts(1_700_000_000_000)))
            .unwrap();
        r.update_status(&id, TenantStatus::Suspended).unwrap();
        r.update_status(&id, TenantStatus::Active).unwrap();
        assert_eq!(r.get(&id).unwrap().status, TenantStatus::Active);
    }
    #[test]
    fn archive_from_active() {
        let mut r = TenantRegistry::new();
        let id = r
            .create(registration(uuid(1), "t", ts(1_700_000_000_000)))
            .unwrap();
        r.update_status(&id, TenantStatus::Archived).unwrap();
    }
    #[test]
    fn invalid_transition() {
        let mut r = TenantRegistry::new();
        let id = r
            .create(registration(uuid(1), "t", ts(1_700_000_000_000)))
            .unwrap();
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
        r.create(registration(uuid(1), "a", ts(1_700_000_000_000)))
            .unwrap();
        r.create(registration(uuid(2), "b", ts(1_700_000_000_001)))
            .unwrap();
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
        let id = r
            .create(registration(uuid(1), "t", ts(1_700_000_000_000)))
            .unwrap();
        let t = r.get(&id).unwrap();
        let j = serde_json::to_string(t).unwrap();
        let rt: Tenant = serde_json::from_str(&j).unwrap();
        assert_eq!(rt.name, "t");
    }
    #[test]
    fn get_mut() {
        let mut r = TenantRegistry::new();
        let id = r
            .create(registration(uuid(1), "t", ts(1_700_000_000_000)))
            .unwrap();
        r.get_mut(&id).unwrap().name = "updated".into();
        assert_eq!(r.get(&id).unwrap().name, "updated");
    }
}
