//! Tenant-specific errors.
use thiserror::Error;
use uuid::Uuid;

/// Errors returned by tenant management operations.
#[derive(Debug, Error)]
pub enum TenantError {
    #[error("tenant not found: {0}")]
    TenantNotFound(Uuid),
    #[error("tenant already exists: {0}")]
    TenantAlreadyExists(Uuid),
    #[error("invalid tenant: {reason}")]
    InvalidTenant { reason: String },
    #[error("invalid state transition: {reason}")]
    InvalidStateTransition { reason: String },
    #[error("storage record already exists for tenant {tenant_id}, item {item_id}")]
    StorageRecordAlreadyExists { tenant_id: Uuid, item_id: Uuid },
    #[error("storage record not found for tenant {tenant_id}, item {item_id}")]
    StorageRecordNotFound { tenant_id: Uuid, item_id: Uuid },
    #[error("cold storage reference already exists for tenant {tenant_id}, object {object_key}")]
    ColdStorageReferenceAlreadyExists { tenant_id: Uuid, object_key: String },
    #[error("shard error: {reason}")]
    ShardError { reason: String },
    #[error("storage error: {reason}")]
    StorageError { reason: String },
    #[error("migration error: {reason}")]
    MigrationError { reason: String },
}
/// Convenience alias for results with [`TenantError`].
pub type Result<T> = std::result::Result<T, TenantError>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_display() {
        let es: Vec<TenantError> = vec![
            TenantError::TenantNotFound(Uuid::nil()),
            TenantError::TenantAlreadyExists(Uuid::nil()),
            TenantError::InvalidTenant { reason: "x".into() },
            TenantError::InvalidStateTransition { reason: "x".into() },
            TenantError::StorageRecordAlreadyExists {
                tenant_id: Uuid::nil(),
                item_id: Uuid::nil(),
            },
            TenantError::StorageRecordNotFound {
                tenant_id: Uuid::nil(),
                item_id: Uuid::nil(),
            },
            TenantError::ColdStorageReferenceAlreadyExists {
                tenant_id: Uuid::nil(),
                object_key: "x".into(),
            },
            TenantError::ShardError { reason: "x".into() },
            TenantError::StorageError { reason: "x".into() },
            TenantError::MigrationError { reason: "x".into() },
        ];
        for e in &es {
            assert!(!e.to_string().is_empty());
        }
    }
}
