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
    #[error("invalid state transition: {reason}")]
    InvalidStateTransition { reason: String },
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
            TenantError::InvalidStateTransition { reason: "x".into() },
            TenantError::ShardError { reason: "x".into() },
            TenantError::StorageError { reason: "x".into() },
            TenantError::MigrationError { reason: "x".into() },
        ];
        for e in &es {
            assert!(!e.to_string().is_empty());
        }
    }
}
