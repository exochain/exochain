//! Key custody for exoguard's own secrets (OpenRouter API key, DAG payload
//! encryption key, tenant webhook secrets).
//!
//! MVP ships `SingleKeyCustodian`; the 3-of-4 multisig is stubbed behind
//! `MultisigCustodianStub` so storage formats stay stable across the
//! eventual upgrade (no data migration needed later).

use async_trait::async_trait;

use crate::error::DlpError;

/// A handle to a secret; opaque to callers.
#[derive(Debug, Clone)]
pub struct SecretHandle(pub String);

#[async_trait]
pub trait KeyCustodian: Send + Sync {
    /// Resolve a `SecretHandle` to its plaintext bytes. Implementations
    /// must zeroize returned buffers when dropped.
    async fn fetch(&self, handle: &SecretHandle) -> Result<Vec<u8>, DlpError>;
}

/// MVP custodian: single local key, no quorum. Fine for first pilot tenant.
pub struct SingleKeyCustodian {
    pub handle_prefix: String,
}

impl SingleKeyCustodian {
    #[must_use]
    pub fn new(handle_prefix: impl Into<String>) -> Self {
        Self {
            handle_prefix: handle_prefix.into(),
        }
    }
}

#[async_trait]
impl KeyCustodian for SingleKeyCustodian {
    async fn fetch(&self, _handle: &SecretHandle) -> Result<Vec<u8>, DlpError> {
        Err(DlpError::Unimplemented("SingleKeyCustodian::fetch"))
    }
}

/// Frozen interface for 3-of-4 multisig. Not wired in MVP, but defined now
/// so storage formats don't need to change when multisig lands.
pub struct MultisigCustodianStub {
    pub members: Vec<String>,
    pub threshold: u32,
}
