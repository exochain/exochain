//! Governance middleware chain — consent, governance, and audit middleware.
use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::{GatewayError, Result};

/// Verdict from governance adjudication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Deny { reason: String },
    Escalate { reason: String },
}

/// Audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub actor: Did,
    pub action: String,
    pub timestamp: Timestamp,
    pub outcome: String,
}

/// Audit log.
#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    pub entries: Vec<AuditEntry>,
}
impl AuditLog {
    /// Create a new empty audit log.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    /// Append an audit entry to the log.
    pub fn record(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
    }
    /// Return the number of entries in the log.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Return `true` if the log contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Consent check — default-deny. Returns Ok if consent is explicitly granted.
pub fn consent_middleware(_actor: &Did, _action: &str, consent_granted: bool) -> Result<()> {
    if consent_granted {
        Ok(())
    } else {
        Err(GatewayError::ConsentDenied {
            reason: "no active consent for actor".into(),
        })
    }
}

/// Governance check — every action must pass governance adjudication.
pub fn governance_middleware(_actor: &Did, _action: &str, verdict: &Verdict) -> Result<()> {
    match verdict {
        Verdict::Allow => Ok(()),
        Verdict::Deny { reason } => Err(GatewayError::GovernanceDenied {
            reason: reason.clone(),
        }),
        Verdict::Escalate { reason } => Err(GatewayError::GovernanceDenied {
            reason: format!("escalated: {reason}"),
        }),
    }
}

/// Record an audit entry for every request.
///
/// Requires a real HLC timestamp — `Timestamp::ZERO` is rejected as invalid.
///
/// # Errors
/// Returns `GatewayError::BadRequest` if `timestamp` is `Timestamp::ZERO`.
pub fn audit_middleware(
    actor: &Did,
    action: &str,
    outcome: &str,
    timestamp: &Timestamp,
    log: &mut AuditLog,
) -> Result<()> {
    if *timestamp == Timestamp::ZERO {
        return Err(GatewayError::BadRequest(
            "audit timestamp must not be Timestamp::ZERO; provide a real HLC timestamp".into(),
        ));
    }
    log.record(AuditEntry {
        actor: actor.clone(),
        action: action.into(),
        timestamp: *timestamp,
        outcome: outcome.into(),
    });
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }

    #[test]
    fn consent_granted() {
        assert!(consent_middleware(&did("a"), "read", true).is_ok());
    }
    #[test]
    fn consent_denied() {
        assert!(consent_middleware(&did("a"), "read", false).is_err());
    }

    #[test]
    fn consent_denial_does_not_display_raw_did() {
        let sensitive_did = did("privacy-sensitive-consent-subject");
        let error = consent_middleware(&sensitive_did, "read", false)
            .expect_err("missing consent must be rejected")
            .to_string();

        assert!(
            !error.contains(sensitive_did.as_str()),
            "consent denial display must not expose raw DID identifiers: {error}"
        );
    }

    #[test]
    fn governance_allow() {
        assert!(governance_middleware(&did("a"), "r", &Verdict::Allow).is_ok());
    }
    #[test]
    fn governance_deny() {
        assert!(
            governance_middleware(
                &did("a"),
                "r",
                &Verdict::Deny {
                    reason: "no".into()
                }
            )
            .is_err()
        );
    }
    #[test]
    fn governance_escalate() {
        assert!(
            governance_middleware(&did("a"), "r", &Verdict::Escalate { reason: "y".into() })
                .is_err()
        );
    }
    #[test]
    fn audit_records() {
        let mut log = AuditLog::new();
        let ts = Timestamp::new(1000, 0);
        audit_middleware(&did("a"), "read", "ok", &ts, &mut log).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log.entries[0].timestamp, ts);
    }
    #[test]
    fn audit_rejects_zero_timestamp() {
        let mut log = AuditLog::new();
        assert!(audit_middleware(&did("a"), "read", "ok", &Timestamp::ZERO, &mut log).is_err());
        assert!(log.is_empty());
    }
    #[test]
    fn audit_empty() {
        assert!(AuditLog::new().is_empty());
    }
    #[test]
    fn audit_default() {
        assert!(AuditLog::default().is_empty());
    }
    #[test]
    fn verdict_serde() {
        for v in [
            Verdict::Allow,
            Verdict::Deny { reason: "x".into() },
            Verdict::Escalate { reason: "y".into() },
        ] {
            let j = serde_json::to_string(&v).unwrap();
            let r: Verdict = serde_json::from_str(&j).unwrap();
            assert_eq!(r, v);
        }
    }
}
