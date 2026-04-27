//! Conflict of interest disclosure requirements.

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::{LegalError, Result};

/// A conflict-of-interest disclosure filed by a declarant before a governed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disclosure {
    pub declarant: Did,
    pub nature: String,
    pub related_parties: Vec<Did>,
    pub timestamp: Timestamp,
    pub verified: bool,
}

const REQUIRED_ACTIONS: &[&str] = &[
    "vote",
    "approve",
    "fund",
    "transfer",
    "delegate",
    "adjudicate",
];

/// Returns `true` if the given action requires a conflict-of-interest disclosure before proceeding.
#[must_use]
pub fn require_disclosure(_actor: &Did, action: &str) -> bool {
    let lower = action.to_lowercase();
    REQUIRED_ACTIONS.iter().any(|k| lower.contains(k))
}

/// Files a new unverified disclosure describing the conflict and the related parties.
pub fn file_disclosure(
    actor: &Did,
    nature: &str,
    related: &[Did],
    timestamp: Timestamp,
) -> Result<Disclosure> {
    if nature.trim().is_empty() {
        return Err(LegalError::DisclosureRequired {
            action: "conflict disclosure requires a non-empty nature".into(),
        });
    }
    if timestamp == Timestamp::ZERO {
        return Err(LegalError::DisclosureRequired {
            action: "conflict disclosure timestamp must not be Timestamp::ZERO".into(),
        });
    }
    Ok(Disclosure {
        declarant: actor.clone(),
        nature: nature.into(),
        related_parties: related.to_vec(),
        timestamp,
        verified: false,
    })
}

/// Marks a previously filed disclosure as verified.
pub fn verify_disclosure(d: &mut Disclosure) {
    d.verified = true;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn did(n: &str) -> Did {
        Did::new(&format!("did:exo:{n}")).unwrap()
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    #[test]
    fn file_disclosure_uses_caller_supplied_timestamp() {
        let disclosure =
            file_disclosure(&did("a"), "board conflict", &[did("b")], ts(1000)).unwrap();
        assert_eq!(disclosure.timestamp, ts(1000));
    }

    #[test]
    fn file_disclosure_rejects_placeholder_metadata() {
        assert!(file_disclosure(&did("a"), "board conflict", &[], Timestamp::ZERO).is_err());
        assert!(file_disclosure(&did("a"), " ", &[], ts(1000)).is_err());
    }

    #[test]
    fn require_vote() {
        assert!(require_disclosure(&did("a"), "vote on proposal"));
    }
    #[test]
    fn require_approve() {
        assert!(require_disclosure(&did("a"), "approve budget"));
    }
    #[test]
    fn require_fund() {
        assert!(require_disclosure(&did("a"), "fund project"));
    }
    #[test]
    fn require_transfer() {
        assert!(require_disclosure(&did("a"), "transfer assets"));
    }
    #[test]
    fn require_delegate() {
        assert!(require_disclosure(&did("a"), "delegate authority"));
    }
    #[test]
    fn require_adjudicate() {
        assert!(require_disclosure(&did("a"), "adjudicate dispute"));
    }
    #[test]
    fn no_require_read() {
        assert!(!require_disclosure(&did("a"), "read document"));
    }
    #[test]
    fn case_insensitive() {
        assert!(require_disclosure(&did("a"), "VOTE"));
    }
    #[test]
    fn file_basic() {
        let d = file_disclosure(&did("a"), "financial", &[did("b")], ts(1000)).unwrap();
        assert_eq!(d.related_parties.len(), 1);
        assert!(!d.verified);
    }
    #[test]
    fn file_empty() {
        let d = file_disclosure(&did("a"), "x", &[], ts(1000)).unwrap();
        assert!(d.related_parties.is_empty());
    }
    #[test]
    fn verify_sets_flag() {
        let mut d = file_disclosure(&did("a"), "x", &[], ts(1000)).unwrap();
        verify_disclosure(&mut d);
        assert!(d.verified);
    }
    #[test]
    fn serde() {
        let d = file_disclosure(&did("a"), "x", &[did("b")], ts(1000)).unwrap();
        let j = serde_json::to_string(&d).unwrap();
        let r: Disclosure = serde_json::from_str(&j).unwrap();
        assert_eq!(r.declarant, did("a"));
    }
    #[test]
    fn required_count() {
        assert_eq!(REQUIRED_ACTIONS.len(), 6);
    }
}
