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

//! Consent gate — the default-deny enforcement point.
//!
//! All actions must pass through the consent gate. The gate holds the
//! policy engine and active bailments, and returns a deterministic
//! consent decision for every action request.

use std::collections::{BTreeMap, BTreeSet};

use exo_core::{Did, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{
    bailment::{self, Bailment},
    error::ConsentError,
    policy::{ActionRequest, ActiveConsent, ConsentDecision, ConsentPolicy, PolicyEngine},
};

/// Maximum retained consent access log entries in memory and snapshots.
pub const MAX_ACCESS_LOG_ENTRIES: usize = 4_096;
/// Maximum action type size accepted by the consent access log boundary.
pub const MAX_ACCESS_LOG_ACTION_BYTES: usize = 256;

/// Internal consent registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsentReg {
    action_type: String,
    role: String,
    clearance_level: u32,
    bailment: Bailment,
}

/// Durable record of a consent check before a caller may release protected data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentAccessLogEntry {
    pub sequence: u64,
    pub actor: Did,
    pub action_type: String,
    pub checked_at: Timestamp,
    pub decision: ConsentDecision,
}

/// Durable revocation record used to prevent stale consent replay after restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRevocationLogEntry {
    pub sequence: u64,
    pub bailment_id: String,
    pub revoked_at: Timestamp,
}

/// Serializable consent gate state. Persist this snapshot atomically with the
/// hosting runtime's durable state so revocations survive process restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentGateSnapshot {
    pub policy: ConsentPolicy,
    bailments: BTreeMap<String, Vec<Bailment>>,
    consents: BTreeMap<String, Vec<ConsentReg>>,
    pub revoked_bailment_ids: BTreeSet<String>,
    pub revocation_log: Vec<ConsentRevocationLogEntry>,
    pub access_log: Vec<ConsentAccessLogEntry>,
    next_revocation_sequence: u64,
    next_access_sequence: u64,
}

/// The consent gate — default-deny enforcement point.
#[derive(Debug)]
pub struct ConsentGate {
    engine: PolicyEngine,
    policy: ConsentPolicy,
    bailments: BTreeMap<String, Vec<Bailment>>,
    consents: BTreeMap<String, Vec<ConsentReg>>,
    revoked_bailment_ids: BTreeSet<String>,
    revocation_log: Vec<ConsentRevocationLogEntry>,
    access_log: Vec<ConsentAccessLogEntry>,
    next_revocation_sequence: u64,
    next_access_sequence: u64,
}

impl ConsentGate {
    #[must_use]
    pub fn new(policy: ConsentPolicy) -> Self {
        Self {
            engine: PolicyEngine::new(),
            policy,
            bailments: BTreeMap::new(),
            consents: BTreeMap::new(),
            revoked_bailment_ids: BTreeSet::new(),
            revocation_log: Vec::new(),
            access_log: Vec::new(),
            next_revocation_sequence: 0,
            next_access_sequence: 0,
        }
    }

    #[must_use]
    pub fn from_snapshot(snapshot: ConsentGateSnapshot) -> Self {
        let ConsentGateSnapshot {
            policy,
            mut bailments,
            mut consents,
            revoked_bailment_ids,
            revocation_log,
            mut access_log,
            next_revocation_sequence,
            next_access_sequence,
        } = snapshot;

        for registered_bailments in bailments.values_mut() {
            registered_bailments.retain(|bailment| !revoked_bailment_ids.contains(&bailment.id));
        }
        for registered_consents in consents.values_mut() {
            registered_consents.retain(|reg| !revoked_bailment_ids.contains(&reg.bailment.id));
        }
        let next_revocation_sequence =
            revocation_log_next_sequence(next_revocation_sequence, &revocation_log);
        let next_access_sequence = access_log_next_sequence(next_access_sequence, &access_log);
        prune_access_log(&mut access_log);

        Self {
            engine: PolicyEngine::new(),
            policy,
            bailments,
            consents,
            revoked_bailment_ids,
            revocation_log,
            access_log,
            next_revocation_sequence,
            next_access_sequence,
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> ConsentGateSnapshot {
        ConsentGateSnapshot {
            policy: self.policy.clone(),
            bailments: self.bailments.clone(),
            consents: self.consents.clone(),
            revoked_bailment_ids: self.revoked_bailment_ids.clone(),
            revocation_log: self.revocation_log.clone(),
            access_log: self.access_log.clone(),
            next_revocation_sequence: self.next_revocation_sequence,
            next_access_sequence: self.next_access_sequence,
        }
    }

    pub fn register_bailment(&mut self, bailment: Bailment) -> Result<(), ConsentError> {
        self.ensure_not_revoked(&bailment.id)?;
        self.bailments
            .entry(bailment.bailee_did.as_str().to_owned())
            .or_default()
            .push(bailment);
        Ok(())
    }

    pub fn register_consent(
        &mut self,
        actor: &Did,
        action_type: &str,
        role: &str,
        clearance_level: u32,
        bailment: Bailment,
    ) -> Result<(), ConsentError> {
        self.ensure_not_revoked(&bailment.id)?;
        self.consents
            .entry(actor.as_str().to_owned())
            .or_default()
            .push(ConsentReg {
                action_type: action_type.into(),
                role: role.into(),
                clearance_level,
                bailment,
            });
        Ok(())
    }

    pub fn revoke_by_bailment_id(
        &mut self,
        bailment_id: &str,
        revoked_at: Timestamp,
    ) -> Result<(), ConsentError> {
        if bailment_id.is_empty() {
            return Err(ConsentError::Denied(
                "bailment_id must not be empty for revocation".into(),
            ));
        }
        for regs in self.consents.values_mut() {
            regs.retain(|r| r.bailment.id != bailment_id);
        }
        for bs in self.bailments.values_mut() {
            bs.retain(|b| b.id != bailment_id);
        }
        if self.revoked_bailment_ids.insert(bailment_id.to_owned()) {
            let sequence = next_sequence(&mut self.next_revocation_sequence, "revocation_log")?;
            self.revocation_log.push(ConsentRevocationLogEntry {
                sequence,
                bailment_id: bailment_id.to_owned(),
                revoked_at,
            });
        }
        Ok(())
    }

    /// Check consent. Default: DENY.
    pub fn check(
        &mut self,
        actor: &Did,
        action: &str,
        now: &Timestamp,
    ) -> Result<ConsentDecision, ConsentError> {
        validate_access_log_action(action)?;
        let req = ActionRequest {
            actor: actor.clone(),
            action_type: action.into(),
        };
        let active: Vec<ActiveConsent> = match self.consents.get(actor.as_str()) {
            Some(regs) => regs
                .iter()
                .filter(|r| self.is_registered_consent_active(r, now))
                .map(|r| ActiveConsent {
                    grantor: r.bailment.bailor_did.clone(),
                    action_type: r.action_type.clone(),
                    role: r.role.clone(),
                    clearance_level: r.clearance_level,
                    bailment: r.bailment.clone(),
                })
                .collect(),
            None => Vec::new(),
        };

        let decision = self.engine.evaluate(&self.policy, &active, &req, now);
        self.append_access_log(actor, action, now, &decision)?;
        Ok(decision)
    }

    #[must_use]
    pub fn policy(&self) -> &ConsentPolicy {
        &self.policy
    }

    pub fn set_policy(&mut self, policy: ConsentPolicy) {
        self.policy = policy;
    }

    #[must_use]
    pub fn access_log(&self) -> &[ConsentAccessLogEntry] {
        &self.access_log
    }

    #[must_use]
    pub fn revocation_log(&self) -> &[ConsentRevocationLogEntry] {
        &self.revocation_log
    }

    fn ensure_not_revoked(&self, bailment_id: &str) -> Result<(), ConsentError> {
        if self.revoked_bailment_ids.contains(bailment_id) {
            return Err(ConsentError::Revoked {
                bailment_id: bailment_id.to_owned(),
            });
        }
        Ok(())
    }

    fn is_registered_consent_active(&self, reg: &ConsentReg, now: &Timestamp) -> bool {
        !self.revoked_bailment_ids.contains(&reg.bailment.id)
            && bailment::is_active(&reg.bailment, now)
    }

    fn append_access_log(
        &mut self,
        actor: &Did,
        action: &str,
        now: &Timestamp,
        decision: &ConsentDecision,
    ) -> Result<(), ConsentError> {
        let sequence = next_sequence(&mut self.next_access_sequence, "access_log")?;
        self.access_log.push(ConsentAccessLogEntry {
            sequence,
            actor: actor.clone(),
            action_type: action.to_owned(),
            checked_at: *now,
            decision: decision.clone(),
        });
        prune_access_log(&mut self.access_log);
        Ok(())
    }
}

fn validate_access_log_action(action: &str) -> Result<(), ConsentError> {
    if action.len() > MAX_ACCESS_LOG_ACTION_BYTES {
        return Err(ConsentError::Denied(format!(
            "action_type exceeds maximum consent access log length of {MAX_ACCESS_LOG_ACTION_BYTES} bytes"
        )));
    }
    Ok(())
}

fn prune_access_log(access_log: &mut Vec<ConsentAccessLogEntry>) {
    let overflow = access_log.len().saturating_sub(MAX_ACCESS_LOG_ENTRIES);
    if overflow > 0 {
        access_log.drain(0..overflow);
    }
}

fn next_sequence(counter: &mut u64, counter_name: &str) -> Result<u64, ConsentError> {
    let sequence = *counter;
    *counter = counter
        .checked_add(1)
        .ok_or_else(|| ConsentError::SequenceOverflow {
            counter: counter_name.to_owned(),
        })?;
    Ok(sequence)
}

fn revocation_log_next_sequence(current: u64, log: &[ConsentRevocationLogEntry]) -> u64 {
    log.iter().fold(current, |next, entry| {
        next_after_seen_sequence(next, entry.sequence)
    })
}

fn access_log_next_sequence(current: u64, log: &[ConsentAccessLogEntry]) -> u64 {
    log.iter().fold(current, |next, entry| {
        next_after_seen_sequence(next, entry.sequence)
    })
}

fn next_after_seen_sequence(current: u64, seen: u64) -> u64 {
    if seen < current {
        return current;
    }
    seen.saturating_add(1)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        bailment::{self, BailmentType},
        policy::ConsentRequirement,
    };

    fn alice() -> Did {
        Did::new("did:exo:alice").unwrap()
    }
    fn bob() -> Did {
        Did::new("did:exo:bob").unwrap()
    }
    fn charlie() -> Did {
        Did::new("did:exo:charlie").unwrap()
    }
    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }
    fn now() -> Timestamp {
        ts(5000)
    }

    fn strict_policy() -> ConsentPolicy {
        ConsentPolicy {
            id: "strict".into(),
            name: "strict".into(),
            deny_by_default: true,
            required_consents: vec![ConsentRequirement {
                action_type: "read".into(),
                required_role: "data-owner".into(),
                min_clearance_level: 1,
            }],
        }
    }

    fn make_bailment(
        bailor: &Did,
        bailee: &Did,
        bt: BailmentType,
        exp: Option<Timestamp>,
    ) -> Bailment {
        let mut b = bailment::propose(bailor, bailee, b"gt", bt, "gatekeeper-test", ts(1000))
            .expect("test bailment proposal");
        // Produce a valid bailee signature for the GAP-012-verified accept().
        let (pk, sk) = exo_core::crypto::generate_keypair();
        let payload = bailment::signing_payload(&b).expect("canonical payload");
        let sig = exo_core::crypto::sign(&payload, &sk);
        let bailee_did = b.bailee_did.clone();
        bailment::accept(&mut b, |did| (did == &bailee_did).then_some(pk), &sig)
            .expect("test bailment accepts");
        b.expires = exp;
        b
    }

    #[test]
    fn default_deny() {
        let mut g = ConsentGate::new(strict_policy());
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            Ok(ConsentDecision::Denied { .. })
        ));
    }

    #[test]
    fn check_uses_explicit_default_deny_for_missing_actor_consent() {
        let source = include_str!("gatekeeper.rs");
        let check_source = source
            .split("pub fn check(")
            .nth(1)
            .and_then(|section| section.split("    #[must_use]").next())
            .expect("check function source must be present");

        assert!(
            !check_source.contains("unwrap_or_default"),
            "missing consent registrations must flow through an explicit default-deny branch"
        );
        assert!(
            matches!(
                ConsentGate::new(strict_policy()).check(&charlie(), "read", &now()),
                Ok(ConsentDecision::Denied { .. })
            ),
            "unregistered actors must remain denied"
        );
    }

    #[test]
    fn grant_with_valid_consent() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        g.register_bailment(b.clone()).expect("register bailment");
        g.register_consent(&bob(), "read", "data-owner", 1, b)
            .expect("register consent");
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            Ok(ConsentDecision::Granted { .. })
        ));
    }

    #[test]
    fn granted_check_appends_access_log_before_returning() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        g.register_bailment(b.clone()).expect("register bailment");
        g.register_consent(&bob(), "read", "data-owner", 1, b)
            .expect("register consent");

        assert!(g.access_log().is_empty());
        let decision = g.check(&bob(), "read", &now()).expect("logged check");

        assert!(matches!(decision, ConsentDecision::Granted { .. }));
        let access_log = g.access_log();
        assert_eq!(access_log.len(), 1);
        assert_eq!(access_log[0].sequence, 0);
        assert_eq!(access_log[0].actor, bob());
        assert_eq!(access_log[0].action_type, "read");
        assert_eq!(access_log[0].checked_at, now());
        assert_eq!(access_log[0].decision, decision);
    }

    #[test]
    fn access_log_keeps_latest_bounded_entries() {
        let mut g = ConsentGate::new(strict_policy());
        for offset in 0..(MAX_ACCESS_LOG_ENTRIES + 2) {
            let timestamp = ts(u64::try_from(offset + 1).expect("test offset fits u64"));
            g.check(&charlie(), "read", &timestamp)
                .expect("denied checks are logged within cap");
        }

        assert_eq!(g.access_log().len(), MAX_ACCESS_LOG_ENTRIES);
        assert_eq!(g.access_log()[0].sequence, 2);
        assert_eq!(
            g.access_log()
                .last()
                .expect("bounded log has latest entry")
                .sequence,
            u64::try_from(MAX_ACCESS_LOG_ENTRIES + 1).expect("cap fits u64")
        );
        assert_eq!(g.snapshot().access_log.len(), MAX_ACCESS_LOG_ENTRIES);
    }

    #[test]
    fn restored_snapshot_prunes_oversized_access_log_without_reusing_sequence() {
        let mut snapshot = ConsentGate::new(strict_policy()).snapshot();
        snapshot.access_log = (0..(MAX_ACCESS_LOG_ENTRIES + 2))
            .map(|offset| ConsentAccessLogEntry {
                sequence: u64::try_from(offset).expect("test offset fits u64"),
                actor: charlie(),
                action_type: "read".into(),
                checked_at: ts(u64::try_from(offset + 1).expect("test offset fits u64")),
                decision: ConsentDecision::Denied {
                    reason: "test".into(),
                },
            })
            .collect();
        snapshot.next_access_sequence = 0;

        let mut restored = ConsentGate::from_snapshot(snapshot);
        assert_eq!(restored.access_log().len(), MAX_ACCESS_LOG_ENTRIES);
        assert_eq!(restored.access_log()[0].sequence, 2);

        restored
            .check(&charlie(), "read", &ts(9_000))
            .expect("post-restore check");
        assert_eq!(restored.access_log().len(), MAX_ACCESS_LOG_ENTRIES);
        assert_eq!(
            restored
                .access_log()
                .last()
                .expect("bounded log has latest entry")
                .sequence,
            u64::try_from(MAX_ACCESS_LOG_ENTRIES + 2).expect("cap fits u64")
        );
    }

    #[test]
    fn oversized_action_type_is_rejected_before_access_log_append() {
        let mut g = ConsentGate::new(strict_policy());
        let action = "x".repeat(MAX_ACCESS_LOG_ACTION_BYTES + 1);

        let err = g
            .check(&charlie(), &action, &now())
            .expect_err("oversized action labels must be rejected");

        assert!(matches!(err, ConsentError::Denied(_)));
        assert!(g.access_log().is_empty());
    }

    #[test]
    fn access_log_source_keeps_memory_and_snapshot_bounds() {
        let source = include_str!("gatekeeper.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        let check_source = production
            .split("pub fn check(")
            .nth(1)
            .and_then(|section| section.split("    #[must_use]").next())
            .expect("check source exists");
        let append_source = production
            .split("fn append_access_log(")
            .nth(1)
            .and_then(|section| section.split("fn validate_access_log_action").next())
            .expect("append source exists");
        let from_snapshot_source = production
            .split("pub fn from_snapshot(")
            .nth(1)
            .and_then(|section| section.split("    #[must_use]").next())
            .expect("from_snapshot source exists");

        assert!(production.contains("pub const MAX_ACCESS_LOG_ENTRIES"));
        assert!(production.contains("pub const MAX_ACCESS_LOG_ACTION_BYTES"));
        assert!(check_source.contains("validate_access_log_action(action)?"));
        assert!(append_source.contains("prune_access_log(&mut self.access_log)"));
        assert!(from_snapshot_source.contains("prune_access_log(&mut access_log)"));
    }

    #[test]
    fn deny_after_revocation() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        let bid = b.id.clone();
        g.register_bailment(b.clone()).expect("register bailment");
        g.register_consent(&bob(), "read", "data-owner", 1, b)
            .expect("register consent");
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            Ok(ConsentDecision::Granted { .. })
        ));
        g.revoke_by_bailment_id(&bid, ts(6000))
            .expect("revoke bailment");
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            Ok(ConsentDecision::Denied { .. })
        ));
    }

    #[test]
    fn revoked_bailment_snapshot_blocks_restart_replay() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        let bid = b.id.clone();
        g.register_bailment(b.clone()).expect("register bailment");
        g.register_consent(&bob(), "read", "data-owner", 1, b.clone())
            .expect("register consent");

        assert!(matches!(
            g.check(&bob(), "read", &now())
                .expect("pre-revocation check"),
            ConsentDecision::Granted { .. }
        ));

        g.revoke_by_bailment_id(&bid, ts(6000))
            .expect("revocation persists");
        let snapshot = g.snapshot();
        assert!(snapshot.revoked_bailment_ids.contains(&bid));
        assert_eq!(snapshot.revocation_log.len(), 1);

        let mut restored = ConsentGate::from_snapshot(snapshot);
        assert!(matches!(
            restored
                .check(&bob(), "read", &ts(7000))
                .expect("post-restore check"),
            ConsentDecision::Denied { .. }
        ));
        assert!(
            restored.register_bailment(b.clone()).is_err(),
            "a revoked bailment id must not be replayable after restore"
        );
        assert!(
            restored
                .register_consent(&bob(), "read", "data-owner", 1, b)
                .is_err(),
            "a revoked consent id must not be replayable after restore"
        );
    }

    #[test]
    fn restored_snapshot_filters_revoked_stale_registrations() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        let bid = b.id.clone();
        g.register_bailment(b.clone()).expect("register bailment");
        g.register_consent(&bob(), "read", "data-owner", 1, b)
            .expect("register consent");

        let mut snapshot = g.snapshot();
        snapshot.revoked_bailment_ids.insert(bid.clone());
        snapshot.revocation_log.push(ConsentRevocationLogEntry {
            sequence: 0,
            bailment_id: bid,
            revoked_at: ts(6000),
        });
        snapshot.next_revocation_sequence = 1;

        let restored = ConsentGate::from_snapshot(snapshot);
        let restored_snapshot = restored.snapshot();

        assert!(
            restored_snapshot.bailments.values().all(Vec::is_empty),
            "restored state must not retain stale bailment registrations for revoked ids"
        );
        assert!(
            restored_snapshot.consents.values().all(Vec::is_empty),
            "restored state must not retain stale consent registrations for revoked ids"
        );
    }

    #[test]
    fn snapshot_restore_advances_sequence_counters_past_persisted_logs() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        let bid = b.id.clone();
        g.register_bailment(b.clone()).expect("register bailment");
        g.register_consent(&bob(), "read", "data-owner", 1, b)
            .expect("register consent");
        g.check(&bob(), "read", &now())
            .expect("pre-revocation check");
        g.revoke_by_bailment_id(&bid, ts(6000))
            .expect("revoke bailment");

        let mut snapshot = g.snapshot();
        snapshot.next_access_sequence = 0;
        snapshot.next_revocation_sequence = 0;

        let mut restored = ConsentGate::from_snapshot(snapshot);
        restored
            .check(&bob(), "read", &ts(7000))
            .expect("post-restore check");
        restored
            .revoke_by_bailment_id("another-bailment", ts(8000))
            .expect("second revocation");

        assert_eq!(restored.access_log()[1].sequence, 1);
        assert_eq!(restored.revocation_log()[1].sequence, 1);
    }

    #[test]
    fn deny_after_expiry() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, Some(ts(3000)));
        g.register_bailment(b.clone()).expect("register bailment");
        g.register_consent(&bob(), "read", "data-owner", 1, b)
            .expect("register consent");
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            Ok(ConsentDecision::Denied { .. })
        ));
    }

    #[test]
    fn grant_with_future_expiry() {
        let mut g = ConsentGate::new(strict_policy());
        let exp = ts(10000);
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, Some(exp));
        g.register_bailment(b.clone()).expect("register bailment");
        g.register_consent(&bob(), "read", "data-owner", 1, b)
            .expect("register consent");
        assert_eq!(
            g.check(&bob(), "read", &now()),
            Ok(ConsentDecision::Granted { expires: Some(exp) })
        );
    }

    #[test]
    fn escalate_with_delegation() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Delegation, None);
        g.register_bailment(b.clone()).expect("register bailment");
        g.register_consent(&bob(), "read", "viewer", 0, b)
            .expect("register consent");
        let d = g.check(&bob(), "read", &now());
        assert!(matches!(d, Ok(ConsentDecision::Escalated { .. })));
        if let Ok(ConsentDecision::Escalated { to }) = d {
            assert_eq!(to, alice());
        }
    }

    #[test]
    fn deny_unknown_action() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        g.register_consent(&bob(), "read", "data-owner", 1, b)
            .expect("register consent");
        assert!(matches!(
            g.check(&bob(), "write", &now()),
            Ok(ConsentDecision::Denied { .. })
        ));
    }

    #[test]
    fn deny_unknown_actor() {
        let mut g = ConsentGate::new(strict_policy());
        assert!(matches!(
            g.check(&charlie(), "read", &now()),
            Ok(ConsentDecision::Denied { .. })
        ));
    }

    #[test]
    fn check_denies_status_forged_active_bailment() {
        let mut g = ConsentGate::new(strict_policy());
        let mut b = bailment::propose(
            &alice(),
            &bob(),
            b"gt",
            BailmentType::Custody,
            "forged",
            ts(1000),
        )
        .expect("test bailment proposal");
        b.status = bailment::BailmentStatus::Active;
        b.signature = exo_core::Signature::from_bytes([0xAB; 64]);
        g.register_consent(&bob(), "read", "data-owner", 1, b)
            .expect("register consent");

        assert!(
            matches!(
                g.check(&bob(), "read", &now()),
                Ok(ConsentDecision::Denied { .. })
            ),
            "ConsentGate must not grant on a status-forged active bailment"
        );
    }

    #[test]
    fn policy_accessor() {
        let g = ConsentGate::new(strict_policy());
        assert_eq!(g.policy().id, "strict");
    }

    #[test]
    fn set_policy() {
        let mut g = ConsentGate::new(strict_policy());
        let p = ConsentPolicy {
            id: "perm".into(),
            name: "perm".into(),
            required_consents: vec![],
            deny_by_default: false,
        };
        g.set_policy(p);
        assert_eq!(g.policy().id, "perm");
        assert!(matches!(
            g.check(&bob(), "anything", &now()),
            Ok(ConsentDecision::Granted { .. })
        ));
    }

    #[test]
    fn multiple_consents() {
        let mut g = ConsentGate::new(ConsentPolicy {
            id: "m".into(),
            name: "m".into(),
            deny_by_default: true,
            required_consents: vec![
                ConsentRequirement {
                    action_type: "read".into(),
                    required_role: "data-owner".into(),
                    min_clearance_level: 1,
                },
                ConsentRequirement {
                    action_type: "write".into(),
                    required_role: "admin".into(),
                    min_clearance_level: 2,
                },
            ],
        });
        let b1 = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        let b2 = make_bailment(&alice(), &bob(), BailmentType::Processing, None);
        g.register_consent(&bob(), "read", "data-owner", 1, b1)
            .expect("register consent");
        g.register_consent(&bob(), "write", "admin", 3, b2)
            .expect("register consent");
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            Ok(ConsentDecision::Granted { .. })
        ));
        assert!(matches!(
            g.check(&bob(), "write", &now()),
            Ok(ConsentDecision::Granted { .. })
        ));
    }

    #[test]
    fn revoke_nonexistent_is_noop() {
        let mut g = ConsentGate::new(strict_policy());
        let b = make_bailment(&alice(), &bob(), BailmentType::Custody, None);
        g.register_consent(&bob(), "read", "data-owner", 1, b)
            .expect("register consent");
        g.revoke_by_bailment_id("nonexistent", ts(6000))
            .expect("revoke nonexistent");
        assert!(matches!(
            g.check(&bob(), "read", &now()),
            Ok(ConsentDecision::Granted { .. })
        ));
    }
}
