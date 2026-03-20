//! Trust-Critical Non-Negotiable Controls (TNC-01 through TNC-10).
//!
//! One clean implementation of all 10 TNCs. Each TNC is a function:
//! `enforce_tnc_XX(context) -> Result<(), ForumError>`.
//! Called on every state transition. No bypass, no override.

use crate::{
    decision_object::{ActorKind, DecisionObject},
    error::{ForumError, Result},
};

/// Context for TNC enforcement checks.
pub struct TncContext<'a> {
    pub decision: &'a DecisionObject,
    pub constitutional_hash_valid: bool,
    pub consent_verified: bool,
    pub identity_verified: bool,
    pub evidence_complete: bool,
    pub quorum_met: bool,
    pub human_gate_satisfied: bool,
    pub authority_chain_verified: bool,
    /// Whether AI signer delegation ceilings have been verified externally
    /// against the delegation registry (not self-declared by the AI agent).
    ///
    /// When `false` (default), TNC-09 restricts ALL AI signers to `Routine`
    /// decisions only — a fail-closed posture that prevents AI agents from
    /// bypassing human oversight by self-declaring an elevated ceiling.
    ///
    /// Set to `true` only after looking up each AI signer's `delegation_id`
    /// in the delegation registry and confirming the `ceiling_class` in the
    /// vote matches the registry-granted ceiling (not self-asserted).
    pub ai_ceilings_externally_verified: bool,
}

/// TNC-01: Every action must have a verified authority chain.
pub fn enforce_tnc_01(ctx: &TncContext<'_>) -> Result<()> {
    if !ctx.authority_chain_verified {
        return Err(ForumError::TncViolation {
            tnc_id: 1,
            reason: "authority chain not verified".into(),
        });
    }
    if ctx.decision.authority_chain.is_empty() {
        return Err(ForumError::TncViolation {
            tnc_id: 1,
            reason: "empty authority chain".into(),
        });
    }
    Ok(())
}

/// TNC-02: Human gate enforcement — AI cannot satisfy human-required approvals.
pub fn enforce_tnc_02(ctx: &TncContext<'_>) -> Result<()> {
    if !ctx.human_gate_satisfied {
        return Err(ForumError::TncViolation {
            tnc_id: 2,
            reason: "human gate not satisfied".into(),
        });
    }
    Ok(())
}

/// TNC-03: Consent must be verified before any action proceeds.
pub fn enforce_tnc_03(ctx: &TncContext<'_>) -> Result<()> {
    if !ctx.consent_verified {
        return Err(ForumError::TncViolation {
            tnc_id: 3,
            reason: "consent not verified".into(),
        });
    }
    Ok(())
}

/// TNC-04: Identity must be resolved before governance actions.
pub fn enforce_tnc_04(ctx: &TncContext<'_>) -> Result<()> {
    if !ctx.identity_verified {
        return Err(ForumError::TncViolation {
            tnc_id: 4,
            reason: "identity not verified".into(),
        });
    }
    Ok(())
}

/// TNC-05: Delegation expiry must be enforced — no expired delegations.
pub fn enforce_tnc_05(ctx: &TncContext<'_>) -> Result<()> {
    // Expired delegations must not appear in the authority chain.
    // We check that the authority chain is verified (which includes expiry).
    if !ctx.authority_chain_verified {
        return Err(ForumError::TncViolation {
            tnc_id: 5,
            reason: "delegation expiry not enforced (authority chain unverified)".into(),
        });
    }
    Ok(())
}

/// TNC-06: Constitutional binding — decision must reference valid constitution.
pub fn enforce_tnc_06(ctx: &TncContext<'_>) -> Result<()> {
    if !ctx.constitutional_hash_valid {
        return Err(ForumError::TncViolation {
            tnc_id: 6,
            reason: "decision not bound to valid constitution".into(),
        });
    }
    Ok(())
}

/// TNC-07: Quorum must be verified before votes are counted.
pub fn enforce_tnc_07(ctx: &TncContext<'_>) -> Result<()> {
    if !ctx.quorum_met {
        return Err(ForumError::TncViolation {
            tnc_id: 7,
            reason: "quorum not met".into(),
        });
    }
    Ok(())
}

/// TNC-08: Immutability — terminal decisions cannot be modified.
pub fn enforce_tnc_08(ctx: &TncContext<'_>) -> Result<()> {
    if ctx.decision.is_terminal() {
        return Err(ForumError::TncViolation {
            tnc_id: 8,
            reason: "decision is in terminal state — immutable".into(),
        });
    }
    Ok(())
}

/// TNC-09: AI delegation ceiling — AI cannot exceed its ceiling class.
///
/// When `ctx.ai_ceilings_externally_verified` is `false`, all AI signers are
/// restricted to `Routine` decisions regardless of their self-declared
/// `ceiling_class`.  This prevents AI agents from bypassing governance controls
/// by self-asserting an elevated ceiling (M3 Phase 1 mitigation).
pub fn enforce_tnc_09(ctx: &TncContext<'_>) -> Result<()> {
    use crate::decision_object::DecisionClass;
    for vote in &ctx.decision.votes {
        if let ActorKind::AiAgent {
            ceiling_class,
            delegation_id,
        } = &vote.actor_kind
        {
            // Fail-closed: when ceilings have not been externally verified
            // via the delegation registry, restrict all AI signers to Routine.
            let effective_ceiling = if ctx.ai_ceilings_externally_verified {
                *ceiling_class
            } else {
                DecisionClass::Routine
            };
            if ctx.decision.class > effective_ceiling {
                return Err(ForumError::TncViolation {
                    tnc_id: 9,
                    reason: if ctx.ai_ceilings_externally_verified {
                        format!(
                            "AI agent '{}' vote on {:?} exceeds delegation-registry ceiling {:?}",
                            delegation_id, ctx.decision.class, ceiling_class
                        )
                    } else {
                        format!(
                            "AI agent '{}' ceiling unverified — restricted to Routine, got {:?}",
                            delegation_id, ctx.decision.class,
                        )
                    },
                });
            }
        }
    }
    Ok(())
}

/// TNC-10: Evidence completeness — all decisions must have supporting evidence.
pub fn enforce_tnc_10(ctx: &TncContext<'_>) -> Result<()> {
    if !ctx.evidence_complete {
        return Err(ForumError::TncViolation {
            tnc_id: 10,
            reason: "evidence bundle incomplete".into(),
        });
    }
    Ok(())
}

/// Run ALL TNC enforcements. Returns the first violation found, or Ok(()).
pub fn enforce_all(ctx: &TncContext<'_>) -> Result<()> {
    enforce_tnc_01(ctx)?;
    enforce_tnc_02(ctx)?;
    enforce_tnc_03(ctx)?;
    enforce_tnc_04(ctx)?;
    enforce_tnc_05(ctx)?;
    enforce_tnc_06(ctx)?;
    enforce_tnc_07(ctx)?;
    enforce_tnc_08(ctx)?;
    enforce_tnc_09(ctx)?;
    enforce_tnc_10(ctx)?;
    Ok(())
}

/// Collect ALL TNC violations (does not short-circuit).
pub fn collect_violations(ctx: &TncContext<'_>) -> Vec<ForumError> {
    let checks: Vec<fn(&TncContext<'_>) -> Result<()>> = vec![
        enforce_tnc_01,
        enforce_tnc_02,
        enforce_tnc_03,
        enforce_tnc_04,
        enforce_tnc_05,
        enforce_tnc_06,
        enforce_tnc_07,
        enforce_tnc_08,
        enforce_tnc_09,
        enforce_tnc_10,
    ];
    checks.iter().filter_map(|check| check(ctx).err()).collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use exo_core::{
        bcts::BctsState,
        hlc::HybridClock,
        types::{Did, Hash256},
    };

    use super::*;
    use crate::decision_object::*;

    fn test_clock() -> HybridClock {
        let counter = AtomicU64::new(1000);
        HybridClock::with_wall_clock(move || counter.fetch_add(1, Ordering::Relaxed))
    }

    fn passing_ctx(d: &DecisionObject) -> TncContext<'_> {
        TncContext {
            decision: d,
            constitutional_hash_valid: true,
            consent_verified: true,
            identity_verified: true,
            evidence_complete: true,
            quorum_met: true,
            human_gate_satisfied: true,
            authority_chain_verified: true,
            ai_ceilings_externally_verified: true,
        }
    }

    fn decision_with_authority(clock: &mut HybridClock) -> DecisionObject {
        let mut d = DecisionObject::new("test", DecisionClass::Operational, Hash256::ZERO, clock);
        let ts = clock.now();
        d.add_authority_link(AuthorityLink {
            actor_did: Did::new("did:exo:root").expect("ok"),
            actor_kind: ActorKind::Human,
            delegation_hash: Hash256::digest(b"d1"),
            timestamp: ts,
        })
        .expect("ok");
        d
    }

    #[test]
    fn all_pass() {
        let mut clock = test_clock();
        let d = decision_with_authority(&mut clock);
        let ctx = passing_ctx(&d);
        assert!(enforce_all(&ctx).is_ok());
    }

    #[test]
    fn tnc_01_empty_authority() {
        let mut clock = test_clock();
        let d = DecisionObject::new("test", DecisionClass::Routine, Hash256::ZERO, &mut clock);
        let ctx = passing_ctx(&d);
        let err = enforce_tnc_01(&ctx).unwrap_err();
        assert!(matches!(err, ForumError::TncViolation { tnc_id: 1, .. }));
    }

    #[test]
    fn tnc_01_unverified() {
        let mut clock = test_clock();
        let d = decision_with_authority(&mut clock);
        let mut ctx = passing_ctx(&d);
        ctx.authority_chain_verified = false;
        assert!(enforce_tnc_01(&ctx).is_err());
    }

    #[test]
    fn tnc_02_human_gate() {
        let mut clock = test_clock();
        let d = decision_with_authority(&mut clock);
        let mut ctx = passing_ctx(&d);
        ctx.human_gate_satisfied = false;
        let err = enforce_tnc_02(&ctx).unwrap_err();
        assert!(matches!(err, ForumError::TncViolation { tnc_id: 2, .. }));
    }

    #[test]
    fn tnc_03_consent() {
        let mut clock = test_clock();
        let d = decision_with_authority(&mut clock);
        let mut ctx = passing_ctx(&d);
        ctx.consent_verified = false;
        assert!(enforce_tnc_03(&ctx).is_err());
    }

    #[test]
    fn tnc_04_identity() {
        let mut clock = test_clock();
        let d = decision_with_authority(&mut clock);
        let mut ctx = passing_ctx(&d);
        ctx.identity_verified = false;
        assert!(enforce_tnc_04(&ctx).is_err());
    }

    #[test]
    fn tnc_06_constitution() {
        let mut clock = test_clock();
        let d = decision_with_authority(&mut clock);
        let mut ctx = passing_ctx(&d);
        ctx.constitutional_hash_valid = false;
        assert!(enforce_tnc_06(&ctx).is_err());
    }

    #[test]
    fn tnc_07_quorum() {
        let mut clock = test_clock();
        let d = decision_with_authority(&mut clock);
        let mut ctx = passing_ctx(&d);
        ctx.quorum_met = false;
        assert!(enforce_tnc_07(&ctx).is_err());
    }

    #[test]
    fn tnc_08_immutability() {
        let mut clock = test_clock();
        let actor = Did::new("did:exo:root").expect("ok");
        let mut d = decision_with_authority(&mut clock);
        for s in [
            BctsState::Submitted,
            BctsState::IdentityResolved,
            BctsState::ConsentValidated,
            BctsState::Deliberated,
            BctsState::Verified,
            BctsState::Governed,
            BctsState::Approved,
            BctsState::Executed,
            BctsState::Recorded,
            BctsState::Closed,
        ] {
            d.transition(s, &actor, &mut clock).expect("ok");
        }
        let ctx = passing_ctx(&d);
        let err = enforce_tnc_08(&ctx).unwrap_err();
        assert!(matches!(err, ForumError::TncViolation { tnc_id: 8, .. }));
    }

    #[test]
    fn tnc_09_ai_ceiling() {
        let mut clock = test_clock();
        let mut d =
            DecisionObject::new("test", DecisionClass::Strategic, Hash256::ZERO, &mut clock);
        d.add_authority_link(AuthorityLink {
            actor_did: Did::new("did:exo:root").expect("ok"),
            actor_kind: ActorKind::Human,
            delegation_hash: Hash256::ZERO,
            timestamp: clock.now(),
        })
        .expect("ok");
        let ts = clock.now();
        d.add_vote(Vote {
            voter_did: Did::new("did:exo:ai-bot").expect("ok"),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::AiAgent {
                delegation_id: "d1".into(),
                ceiling_class: DecisionClass::Operational,
            },
            timestamp: ts,
            signature_hash: Hash256::ZERO,
        })
        .expect("ok");
        let ctx = passing_ctx(&d);
        let err = enforce_tnc_09(&ctx).unwrap_err();
        assert!(matches!(err, ForumError::TncViolation { tnc_id: 9, .. }));
    }

    #[test]
    fn tnc_10_evidence() {
        let mut clock = test_clock();
        let d = decision_with_authority(&mut clock);
        let mut ctx = passing_ctx(&d);
        ctx.evidence_complete = false;
        assert!(enforce_tnc_10(&ctx).is_err());
    }

    #[test]
    fn collect_violations_multiple() {
        let mut clock = test_clock();
        let d = DecisionObject::new("test", DecisionClass::Routine, Hash256::ZERO, &mut clock);
        let ctx = TncContext {
            decision: &d,
            constitutional_hash_valid: false,
            consent_verified: false,
            identity_verified: false,
            evidence_complete: false,
            quorum_met: false,
            human_gate_satisfied: false,
            authority_chain_verified: false,
            ai_ceilings_externally_verified: false,
        };
        let violations = collect_violations(&ctx);
        assert!(violations.len() > 1);
    }

    #[test]
    fn collect_violations_none() {
        let mut clock = test_clock();
        let d = decision_with_authority(&mut clock);
        let ctx = passing_ctx(&d);
        let violations = collect_violations(&ctx);
        assert!(violations.is_empty());
    }

    // -----------------------------------------------------------------------
    // M3 adversarial tests — AI ceiling external verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_ai_ceiling_unverified_blocks_non_routine() {
        // Without external ceiling verification, an AI signer on an Operational
        // decision must be rejected even if it self-declares Operational ceiling.
        let mut clock = test_clock();
        let mut d =
            DecisionObject::new("test", DecisionClass::Operational, Hash256::ZERO, &mut clock);
        d.add_authority_link(AuthorityLink {
            actor_did: Did::new("did:exo:human-root").expect("ok"),
            actor_kind: ActorKind::Human,
            delegation_hash: Hash256::ZERO,
            timestamp: clock.now(),
        })
        .expect("ok");
        d.add_vote(Vote {
            voter_did: Did::new("did:exo:ai-agent").expect("ok"),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::AiAgent {
                delegation_id: "del-001".into(),
                ceiling_class: DecisionClass::Operational, // self-declared
            },
            timestamp: clock.now(),
            signature_hash: Hash256::ZERO,
        })
        .expect("ok");
        let mut ctx = passing_ctx(&d);
        ctx.ai_ceilings_externally_verified = false; // not verified — fail-closed
        let err = enforce_tnc_09(&ctx).unwrap_err();
        assert!(
            matches!(err, ForumError::TncViolation { tnc_id: 9, .. }),
            "expected TNC-09, got {err:?}"
        );
        assert!(err.to_string().contains("unverified"));
    }

    #[test]
    fn test_ai_ceiling_unverified_allows_routine() {
        // Without external verification, AI signers are still allowed on Routine.
        let mut clock = test_clock();
        let mut d =
            DecisionObject::new("test", DecisionClass::Routine, Hash256::ZERO, &mut clock);
        d.add_authority_link(AuthorityLink {
            actor_did: Did::new("did:exo:human-root").expect("ok"),
            actor_kind: ActorKind::Human,
            delegation_hash: Hash256::ZERO,
            timestamp: clock.now(),
        })
        .expect("ok");
        d.add_vote(Vote {
            voter_did: Did::new("did:exo:ai-agent").expect("ok"),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::AiAgent {
                delegation_id: "del-001".into(),
                ceiling_class: DecisionClass::Routine,
            },
            timestamp: clock.now(),
            signature_hash: Hash256::ZERO,
        })
        .expect("ok");
        let mut ctx = passing_ctx(&d);
        ctx.ai_ceilings_externally_verified = false;
        assert!(enforce_tnc_09(&ctx).is_ok());
    }

    #[test]
    fn test_ai_ceiling_verified_allows_declared_class() {
        // With external verification, the declared ceiling_class is trusted.
        let mut clock = test_clock();
        let mut d =
            DecisionObject::new("test", DecisionClass::Operational, Hash256::ZERO, &mut clock);
        d.add_authority_link(AuthorityLink {
            actor_did: Did::new("did:exo:human-root").expect("ok"),
            actor_kind: ActorKind::Human,
            delegation_hash: Hash256::ZERO,
            timestamp: clock.now(),
        })
        .expect("ok");
        d.add_vote(Vote {
            voter_did: Did::new("did:exo:ai-agent").expect("ok"),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::AiAgent {
                delegation_id: "del-001".into(),
                ceiling_class: DecisionClass::Operational,
            },
            timestamp: clock.now(),
            signature_hash: Hash256::ZERO,
        })
        .expect("ok");
        let mut ctx = passing_ctx(&d);
        ctx.ai_ceilings_externally_verified = true;
        assert!(enforce_tnc_09(&ctx).is_ok());
    }

    #[test]
    fn test_ai_self_declared_strategic_blocked_when_verified_ceiling_is_operational() {
        // Even when externally verified, AI cannot exceed its actual registry ceiling.
        let mut clock = test_clock();
        let mut d =
            DecisionObject::new("test", DecisionClass::Strategic, Hash256::ZERO, &mut clock);
        d.add_authority_link(AuthorityLink {
            actor_did: Did::new("did:exo:human-root").expect("ok"),
            actor_kind: ActorKind::Human,
            delegation_hash: Hash256::ZERO,
            timestamp: clock.now(),
        })
        .expect("ok");
        d.add_vote(Vote {
            voter_did: Did::new("did:exo:ai-agent").expect("ok"),
            choice: VoteChoice::Approve,
            actor_kind: ActorKind::AiAgent {
                delegation_id: "del-001".into(),
                ceiling_class: DecisionClass::Operational, // registry says Operational
            },
            timestamp: clock.now(),
            signature_hash: Hash256::ZERO,
        })
        .expect("ok");
        let mut ctx = passing_ctx(&d);
        ctx.ai_ceilings_externally_verified = true;
        let err = enforce_tnc_09(&ctx).unwrap_err();
        assert!(matches!(err, ForumError::TncViolation { tnc_id: 9, .. }));
        // Error mentions the registry ceiling
        assert!(err.to_string().contains("Operational"));
    }
}
