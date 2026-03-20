//! Holon autonomous agent runtime.
//!
//! A Holon is an autonomous agent that executes a combinator program
//! under kernel adjudication. Every step is capability-checked.

use exo_core::Did;
use serde::{Deserialize, Serialize};

use crate::{
    combinator::{CheckpointId, Combinator, CombinatorInput, CombinatorOutput, reduce},
    error::GatekeeperError,
    kernel::{ActionRequest, AdjudicationContext, Kernel, Verdict},
    types::PermissionSet,
};

// ---------------------------------------------------------------------------
// Holon state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HolonState {
    Idle,
    Executing,
    Suspended,
    Terminated,
}

// ---------------------------------------------------------------------------
// Checkpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub id: CheckpointId,
    pub holon_id: Did,
    pub state: HolonState,
    pub last_output: Option<CombinatorOutput>,
}

// ---------------------------------------------------------------------------
// Holon
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Holon {
    pub id: Did,
    pub capabilities: PermissionSet,
    pub state: HolonState,
    pub combinator_chain: Combinator,
    pub last_output: Option<CombinatorOutput>,
}

#[must_use]
pub fn spawn(id: Did, capabilities: PermissionSet, program: Combinator) -> Holon {
    Holon {
        id,
        capabilities,
        state: HolonState::Idle,
        combinator_chain: program,
        last_output: None,
    }
}

pub fn step(
    holon: &mut Holon,
    input: &CombinatorInput,
    kernel: &Kernel,
    adjudication_context: &AdjudicationContext,
) -> Result<CombinatorOutput, GatekeeperError> {
    match holon.state {
        HolonState::Terminated => {
            return Err(GatekeeperError::HolonError(
                "Cannot step a terminated holon".into(),
            ));
        }
        HolonState::Suspended => {
            return Err(GatekeeperError::HolonError(
                "Cannot step a suspended holon — resume first".into(),
            ));
        }
        _ => {}
    }

    let action = ActionRequest {
        actor: holon.id.clone(),
        action: "holon_step".into(),
        required_permissions: holon.capabilities.clone(),
        is_self_grant: false,
        modifies_kernel: false,
    };

    match kernel.adjudicate(&action, adjudication_context) {
        Verdict::Permitted => {}
        Verdict::Denied { violations } => {
            holon.state = HolonState::Terminated;
            let descs: Vec<String> = violations.iter().map(|v| v.description.clone()).collect();
            return Err(GatekeeperError::CapabilityDenied(descs.join("; ")));
        }
        Verdict::Escalated { reason } => {
            holon.state = HolonState::Suspended;
            return Err(GatekeeperError::HolonError(format!(
                "Step escalated: {}",
                reason
            )));
        }
    }

    holon.state = HolonState::Executing;
    let output = reduce(&holon.combinator_chain, input)?;
    holon.last_output = Some(output.clone());
    holon.state = HolonState::Idle;
    Ok(output)
}

pub fn suspend(holon: &mut Holon) -> Result<Checkpoint, GatekeeperError> {
    if holon.state == HolonState::Terminated {
        return Err(GatekeeperError::HolonError(
            "Cannot suspend a terminated holon".into(),
        ));
    }
    holon.state = HolonState::Suspended;
    Ok(Checkpoint {
        id: CheckpointId(format!("checkpoint-{}", holon.id)),
        holon_id: holon.id.clone(),
        state: holon.state,
        last_output: holon.last_output.clone(),
    })
}

pub fn resume(holon: &mut Holon, checkpoint: &Checkpoint) -> Result<(), GatekeeperError> {
    if holon.state != HolonState::Suspended {
        return Err(GatekeeperError::HolonError(
            "Can only resume a suspended holon".into(),
        ));
    }
    if checkpoint.holon_id != holon.id {
        return Err(GatekeeperError::CheckpointError(
            "Checkpoint holon ID does not match".into(),
        ));
    }
    holon.last_output.clone_from(&checkpoint.last_output);
    holon.state = HolonState::Idle;
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        combinator::{Predicate, TransformFn},
        invariants::InvariantSet,
        types::*,
    };

    fn did(s: &str) -> Did {
        Did::new(s).expect("valid DID")
    }
    fn test_kernel() -> Kernel {
        Kernel::new(b"constitution", InvariantSet::all())
    }

    fn test_holon() -> Holon {
        spawn(
            did("did:exo:holon1"),
            PermissionSet::new(vec![Permission::new("read")]),
            Combinator::Identity,
        )
    }

    fn valid_adj(actor: &Did) -> AdjudicationContext {
        AdjudicationContext {
            actor_roles: vec![Role {
                name: "worker".into(),
                branch: GovernmentBranch::Executive,
            }],
            authority_chain: AuthorityChain {
                links: vec![AuthorityLink {
                    grantor: did("did:exo:root"),
                    grantee: actor.clone(),
                    permissions: PermissionSet::new(vec![Permission::new("read")]),
                    signature: vec![1, 2, 3],
                    grantor_public_key: None,
                }],
            },
            consent_records: vec![ConsentRecord {
                subject: did("did:exo:owner"),
                granted_to: actor.clone(),
                scope: "data".into(),
                active: true,
            }],
            bailment_state: BailmentState::Active {
                bailor: did("did:exo:owner"),
                bailee: actor.clone(),
                scope: "data".into(),
            },
            human_override_preserved: true,
            actor_permissions: PermissionSet::new(vec![Permission::new("read")]),
            provenance: Some(Provenance {
                actor: actor.clone(),
                timestamp: "t".into(),
                action_hash: vec![1],
                signature: vec![4, 5, 6],
            }),
            quorum_evidence: None,
        }
    }

    #[test]
    fn spawn_creates_idle() {
        let h = test_holon();
        assert_eq!(h.state, HolonState::Idle);
        assert!(h.last_output.is_none());
    }

    #[test]
    fn step_succeeds() {
        let kernel = test_kernel();
        let mut h = test_holon();
        let ctx = valid_adj(&h.id);
        let out = step(
            &mut h,
            &CombinatorInput::new().with("x", "1"),
            &kernel,
            &ctx,
        )
        .unwrap();
        assert_eq!(out.fields.get("x"), Some(&"1".to_string()));
        assert_eq!(h.state, HolonState::Idle);
    }

    #[test]
    fn step_denied_no_consent() {
        let kernel = test_kernel();
        let mut h = test_holon();
        let mut ctx = valid_adj(&h.id);
        ctx.bailment_state = BailmentState::None;
        assert!(step(&mut h, &CombinatorInput::new(), &kernel, &ctx).is_err());
        assert_eq!(h.state, HolonState::Terminated);
    }

    #[test]
    fn step_fails_terminated() {
        let kernel = test_kernel();
        let mut h = test_holon();
        h.state = HolonState::Terminated;
        let ctx = valid_adj(&h.id);
        assert!(step(&mut h, &CombinatorInput::new(), &kernel, &ctx).is_err());
    }

    #[test]
    fn step_fails_suspended() {
        let kernel = test_kernel();
        let mut h = test_holon();
        h.state = HolonState::Suspended;
        let ctx = valid_adj(&h.id);
        assert!(step(&mut h, &CombinatorInput::new(), &kernel, &ctx).is_err());
    }

    #[test]
    fn step_enforces_separation_of_powers() {
        let kernel = test_kernel();
        let mut h = test_holon();
        let mut ctx = valid_adj(&h.id);
        ctx.actor_roles = vec![
            Role {
                name: "j".into(),
                branch: GovernmentBranch::Judicial,
            },
            Role {
                name: "s".into(),
                branch: GovernmentBranch::Legislative,
            },
        ];
        assert!(step(&mut h, &CombinatorInput::new(), &kernel, &ctx).is_err());
        assert_eq!(h.state, HolonState::Terminated);
    }

    #[test]
    fn suspend_and_resume() {
        let mut h = test_holon();
        let cp = suspend(&mut h).unwrap();
        assert_eq!(h.state, HolonState::Suspended);
        resume(&mut h, &cp).unwrap();
        assert_eq!(h.state, HolonState::Idle);
    }

    #[test]
    fn suspend_fails_terminated() {
        let mut h = test_holon();
        h.state = HolonState::Terminated;
        assert!(suspend(&mut h).is_err());
    }

    #[test]
    fn resume_fails_not_suspended() {
        let mut h = test_holon();
        let cp = Checkpoint {
            id: CheckpointId("t".into()),
            holon_id: h.id.clone(),
            state: HolonState::Idle,
            last_output: None,
        };
        assert!(resume(&mut h, &cp).is_err());
    }

    #[test]
    fn resume_fails_mismatch() {
        let mut h = test_holon();
        h.state = HolonState::Suspended;
        let cp = Checkpoint {
            id: CheckpointId("t".into()),
            holon_id: did("did:exo:wrong"),
            state: HolonState::Suspended,
            last_output: None,
        };
        assert!(resume(&mut h, &cp).is_err());
    }

    #[test]
    fn step_with_transform() {
        let kernel = test_kernel();
        let mut h = spawn(
            did("did:exo:holon1"),
            PermissionSet::new(vec![Permission::new("read")]),
            Combinator::Transform(
                Box::new(Combinator::Identity),
                TransformFn {
                    name: "e".into(),
                    output_key: "enriched".into(),
                    output_value: "true".into(),
                },
            ),
        );
        let ctx = valid_adj(&h.id);
        let out = step(
            &mut h,
            &CombinatorInput::new().with("d", "r"),
            &kernel,
            &ctx,
        )
        .unwrap();
        assert_eq!(out.fields.get("enriched"), Some(&"true".to_string()));
    }

    #[test]
    fn full_lifecycle() {
        let kernel = test_kernel();
        let mut h = test_holon();
        let input = CombinatorInput::new().with("x", "1");
        let ctx = valid_adj(&h.id);
        let _ = step(&mut h, &input, &kernel, &ctx).unwrap();
        let cp = suspend(&mut h).unwrap();
        resume(&mut h, &cp).unwrap();
        let out = step(&mut h, &input, &kernel, &ctx).unwrap();
        assert_eq!(out.fields.get("x"), Some(&"1".to_string()));
    }

    #[test]
    fn step_guard_success() {
        let kernel = test_kernel();
        let mut h = spawn(
            did("did:exo:holon1"),
            PermissionSet::new(vec![Permission::new("read")]),
            Combinator::Guard(
                Box::new(Combinator::Identity),
                Predicate {
                    name: "t".into(),
                    required_key: "token".into(),
                    expected_value: None,
                },
            ),
        );
        let ctx = valid_adj(&h.id);
        assert!(
            step(
                &mut h,
                &CombinatorInput::new().with("token", "abc"),
                &kernel,
                &ctx
            )
            .is_ok()
        );
    }

    #[test]
    fn step_guard_failure() {
        let kernel = test_kernel();
        let mut h = spawn(
            did("did:exo:holon1"),
            PermissionSet::new(vec![Permission::new("read")]),
            Combinator::Guard(
                Box::new(Combinator::Identity),
                Predicate {
                    name: "t".into(),
                    required_key: "token".into(),
                    expected_value: None,
                },
            ),
        );
        let ctx = valid_adj(&h.id);
        assert!(step(&mut h, &CombinatorInput::new(), &kernel, &ctx).is_err());
    }
}
