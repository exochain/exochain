'use strict';

/**
 * ExoChain Core Type Definitions
 *
 * JavaScript constants mirroring the Rust enums/structs from the ExoChain crates:
 *   - DecisionClass      ← decision-forum/src/decision_object.rs
 *   - DecisionState       ← exo-core/src/bcts.rs  (BctsState)
 *   - VoteChoice          ← decision-forum/src/decision_object.rs
 *   - ActorKind           ← decision-forum/src/decision_object.rs
 *   - QuorumSpec          ← exo-governance/src/decision.rs
 *   - ChallengeGround     ← exo-governance/src/challenge.rs
 *   - AccountabilityType  ← decision-forum/src/accountability.rs
 */

// ---------------------------------------------------------------------------
// DecisionClass — escalating severity of governance decisions
// ---------------------------------------------------------------------------

const DecisionClass = Object.freeze({
  ROUTINE:        'Routine',        // Day-to-day operational decisions
  OPERATIONAL:    'Operational',    // Decisions affecting operations or resources
  STRATEGIC:      'Strategic',      // Long-term or high-impact decisions
  CONSTITUTIONAL: 'Constitutional', // Decisions that modify the constitutional corpus
});

/** Ordered from lowest to highest severity. */
const DECISION_CLASS_ORDER = Object.freeze([
  DecisionClass.ROUTINE,
  DecisionClass.OPERATIONAL,
  DecisionClass.STRATEGIC,
  DecisionClass.CONSTITUTIONAL,
]);

// ---------------------------------------------------------------------------
// DecisionState — 14-state BCTS lifecycle (Bailment-Conditioned Transaction Set)
// ---------------------------------------------------------------------------

const DecisionState = Object.freeze({
  DRAFT:              'Draft',
  SUBMITTED:          'Submitted',
  IDENTITY_RESOLVED:  'IdentityResolved',
  CONSENT_VALIDATED:  'ConsentValidated',
  DELIBERATED:        'Deliberated',
  VERIFIED:           'Verified',
  GOVERNED:           'Governed',
  APPROVED:           'Approved',
  EXECUTED:           'Executed',
  RECORDED:           'Recorded',
  CLOSED:             'Closed',
  DENIED:             'Denied',
  ESCALATED:          'Escalated',
  REMEDIATED:         'Remediated',
});

/** Valid state transitions — maps each state to its allowed next states. */
const DECISION_STATE_TRANSITIONS = Object.freeze({
  [DecisionState.DRAFT]:              [DecisionState.SUBMITTED],
  [DecisionState.SUBMITTED]:          [DecisionState.IDENTITY_RESOLVED, DecisionState.DENIED],
  [DecisionState.IDENTITY_RESOLVED]:  [DecisionState.CONSENT_VALIDATED, DecisionState.DENIED],
  [DecisionState.CONSENT_VALIDATED]:  [DecisionState.DELIBERATED, DecisionState.DENIED],
  [DecisionState.DELIBERATED]:        [DecisionState.VERIFIED, DecisionState.DENIED, DecisionState.ESCALATED],
  [DecisionState.VERIFIED]:           [DecisionState.GOVERNED, DecisionState.DENIED, DecisionState.ESCALATED],
  [DecisionState.GOVERNED]:           [DecisionState.APPROVED, DecisionState.DENIED, DecisionState.ESCALATED],
  [DecisionState.APPROVED]:           [DecisionState.EXECUTED, DecisionState.DENIED],
  [DecisionState.EXECUTED]:           [DecisionState.RECORDED, DecisionState.ESCALATED],
  [DecisionState.RECORDED]:           [DecisionState.CLOSED, DecisionState.ESCALATED],
  [DecisionState.CLOSED]:             [],
  [DecisionState.DENIED]:             [DecisionState.REMEDIATED],
  [DecisionState.ESCALATED]:          [DecisionState.DELIBERATED, DecisionState.DENIED, DecisionState.REMEDIATED],
  [DecisionState.REMEDIATED]:         [DecisionState.SUBMITTED],
});

/**
 * Check whether a state transition is valid.
 * @param {string} from - Current DecisionState value
 * @param {string} to   - Target DecisionState value
 * @returns {boolean}
 */
function canTransition(from, to) {
  const allowed = DECISION_STATE_TRANSITIONS[from];
  return Array.isArray(allowed) && allowed.includes(to);
}

// ---------------------------------------------------------------------------
// VoteChoice
// ---------------------------------------------------------------------------

const VoteChoice = Object.freeze({
  APPROVE: 'Approve',
  REJECT:  'Reject',
  ABSTAIN: 'Abstain',
});

// ---------------------------------------------------------------------------
// ActorKind — Human vs AI with delegation ceiling
// ---------------------------------------------------------------------------

const ActorKind = Object.freeze({
  HUMAN:    'Human',
  AI_AGENT: 'AiAgent',
});

/**
 * Create an ActorKind descriptor.
 * @param {string}  kind            - ActorKind.HUMAN or ActorKind.AI_AGENT
 * @param {object}  [opts]          - Options for AI agents
 * @param {string}  [opts.delegationId]   - Delegation identifier
 * @param {string}  [opts.ceilingClass]   - Maximum DecisionClass the agent may act on
 * @returns {object}
 */
function makeActor(kind, opts) {
  if (kind === ActorKind.HUMAN) {
    return { kind: ActorKind.HUMAN };
  }
  return {
    kind: ActorKind.AI_AGENT,
    delegationId:  opts && opts.delegationId  || null,
    ceilingClass:  opts && opts.ceilingClass  || DecisionClass.ROUTINE,
  };
}

/**
 * Check whether an actor is permitted to act on a given decision class.
 * Humans have no ceiling. AI agents are bounded by their delegation ceiling.
 * @param {object} actor          - Actor descriptor from makeActor()
 * @param {string} decisionClass  - A DecisionClass value
 * @returns {boolean}
 */
function actorCanDecide(actor, decisionClass) {
  if (actor.kind === ActorKind.HUMAN) return true;
  const ceilingIdx = DECISION_CLASS_ORDER.indexOf(actor.ceilingClass);
  const classIdx   = DECISION_CLASS_ORDER.indexOf(decisionClass);
  return classIdx >= 0 && ceilingIdx >= 0 && classIdx <= ceilingIdx;
}

// ---------------------------------------------------------------------------
// QuorumSpec — quorum policy for a decision class
// ---------------------------------------------------------------------------

/**
 * Create a QuorumSpec.
 * @param {object} spec
 * @param {number} spec.minParticipants    - Minimum eligible voters who must participate
 * @param {number} spec.approvalThreshold  - Approval percentage (0-100)
 * @param {string[]} spec.eligibleVoters   - Array of eligible voter identifiers (DIDs)
 * @returns {object}
 */
function makeQuorumSpec(spec) {
  return Object.freeze({
    minParticipants:   spec.minParticipants,
    approvalThreshold: spec.approvalThreshold,
    eligibleVoters:    Object.freeze(spec.eligibleVoters.slice()),
  });
}

/**
 * Check whether quorum is met given participant count.
 * @param {object} quorum        - QuorumSpec from makeQuorumSpec()
 * @param {number} participants  - Number of voters who participated
 * @returns {boolean}
 */
function isQuorumMet(quorum, participants) {
  return participants >= quorum.minParticipants;
}

/**
 * Check whether a vote passes given approve and total counts.
 * @param {object} quorum  - QuorumSpec from makeQuorumSpec()
 * @param {number} approvals
 * @param {number} totalVotes
 * @returns {boolean}
 */
function isApproved(quorum, approvals, totalVotes) {
  if (totalVotes === 0) return false;
  return (approvals / totalVotes) * 100 >= quorum.approvalThreshold;
}

/** Default quorum policies per decision class (from ExoChain spec). */
const DEFAULT_QUORUM = Object.freeze({
  [DecisionClass.ROUTINE]:        makeQuorumSpec({ minParticipants: 1, approvalThreshold: 51, eligibleVoters: [] }),
  [DecisionClass.OPERATIONAL]:    makeQuorumSpec({ minParticipants: 3, approvalThreshold: 51, eligibleVoters: [] }),
  [DecisionClass.STRATEGIC]:      makeQuorumSpec({ minParticipants: 5, approvalThreshold: 67, eligibleVoters: [] }),
  [DecisionClass.CONSTITUTIONAL]: makeQuorumSpec({ minParticipants: 7, approvalThreshold: 75, eligibleVoters: [] }),
});

// ---------------------------------------------------------------------------
// ChallengeGround — 6 constitutional grounds for challenging a decision
// ---------------------------------------------------------------------------

const ChallengeGround = Object.freeze({
  AUTHORITY_CHAIN_INVALID: 'AuthorityChainInvalid',
  QUORUM_VIOLATION:        'QuorumViolation',
  UNDISCLOSED_CONFLICT:    'UndisclosedConflict',
  PROCEDURAL_ERROR:        'ProceduralError',
  SYBIL_ALLEGATION:        'SybilAllegation',
  CONSENT_VIOLATION:       'ConsentViolation',
});

// ---------------------------------------------------------------------------
// AccountabilityType — 4 accountability action types (GOV-012)
// ---------------------------------------------------------------------------

const AccountabilityType = Object.freeze({
  CENSURE:    'Censure',
  SUSPENSION: 'Suspension',
  REVOCATION: 'Revocation',
  RECALL:     'Recall',
});

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  // Enums
  DecisionClass,
  DECISION_CLASS_ORDER,
  DecisionState,
  DECISION_STATE_TRANSITIONS,
  VoteChoice,
  ActorKind,
  ChallengeGround,
  AccountabilityType,

  // Quorum
  DEFAULT_QUORUM,

  // Helpers
  canTransition,
  makeActor,
  actorCanDecide,
  makeQuorumSpec,
  isQuorumMet,
  isApproved,
};
