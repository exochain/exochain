/**
 * IntelWar reputation mechanics — multi-dimensional, slow, hard to game.
 * Lives on intelwar.net. Work in the Living Log remains final authority.
 * All values integer basis points (0–10000). Fast engagement signals weight 0.
 */

import { clampBps, composeMeritBps, meritBand, meritPercent } from "./merit.js";

/** @typedef {'evidence'|'adversarial'|'crosscheck'|'synthesis'|'judgment'} StandingDimension */

export const DIMENSION_LABELS = {
  evidence: "Evidence Quality",
  adversarial: "Adversarial Rigor",
  crosscheck: "Cross-Check Quality",
  synthesis: "Synthesis",
  judgment: "Judgment Reliability",
};

/**
 * Core composite weights (sum 100). No dimension > 40.
 * Social/engagement velocity excluded (weight 0).
 */
export const CORE_WEIGHTS = {
  evidence: 30,
  adversarial: 25,
  crosscheck: 15,
  synthesis: 10,
  judgment: 20,
};

/**
 * @typedef {object} StandingDimensions
 * @property {number} evidence
 * @property {number} adversarial
 * @property {number} crosscheck
 * @property {number} synthesis
 * @property {number} judgment
 */

/**
 * @typedef {object} ContributionEdge
 * @property {string} id
 * @property {string} fromId — author of later work
 * @property {string} toId — earlier contribution / person whose work is built on
 * @property {'builds_on'|'cites'|'challenges'} kind
 * @property {number} weightBps
 * @property {number} ordinal
 */

/**
 * @typedef {object} StakeAction
 * @property {string} id
 * @property {string} stakerId
 * @property {string} targetId
 * @property {'endorse'|'challenge'} kind
 * @property {number} stakeBps
 * @property {'open'|'resolved_valid'|'resolved_failed'} status
 * @property {number} ordinal
 */

/**
 * Map legacy MeritBreakdown + optional dimension overrides → StandingDimensions.
 * @param {import('./merit.js').MeritBreakdown} merit
 * @param {Partial<StandingDimensions>} [overrides]
 */
export function dimensionsFromMerit(merit, overrides = {}) {
  const m = merit || {};
  return {
    evidence: clampBps(
      overrides.evidence ??
        Math.floor(
          (clampBps(m.logRefsBps) * 70 + clampBps(m.adversarialBps) * 30) / 100,
        ),
    ),
    adversarial: clampBps(
      overrides.adversarial ??
        Math.floor(
          (clampBps(m.adversarialBps) * 60 + clampBps(m.contestBps) * 40) /
            100,
        ),
    ),
    crosscheck: clampBps(
      overrides.crosscheck ??
        Math.floor(
          (clampBps(m.adversarialBps) * 50 + clampBps(m.contestBps) * 50) /
            100,
        ),
    ),
    synthesis: clampBps(
      overrides.synthesis ??
        Math.floor(
          (clampBps(m.contestBps) * 40 +
            clampBps(m.logRefsBps) * 30 +
            clampBps(m.peerMeritBps) * 30) /
            100,
        ),
    ),
    judgment: clampBps(
      overrides.judgment ??
        Math.floor(
          (clampBps(m.peerMeritBps) * 55 + clampBps(m.logRefsBps) * 45) / 100,
        ),
    ),
  };
}

/**
 * Multi-dimensional composite — convergence required; engagement weight 0.
 * @param {StandingDimensions} dims
 */
export function composeStandingBps(dims) {
  const d = dims || {};
  const weighted =
    clampBps(d.evidence) * CORE_WEIGHTS.evidence +
    clampBps(d.adversarial) * CORE_WEIGHTS.adversarial +
    clampBps(d.crosscheck) * CORE_WEIGHTS.crosscheck +
    clampBps(d.synthesis) * CORE_WEIGHTS.synthesis +
    clampBps(d.judgment) * CORE_WEIGHTS.judgment;
  return clampBps(Math.floor(weighted / 100));
}

/**
 * Fast signals explicitly zeroed — views, reactions, emotional velocity.
 */
export function fastSignalWeightBps() {
  return 0;
}

/**
 * Contribution-graph boost from inbound edges (citation / builds_on).
 * Challenges from high-standing nodes also count as adversarial survival pressure.
 * @param {string} personId
 * @param {ContributionEdge[]} edges
 * @param {Record<string, number>} standingById — composite standing of fromId
 */
export function contributionGraphBoostBps(personId, edges, standingById) {
  let citeBoost = 0;
  let challengePressure = 0;
  const inbound = (edges || []).filter((e) => e.toId === personId);
  for (const e of inbound) {
    const fromStanding = clampBps(standingById[e.fromId] || 0);
    const w = clampBps(e.weightBps);
    if (e.kind === "builds_on" || e.kind === "cites") {
      // Higher-standing citers count more; slow accrual via floor division
      citeBoost += Math.floor((w * fromStanding) / 20000);
    } else if (e.kind === "challenges") {
      challengePressure += Math.floor((w * fromStanding) / 25000);
    }
  }
  return {
    logPersistenceBoostBps: clampBps(citeBoost),
    adversarialPressureBps: clampBps(challengePressure),
  };
}

/**
 * Apply graph boosts into dimensions (deterministic).
 * @param {StandingDimensions} dims
 * @param {{ logPersistenceBoostBps: number, adversarialPressureBps: number }} boost
 */
export function applyGraphBoost(dims, boost) {
  return {
    evidence: clampBps(
      dims.evidence + Math.floor((boost.logPersistenceBoostBps || 0) / 2),
    ),
    adversarial: clampBps(
      dims.adversarial + Math.floor((boost.adversarialPressureBps || 0) / 2),
    ),
    crosscheck: dims.crosscheck,
    synthesis: dims.synthesis,
    judgment: clampBps(
      dims.judgment + Math.floor((boost.logPersistenceBoostBps || 0) / 4),
    ),
  };
}

/**
 * Trajectory: is rigor improving? Positive mind-changes + rising standing.
 * @param {number} mindChangedCount
 * @param {number} earlyStandingBps
 * @param {number} currentStandingBps
 */
export function trajectoryLabel(
  mindChangedCount,
  earlyStandingBps,
  currentStandingBps,
) {
  const delta = clampBps(currentStandingBps) - clampBps(earlyStandingBps);
  const updates = Number(mindChangedCount) || 0;
  if (delta >= 800 && updates >= 2) return "ascending";
  if (delta <= -800) return "declining";
  if (updates >= 3) return "updating";
  return "stable";
}

/**
 * Stake: endorser must have Contested+ band and enough stake budget.
 * @param {number} stakerStandingBps
 * @param {number} stakeBps
 * @param {number} alreadyStakedBps
 * @param {number} [budgetBps]
 */
export function canStake(
  stakerStandingBps,
  stakeBps,
  alreadyStakedBps = 0,
  budgetBps = 2000,
) {
  if (clampBps(stakerStandingBps) < 3500) return false;
  const stake = clampBps(stakeBps);
  if (stake < 100 || stake > 1000) return false;
  return clampBps(alreadyStakedBps) + stake <= clampBps(budgetBps);
}

/**
 * Resolve a stake — valid endorsement/challenge transfers small standing;
 * failed stake burns staker (anti-tribal cost).
 * @param {StakeAction} stake
 * @param {'resolved_valid'|'resolved_failed'} outcome
 */
export function resolveStake(stake, outcome) {
  const amount = clampBps(stake.stakeBps);
  if (outcome === "resolved_valid") {
    return {
      stake: { ...stake, status: "resolved_valid" },
      stakerDeltaBps: Math.floor(amount / 10), // small reward for good judgment
      targetDeltaBps:
        stake.kind === "endorse"
          ? Math.floor(amount / 2)
          : Math.floor(amount / 5),
    };
  }
  return {
    stake: { ...stake, status: "resolved_failed" },
    stakerDeltaBps: -amount, // full burn on careless/tribal stake
    targetDeltaBps: 0,
  };
}

/**
 * Rate-limit: max stakes per actor in an ordinal window.
 */
export function stakeRateAllowed(stakesByActor, ordinal, windowSize = 5, max = 3) {
  const recent = (stakesByActor || []).filter(
    (s) => ordinal - s.ordinal < windowSize,
  );
  return recent.length < max;
}

/**
 * Clique / endorsement-ring heuristic: dense mutual endorse among ≤N actors.
 * @param {StakeAction[]} stakes
 * @param {number} [minMutual]
 */
export function detectEndorsementRing(stakes, minMutual = 3) {
  /** @type {Record<string, Set<string>>} */
  const endorse = {};
  for (const s of stakes || []) {
    if (s.kind !== "endorse") continue;
    if (s.status === "resolved_failed") continue;
    if (!endorse[s.stakerId]) endorse[s.stakerId] = new Set();
    endorse[s.stakerId].add(s.targetId);
  }
  const flagged = [];
  const ids = Object.keys(endorse).sort();
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      const a = ids[i];
      const b = ids[j];
      const ab = endorse[a]?.has(b);
      const ba = endorse[b]?.has(a);
      if (ab && ba) {
        // count common mutual targets
        let mutual = 0;
        for (const t of endorse[a]) {
          if (t !== b && endorse[b].has(t) && endorse[t]?.has(a)) mutual += 1;
        }
        if (mutual >= minMutual || (ab && ba && minMutual <= 1)) {
          flagged.push([a, b].sort().join("|"));
        }
      }
    }
  }
  return [...new Set(flagged)].sort();
}

/**
 * Qualitative strength for public visibility (not exact score).
 * @param {number} bps
 */
export function dimensionStrength(bps) {
  const v = clampBps(bps);
  if (v >= 7500) return "exceptional";
  if (v >= 5500) return "strong";
  if (v >= 3500) return "solid";
  if (v >= 1500) return "developing";
  return "nascent";
}

/**
 * Public-facing standing — legible, not a leaderboard.
 * Exact bps withheld unless inspectBasis.
 * @param {object} opts
 * @param {StandingDimensions} opts.dimensions
 * @param {number} opts.standingBps
 * @param {string[]} opts.basis
 * @param {string} opts.trajectory
 * @param {boolean} [opts.inspectBasis]
 */
export function publicFacingStanding({
  dimensions,
  standingBps,
  basis,
  trajectory,
  inspectBasis = false,
}) {
  const dims = dimensions || {};
  const publicDimensions = Object.keys(DIMENSION_LABELS)
    .sort()
    .map((key) => ({
      key,
      label: DIMENSION_LABELS[key],
      strength: dimensionStrength(dims[key]),
      ...(inspectBasis ? { bps: clampBps(dims[key]) } : {}),
    }));

  return {
    band: meritBand(standingBps),
    // Deliberately omit global rank / percentile ordering
    trajectory,
    dimensions: publicDimensions,
    basis: (basis || []).slice().sort(),
    exactStandingBps: inspectBasis ? clampBps(standingBps) : null,
    exactStandingPercent: inspectBasis ? meritPercent(standingBps) : null,
    note: "The Living Log contribution remains the final authority — not this standing.",
  };
}

/**
 * Build full standing record for a passport + graph.
 * @param {import('./merit.js').IdentityPassport} passport
 * @param {ContributionEdge[]} edges
 * @param {import('./merit.js').IdentityPassport[]} allPassports
 * @param {Partial<StandingDimensions>} [dimOverrides]
 */
export function buildStandingRecord(
  passport,
  edges,
  allPassports,
  dimOverrides = {},
) {
  const baseDims = dimensionsFromMerit(passport.merit, dimOverrides);
  const standingById = {};
  for (const p of allPassports || []) {
    standingById[p.id] = p.meritBps;
  }
  const boost = contributionGraphBoostBps(passport.id, edges, standingById);
  const dims = applyGraphBoost(baseDims, boost);
  const standingBps = composeStandingBps(dims);
  // Also keep legacy compose for continuity checks
  const legacyBps = composeMeritBps(passport.merit);
  const early = Math.max(0, standingBps - (passport.mindChangedCount || 0) * 200);
  const trajectory = trajectoryLabel(
    passport.mindChangedCount,
    early,
    standingBps,
  );

  const basis = [
    `Log / evidence signals (legacy logRefs ${meritPercent(passport.merit.logRefsBps)})`,
    `Adversarial & contest signals`,
    `Peer recognition (weighted; secondary social capped)`,
    `Contribution-graph inbound: +${meritPercent(boost.logPersistenceBoostBps)} persistence / +${meritPercent(boost.adversarialPressureBps)} pressure`,
    `Mind-changed under pressure: ${passport.mindChangedCount || 0}`,
    `Fast engagement signals: weight ${fastSignalWeightBps()}`,
    `Accountability bound: ${passport.accountabilityBound ? "yes" : "no (Architect band blocked)"}`,
  ];

  let finalStanding = standingBps;
  // Pure anonymity / unbound cannot hold Architect band
  if (!passport.accountabilityBound && finalStanding >= 7500) {
    finalStanding = 7499;
  }

  return {
    passportId: passport.id,
    dimensions: dims,
    standingBps: finalStanding,
    legacyMeritBps: legacyBps,
    trajectory,
    boost,
    public: publicFacingStanding({
      dimensions: dims,
      standingBps: finalStanding,
      basis,
      trajectory,
      inspectBasis: false,
    }),
    inspect: publicFacingStanding({
      dimensions: dims,
      standingBps: finalStanding,
      basis,
      trajectory,
      inspectBasis: true,
    }),
  };
}

/**
 * Context-sensitive weighting: pick a primary dimension for a task.
 * @param {'evidence_review'|'adversarial_debate'|'synthesis_task'|'general'} context
 */
export function contextPrimaryDimension(context) {
  switch (context) {
    case "evidence_review":
      return "evidence";
    case "adversarial_debate":
      return "adversarial";
    case "synthesis_task":
      return "synthesis";
    default:
      return "judgment";
  }
}

/**
 * Sort collaborators for a context without exposing a global popularity board.
 * @param {ReturnType<typeof buildStandingRecord>[]} records
 * @param {'evidence_review'|'adversarial_debate'|'synthesis_task'|'general'} context
 * @param {number} [limit]
 */
export function collaboratorsForContext(records, context, limit = 5) {
  const key = contextPrimaryDimension(context);
  return records
    .slice()
    .sort(
      (a, b) =>
        b.dimensions[key] - a.dimensions[key] ||
        b.standingBps - a.standingBps ||
        a.passportId.localeCompare(b.passportId),
    )
    .slice(0, limit);
}
