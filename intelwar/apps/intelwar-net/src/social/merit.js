/**
 * IntelWar social layer — merit & coalition model.
 * Social is downstream of arena / Log / contests.
 * All scores in integer basis points (0–10000). No engagement-primary ranking.
 */

/** @typedef {'exploratory'|'coalition'|'public_contest'|'record'} ContextTier */

/**
 * @typedef {object} MeritBreakdown
 * @property {number} logRefsBps — Log contributions still referenced
 * @property {number} contestBps — structured contest performance
 * @property {number} adversarialBps — cross-check / evidence / synthesis
 * @property {number} peerMeritBps — recognition from high-merit peers
 * @property {number} socialSecondaryBps — capped secondary social signals
 */

/**
 * @typedef {object} IdentityPassport
 * @property {string} id
 * @property {string} handle
 * @property {string} displayName
 * @property {string} stance — short principle line, not bio performance
 * @property {MeritBreakdown} merit
 * @property {number} meritBps — composite
 * @property {string[]} activeCoalitionIds
 * @property {string[]} surfacesActive — org|press|net|ai|tv
 * @property {number} mindChangedCount — social cheapness to update beliefs (positive)
 * @property {boolean} accountabilityBound — not pure anonymity
 */

/**
 * @typedef {object} Coalition
 * @property {string} id
 * @property {string} name
 * @property {string} mission
 * @property {string} campaignRef
 * @property {'forming'|'active'|'winding_down'|'dissolved'} status
 * @property {string[]} memberIds
 * @property {number} formedAtOrdinal — deterministic seed order
 * @property {number|null} dissolveAtOrdinal
 * @property {ContextTier} defaultTier
 */

/**
 * Composite merit: Log 35, contest 25, adversarial 25, peer 15, social secondary max 5.
 * Secondary is hard-capped so it cannot dominate.
 */
export function composeMeritBps(breakdown) {
  const b = breakdown || {};
  const log = clampBps(b.logRefsBps);
  const contest = clampBps(b.contestBps);
  const adversarial = clampBps(b.adversarialBps);
  const peer = clampBps(b.peerMeritBps);
  const social = Math.min(500, clampBps(b.socialSecondaryBps)); // max 5% effective

  const weighted =
    log * 35 + contest * 25 + adversarial * 25 + peer * 15 + social * 5;
  return clampBps(Math.floor(weighted / 100));
}

export function clampBps(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return 0;
  if (v < 0) return 0;
  if (v > 10000) return 10000;
  return Math.floor(v);
}

export function meritBand(bps) {
  const m = clampBps(bps);
  if (m >= 7500) return "Architect";
  if (m >= 5500) return "Proven";
  if (m >= 3500) return "Contested";
  if (m >= 1500) return "Emerging";
  return "Observer";
}

export function meritPercent(bps) {
  return Math.floor(clampBps(bps) / 100);
}

/**
 * Discovery rank: merit × relevance to query domains. No emotional velocity.
 * @param {IdentityPassport[]} passports
 * @param {string[]} [domains]
 * @param {number} [limit]
 */
export function discoverByMerit(passports, domains = [], limit = 8) {
  const domainSet = new Set(domains.map((d) => String(d).toLowerCase()));
  return passports
    .slice()
    .map((p) => {
      const relevance = domainSet.size
        ? p.surfacesActive.filter((s) => domainSet.has(s)).length * 400
        : 0;
      return {
        passport: p,
        scoreBps: clampBps(p.meritBps + relevance),
      };
    })
    .sort(
      (a, b) =>
        b.scoreBps - a.scoreBps ||
        a.passport.handle.localeCompare(b.passport.handle),
    )
    .slice(0, limit);
}

/**
 * Active coalitions only — dissolved ones excluded from association surfaces.
 * @param {Coalition[]} coalitions
 */
export function activeCoalitions(coalitions) {
  return coalitions
    .filter((c) => c.status === "forming" || c.status === "active")
    .sort(
      (a, b) =>
        a.formedAtOrdinal - b.formedAtOrdinal || a.id.localeCompare(b.id),
    );
}

/**
 * Wind down a coalition — prefer dissolve over permanent tribe.
 * @param {Coalition} coalition
 * @param {number} ordinal
 */
export function windDownCoalition(coalition, ordinal) {
  return {
    ...coalition,
    status: "winding_down",
    dissolveAtOrdinal: ordinal,
  };
}

export function dissolveCoalition(coalition, ordinal) {
  return {
    ...coalition,
    status: "dissolved",
    dissolveAtOrdinal: ordinal,
    memberIds: [],
  };
}

/**
 * Join if mission-aligned and not a permanent tribe fortress.
 * Dissolved / winding_down reject new joins.
 */
export function canJoinCoalition(coalition) {
  return coalition.status === "forming" || coalition.status === "active";
}

/**
 * @param {Coalition} coalition
 * @param {string} memberId
 */
export function joinCoalition(coalition, memberId) {
  if (!canJoinCoalition(coalition)) return coalition;
  if (coalition.memberIds.includes(memberId)) return coalition;
  return {
    ...coalition,
    memberIds: [...coalition.memberIds, memberId].sort(),
  };
}

/**
 * Graduated visibility — what may be shown in which surface.
 * @param {ContextTier} tier
 * @param {'self'|'coalition_member'|'public'|'record_reader'} viewer
 */
export function canViewTier(tier, viewer) {
  if (tier === "exploratory") {
    return viewer === "self" || viewer === "coalition_member";
  }
  if (tier === "coalition") {
    return (
      viewer === "self" ||
      viewer === "coalition_member" ||
      viewer === "record_reader"
    );
  }
  if (tier === "public_contest") return true;
  if (tier === "record") return true;
  return false;
}

/**
 * Notification philosophy: sparse + consequential.
 * @typedef {object} Notice
 * @property {string} id
 * @property {'merit'|'coalition'|'contest'|'log_bind'|'recognition'} kind
 * @property {string} summary
 * @property {ContextTier} tier
 * @property {boolean} actionable
 */

/**
 * Filter notices — drop non-actionable exploratory noise for public viewers.
 * @param {Notice[]} notices
 * @param {'self'|'coalition_member'|'public'} viewer
 */
export function filterNotices(notices, viewer) {
  return notices
    .filter((n) => {
      if (!canViewTier(n.tier, viewer === "public" ? "public" : viewer)) {
        return false;
      }
      if (viewer === "public" && !n.actionable) return false;
      return true;
    })
    .sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * Recognition from high-merit peers only counts if recognizer merit ≥ threshold.
 */
export function peerRecognitionValid(recognizerMeritBps, thresholdBps = 3500) {
  return clampBps(recognizerMeritBps) >= clampBps(thresholdBps);
}

/**
 * Build passport with composed merit.
 * @param {Omit<IdentityPassport, 'meritBps'> & { meritBps?: number }} partial
 */
export function makePassport(partial) {
  const merit = partial.merit || {
    logRefsBps: 0,
    contestBps: 0,
    adversarialBps: 0,
    peerMeritBps: 0,
    socialSecondaryBps: 0,
  };
  return {
    id: partial.id,
    handle: partial.handle,
    displayName: partial.displayName,
    stance: partial.stance,
    merit,
    meritBps: composeMeritBps(merit),
    activeCoalitionIds: partial.activeCoalitionIds || [],
    surfacesActive: partial.surfacesActive || [],
    mindChangedCount: Number(partial.mindChangedCount) || 0,
    accountabilityBound: Boolean(partial.accountabilityBound),
  };
}
