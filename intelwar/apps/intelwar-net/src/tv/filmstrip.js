/**
 * Recursive filmstrip model for intelwar.tv (adjacent experiential layer).
 * Living Log remains the permanent provenance-backed record.
 * Heat and merit use integer basis points (0–10000) — no floats.
 */

/** @typedef {'assertion'|'rebuttal'|'evidence'|'reframe'|'synthesis'|'concession'|'fork'} ArgumentMove */
/** @typedef {'well_supported'|'contested'|'speculative'|'emerging'} EpistemicStatus */

/**
 * @typedef {object} SceneTags
 * @property {string[]} claims
 * @property {string[]} entities
 * @property {ArgumentMove} function
 * @property {EpistemicStatus} epistemic
 * @property {string} temperature
 * @property {string[]} domains
 */

/**
 * @typedef {object} Scene
 * @property {string} id
 * @property {string} filmstripId
 * @property {string} title
 * @property {ArgumentMove} move
 * @property {number} durationSec
 * @property {string} openHook
 * @property {string} core
 * @property {string} closeHook
 * @property {number} heatBps heat in basis points 0–10000
 * @property {number} viewThroughBps
 * @property {number} rewatchBps
 * @property {number} branchDepthCount
 * @property {number} forkCount
 * @property {number} exploreSeconds
 * @property {number} crossRefs
 * @property {number} highMeritSignals
 * @property {SceneTags} tags
 * @property {string[]} branchFilmstripIds
 * @property {string|null} parentSceneId
 * @property {boolean} logBound
 * @property {number} meritBps
 * @property {string} [speaker]
 * @property {boolean} [criticalNode]
 * @property {Array<{ action: string, dimension: string, atLabel: string }>} [tagRevisions]
 */

/**
 * @typedef {object} Filmstrip
 * @property {string} id
 * @property {string} title
 * @property {string} campaign
 * @property {'root'|'branch'|'fork'} kind
 * @property {string|null} parentSceneId
 * @property {string[]} sceneIds
 * @property {'async'|'live'} mode
 */

/**
 * Compute composite Heat (basis points) from engagement signals.
 * Weights are integers summing to 100.
 */
export function computeHeatBps(signals) {
  const s = signals || {};
  const view = clampBps(s.viewThroughBps);
  const rewatch = clampBps(s.rewatchBps);
  const depth = clampBps((Number(s.branchDepthCount) || 0) * 800);
  const forks = clampBps((Number(s.forkCount) || 0) * 1200);
  const explore = clampBps(Math.min(10000, (Number(s.exploreSeconds) || 0) * 15));
  const xref = clampBps((Number(s.crossRefs) || 0) * 900);
  const merit = clampBps((Number(s.highMeritSignals) || 0) * 1500);

  // weights: view 20, rewatch 15, depth 15, forks 20, explore 10, xref 10, merit 10
  const weighted =
    view * 20 +
    rewatch * 15 +
    depth * 15 +
    forks * 20 +
    explore * 10 +
    xref * 10 +
    merit * 10;
  return clampBps(Math.floor(weighted / 100));
}

export function clampBps(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return 0;
  if (v < 0) return 0;
  if (v > 10000) return 10000;
  return Math.floor(v);
}

export function heatLabel(bps) {
  const h = clampBps(bps);
  if (h >= 7500) return "Critical";
  if (h >= 5500) return "Hot";
  if (h >= 3500) return "Warm";
  if (h >= 1500) return "Cool";
  return "Cold";
}

export function heatPercent(bps) {
  return Math.floor(clampBps(bps) / 100);
}

/**
 * @param {Record<string, Filmstrip>} strips
 * @param {Record<string, Scene>} scenes
 * @param {string} filmstripId
 */
export function orderedScenes(strips, scenes, filmstripId) {
  const strip = strips[filmstripId];
  if (!strip) return [];
  return strip.sceneIds.map((id) => scenes[id]).filter(Boolean);
}

/**
 * @param {Record<string, Scene>} scenes
 * @param {number} [limit]
 */
export function hottestScenes(scenes, limit = 6) {
  return Object.values(scenes)
    .slice()
    .sort((a, b) => b.heatBps - a.heatBps || a.id.localeCompare(b.id))
    .slice(0, limit);
}

/**
 * @param {Record<string, Scene>} scenes
 */
export function mostBranchedScenes(scenes, limit = 4) {
  return Object.values(scenes)
    .slice()
    .sort(
      (a, b) =>
        b.branchFilmstripIds.length - a.branchFilmstripIds.length ||
        b.heatBps - a.heatBps ||
        a.id.localeCompare(b.id),
    )
    .filter((s) => s.branchFilmstripIds.length > 0)
    .slice(0, limit);
}

/**
 * @param {Record<string, Scene>} scenes
 */
export function fastestGrowingForks(scenes, limit = 4) {
  return Object.values(scenes)
    .slice()
    .filter((s) => s.move === "fork" || s.forkCount > 0)
    .sort(
      (a, b) =>
        b.forkCount - a.forkCount ||
        b.heatBps - a.heatBps ||
        a.id.localeCompare(b.id),
    )
    .slice(0, limit);
}

/**
 * Emerging contested territories across campaigns (domain × epistemic heat).
 * @param {Record<string, Scene>} scenes
 * @param {number} [limit]
 */
export function emergingContestedTerritories(scenes, limit = 6) {
  /** @type {Record<string, { domain: string, heatBps: number, contested: number, sceneIds: string[] }>} */
  const byDomain = {};
  for (const s of Object.values(scenes)) {
    const domains = s.tags?.domains?.length ? s.tags.domains : ["unscoped"];
    for (const domain of domains) {
      if (!byDomain[domain]) {
        byDomain[domain] = {
          domain,
          heatBps: 0,
          contested: 0,
          sceneIds: [],
        };
      }
      const row = byDomain[domain];
      row.heatBps = clampBps(row.heatBps + Math.floor(s.heatBps / 4));
      if (s.tags?.epistemic === "contested" || s.tags?.epistemic === "emerging") {
        row.contested += 1;
      }
      row.sceneIds.push(s.id);
    }
  }
  return Object.values(byDomain)
    .sort(
      (a, b) =>
        b.contested - a.contested ||
        b.heatBps - a.heatBps ||
        a.domain.localeCompare(b.domain),
    )
    .slice(0, limit);
}

/**
 * Campaign-level heat map rows for strategist overview.
 * @param {Record<string, Filmstrip>} strips
 * @param {Record<string, Scene>} scenes
 */
export function campaignHeatMap(strips, scenes) {
  /** @type {Array<{ id: string, title: string, kind: string, heatBps: number, sceneCount: number, branchCount: number, forkCount: number, criticalCount: number }>} */
  const rows = [];
  for (const strip of Object.values(strips)) {
    const stripScenes = orderedScenes(strips, scenes, strip.id);
    if (stripScenes.length === 0) continue;
    let heatSum = 0;
    let forkCount = 0;
    let branchCount = 0;
    let criticalCount = 0;
    for (const s of stripScenes) {
      heatSum += s.heatBps;
      forkCount += s.forkCount || 0;
      branchCount += s.branchFilmstripIds.length;
      if (s.criticalNode) criticalCount += 1;
    }
    rows.push({
      id: strip.id,
      title: strip.title,
      kind: strip.kind,
      heatBps: clampBps(Math.floor(heatSum / stripScenes.length)),
      sceneCount: stripScenes.length,
      branchCount,
      forkCount,
      criticalCount,
    });
  }
  return rows.sort(
    (a, b) =>
      b.heatBps - a.heatBps ||
      b.sceneCount - a.sceneCount ||
      a.id.localeCompare(b.id),
  );
}

/**
 * Mark a scene as a critical node (high-0dentity explicit signal).
 * @param {Scene} scene
 */
export function markCriticalNode(scene) {
  const next = {
    ...scene,
    criticalNode: true,
    highMeritSignals: (scene.highMeritSignals || 0) + 1,
  };
  next.heatBps = computeHeatBps(next);
  next.meritBps = clampBps((scene.meritBps || 0) + 800);
  return next;
}

/**
 * Strengthen or challenge an autotag. Deterministic revise of epistemic/temperature.
 * @param {Scene} scene
 * @param {'strengthen'|'challenge'} action
 * @param {'epistemic'|'temperature'|'claim'} dimension
 */
export function reviseTag(scene, action, dimension) {
  const tags = {
    ...scene.tags,
    claims: [...(scene.tags.claims || [])],
    entities: [...(scene.tags.entities || [])],
    domains: [...(scene.tags.domains || [])],
  };
  const revisions = [...(scene.tagRevisions || [])];

  if (dimension === "epistemic") {
    if (action === "strengthen") {
      tags.epistemic =
        tags.epistemic === "speculative"
          ? "emerging"
          : tags.epistemic === "emerging"
            ? "contested"
            : tags.epistemic === "contested"
              ? "well_supported"
              : "well_supported";
    } else {
      tags.epistemic =
        tags.epistemic === "well_supported"
          ? "contested"
          : tags.epistemic === "contested"
            ? "emerging"
            : tags.epistemic === "emerging"
              ? "speculative"
              : "speculative";
    }
  } else if (dimension === "temperature") {
    tags.temperature =
      action === "strengthen" ? "analytical" : "confrontational";
  } else if (dimension === "claim") {
    const note =
      action === "strengthen"
        ? "Claim reinforced by high-merit review"
        : "Claim contested by high-merit review";
    if (!tags.claims.includes(note)) tags.claims = [...tags.claims, note];
  }

  revisions.push({
    action,
    dimension,
    atLabel: "0dentity review",
  });

  return {
    ...scene,
    tags,
    tagRevisions: revisions,
    meritBps: clampBps(
      (scene.meritBps || 0) + (action === "strengthen" ? 200 : 150),
    ),
  };
}

/**
 * Product-level leading indicators from current graph (demo metrics).
 * @param {Record<string, Scene>} scenes
 * @param {{ depthVisits: number, linearWatches: number, forksOpened: number }} engagement
 */
export function productLeadingMetrics(scenes, engagement) {
  const list = Object.values(scenes);
  const n = Math.max(1, list.length);
  const depth = Number(engagement?.depthVisits) || 0;
  const linear = Number(engagement?.linearWatches) || 0;
  const totalNav = Math.max(1, depth + linear);
  const recursivePct = Math.floor((depth * 10000) / totalNav); // bps of nav that went deep
  const forksOpened = Number(engagement?.forksOpened) || 0;
  const heats = list.map((s) => s.heatBps).sort((a, b) => a - b);
  const median = heats[Math.floor(heats.length / 2)] || 0;
  const top = heats[heats.length - 1] || 0;
  const distributionSpread = clampBps(top - median);
  const highMerit = list.filter((s) => (s.meritBps || 0) >= 5000).length;
  const heatMeritAligned = list.filter(
    (s) => s.heatBps >= 7000 && (s.meritBps || 0) >= 4500,
  ).length;

  return {
    recursiveDepthBps: clampBps(recursivePct),
    forksPerDebateBps: clampBps(Math.floor((forksOpened * 10000) / n)),
    heatDistributionSpreadBps: distributionSpread,
    heatMeritCorrelationCount: heatMeritAligned,
    highMeritSceneCount: highMerit,
    sceneCount: n,
  };
}

/**
 * Path stack for recursive orientation.
 * @typedef {{ filmstripId: string, sceneId: string|null, title: string }} PathFrame
 */

/**
 * @param {PathFrame[]} path
 * @param {Filmstrip} strip
 * @param {Scene|null} scene
 */
export function pushPath(path, strip, scene) {
  return [
    ...path,
    {
      filmstripId: strip.id,
      sceneId: scene ? scene.id : null,
      title: scene ? scene.title : strip.title,
    },
  ];
}

/**
 * @param {PathFrame[]} path
 * @param {number} index
 */
export function truncatePath(path, index) {
  if (index < 0) return path.slice(0, 1);
  return path.slice(0, index + 1);
}

/**
 * Atomize a fork exchange into child scenes attached under a parent.
 * Deterministic IDs from parent + salt for demo stability when salt provided.
 */
export function createForkBranch({
  parentScene,
  challenge,
  mode,
  salt = "demo",
  nextId,
}) {
  const base = nextId || `fork-${parentScene.id}-${salt}`;
  const stripId = `${base}-strip`;
  const challengeId = `${base}-c`;
  const replyId = `${base}-r`;
  const synthId = `${base}-s`;

  /** @type {Filmstrip} */
  const strip = {
    id: stripId,
    title: `Fork · ${parentScene.title}`,
    campaign: "In-situ fork",
    kind: "fork",
    parentSceneId: parentScene.id,
    sceneIds: [challengeId, replyId, synthId],
    mode: "async",
  };

  const challengeScene = makeScene({
    id: challengeId,
    filmstripId: stripId,
    title: "Challenge",
    move: "fork",
    durationSec: 48,
    openHook: "A fork opens on the claim.",
    core: challenge || "Direct challenge entered from the filmstrip.",
    closeHook: mode === "ai" ? "AI adversarial reply loading…" : "Counter loading…",
    parentSceneId: parentScene.id,
    tags: {
      claims: parentScene.tags.claims.slice(0, 1),
      entities: parentScene.tags.entities.slice(0, 2),
      function: "fork",
      epistemic: "contested",
      temperature: "confrontational",
      domains: parentScene.tags.domains,
    },
    heatBps: 3200,
    forkCount: 0,
    meritBps: 1800,
  });

  const replyScene = makeScene({
    id: replyId,
    filmstripId: stripId,
    title: mode === "ai" ? "Adversarial analysis" : "Micro-debate reply",
    move: "rebuttal",
    durationSec: 62,
    openHook: "Pressure applied to the weakest premise.",
    core:
      mode === "ai"
        ? "AI adversarial analysis isolates unstated assumptions and requests evidence under Log rules."
        : "Structured micro-debate reply contests the move without flooding the zone.",
    closeHook: "Synthesis available — or escalate to the Living Log.",
    parentSceneId: parentScene.id,
    tags: {
      claims: parentScene.tags.claims.slice(0, 1),
      entities: ["CrossCheck", ...parentScene.tags.entities.slice(0, 1)],
      function: "rebuttal",
      epistemic: "contested",
      temperature: "analytical",
      domains: parentScene.tags.domains,
    },
    heatBps: 4100,
    meritBps: 2400,
  });

  const synthScene = makeScene({
    id: synthId,
    filmstripId: stripId,
    title: "Provisional synthesis",
    move: "synthesis",
    durationSec: 55,
    openHook: "What survives so far.",
    core: "Fork atomized into three scenes. High-quality forks may bind into the permanent Record under consent.",
    closeHook: "Return to parent — or go deeper again.",
    parentSceneId: parentScene.id,
    tags: {
      claims: ["Fork integrity"],
      entities: ["Living Log", "0dentity"],
      function: "synthesis",
      epistemic: "emerging",
      temperature: "synthetic",
      domains: ["merit", "record"],
    },
    heatBps: 2800,
    logBound: false,
    meritBps: 3000,
  });

  return {
    strip,
    scenes: [challengeScene, replyScene, synthScene],
    entrySceneId: challengeId,
  };
}

/**
 * @param {Partial<Scene> & { id: string, filmstripId: string, title: string, move: ArgumentMove, openHook: string, core: string, closeHook: string }} partial
 * @returns {Scene}
 */
export function makeScene(partial) {
  const signals = {
    viewThroughBps: partial.viewThroughBps ?? 5000,
    rewatchBps: partial.rewatchBps ?? 2000,
    branchDepthCount: partial.branchDepthCount ?? 0,
    forkCount: partial.forkCount ?? 0,
    exploreSeconds: partial.exploreSeconds ?? 120,
    crossRefs: partial.crossRefs ?? 0,
    highMeritSignals: partial.highMeritSignals ?? 0,
  };
  const heatBps =
    partial.heatBps != null ? clampBps(partial.heatBps) : computeHeatBps(signals);

  return {
    id: partial.id,
    filmstripId: partial.filmstripId,
    title: partial.title,
    move: partial.move,
    durationSec: partial.durationSec ?? 60,
    openHook: partial.openHook,
    core: partial.core,
    closeHook: partial.closeHook,
    heatBps,
    viewThroughBps: signals.viewThroughBps,
    rewatchBps: signals.rewatchBps,
    branchDepthCount: signals.branchDepthCount,
    forkCount: signals.forkCount,
    exploreSeconds: signals.exploreSeconds,
    crossRefs: signals.crossRefs,
    highMeritSignals: signals.highMeritSignals,
    tags: partial.tags || {
      claims: [],
      entities: [],
      function: partial.move,
      epistemic: "contested",
      temperature: "analytical",
      domains: [],
    },
    branchFilmstripIds: partial.branchFilmstripIds || [],
    parentSceneId: partial.parentSceneId ?? null,
    logBound: Boolean(partial.logBound),
    meritBps: clampBps(partial.meritBps ?? 0),
    speaker: partial.speaker || "Arena",
    criticalNode: Boolean(partial.criticalNode),
    tagRevisions: partial.tagRevisions || [],
  };
}

export function scenePhaseAt(elapsedSec, durationSec) {
  const d = Math.max(1, Number(durationSec) || 60);
  const t = Math.max(0, Number(elapsedSec) || 0);
  const openEnd = Math.min(8, Math.max(3, Math.floor(d * 0.12)));
  const closeStart = Math.max(openEnd + 1, d - Math.min(8, Math.max(3, Math.floor(d * 0.12))));
  if (t < openEnd) return "open";
  if (t >= closeStart) return "close";
  return "core";
}
