import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildSeedCampaign } from "./campaign-data.js";
import {
  campaignHeatMap,
  clampBps,
  computeHeatBps,
  createForkBranch,
  emergingContestedTerritories,
  heatLabel,
  heatPercent,
  hottestScenes,
  markCriticalNode,
  mostBranchedScenes,
  orderedScenes,
  productLeadingMetrics,
  reviseTag,
  scenePhaseAt,
  truncatePath,
} from "./filmstrip.js";

describe("filmstrip heat", () => {
  it("clamps basis points", () => {
    assert.equal(clampBps(-1), 0);
    assert.equal(clampBps(10001), 10000);
    assert.equal(clampBps(4321.9), 4321);
  });

  it("computeHeatBps is deterministic and integer", () => {
    const a = computeHeatBps({
      viewThroughBps: 8000,
      rewatchBps: 4000,
      branchDepthCount: 2,
      forkCount: 1,
      exploreSeconds: 200,
      crossRefs: 2,
      highMeritSignals: 1,
    });
    const b = computeHeatBps({
      viewThroughBps: 8000,
      rewatchBps: 4000,
      branchDepthCount: 2,
      forkCount: 1,
      exploreSeconds: 200,
      crossRefs: 2,
      highMeritSignals: 1,
    });
    assert.equal(a, b);
    assert.equal(a, Math.floor(a));
    assert.ok(a > 0 && a <= 10000);
  });

  it("heatLabel thresholds", () => {
    assert.equal(heatLabel(8000), "Critical");
    assert.equal(heatLabel(6000), "Hot");
    assert.equal(heatLabel(4000), "Warm");
    assert.equal(heatLabel(2000), "Cool");
    assert.equal(heatLabel(100), "Cold");
    assert.equal(heatPercent(7500), 75);
  });
});

describe("seed campaign recursion", () => {
  it("root strip orders scenes and exposes branches", () => {
    const { strips, scenes, rootId } = buildSeedCampaign();
    const rail = orderedScenes(strips, scenes, rootId);
    assert.equal(rail.length, 8);
    assert.ok(scenes.s03.branchFilmstripIds.includes("strip-evidence-s03"));
    const evidence = orderedScenes(strips, scenes, "strip-evidence-s03");
    assert.equal(evidence.length, 4);
    assert.ok(scenes.e02.branchFilmstripIds.includes("strip-deep-e02"));
  });

  it("hottestScenes sorts by heat then id", () => {
    const { scenes } = buildSeedCampaign();
    const hot = hottestScenes(scenes, 3);
    assert.equal(hot.length, 3);
    assert.ok(hot[0].heatBps >= hot[1].heatBps);
    assert.ok(mostBranchedScenes(scenes, 2)[0].branchFilmstripIds.length > 0);
  });
});

describe("fork branch atomization", () => {
  it("creates three scenes under a fork strip", () => {
    const { scenes } = buildSeedCampaign();
    const parent = scenes.s03;
    const fork = createForkBranch({
      parentScene: parent,
      challenge: "Demand the missing receipt.",
      mode: "ai",
      salt: "t1",
    });
    assert.equal(fork.strip.kind, "fork");
    assert.equal(fork.scenes.length, 3);
    assert.equal(fork.strip.parentSceneId, parent.id);
    assert.equal(fork.scenes[0].move, "fork");
  });
});

describe("scene phases and path", () => {
  it("scenePhaseAt respects open/core/close windows", () => {
    assert.equal(scenePhaseAt(2, 60), "open");
    assert.equal(scenePhaseAt(30, 60), "core");
    assert.equal(scenePhaseAt(58, 60), "close");
  });

  it("truncatePath keeps ancestry", () => {
    const path = [
      { filmstripId: "a", sceneId: "1", title: "A" },
      { filmstripId: "b", sceneId: "2", title: "B" },
      { filmstripId: "c", sceneId: "3", title: "C" },
    ];
    assert.equal(truncatePath(path, 1).length, 2);
    assert.equal(truncatePath(path, 1)[1].filmstripId, "b");
  });
});

describe("PRD completeness helpers", () => {
  it("emergingContestedTerritories and campaignHeatMap", () => {
    const { strips, scenes } = buildSeedCampaign();
    const territories = emergingContestedTerritories(scenes, 4);
    assert.ok(territories.length > 0);
    assert.ok(territories[0].domain);
    const map = campaignHeatMap(strips, scenes);
    assert.ok(map.some((r) => r.kind === "root"));
    assert.ok(map[0].heatBps >= map[map.length - 1].heatBps);
  });

  it("markCriticalNode and reviseTag are deterministic", () => {
    const { scenes } = buildSeedCampaign();
    const base = scenes.s03;
    const a = markCriticalNode(base);
    const b = markCriticalNode(base);
    assert.equal(a.criticalNode, true);
    assert.equal(a.heatBps, b.heatBps);
    const strengthened = reviseTag(base, "strengthen", "epistemic");
    const challenged = reviseTag(base, "challenge", "epistemic");
    assert.notEqual(strengthened.tags.epistemic, challenged.tags.epistemic);
    assert.equal(strengthened.tagRevisions.length, 1);
  });

  it("productLeadingMetrics uses integer bps", () => {
    const { scenes } = buildSeedCampaign();
    const m = productLeadingMetrics(scenes, {
      depthVisits: 3,
      linearWatches: 7,
      forksOpened: 2,
    });
    assert.equal(m.recursiveDepthBps, 3000);
    assert.equal(m.recursiveDepthBps, Math.floor(m.recursiveDepthBps));
    assert.ok(m.sceneCount >= 8);
  });
});
