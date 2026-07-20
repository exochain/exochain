import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  activeCoalitions,
  canViewTier,
  composeMeritBps,
  discoverByMerit,
  dissolveCoalition,
  filterNotices,
  joinCoalition,
  makePassport,
  meritBand,
  peerRecognitionValid,
} from "./merit.js";
import { buildSocialSeed } from "./social-data.js";

describe("composeMeritBps", () => {
  it("hard-caps social secondary so performers stay low band", () => {
    const performer = composeMeritBps({
      logRefsBps: 400,
      contestBps: 600,
      adversarialBps: 300,
      peerMeritBps: 200,
      socialSecondaryBps: 9200,
    });
    const chronicler = composeMeritBps({
      logRefsBps: 8200,
      contestBps: 5400,
      adversarialBps: 6100,
      peerMeritBps: 7000,
      socialSecondaryBps: 900,
    });
    assert.ok(performer < 2000);
    assert.equal(meritBand(performer), "Observer");
    assert.ok(chronicler > performer);
    assert.ok(["Proven", "Architect"].includes(meritBand(chronicler)));
  });

  it("is deterministic", () => {
    const b = {
      logRefsBps: 5000,
      contestBps: 5000,
      adversarialBps: 5000,
      peerMeritBps: 5000,
      socialSecondaryBps: 5000,
    };
    assert.equal(composeMeritBps(b), composeMeritBps(b));
  });
});

describe("coalitions", () => {
  it("activeCoalitions excludes dissolved", () => {
    const { coalitions } = buildSocialSeed();
    const live = activeCoalitions(coalitions);
    assert.ok(live.every((c) => c.status !== "dissolved"));
    assert.ok(coalitions.some((c) => c.status === "dissolved"));
  });

  it("join and dissolve", () => {
    const { coalitions } = buildSocialSeed();
    const c = coalitions.find((x) => x.id === "coal-alignment");
    const joined = joinCoalition(c, "p-observer");
    assert.ok(joined.memberIds.includes("p-observer"));
    const dead = dissolveCoalition(joined, 99);
    assert.equal(dead.status, "dissolved");
    assert.equal(dead.memberIds.length, 0);
    assert.equal(joinCoalition(dead, "p-observer").memberIds.length, 0);
  });
});

describe("context and notices", () => {
  it("exploratory hidden from public", () => {
    assert.equal(canViewTier("exploratory", "public"), false);
    assert.equal(canViewTier("exploratory", "self"), true);
    assert.equal(canViewTier("public_contest", "public"), true);
  });

  it("filterNotices drops public non-actionable exploratory", () => {
    const { notices } = buildSocialSeed();
    const pub = filterNotices(notices, "public");
    assert.ok(pub.every((n) => n.actionable));
    assert.ok(!pub.some((n) => n.tier === "exploratory"));
    const self = filterNotices(notices, "self");
    assert.ok(self.length >= pub.length);
  });
});

describe("discovery and peer recognition", () => {
  it("discoverByMerit ranks high-merit first", () => {
    const { passports } = buildSocialSeed();
    const ranked = discoverByMerit(passports, [], 3);
    assert.ok(ranked[0].scoreBps >= ranked[1].scoreBps);
    assert.notEqual(ranked[0].passport.handle, "signalnoise");
  });

  it("peerRecognitionValid thresholds", () => {
    assert.equal(peerRecognitionValid(4000), true);
    assert.equal(peerRecognitionValid(1000), false);
  });

  it("makePassport composes meritBps", () => {
    const p = makePassport({
      id: "x",
      handle: "x",
      displayName: "X",
      stance: "test",
      merit: {
        logRefsBps: 1000,
        contestBps: 1000,
        adversarialBps: 1000,
        peerMeritBps: 1000,
        socialSecondaryBps: 1000,
      },
      accountabilityBound: true,
    });
    assert.equal(p.meritBps, composeMeritBps(p.merit));
  });
});
