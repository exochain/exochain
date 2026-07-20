import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildSocialSeed } from "./social-data.js";
import {
  buildStandingRecord,
  canStake,
  collaboratorsForContext,
  composeStandingBps,
  contributionGraphBoostBps,
  detectEndorsementRing,
  dimensionsFromMerit,
  fastSignalWeightBps,
  publicFacingStanding,
  resolveStake,
  stakeRateAllowed,
  trajectoryLabel,
} from "./reputation.js";

describe("standing composition", () => {
  it("fast signals have zero weight", () => {
    assert.equal(fastSignalWeightBps(), 0);
  });

  it("composeStandingBps is deterministic and bounded", () => {
    const dims = {
      evidence: 8000,
      adversarial: 7000,
      crosscheck: 6000,
      synthesis: 5000,
      judgment: 6500,
    };
    assert.equal(composeStandingBps(dims), composeStandingBps(dims));
    assert.ok(composeStandingBps(dims) <= 10000);
  });

  it("performer cannot dominate via social secondary in dimensions", () => {
    const { passports } = buildSocialSeed();
    const performer = passports.find((p) => p.handle === "signalnoise");
    const chronicler = passports.find((p) => p.handle === "chronicler");
    const pd = dimensionsFromMerit(performer.merit);
    const cd = dimensionsFromMerit(chronicler.merit);
    assert.ok(composeStandingBps(cd) > composeStandingBps(pd));
  });
});

describe("contribution graph and trajectory", () => {
  it("inbound builds_on from high standing boosts persistence", () => {
    const boost = contributionGraphBoostBps(
      "p-chronicler",
      [
        {
          id: "x",
          fromId: "p-adversary",
          toId: "p-chronicler",
          kind: "builds_on",
          weightBps: 8000,
          ordinal: 1,
        },
      ],
      { "p-adversary": 7000 },
    );
    assert.ok(boost.logPersistenceBoostBps > 0);
  });

  it("trajectory labels updates", () => {
    assert.equal(trajectoryLabel(4, 4000, 5500), "ascending");
    assert.equal(trajectoryLabel(0, 5000, 4000), "declining");
    assert.equal(trajectoryLabel(3, 5000, 5100), "updating");
  });
});

describe("stake and anti-gaming", () => {
  it("canStake enforces band and budget", () => {
    assert.equal(canStake(4000, 300, 0), true);
    assert.equal(canStake(2000, 300, 0), false);
    assert.equal(canStake(4000, 50, 0), false);
    assert.equal(canStake(4000, 500, 1800), false);
  });

  it("failed stake burns staker", () => {
    const r = resolveStake(
      {
        id: "s",
        stakerId: "a",
        targetId: "b",
        kind: "endorse",
        stakeBps: 400,
        status: "open",
        ordinal: 1,
      },
      "resolved_failed",
    );
    assert.equal(r.stakerDeltaBps, -400);
    assert.equal(r.targetDeltaBps, 0);
  });

  it("rate limit and ring detection", () => {
    const stakes = [
      { id: "1", stakerId: "a", targetId: "b", kind: "endorse", stakeBps: 100, status: "open", ordinal: 8 },
      { id: "2", stakerId: "a", targetId: "c", kind: "endorse", stakeBps: 100, status: "open", ordinal: 9 },
      { id: "3", stakerId: "a", targetId: "d", kind: "endorse", stakeBps: 100, status: "open", ordinal: 10 },
    ];
    assert.equal(stakeRateAllowed(stakes, 11, 5, 3), false);
    const ring = detectEndorsementRing(
      [
        { id: "1", stakerId: "a", targetId: "b", kind: "endorse", stakeBps: 100, status: "open", ordinal: 1 },
        { id: "2", stakerId: "b", targetId: "a", kind: "endorse", stakeBps: 100, status: "open", ordinal: 2 },
      ],
      1,
    );
    assert.ok(ring.includes("a|b"));
  });
});

describe("visibility and standing records", () => {
  it("public facing omits exact scores until inspect", () => {
    const dims = {
      evidence: 8000,
      adversarial: 7000,
      crosscheck: 6000,
      synthesis: 5000,
      judgment: 6500,
    };
    const pub = publicFacingStanding({
      dimensions: dims,
      standingBps: 6800,
      basis: ["test"],
      trajectory: "stable",
      inspectBasis: false,
    });
    assert.equal(pub.exactStandingBps, null);
    assert.ok(pub.dimensions[0].strength);
    assert.equal(pub.dimensions[0].bps, undefined);

    const insp = publicFacingStanding({
      dimensions: dims,
      standingBps: 6800,
      basis: ["test"],
      trajectory: "stable",
      inspectBasis: true,
    });
    assert.equal(insp.exactStandingBps, 6800);
    assert.ok(insp.dimensions.every((d) => typeof d.bps === "number"));
  });

  it("buildStandingRecord blocks Architect for unbound", () => {
    const { passports, contributionEdges } = buildSocialSeed();
    const performer = passports.find((p) => p.handle === "signalnoise");
    const rec = buildStandingRecord(performer, contributionEdges, passports);
    assert.ok(rec.standingBps < 7500);
    assert.equal(rec.public.exactStandingBps, null);
  });

  it("collaboratorsForContext sorts by dimension", () => {
    const { passports, contributionEdges } = buildSocialSeed();
    const records = passports.map((p) =>
      buildStandingRecord(p, contributionEdges, passports),
    );
    const list = collaboratorsForContext(records, "adversarial_debate", 2);
    assert.equal(list.length, 2);
    assert.ok(
      list[0].dimensions.adversarial >= list[1].dimensions.adversarial,
    );
  });
});
