import { makePassport } from "./merit.js";

/** Seed graph for social layer demo — merit-primary, coalition-friendly. */
export function buildSocialSeed() {
  const passports = [
    makePassport({
      id: "p-chronicler",
      handle: "chronicler",
      displayName: "Chronicler",
      stance: "Nothing enters memory without consent. The Record is the defense.",
      merit: {
        logRefsBps: 8200,
        contestBps: 5400,
        adversarialBps: 6100,
        peerMeritBps: 7000,
        socialSecondaryBps: 900,
      },
      activeCoalitionIds: ["coal-provenance", "coal-press"],
      surfacesActive: ["net", "press", "org"],
      mindChangedCount: 4,
      accountabilityBound: true,
    }),
    makePassport({
      id: "p-adversary",
      handle: "crosscheck",
      displayName: "Adversary",
      stance: "Pressure the weakest premise. Survive scrutiny or revise.",
      merit: {
        logRefsBps: 4800,
        contestBps: 7800,
        adversarialBps: 8800,
        peerMeritBps: 6500,
        socialSecondaryBps: 400,
      },
      activeCoalitionIds: ["coal-provenance", "coal-alignment"],
      surfacesActive: ["ai", "tv", "net"],
      mindChangedCount: 7,
      accountabilityBound: true,
    }),
    makePassport({
      id: "p-strategist",
      handle: "strategist",
      displayName: "Strategist",
      stance: "Campaigns over tribes. Dissolve when the mission ends.",
      merit: {
        logRefsBps: 5600,
        contestBps: 7200,
        adversarialBps: 5000,
        peerMeritBps: 5800,
        socialSecondaryBps: 1200,
      },
      activeCoalitionIds: ["coal-press", "coal-alignment"],
      surfacesActive: ["press", "org", "tv"],
      mindChangedCount: 3,
      accountabilityBound: true,
    }),
    makePassport({
      id: "p-observer",
      handle: "analyst",
      displayName: "Analyst",
      stance: "Study the terrain before engaging. Recognition follows rigor.",
      merit: {
        logRefsBps: 2200,
        contestBps: 1800,
        adversarialBps: 3100,
        peerMeritBps: 2400,
        socialSecondaryBps: 800,
      },
      activeCoalitionIds: ["coal-provenance"],
      surfacesActive: ["tv", "org"],
      mindChangedCount: 2,
      accountabilityBound: true,
    }),
    makePassport({
      id: "p-performer",
      handle: "signalnoise",
      displayName: "Signalnoise",
      stance: "High reactivity · low Log density (illustrative anti-pattern).",
      merit: {
        logRefsBps: 400,
        contestBps: 600,
        adversarialBps: 300,
        peerMeritBps: 200,
        socialSecondaryBps: 9200,
      },
      activeCoalitionIds: [],
      surfacesActive: ["press"],
      mindChangedCount: 0,
      accountabilityBound: false,
    }),
  ];

  const coalitions = [
    {
      id: "coal-provenance",
      name: "Provenance Guard",
      mission:
        "Defend receipt integrity and Log binding for synthetic-reality contests.",
      campaignRef: "Synthetic Reality vs Provenance",
      status: "active",
      memberIds: ["p-chronicler", "p-adversary", "p-observer"],
      formedAtOrdinal: 1,
      dissolveAtOrdinal: null,
      defaultTier: "coalition",
    },
    {
      id: "coal-press",
      name: "Fourth Estate Working Group",
      mission:
        "Publish dispatches and contests under First Amendment posture — free, rigorous, permanent.",
      campaignRef: "Institutional Trust Collapse",
      status: "active",
      memberIds: ["p-chronicler", "p-strategist"],
      formedAtOrdinal: 2,
      dissolveAtOrdinal: null,
      defaultTier: "public_contest",
    },
    {
      id: "coal-alignment",
      name: "Multi-Intelligence Rules",
      mission:
        "Declare synthetic voice; keep human override; refuse unattested fusion.",
      campaignRef: "Multi-Intelligence Alignment",
      status: "forming",
      memberIds: ["p-adversary", "p-strategist"],
      formedAtOrdinal: 3,
      dissolveAtOrdinal: null,
      defaultTier: "exploratory",
    },
    {
      id: "coal-spent",
      name: "Archive · Spent Mission",
      mission: "Example dissolved coalition — mission ended; not a tribe fortress.",
      campaignRef: "Memory Without Compounding",
      status: "dissolved",
      memberIds: [],
      formedAtOrdinal: 0,
      dissolveAtOrdinal: 10,
      defaultTier: "coalition",
    },
  ];

  /** High-signal discovery items — chronological/structural, not engagement feed */
  const discovery = [
    {
      id: "d1",
      kind: "log_ref",
      title: "Consent before memory — still referenced",
      by: "p-chronicler",
      tier: "record",
      domains: ["net", "press"],
      ordinal: 1,
    },
    {
      id: "d2",
      kind: "contest",
      title: "Open contest · Corporate Fourth Estate abandonment",
      by: "p-strategist",
      tier: "public_contest",
      domains: ["press"],
      ordinal: 2,
    },
    {
      id: "d3",
      kind: "filmstrip",
      title: "Critical node · Receipts as weapons",
      by: "p-adversary",
      tier: "public_contest",
      domains: ["tv", "ai"],
      ordinal: 3,
    },
    {
      id: "d4",
      kind: "recognition",
      title: "Peer recognition · adversarial synthesis survived scrutiny",
      by: "p-chronicler",
      about: "p-adversary",
      tier: "coalition",
      domains: ["ai", "net"],
      ordinal: 4,
    },
    {
      id: "d5",
      kind: "coalition",
      title: "Coalition forming · Multi-Intelligence Rules",
      by: "p-strategist",
      tier: "exploratory",
      domains: ["org", "ai"],
      ordinal: 5,
    },
  ];

  const notices = [
    {
      id: "n1",
      kind: "log_bind",
      summary: "Your Scene was proposed for Living Log bind — consent required.",
      tier: "record",
      actionable: true,
    },
    {
      id: "n2",
      kind: "recognition",
      summary: "High-merit peer recognized your CrossCheck on receipt failure modes.",
      tier: "coalition",
      actionable: false,
    },
    {
      id: "n3",
      kind: "coalition",
      summary: "Provenance Guard: mission checkpoint in 2 contest rounds.",
      tier: "coalition",
      actionable: true,
    },
    {
      id: "n4",
      kind: "contest",
      summary: "New public contest opened on your tracked campaign.",
      tier: "public_contest",
      actionable: true,
    },
    {
      id: "n5",
      kind: "merit",
      summary: "Exploratory draft reply from a low-context visitor.",
      tier: "exploratory",
      actionable: false,
    },
  ];

  const principles = [
    {
      id: "p1",
      title: "Merit before visibility",
      body: "Reach follows Log contribution, contest survival, and adversarial rigor — not raw engagement.",
    },
    {
      id: "p2",
      title: "Context is scarce",
      body: "Exploratory, coalition, public contest, and Record are separated. Collapsing them recreates feed failure modes.",
    },
    {
      id: "p3",
      title: "Coalitions over tribes",
      body: "Mission-aligned, dissolvable groups. Permanent identity fortresses are structurally discouraged.",
    },
    {
      id: "p4",
      title: "Status hard to fake",
      body: "0dentity bands are legible. Social secondary signals are hard-capped so performers cannot buy Architect status.",
    },
    {
      id: "p5",
      title: "Social is downstream",
      body: "The layer serves the arena, the Log, and the contests — never the reverse.",
    },
    {
      id: "p6",
      title: "Non-extractive",
      body: "No attention-extraction monetization. Demanding and less addictive is a design consequence, not a bug.",
    },
  ];

  /** Contribution graph — reputation from what is built upon, not ratings volume */
  const contributionEdges = [
    {
      id: "e1",
      fromId: "p-adversary",
      toId: "p-chronicler",
      kind: "builds_on",
      weightBps: 8000,
      ordinal: 2,
    },
    {
      id: "e2",
      fromId: "p-strategist",
      toId: "p-chronicler",
      kind: "cites",
      weightBps: 6500,
      ordinal: 3,
    },
    {
      id: "e3",
      fromId: "p-adversary",
      toId: "p-strategist",
      kind: "challenges",
      weightBps: 7000,
      ordinal: 4,
    },
    {
      id: "e4",
      fromId: "p-observer",
      toId: "p-adversary",
      kind: "cites",
      weightBps: 4000,
      ordinal: 5,
    },
    {
      id: "e5",
      fromId: "p-chronicler",
      toId: "p-adversary",
      kind: "builds_on",
      weightBps: 7200,
      ordinal: 6,
    },
    {
      id: "e6",
      fromId: "p-performer",
      toId: "p-strategist",
      kind: "cites",
      weightBps: 9000,
      ordinal: 7,
    },
  ];

  /** Stake + attestation ledger (slow, costly) */
  const stakes = [
    {
      id: "st1",
      stakerId: "p-chronicler",
      targetId: "p-adversary",
      kind: "endorse",
      stakeBps: 400,
      status: "resolved_valid",
      ordinal: 4,
    },
    {
      id: "st2",
      stakerId: "p-adversary",
      targetId: "p-strategist",
      kind: "challenge",
      stakeBps: 300,
      status: "open",
      ordinal: 8,
    },
    {
      id: "st3",
      stakerId: "p-strategist",
      targetId: "p-chronicler",
      kind: "endorse",
      stakeBps: 250,
      status: "resolved_valid",
      ordinal: 5,
    },
  ];

  return {
    passports,
    coalitions,
    discovery,
    notices,
    principles,
    contributionEdges,
    stakes,
  };
}

export function passportById(passports, id) {
  return passports.find((p) => p.id === id) || null;
}
