/**
 * Campaign Zero — the founding campaign of IntelWar.
 *
 * The design and architectural contest of the system itself is the first
 * live campaign. Entries here capture real decisions and tensions from the
 * build (unified shell, permanence vs erasure, cost ceilings, fail-closed
 * Kernel appends, multi-model adversarial engine) — recorded cleanly, not
 * dramatized.
 *
 * Rules (intelwar-campaign-zero directive):
 * - founding entries are flagged and merit-sandboxed (non-portable);
 * - every contribution attests its intelligence (human, or model where the
 *   identity is recorded — council-seat material is honestly marked as
 *   synthetic with identity unrecorded);
 * - Campaign Zero is the founding campaign, not the permanent subject: the
 *   transition rule to external campaigns is itself a founding entry.
 */

export const CAMPAIGN_ZERO = {
  id: "campaign-zero",
  title: "Campaign Zero — The Founding of the Arena",
  status: "founding",
  summary_prefix: "CZ-",
  merit_scope: "sandboxed",
  transition_rule:
    "Campaign Zero opens the arena; once Living Log + adversarial instruments are live, external campaigns take primacy. The system must not remain permanently about its own construction.",
};

/**
 * Founding entries. Deterministic order; summaries carry the CZ- prefix so
 * Kernel mirror rows remain identifiable without payload inspection.
 * @returns {Array<{ code: string, summary: string, entry_kind: string, voice_kind: 'human'|'synthetic', model_id?: string, decision: string, counters: string[], event_type: string }>}
 */
export function foundingEntries() {
  return [
    {
      code: "CZ-01",
      summary:
        "CZ-01 · Campaign Zero opened — the design of IntelWar is the founding campaign",
      entry_kind: "DevelopmentDecision",
      voice_kind: "human",
      event_type: "campaign.created",
      decision:
        "The construction of the system is the first high-signal contest. Capture decisions, tensions, and human–AI exchanges as structured Log entries with provenance instead of synthetic seeding.",
      counters: [
        "Careful sequential validation risks sanding the project into something correct and dead.",
        "Private cathedral-building risks an impressive empty system.",
        "Synthetic seeding feels fake and poisons provenance.",
      ],
    },
    {
      code: "CZ-02",
      summary:
        "CZ-02 · Unified shell at launch; five TLDs remain the earned long-term architecture",
      entry_kind: "DevelopmentDecision",
      voice_kind: "human",
      event_type: "campaign.founding_decision",
      decision:
        "Launch as one deployable surface with host-locked sections (.org/.press/.net/.ai/.tv) rather than five independent public deployments. Split only when a domain earns independent scaling or ownership.",
      counters: [
        "Five separate TLD deployments multiply DNS/cert/CI/observability overhead (~$250–600/mo vs ~$50–150/mo).",
        "Premature split fragments the founding audience and solo-operator attention.",
      ],
    },
    {
      code: "CZ-03",
      summary:
        "CZ-03 · Social + reputation live on .net; .org stays theatre entrance",
      entry_kind: "DevelopmentDecision",
      voice_kind: "human",
      event_type: "campaign.founding_decision",
      decision:
        "Full social layer and reputation mechanics belong to the operational surface (intelwar.net). The theatre entrance (intelwar.org) keeps orientation and lightweight merit signals only.",
      counters: [
        "Placing social on the entrance surface converts the threshold into a feed and undermines the theatre framing.",
      ],
    },
    {
      code: "CZ-04",
      summary:
        "CZ-04 · Permanence vs erasure — permanent record becomes tiered retention + transparent takedown",
      entry_kind: "DebateNote",
      voice_kind: "synthetic",
      model_id: "council-seat-review (model identity unrecorded)",
      event_type: "claim.challenged",
      decision:
        "The unqualified 'permanent record' claim did not survive legal and red-team pressure. Adopted: tiered retention, crypto-erasure capability, and a transparent takedown policy — provenance of removal is itself recorded.",
      counters: [
        "An absolute permanence promise collides with GDPR erasure, defamation exposure, and operator billing failure modes.",
        "Silent deletion without a takedown trail would be worse than bounded retention.",
      ],
    },
    {
      code: "CZ-05",
      summary:
        "CZ-05 · Session cost ceilings enforced in code — $0.15 stress / $0.35 cross-check / $1.00 red team",
      entry_kind: "DevelopmentDecision",
      voice_kind: "human",
      event_type: "campaign.founding_decision",
      decision:
        "Ceilings ship as code, not policy: live meter (micro-USD integers), auto-downgrade to budget tier at 80%, graceful Command Review stop at 100% — never a raw HTTP 429. Ceiling messaging is transparency, not scarcity upsell.",
      counters: [
        "An exit criterion referencing an undefined ceiling is not gate-able (v1.1 defect).",
        "Unbounded red-team sessions are the tail-cost risk, not the average session.",
      ],
    },
    {
      code: "CZ-06",
      summary:
        "CZ-06 · No simulated Kernel success — Living Log appends fail closed",
      entry_kind: "DevelopmentDecision",
      voice_kind: "human",
      event_type: "campaign.founding_decision",
      decision:
        "The log API refuses to fabricate adjudication: without the Kernel append and CrossCheck bins the service returns 503. A source guard forbids `simulated: true` success objects.",
      counters: [
        "A demo path that fakes constitutional enforcement would make every later trust claim unverifiable.",
      ],
    },
    {
      code: "CZ-07",
      summary:
        "CZ-07 · Multi-model adversarial engine — model identity mandatory, AI never final authority",
      entry_kind: "DevelopmentDecision",
      voice_kind: "human",
      event_type: "campaign.founding_decision",
      decision:
        "intelwar.ai routes through OpenRouter across a frontier roster; every output carries model identity and the disclosure 'generated adversarial analysis, not certification'. Attestation is audit metadata, not proof of accuracy.",
      counters: [
        "Hard-coupling to a single vendor model makes the product a wrapper that dies with a pricing change.",
        "Unlabeled synthetic output collapses the human/machine distinction the theatre depends on.",
      ],
    },
    {
      code: "CZ-08",
      summary:
        "CZ-08 · Founding merit is sandboxed, labeled, non-portable until diluted",
      entry_kind: "DevelopmentDecision",
      voice_kind: "human",
      event_type: "merit.signal",
      decision:
        "Merit earned inside Campaign Zero carries merit_scope=sandboxed and is excluded from anti-gaming baselines. It becomes portable only after dilution by external contribution.",
      counters: [
        "Founders grading their own founding argument is a self-dealing vector if early merit flows into public standing.",
      ],
    },
    {
      code: "CZ-09",
      summary:
        "CZ-09 · Transition rule — the arena opens to external campaigns once the instruments are live",
      // DevelopmentDecision, not Doctrine: the Kernel requires an approved
      // debate DecisionObject before doctrine — this rule has not had one.
      entry_kind: "DevelopmentDecision",
      voice_kind: "human",
      event_type: "campaign.status_changed",
      decision: CAMPAIGN_ZERO.transition_rule,
      counters: [
        "A system permanently about its own construction is a mirror, not an arena.",
      ],
    },
  ];
}

/**
 * @param {Record<string, unknown>} mirrorEntry
 */
export function isCampaignZeroEntry(mirrorEntry) {
  return (
    typeof mirrorEntry?.summary === "string" &&
    mirrorEntry.summary.startsWith(CAMPAIGN_ZERO.summary_prefix)
  );
}

/**
 * Compare planned founding entries against Kernel mirror rows.
 * @param {Array<Record<string, unknown>>} mirrorEntries
 */
export function campaignZeroStatus(mirrorEntries) {
  const planned = foundingEntries();
  const seededSummaries = new Set(
    (mirrorEntries || [])
      .filter(isCampaignZeroEntry)
      .map((e) => String(e.summary)),
  );
  const missing = planned.filter((p) => !seededSummaries.has(p.summary));
  return {
    planned: planned.length,
    seeded: planned.length - missing.length,
    missing_codes: missing.map((m) => m.code),
    complete: missing.length === 0,
  };
}

/**
 * Kernel bridge payload for a founding entry (stringified into the DAG).
 * @param {ReturnType<typeof foundingEntries>[number]} entry
 */
export function foundingEntryPayload(entry) {
  return JSON.stringify({
    campaign: CAMPAIGN_ZERO.id,
    founding: true,
    seed: true,
    merit_scope: CAMPAIGN_ZERO.merit_scope,
    event_type: entry.event_type,
    code: entry.code,
    decision: entry.decision,
    counters: entry.counters,
    attestation:
      entry.voice_kind === "synthetic"
        ? "synthetic — council-seat material, model identity unrecorded"
        : "human — operator decision",
  });
}
