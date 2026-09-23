/**
 * 0dentity summary — honest signals derived from the Kernel log mirror.
 *
 * This is NOT a merit score. It exposes countable, auditable facts from
 * Kernel-adjudicated entries (contract §13 direction: additive dimensions,
 * log_offset for staleness). Founding-campaign material stays sandboxed.
 */

const CZ_PREFIX = "CZ-";

/**
 * @param {Array<Record<string, unknown>>} entries — mirror rows in append order
 */
export function buildOdentitySummary(entries) {
  const rows = Array.isArray(entries) ? entries : [];
  let human = 0;
  let synthetic = 0;
  let system = 0;
  let analysisEvents = 0;
  let campaignZero = 0;
  /** @type {Record<string, number>} */
  const byKind = {};

  for (const e of rows) {
    const voice = String(e.voice_kind || "");
    if (voice === "human") human += 1;
    else if (voice === "synthetic") synthetic += 1;
    else system += 1;

    const kind = String(e.entry_kind || "Unknown");
    byKind[kind] = (byKind[kind] || 0) + 1;

    const summary = String(e.summary || "");
    if (summary.startsWith(CZ_PREFIX)) campaignZero += 1;
    if (kind === "Analysis" || summary.startsWith("analysis.")) {
      analysisEvents += 1;
    }
  }

  let chainLinked = rows.length > 0;
  for (let i = 1; i < rows.length; i += 1) {
    if (rows[i].previous_receipt_hash !== rows[i - 1].receipt_hash) {
      chainLinked = false;
      break;
    }
  }

  const head = rows.length ? rows[rows.length - 1] : null;

  return {
    log_offset: rows.length,
    dimensions: {
      log_entries: rows.length,
      human_entries: human,
      synthetic_entries: synthetic,
      system_entries: system,
      analysis_events: analysisEvents,
      campaign_zero_founding: campaignZero,
    },
    by_entry_kind: byKind,
    chain_linked: chainLinked,
    head_receipt_hash: head ? head.receipt_hash || null : null,
    merit_note:
      "Signals, not scores. Founding-campaign (CZ-*) material is merit-sandboxed and non-portable until diluted by external contribution.",
  };
}
