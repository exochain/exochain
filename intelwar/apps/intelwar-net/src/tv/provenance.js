/**
 * .tv provenance viewer (IW-2 / IW-8 / PM-005).
 *
 * Builds receipt chains from Living Log entries using previous_receipt_hash /
 * receipt_hash links. Honest about simulated vs Kernel-adjudicated rows.
 */

/**
 * @param {Record<string, unknown>} entry
 */
export function summarizeProvenance(entry) {
  if (!entry) {
    return { ok: false, error: "missing_entry" };
  }
  return {
    ok: true,
    simulated: entry.simulated !== false,
    kernel_adjudicated: Boolean(entry.kernel_adjudicated),
    voice_kind: entry.voice_kind || "unspecified",
    author_did: entry.author_did || null,
    content_hash: entry.content_hash || null,
    receipt_hash: entry.receipt_hash || null,
    previous_receipt_hash: entry.previous_receipt_hash || null,
    dag_node_hash: entry.dag_node_hash || null,
    dag_scope: entry.dag_scope || null,
    constitution_ref: entry.constitution_ref || "INTELWAR_CONSTITUTION.md",
  };
}

/**
 * Walk `previous_receipt_hash` links newest → oldest.
 * @param {Array<Record<string, unknown>>} entries
 * @param {string} entryId
 * @returns {{ ok: boolean, chain?: Array<Record<string, unknown>>, error?: string, broken?: boolean }}
 */
export function buildReceiptChain(entries, entryId) {
  if (!Array.isArray(entries) || !entryId) {
    return { ok: false, error: "missing_entries_or_id" };
  }
  const byId = new Map(entries.map((e) => [String(e.entry_id), e]));
  const byReceipt = new Map();
  for (const e of entries) {
    if (e.receipt_hash) {
      byReceipt.set(String(e.receipt_hash), e);
    }
  }

  const start = byId.get(String(entryId));
  if (!start) {
    return { ok: false, error: "entry_not_found" };
  }

  const chain = [];
  let current = start;
  let broken = false;
  const seen = new Set();

  while (current) {
    const id = String(current.entry_id);
    if (seen.has(id)) {
      broken = true;
      break;
    }
    seen.add(id);
    chain.push({
      entry_id: current.entry_id,
      summary: current.summary,
      simulated: current.simulated !== false,
      kernel_adjudicated: Boolean(current.kernel_adjudicated),
      receipt_hash: current.receipt_hash || null,
      previous_receipt_hash: current.previous_receipt_hash || null,
      content_hash: current.content_hash || null,
      dag_node_hash: current.dag_node_hash || null,
      voice_kind: current.voice_kind || null,
      author_did: current.author_did || null,
    });

    const prev = current.previous_receipt_hash;
    if (!prev) break;
    const next = byReceipt.get(String(prev));
    if (!next) {
      broken = true;
      break;
    }
    current = next;
  }

  return {
    ok: true,
    broken,
    depth: chain.length,
    chain,
    tip_entry_id: start.entry_id,
  };
}

/**
 * Placeholder for a .tv deep-link / embed surface.
 */
export function provenanceViewerUrl(entryId) {
  if (!entryId) return null;
  return `/tv/provenance/${encodeURIComponent(entryId)}`;
}
