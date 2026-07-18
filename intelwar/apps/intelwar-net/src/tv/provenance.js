/**
 * .tv provenance viewer hooks (IW-2 / IW-3 / IW-8 extension point).
 *
 * Future: render gatekeeper Provenance + LivingLogReceipt chains, optionally
 * via exochain-wasm verification helpers.
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
    simulated: Boolean(entry.simulated),
    voice_kind: entry.voice_kind || "unspecified",
    author_did: entry.author_did || null,
    content_hash: entry.content_hash || null,
    constitution_ref: entry.constitution_ref || "INTELWAR_CONSTITUTION.md",
    note: "Stub viewer — bind to LivingLogReceipt + wasm_enforce_invariants",
  };
}

/**
 * Placeholder for a .tv deep-link / embed surface.
 */
export function provenanceViewerUrl(entryId) {
  if (!entryId) return null;
  return `/tv/provenance/${encodeURIComponent(entryId)}`;
}
