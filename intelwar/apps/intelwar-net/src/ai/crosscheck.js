/**
 * .ai crosscheck scaffolding (IW-4 EvidenceDisciplined extension point).
 *
 * Future: proxy to crosschecked.ai / decision-forum contestation while keeping
 * constitutional truth in intelwar-core + CGR Kernel.
 */

/**
 * @typedef {{ checker_did: string, subject_entry_hash: string, verdict: 'agree'|'disagree'|'abstain', evidence_hash: string, voice_kind: string }} CrossCheckDraft
 */

/**
 * Build a draft CrossCheckResult-shaped object for later core verification.
 * @param {CrossCheckDraft} draft
 */
export function draftCrossCheck(draft) {
  if (!draft?.checker_did || !draft?.subject_entry_hash) {
    return {
      ok: false,
      error: "crosscheck_incomplete",
      message: "checker_did and subject_entry_hash are required",
    };
  }
  return {
    ok: true,
    simulated: true,
    result: {
      ...draft,
      signature: draft.signature || [],
      note: "Stub — verify via intelwar_core::crosschecks_satisfy",
    },
  };
}

/**
 * Hook for .ai layer UI — currently no network call.
 */
export async function requestCrossCheck(_subjectHash) {
  return {
    ok: false,
    error: "ai_crosscheck_unconfigured",
    message:
      "Configure .ai adapter before requesting live crosschecks. See intelwar/wasm and IW-4.",
  };
}
