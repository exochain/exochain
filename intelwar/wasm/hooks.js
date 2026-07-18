/**
 * Fail-closed hooks toward crates/exochain-wasm.
 *
 * Set INTELWAR_WASM_PATH or pass a loader that resolves the generated module.
 */

/**
 * @returns {Promise<{ ok: false, error: string, message: string } | { ok: true, wasm: unknown }>}
 */
export async function loadExochainWasm(loader) {
  if (typeof loader === "function") {
    try {
      const wasm = await loader();
      return { ok: true, wasm };
    } catch (err) {
      return {
        ok: false,
        error: "wasm_load_failed",
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }
  return {
    ok: false,
    error: "exochain_wasm_unconfigured",
    message:
      "Provide a loader to packages/exochain-wasm or crates/exochain-wasm build output.",
  };
}

/**
 * Preflight invariant check — never treat as sole constitutional authority.
 */
export async function preflightEnforceInvariants(wasm, requestJson) {
  if (!wasm || typeof wasm.wasm_enforce_invariants !== "function") {
    return {
      ok: false,
      error: "wasm_enforce_invariants_unavailable",
      message: "exochain-wasm not loaded",
    };
  }
  try {
    const result = wasm.wasm_enforce_invariants(requestJson);
    return { ok: true, result, advisory: true };
  } catch (err) {
    return {
      ok: false,
      error: "wasm_enforce_failed",
      message: err instanceof Error ? err.message : String(err),
    };
  }
}
