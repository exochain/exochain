# IntelWar ↔ exochain-wasm hooks

**Status:** Extension points (fail closed until configured)

## Canonical WASM surface

Use the EXOCHAIN v0.2.3 crate / package — do not fork:

- Rust: `crates/exochain-wasm`
- Demo JS wrapper pattern: `demo/packages/exochain-wasm`
- Published package path (when built): `@exochain/exochain-wasm`

## IntelWar call plan

| Layer | WASM export | IntelWar use |
|-------|-------------|--------------|
| .net / browser | `wasm_enforce_invariants` | Preflight UI checks (never sole authority) |
| .net / browser | `wasm_propose_bailment` / bailment signing | Consent UX helpers |
| .ai | decision-forum / contestation exports | CrossCheck workflow |
| .tv | provenance-oriented display + optional verify | Receipt chain viewer |

## Local hook module

`hooks.js` documents the intended JS API. It returns structured
`dagdb_adapter_unconfigured`-style failures until `INTELWAR_WASM_PATH` points at
a built `exochain_wasm.js`.

## Rule

Browser WASM is a **runtime adapter**, not a substitute for `intelwar-core`
server-side adjudication. Fail closed when WASM or trusted DID keys are absent.
