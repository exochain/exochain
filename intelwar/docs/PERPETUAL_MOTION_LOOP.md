# Perpetual Motion Loop

After every major IntelWar work unit, the agent (or human) MUST:

1. **Cite the Constitution** — which Articles / invariant IDs were touched.
2. **Emit a Log artifact** — `node intelwar/tools/emit-log-entry.js --summary "..."`.
3. **Triage residue** — `node intelwar/tools/triage.js "..."` for leftover risks.
4. **Write 3–5 next tasks** into `CURSOR_AGENT_HANDOFF.md` → Perpetual Motion Backlog.
5. **Attest AI work** — synthetic voice + agent_attestation fields (IW-4).

## Structured next-task format (paste into handoff)

```yaml
- id: PM-00N
  title: Short imperative title
  why: Compounding value in one line
  invariants: [consent-before-memory, provenance-compounding]
  paths: [intelwar/crates/intelwar-core/src/...]
  command: cargo test -p intelwar-core
  done_when: Observable acceptance check
```

## Stop conditions

- Same validation failure twice → escalate to human (do not loop).
- `max_iterations` for any automation ≤ 25 (AGENTS.md workflow bounds).
- Human override always available (IW-5).
