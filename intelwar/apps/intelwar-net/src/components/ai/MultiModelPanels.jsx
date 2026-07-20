import { useState } from "react";
import { runAdversarial } from "../../ai/adversarial.js";
import RunMeta from "./RunMeta.jsx";

export function CrossCheckAdversarial({
  apiBase,
  onPromote,
  initialClaim = "",
  handoffNote = null,
}) {
  const [claim, setClaim] = useState(initialClaim);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  async function onRun() {
    setBusy(true);
    setResult(null);
    try {
      setResult(
        await runAdversarial(apiBase, {
          mode: "cross_check",
          claim,
        }),
      );
    } catch (err) {
      setResult({
        ok: false,
        message: err instanceof Error ? err.message : "failed",
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="adv-panel">
      <p className="support">
        Multi-model verification: consistency, evidence strength, contradictions,
        unstated assumptions. Comparable columns. Not an oracle.
      </p>
      {handoffNote ? <p className="bind-flash">{handoffNote}</p> : null}
      <label className="adv-label">
        Claim / Scene / dispatch text
        <textarea
          rows={5}
          value={claim}
          onChange={(e) => setClaim(e.target.value)}
          placeholder="Paste the claim to cross-check…"
        />
      </label>
      <button
        type="button"
        className="primary"
        disabled={busy || claim.trim().length < 8}
        onClick={onRun}
      >
        {busy ? "Cross-checking…" : "Run Cross-Check"}
      </button>

      {result?.ok ? (
        <div className="adv-compare">
          <div className="adv-attribution">
            {result.dry_run ? (
              <span className="passport-warn">structure demo — not frontier</span>
            ) : (
              <span className="log-bound">OpenRouter multi-model</span>
            )}
            <span>final_authority: false</span>
          </div>
          <div className="adv-compare-grid">
            {(result.runs || []).map((run) => {
              const c = run.content || {};
              return (
                <article key={`${run.model}-${run.id || ""}`} className="adv-compare-card">
                  <header>
                    <span className="dispatch-kind">synthetic</span>
                    <strong>{run.model}</strong>
                  </header>
                  <p>
                    <em>Consistency</em>{" "}
                    {c.consistency?.rating || "—"} — {c.consistency?.notes || ""}
                  </p>
                  <p>
                    <em>Evidence</em>{" "}
                    {c.evidence_strength?.rating || "—"} —{" "}
                    {c.evidence_strength?.notes || ""}
                  </p>
                  <p>
                    <em>Verdict hint</em> {c.verdict_hint || "abstain"}
                  </p>
                  <p>{c.summary || c.notes || ""}</p>
                  {Array.isArray(c.contradictions) && c.contradictions.length ? (
                    <ul>
                      {c.contradictions.map((x) => (
                        <li key={x}>{x}</li>
                      ))}
                    </ul>
                  ) : null}
                  {Array.isArray(c.unstated_assumptions) &&
                  c.unstated_assumptions.length ? (
                    <>
                      <h5>Assumptions</h5>
                      <ul>
                        {c.unstated_assumptions.map((x) => (
                          <li key={x}>{x}</li>
                        ))}
                      </ul>
                    </>
                  ) : null}
                </article>
              );
            })}
          </div>
          <RunMeta result={result} />
          <button
            type="button"
            className="ghost"
            disabled={result.dry_run}
            onClick={() => onPromote?.(result.artifact_draft, result)}
          >
            Promote cross-check artifact
          </button>
        </div>
      ) : null}
      {result && !result.ok ? (
        <div className="adv-error">
          <p>{result.message || result.error}</p>
        </div>
      ) : null}
    </div>
  );
}

export function RedTeamPanel({
  apiBase,
  onPromote,
  initialClaim = "",
  handoffNote = null,
}) {
  const [claim, setClaim] = useState(initialClaim);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  async function onRun() {
    setBusy(true);
    setResult(null);
    try {
      setResult(
        await runAdversarial(apiBase, {
          mode: "red_team",
          claim,
          roles: ["advocate", "attacker", "evidence_auditor", "synthesizer"],
        }),
      );
    } catch (err) {
      setResult({
        ok: false,
        message: err instanceof Error ? err.message : "failed",
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="adv-panel">
      <p className="support">
        Assigned roles across frontier models: Advocate, Attacker, Evidence
        Auditor, Synthesizer. Backend for .tv fork pressure.
      </p>
      {handoffNote ? <p className="bind-flash">{handoffNote}</p> : null}
      <label className="adv-label">
        Subject for red team
        <textarea
          rows={5}
          value={claim}
          onChange={(e) => setClaim(e.target.value)}
          placeholder="Claim or Scene core to red-team…"
        />
      </label>
      <button
        type="button"
        className="primary"
        disabled={busy || claim.trim().length < 8}
        onClick={onRun}
      >
        {busy ? "Red-teaming…" : "Run Multi-Model Red Team"}
      </button>

      {result?.ok ? (
        <div className="adv-compare">
          <div className="adv-compare-grid adv-roles">
            {(result.runs || []).map((run) => (
              <article key={`${run.role}-${run.model}`} className="adv-compare-card">
                <header>
                  <span className="dispatch-kind">{run.role || "role"}</span>
                  <strong>{run.model}</strong>
                </header>
                <pre className="adv-json">
                  {JSON.stringify(run.content, null, 2)}
                </pre>
              </article>
            ))}
          </div>
          <RunMeta result={result} />
          <button
            type="button"
            className="ghost"
            disabled={result.dry_run}
            onClick={() => onPromote?.(result.artifact_draft, result)}
          >
            Promote red-team artifact
          </button>
        </div>
      ) : null}
    </div>
  );
}
