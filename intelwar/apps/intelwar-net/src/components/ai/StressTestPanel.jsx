import { useState } from "react";
import {
  normalizeStressSections,
  runAdversarial,
} from "../../ai/adversarial.js";
import RunMeta from "./RunMeta.jsx";

const FOCUS_OPTS = [
  ["logical", "Logical structure"],
  ["evidence", "Evidence strength"],
  ["assumptions", "Hidden assumptions"],
  ["counters", "Strongest counters"],
  ["steelman", "Steelmanning required first"],
];

export default function StressTestPanel({
  apiBase,
  onPromote,
  initialClaim = "",
  handoffNote = null,
}) {
  const [claim, setClaim] = useState(initialClaim);
  const [focus, setFocus] = useState(["logical", "evidence", "assumptions", "counters"]);
  const [steelman, setSteelman] = useState(true);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  const toggleFocus = (id) => {
    setFocus((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    );
  };

  async function onRun() {
    setBusy(true);
    setResult(null);
    try {
      const out = await runAdversarial(apiBase, {
        mode: "stress_test",
        claim,
        focus,
        steelman_first: steelman,
      });
      setResult(out);
    } catch (err) {
      setResult({
        ok: false,
        error: "client_error",
        message: err instanceof Error ? err.message : "failed",
      });
    } finally {
      setBusy(false);
    }
  }

  const section =
    result?.ok && result.runs?.[0]
      ? normalizeStressSections(result.runs[0])
      : null;

  return (
    <div className="adv-panel">
      <p className="support">
        Flagship mode: pit your claim against frontier models under structured
        prompts. Steelmanning before attack when enabled. Not a chatbot.
      </p>
      {handoffNote ? <p className="bind-flash">{handoffNote}</p> : null}
      <label className="adv-label">
        Claim / argument
        <textarea
          rows={6}
          value={claim}
          onChange={(e) => setClaim(e.target.value)}
          placeholder="State the position you want stress-tested…"
        />
      </label>
      <div className="adv-focus" role="group" aria-label="Focus">
        {FOCUS_OPTS.map(([id, label]) => (
          <button
            key={id}
            type="button"
            className={focus.includes(id) ? "is-on" : ""}
            onClick={() => toggleFocus(id)}
          >
            {label}
          </button>
        ))}
      </div>
      <label className="adv-check">
        <input
          type="checkbox"
          checked={steelman}
          onChange={(e) => setSteelman(e.target.checked)}
        />
        Steelman first (fair adversarial posture)
      </label>
      <div className="cta-row">
        <button
          type="button"
          className="primary"
          disabled={busy || claim.trim().length < 8}
          onClick={onRun}
        >
          {busy ? "Running…" : "Stress Test My Argument"}
        </button>
      </div>

      {result && !result.ok ? (
        <div className="adv-error">
          <strong>{result.error || "failed"}</strong>
          <p>{result.message}</p>
        </div>
      ) : null}

      {section ? (
        <div className="adv-result">
          <div className="adv-attribution">
            <span className="dispatch-kind">synthetic</span>
            <span className="adv-model">{section.model}</span>
            {result.dry_run ? (
              <span className="passport-warn">structure demo — not frontier</span>
            ) : (
              <span className="log-bound">OpenRouter · not final authority</span>
            )}
          </div>
          <AnalysisBlock title="Strongest interpretation" body={section.strongest_interpretation} />
          <AnalysisList title="Key vulnerabilities" items={section.key_vulnerabilities} />
          <AnalysisList title="Strongest counters" items={section.strongest_counters} />
          <AnalysisList title="Evidence gaps" items={section.evidence_gaps} />
          <AnalysisList title="Suggested fortifications" items={section.fortifications} />
          {section.objection_quality.length ? (
            <div className="adv-block">
              <h4>Objection quality</h4>
              <ul>
                {section.objection_quality.map((o, i) => (
                  <li key={`${o.objection}-${i}`}>
                    <strong>{o.strength}</strong> — {o.objection}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {section.notes ? <p className="social-note">{section.notes}</p> : null}
          <RunMeta result={result} />
          <div className="cta-row">
            <button
              type="button"
              className="ghost"
              disabled={result.dry_run}
              onClick={() => onPromote?.(result.artifact_draft, result)}
            >
              {result.dry_run
                ? "Not Log-eligible (dry-run)"
                : "Promote artifact → Log path"}
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function AnalysisBlock({ title, body }) {
  if (!body) return null;
  return (
    <div className="adv-block">
      <h4>{title}</h4>
      <p>{body}</p>
    </div>
  );
}

function AnalysisList({ title, items }) {
  if (!items?.length) return null;
  return (
    <div className="adv-block">
      <h4>{title}</h4>
      <ul>
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
