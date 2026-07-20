import { useCallback, useEffect, useState } from "react";
import ArenaMark from "../components/ArenaMark.jsx";
import CrossCheckPanel from "../components/CrossCheckPanel.jsx";
import StressTestPanel from "../components/ai/StressTestPanel.jsx";
import {
  CrossCheckAdversarial,
  RedTeamPanel,
} from "../components/ai/MultiModelPanels.jsx";
import {
  consumeAdversarialHandoff,
  fetchAdversarialCatalog,
  formatMicroUsd,
} from "../ai/adversarial.js";

const MODES = [
  ["stress", "Stress Test"],
  ["cross", "Cross-Check"],
  ["red", "Red Team"],
  ["kernel", "Kernel Attest"],
];

function handoffMode(mode) {
  if (mode === "cross" || mode === "red" || mode === "kernel") return mode;
  return "stress";
}

export default function AiSurface({ apiBase, entries, onNavigate }) {
  const [mode, setMode] = useState("stress");
  const [stagedClaim, setStagedClaim] = useState("");
  const [handoffNote, setHandoffNote] = useState(null);
  const [catalog, setCatalog] = useState(null);
  const [promoteNote, setPromoteNote] = useState(null);

  useEffect(() => {
    const handoff = consumeAdversarialHandoff();
    if (handoff?.claim) {
      setStagedClaim(handoff.claim);
      setMode(handoffMode(handoff.mode));
      setHandoffNote(
        handoff.source === "tv"
          ? `Loaded from filmstrip Scene${handoff.sceneId ? ` ${handoff.sceneId}` : ""}.`
          : "Loaded from staged handoff.",
      );
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchAdversarialCatalog(apiBase).then((c) => {
      if (!cancelled) setCatalog(c);
    });
    return () => {
      cancelled = true;
    };
  }, [apiBase]);

  const onPromote = useCallback(
    (artifact) => {
      if (!artifact) return;
      try {
        sessionStorage.setItem(
          "intelwar_adversarial_artifact",
          JSON.stringify({
            ...artifact,
            promoted_at_label: "session",
          }),
        );
      } catch {
        /* ignore */
      }
      setPromoteNote(
        "Artifact staged in session. Deploy to Living Log on .net with consent — Kernel path required. AI is not final authority.",
      );
    },
    [],
  );

  return (
    <>
      <section className="hero hero-compact hero-ai">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.ai · Adversarial Intelligence</p>
          <h1 className="brand brand-sm">Adversary</h1>
          <p className="headline headline-ai">
            Pit your mind against frontier models under clear rules — results
            eligible for the permanent record.
          </p>
          <p className="lede">
            Not a general assistant. Structured stress tests, multi-model
            cross-checks, and red teams via OpenRouter. Multi-Intelligence
            Transparency is mandatory. AI never declares final truth.
          </p>
          <div className="status-row">
            <span
              className={`status-pill ${catalog?.configured ? "is-kernel" : "is-neutral"}`}
            >
              {catalog?.configured
                ? "OpenRouter configured"
                : "OpenRouter unset · structure demo available"}
            </span>
            <span className="status-pill is-neutral">
              final_authority: false
            </span>
          </div>
          <div className="cta-row">
            <button
              type="button"
              className="primary"
              onClick={() => {
                setMode("stress");
                document
                  .getElementById("ai-workbench")
                  ?.scrollIntoView({ behavior: "smooth" });
              }}
            >
              Stress Test My Argument
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => onNavigate("net")}
            >
              Living Log (.net)
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => onNavigate("tv")}
            >
              Filmstrip forks (.tv)
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => onNavigate("org")}
            >
              Theatre (.org)
            </button>
          </div>
        </div>
        <div className="hero-visual hero-visual-sm" aria-hidden="true">
          <ArenaMark />
        </div>
      </section>

      <section className="section" aria-label="Capabilities">
        <div className="tv-concept-grid">
          {[
            [
              "Stress Test",
              "Flagship: steelman → vulnerabilities → counters → fortifications.",
            ],
            [
              "Cross-Check",
              "Multi-model verification of claims, Scenes, or dispatches.",
            ],
            [
              "Red Team",
              "Advocate / Attacker / Auditor / Synthesizer across models.",
            ],
            [
              "In-situ .tv",
              "Powers Scene fork adversarial pressure in the filmstrip.",
            ],
            [
              "Log artifacts",
              "Promote high-quality runs for consent-gated Living Log bind.",
            ],
            [
              "Merit",
              "Quality of adversarial work feeds 0dentity — not query volume.",
            ],
          ].map(([t, b]) => (
            <article key={t}>
              <h3>{t}</h3>
              <p>{b}</p>
            </article>
          ))}
        </div>
      </section>

      {catalog?.models ? (
        <section className="section section-muted">
          <div className="section-head">
            <h2>Model routing (OpenRouter)</h2>
            <p className="support">
              Frontier roster via OpenRouter — not hard-coupled to one vendor
              model. Every run returns model identity.
            </p>
          </div>
          <ul className="adv-model-catalog">
            {(catalog.roster?.length
              ? catalog.roster.map((id) => {
                  const role =
                    Object.entries(catalog.models).find(([, m]) => m === id)?.[0] ||
                    "model";
                  return [role, id];
                })
              : Object.entries(catalog.models)
            ).map(([role, id]) => (
              <li key={`${role}-${id}`}>
                <span className="discovery-kind">{role}</span>
                <code>{id}</code>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section className="section" id="ai-workbench">
        <div className="section-head">
          <h2>Workbench</h2>
          <p className="support">
            Analytical instrument. Structured outputs over chat walls. Private
            until you promote.
          </p>
        </div>
        {catalog?.ceilings_micro_usd ? (
          <div className="status-row adv-ceilings" aria-label="Cost ceilings">
            <span className="status-pill is-neutral">
              ceilings · stress{" "}
              {formatMicroUsd(catalog.ceilings_micro_usd.stress_test)} · cross{" "}
              {formatMicroUsd(catalog.ceilings_micro_usd.cross_check)} · red
              team {formatMicroUsd(catalog.ceilings_micro_usd.red_team)}
            </span>
            <span
              className={`status-pill ${catalog.log_write?.kernel_ready ? "is-kernel" : "is-neutral"}`}
            >
              Log write:{" "}
              {catalog.log_write?.kernel_ready
                ? catalog.log_write?.consent_active
                  ? "Kernel ready · consent active"
                  : "Kernel ready · grant consent on .net"
                : "Kernel bins unset"}
            </span>
          </div>
        ) : null}
        <div className="theatre-mode adv-mode-tabs" role="tablist">
          {MODES.map(([id, label]) => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={mode === id}
              className={mode === id ? "is-on" : ""}
              onClick={() => setMode(id)}
            >
              {label}
            </button>
          ))}
        </div>

        {promoteNote ? <p className="bind-flash rep-flash">{promoteNote}</p> : null}

        {mode === "stress" ? (
          <StressTestPanel
            apiBase={apiBase}
            onPromote={onPromote}
            initialClaim={stagedClaim}
            handoffNote={handoffNote}
          />
        ) : null}
        {mode === "cross" ? (
          <CrossCheckAdversarial
            apiBase={apiBase}
            onPromote={onPromote}
            initialClaim={stagedClaim}
            handoffNote={handoffNote}
          />
        ) : null}
        {mode === "red" ? (
          <RedTeamPanel
            apiBase={apiBase}
            onPromote={onPromote}
            initialClaim={stagedClaim}
            handoffNote={handoffNote}
          />
        ) : null}
        {mode === "kernel" ? (
          <div className="adv-panel">
            <p className="support">
              Kernel attestation path — sign-demo + INTELWAR_CROSSCHECK_BIN.
              Distinct from OpenRouter analytical pressure. Fail-closed without
              bins.
            </p>
            <div className="panel" data-panel="crosscheck">
              <CrossCheckPanel apiBase={apiBase} entries={entries} />
            </div>
          </div>
        ) : null}
      </section>

      <section className="section section-deep">
        <details className="engine-details">
          <summary>Governance & boundaries</summary>
          <div className="engine-body">
            <ul className="reject-list">
              <li>AI outputs are never presented as final authority.</li>
              <li>Multi-Intelligence Transparency is mandatory.</li>
              <li>
                Exploratory analysis ≠ Log-eligible artifact until consent +
                Kernel path.
              </li>
              <li>
                Resist becoming a factory for persuasive low-integrity content.
              </li>
              <li>Query volume carries little or no merit weight.</li>
            </ul>
          </div>
        </details>
      </section>
    </>
  );
}
