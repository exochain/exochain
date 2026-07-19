import ArenaMark from "../components/ArenaMark.jsx";
import ConsentDemo from "../components/ConsentDemo.jsx";
import LivingLogViewer from "../components/LivingLogViewer.jsx";

const apiBase = (import.meta.env.VITE_LOG_API_URL || "").replace(/\/$/, "");

export default function NetSurface({
  entries,
  loading,
  error,
  consent,
  setConsent,
  onAppended,
  onNavigate,
}) {
  const simulated =
    !entries.length || entries.some((e) => e.simulated !== false);

  return (
    <>
      <section className="hero hero-portal">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.net · Portal</p>
          <h1 className="brand brand-sm">Living Log</h1>
          <p className="headline">Functional entry to the arena.</p>
          <p className="lede">
            Consent-governed, append-only memory. Instrument of the frame — home
            is{" "}
            <button type="button" className="inline-link" onClick={() => onNavigate("org")}>
              intelwar.org
            </button>
            ; spine is{" "}
            <button type="button" className="inline-link" onClick={() => onNavigate("press")}>
              intelwar.press
            </button>
            . Status below is honest: simulated until Kernel is deliberately wired.
          </p>
          <div className="status-row" aria-label="Path status">
            <span className={`status-pill ${simulated ? "is-sim" : "is-kernel"}`}>
              {simulated ? "Path: simulated" : "Path: Kernel-linked"}
            </span>
            <span className="status-pill is-neutral">trust_claim: none</span>
          </div>
          <div className="cta-row">
            <button
              type="button"
              className="primary"
              onClick={() =>
                document.getElementById("living-log")?.scrollIntoView({
                  behavior: "smooth",
                })
              }
            >
              Explore the Log
            </button>
            <button type="button" className="ghost" onClick={() => onNavigate("org")}>
              Review the Constitution
            </button>
          </div>
        </div>
        <div className="hero-visual hero-visual-sm" aria-hidden="true">
          <ArenaMark />
        </div>
      </section>

      <section className="portal-grid" aria-label="Surfaces">
        {[
          ["org", ".org", "Foundation", "Constitutional home"],
          ["press", ".press", "Spine", "Dispatches + doctrine"],
          ["ai", ".ai", "CrossCheck", "Adversarial verify"],
          ["tv", ".tv", "Provenance", "Receipt chains"],
        ].map(([id, label, title, blurb]) => (
          <button
            key={id}
            type="button"
            className="portal-card"
            onClick={() => onNavigate(id)}
          >
            <span className="rail-label">{label}</span>
            <strong>{title}</strong>
            <span>{blurb}</span>
          </button>
        ))}
      </section>

      <section className="section" id="living-log">
        <div className="section-head">
          <h2>Living Log</h2>
          <p className="support">
            Append-only stream with multi-intelligence transparency. Rows marked
            Simulated until Kernel adjudication via <code>INTELWAR_CORE_BIN</code>.
          </p>
        </div>
        <div className="panel" data-panel="living-log">
          <LivingLogViewer entries={entries} loading={loading} error={error} />
        </div>
      </section>

      <section className="section" id="consent-demo">
        <div className="section-head">
          <h2>Consent-gated append</h2>
          <p className="support">
            Demo consent, then append. Constitutional bailment is enforced in{" "}
            <code>intelwar_core</code>, not in this Node fixture alone.
          </p>
        </div>
        <ConsentDemo
          apiBase={apiBase}
          consent={consent}
          onConsentChange={setConsent}
          onAppended={onAppended}
        />
      </section>
    </>
  );
}
