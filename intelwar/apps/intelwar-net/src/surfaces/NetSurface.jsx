import ArenaMark from "../components/ArenaMark.jsx";
import CampaignZeroPanel from "../components/net/CampaignZeroPanel.jsx";
import ConsentDemo from "../components/ConsentDemo.jsx";
import LivingLogViewer from "../components/LivingLogViewer.jsx";
import SocialSurface from "./SocialSurface.jsx";

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
  const kernelLinked =
    entries.length > 0 && entries.every((e) => e.simulated === false);
  const durable = entries.find((e) => e.durable)?.durable || "local_kernel";

  return (
    <>
      <section className="hero hero-portal">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.net · Operational layer</p>
          <h1 className="brand brand-sm">Social + Log</h1>
          <p className="headline">
            Daily engagement, 0dentity reputation, coalitions — and the Living
            Log that makes contribution endure.
          </p>
          <p className="lede">
            This is the operational shell. Social and reputation live here —
            not on the theatre entrance. Home orientation is{" "}
            <button
              type="button"
              className="inline-link"
              onClick={() => onNavigate("org")}
            >
              intelwar.org
            </button>
            ; publishing spine is{" "}
            <button
              type="button"
              className="inline-link"
              onClick={() => onNavigate("press")}
            >
              intelwar.press
            </button>
            . Appends are Kernel-adjudicated; API fail-closes without bins.
          </p>
          <div className="status-row" aria-label="Path status">
            <span
              className={`status-pill ${kernelLinked ? "is-kernel" : "is-neutral"}`}
            >
              {kernelLinked
                ? "Path: Kernel-linked"
                : "Path: awaiting Kernel entries"}
            </span>
            <span className="status-pill is-neutral">durable: {durable}</span>
          </div>
          <div className="cta-row">
            <button
              type="button"
              className="primary"
              onClick={() =>
                document
                  .getElementById("social-layer")
                  ?.scrollIntoView({ behavior: "smooth" })
              }
            >
              Enter Social / Merit
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() =>
                document.getElementById("living-log")?.scrollIntoView({
                  behavior: "smooth",
                })
              }
            >
              Explore the Log
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

      <section className="portal-grid" aria-label="Surfaces">
        {[
          ["org", ".org", "Theatre", "Threshold + orientation"],
          ["press", ".press", "Press", "Dispatches + contests"],
          ["ai", ".ai", "Adversary", "Stress test + cross-check"],
          ["tv", ".tv", "Filmstrip", "Recursive theatre"],
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

      <nav className="net-ops-nav" aria-label="Operational sections">
        <a href="#social-layer">Social · Merit</a>
        <a href="#reputation-mechanics">Reputation</a>
        <a href="#campaign-zero">Campaign Zero</a>
        <a href="#living-log">Living Log</a>
        <a href="#consent-demo">Consent append</a>
      </nav>

      {/* Primary: social + reputation */}
      <section className="section section-social-primary">
        <SocialSurface onNavigate={onNavigate} embedded />
      </section>

      <section className="section" id="campaign-zero">
        <div className="section-head">
          <h2>Campaign Zero — The Founding of the Arena</h2>
          <p className="support">
            The first live campaign is the design contest of the system
            itself: real decisions, real counters, Kernel-appended with
            provenance and multi-intelligence attestation. The arena opens to
            external campaigns once the instruments are live.
          </p>
        </div>
        <CampaignZeroPanel
          apiBase={apiBase}
          consentActive={Boolean(consent?.active)}
          onSeeded={onAppended}
        />
      </section>

      <section className="section" id="living-log">
        <div className="section-head">
          <h2>Living Log</h2>
          <p className="support">
            Append-only stream with multi-intelligence transparency. Rows marked
            Simulated until Kernel adjudication via{" "}
            <code>INTELWAR_CORE_BIN</code>. Social merit is earned here when
            contributions endure under reference and scrutiny.
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
