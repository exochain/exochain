import { useCallback, useEffect, useState } from "react";
import ArenaMark from "./components/ArenaMark.jsx";
import ConsentDemo from "./components/ConsentDemo.jsx";
import CrossCheckPanel from "./components/CrossCheckPanel.jsx";
import LivingLogViewer from "./components/LivingLogViewer.jsx";
import ProvenanceViewer from "./components/ProvenanceViewer.jsx";
import SiteFooter from "./components/SiteFooter.jsx";
import SiteNav from "./components/SiteNav.jsx";
import {
  isProductionHost,
  resolveSurface,
  surfaceHref,
  surfaceTitle,
} from "./lib/surface.js";

const apiBase = (import.meta.env.VITE_LOG_API_URL || "").replace(/\/$/, "");

export default function App() {
  const [surface, setSurface] = useState(() => resolveSurface());
  const [entries, setEntries] = useState([]);
  const [consent, setConsent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const navigate = useCallback((next) => {
    if (isProductionHost(window.location.hostname)) {
      const href = surfaceHref(next);
      if (href.startsWith("http") && !href.includes(window.location.host)) {
        window.location.assign(href);
        return;
      }
    }
    setSurface(next);
    const hash = next === "net" ? "net" : next;
    if (window.location.hash.replace(/^#/, "") !== hash) {
      window.history.replaceState(null, "", `#${hash}`);
    }
    document.title = surfaceTitle(next);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  useEffect(() => {
    document.title = surfaceTitle(surface);
    const onHash = () => setSurface(resolveSurface());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [surface]);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [logRes, consentRes] = await Promise.all([
        fetch(`${apiBase}/api/log`),
        fetch(`${apiBase}/api/consent`),
      ]);
      if (!logRes.ok) throw new Error(`log ${logRes.status}`);
      const log = await logRes.json();
      const c = consentRes.ok ? await consentRes.json() : null;
      setEntries(log.entries || []);
      setConsent(c);
    } catch (err) {
      setError(err instanceof Error ? err.message : "fetch_failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <div className={`app surface-${surface}`}>
      <SiteNav surface={surface} onNavigate={navigate} />

      <main id="main">
        {surface === "net" ? (
          <NetSurface
            entries={entries}
            loading={loading}
            error={error}
            consent={consent}
            setConsent={setConsent}
            onAppended={refresh}
            onNavigate={navigate}
          />
        ) : null}

        {surface === "ai" ? (
          <AiSurface apiBase={apiBase} entries={entries} onNavigate={navigate} />
        ) : null}

        {surface === "tv" ? (
          <TvSurface entries={entries} onNavigate={navigate} />
        ) : null}
      </main>

      <SiteFooter onNavigate={navigate} />
    </div>
  );
}

function NetSurface({
  entries,
  loading,
  error,
  consent,
  setConsent,
  onAppended,
  onNavigate,
}) {
  return (
    <>
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.net · Living Log</p>
          <h1 className="brand">IntelWar</h1>
          <p className="headline">Where arguments earn their survival.</p>
          <p className="lede">
            Consent-governed, append-only memory for the intelligentsia. Ideas
            contested under constitutional rules; the record compounds. This
            shell is adjacent — Kernel adjudication is not claimed by proximity.
          </p>
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
              Enter the Log
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => onNavigate("ai")}
            >
              Open .ai CrossCheck
            </button>
          </div>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <ArenaMark />
        </div>
      </section>

      <section className="pillars" aria-label="What IntelWar protects">
        <article>
          <h3>Consent before memory</h3>
          <p>Nothing enters the Log without an active consent gate.</p>
        </article>
        <article>
          <h3>Provenance compounds</h3>
          <p>Every row chains to what came before — auditable, not decorative.</p>
        </article>
        <article>
          <h3>Attested intelligence</h3>
          <p>Synthetic voices must declare themselves. Unattested prose is noise.</p>
        </article>
      </section>

      <section className="section" id="living-log">
        <div className="section-head">
          <h2>Living Log</h2>
          <p className="support">
            Append-only stream with multi-intelligence transparency. Rows marked
            Simulated until Kernel adjudication is wired via{" "}
            <code>INTELWAR_CORE_BIN</code>.
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

      <section className="surface-rail">
        <button type="button" className="rail-card" onClick={() => onNavigate("ai")}>
          <span className="rail-label">.ai</span>
          <strong>CrossCheck</strong>
          <span>Verify multi-intelligence attestations</span>
        </button>
        <button type="button" className="rail-card" onClick={() => onNavigate("tv")}>
          <span className="rail-label">.tv</span>
          <strong>Provenance</strong>
          <span>Inspect receipt chains without minting trust</span>
        </button>
      </section>
    </>
  );
}

function AiSurface({ apiBase, entries, onNavigate }) {
  return (
    <>
      <section className="hero hero-compact">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.ai · CrossCheck</p>
          <h1 className="brand brand-sm">CrossCheck</h1>
          <p className="headline">Attestations that can be refused.</p>
          <p className="lede">
            Multi-intelligence verify surface. Fail-closed when the verify binary
            is unset — this page will not invent a Permitted outcome.
          </p>
          <div className="cta-row">
            <button type="button" className="ghost" onClick={() => onNavigate("net")}>
              ← Living Log
            </button>
            <button type="button" className="ghost" onClick={() => onNavigate("tv")}>
              Provenance .tv →
            </button>
          </div>
        </div>
        <div className="hero-visual hero-visual-sm" aria-hidden="true">
          <ArenaMark />
        </div>
      </section>

      <section className="section">
        <div className="panel" data-panel="crosscheck">
          <CrossCheckPanel apiBase={apiBase} entries={entries} />
        </div>
      </section>
    </>
  );
}

function TvSurface({ entries, onNavigate }) {
  return (
    <>
      <section className="hero hero-compact">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.tv · Provenance</p>
          <h1 className="brand brand-sm">Provenance</h1>
          <p className="headline">History you can audit, not decorate.</p>
          <p className="lede">
            Receipt-chain viewer over Living Log rows (IW-2 / IW-8). Broken chains
            are labeled. This surface does not mint trust.
          </p>
          <div className="cta-row">
            <button type="button" className="ghost" onClick={() => onNavigate("net")}>
              ← Living Log
            </button>
            <button type="button" className="ghost" onClick={() => onNavigate("ai")}>
              CrossCheck .ai →
            </button>
          </div>
        </div>
        <div className="hero-visual hero-visual-sm" aria-hidden="true">
          <ArenaMark />
        </div>
      </section>

      <section className="section">
        <div className="panel" data-panel="provenance">
          <ProvenanceViewer entries={entries} />
        </div>
      </section>
    </>
  );
}
