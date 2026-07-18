import { useCallback, useEffect, useState } from "react";
import ConsentDemo from "./components/ConsentDemo.jsx";
import LivingLogViewer from "./components/LivingLogViewer.jsx";
import { draftCrossCheck } from "./ai/crosscheck.js";
import { summarizeProvenance } from "./tv/provenance.js";

const apiBase = (import.meta.env.VITE_LOG_API_URL || "").replace(/\/$/, "");

export default function App() {
  const [entries, setEntries] = useState([]);
  const [consent, setConsent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [provNote, setProvNote] = useState("");

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
      if (log.entries?.[0]) {
        const summary = summarizeProvenance(log.entries[0]);
        setProvNote(
          `Provenance hook: voice=${summary.voice_kind}, simulated=${summary.simulated}`,
        );
      }
      // Touch .ai scaffold so the extension point stays wired in the bundle.
      draftCrossCheck({
        checker_did: "did:exo:crosscheck-stub",
        subject_entry_hash: "pending",
        verdict: "abstain",
        evidence_hash: "pending",
        voice_kind: "system",
      });
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
    <div className="shell">
      <header className="brand-hero">
        <h1 className="brand">IntelWar</h1>
        <p className="headline">A consent-governed Living Log for strategic wisdom.</p>
        <p className="lede">
          Built on EXOCHAIN v0.2.3 — CGR Kernel, bailment consent, and provenance
          receipts. Adjacent demo surfaces never claim constitutional enforcement
          by proximity.
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
            View Living Log
          </button>
          <button
            type="button"
            className="ghost"
            onClick={() =>
              document.getElementById("consent-demo")?.scrollIntoView({
                behavior: "smooth",
              })
            }
          >
            Try consent-gated append
          </button>
        </div>
      </header>

      <section className="section" id="living-log">
        <h2>Living Log</h2>
        <p className="support">
          Append-only memory with multi-intelligence transparency. Simulated rows
          are labeled until the Rust `intelwar-core` adapter is wired through
          WASM/gateway.
        </p>
        <div className="panel">
          <LivingLogViewer entries={entries} loading={loading} error={error} />
          {provNote ? <p className="status-line">{provNote}</p> : null}
        </div>
      </section>

      <section className="section" id="consent-demo">
        <h2>Consent-gated demo</h2>
        <p className="support">
          Grant demo consent, then append. This is an adjacent shell for
          intelwar.net — constitutional append is `intelwar_core::append_log_entry`.
        </p>
        <ConsentDemo
          apiBase={apiBase}
          consent={consent}
          onConsentChange={setConsent}
          onAppended={refresh}
        />
      </section>

      <footer className="foot">
        Constitution: INTELWAR_CONSTITUTION.md · Invariants v1 · Substrate EXOCHAIN
        v0.2.3 · Target: intelwar.net
      </footer>
    </div>
  );
}
