import ArenaMark from "../components/ArenaMark.jsx";
import CrossCheckPanel from "../components/CrossCheckPanel.jsx";

export default function AiSurface({ apiBase, entries, onNavigate }) {
  return (
    <>
      <section className="hero hero-compact">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.ai · CrossCheck</p>
          <h1 className="brand brand-sm">CrossCheck</h1>
          <p className="headline">
            Adversarial rigor grounded in the Living Log.
          </p>
          <p className="lede">
            Highest-rigor verification layer — multi-intelligence attestations
            that can be refused. Fail-closed when the verify binary is unset:
            this surface will not invent a Permitted outcome.
          </p>
          <div className="status-row">
            <span className="status-pill is-kernel">Core verify required</span>
            <span className="status-pill is-neutral">
              sign-demo → INTELWAR_CROSSCHECK_BIN
            </span>
          </div>
          <div className="cta-row">
            <button type="button" className="ghost" onClick={() => onNavigate("org")}>
              ← Home
            </button>
            <button type="button" className="ghost" onClick={() => onNavigate("net")}>
              Explore the Log
            </button>
          </div>
        </div>
        <div className="hero-visual hero-visual-sm" aria-hidden="true">
          <ArenaMark />
        </div>
      </section>

      <section className="section">
        <div className="section-head">
          <h2>CrossCheck flow</h2>
          <p className="support">
            Subject → attestations → verify → permit or refuse. Citation strength
            and provenance travel with the result.
          </p>
        </div>
        <ol className="flow-list">
          <li>
            <strong>Ground</strong> — select a Living Log subject (hash-linked).
          </li>
          <li>
            <strong>Attest</strong> — human or synthetic checkers declare voice_kind.
          </li>
          <li>
            <strong>Verify</strong> — core binary or honest fail-closed refusal.
          </li>
          <li>
            <strong>Record</strong> — outcome does not mint trust by UI proximity.
          </li>
        </ol>
      </section>

      <section className="section">
        <div className="panel" data-panel="crosscheck">
          <CrossCheckPanel apiBase={apiBase} entries={entries} />
        </div>
      </section>
    </>
  );
}
