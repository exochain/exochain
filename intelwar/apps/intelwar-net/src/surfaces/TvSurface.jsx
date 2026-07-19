import ArenaMark from "../components/ArenaMark.jsx";
import ProvenanceViewer from "../components/ProvenanceViewer.jsx";

/**
 * .tv is Provenance in the live product model (not a video library yet).
 * Polish uses cinematic/high-signal framing + Key Claims / Strategic Terrain.
 */
export default function TvSurface({ entries, onNavigate }) {
  return (
    <>
      <section className="hero hero-compact">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.tv · Provenance</p>
          <h1 className="brand brand-sm">Provenance</h1>
          <p className="headline">
            History you can audit — overlays for claims, not decoration.
          </p>
          <p className="lede">
            Receipt-chain viewer over Living Log rows (IW-2 / IW-8). Broken chains
            are labeled. Future agentic video will ride these overlays; today the
            instrument is the chain itself. This surface does not mint trust.
          </p>
          <div className="cta-row">
            <button type="button" className="ghost" onClick={() => onNavigate("org")}>
              ← Home
            </button>
            <button type="button" className="ghost" onClick={() => onNavigate("ai")}>
              CrossCheck →
            </button>
          </div>
        </div>
        <div className="hero-visual hero-visual-sm" aria-hidden="true">
          <ArenaMark />
        </div>
      </section>

      <section className="section">
        <div className="pillars pillars-tight">
          <article>
            <h3>Key claims</h3>
            <p>
              Each row is a claim-bearing receipt. Inspect hash linkage before
              treating content as history.
            </p>
          </article>
          <article>
            <h3>Strategic terrain</h3>
            <p>
              Prior entries form the terrain. Contested ground is visible as
              chain structure — not as narrative spin.
            </p>
          </article>
          <article>
            <h3>Log linkage</h3>
            <p>
              Provenance without the Living Log is costume. Open{" "}
              <button type="button" className="inline-link" onClick={() => onNavigate("net")}>
                .net
              </button>{" "}
              to see the stream this audits.
            </p>
          </article>
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
