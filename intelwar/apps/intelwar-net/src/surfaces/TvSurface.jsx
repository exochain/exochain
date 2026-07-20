import ArenaMark from "../components/ArenaMark.jsx";
import ProvenanceViewer from "../components/ProvenanceViewer.jsx";
import FilmstripTheatre from "../components/tv/FilmstripTheatre.jsx";

/**
 * intelwar.tv — visual recursive filmstrip theatre (PRD 2026-07-19).
 * Filmstrip = experiential layer. Living Log = permanent record.
 * Provenance viewer remains available as Log substrate.
 */
export default function TvSurface({ entries, onNavigate }) {
  return (
    <>
      <section className="hero hero-compact hero-tv" id="tv-threshold">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.tv · Visual Theatre</p>
          <h1 className="brand brand-sm">Filmstrip</h1>
          <p className="headline headline-tv">
            Intellectual combat as a navigable, recursive filmstrip —
            forward and backward in time, deeper into any claim, sideways into
            forks.
          </p>
          <p className="lede">
            Scenes of 30–90 seconds. Horizontal time. Recursive depth. In-situ
            forking. Heat maps where rigorous attention concentrates. 0dentity
            merit rewards signal — not applause. Significant moves bind to the
            Living Log under consent.
          </p>
          <p className="press-supporting">
            Watchable. Forkable. Bound to the Record.
          </p>
          <div className="cta-row">
            <button
              type="button"
              className="primary"
              onClick={() =>
                document
                  .getElementById("filmstrip-theatre")
                  ?.scrollIntoView({ behavior: "smooth" })
              }
            >
              Enter the Filmstrip
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() =>
                document
                  .getElementById("tv-heat")
                  ?.scrollIntoView({ behavior: "smooth" })
              }
            >
              View Heat Map
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => onNavigate("net")}
            >
              Open the Living Log
            </button>
          </div>
        </div>
        <div className="hero-visual hero-visual-sm" aria-hidden="true">
          <ArenaMark />
        </div>
      </section>

      <section className="section tv-concepts" aria-label="Core concepts">
        <div className="tv-concept-grid">
          {[
            ["Scene", "Atomic 30–90s intellectual move — open hook, core, close hook."],
            ["Filmstrip", "Ordered sequence reconstructing a coherent debate arc."],
            ["Branch", "Nested strip under a Scene — evidence, precedent, sub-argument."],
            ["Fork", "Participatory branch initiated in-situ from any Scene."],
            ["Heat", "Composite attention + intensity — surfaces scrutiny, not truth."],
            ["0dentity Merit", "Portable reputation for high-signal contribution."],
          ].map(([title, body]) => (
            <article key={title}>
              <h3>{title}</h3>
              <p>{body}</p>
            </article>
          ))}
        </div>
      </section>

      <section
        className="section section-muted"
        id="scene-production"
        aria-labelledby="production-heading"
      >
        <div className="section-head">
          <h2 id="production-heading">Scene production discipline</h2>
          <p className="support">
            High information density with intellectual dignity. Watching Scenes
            in order must reconstruct a coherent debate arc. Every Scene is fork-ready.
          </p>
        </div>
        <ol className="production-rules">
          <li>
            <strong>Open hook (3–8s)</strong> — orientation and curiosity.
          </li>
          <li>
            <strong>Intellectual core</strong> — one clear move with supporting
            cutaways / synthetic b-roll.
          </li>
          <li>
            <strong>Close hook (3–8s)</strong> — forward or backward pull into
            the next Scene or a branch.
          </li>
          <li>
            <strong>Length</strong> — ideal 45–75s; acceptable 30–90s.
          </li>
        </ol>
      </section>

      <section className="section section-theatre" id="filmstrip-theatre">
        <FilmstripTheatre onNavigate={onNavigate} />
      </section>

      <section
        className="section section-muted"
        id="tv-log-bond"
        aria-labelledby="log-bond-heading"
      >
        <div className="section-head">
          <h2 id="log-bond-heading">Relationship to the Living Log</h2>
          <p className="support">
            The filmstrip is experiential. The Log is permanent. Significant
            Scenes and accepted Forks write structured entries with consent,
            authority, and provenance — preserving constitutional guarantees
            while enabling rich media.
          </p>
        </div>
        <div className="pillars pillars-tight">
          <article>
            <h3>Experience layer</h3>
            <p>
              Navigation, heat, forks, and AI packaging live here. This shell
              does not mint Kernel trust by proximity.
            </p>
          </article>
          <article>
            <h3>Record layer</h3>
            <p>
              Durable writes fail closed without consent and adjudication.
              Broken chains are labeled in the provenance instrument below.
            </p>
          </article>
          <article>
            <h3>Cross-domain</h3>
            <p>
              Move between{" "}
              <button type="button" className="inline-link" onClick={() => onNavigate("press")}>
                .press
              </button>
              ,{" "}
              <button type="button" className="inline-link" onClick={() => onNavigate("ai")}>
                .ai
              </button>
              , and{" "}
              <button type="button" className="inline-link" onClick={() => onNavigate("net")}>
                .net
              </button>{" "}
              without losing the theatre’s orientation to the Record.
            </p>
          </article>
        </div>
      </section>

      <section className="section section-deep" id="tv-provenance">
        <details className="engine-details">
          <summary>Provenance substrate — receipt chains over Living Log rows</summary>
          <div className="engine-body">
            <p>
              IW-2 / IW-8 instrument. History you can audit. Future agentic video
              rides these overlays; today the chain remains the ground truth
              check.
            </p>
            <div className="panel" data-panel="provenance">
              <ProvenanceViewer entries={entries} />
            </div>
          </div>
        </details>
      </section>
    </>
  );
}
