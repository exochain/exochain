import ArenaMark from "../components/ArenaMark.jsx";

const DISPATCHES = [
  {
    kind: "Doctrine",
    voice: "Human-curated",
    title: "Consent before memory",
    lede: "Nothing enters durable record without an active consent gate. Unconsented append is noise, not history.",
    provenance: "Spine · IW-2",
  },
  {
    kind: "Terrain",
    voice: "Human-curated",
    title: "Cognitive domain as battlespace",
    lede: "High-level context for why structured contest matters — without alarmism, without moralizing.",
    provenance: "Spine · Context",
  },
  {
    kind: "Dispatch",
    voice: "Agentic draft · human gate",
    title: "Provenance compounds",
    lede: "Every claim that survives must chain. Broken chains are labeled — never papered over.",
    provenance: "Spine · IW-8",
  },
  {
    kind: "Brief",
    voice: "Human-authored",
    title: "No trust by proximity",
    lede: "Adjacent shell is not constitutional enforcement. trust_claim: none until Kernel paths are proven.",
    provenance: "Spine · Boundary",
  },
];

export default function PressSurface({ onNavigate }) {
  return (
    <>
      <section className="hero hero-compact">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.press · Spine</p>
          <h1 className="brand brand-sm">Press</h1>
          <p className="headline">
            Dispatches from the strategic front — long-form with provenance.
          </p>
          <p className="lede">
            Agentic and human-curated analysis that holds the instruments upright.
            Not a blog skin over the Log: the narrative spine that makes contest
            coherent. Every piece carries provenance indicators.
          </p>
          <div className="cta-row">
            <button type="button" className="ghost" onClick={() => onNavigate("org")}>
              ← Review the Constitution
            </button>
            <button type="button" className="primary" onClick={() => onNavigate("net")}>
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
          <h2>Featured on the spine</h2>
          <p className="support">
            Substantial, strategic — not feed-shaped. Voice kind is declared on
            every card.
          </p>
        </div>
        <div className="dispatch-grid">
          {DISPATCHES.map((d) => (
            <article key={d.title} className="dispatch-card">
              <div className="dispatch-meta">
                <span className="dispatch-kind">{d.kind}</span>
                <span className="dispatch-voice">{d.voice}</span>
              </div>
              <h3>{d.title}</h3>
              <p>{d.lede}</p>
              <p className="dispatch-prov">{d.provenance}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="section section-muted">
        <div className="section-head">
          <h2>Voice distinction</h2>
          <p className="support">
            Agentic drafts are labeled. Human authorship and curation are labeled.
            Unattested prose is noise.
          </p>
        </div>
        <div className="pillars pillars-tight">
          <article>
            <h3>Human-authored / curated</h3>
            <p>Accountable judgment. Final gate on what the spine carries.</p>
          </article>
          <article>
            <h3>Agentic contribution</h3>
            <p>Declared synthetic voice. Never presented as unaided human prose.</p>
          </article>
          <article>
            <h3>Provenance light</h3>
            <p>Every dispatch shows chain posture — even when the piece is doctrine.</p>
          </article>
        </div>
      </section>
    </>
  );
}
