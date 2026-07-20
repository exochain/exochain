import ArenaMark from "../components/ArenaMark.jsx";

const DISPATCHES = [
  {
    kind: "Doctrine",
    voice: "Human-curated",
    title: "Consent before memory",
    lede: "Nothing enters durable record without an active consent gate. Unconsented append is noise, not history.",
    provenance: "Record · IW-2",
  },
  {
    kind: "Analysis",
    voice: "Human-authored",
    title: "Capture and chaos",
    lede: "Institutional media subordinated inquiry to narrative and access; the opposite pathology floods the zone with low-rigor assertion. Both damage clear thought.",
    provenance: "Record · Editorial",
  },
  {
    kind: "Dispatch",
    voice: "Agentic draft · human gate",
    title: "Provenance compounds",
    lede: "Every claim that survives must chain. Broken chains are labeled — never papered over.",
    provenance: "Record · IW-8",
  },
  {
    kind: "Brief",
    voice: "Human-authored",
    title: "Protected speech, accountable record",
    lede: "First Amendment protection for political and intellectual speech — paired with provenance so expression is harder to erase and harder to rewrite.",
    provenance: "Record · 1A",
  },
];

const CONTESTS = [
  {
    claim: "Has the corporate Fourth Estate abandoned truth-seeking for narrative management?",
    status: "Open",
    stakes: "Institutional legitimacy · public memory",
  },
  {
    claim: "Does cryptographic permanence meaningfully defend free expression against memory-holing?",
    status: "Open",
    stakes: "Structural defense · Living Log",
  },
  {
    claim: "Where does protected inquiry end and unprotected speech begin — and who decides under pressure?",
    status: "Contested",
    stakes: "First Amendment · process integrity",
  },
  {
    claim: "Can high-rigor contest coexist with open participation without collapsing into noise?",
    status: "Emerging",
    stakes: "Standards · participation design",
  },
];

const PATHWAYS = [
  {
    title: "Reader / Observer",
    description:
      "Read dispatches and follow contests. Study the terrain before you publish or engage.",
    action: "Enter the Press",
    target: "dispatches",
  },
  {
    title: "Contributor",
    description:
      "Publish under provenance requirements. Voice kind is declared. Low-effort volume is structurally discouraged.",
    action: "Open the Log",
    surface: "net",
  },
  {
    title: "Combatant",
    description:
      "Enter structured contest on claims of public importance. Arguments must earn survival under clear rules.",
    action: "View Contests",
    target: "contests",
  },
  {
    title: "Cross-Checker",
    description:
      "Adversarial review against the Living Log. Refuse what cannot be attested.",
    action: "Open CrossCheck",
    surface: "ai",
  },
  {
    title: "Chronicler of the Record",
    description:
      "High-integrity entries intended to endure — contestable, rebuttable, not silently erasable.",
    action: "Read the Record",
    target: "the-record",
  },
];

function scrollTo(id) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
}

export default function PressSurface({ onNavigate }) {
  return (
    <>
      {/* 1. Hero / Threshold */}
      <section className="hero hero-compact hero-press" id="threshold">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.press · Fourth Estate</p>
          <h1 className="brand brand-sm">Press</h1>
          <p className="headline headline-press">
            The Fourth Estate has largely failed.
            <br />
            Ideas are now treated as weapons to be controlled rather than
            arguments to be tested.
          </p>
          <p className="lede">
            intelwar.press exists to restore a harder standard: free expression
            under constitutional protection, structured contest under clear
            rules, and a permanent record that cannot be memory-holed.
          </p>
          <p className="press-supporting">
            Protected speech. Provenance. Permanent record.
          </p>
          <div className="cta-row">
            <button
              type="button"
              className="primary"
              onClick={() => scrollTo("dispatches")}
            >
              Enter the Press
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => scrollTo("contests")}
            >
              View Current Contests
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => scrollTo("the-record")}
            >
              Read the Record
            </button>
          </div>
        </div>
        <div className="hero-visual hero-visual-sm" aria-hidden="true">
          <ArenaMark />
        </div>
      </section>

      {/* 2. Why This Exists */}
      <section
        className="section"
        id="why-this-exists"
        aria-labelledby="why-heading"
      >
        <div className="section-head">
          <h2 id="why-heading">Why this exists</h2>
          <p className="support">
            Principle over tribe. A higher standard under First Amendment
            protection — with cryptographic permanence as structural defense.
          </p>
        </div>
        <div className="press-why-grid">
          <article className="press-why-card">
            <h3>Institutional failure</h3>
            <p>
              Institutional and corporate media have repeatedly subordinated
              truth-seeking to narrative, access, and institutional interest.
              That is a failure of courage and process — not primarily of
              technology.
            </p>
          </article>
          <article className="press-why-card">
            <h3>Censorship pressure</h3>
            <p>
              Pressure from state, corporate, and cultural actors has made
              certain categories of inquiry more costly than they should be in a
              free society. Protected speech includes unpopular and contested
              ideas.
            </p>
          </article>
          <article className="press-why-card">
            <h3>Collapse of standards</h3>
            <p>
              The opposite pathology is also real: low-rigor assertion and
              conspiracy presented as investigation. Chaos damages clear thought
              as surely as capture does.
            </p>
          </article>
          <article className="press-why-card press-why-resolve">
            <h3>The harder middle</h3>
            <p>
              intelwar.press rejects both suppression and noise. It aims for
              rigorous, protected, provenance-backed expression and intellectual
              combat — free, rigorous, and permanent.
            </p>
          </article>
        </div>
      </section>

      {/* 3. The Record */}
      <section
        className="section section-muted"
        id="the-record"
        aria-labelledby="record-heading"
      >
        <div className="section-head">
          <h2 id="record-heading">The Record</h2>
          <p className="support">
            The Living Log is institutional memory in durable form — the defense
            previous free-press institutions lacked.
          </p>
        </div>
        <div className="record-panel">
          <p className="record-lede">
            What is published here is intended to endure.
            <br />
            Entries can be contested. They can be rebutted. They can be refined.
            <br />
            They should not be silently erased.
          </p>
          <p className="record-body">
            Free expression becomes harder to erase, harder to rewrite, and
            harder to gaslight out of existence when it leaves a consent-gated,
            provenance-chained trail. The Log is not the product pitch — it is
            the structural defense of the press function itself.
          </p>
          <div className="cta-row">
            <button
              type="button"
              className="primary"
              onClick={() => onNavigate("net")}
            >
              Open the Living Log
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => onNavigate("org")}
            >
              Theatre rules (.org)
            </button>
          </div>
        </div>
      </section>

      {/* 4. Dual streams: Dispatches + Contests */}
      <section
        className="section"
        id="dispatches"
        aria-labelledby="dispatches-heading"
      >
        <div className="section-head">
          <h2 id="dispatches-heading">Dispatches</h2>
          <p className="support">
            High-signal analysis, investigation, and strategic writing. Voice
            kind declared. Provenance carried.
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

      <section
        className="section section-board"
        id="contests"
        aria-labelledby="contests-heading"
      >
        <div className="section-head">
          <h2 id="contests-heading">Current Contests</h2>
          <p className="support">
            Structured intellectual combat on claims of public importance —
            adversarial, rules-based, recorded.
          </p>
        </div>
        <div className="contest-board" role="list">
          {CONTESTS.map((c) => (
            <article key={c.claim} className="contest-card" role="listitem">
              <div className="campaign-meta">
                <span
                  className={`campaign-status status-${c.status.toLowerCase()}`}
                >
                  {c.status}
                </span>
                <span className="campaign-terrain">{c.stakes}</span>
              </div>
              <h3>{c.claim}</h3>
              <button
                type="button"
                className="ghost role-cta"
                onClick={() => onNavigate("ai")}
              >
                Cross-check this claim →
              </button>
            </article>
          ))}
        </div>
      </section>

      {/* 5. Participation */}
      <section
        className="section section-muted"
        id="participation"
        aria-labelledby="participation-heading"
      >
        <div className="section-head">
          <h2 id="participation-heading">Participation</h2>
          <p className="support">
            Consequential pathways. Low-effort, high-volume noise is
            structurally discouraged.
          </p>
        </div>
        <div className="role-grid">
          {PATHWAYS.map((p) => (
            <article key={p.title} className="role-card">
              <h3>{p.title}</h3>
              <p>{p.description}</p>
              <button
                type="button"
                className="ghost role-cta"
                onClick={() => {
                  if (p.surface) onNavigate(p.surface);
                  else if (p.target) scrollTo(p.target);
                }}
              >
                {p.action} →
              </button>
            </article>
          ))}
        </div>
      </section>

      {/* Constitutional posture */}
      <section
        className="section"
        id="constitutional-posture"
        aria-labelledby="posture-heading"
      >
        <div className="section-head">
          <h2 id="posture-heading">Constitutional posture</h2>
          <p className="support">
            This domain is meant to stand firm — without dilution.
          </p>
        </div>
        <div className="pillars pillars-tight">
          <article>
            <h3>First Amendment</h3>
            <p>
              Full protection for political and intellectual speech, including
              inconvenient ideas. Not a claim to defamation, fraud, or other
              unprotected categories.
            </p>
          </article>
          <article>
            <h3>Truth-seeking conditions</h3>
            <p>
              Not to declare official truth — to create conditions under which
              better arguments can surface, be tested, and leave a durable
              trace.
            </p>
          </article>
          <article>
            <h3>Against capture and chaos</h3>
            <p>
              Resistance to both invisible constraints dressed as neutrality and
              the flood of low-rigor assertion. Free. Rigorous. Permanent.
            </p>
          </article>
        </div>
        <div className="cta-row section-cta">
          <button
            type="button"
            className="primary"
            onClick={() => onNavigate("net")}
          >
            Read the Record
          </button>
          <button
            type="button"
            className="ghost"
            onClick={() => onNavigate("org")}
          >
            Enter the Theatre
          </button>
          <button
            type="button"
            className="ghost"
            onClick={() => onNavigate("ai")}
          >
            Begin adversarial review
          </button>
        </div>
      </section>
    </>
  );
}
