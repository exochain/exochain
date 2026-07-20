import ArenaMark from "../components/ArenaMark.jsx";
import Explainers from "../components/Explainers.jsx";
import LivingLogFlow from "../components/LivingLogFlow.jsx";

const CAMPAIGNS = [
  {
    name: "The Narrative of Inevitable Decline",
    description:
      "Whether civilizational decay is destiny or a story that rewards those who tell it. Contested across media, academia, and policy.",
    status: "Active",
    terrain: "Narrative warfare · institutional morale",
    meritSignal: "Strategist · Proven",
  },
  {
    name: "The Autonomy of the Individual Mind",
    description:
      "Can judgment remain sovereign when attention, memory, and recommendation are industrially optimized against it?",
    status: "Contested",
    terrain: "Cognitive sovereignty · persuasion systems",
    meritSignal: "Analyst · Emerging",
  },
  {
    name: "Synthetic Reality vs Provenance",
    description:
      "When generation is cheap, what survives as history? Provenance becomes the decisive terrain.",
    status: "Active",
    terrain: "Authenticity · receipt chains",
    meritSignal: "Chronicler · Architect",
  },
  {
    name: "Institutional Trust Collapse",
    description:
      "Erosion of shared epistemic authorities — and whether new structures of integrity can replace them.",
    status: "Emerging",
    terrain: "Institutions · legitimacy",
    meritSignal: "Strategist · Proven",
  },
  {
    name: "Multi-Intelligence Alignment",
    description:
      "Human and artificial intelligence under shared rules — or unattested fusion that dissolves accountability.",
    status: "Active",
    terrain: "Attestation · human override",
    meritSignal: "Adversary · Architect",
  },
  {
    name: "Memory Without Compounding",
    description:
      "Discourse that performs and vanishes versus contests that leave a queryable strategic record.",
    status: "Contested",
    terrain: "Living Log · permanence",
    meritSignal: "Chronicler · Architect",
  },
];

const ROLES = [
  {
    id: "observer",
    title: "Observer / Analyst",
    description:
      "Study the terrain, review past contests, understand strategic patterns before you engage.",
    action: "Study the terrain",
    surface: "tv",
  },
  {
    id: "combatant",
    title: "Combatant",
    description:
      "Enter structured intellectual contests under the rules of the arena. Arguments must earn survival.",
    action: "Enter contest",
    surface: "net",
  },
  {
    id: "crosschecker",
    title: "Cross-Checker",
    description:
      "Adversarial analysis and verification grounded in the Living Log. Refuse what cannot be attested.",
    action: "Open CrossCheck",
    surface: "ai",
  },
  {
    id: "strategist",
    title: "Strategist",
    description:
      "Design and track longer campaigns of ideas. Doctrine and dispatches that hold the theatre coherent.",
    action: "Read the spine",
    surface: "press",
  },
  {
    id: "chronicler",
    title: "Chronicler",
    description:
      "Contribute to the permanent record with high-integrity, consent-gated entries.",
    action: "Open the Log",
    surface: "net",
  },
];

const RULES = [
  {
    name: "Consent",
    line: "Nothing enters durable memory without an active consent gate.",
  },
  {
    name: "Provenance",
    line: "Claims that survive must chain. Broken chains are labeled.",
  },
  {
    name: "Multi-Intelligence Transparency",
    line: "Synthetic voices declare themselves. Unattested prose is noise.",
  },
  {
    name: "Human Override",
    line: "Emergency human intervention remains possible. Always.",
  },
  {
    name: "Fail-Closed Enforcement",
    line: "When verify or adjudication cannot run, the system refuses — it does not invent permission.",
  },
  {
    name: "Log Integrity",
    line: "The record compounds. Serious contests leave a lasting, queryable trail.",
  },
];

function scrollTo(id) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
}

export default function OrgSurface({ onNavigate }) {
  return (
    <>
      {/* 1. Threshold */}
      <section className="hero hero-threshold" id="threshold">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.org · Mind War Theatre</p>
          <h1 className="brand brand-theatre">IntelWar</h1>
          <p className="headline headline-theatre">
            You have entered the Mind War Theatre.
          </p>
          <p className="lede lede-theatre">
            A constitutional arena for rigorous intellectual combat — where human
            and artificial intelligence contest ideas under rules of integrity,
            and where the record of those contests becomes permanent strategic
            knowledge.
          </p>
          <p className="subhead-theatre">
            Ideas are contested here under constitutional rules.
            <br />
            The outcomes are preserved.
            <br />
            The memory compounds.
          </p>
          <div className="cta-row">
            <button
              type="button"
              className="primary"
              onClick={() => scrollTo("basic-training")}
            >
              Begin Basic Training
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => scrollTo("active-campaigns")}
            >
              View Active Campaigns
            </button>
          </div>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <ArenaMark />
        </div>
      </section>

      {/* 2. Active Campaigns */}
      <section
        className="section section-board"
        id="active-campaigns"
        aria-labelledby="campaigns-heading"
      >
        <div className="section-head">
          <h2 id="campaigns-heading">Active Campaigns</h2>
          <p className="support">
            Current wars of ideas. Without visible contests, there is no theatre.
          </p>
        </div>
        <div className="campaign-board" role="list">
          {CAMPAIGNS.map((c) => (
            <article key={c.name} className="campaign-card" role="listitem">
              <div className="campaign-meta">
                <span className={`campaign-status status-${c.status.toLowerCase()}`}>
                  {c.status}
                </span>
                <span className="campaign-terrain">{c.terrain}</span>
              </div>
              <h3>{c.name}</h3>
              <p>{c.description}</p>
              {c.meritSignal ? (
                <p className="campaign-merit">
                  High-merit signal · {c.meritSignal}{" "}
                  <button
                    type="button"
                    className="inline-link"
                    onClick={() => onNavigate("net")}
                  >
                    full social on .net →
                  </button>
                </p>
              ) : null}
            </article>
          ))}
        </div>
        <p className="org-social-teaser">
          Profiles, coalitions, and 0dentity reputation are operational — they
          live on{" "}
          <button
            type="button"
            className="inline-link"
            onClick={() => onNavigate("net")}
          >
            intelwar.net
          </button>
          , not on this theatre entrance.
        </p>
      </section>

      {/* 3. Basic Training */}
      <section
        className="section"
        id="basic-training"
        aria-labelledby="training-heading"
      >
        <div className="section-head">
          <h2 id="training-heading">Basic Training</h2>
          <p className="support">
            Orientation for those who intend to engage with seriousness.
          </p>
        </div>

        <div className="training-grid">
          <article className="training-block" id="nature-of-war">
            <h3>1. The Nature of the War</h3>
            <p>
              The information environment is not a neutral commons. Perception,
              reasoning, memory, and decision are contested at scale. Most people
              fight without memory, without rules, and without a permanent record.
              That ends here — not with alarm, but with structure.
            </p>
          </article>

          <article className="training-block" id="rules-of-engagement">
            <h3>2. Rules of Engagement</h3>
            <p>
              The arena is constitutional. These are the rules of the theatre —
              not product features.
            </p>
            <ul className="rules-list">
              {RULES.map((r) => (
                <li key={r.name}>
                  <strong>{r.name}.</strong> {r.line}
                </li>
              ))}
            </ul>
          </article>

          <article className="training-block" id="living-log-training">
            <h3>3. The Living Log</h3>
            <p>
              The permanent strategic record of the theatre. Consent-gated,
              append-only, provenance-chained. Ordinary discourse performs and
              vanishes; here, serious contests leave a lasting, queryable trail.
            </p>
            <LivingLogFlow />
          </article>

          <article className="training-block" id="what-changes">
            <h3>4. What Changes</h3>
            <p>
              When arguments are tested under rules and preserved with integrity,
              strategic knowledge can actually accumulate. Participants do not
              merely argue — they contribute to a body of contested clarity that
              can be audited and built upon.
            </p>
          </article>
        </div>
      </section>

      {/* 4. Find Your Role */}
      <section
        className="section section-muted"
        id="find-your-role"
        aria-labelledby="roles-heading"
      >
        <div className="section-head">
          <h2 id="roles-heading">Find Your Role</h2>
          <p className="support">
            Choose a path inside the theatre — not a product tier.
          </p>
        </div>
        <div className="role-grid">
          {ROLES.map((role) => (
            <article key={role.id} className="role-card">
              <h3>{role.title}</h3>
              <p>{role.description}</p>
              <button
                type="button"
                className="ghost role-cta"
                onClick={() => onNavigate(role.surface)}
              >
                {role.action} →
              </button>
            </article>
          ))}
        </div>
      </section>

      {/* 5. Deployment */}
      <section
        className="section section-deploy"
        id="deployment"
        aria-labelledby="deploy-heading"
      >
        <div className="deploy-panel">
          <h2 id="deploy-heading">Deployment</h2>
          <p className="deploy-lede">
            The arena is open.
            <br />
            The record is permanent.
            <br />
            Enter with intention.
          </p>
          <div className="deploy-actions">
            <button
              type="button"
              className="primary"
              onClick={() => onNavigate("net")}
            >
              Deploy to .net (Social + Log)
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => scrollTo("active-campaigns")}
            >
              View current contests
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => onNavigate("ai")}
            >
              Begin structured engagement
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => scrollTo("constitutional-engine")}
            >
              Review the Constitution
            </button>
          </div>
        </div>
      </section>

      {/* 6. How the Theatre Works — deep tech, secondary */}
      <section
        className="section section-deep"
        id="constitutional-engine"
        aria-labelledby="engine-heading"
      >
        <div className="section-head">
          <h2 id="engine-heading">How the Theatre Works</h2>
          <p className="support">
            The Constitutional Engine — for those who want the machinery. The
            homepage leads with the theatre; this is the substrate.
          </p>
        </div>
        <details className="engine-details">
          <summary>Open the Constitutional Engine</summary>
          <div className="engine-body">
            <p>
              Adjudication runs through EXOCHAIN gatekeeper invariants and
              IntelWar overlays (IW-1…IW-8). Appends are Kernel-required:
              consent wire, provenance, local DAG, optional DAG DB intake.
              This shell remains honest about boundaries — enforcement is proven
              by call path and tests, not by proximity to branding.
            </p>
            <Explainers />
            <div className="cta-row section-cta">
              <button
                type="button"
                className="ghost"
                onClick={() => onNavigate("net")}
              >
                Operational shell (.net)
              </button>
              <button
                type="button"
                className="ghost"
                onClick={() => onNavigate("tv")}
              >
                Filmstrip (.tv)
              </button>
            </div>
          </div>
        </details>
      </section>
    </>
  );
}
