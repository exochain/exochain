import ArenaMark from "../components/ArenaMark.jsx";
import Explainers from "../components/Explainers.jsx";
import LivingLogFlow from "../components/LivingLogFlow.jsx";

export default function OrgSurface({ onNavigate }) {
  return (
    <>
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">IntelWar.org · Foundation</p>
          <h1 className="brand">IntelWar</h1>
          <p className="headline">
            The constitutional arena for rigorous intellectual combat. Human +
            AI. Compounding strategic memory.
          </p>
          <p className="lede">
            Disciplined arena + living strategic memory for rigorous intellectual
            combat in the age of cognitive warfare. Ideas are contested under
            enforceable rules; the record compounds. This shell is adjacent —
            Kernel adjudication is not claimed by proximity.
          </p>
          <div className="cta-row">
            <button
              type="button"
              className="primary"
              onClick={() => onNavigate("net")}
            >
              Enter the Arena
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() =>
                document.getElementById("living-log-explainer")?.scrollIntoView({
                  behavior: "smooth",
                })
              }
            >
              Explore the Living Log
            </button>
          </div>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <ArenaMark />
        </div>
      </section>

      <section className="section" id="about" aria-labelledby="about-heading">
        <div className="section-head">
          <h2 id="about-heading">Why this exists</h2>
          <p className="support">
            Not better discourse theater — infrastructure for those who refuse to
            outsource their thinking.
          </p>
        </div>
        <ol className="narrative-arc">
          <li>
            <h3>Ordinary world</h3>
            <p>
              Speed and performance crowd out rigor. Serious thought is
              fragmented, ephemeral, easily corrupted.
            </p>
          </li>
          <li>
            <h3>Call</h3>
            <p>
              The environment is not neutral. Actors actively degrade collective
              sensemaking at scale.
            </p>
          </li>
          <li>
            <h3>Tension</h3>
            <p>
              Most tools pretend neutrality — or accelerate the problem for
              engagement.
            </p>
          </li>
          <li>
            <h3>Threshold</h3>
            <p>
              Structured contest under constitutional rules, with a living record
              that compounds.
            </p>
          </li>
          <li>
            <h3>Transformation</h3>
            <p>
              Participants do not merely argue. They contribute to strategic
              knowledge that can be queried, audited, and built upon.
            </p>
          </li>
          <li>
            <h3>Return</h3>
            <p>
              The output is not opinions — clarity, resilience, and accumulated
              strategic advantage.
            </p>
          </li>
        </ol>
      </section>

      <section className="section section-muted" id="cognitive-warfare">
        <div className="section-head">
          <h2>Cognitive warfare — context</h2>
          <p className="support">
            High-level posture, not alarmism. The cognitive domain is contested;
            IntelWar is cognitive defense infrastructure for rigorous thought.
          </p>
        </div>
        <div className="pillars pillars-tight">
          <article>
            <h3>Contested cognition</h3>
            <p>
              Perception, reasoning, memory, and decision are targeted — not
              merely “debated.”
            </p>
          </article>
          <article>
            <h3>Multi-intelligence</h3>
            <p>
              Human judgment and AI capability participate under attestation,
              consent, and human override.
            </p>
          </article>
          <article>
            <h3>Constitutional rules</h3>
            <p>
              Invariants IW-1…IW-8 bound the arena. Structure is what makes
              contest honest.
            </p>
          </article>
        </div>
      </section>

      <section className="section" id="living-log-explainer">
        <div className="section-head">
          <h2>The Living Log</h2>
          <p className="support">
            Claim to append — consent, invariants, provenance, then durable
            memory. Value compounds over time.
          </p>
        </div>
        <LivingLogFlow />
        <div className="cta-row section-cta">
          <button
            type="button"
            className="primary"
            onClick={() => onNavigate("net")}
          >
            Explore the Living Log
          </button>
          <button
            type="button"
            className="ghost"
            onClick={() => onNavigate("tv")}
          >
            Review provenance
          </button>
        </div>
      </section>

      <section className="section" id="explainers">
        <div className="section-head">
          <h2>Explainers</h2>
          <p className="support">
            Four concepts. Minimal text. Motion that reveals structure.
          </p>
        </div>
        <Explainers />
      </section>

      <section className="surface-rail" aria-label="Open a surface">
        <button type="button" className="rail-card" onClick={() => onNavigate("press")}>
          <span className="rail-label">.press</span>
          <strong>Spine</strong>
          <span>Dispatches with provenance</span>
        </button>
        <button type="button" className="rail-card" onClick={() => onNavigate("net")}>
          <span className="rail-label">.net</span>
          <strong>Living Log</strong>
          <span>Enter the arena</span>
        </button>
        <button type="button" className="rail-card" onClick={() => onNavigate("ai")}>
          <span className="rail-label">.ai</span>
          <strong>CrossCheck</strong>
          <span>Adversarial verify</span>
        </button>
        <button type="button" className="rail-card" onClick={() => onNavigate("tv")}>
          <span className="rail-label">.tv</span>
          <strong>Provenance</strong>
          <span>Audit the chain</span>
        </button>
      </section>
    </>
  );
}
