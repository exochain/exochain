import { useState } from "react";

const ITEMS = [
  {
    id: "living-log",
    title: "What is the Living Log?",
    hook: "Serious thought should accumulate — not vanish into the feed.",
    body: "A consent-gated, append-only record where claims earn survival under constitutional rules. Each row chains to what came before. Over time the Log compounds into strategic knowledge you can audit and query.",
    soWhat:
      "Infrastructure for memory with integrity — not another timeline of performance.",
  },
  {
    id: "cognitive-age",
    title: "Intellectual Combat in the Cognitive Age",
    hook: "The information environment is contested terrain — not a neutral commons.",
    body: "Actors target perception, reasoning, and decision at scale. Unstructured noise rewards speed over rigor. IntelWar answers with structured contest and a permanent record that resists erasure and corruption.",
    soWhat:
      "Combat with memory is cognitive defense — clarity that outlasts the news cycle.",
  },
  {
    id: "multi-intel",
    title: "Multi-Intelligence Arena",
    hook: "Human judgment and AI capability — under rules, not vibes.",
    body: "Synthetic voices must attest. Human override remains possible. CrossCheck can refuse when verify is unset. Power is controlled by constitution, not proximity to a model.",
    soWhat:
      "Multi-intelligence without attestation is theater. With rules, it is an instrument.",
  },
  {
    id: "structure",
    title: "Why Structure Matters",
    hook: "Free-for-all discourse does not produce durable strategic knowledge.",
    body: "Constitutional invariants, consent gates, and provenance receipts turn argument into an auditable chain. Structure is what makes freedom of contest meaningful — and what makes the record worth keeping.",
    soWhat:
      "Without structure, you get noise. With it, you get integrity that compounds.",
  },
];

export default function Explainers() {
  const [active, setActive] = useState(ITEMS[0].id);
  const current = ITEMS.find((i) => i.id === active) || ITEMS[0];

  return (
    <div className="explainers" data-panel="explainers">
      <div className="explainer-tabs" role="tablist" aria-label="Explainers">
        {ITEMS.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={active === item.id}
            className={`explainer-tab ${active === item.id ? "is-active" : ""}`}
            onClick={() => setActive(item.id)}
          >
            {item.title}
          </button>
        ))}
      </div>
      <div className="explainer-panel" role="tabpanel">
        <StructureSvg concept={current.id} />
        <div className="explainer-copy">
          <p className="explainer-hook">{current.hook}</p>
          <p>{current.body}</p>
          <p className="explainer-so-what">{current.soWhat}</p>
        </div>
      </div>
    </div>
  );
}

function StructureSvg({ concept }) {
  return (
    <svg
      className={`explainer-svg concept-${concept}`}
      viewBox="0 0 320 180"
      role="img"
      aria-hidden="true"
    >
      {concept === "living-log" ? <LivingLogMini /> : null}
      {concept === "cognitive-age" ? <TerrainMini /> : null}
      {concept === "multi-intel" ? <ArenaMini /> : null}
      {concept === "structure" ? <StructureMini /> : null}
    </svg>
  );
}

function LivingLogMini() {
  return (
    <g className="mini-log">
      {[0, 1, 2, 3].map((i) => (
        <rect
          key={i}
          className={`mini-layer l${i}`}
          x={40 + i * 8}
          y={120 - i * 22}
          width={200 - i * 16}
          height="16"
          rx="3"
          fill="#1f6b5a"
          opacity={0.25 + i * 0.18}
        />
      ))}
    </g>
  );
}

function TerrainMini() {
  return (
    <g className="mini-terrain">
      <path
        className="noise"
        d="M20 140 Q80 40 160 100 T300 60"
        fill="none"
        stroke="#8b5a2b"
        strokeOpacity="0.35"
        strokeWidth="2"
        strokeDasharray="4 6"
      />
      <path
        className="structure"
        d="M20 140 L100 140 L100 80 L180 80 L180 120 L260 120 L260 50 L300 50"
        fill="none"
        stroke="#1f6b5a"
        strokeWidth="2.5"
      />
    </g>
  );
}

function ArenaMini() {
  return (
    <g className="mini-arena">
      <circle className="human" cx="110" cy="90" r="28" fill="none" stroke="#1f6b5a" strokeWidth="2" />
      <circle className="ai" cx="210" cy="90" r="28" fill="none" stroke="#2a6f97" strokeWidth="2" strokeDasharray="5 4" />
      <line x1="138" y1="90" x2="182" y2="90" stroke="#141816" strokeOpacity="0.25" />
      <text x="110" y="95" textAnchor="middle" fontSize="10" fill="#1f6b5a">H</text>
      <text x="210" y="95" textAnchor="middle" fontSize="10" fill="#2a6f97">AI</text>
    </g>
  );
}

function StructureMini() {
  return (
    <g className="mini-structure">
      <rect className="chaos" x="30" y="40" width="100" height="100" fill="#141816" opacity="0.06" />
      <circle cx="55" cy="70" r="4" fill="#141816" opacity="0.2" />
      <circle cx="90" cy="110" r="4" fill="#141816" opacity="0.2" />
      <circle cx="70" cy="90" r="4" fill="#141816" opacity="0.2" />
      <g className="ordered">
        <rect x="180" y="50" width="100" height="20" rx="2" fill="#1f6b5a" opacity="0.2" />
        <rect x="180" y="80" width="100" height="20" rx="2" fill="#1f6b5a" opacity="0.35" />
        <rect x="180" y="110" width="100" height="20" rx="2" fill="#1f6b5a" opacity="0.5" />
      </g>
    </g>
  );
}
