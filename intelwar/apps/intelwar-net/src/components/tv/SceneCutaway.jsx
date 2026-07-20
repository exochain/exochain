/**
 * Synthetic b-roll / animated explainer cutaways that serve the argument phase.
 * Decorative only — does not claim Kernel enforcement.
 */
export default function SceneCutaway({ phase, move, heatLabel: heat }) {
  return (
    <svg
      className="scene-cutaway"
      viewBox="0 0 320 220"
      role="img"
      aria-label={`Cutaway for ${phase} phase`}
    >
      <defs>
        <linearGradient id="cut-grad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#1f6b5a" stopOpacity="0.55" />
          <stop offset="100%" stopColor="#2a6f97" stopOpacity="0.35" />
        </linearGradient>
        <pattern id="cut-dots" width="12" height="12" patternUnits="userSpaceOnUse">
          <circle cx="1" cy="1" r="1" fill="rgba(232,235,230,0.2)" />
        </pattern>
      </defs>
      <rect width="320" height="220" fill="#0e1210" />
      <rect width="320" height="220" fill="url(#cut-dots)" />

      {phase === "open" ? <OpenCutaway /> : null}
      {phase === "core" ? <CoreCutaway move={move} /> : null}
      {phase === "close" ? <CloseCutaway /> : null}

      <text x="16" y="28" fill="rgba(232,235,230,0.45)" fontSize="10" fontFamily="monospace">
        CUTAWAY · {String(phase).toUpperCase()} · {String(move || "scene").toUpperCase()}
      </text>
      <text x="16" y="206" fill="rgba(232,235,230,0.35)" fontSize="9" fontFamily="monospace">
        HEAT {heat || "—"} · SYNTHETIC B-ROLL
      </text>
    </svg>
  );
}

function OpenCutaway() {
  return (
    <g className="cut-open">
      <circle cx="160" cy="110" r="48" fill="none" stroke="url(#cut-grad)" strokeWidth="2">
        <animate attributeName="r" values="40;52;40" dur="3.2s" repeatCount="indefinite" />
      </circle>
      <path
        d="M90 140 Q160 60 230 140"
        fill="none"
        stroke="#b8e0d4"
        strokeWidth="1.5"
        strokeDasharray="4 4"
      >
        <animate attributeName="stroke-dashoffset" values="0;24" dur="2s" repeatCount="indefinite" />
      </path>
      <rect x="138" y="96" width="44" height="28" rx="3" fill="url(#cut-grad)" opacity="0.85" />
    </g>
  );
}

function CoreCutaway({ move }) {
  const nodes = [
    [70, 90],
    [160, 70],
    [250, 95],
    [110, 150],
    [210, 155],
  ];
  return (
    <g className="cut-core">
      {nodes.map(([x, y], i) => (
        <g key={`${x}-${y}`}>
          <circle cx={x} cy={y} r={move === "evidence" ? 7 : 5} fill="#1f6b5a">
            <animate
              attributeName="opacity"
              values="0.4;1;0.4"
              dur={`${2 + (i % 3)}s`}
              repeatCount="indefinite"
            />
          </circle>
          {i < nodes.length - 1 ? (
            <line
              x1={x}
              y1={y}
              x2={nodes[i + 1][0]}
              y2={nodes[i + 1][1]}
              stroke="rgba(184,224,212,0.45)"
              strokeWidth="1"
            />
          ) : null}
        </g>
      ))}
      <rect
        x="120"
        y="100"
        width="80"
        height="36"
        rx="4"
        fill="none"
        stroke="#2a6f97"
        strokeWidth="1.5"
      />
      <text x="132" y="122" fill="#e8ebe6" fontSize="11" fontFamily="sans-serif">
        {move === "rebuttal" ? "COUNTER" : move === "reframe" ? "REFRAME" : "CORE"}
      </text>
    </g>
  );
}

function CloseCutaway() {
  return (
    <g className="cut-close">
      <polyline
        points="60,150 110,90 160,120 210,70 260,110"
        fill="none"
        stroke="#b8e0d4"
        strokeWidth="2"
      >
        <animate attributeName="points"
          values="60,150 110,90 160,120 210,70 260,110;60,140 110,100 160,110 210,80 260,100;60,150 110,90 160,120 210,70 260,110"
          dur="4s"
          repeatCount="indefinite"
        />
      </polyline>
      <circle cx="260" cy="110" r="6" fill="#2a6f97" />
      <text x="210" y="170" fill="rgba(232,235,230,0.55)" fontSize="10" fontFamily="monospace">
        FORWARD / BACK PULL
      </text>
    </g>
  );
}
