/** Animated SVG — claim → append flow (motion reveals structure). */

const STEPS = [
  { id: "claim", label: "Claim + Evidence", x: 70 },
  { id: "consent", label: "Consent & Authority", x: 200 },
  { id: "cgr", label: "CGR / Invariants", x: 330 },
  { id: "receipt", label: "Provenance Receipt", x: 460 },
  { id: "append", label: "Append to Log", x: 590 },
];

export default function LivingLogFlow() {
  return (
    <div className="explainer-frame" data-explainer="living-log">
      <svg
        className="explainer-svg living-log-flow"
        viewBox="0 0 720 220"
        role="img"
        aria-label="Living Log flow from claim through append"
      >
        <defs>
          <linearGradient id="flowLine" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="#1f6b5a" stopOpacity="0.15" />
            <stop offset="50%" stopColor="#1f6b5a" stopOpacity="0.85" />
            <stop offset="100%" stopColor="#1f6b5a" stopOpacity="0.25" />
          </linearGradient>
        </defs>

        <line
          className="flow-spine"
          x1="70"
          y1="88"
          x2="590"
          y2="88"
          stroke="url(#flowLine)"
          strokeWidth="2.5"
        />

        {STEPS.map((s, i) => (
          <g key={s.id} className={`flow-step flow-step-${i}`}>
            <circle
              cx={s.x}
              cy="88"
              r="18"
              fill="#ecedea"
              stroke="#1f6b5a"
              strokeWidth="2"
            />
            <text
              x={s.x}
              y="93"
              textAnchor="middle"
              fontSize="11"
              fontFamily="IBM Plex Mono, monospace"
              fill="#1f6b5a"
            >
              {i + 1}
            </text>
            <text
              x={s.x}
              y="140"
              textAnchor="middle"
              fontSize="11"
              fontFamily="Figtree, sans-serif"
              fill="#3a403c"
            >
              {s.label}
            </text>
          </g>
        ))}

        {/* Compounding stack — Log growing richer */}
        <g className="compound-stack" aria-hidden="true">
          {[0, 1, 2, 3, 4].map((n) => (
            <rect
              key={n}
              className={`compound-layer layer-${n}`}
              x={620}
              y={150 - n * 14}
              width={70}
              height={10}
              rx="2"
              fill="#1f6b5a"
              opacity={0.2 + n * 0.15}
            />
          ))}
          <text
            x="655"
            y="185"
            textAnchor="middle"
            fontSize="10"
            fontFamily="Figtree, sans-serif"
            fill="#5a635e"
          >
            Compounds
          </text>
        </g>
      </svg>
      <p className="explainer-so-what">
        So what: contested claims become queryable strategic memory — value
        accrues with every honest append, not every loud take.
      </p>
    </div>
  );
}
