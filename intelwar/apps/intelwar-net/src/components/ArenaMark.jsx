/** Animated SVG mark — contested field + compounding receipt chain. */
export default function ArenaMark({ className = "" }) {
  return (
    <svg
      className={`arena-mark ${className}`}
      viewBox="0 0 720 480"
      role="img"
      aria-label="IntelWar mark: contested field with compounding provenance chain"
    >
      <defs>
        <linearGradient id="fieldFade" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#1f6b5a" stopOpacity="0.35" />
          <stop offset="55%" stopColor="#1f6b5a" stopOpacity="0.08" />
          <stop offset="100%" stopColor="#1f6b5a" stopOpacity="0" />
        </linearGradient>
        <linearGradient id="chainGlow" x1="0" y1="0.5" x2="1" y2="0.5">
          <stop offset="0%" stopColor="#2a6f97" stopOpacity="0" />
          <stop offset="40%" stopColor="#1f6b5a" stopOpacity="0.9" />
          <stop offset="100%" stopColor="#1f6b5a" stopOpacity="0.2" />
        </linearGradient>
      </defs>

      {/* Contested terrain grid */}
      <g className="arena-grid" opacity="0.55">
        {Array.from({ length: 9 }, (_, i) => (
          <line
            key={`h${i}`}
            x1="40"
            y1={60 + i * 40}
            x2="680"
            y2={60 + i * 40}
            stroke="#141816"
            strokeOpacity="0.08"
          />
        ))}
        {Array.from({ length: 13 }, (_, i) => (
          <line
            key={`v${i}`}
            x1={40 + i * 50}
            y1="60"
            x2={40 + i * 50}
            y2="420"
            stroke="#141816"
            strokeOpacity="0.08"
          />
        ))}
      </g>

      <ellipse cx="360" cy="240" rx="260" ry="160" fill="url(#fieldFade)" />

      {/* Orbit rings */}
      <g className="arena-orbits" fill="none" stroke="#1f6b5a" strokeOpacity="0.35">
        <ellipse className="orbit orbit-a" cx="360" cy="240" rx="210" ry="120" />
        <ellipse className="orbit orbit-b" cx="360" cy="240" rx="150" ry="85" />
        <ellipse className="orbit orbit-c" cx="360" cy="240" rx="90" ry="50" />
      </g>

      {/* Receipt chain */}
      <g className="arena-chain">
        <path
          className="chain-path"
          d="M120 300 C220 180, 300 360, 360 240 S500 120, 600 200"
          fill="none"
          stroke="url(#chainGlow)"
          strokeWidth="3"
          strokeLinecap="round"
        />
        {[
          [120, 300],
          [220, 230],
          [300, 300],
          [360, 240],
          [450, 180],
          [520, 160],
          [600, 200],
        ].map(([x, y], i) => (
          <g key={i} className={`node node-${i}`}>
            <circle cx={x} cy={y} r="10" fill="#ecedea" stroke="#1f6b5a" strokeWidth="2" />
            <circle cx={x} cy={y} r="3.5" fill="#1f6b5a" />
          </g>
        ))}
      </g>

      {/* Scanning beam */}
      <g className="arena-scan">
        <line
          x1="360"
          y1="240"
          x2="560"
          y2="140"
          stroke="#1f6b5a"
          strokeOpacity="0.45"
          strokeWidth="1.5"
        />
        <circle cx="560" cy="140" r="5" fill="#2a6f97" className="scan-dot" />
      </g>
    </svg>
  );
}
