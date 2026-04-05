//! 0dentity Dashboard — self-contained HTML dashboard.
//!
//! Serves `GET /0dentity/dashboard/:did` as a single HTML document with all
//! CSS and JavaScript inlined.  The page polls `GET /api/v1/0dentity/:did/score`
//! every 5 seconds to keep the polar graph live.
//!
//! Spec reference: §8 (Dashboard).

use axum::{Router, extract::Path, response::Html, routing::get};

/// Route: `GET /0dentity/dashboard/:did`
pub async fn zerodentity_dashboard(Path(did): Path<String>) -> Html<String> {
    // Escape DID for safe inline use — DIDs only contain alphanumeric chars
    // and colons, so this is a formatting concern rather than XSS risk.
    let escaped = did.replace('"', "&quot;");
    Html(DASHBOARD_HTML.replace("{DID}", &escaped))
}

/// Router for the 0dentity dashboard endpoint.
pub fn zerodentity_dashboard_router() -> Router {
    Router::new().route("/0dentity/dashboard/:did", get(zerodentity_dashboard))
}

// ---------------------------------------------------------------------------
// Self-contained HTML (§8)
// ---------------------------------------------------------------------------

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>0dentity Dashboard</title>
<style>
  :root {
    --primary: #38bdf8;
    --bg: #0a0e17;
    --bg-card: #141b2a;
    --border: #1e2940;
    --text: #e2e8f0;
    --dim: #64748b;
    --green: #22c55e;
    --amber: #f59e0b;
    --red: #ef4444;
    --font: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: var(--font); background: var(--bg); color: var(--text); min-height: 100vh; }

  /* Header */
  .header {
    padding: 1rem 2rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
  .header-brand { color: var(--primary); font-size: 1.1rem; font-weight: 700; letter-spacing: 0.05em; }
  .header-did { color: var(--dim); font-size: 0.75rem; word-break: break-all; max-width: 50%; }
  .header-score { font-size: 1.5rem; font-weight: 700; color: var(--text); }
  .header-score span { font-size: 0.75rem; color: var(--dim); }
  .header-right { display: flex; align-items: center; gap: 1rem; }
  .status-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--green); display: inline-block;
    box-shadow: 0 0 6px var(--green);
    animation: pulse-dot 2s infinite;
  }
  @keyframes pulse-dot { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }

  /* Main layout */
  .main { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; padding: 1.5rem 2rem; }
  @media (max-width: 900px) { .main { grid-template-columns: 1fr; } }

  /* Card */
  .card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
  }
  .card-title {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--dim);
    margin-bottom: 1.25rem;
  }

  /* Polar graph */
  .graph-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.75rem;
  }
  .graph-container {
    width: 100%;
    max-width: 400px;
    position: relative;
  }
  #polarSvg {
    width: 100%;
    height: auto;
    display: block;
  }
  .composite-center {
    position: absolute;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
    pointer-events: none;
  }
  .composite-value { font-size: 2rem; font-weight: 700; color: var(--text); line-height: 1; }
  .composite-label { font-size: 0.65rem; color: var(--dim); text-transform: uppercase; letter-spacing: 0.08em; }
  .symmetry-row { font-size: 0.75rem; color: var(--dim); }
  .symmetry-row span { color: var(--primary); }

  /* Axis breakdown */
  .axis-list { display: flex; flex-direction: column; gap: 0.6rem; }
  .axis-row { display: flex; align-items: center; gap: 0.75rem; }
  .axis-name { width: 140px; font-size: 0.75rem; color: var(--dim); flex-shrink: 0; }
  .axis-bar-wrap { flex: 1; height: 6px; background: rgba(30,41,64,1); border-radius: 3px; overflow: hidden; }
  .axis-bar { height: 100%; border-radius: 3px; background: var(--primary); transition: width 0.8s ease; }
  .axis-value { width: 32px; text-align: right; font-size: 0.8rem; color: var(--text); }

  /* Claims table */
  .full-width { grid-column: 1 / -1; }
  .claims-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
  .claims-table th {
    text-align: left;
    padding: 0.5rem 0.75rem;
    color: var(--dim);
    border-bottom: 1px solid var(--border);
    text-transform: uppercase;
    font-size: 0.65rem;
    letter-spacing: 0.06em;
  }
  .claims-table td { padding: 0.55rem 0.75rem; border-bottom: 1px solid rgba(30,41,64,0.5); vertical-align: middle; }
  .claims-table tr:last-child td { border-bottom: none; }
  .claims-table tr:hover td { background: rgba(30,41,64,0.4); }
  .status-badge {
    display: inline-block;
    padding: 0.15rem 0.45rem;
    border-radius: 4px;
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .badge-verified { background: rgba(34,197,94,0.15); color: var(--green); }
  .badge-pending { background: rgba(245,158,11,0.15); color: var(--amber); }
  .badge-expired { background: rgba(239,68,68,0.15); color: var(--red); }
  .badge-revoked { background: rgba(100,116,139,0.15); color: var(--dim); }
  .hash-cell { color: var(--primary); font-size: 0.7rem; }

  /* Score history card */
  .history-timeline { display: flex; flex-direction: column; gap: 0.5rem; max-height: 240px; overflow-y: auto; }
  .history-item { display: flex; align-items: center; gap: 1rem; font-size: 0.75rem; padding: 0.5rem 0; border-bottom: 1px solid rgba(30,41,64,0.5); }
  .history-item:last-child { border-bottom: none; }
  .history-ts { color: var(--dim); flex-shrink: 0; }
  .history-score { color: var(--primary); font-weight: 600; width: 48px; }
  .history-claims { color: var(--dim); font-size: 0.7rem; }

  /* Growth actions */
  .growth-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
  @media (max-width: 600px) { .growth-grid { grid-template-columns: 1fr; } }
  .growth-card {
    background: rgba(30,41,64,0.5);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
    cursor: pointer;
    transition: border-color 0.2s, background 0.2s;
  }
  .growth-card:hover { border-color: var(--primary); background: rgba(56,189,248,0.05); }
  .growth-icon { font-size: 1.3rem; margin-bottom: 0.4rem; }
  .growth-title { font-size: 0.78rem; font-weight: 600; color: var(--text); margin-bottom: 0.2rem; }
  .growth-desc { font-size: 0.68rem; color: var(--dim); line-height: 1.4; }
  .growth-impact { font-size: 0.65rem; color: var(--green); font-weight: 600; margin-top: 0.4rem; }

  /* Fingerprint consistency */
  .fp-list { display: flex; flex-direction: column; gap: 0.5rem; }
  .fp-item { display: flex; align-items: center; gap: 0.75rem; padding: 0.5rem 0; border-bottom: 1px solid rgba(30,41,64,0.5); }
  .fp-item:last-child { border-bottom: none; }
  .fp-hash { font-size: 0.7rem; color: var(--primary); width: 80px; flex-shrink: 0; }
  .fp-bar-wrap { flex: 1; height: 6px; background: rgba(30,41,64,1); border-radius: 3px; overflow: hidden; }
  .fp-bar { height: 100%; border-radius: 3px; transition: width 0.8s ease; }
  .fp-bar-high { background: var(--green); }
  .fp-bar-med { background: var(--amber); }
  .fp-bar-low { background: var(--red); }
  .fp-value { width: 40px; text-align: right; font-size: 0.75rem; color: var(--text); flex-shrink: 0; }
  .fp-signals { font-size: 0.65rem; color: var(--dim); width: 60px; text-align: right; flex-shrink: 0; }
  .fp-time { font-size: 0.65rem; color: var(--dim); width: 60px; flex-shrink: 0; }

  /* Empty state */
  .empty { text-align: center; padding: 2rem; color: var(--dim); font-size: 0.8rem; }

  /* Last updated indicator */
  .last-updated { font-size: 0.65rem; color: var(--dim); text-align: right; margin-top: 0.75rem; }
  .last-updated span { color: var(--text); }

  /* Error banner */
  .error-banner {
    display: none;
    background: rgba(239,68,68,0.1);
    border: 1px solid rgba(239,68,68,0.3);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    color: var(--red);
    font-size: 0.78rem;
    margin: 1rem 2rem 0;
  }
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="header-brand">◈ 0dentity</div>
    <div class="header-did" id="headerDid" title="{DID}">{DID}</div>
  </div>
  <div class="header-right">
    <span class="status-dot" id="statusDot"></span>
    <div>
      <div class="header-score" id="headerScore">—<span> / 100</span></div>
    </div>
  </div>
</div>

<div class="error-banner" id="errorBanner"></div>

<div class="main">

  <!-- Polar graph card -->
  <div class="card">
    <div class="card-title">Trust Polygon</div>
    <div class="graph-wrap">
      <div class="graph-container">
        <svg id="polarSvg" viewBox="0 0 400 400"></svg>
        <div class="composite-center">
          <div class="composite-value" id="compositeValue">—</div>
          <div class="composite-label">composite</div>
        </div>
      </div>
      <div class="symmetry-row">Symmetry index: <span id="symmetryValue">—</span></div>
    </div>
    <div class="last-updated">Last updated: <span id="lastUpdated">—</span></div>
  </div>

  <!-- Axis breakdown card -->
  <div class="card">
    <div class="card-title">Score Breakdown</div>
    <div class="axis-list" id="axisList">
      <div class="empty">Loading score…</div>
    </div>
  </div>

  <!-- Claims table — full width -->
  <div class="card full-width">
    <div class="card-title">Identity Claims</div>
    <div id="claimsWrap"><div class="empty">Loading claims…</div></div>
  </div>

  <!-- Score history -->
  <div class="card">
    <div class="card-title">Score History</div>
    <div class="history-timeline" id="historyList">
      <div class="empty">Loading history…</div>
    </div>
  </div>

  <!-- Fingerprint consistency -->
  <div class="card">
    <div class="card-title">Fingerprint Consistency</div>
    <div class="fp-list" id="fpList">
      <div class="empty">Loading fingerprints…</div>
    </div>
  </div>

  <!-- Growth actions — full width -->
  <div class="card full-width">
    <div class="card-title">Grow Your Score</div>
    <div class="growth-grid" id="growthGrid">
      <div class="growth-card" onclick="alert('Navigate to identity verification to add a Government ID claim.')">
        <div class="growth-icon">🪪</div>
        <div class="growth-title">Add Government ID</div>
        <div class="growth-desc">Submit a government-issued identification for credential depth verification.</div>
        <div class="growth-impact">+35 credential depth</div>
      </div>
      <div class="growth-card" onclick="alert('Ask a verified peer to attest your identity.')">
        <div class="growth-icon">🤝</div>
        <div class="growth-title">Request Peer Attestation</div>
        <div class="growth-desc">Have a verified peer vouch for your identity to boost network reputation.</div>
        <div class="growth-impact">+5 network reputation</div>
      </div>
      <div class="growth-card" onclick="alert('Participate in governance to boost your constitutional standing.')">
        <div class="growth-icon">🗳️</div>
        <div class="growth-title">Cast a Governance Vote</div>
        <div class="growth-desc">Participate in governance decisions to demonstrate constitutional engagement.</div>
        <div class="growth-impact">+4 constitutional standing</div>
      </div>
      <div class="growth-card" onclick="alert('Rotate your Ed25519 key pair to improve cryptographic strength.')">
        <div class="growth-icon">🔑</div>
        <div class="growth-title">Rotate Cryptographic Key</div>
        <div class="growth-desc">Rotate your Ed25519 key pair to demonstrate key hygiene and freshness.</div>
        <div class="growth-impact">+8 cryptographic strength</div>
      </div>
    </div>
  </div>

</div>

<script>
(function() {
  'use strict';

  const DID = "{DID}";
  const POLL_INTERVAL_MS = 5000;

  // Axis order matches PolarAxes struct field order in spec §2.2
  const AXIS_LABELS = [
    ['constitutional_standing', 'Constitutional'],
    ['communication',           'Communication'],
    ['credential_depth',        'Cred. Depth'],
    ['device_trust',            'Device Trust'],
    ['behavioral_signature',    'Behavioral'],
    ['network_reputation',      'Network Rep.'],
    ['temporal_stability',      'Temporal'],
    ['cryptographic_strength',  'Crypto Str.'],
  ];

  // Polar graph axis order (matches §6.1 — starts at 12-o'clock, clockwise)
  const POLAR_AXIS_ORDER = [
    'constitutional_standing',
    'communication',
    'credential_depth',
    'device_trust',
    'behavioral_signature',
    'network_reputation',
    'temporal_stability',
    'cryptographic_strength',
  ];

  // ---------------------------------------------------------------------------
  // SVG polar graph (§6.1)
  // ---------------------------------------------------------------------------

  const NS = 'http://www.w3.org/2000/svg';
  const SIZE = 400;
  const CENTER = SIZE / 2;
  const RADIUS = SIZE * 0.38;
  const AXIS_COUNT = 8;
  const AXIS_ANGLE = (2 * Math.PI) / AXIS_COUNT;
  const START_ANGLE = -Math.PI / 2;  // 12 o'clock

  const COLORS = {
    gridLine:     'rgba(148, 163, 184, 0.15)',
    axisLine:     'rgba(148, 163, 184, 0.3)',
    maxPolygon:   'rgba(56, 189, 248, 0.08)',
    maxStroke:    'rgba(56, 189, 248, 0.2)',
    scorePolygon: 'rgba(56, 189, 248, 0.25)',
    scoreStroke:  'rgba(56, 189, 248, 0.9)',
    scoreDot:     '#38bdf8',
    labelText:    '#94a3b8',
    valueText:    '#e2e8f0',
  };

  const POLAR_AXIS_LABELS = [
    'Constitutional\nStanding',
    'Communication',
    'Credential\nDepth',
    'Device\nTrust',
    'Behavioral\nSignature',
    'Network\nReputation',
    'Temporal\nStability',
    'Cryptographic\nStrength',
  ];

  const svg = document.getElementById('polarSvg');
  let scorePolygon, valueDots = [], currentValues = Array(8).fill(0);

  function initGraph() {
    // Concentric grid rings at 20%, 40%, 60%, 80%, 100%
    for (let ring = 1; ring <= 5; ring++) {
      const r = RADIUS * (ring / 5);
      const circle = document.createElementNS(NS, 'circle');
      circle.setAttribute('cx', CENTER);
      circle.setAttribute('cy', CENTER);
      circle.setAttribute('r', r);
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', COLORS.gridLine);
      circle.setAttribute('stroke-width', ring === 5 ? '1.5' : '0.75');
      svg.appendChild(circle);
    }

    // Axis lines and labels
    for (let i = 0; i < AXIS_COUNT; i++) {
      const angle = START_ANGLE + i * AXIS_ANGLE;
      const x2 = CENTER + RADIUS * Math.cos(angle);
      const y2 = CENTER + RADIUS * Math.sin(angle);

      const line = document.createElementNS(NS, 'line');
      line.setAttribute('x1', CENTER); line.setAttribute('y1', CENTER);
      line.setAttribute('x2', x2);    line.setAttribute('y2', y2);
      line.setAttribute('stroke', COLORS.axisLine);
      line.setAttribute('stroke-width', '1');
      svg.appendChild(line);

      const labelR = RADIUS + 30;
      const lx = CENTER + labelR * Math.cos(angle);
      const ly = CENTER + labelR * Math.sin(angle);
      const text = document.createElementNS(NS, 'text');
      text.setAttribute('x', lx);
      text.setAttribute('y', ly);
      text.setAttribute('text-anchor', 'middle');
      text.setAttribute('dominant-baseline', 'middle');
      text.setAttribute('fill', COLORS.labelText);
      text.setAttribute('font-size', '10');
      text.setAttribute('font-family', 'ui-monospace, monospace');
      const lineTexts = POLAR_AXIS_LABELS[i].split('\n');
      lineTexts.forEach((t, li) => {
        const tspan = document.createElementNS(NS, 'tspan');
        tspan.setAttribute('x', lx);
        tspan.setAttribute('dy', li === 0 ? '0' : '1.2em');
        tspan.textContent = t;
        text.appendChild(tspan);
      });
      svg.appendChild(text);
    }

    // Max polygon (faint outline at 100%)
    const maxPoly = document.createElementNS(NS, 'polygon');
    maxPoly.setAttribute('points', polygonPoints(Array(8).fill(100)));
    maxPoly.setAttribute('fill', COLORS.maxPolygon);
    maxPoly.setAttribute('stroke', COLORS.maxStroke);
    maxPoly.setAttribute('stroke-width', '1');
    svg.appendChild(maxPoly);

    // Score polygon
    scorePolygon = document.createElementNS(NS, 'polygon');
    scorePolygon.setAttribute('points', polygonPoints(Array(8).fill(0)));
    scorePolygon.setAttribute('fill', COLORS.scorePolygon);
    scorePolygon.setAttribute('stroke', COLORS.scoreStroke);
    scorePolygon.setAttribute('stroke-width', '2');
    svg.appendChild(scorePolygon);

    // Score dots
    for (let i = 0; i < AXIS_COUNT; i++) {
      const dot = document.createElementNS(NS, 'circle');
      dot.setAttribute('cx', CENTER); dot.setAttribute('cy', CENTER);
      dot.setAttribute('r', '4');
      dot.setAttribute('fill', COLORS.scoreDot);
      svg.appendChild(dot);
      valueDots.push(dot);
    }
  }

  function polygonPoints(values) {
    return values.map((v, i) => {
      const angle = START_ANGLE + i * AXIS_ANGLE;
      const r = RADIUS * (v / 100);
      return `${CENTER + r * Math.cos(angle)},${CENTER + r * Math.sin(angle)}`;
    }).join(' ');
  }

  function updatePolygon(values) {
    scorePolygon.setAttribute('points', polygonPoints(values));
    for (let i = 0; i < AXIS_COUNT; i++) {
      const angle = START_ANGLE + i * AXIS_ANGLE;
      const r = RADIUS * (values[i] / 100);
      valueDots[i].setAttribute('cx', CENTER + r * Math.cos(angle));
      valueDots[i].setAttribute('cy', CENTER + r * Math.sin(angle));
    }
  }

  function ease(t) {
    return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
  }

  function animateTo(targetValues, duration = 1200) {
    const startValues = [...currentValues];
    const startTime = performance.now();
    function frame(now) {
      const progress = Math.min((now - startTime) / duration, 1);
      const ep = ease(progress);
      const current = startValues.map((s, i) => s + (targetValues[i] - s) * ep);
      updatePolygon(current);
      if (progress < 1) requestAnimationFrame(frame);
      else currentValues = [...targetValues];
    }
    requestAnimationFrame(frame);
  }

  // ---------------------------------------------------------------------------
  // Data fetching
  // ---------------------------------------------------------------------------

  function setError(msg) {
    const banner = document.getElementById('errorBanner');
    if (msg) {
      banner.textContent = msg;
      banner.style.display = 'block';
    } else {
      banner.style.display = 'none';
    }
  }

  async function fetchScore() {
    const res = await fetch(`/api/v1/0dentity/${encodeURIComponent(DID)}/score`);
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`Score fetch failed: ${res.status}`);
    return res.json();
  }

  async function fetchClaims() {
    const res = await fetch(`/api/v1/0dentity/${encodeURIComponent(DID)}/claims`);
    if (res.status === 404 || res.status === 403) return { claims: [] };
    if (!res.ok) return { claims: [] };
    return res.json();
  }

  async function fetchHistory() {
    const res = await fetch(`/api/v1/0dentity/${encodeURIComponent(DID)}/score/history`);
    if (!res.ok) return { snapshots: [] };
    return res.json();
  }

  function renderScore(score) {
    if (!score) {
      document.getElementById('headerScore').innerHTML = '—<span> / 100</span>';
      document.getElementById('compositeValue').textContent = '—';
      document.getElementById('symmetryValue').textContent = '—';
      document.getElementById('axisList').innerHTML = '<div class="empty">No score available yet.</div>';
      animateTo(Array(8).fill(0));
      return;
    }

    const composite = score.composite != null ? score.composite.toFixed(1) : '—';
    document.getElementById('headerScore').innerHTML = `${composite}<span> / 100</span>`;
    document.getElementById('compositeValue').textContent = composite;
    document.getElementById('symmetryValue').textContent =
      score.symmetry != null ? score.symmetry.toFixed(3) : '—';

    const axes = score.axes || {};
    const values = POLAR_AXIS_ORDER.map(k => axes[k] ?? 0);
    animateTo(values);

    const listEl = document.getElementById('axisList');
    listEl.innerHTML = AXIS_LABELS.map(([key, label]) => {
      const val = axes[key] ?? 0;
      const pct = Math.min(Math.max(val, 0), 100);
      return `
        <div class="axis-row">
          <div class="axis-name">${label}</div>
          <div class="axis-bar-wrap">
            <div class="axis-bar" style="width:${pct}%"></div>
          </div>
          <div class="axis-value">${pct.toFixed(0)}</div>
        </div>`;
    }).join('');

    const ts = score.computed_ms ? new Date(score.computed_ms).toLocaleTimeString() : '—';
    document.getElementById('lastUpdated').innerHTML = `<span>${ts}</span>`;
  }

  function claimStatusClass(status) {
    const map = { Verified: 'badge-verified', Pending: 'badge-pending', Expired: 'badge-expired', Revoked: 'badge-revoked' };
    return map[status] || 'badge-pending';
  }

  function shortHash(hex) {
    if (!hex || hex.length < 12) return hex || '—';
    return `${hex.slice(0, 6)}…${hex.slice(-4)}`;
  }

  function relativeTime(ms) {
    if (!ms) return '—';
    const secs = Math.floor((Date.now() - ms) / 1000);
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return new Date(ms).toLocaleDateString();
  }

  function renderClaims(data) {
    const claims = (data && data.claims) ? data.claims : [];
    const wrap = document.getElementById('claimsWrap');
    if (claims.length === 0) {
      wrap.innerHTML = '<div class="empty">No claims found.</div>';
      return;
    }
    wrap.innerHTML = `
      <table class="claims-table">
        <thead>
          <tr>
            <th>Type</th>
            <th>Hash</th>
            <th>Status</th>
            <th>Verified</th>
            <th>Expires</th>
          </tr>
        </thead>
        <tbody>
          ${claims.map(c => `
            <tr>
              <td>${c.claim_type || '—'}</td>
              <td class="hash-cell">${shortHash(c.claim_hash)}</td>
              <td><span class="status-badge ${claimStatusClass(c.status)}">${c.status || '—'}</span></td>
              <td>${relativeTime(c.verified_ms)}</td>
              <td>${c.expires_ms ? relativeTime(c.expires_ms) : 'Never'}</td>
            </tr>`).join('')}
        </tbody>
      </table>`;
  }

  function renderHistory(data) {
    const snapshots = (data && data.snapshots) ? data.snapshots : [];
    const listEl = document.getElementById('historyList');
    if (snapshots.length === 0) {
      listEl.innerHTML = '<div class="empty">No score history yet.</div>';
      return;
    }
    // Show most-recent first
    const sorted = [...snapshots].sort((a, b) => (b.computed_ms || 0) - (a.computed_ms || 0));
    listEl.innerHTML = sorted.map(s => `
      <div class="history-item">
        <div class="history-ts">${s.computed_ms ? new Date(s.computed_ms).toLocaleString() : '—'}</div>
        <div class="history-score">${s.composite != null ? s.composite.toFixed(1) : '—'}</div>
        <div class="history-claims">${s.claim_count != null ? `${s.claim_count} claims` : ''}</div>
      </div>`).join('');
  }

  async function fetchFingerprints() {
    // Fingerprints require auth — try without token first; if 401, skip gracefully
    const res = await fetch(`/api/v1/0dentity/${encodeURIComponent(DID)}/fingerprints`);
    if (res.status === 401 || res.status === 403) return { fingerprints: [] };
    if (!res.ok) return { fingerprints: [] };
    return res.json();
  }

  function renderFingerprints(data) {
    const fps = (data && data.fingerprints) ? data.fingerprints : [];
    const listEl = document.getElementById('fpList');
    if (fps.length === 0) {
      listEl.innerHTML = '<div class="empty">No fingerprint sessions recorded yet.</div>';
      return;
    }
    // Sort most recent first
    const sorted = [...fps].sort((a, b) => (b.captured_ms || 0) - (a.captured_ms || 0));
    listEl.innerHTML = sorted.map(fp => {
      const score = fp.consistency_score != null ? fp.consistency_score : null;
      const pct = score != null ? Math.min(Math.max(score / 100, 0), 100) : 0;
      const barClass = pct >= 70 ? 'fp-bar-high' : pct >= 40 ? 'fp-bar-med' : 'fp-bar-low';
      const scoreText = score != null ? (score / 100).toFixed(0) + '%' : 'N/A';
      const hash = fp.composite_hash || '—';
      const shortH = hash.length > 10 ? hash.slice(0, 6) + '…' + hash.slice(-4) : hash;
      const signals = fp.signal_count != null ? fp.signal_count + ' sig' : '';
      const time = fp.captured_ms ? relativeTime(fp.captured_ms) : '—';
      return `<div class="fp-item">
        <div class="fp-hash">${shortH}</div>
        <div class="fp-bar-wrap"><div class="fp-bar ${barClass}" style="width:${pct}%"></div></div>
        <div class="fp-value">${scoreText}</div>
        <div class="fp-signals">${signals}</div>
        <div class="fp-time">${time}</div>
      </div>`;
    }).join('');
  }

  async function poll() {
    try {
      const [scoreData, claimsData, historyData, fpData] = await Promise.all([
        fetchScore(),
        fetchClaims(),
        fetchHistory(),
        fetchFingerprints(),
      ]);
      setError(null);
      renderScore(scoreData);
      renderClaims(claimsData);
      renderHistory(historyData);
      renderFingerprints(fpData);
    } catch (err) {
      setError(`Failed to refresh: ${err.message}`);
    }
  }

  // ---------------------------------------------------------------------------
  // Bootstrap
  // ---------------------------------------------------------------------------

  initGraph();
  poll();
  setInterval(poll, POLL_INTERVAL_MS);

})();
</script>

</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dashboard_contains_svg() {
        let response = zerodentity_dashboard(Path("did:exo:test123".to_string())).await;
        let html = response.0;
        assert!(html.contains("<svg"), "dashboard must contain <svg element");
    }

    #[tokio::test]
    async fn test_dashboard_contains_set_interval() {
        let response = zerodentity_dashboard(Path("did:exo:test123".to_string())).await;
        let html = response.0;
        assert!(
            html.contains("setInterval"),
            "dashboard must contain setInterval for polling"
        );
    }

    #[tokio::test]
    async fn test_dashboard_contains_css_variables() {
        let response = zerodentity_dashboard(Path("did:exo:test123".to_string())).await;
        let html = response.0;
        assert!(
            html.contains("--primary"),
            "dashboard must contain --primary CSS variable"
        );
        assert!(
            html.contains("--bg"),
            "dashboard must contain --bg CSS variable"
        );
    }

    #[tokio::test]
    async fn test_dashboard_substitutes_did() {
        let did = "did:exo:abc123test456";
        let response = zerodentity_dashboard(Path(did.to_string())).await;
        let html = response.0;
        assert!(
            html.contains(did),
            "dashboard must contain the requested DID"
        );
        assert!(
            !html.contains("{DID}"),
            "dashboard must not contain raw {{DID}} template placeholder"
        );
    }

    #[test]
    fn test_dashboard_router_builds() {
        let _ = zerodentity_dashboard_router();
    }

    #[tokio::test]
    async fn test_dashboard_contains_growth_actions() {
        let response = zerodentity_dashboard(Path("did:exo:test123".to_string())).await;
        let html = response.0;
        assert!(
            html.contains("Grow Your Score"),
            "dashboard must contain growth actions panel"
        );
        assert!(
            html.contains("Add Government ID"),
            "dashboard must contain Gov ID growth action"
        );
        assert!(
            html.contains("Request Peer Attestation"),
            "dashboard must contain attestation growth action"
        );
        assert!(
            html.contains("Cast a Governance Vote"),
            "dashboard must contain vote growth action"
        );
        assert!(
            html.contains("Rotate Cryptographic Key"),
            "dashboard must contain key rotation growth action"
        );
    }

    #[tokio::test]
    async fn test_dashboard_contains_fingerprint_panel() {
        let response = zerodentity_dashboard(Path("did:exo:test123".to_string())).await;
        let html = response.0;
        assert!(
            html.contains("Fingerprint Consistency"),
            "dashboard must contain fingerprint consistency panel"
        );
        assert!(
            html.contains("fetchFingerprints"),
            "dashboard must contain fingerprint fetch function"
        );
        assert!(
            html.contains("renderFingerprints"),
            "dashboard must contain fingerprint render function"
        );
    }
}
