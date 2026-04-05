//! Live status dashboard — single-page HTML served at `/`.
//!
//! A real-time dashboard that polls the node's own API endpoints
//! (`/health`, `/api/v1/governance/status`, `/metrics`) and renders
//! live consensus state, validator set, and network topology.
//!
//! No JavaScript frameworks — just vanilla HTML/CSS/JS with a 3-second
//! refresh cycle.

use axum::{Router, response::Html, routing::get};

/// Build a router containing the dashboard root route.
pub fn dashboard_router() -> Router {
    Router::new().route("/", get(handle_dashboard))
}

async fn handle_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>exochain</title>
<style>
  :root {
    --bg: #0a0e17;
    --surface: #111827;
    --border: #1e293b;
    --text: #e2e8f0;
    --text-dim: #94a3b8;
    --accent: #38bdf8;
    --accent-dim: #0c4a6e;
    --green: #22c55e;
    --green-dim: #064e3b;
    --amber: #f59e0b;
    --amber-dim: #78350f;
    --red: #ef4444;
    --red-dim: #7f1d1d;
    --mono: 'SF Mono', 'Fira Code', 'JetBrains Mono', 'Cascadia Code', monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }

  /* Header */
  header {
    border-bottom: 1px solid var(--border);
    padding: 1.25rem 2rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 1rem;
  }

  .logo {
    font-family: var(--mono);
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: var(--accent);
  }

  .logo span {
    color: var(--text-dim);
    font-weight: 400;
  }

  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.375rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.8125rem;
    font-weight: 500;
    font-family: var(--mono);
  }

  .status-badge.ok {
    background: var(--green-dim);
    color: var(--green);
  }

  .status-badge.degraded {
    background: var(--amber-dim);
    color: var(--amber);
  }

  .status-badge.offline {
    background: var(--red-dim);
    color: var(--red);
  }

  .pulse {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    animation: pulse 2s ease-in-out infinite;
  }

  .ok .pulse { background: var(--green); }
  .degraded .pulse { background: var(--amber); }
  .offline .pulse { background: var(--red); }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  /* Main grid */
  main {
    flex: 1;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
    width: 100%;
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.25rem;
    margin-bottom: 1.5rem;
  }

  /* Metric cards */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    transition: border-color 0.2s;
  }

  .card:hover {
    border-color: var(--accent-dim);
  }

  .card-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-dim);
    margin-bottom: 0.5rem;
  }

  .card-value {
    font-family: var(--mono);
    font-size: 2rem;
    font-weight: 700;
    line-height: 1.1;
    color: var(--text);
  }

  .card-value.accent { color: var(--accent); }

  .card-sub {
    font-size: 0.8125rem;
    color: var(--text-dim);
    margin-top: 0.375rem;
    font-family: var(--mono);
  }

  /* Validator list */
  .validators-section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }

  .section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
  }

  .section-title {
    font-size: 0.875rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-dim);
  }

  .quorum-badge {
    font-family: var(--mono);
    font-size: 0.75rem;
    padding: 0.25rem 0.625rem;
    border-radius: 6px;
    background: var(--accent-dim);
    color: var(--accent);
  }

  .validator-list {
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .validator-item {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.625rem 0.875rem;
    background: var(--bg);
    border-radius: 8px;
    font-family: var(--mono);
    font-size: 0.8125rem;
    color: var(--text);
    border: 1px solid transparent;
    transition: border-color 0.2s;
  }

  .validator-item:hover {
    border-color: var(--border);
  }

  .validator-item.self {
    border-color: var(--accent-dim);
  }

  .validator-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--green);
    flex-shrink: 0;
  }

  .validator-item.self .validator-dot {
    background: var(--accent);
  }

  .self-tag {
    font-size: 0.6875rem;
    padding: 0.125rem 0.5rem;
    border-radius: 4px;
    background: var(--accent-dim);
    color: var(--accent);
    margin-left: auto;
    flex-shrink: 0;
  }

  /* Activity log */
  .activity-section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem;
  }

  .activity-log {
    font-family: var(--mono);
    font-size: 0.75rem;
    color: var(--text-dim);
    max-height: 200px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .log-entry {
    padding: 0.25rem 0;
    border-bottom: 1px solid var(--border);
    display: flex;
    gap: 0.75rem;
  }

  .log-entry:last-child { border-bottom: none; }

  .log-time { color: var(--text-dim); white-space: nowrap; }
  .log-msg { color: var(--text); }
  .log-msg.advance { color: var(--accent); }
  .log-msg.commit { color: var(--green); }
  .log-msg.warn { color: var(--amber); }

  /* Footer */
  footer {
    border-top: 1px solid var(--border);
    padding: 1rem 2rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.5rem;
    font-size: 0.75rem;
    color: var(--text-dim);
    font-family: var(--mono);
  }

  footer a {
    color: var(--accent);
    text-decoration: none;
  }

  footer a:hover { text-decoration: underline; }

  .update-indicator {
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
  }

  .update-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent);
    opacity: 0;
    transition: opacity 0.15s;
  }

  .update-dot.flash { opacity: 1; }

  /* Responsive */
  @media (max-width: 640px) {
    header { padding: 1rem; }
    main { padding: 1rem; }
    .card-value { font-size: 1.5rem; }
    .validator-item { font-size: 0.6875rem; }
    footer { padding: 0.75rem 1rem; }
  }
</style>
</head>
<body>
  <header>
    <div class="logo">exochain <span>node</span></div>
    <div id="status-badge" class="status-badge offline">
      <div class="pulse"></div>
      <span id="status-text">connecting...</span>
    </div>
  </header>

  <main>
    <div class="grid">
      <div class="card">
        <div class="card-label">Consensus Round</div>
        <div class="card-value accent" id="round">—</div>
        <div class="card-sub" id="round-rate"></div>
      </div>

      <div class="card">
        <div class="card-label">Committed Height</div>
        <div class="card-value" id="height">—</div>
        <div class="card-sub" id="dag-nodes"></div>
      </div>

      <div class="card">
        <div class="card-label">Connected Peers</div>
        <div class="card-value" id="peers">—</div>
        <div class="card-sub" id="sync-status"></div>
      </div>

      <div class="card">
        <div class="card-label">Uptime</div>
        <div class="card-value" id="uptime">—</div>
        <div class="card-sub" id="version"></div>
      </div>
    </div>

    <div class="validators-section">
      <div class="section-header">
        <span class="section-title">Validator Set</span>
        <span class="quorum-badge" id="quorum-info">—</span>
      </div>
      <ul class="validator-list" id="validator-list">
        <li class="validator-item"><span style="color:var(--text-dim)">loading...</span></li>
      </ul>
    </div>

    <div class="activity-section">
      <div class="section-header">
        <span class="section-title">Activity</span>
        <span style="font-size:0.75rem;color:var(--text-dim);font-family:var(--mono)" id="update-count"></span>
      </div>
      <div class="activity-log" id="activity-log"></div>
    </div>
  </main>

  <footer>
    <div>
      <span id="node-did" style="user-select:all">—</span>
    </div>
    <div class="update-indicator">
      <div class="update-dot" id="update-dot"></div>
      <span>refreshes every 3s</span>
      &middot;
      <a href="/health">/health</a>
      &middot;
      <a href="/ready">/ready</a>
      &middot;
      <a href="/metrics">/metrics</a>
      &middot;
      <a href="/api/v1/governance/status">/api</a>
      &middot;
      <a href="https://github.com/exochain/exochain" target="_blank" rel="noopener">github</a>
    </div>
  </footer>

<script>
(function() {
  'use strict';

  // State
  let prevRound = null;
  let prevHeight = null;
  let nodeDid = null;
  let pollCount = 0;
  const activityLog = [];
  const MAX_LOG = 50;

  function formatUptime(secs) {
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
    if (h > 0) return h + 'h ' + m + 'm ' + s + 's';
    if (m > 0) return m + 'm ' + s + 's';
    return s + 's';
  }

  function truncateDid(did) {
    if (!did || did.length < 24) return did;
    return did.slice(0, 16) + '...' + did.slice(-8);
  }

  function addLog(msg, cls) {
    const now = new Date();
    const ts = now.toLocaleTimeString('en-US', { hour12: false });
    activityLog.unshift({ time: ts, msg: msg, cls: cls || '' });
    if (activityLog.length > MAX_LOG) activityLog.pop();
    renderLog();
  }

  function renderLog() {
    const el = document.getElementById('activity-log');
    el.innerHTML = activityLog.map(function(e) {
      return '<div class="log-entry"><span class="log-time">' + e.time +
        '</span><span class="log-msg ' + e.cls + '">' + e.msg + '</span></div>';
    }).join('');
  }

  function flashDot() {
    const dot = document.getElementById('update-dot');
    dot.classList.add('flash');
    setTimeout(function() { dot.classList.remove('flash'); }, 300);
  }

  function setStatus(status, text) {
    const badge = document.getElementById('status-badge');
    const textEl = document.getElementById('status-text');
    badge.className = 'status-badge ' + status;
    textEl.textContent = text;
  }

  async function fetchJSON(url) {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(resp.status + '');
    return resp.json();
  }

  async function fetchText(url) {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(resp.status + '');
    return resp.text();
  }

  function parseMetrics(text) {
    const metrics = {};
    text.split('\n').forEach(function(line) {
      if (line.startsWith('#') || line.trim() === '') return;
      const parts = line.split(' ');
      if (parts.length >= 2) {
        metrics[parts[0]] = parseFloat(parts[1]);
      }
    });
    return metrics;
  }

  async function poll() {
    try {
      const [health, gov, metricsText] = await Promise.all([
        fetchJSON('/health'),
        fetchJSON('/api/v1/governance/status'),
        fetchText('/metrics')
      ]);

      const m = parseMetrics(metricsText);
      pollCount++;

      // Status badge
      if (health.status === 'ok') {
        const peers = m.exochain_peer_count || 0;
        if (peers === 0 && gov.validator_count <= 1) {
          setStatus('ok', 'seed node');
        } else if (peers === 0) {
          setStatus('degraded', 'no peers');
        } else {
          setStatus('ok', 'operational');
        }
      } else {
        setStatus('degraded', health.status);
      }

      // Cards
      document.getElementById('round').textContent = gov.consensus_round.toLocaleString();
      document.getElementById('height').textContent = gov.committed_height.toLocaleString();
      document.getElementById('peers').textContent = (m.exochain_peer_count || 0).toLocaleString();
      document.getElementById('uptime').textContent = formatUptime(health.uptime_seconds);
      document.getElementById('version').textContent = 'v' + health.version;

      // Sub-info
      const dagNodes = m.exochain_dag_nodes_total || 0;
      document.getElementById('dag-nodes').textContent = dagNodes + ' DAG nodes';

      const syncing = m.exochain_sync_in_progress || 0;
      document.getElementById('sync-status').textContent = syncing ? 'syncing...' : 'idle';

      // Round rate
      if (prevRound !== null && gov.consensus_round > prevRound) {
        const delta = gov.consensus_round - prevRound;
        document.getElementById('round-rate').textContent = '+' + delta + ' / 3s';
        if (delta > 0) addLog('round advanced to ' + gov.consensus_round.toLocaleString(), 'advance');
      } else if (prevRound !== null) {
        document.getElementById('round-rate').textContent = 'steady';
      }

      // Height changes
      if (prevHeight !== null && gov.committed_height > prevHeight) {
        addLog('committed height ' + gov.committed_height.toLocaleString(), 'commit');
      }

      prevRound = gov.consensus_round;
      prevHeight = gov.committed_height;

      // Node DID
      if (!nodeDid && gov.validators && gov.validators.length > 0 && gov.is_validator) {
        nodeDid = gov.validators.find(function() { return true; });
        document.getElementById('node-did').textContent = nodeDid || '—';
      } else if (!nodeDid) {
        document.getElementById('node-did').textContent = 'observer';
      }

      // Validators
      const vList = document.getElementById('validator-list');
      const quorum = Math.floor((gov.validator_count * 2) / 3) + 1;
      document.getElementById('quorum-info').textContent =
        gov.validator_count + ' validators / quorum ' + quorum;

      if (gov.validators && gov.validators.length > 0) {
        vList.innerHTML = gov.validators.map(function(did, i) {
          const isSelf = gov.is_validator && i === 0 && gov.validator_count === 1;
          const selfCls = isSelf ? ' self' : '';
          const selfTag = isSelf ? '<span class="self-tag">this node</span>' : '';
          return '<li class="validator-item' + selfCls + '">' +
            '<span class="validator-dot"></span>' +
            '<span title="' + did + '">' + truncateDid(did) + '</span>' +
            selfTag + '</li>';
        }).join('');
      }

      // First successful poll
      if (pollCount === 1) {
        addLog('dashboard connected to node', '');
        addLog('version ' + health.version + ' / uptime ' + formatUptime(health.uptime_seconds), '');
        if (gov.is_validator) {
          addLog('node is a consensus validator', 'advance');
        } else {
          addLog('node is an observer', '');
        }
      }

      document.getElementById('update-count').textContent = 'poll #' + pollCount;
      flashDot();

    } catch (err) {
      setStatus('offline', 'unreachable');
      addLog('fetch failed: ' + err.message, 'warn');
      flashDot();
    }
  }

  // Initial poll, then every 3 seconds
  poll();
  setInterval(poll, 3000);
})();
</script>
</body>
</html>
"##;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn dashboard_returns_html() {
        let app = dashboard_router();
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("text/html"));

        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("exochain"));
        assert!(html.contains("/api/v1/governance/status"));
    }

    #[tokio::test]
    async fn dashboard_html_contains_all_endpoints() {
        let app = dashboard_router();
        let resp = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("/health"));
        assert!(html.contains("/metrics"));
        assert!(html.contains("/api/v1/governance/status"));
    }
}
