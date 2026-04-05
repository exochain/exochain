//! Receipt drill-down dashboard — self-contained HTML receipt explorer.
//!
//! Serves a single-page application at `GET /receipts` that lets operators
//! browse, filter, and drill into individual trust receipts.  Polls the
//! existing `/api/v1/receipts` endpoint — zero additional backend changes.

use axum::{Router, response::Html, routing::get};

const RECEIPT_DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EXOCHAIN — Trust Receipt Explorer</title>
<style>
  :root { --bg: #0a0e17; --surface: #141b2a; --border: #1e2940; --text: #e2e8f0;
    --dim: #64748b; --accent: #38bdf8; --green: #22c55e; --red: #ef4444; --amber: #f59e0b; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'SF Mono', 'Fira Code', monospace; background: var(--bg); color: var(--text); }
  .header { padding: 1.5rem 2rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
  .header h1 { font-size: 1.2rem; color: var(--accent); }
  .header a { color: var(--dim); text-decoration: none; font-size: 0.85rem; }
  .header a:hover { color: var(--accent); }
  .controls { padding: 1rem 2rem; display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; }
  .controls input, .controls select { background: var(--surface); border: 1px solid var(--border); color: var(--text);
    padding: 0.5rem 0.75rem; border-radius: 6px; font-family: inherit; font-size: 0.85rem; }
  .controls input { flex: 1; min-width: 200px; }
  .controls button { background: var(--accent); color: var(--bg); border: none; padding: 0.5rem 1rem;
    border-radius: 6px; cursor: pointer; font-family: inherit; font-weight: 600; }
  .controls button:hover { opacity: 0.9; }
  .count { color: var(--dim); font-size: 0.8rem; padding: 0 2rem 0.5rem; }
  .table-wrap { overflow-x: auto; padding: 0 1rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th { text-align: left; padding: 0.6rem 0.75rem; color: var(--dim); border-bottom: 1px solid var(--border);
    text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.05em; position: sticky; top: 0; background: var(--bg); }
  td { padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:hover td { background: var(--surface); }
  tr.clickable { cursor: pointer; }
  .hash { color: var(--accent); font-size: 0.75rem; }
  .outcome-executed { color: var(--green); }
  .outcome-denied { color: var(--red); }
  .outcome-escalated { color: var(--amber); }
  .outcome-pending { color: var(--dim); }
  .detail-panel { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    margin: 1rem 2rem; padding: 1.5rem; display: none; }
  .detail-panel.active { display: block; }
  .detail-panel h2 { color: var(--accent); font-size: 1rem; margin-bottom: 1rem; }
  .detail-row { display: flex; padding: 0.4rem 0; border-bottom: 1px solid var(--border); }
  .detail-label { color: var(--dim); width: 180px; flex-shrink: 0; font-size: 0.8rem; }
  .detail-value { font-size: 0.8rem; word-break: break-all; }
  .close-btn { float: right; background: none; border: 1px solid var(--border); color: var(--dim);
    padding: 0.3rem 0.6rem; border-radius: 4px; cursor: pointer; font-size: 0.75rem; }
  .close-btn:hover { color: var(--text); border-color: var(--text); }
  .empty { text-align: center; padding: 3rem; color: var(--dim); }
</style>
</head>
<body>
<div class="header">
  <h1>&#x1f9fe; Trust Receipt Explorer</h1>
  <a href="/">&larr; Dashboard</a>
</div>

<div class="controls">
  <input type="text" id="actorInput" placeholder="Filter by actor DID (e.g. did:exo:...)" />
  <select id="limitSelect">
    <option value="25">25</option>
    <option value="50" selected>50</option>
    <option value="100">100</option>
    <option value="500">500</option>
  </select>
  <button onclick="loadReceipts()">Search</button>
</div>
<div class="count" id="resultCount"></div>

<div class="detail-panel" id="detailPanel">
  <button class="close-btn" onclick="closeDetail()">&#x2715; Close</button>
  <h2>Receipt Detail</h2>
  <div id="detailContent"></div>
</div>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Receipt Hash</th>
        <th>Actor</th>
        <th>Action</th>
        <th>Outcome</th>
        <th>Timestamp</th>
      </tr>
    </thead>
    <tbody id="receiptBody"></tbody>
  </table>
</div>

<div class="empty" id="emptyState">Enter an actor DID and click Search to load receipts.</div>

<script>
let allReceipts = [];

async function loadReceipts() {
  const actor = document.getElementById('actorInput').value.trim();
  const limit = document.getElementById('limitSelect').value;
  if (!actor) { alert('Please enter an actor DID'); return; }

  try {
    const resp = await fetch(`/api/v1/receipts?actor=${encodeURIComponent(actor)}&limit=${limit}`);
    if (!resp.ok) { const t = await resp.text(); alert('Error: ' + t); return; }
    allReceipts = await resp.json();
    renderTable();
  } catch (e) { alert('Fetch error: ' + e.message); }
}

function renderTable() {
  const tbody = document.getElementById('receiptBody');
  const empty = document.getElementById('emptyState');
  const count = document.getElementById('resultCount');

  if (allReceipts.length === 0) {
    tbody.innerHTML = '';
    empty.style.display = 'block';
    empty.textContent = 'No receipts found for this actor.';
    count.textContent = '';
    return;
  }

  empty.style.display = 'none';
  count.textContent = allReceipts.length + ' receipt(s)';

  tbody.innerHTML = allReceipts.map((r, i) => `
    <tr class="clickable" onclick="showDetail(${i})">
      <td class="hash">${r.receipt_hash.slice(0, 16)}...</td>
      <td>${r.actor_did}</td>
      <td>${r.action_type}</td>
      <td class="outcome-${r.outcome}">${r.outcome}</td>
      <td>${new Date(r.timestamp_ms).toISOString().replace('T', ' ').slice(0, 19)}</td>
    </tr>
  `).join('');
}

function showDetail(idx) {
  const r = allReceipts[idx];
  const panel = document.getElementById('detailPanel');
  const content = document.getElementById('detailContent');

  const fields = [
    ['Receipt Hash', r.receipt_hash],
    ['Actor DID', r.actor_did],
    ['Action Type', r.action_type],
    ['Action Hash', r.action_hash],
    ['Outcome', r.outcome],
    ['Authority Chain', r.authority_chain_hash],
    ['Consent Ref', r.consent_reference || '(none)'],
    ['Challenge Ref', r.challenge_reference || '(none)'],
    ['Timestamp', new Date(r.timestamp_ms).toISOString()],
    ['Timestamp (ms)', r.timestamp_ms],
  ];

  content.innerHTML = fields.map(([k, v]) =>
    `<div class="detail-row"><span class="detail-label">${k}</span><span class="detail-value">${v}</span></div>`
  ).join('');

  panel.classList.add('active');
  panel.scrollIntoView({ behavior: 'smooth' });
}

function closeDetail() {
  document.getElementById('detailPanel').classList.remove('active');
}

// Auto-load if actor param in URL.
const params = new URLSearchParams(window.location.search);
if (params.get('actor')) {
  document.getElementById('actorInput').value = params.get('actor');
  loadReceipts();
}
</script>
</body>
</html>"##;

async fn handle_receipt_dashboard() -> Html<&'static str> {
    Html(RECEIPT_DASHBOARD_HTML)
}

/// Build the receipt dashboard router.
pub fn receipt_dashboard_router() -> Router {
    Router::new().route("/receipts", get(handle_receipt_dashboard))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn receipt_dashboard_returns_html() {
        let app = receipt_dashboard_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/receipts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 16384).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Trust Receipt Explorer"));
        assert!(html.contains("/api/v1/receipts"));
        assert!(html.contains("showDetail"));
    }

    #[tokio::test]
    async fn receipt_dashboard_contains_filter_controls() {
        let app = receipt_dashboard_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/receipts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(resp.into_body(), 16384).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        // Verify filter UI elements exist.
        assert!(html.contains("controls"));
        assert!(html.contains("detail-panel"));
        assert!(html.contains("outcome-executed"));
        assert!(html.contains("outcome-denied"));
    }

    #[tokio::test]
    async fn receipt_dashboard_content_type_is_html() {
        let app = receipt_dashboard_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/receipts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("text/html"));
    }
}
