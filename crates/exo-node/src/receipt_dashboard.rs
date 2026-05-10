// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
    tbody.replaceChildren();
    empty.style.display = 'block';
    empty.textContent = 'No receipts found for this actor.';
    count.textContent = '';
    return;
  }

  empty.style.display = 'none';
  count.textContent = allReceipts.length + ' receipt(s)';

  const rows = allReceipts.map((r, i) => {
    const tr = document.createElement('tr');
    tr.className = 'clickable';
    tr.addEventListener('click', () => showDetail(i));

    appendCell(tr, `${String(r.receipt_hash || '').slice(0, 16)}...`, 'hash');
    appendCell(tr, r.actor_did || '');
    appendCell(tr, r.action_type || '');
    appendCell(tr, r.outcome || '', outcomeClass(r.outcome));
    appendCell(tr, formatTimestamp(r.timestamp_ms));
    return tr;
  });
  tbody.replaceChildren(...rows);
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

  const rows = fields.map(([k, v]) => {
    const row = document.createElement('div');
    row.className = 'detail-row';
    appendSpan(row, k, 'detail-label');
    appendSpan(row, v, 'detail-value');
    return row;
  });
  content.replaceChildren(...rows);

  panel.classList.add('active');
  panel.scrollIntoView({ behavior: 'smooth' });
}

function appendCell(row, value, className = '') {
  const td = document.createElement('td');
  if (className) { td.className = className; }
  td.textContent = String(value ?? '');
  row.appendChild(td);
}

function appendSpan(row, value, className) {
  const span = document.createElement('span');
  span.className = className;
  span.textContent = String(value ?? '');
  row.appendChild(span);
}

function outcomeClass(outcome) {
  const normalized = String(outcome || '').toLowerCase();
  if (['executed', 'denied', 'escalated', 'pending'].includes(normalized)) {
    return `outcome-${normalized}`;
  }
  return 'outcome-pending';
}

function formatTimestamp(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) { return '(invalid timestamp)'; }
  return date.toISOString().replace('T', ' ').slice(0, 19);
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

    #[test]
    fn receipt_dashboard_uses_text_content_for_api_fields() {
        assert!(
            RECEIPT_DASHBOARD_HTML.contains("textContent"),
            "API response fields must be written through textContent"
        );
        assert!(
            !RECEIPT_DASHBOARD_HTML.contains("tbody.innerHTML = allReceipts.map"),
            "receipt rows must not be rendered by injecting API data through innerHTML"
        );
        assert!(
            !RECEIPT_DASHBOARD_HTML.contains("content.innerHTML = fields.map"),
            "receipt details must not be rendered by injecting API data through innerHTML"
        );
    }
}
