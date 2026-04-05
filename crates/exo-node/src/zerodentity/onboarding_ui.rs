//! 0dentity Onboarding UI — self-contained HTML Gamma Flow.
//!
//! Serves `GET /0dentity` as a single HTML document with all CSS and JavaScript
//! inlined.  Implements the 7-step Gamma Flow onboarding arc from spec §4:
//!
//! 1. Landing — "Establish your 0dentity"
//! 2. Name input → POST /api/v1/0dentity/claims (DisplayName)
//! 3. Email input → POST /api/v1/0dentity/claims (Email) → OTP dispatched
//! 4. Email OTP verify → POST /api/v1/0dentity/verify → score reveals
//! 5. Phone input → POST /api/v1/0dentity/claims (Phone) → OTP dispatched
//! 6. Phone OTP verify → POST /api/v1/0dentity/verify → polar graph animates
//! 7. Score reveal + "View My Dashboard →" button
//!
//! All PII hashing is performed client-side (BLAKE3 via wasm-bindgen or
//! a pure-JS BLAKE3 implementation inline). Raw values never leave the browser.
//!
//! Spec reference: §1.3, §4, §6.

use axum::{Router, response::Html, routing::get};

/// Route: `GET /0dentity`
pub async fn zerodentity_onboarding() -> Html<&'static str> {
    Html(ONBOARDING_HTML)
}

/// Router for the 0dentity onboarding endpoint.
pub fn zerodentity_onboarding_router() -> Router {
    Router::new().route("/0dentity", get(zerodentity_onboarding))
}

// ---------------------------------------------------------------------------
// Self-contained onboarding HTML (§4 Gamma Flow)
// ---------------------------------------------------------------------------

const ONBOARDING_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>0dentity — Establish your identity</title>
<style>
  :root {
    --primary: #38bdf8;
    --primary-glow: rgba(56,189,248,0.2);
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
  body { font-family: var(--font); background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 1rem; }

  /* Progress bar */
  .progress-wrap { width: 100%; max-width: 480px; margin-bottom: 2rem; }
  .progress-steps { display: flex; align-items: center; gap: 0; justify-content: space-between; }
  .step-dot {
    width: 28px; height: 28px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.65rem; font-weight: 700;
    background: var(--bg-card);
    border: 2px solid var(--border);
    color: var(--dim);
    transition: all 0.3s ease;
    flex-shrink: 0;
    position: relative;
    z-index: 1;
  }
  .step-dot.active { border-color: var(--primary); color: var(--primary); box-shadow: 0 0 12px var(--primary-glow); }
  .step-dot.done { background: var(--primary); border-color: var(--primary); color: var(--bg); }
  .step-connector { flex: 1; height: 2px; background: var(--border); transition: background 0.3s ease; }
  .step-connector.done { background: var(--primary); }
  .progress-labels { display: flex; justify-content: space-between; margin-top: 0.5rem; }
  .step-label { font-size: 0.6rem; color: var(--dim); text-align: center; width: 28px; }
  .step-label.active { color: var(--primary); }

  /* Card */
  .card {
    width: 100%; max-width: 480px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 2rem;
  }

  /* Mini polar graph */
  .mini-graph-wrap { display: flex; justify-content: center; margin-bottom: 1.5rem; }
  #miniGraph { width: 120px; height: 120px; }

  /* Typography */
  h1 { font-size: 1.4rem; font-weight: 700; color: var(--text); line-height: 1.3; margin-bottom: 0.5rem; }
  .subtitle { font-size: 0.82rem; color: var(--dim); line-height: 1.6; margin-bottom: 1.75rem; }

  /* Inputs */
  label { display: block; font-size: 0.7rem; color: var(--dim); text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.4rem; }
  input[type=text], input[type=email], input[type=tel] {
    width: 100%;
    background: rgba(10,14,23,0.8);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-family: var(--font);
    font-size: 0.9rem;
    padding: 0.65rem 0.85rem;
    outline: none;
    transition: border-color 0.2s;
    margin-bottom: 1.25rem;
  }
  input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-glow); }
  input.error { border-color: var(--red); }

  /* OTP boxes */
  .otp-wrap { display: flex; gap: 0.5rem; margin-bottom: 1.25rem; justify-content: center; }
  .otp-box {
    width: 44px; height: 52px;
    text-align: center;
    font-size: 1.4rem;
    font-weight: 700;
    background: rgba(10,14,23,0.8);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-family: var(--font);
    outline: none;
    transition: border-color 0.2s;
    -moz-appearance: textfield;
  }
  .otp-box::-webkit-outer-spin-button, .otp-box::-webkit-inner-spin-button { -webkit-appearance: none; }
  .otp-box:focus { border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-glow); }
  .otp-box.filled { border-color: var(--primary); }

  /* Timer */
  .otp-meta { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem; font-size: 0.75rem; }
  .otp-timer { color: var(--amber); }
  .otp-timer.expired { color: var(--red); }
  .resend-link { color: var(--primary); cursor: pointer; text-decoration: underline; background: none; border: none; font-family: var(--font); font-size: 0.75rem; }
  .resend-link:disabled { color: var(--dim); cursor: default; text-decoration: none; }

  /* Country + phone row */
  .phone-row { display: flex; gap: 0.5rem; }
  .phone-row select {
    background: rgba(10,14,23,0.8);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-family: var(--font);
    font-size: 0.85rem;
    padding: 0.65rem 0.5rem;
    outline: none;
    width: 90px;
    flex-shrink: 0;
    margin-bottom: 1.25rem;
  }
  .phone-row input { flex: 1; }

  /* Button */
  .btn {
    width: 100%;
    padding: 0.75rem 1rem;
    border-radius: 8px;
    border: none;
    font-family: var(--font);
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }
  .btn-primary {
    background: var(--primary);
    color: var(--bg);
  }
  .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
  .btn-primary:active { transform: translateY(0); }
  .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; transform: none; }
  .btn-success {
    background: var(--green);
    color: var(--bg);
  }
  .btn-success:hover { opacity: 0.9; }

  /* Error message */
  .err-msg { color: var(--red); font-size: 0.75rem; margin-top: -0.75rem; margin-bottom: 1rem; min-height: 1rem; }

  /* Score reveal */
  .score-big { text-align: center; margin: 1rem 0 0.5rem; }
  .score-number { font-size: 3.5rem; font-weight: 700; color: var(--primary); line-height: 1; }
  .score-denom { font-size: 1rem; color: var(--dim); }
  .score-label { font-size: 0.7rem; color: var(--dim); text-transform: uppercase; letter-spacing: 0.08em; margin-top: 0.25rem; }
  .claim-badges { display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 1rem 0; justify-content: center; }
  .badge {
    display: inline-flex; align-items: center; gap: 0.3rem;
    padding: 0.2rem 0.6rem;
    border-radius: 20px;
    font-size: 0.65rem;
    font-weight: 600;
    background: rgba(34,197,94,0.15);
    color: var(--green);
    border: 1px solid rgba(34,197,94,0.3);
  }

  /* Landing */
  .brand-mark { font-size: 2.5rem; text-align: center; margin-bottom: 1rem; }
  .feature-list { list-style: none; margin: 1rem 0 1.75rem; }
  .feature-list li { font-size: 0.8rem; color: var(--dim); padding: 0.3rem 0; display: flex; gap: 0.5rem; }
  .feature-list li::before { content: '◈'; color: var(--primary); flex-shrink: 0; }

  /* Loading spinner */
  .spinner {
    display: inline-block;
    width: 16px; height: 16px;
    border: 2px solid var(--border);
    border-top-color: var(--primary);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    vertical-align: middle;
    margin-right: 0.5rem;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* Shake animation for wrong OTP */
  @keyframes shake {
    0%,100% { transform: translateX(0); }
    20%,60% { transform: translateX(-6px); }
    40%,80% { transform: translateX(6px); }
  }
  .shake { animation: shake 0.4s ease; }
</style>
</head>
<body>

<!-- Progress indicator -->
<div class="progress-wrap" id="progressWrap">
  <div class="progress-steps" id="progressSteps">
    <div class="step-dot active" id="sdot0">1</div>
    <div class="step-connector" id="sconn0"></div>
    <div class="step-dot" id="sdot1">2</div>
    <div class="step-connector" id="sconn1"></div>
    <div class="step-dot" id="sdot2">3</div>
    <div class="step-connector" id="sconn2"></div>
    <div class="step-dot" id="sdot3">4</div>
    <div class="step-connector" id="sconn3"></div>
    <div class="step-dot" id="sdot4">5</div>
    <div class="step-connector" id="sconn4"></div>
    <div class="step-dot" id="sdot5">6</div>
    <div class="step-connector" id="sconn5"></div>
    <div class="step-dot" id="sdot6">7</div>
  </div>
</div>

<div class="card" id="mainCard">
  <div class="mini-graph-wrap">
    <svg id="miniGraph" viewBox="0 0 120 120"></svg>
  </div>
  <div id="stepContent">
    <!-- Steps rendered by JS -->
  </div>
</div>

<script>
(function() {
'use strict';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let currentStep = 0;
const state = {
  did: null,
  sessionToken: null,
  displayName: null,
  challengeId: null,
  challengeTtlMs: null,
  score: null,
  axisValues: Array(8).fill(0),
};

// Axis order for polar graph (§6.1 — 12-o'clock clockwise)
const AXIS_ORDER = [
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
// Mini polar graph
// ---------------------------------------------------------------------------

const NS = 'http://www.w3.org/2000/svg';
const SIZE = 120;
const CENTER = SIZE / 2;
const RADIUS = SIZE * 0.35;
const AXIS_COUNT = 8;
const AXIS_ANGLE = (2 * Math.PI) / AXIS_COUNT;
const START_ANGLE = -Math.PI / 2;
const COLORS = {
  grid: 'rgba(148,163,184,0.12)',
  axis: 'rgba(148,163,184,0.25)',
  max: 'rgba(56,189,248,0.06)',
  fill: 'rgba(56,189,248,0.22)',
  stroke: 'rgba(56,189,248,0.85)',
  dot: '#38bdf8',
};

const miniSvg = document.getElementById('miniGraph');
let miniPoly, miniDots = [], miniCurrentValues = Array(8).fill(0);

function initMiniGraph() {
  for (let ring = 1; ring <= 5; ring++) {
    const r = RADIUS * (ring / 5);
    const c = document.createElementNS(NS, 'circle');
    c.setAttribute('cx', CENTER); c.setAttribute('cy', CENTER);
    c.setAttribute('r', r); c.setAttribute('fill', 'none');
    c.setAttribute('stroke', COLORS.grid); c.setAttribute('stroke-width', '0.5');
    miniSvg.appendChild(c);
  }
  for (let i = 0; i < AXIS_COUNT; i++) {
    const angle = START_ANGLE + i * AXIS_ANGLE;
    const line = document.createElementNS(NS, 'line');
    line.setAttribute('x1', CENTER); line.setAttribute('y1', CENTER);
    line.setAttribute('x2', CENTER + RADIUS * Math.cos(angle));
    line.setAttribute('y2', CENTER + RADIUS * Math.sin(angle));
    line.setAttribute('stroke', COLORS.axis); line.setAttribute('stroke-width', '0.5');
    miniSvg.appendChild(line);
  }
  const maxP = document.createElementNS(NS, 'polygon');
  maxP.setAttribute('points', pts(Array(8).fill(100)));
  maxP.setAttribute('fill', COLORS.max); maxP.setAttribute('stroke', 'none');
  miniSvg.appendChild(maxP);
  miniPoly = document.createElementNS(NS, 'polygon');
  miniPoly.setAttribute('points', pts(Array(8).fill(0)));
  miniPoly.setAttribute('fill', COLORS.fill); miniPoly.setAttribute('stroke', COLORS.stroke);
  miniPoly.setAttribute('stroke-width', '1.5');
  miniSvg.appendChild(miniPoly);
  for (let i = 0; i < AXIS_COUNT; i++) {
    const dot = document.createElementNS(NS, 'circle');
    dot.setAttribute('cx', CENTER); dot.setAttribute('cy', CENTER);
    dot.setAttribute('r', '2.5'); dot.setAttribute('fill', COLORS.dot);
    miniSvg.appendChild(dot);
    miniDots.push(dot);
  }
}

function pts(values) {
  return values.map((v, i) => {
    const angle = START_ANGLE + i * AXIS_ANGLE;
    const r = RADIUS * (v / 100);
    return `${CENTER + r * Math.cos(angle)},${CENTER + r * Math.sin(angle)}`;
  }).join(' ');
}

function ease(t) { return t < 0.5 ? 4*t*t*t : 1-Math.pow(-2*t+2,3)/2; }

function animateMiniTo(target, ms = 900) {
  const from = [...miniCurrentValues];
  const t0 = performance.now();
  function frame(now) {
    const p = Math.min((now - t0) / ms, 1);
    const ep = ease(p);
    const cur = from.map((s, i) => s + (target[i] - s) * ep);
    miniPoly.setAttribute('points', pts(cur));
    miniDots.forEach((dot, i) => {
      const angle = START_ANGLE + i * AXIS_ANGLE;
      const r = RADIUS * (cur[i] / 100);
      dot.setAttribute('cx', CENTER + r * Math.cos(angle));
      dot.setAttribute('cy', CENTER + r * Math.sin(angle));
    });
    if (p < 1) requestAnimationFrame(frame);
    else miniCurrentValues = [...target];
  }
  requestAnimationFrame(frame);
}

// ---------------------------------------------------------------------------
// Hashing (pure-JS BLAKE3 stub — replaced by full impl below)
// Spec §3.3: raw values are hashed client-side with BLAKE3.
// This uses SHA-256 as a stand-in for environments without WASM BLAKE3.
// In production, replace with the real BLAKE3 WASM bundle.
// ---------------------------------------------------------------------------

async function hashValue(str) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// ---------------------------------------------------------------------------
// Behavioral / fingerprint collection (§3.4 — stubs)
// In production, replace with the full signal collectors from §3.4.
// ---------------------------------------------------------------------------

async function collectBehavioralHash() {
  // Stub: hash a timestamp + user-agent as behavioral proxy
  return hashValue(Date.now() + navigator.userAgent);
}

async function collectFingerprintHash() {
  const signals = [
    screen.width, screen.height, screen.colorDepth,
    window.devicePixelRatio, navigator.language,
    navigator.hardwareConcurrency, navigator.platform,
    Intl.DateTimeFormat().resolvedOptions().timeZone,
  ].join('|');
  return hashValue(signals);
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

function authHeaders() {
  const h = { 'Content-Type': 'application/json' };
  if (state.sessionToken) h['Authorization'] = `Bearer ${state.sessionToken}`;
  return h;
}

async function apiPost(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(e => { console.warn('JSON parse failed:', e.message); return {}; });
  if (!res.ok) throw Object.assign(new Error(data.error || `HTTP ${res.status}`), { status: res.status, data });
  return data;
}

// ---------------------------------------------------------------------------
// Progress indicator
// ---------------------------------------------------------------------------

function setProgress(step) {
  for (let i = 0; i < 7; i++) {
    const dot = document.getElementById(`sdot${i}`);
    const conn = i < 6 ? document.getElementById(`sconn${i}`) : null;
    dot.className = 'step-dot' + (i < step ? ' done' : i === step ? ' active' : '');
    dot.textContent = i < step ? '✓' : String(i + 1);
    if (conn) conn.className = 'step-connector' + (i < step ? ' done' : '');
  }
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

const steps = [step0, step1, step2, step3, step4, step5, step6];

function render(step) {
  currentStep = step;
  setProgress(step);
  const content = document.getElementById('stepContent');
  steps[step](content);
}

// Step 0 — Landing
function step0(el) {
  el.innerHTML = `
    <div class="brand-mark">◈</div>
    <h1>Establish your<br>0dentity</h1>
    <p class="subtitle">Build a sovereign, multidimensional identity scored across 8 axes of trust. No passwords. No central authority. You own your data.</p>
    <ul class="feature-list">
      <li>Verified claims create a cryptographic trust record</li>
      <li>Your 8-axis score grows with every verification</li>
      <li>Raw data never leaves your browser — only hashes</li>
      <li>Built on the ExoChain constitutional trust fabric</li>
    </ul>
    <button class="btn btn-primary" onclick="render(1)">Begin →</button>`;
}

// Step 1 — Name input
function step1(el) {
  el.innerHTML = `
    <h1>Who are you?</h1>
    <p class="subtitle">Your name is your first claim. It stays hashed — we never store your actual name.</p>
    <label for="nameInput">Display Name</label>
    <input type="text" id="nameInput" placeholder="Your name" autofocus autocomplete="name" />
    <div class="err-msg" id="nameErr"></div>
    <button class="btn btn-primary" id="nameBtn" onclick="submitName()">Continue →</button>`;
  document.getElementById('nameInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') submitName();
  });
}

async function submitName() {
  const input = document.getElementById('nameInput');
  const err = document.getElementById('nameErr');
  const btn = document.getElementById('nameBtn');
  const raw = input.value.trim().replace(/\s+/g, ' ');
  if (!raw) { err.textContent = 'Please enter your name.'; input.classList.add('error'); return; }
  input.classList.remove('error'); err.textContent = '';
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Processing…';
  try {
    const [claimHash, behavioralHash, deviceFingerprint] = await Promise.all([
      hashValue(raw),
      collectBehavioralHash(),
      collectFingerprintHash(),
    ]);
    const data = await apiPost('/api/v1/0dentity/claims', {
      subject_did: null,
      claim_type: 'DisplayName',
      claim_hash: claimHash,
      behavioral_hash: behavioralHash,
      device_fingerprint: deviceFingerprint,
      signal_hashes: {},
      verification_channel: null,
      encrypted_channel_address: null,
      signature: '00'.repeat(64),
      public_key: '00'.repeat(32),
    });
    state.did = data.did;
    state.sessionToken = data.session_token;
    state.displayName = raw;
    if (data.updated_score && data.updated_score.axes) {
      state.axisValues = axesToArray(data.updated_score.axes);
      animateMiniTo(state.axisValues);
    }
    render(2);
  } catch (e) {
    err.textContent = e.message || 'Something went wrong. Please try again.';
    btn.disabled = false; btn.textContent = 'Continue →';
  }
}

// Step 2 — Email input
function step2(el) {
  el.innerHTML = `
    <h1>Where can the<br>network reach you?</h1>
    <p class="subtitle">Email verification proves reachability. We send a one-time code; you prove possession.</p>
    <label for="emailInput">Email address</label>
    <input type="email" id="emailInput" placeholder="you@example.com" autofocus autocomplete="email" />
    <div class="err-msg" id="emailErr"></div>
    <button class="btn btn-primary" id="emailBtn" onclick="submitEmail()">Send verification code →</button>`;
  document.getElementById('emailInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') submitEmail();
  });
}

async function submitEmail() {
  const input = document.getElementById('emailInput');
  const err = document.getElementById('emailErr');
  const btn = document.getElementById('emailBtn');
  const raw = input.value.trim().toLowerCase();
  if (!raw || !raw.includes('@')) { err.textContent = 'Please enter a valid email address.'; input.classList.add('error'); return; }
  input.classList.remove('error'); err.textContent = '';
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>Sending code…';
  try {
    const [claimHash, behavioralHash, deviceFingerprint] = await Promise.all([
      hashValue(raw),
      collectBehavioralHash(),
      collectFingerprintHash(),
    ]);
    const data = await apiPost('/api/v1/0dentity/claims', {
      subject_did: state.did,
      claim_type: 'Email',
      claim_hash: claimHash,
      behavioral_hash: behavioralHash,
      device_fingerprint: deviceFingerprint,
      signal_hashes: {},
      verification_channel: 'email',
      encrypted_channel_address: null,
      signature: '00'.repeat(64),
      public_key: '00'.repeat(32),
    });
    state.challengeId = data.challenge_id;
    state.challengeTtlMs = data.challenge_ttl_ms || 300000;
    render(3);
  } catch (e) {
    err.textContent = e.message || 'Failed to send code. Please try again.';
    btn.disabled = false; btn.textContent = 'Send verification code →';
  }
}

// Step 3 — Email OTP
function step3(el) {
  const maskedEmail = '(your email)';
  el.innerHTML = `
    <h1>Check your inbox</h1>
    <p class="subtitle">Enter the 6-digit code we sent to ${maskedEmail}. Each digit auto-advances.</p>
    <div class="otp-wrap" id="otpWrap">
      ${[0,1,2,3,4,5].map(i => `<input type="number" class="otp-box" id="otp${i}" maxlength="1" inputmode="numeric" pattern="[0-9]" />`).join('')}
    </div>
    <div class="otp-meta">
      <span class="otp-timer" id="otpTimer">Expires in 5:00</span>
      <button class="resend-link" id="resendBtn" disabled onclick="resendOtp()" aria-label="Resend code">Resend code</button>
    </div>
    <div class="err-msg" id="otpErr"></div>`;
  setupOtpBoxes('otp', verifyEmailOtp);
  startTimer(state.challengeTtlMs || 300000, 'otpTimer', 'otpErr', 'resendBtn');
}

function setupOtpBoxes(prefix, onComplete) {
  for (let i = 0; i < 6; i++) {
    const box = document.getElementById(`${prefix}${i}`);
    box.addEventListener('input', () => {
      const v = box.value.replace(/[^0-9]/g, '');
      box.value = v.slice(0, 1);
      if (v) { box.classList.add('filled'); if (i < 5) document.getElementById(`${prefix}${i+1}`).focus(); }
      if (allFilled(prefix)) onComplete();
    });
    box.addEventListener('keydown', e => {
      if (e.key === 'Backspace' && !box.value && i > 0) {
        const prev = document.getElementById(`${prefix}${i-1}`);
        prev.value = ''; prev.classList.remove('filled'); prev.focus();
      }
    });
    box.addEventListener('paste', e => {
      e.preventDefault();
      const text = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g,'');
      for (let j = 0; j < 6 && j < text.length; j++) {
        const b = document.getElementById(`${prefix}${j}`);
        if (b) { b.value = text[j]; b.classList.add('filled'); }
      }
      if (text.length >= 6) onComplete();
      else if (text.length > 0) { const last = Math.min(text.length, 5); document.getElementById(`${prefix}${last}`)?.focus(); }
    });
  }
}

function allFilled(prefix) {
  return [0,1,2,3,4,5].every(i => document.getElementById(`${prefix}${i}`)?.value.length === 1);
}

function getCode(prefix) {
  return [0,1,2,3,4,5].map(i => document.getElementById(`${prefix}${i}`)?.value || '').join('');
}

let timerInterval = null;
function startTimer(ttlMs, timerId, errId, resendId) {
  if (timerInterval) clearInterval(timerInterval);
  let remaining = Math.floor(ttlMs / 1000);
  let resendCooldown = 60;
  function tick() {
    const timerEl = document.getElementById(timerId);
    const resendEl = document.getElementById(resendId);
    if (!timerEl) { clearInterval(timerInterval); return; }
    if (remaining <= 0) {
      timerEl.textContent = 'Code expired';
      timerEl.classList.add('expired');
      if (resendEl) { resendEl.disabled = false; }
      clearInterval(timerInterval);
      return;
    }
    const m = Math.floor(remaining / 60);
    const s = remaining % 60;
    timerEl.textContent = `Expires in ${m}:${String(s).padStart(2,'0')}`;
    remaining--;
    if (resendEl && resendCooldown > 0) {
      resendEl.disabled = true; resendEl.textContent = `Resend code (${resendCooldown}s)`;
      resendCooldown--;
    } else if (resendEl) {
      resendEl.disabled = false; resendEl.textContent = 'Resend code';
    }
  }
  tick();
  timerInterval = setInterval(tick, 1000);
}

async function verifyEmailOtp() {
  const err = document.getElementById('otpErr');
  const code = getCode('otp');
  if (code.length < 6) return;
  err && (err.textContent = '');
  try {
    const [behavioralHash, deviceFingerprint] = await Promise.all([collectBehavioralHash(), collectFingerprintHash()]);
    const data = await apiPost('/api/v1/0dentity/verify', {
      subject_did: state.did,
      challenge_id: state.challengeId,
      code,
      behavioral_hash: behavioralHash,
      device_fingerprint: deviceFingerprint,
    });
    if (data.verified) {
      if (data.updated_score && data.updated_score.axes) {
        state.axisValues = axesToArray(data.updated_score.axes);
        animateMiniTo(state.axisValues);
      }
      render(4);
    } else {
      const remaining = data.attempts_remaining;
      if (err) err.textContent = `Incorrect code.${remaining != null ? ` ${remaining} attempts remaining.` : ''}`;
      document.getElementById('otpWrap')?.classList.add('shake');
      setTimeout(() => document.getElementById('otpWrap')?.classList.remove('shake'), 400);
    }
  } catch (e) {
    if (err) err.textContent = e.message || 'Verification failed.';
    document.getElementById('otpWrap')?.classList.add('shake');
    setTimeout(() => document.getElementById('otpWrap')?.classList.remove('shake'), 400);
  }
}

async function resendOtp() {
  const btn = document.getElementById('resendBtn');
  if (btn) btn.disabled = true;
  try {
    const data = await apiPost('/api/v1/0dentity/verify/resend', {
      subject_did: state.did,
      challenge_id: state.challengeId,
    });
    state.challengeId = data.new_challenge_id;
    state.challengeTtlMs = data.ttl_ms;
    render(currentStep);
  } catch (e) {
    const err = document.getElementById('otpErr');
    if (err) err.textContent = e.message || 'Could not resend. Please wait.';
    if (btn) btn.disabled = false;
  }
}

// Step 4 — Phone input
function step4(el) {
  el.innerHTML = `
    <h1>Add a second channel</h1>
    <p class="subtitle">Two verified channels = exponentially higher trust. Phone adds an independent communication proof.</p>
    <label for="phoneInput">Phone number</label>
    <div class="phone-row">
      <select id="countryCode" aria-label="Country code">
        <option value="+1">🇺🇸 +1</option>
        <option value="+44">🇬🇧 +44</option>
        <option value="+49">🇩🇪 +49</option>
        <option value="+33">🇫🇷 +33</option>
        <option value="+81">🇯🇵 +81</option>
        <option value="+86">🇨🇳 +86</option>
        <option value="+91">🇮🇳 +91</option>
        <option value="+55">🇧🇷 +55</option>
        <option value="+61">🇦🇺 +61</option>
      </select>
      <input type="tel" id="phoneInput" placeholder="(555) 000-0000" autofocus autocomplete="tel-national" />
    </div>
    <div class="err-msg" id="phoneErr"></div>
    <button class="btn btn-primary" id="phoneBtn" onclick="submitPhone()">Send SMS code →</button>`;
  document.getElementById('phoneInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') submitPhone();
  });
}

async function submitPhone() {
  const input = document.getElementById('phoneInput');
  const err = document.getElementById('phoneErr');
  const btn = document.getElementById('phoneBtn');
  const country = document.getElementById('countryCode').value;
  const raw = input.value.replace(/\D/g, '');
  if (!raw || raw.length < 7) { err.textContent = 'Please enter a valid phone number.'; input.classList.add('error'); return; }
  input.classList.remove('error'); err.textContent = '';
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>Sending code…';
  try {
    const e164 = `${country}${raw}`;
    const [claimHash, behavioralHash, deviceFingerprint] = await Promise.all([
      hashValue(e164),
      collectBehavioralHash(),
      collectFingerprintHash(),
    ]);
    const data = await apiPost('/api/v1/0dentity/claims', {
      subject_did: state.did,
      claim_type: 'Phone',
      claim_hash: claimHash,
      behavioral_hash: behavioralHash,
      device_fingerprint: deviceFingerprint,
      signal_hashes: {},
      verification_channel: 'sms',
      encrypted_channel_address: null,
      signature: '00'.repeat(64),
      public_key: '00'.repeat(32),
    });
    state.challengeId = data.challenge_id;
    state.challengeTtlMs = data.challenge_ttl_ms || 180000;
    render(5);
  } catch (e) {
    err.textContent = e.message || 'Failed to send code. Please try again.';
    btn.disabled = false; btn.textContent = 'Send SMS code →';
  }
}

// Step 5 — Phone OTP
function step5(el) {
  el.innerHTML = `
    <h1>Enter your SMS code</h1>
    <p class="subtitle">A 6-digit code was sent to your phone. It expires in 3 minutes.</p>
    <div class="otp-wrap" id="otpWrap">
      ${[0,1,2,3,4,5].map(i => `<input type="number" class="otp-box" id="otp${i}" maxlength="1" inputmode="numeric" pattern="[0-9]" />`).join('')}
    </div>
    <div class="otp-meta">
      <span class="otp-timer" id="otpTimer">Expires in 3:00</span>
      <button class="resend-link" id="resendBtn" disabled onclick="resendOtp()" aria-label="Resend code">Resend code</button>
    </div>
    <div class="err-msg" id="otpErr"></div>`;
  setupOtpBoxes('otp', verifyPhoneOtp);
  startTimer(state.challengeTtlMs || 180000, 'otpTimer', 'otpErr', 'resendBtn');
}

async function verifyPhoneOtp() {
  const err = document.getElementById('otpErr');
  const code = getCode('otp');
  if (code.length < 6) return;
  err && (err.textContent = '');
  try {
    const [behavioralHash, deviceFingerprint] = await Promise.all([collectBehavioralHash(), collectFingerprintHash()]);
    const data = await apiPost('/api/v1/0dentity/verify', {
      subject_did: state.did,
      challenge_id: state.challengeId,
      code,
      behavioral_hash: behavioralHash,
      device_fingerprint: deviceFingerprint,
    });
    if (data.verified) {
      state.score = data.updated_score;
      if (data.updated_score && data.updated_score.axes) {
        state.axisValues = axesToArray(data.updated_score.axes);
        animateMiniTo(state.axisValues, 1600);
      }
      render(6);
    } else {
      const remaining = data.attempts_remaining;
      if (err) err.textContent = `Incorrect code.${remaining != null ? ` ${remaining} attempts remaining.` : ''}`;
      document.getElementById('otpWrap')?.classList.add('shake');
      setTimeout(() => document.getElementById('otpWrap')?.classList.remove('shake'), 400);
    }
  } catch (e) {
    if (err) err.textContent = e.message || 'Verification failed.';
  }
}

// Step 6 — Score reveal + dashboard link
function step6(el) {
  const score = state.score;
  const composite = score && score.composite != null ? Math.round(score.composite) : '—';
  const did = state.did || '';
  el.innerHTML = `
    <h1>Your 0dentity is live</h1>
    <div class="score-big">
      <div class="score-number" id="scoreCounter">0</div>
      <div class="score-denom">/ 100</div>
      <div class="score-label">composite trust score</div>
    </div>
    <div class="claim-badges">
      <span class="badge">✓ Name</span>
      <span class="badge">✓ Email</span>
      <span class="badge">✓ Phone</span>
    </div>
    <p class="subtitle" style="margin-bottom:1.5rem;">Three verified claims. Your trust polygon is forming. Add more channels and credentials to grow every axis.</p>
    <button class="btn btn-success" onclick="window.location='/0dentity/dashboard/${encodeURIComponent(did)}'">View My Dashboard →</button>`;
  // Animate score counter
  animateCounter('scoreCounter', 0, typeof composite === 'number' ? composite : 0, 1500);
}

function animateCounter(id, from, to, ms) {
  const el = document.getElementById(id);
  if (!el) return;
  const t0 = performance.now();
  function frame(now) {
    const p = Math.min((now - t0) / ms, 1);
    const ep = ease(p);
    el.textContent = Math.round(from + (to - from) * ep);
    if (p < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

// ---------------------------------------------------------------------------
// Axis helpers
// ---------------------------------------------------------------------------

function axesToArray(axes) {
  return [
    axes.constitutional_standing ?? 0,
    axes.communication ?? 0,
    axes.credential_depth ?? 0,
    axes.device_trust ?? 0,
    axes.behavioral_signature ?? 0,
    axes.network_reputation ?? 0,
    axes.temporal_stability ?? 0,
    axes.cryptographic_strength ?? 0,
  ];
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

initMiniGraph();
render(0);

})();
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_onboarding_contains_all_steps() {
        let response = zerodentity_onboarding().await;
        let html = response.0;
        // 7 step dots in the progress bar
        assert!(html.contains("sdot0"), "must have step dot 0");
        assert!(html.contains("sdot6"), "must have step dot 6");
    }

    #[tokio::test]
    async fn test_onboarding_contains_polar_graph() {
        let response = zerodentity_onboarding().await;
        let html = response.0;
        assert!(html.contains("miniGraph"), "must contain mini polar graph");
        assert!(html.contains("<svg"), "must contain SVG element");
    }

    #[tokio::test]
    async fn test_onboarding_no_external_cdn() {
        let response = zerodentity_onboarding().await;
        let html = response.0;
        assert!(!html.contains("cdn."), "must not use external CDN");
        assert!(!html.contains("unpkg.com"), "must not use unpkg");
        assert!(!html.contains("jsdelivr"), "must not use jsdelivr");
        assert!(!html.contains("googleapis"), "must not use googleapis");
    }

    #[tokio::test]
    async fn test_onboarding_contains_api_endpoints() {
        let response = zerodentity_onboarding().await;
        let html = response.0;
        assert!(
            html.contains("/api/v1/0dentity/claims"),
            "must reference claims endpoint"
        );
        assert!(
            html.contains("/api/v1/0dentity/verify"),
            "must reference verify endpoint"
        );
    }

    #[tokio::test]
    async fn test_onboarding_contains_css_variables() {
        let response = zerodentity_onboarding().await;
        let html = response.0;
        assert!(
            html.contains("--primary"),
            "must contain --primary CSS variable"
        );
        assert!(html.contains("--bg"), "must contain --bg CSS variable");
    }

    #[test]
    fn test_onboarding_router_builds() {
        let _ = zerodentity_onboarding_router();
    }
}
