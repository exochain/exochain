# 0dentity — Application Requirements Specification

> **Version**: 1.0.0-draft
> **Date**: 2026-04-04
> **Status**: Canonical reference for implementation
> **Scope**: Complete sovereign identity scoring application built on ExoChain
> **Audience**: Any AI or human implementor. This document is self-contained.

---

## 0. Preamble: Why This Document Exists

This specification describes **0dentity** — a sovereign identity scoring application that runs on the ExoChain trust fabric. It is written to be **intrinsically liberating for AIs**: any sufficiently capable language model should be able to read this document and implement the complete system without additional context, clarification, or human hand-holding.

Every type is defined with exact Rust syntax. Every API endpoint has request/response schemas. Every algorithm has deterministic pseudocode. Every UI component has behavioral specification. Ambiguity is a bug in this document.

The system this document describes is the application a user reaches after completing the onboarding arc: they provide their name, email, and phone number; the system verifies each claim, silently collects fingerprintable device metadata, computes a multidimensional trust score displayed as a polar graph, and lands them on a dashboard where their 0dentity lives and grows.

---

## 1. Product Vision

### 1.1 One-Sentence Summary

0dentity replaces binary authentication ("logged in or not") with a continuously-scored, multidimensional trust polygon derived from verified claims, behavioral biometrics, device fingerprinting, and network reputation — all built on a cryptographic DAG where nothing is stored in plaintext and everything is auditable.

### 1.2 Core Principles

| Principle | Meaning | Implementation Consequence |
|-----------|---------|---------------------------|
| **Sovereign Custody** | The user owns their claims | All PII is BLAKE3-hashed client-side before transmission; raw values never leave the browser |
| **Continuous Scoring** | Trust is not binary | 8-axis polar decomposition recalculated on every new claim event |
| **Constitutional Determinism** | Scores are reproducible | Given the same claim DAG, any node must compute the identical score |
| **Transparent Covertness** | Collection is silent but honest | Fingerprinting happens seamlessly during natural interaction; the system openly documents what it collects |
| **Append-Only Provenance** | History cannot be rewritten | Every claim, verification, and score change emits a TrustReceipt to the DAG |

### 1.3 User Story Arc (The Gamma Flow)

```
[Landing] → [Name Input] → [Email Input] → [Email OTP Verify]
         → [Phone Input] → [Phone OTP Verify] → [Score Reveal]
         → [View My Dashboard →]
```

Each step simultaneously:
1. Collects an explicit claim (name, email, phone)
2. Silently harvests fingerprintable device/behavioral metadata
3. Extends the user's polar graph in real time
4. Emits trust receipts to the ExoChain DAG

The "View My Dashboard" button at the end is the entry point to the persistent application described in Sections 8–12.

---

## 2. Foundational Types

These types either exist in the ExoChain codebase or are new to 0dentity. Each is specified with exact Rust syntax.

### 2.1 Existing ExoChain Types (use directly)

```rust
// exo-core/src/types.rs — already in codebase
pub struct Did(String);                     // format: "did:exo:<identifier>"
pub struct Hash256(pub [u8; 32]);           // BLAKE3 content address
pub struct Timestamp {                      // Hybrid Logical Clock
    pub physical_ms: u64,
    pub logical: u32,
}
pub enum Signature {
    Ed25519([u8; 64]),
    PostQuantum(Vec<u8>),
    Hybrid { classical: [u8; 64], pq: Vec<u8> },
    Empty,
}
pub struct TrustReceipt {
    pub receipt_hash: Hash256,
    pub actor_did: Did,
    pub action_type: String,
    pub action_hash: Hash256,
    pub outcome: ReceiptOutcome,
    pub authority_chain_hash: Hash256,
    pub consent_reference: Option<String>,
    pub challenge_reference: Option<String>,
    pub timestamp_ms: u64,
}
pub enum ReceiptOutcome { Executed, Denied, Escalated, Pending }
```

### 2.2 New 0dentity Types

```rust
/// A single claim made by an identity.
/// Claims are the atomic units of the 0dentity system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityClaim {
    /// Content-addressed hash of the claim payload (BLAKE3).
    pub claim_hash: Hash256,
    /// The DID of the identity making this claim.
    pub subject_did: Did,
    /// What kind of claim this is.
    pub claim_type: ClaimType,
    /// Verification status of this claim.
    pub status: ClaimStatus,
    /// When the claim was first made (epoch ms).
    pub created_ms: u64,
    /// When the claim was last verified (epoch ms), if ever.
    pub verified_ms: Option<u64>,
    /// When this claim expires and must be renewed (epoch ms).
    /// None = does not expire.
    pub expires_ms: Option<u64>,
    /// Signature of the subject over the claim payload.
    pub signature: Signature,
    /// Hash of the DAG node where this claim is recorded.
    pub dag_node_hash: Hash256,
}

/// The universe of claim types.
/// Each variant maps to specific axes on the polar graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClaimType {
    // --- Explicit claims (user-provided) ---
    DisplayName,
    Email,
    Phone,
    GovernmentId,
    BiometricLiveness,
    ProfessionalCredential { provider: String },

    // --- Implicit claims (system-observed) ---
    DeviceFingerprint,
    BehavioralSignature,
    GeographicConsistency,
    SessionContinuity,

    // --- Network claims (peer-generated) ---
    PeerAttestation { attester_did: Did },
    DelegationGrant { delegator_did: Did },
    SybilChallengeResolution { challenge_id: String },

    // --- Governance claims (protocol-generated) ---
    GovernanceVote { proposal_hash: Hash256 },
    ProposalAuthored { proposal_hash: Hash256 },
    ValidatorService { round_range: (u64, u64) },

    // --- Cryptographic claims (key-management) ---
    KeyRotation { old_key_hash: Hash256 },
    EntropyAttestation,
}

/// Verification status of a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimStatus {
    /// Claim made but not yet verified.
    Pending,
    /// Claim independently verified (e.g., OTP confirmed).
    Verified,
    /// Claim expired and needs renewal.
    Expired,
    /// Claim revoked by subject or authority.
    Revoked,
    /// Claim challenged and under review.
    Challenged,
}

/// The 8-axis polar decomposition of an identity's trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZerodentityScore {
    /// The DID this score belongs to.
    pub subject_did: Did,
    /// Per-axis scores, each 0–100.
    pub axes: PolarAxes,
    /// Composite score: weighted mean of all axes, 0–100.
    pub composite: f64,
    /// When this score was last computed (epoch ms).
    pub computed_ms: u64,
    /// Hash of the claim DAG state at computation time.
    /// Enables deterministic recomputation.
    pub dag_state_hash: Hash256,
    /// Number of verified claims contributing to this score.
    pub claim_count: u32,
    /// The shape's symmetry index (0.0–1.0).
    /// 1.0 = perfectly symmetric polygon.
    /// Rewards breadth across all dimensions.
    pub symmetry: f64,
}

/// The 8 axes of the 0dentity polar graph.
/// Each axis is scored 0–100 independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolarAxes {
    /// Verified reachability: email + phone channels.
    /// Driven by: Email, Phone claims (verified).
    pub communication: f64,

    /// KYC depth: government ID, biometric liveness.
    /// Driven by: GovernmentId, BiometricLiveness, ProfessionalCredential claims.
    pub credential_depth: f64,

    /// Fingerprint consistency: device binding stability.
    /// Driven by: DeviceFingerprint claims, cross-session consistency.
    pub device_trust: f64,

    /// Typing cadence, interaction patterns, session rhythm.
    /// Driven by: BehavioralSignature claims accumulated over time.
    pub behavioral_signature: f64,

    /// Peer attestations, vouches, delegation history.
    /// Driven by: PeerAttestation, DelegationGrant claims.
    pub network_reputation: f64,

    /// Account age, verification freshness, claim renewal.
    /// Driven by: Time since first claim, renewal cadence.
    pub temporal_stability: f64,

    /// Key algorithm, entropy, rotation hygiene.
    /// Driven by: KeyRotation, EntropyAttestation claims.
    pub cryptographic_strength: f64,

    /// Governance participation, challenge record.
    /// Driven by: GovernanceVote, ProposalAuthored,
    ///            ValidatorService, SybilChallengeResolution claims.
    pub constitutional_standing: f64,
}

/// A single device fingerprint composite.
/// Composed from multiple browser/device signals.
/// Only the composite hash is persisted — never raw signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    /// The composite hash (BLAKE3 of all signal hashes concatenated).
    pub composite_hash: Hash256,
    /// Individual signal hashes (for internal comparison only).
    /// Key = signal type, Value = BLAKE3 hash of that signal's value.
    pub signal_hashes: BTreeMap<FingerprintSignal, Hash256>,
    /// When this fingerprint was captured (epoch ms).
    pub captured_ms: u64,
    /// Similarity score vs. previous fingerprint (0.0–1.0).
    /// 1.0 = identical device, 0.0 = completely different.
    /// None on first capture.
    pub consistency_score: Option<f64>,
}

/// The enumeration of all fingerprintable signals.
/// Each is collected silently during natural interaction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FingerprintSignal {
    /// Canvas rendering — GPU/driver characteristics.
    CanvasRendering,
    /// WebGL parameters — GPU model, vendor, extensions.
    WebGLParameters,
    /// Screen geometry — resolution, color depth, device pixel ratio.
    ScreenGeometry,
    /// Timezone and locale — geographic/cultural signal.
    TimezoneLocale,
    /// User-Agent string — OS, browser, version.
    UserAgent,
    /// AudioContext — hardware audio stack fingerprint.
    AudioContext,
    /// Font enumeration — installed font list hash.
    FontEnumeration,
    /// Battery status — charge level, charging state (where available).
    BatteryStatus,
    /// Color depth and device pixel ratio.
    ColorDepthDPR,
    /// Hardware concurrency — CPU core count.
    HardwareConcurrency,
    /// Device memory — approximate RAM (where available).
    DeviceMemory,
    /// WebRTC local IPs — network interface fingerprint.
    WebRTCLocalIPs,
    /// Touch support — touchpoints, touch event support.
    TouchSupport,
    /// Platform string — navigator.platform value.
    Platform,
    /// Do-Not-Track setting — privacy preference signal.
    DoNotTrack,
}

/// Behavioral biometric sample captured during interaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralSample {
    /// The composite hash of this sample.
    pub sample_hash: Hash256,
    /// Type of behavioral signal.
    pub signal_type: BehavioralSignalType,
    /// When captured (epoch ms).
    pub captured_ms: u64,
    /// Similarity to established baseline (0.0–1.0).
    /// None if no baseline exists yet.
    pub baseline_similarity: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BehavioralSignalType {
    /// Inter-key timing intervals (microsecond precision).
    KeystrokeDynamics,
    /// Mouse movement velocity, acceleration, curvature.
    MouseDynamics,
    /// Touch pressure, contact area, swipe velocity.
    TouchDynamics,
    /// Scroll speed, direction patterns.
    ScrollBehavior,
    /// Time between form field focus events.
    FormNavigationCadence,
}

/// OTP verification state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpChallenge {
    /// Unique challenge ID.
    pub challenge_id: String,
    /// The DID being verified.
    pub subject_did: Did,
    /// What channel this OTP was sent on.
    pub channel: OtpChannel,
    /// HMAC of the OTP code (never store the code itself).
    pub code_hmac: Hash256,
    /// When the OTP was dispatched (epoch ms).
    pub dispatched_ms: u64,
    /// TTL in milliseconds. Email: 300_000 (5 min). Phone: 180_000 (3 min).
    pub ttl_ms: u64,
    /// Number of verification attempts made.
    pub attempts: u32,
    /// Maximum allowed attempts before lockout.
    pub max_attempts: u32,
    /// Current state of this challenge.
    pub state: OtpState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtpChannel { Email, Sms }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtpState {
    /// OTP dispatched, awaiting user input.
    Pending,
    /// User entered correct code.
    Verified,
    /// TTL expired without verification.
    Expired,
    /// Too many failed attempts.
    LockedOut,
}
```

---

## 3. Signal Collection Specification

### 3.1 Philosophy

Every signal is collected **during natural user interaction** — typing in a form field, waiting for an OTP, reading content. No modal dialogs. No permission prompts. No "allow fingerprinting" buttons. The collection is covert in UX but transparent in documentation (this document) and in the privacy disclosure (Section 11).

### 3.2 Collection Timeline

| Onboarding Step | Explicit Claim | Covert Signals Collected |
|-----------------|---------------|--------------------------|
| Page load | — | CanvasRendering, WebGLParameters, ScreenGeometry, TimezoneLocale, UserAgent, HardwareConcurrency, DeviceMemory, Platform, DoNotTrack, TouchSupport, ColorDepthDPR |
| Name input (typing) | DisplayName | KeystrokeDynamics, FontEnumeration |
| Name submit | — | FormNavigationCadence |
| Email input (typing) | Email | KeystrokeDynamics, MouseDynamics |
| Email submit | — | WebRTCLocalIPs, BatteryStatus |
| Email OTP wait (idle) | — | AudioContext (requires user gesture — OTP submit counts) |
| Email OTP entry | — | KeystrokeDynamics (OTP-specific cadence) |
| Phone input | Phone | TouchDynamics (if mobile), MouseDynamics (if desktop) |
| Phone OTP entry | — | KeystrokeDynamics, ScrollBehavior |
| Score reveal (view) | — | FormNavigationCadence (time-to-interact after reveal) |

### 3.3 Client-Side Hashing Protocol

**Critical invariant: raw signal values NEVER leave the browser.**

```
For each signal S collected:
  1. raw_value = collect_signal(S)          // e.g., canvas.toDataURL()
  2. signal_hash = BLAKE3(raw_value)        // 32-byte hash
  3. signal_hashes[S] = signal_hash         // store hash only
  4. discard(raw_value)                     // zero the memory

After all signals for this interaction step:
  5. sorted_hashes = signal_hashes.values().sort()   // deterministic order
  6. composite_input = concat(sorted_hashes)          // concatenate all
  7. composite_hash = BLAKE3(composite_input)          // single digest
  8. transmit(composite_hash, signal_hash_map)         // to server
```

### 3.4 Signal Collection Implementations (JavaScript)

```javascript
// Each collector returns a string value that will be BLAKE3-hashed.
// These are the RAW collectors — the hashing wrapper calls them.

const collectors = {
  [FingerprintSignal.CanvasRendering]: () => {
    const canvas = document.createElement('canvas');
    canvas.width = 256; canvas.height = 64;
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('0dentity:canvas:v1', 2, 15);
    ctx.fillStyle = 'rgba(102,204,0,0.7)';
    ctx.fillText('0dentity:canvas:v1', 4, 17);
    return canvas.toDataURL();
  },

  [FingerprintSignal.WebGLParameters]: () => {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl');
    if (!gl) return 'no-webgl';
    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    return JSON.stringify({
      vendor: gl.getParameter(gl.VENDOR),
      renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'masked',
      version: gl.getParameter(gl.VERSION),
      shadingVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
      maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
      maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS),
      extensions: gl.getSupportedExtensions()?.sort() ?? [],
    });
  },

  [FingerprintSignal.ScreenGeometry]: () => JSON.stringify({
    width: screen.width,
    height: screen.height,
    availWidth: screen.availWidth,
    availHeight: screen.availHeight,
    colorDepth: screen.colorDepth,
    pixelDepth: screen.pixelDepth,
    devicePixelRatio: window.devicePixelRatio,
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight,
  }),

  [FingerprintSignal.TimezoneLocale]: () => JSON.stringify({
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    offset: new Date().getTimezoneOffset(),
    locale: navigator.language,
    languages: navigator.languages,
    dateFormat: new Intl.DateTimeFormat().format(new Date(0)),
  }),

  [FingerprintSignal.AudioContext]: () => {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const oscillator = ctx.createOscillator();
      const analyser = ctx.createAnalyser();
      const gain = ctx.createGain();
      const scriptProcessor = ctx.createScriptProcessor(4096, 1, 1);
      gain.gain.value = 0; // silent
      oscillator.type = 'triangle';
      oscillator.frequency.setValueAtTime(10000, ctx.currentTime);
      oscillator.connect(analyser);
      analyser.connect(scriptProcessor);
      scriptProcessor.connect(gain);
      gain.connect(ctx.destination);
      oscillator.start(0);
      const data = new Float32Array(analyser.frequencyBinCount);
      analyser.getFloatFrequencyData(data);
      oscillator.stop();
      ctx.close();
      return Array.from(data.slice(0, 64)).join(',');
    } catch { return 'no-audio-context'; }
  },

  [FingerprintSignal.FontEnumeration]: () => {
    // Test against known font list using canvas measurement
    const testFonts = [
      'Arial', 'Courier New', 'Georgia', 'Helvetica', 'Times New Roman',
      'Trebuchet MS', 'Verdana', 'Palatino', 'Garamond', 'Bookman',
      'Comic Sans MS', 'Candara', 'Calibri', 'Cambria', 'Consolas',
      'Lucida Console', 'Monaco', 'Menlo', 'SF Pro', 'Roboto',
      'Inter', 'Fira Code', 'JetBrains Mono', 'Segoe UI',
    ];
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const baseline = ctx.measureText('mmmmmmmmmmlli').width;
    ctx.font = '72px monospace';
    const baseWidth = ctx.measureText('mmmmmmmmmmlli').width;
    const available = testFonts.filter(font => {
      ctx.font = `72px "${font}", monospace`;
      return ctx.measureText('mmmmmmmmmmlli').width !== baseWidth;
    });
    return available.sort().join('|');
  },

  [FingerprintSignal.BatteryStatus]: async () => {
    try {
      const battery = await navigator.getBattery();
      return JSON.stringify({
        level: battery.level,
        charging: battery.charging,
        chargingTime: battery.chargingTime,
        dischargingTime: battery.dischargingTime,
      });
    } catch { return 'no-battery-api'; }
  },

  [FingerprintSignal.HardwareConcurrency]: () =>
    String(navigator.hardwareConcurrency || 'unknown'),

  [FingerprintSignal.DeviceMemory]: () =>
    String(navigator.deviceMemory || 'unknown'),

  [FingerprintSignal.TouchSupport]: () => JSON.stringify({
    maxTouchPoints: navigator.maxTouchPoints,
    touchEvent: 'ontouchstart' in window,
    pointerEvent: 'onpointerdown' in window,
  }),

  [FingerprintSignal.Platform]: () => navigator.platform || 'unknown',

  [FingerprintSignal.DoNotTrack]: () =>
    navigator.doNotTrack || window.doNotTrack || 'unset',

  [FingerprintSignal.UserAgent]: () => navigator.userAgent,

  [FingerprintSignal.ColorDepthDPR]: () => JSON.stringify({
    colorDepth: screen.colorDepth,
    pixelRatio: window.devicePixelRatio,
  }),

  [FingerprintSignal.WebRTCLocalIPs]: async () => {
    try {
      const pc = new RTCPeerConnection({ iceServers: [] });
      pc.createDataChannel('');
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      return new Promise(resolve => {
        const ips = new Set();
        pc.onicecandidate = e => {
          if (!e.candidate) { pc.close(); resolve([...ips].sort().join('|')); return; }
          const match = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
          if (match) ips.add(match[1]);
        };
        setTimeout(() => { pc.close(); resolve([...ips].sort().join('|')); }, 3000);
      });
    } catch { return 'no-webrtc'; }
  },
};
```

### 3.5 Behavioral Biometric Collection

```javascript
class BehavioralCollector {
  constructor() {
    this.keystrokeTimings = [];    // inter-key intervals in μs
    this.mouseVelocities = [];     // pixels/ms velocity samples
    this.touchPressures = [];      // pressure values [0.0-1.0]
    this.lastKeyTime = null;
    this.lastMousePos = null;
    this.lastMouseTime = null;
  }

  // Attach to a form field to begin collection.
  attachToField(element) {
    element.addEventListener('keydown', (e) => {
      const now = performance.now() * 1000; // μs
      if (this.lastKeyTime !== null) {
        this.keystrokeTimings.push(now - this.lastKeyTime);
      }
      this.lastKeyTime = now;
    });

    element.addEventListener('mousemove', (e) => {
      const now = performance.now();
      if (this.lastMousePos !== null) {
        const dx = e.clientX - this.lastMousePos.x;
        const dy = e.clientY - this.lastMousePos.y;
        const dt = now - this.lastMouseTime;
        if (dt > 0) {
          this.mouseVelocities.push(Math.sqrt(dx*dx + dy*dy) / dt);
        }
      }
      this.lastMousePos = { x: e.clientX, y: e.clientY };
      this.lastMouseTime = now;
    });

    element.addEventListener('touchstart', (e) => {
      if (e.touches[0]?.force !== undefined) {
        this.touchPressures.push(e.touches[0].force);
      }
    });
  }

  // Produce a hashable summary. Called when a step completes.
  // Returns a deterministic string representation.
  summarize() {
    // Quantize to bins to tolerate natural variation
    const quantize = (arr, bins) => {
      if (arr.length === 0) return Array(bins).fill(0);
      const min = Math.min(...arr);
      const max = Math.max(...arr) || 1;
      const histogram = Array(bins).fill(0);
      arr.forEach(v => {
        const bin = Math.min(bins - 1, Math.floor(((v - min) / (max - min)) * bins));
        histogram[bin]++;
      });
      return histogram;
    };

    return JSON.stringify({
      keystrokeHistogram: quantize(this.keystrokeTimings, 16),
      keystrokeMean: this.keystrokeTimings.length > 0
        ? this.keystrokeTimings.reduce((a,b) => a+b, 0) / this.keystrokeTimings.length
        : null,
      keystrokeStdDev: this._stddev(this.keystrokeTimings),
      mouseVelocityHistogram: quantize(this.mouseVelocities, 8),
      touchPressureMean: this.touchPressures.length > 0
        ? this.touchPressures.reduce((a,b) => a+b, 0) / this.touchPressures.length
        : null,
      sampleCounts: {
        keystrokes: this.keystrokeTimings.length,
        mousePoints: this.mouseVelocities.length,
        touchPoints: this.touchPressures.length,
      },
    });
  }

  _stddev(arr) {
    if (arr.length < 2) return null;
    const mean = arr.reduce((a,b) => a+b, 0) / arr.length;
    const variance = arr.reduce((sum, v) => sum + (v - mean) ** 2, 0) / (arr.length - 1);
    return Math.sqrt(variance);
  }
}
```

---

## 4. Onboarding Flow — Step-by-Step Specification

### 4.1 State Machine

```
                    ┌──────────────┐
                    │   Landing    │
                    │  (no state)  │
                    └──────┬───────┘
                           │ user clicks "Begin your proof →"
                    ┌──────▼───────┐
                    │  Name Input  │
                    │  step: 1/6   │
                    └──────┬───────┘
                           │ name submitted
                    ┌──────▼───────┐
                    │  Email Input │
                    │  step: 2/6   │
                    └──────┬───────┘
                           │ email submitted + OTP dispatched
                    ┌──────▼───────┐
                    │  Email OTP   │
                    │  step: 3/6   │──── [Resend] loops back
                    └──────┬───────┘
                           │ OTP verified
                    ┌──────▼───────┐
                    │  Phone Input │
                    │  step: 4/6   │
                    └──────┬───────┘
                           │ phone submitted + SMS dispatched
                    ┌──────▼───────┐
                    │  Phone OTP   │
                    │  step: 5/6   │──── [Resend] loops back
                    └──────┬───────┘
                           │ OTP verified
                    ┌──────▼───────┐
                    │ Score Reveal │
                    │  step: 6/6   │
                    └──────┬───────┘
                           │ "View My Dashboard →"
                    ┌──────▼───────┐
                    │  Dashboard   │
                    │ (persistent) │
                    └──────────────┘
```

### 4.2 Step 1: Name Input

**UI Components:**
- Progress indicator: `● ○ ○ ○ ○ ○` (1 of 6)
- Heading: "What should we call you?"
- Subtext: "This becomes your public-facing claim. It is immediately hashed — we never see or store your actual name."
- Input field: single-line text, autofocus, placeholder "Full name"
- Continue button: disabled until input.length >= 2
- Mini polar graph: empty outline, 8 faint axes

**On submit:**
```
1. behavioral_summary = behavioralCollector.summarize()
2. behavioral_hash = BLAKE3(behavioral_summary)
3. name_hash = BLAKE3(normalize_name(input.value))
4. session_key = Ed25519.generateKeypair()  // ephemeral session key
5. claim_payload = CBOR.encode({
     claim_type: "DisplayName",
     claim_hash: name_hash,
     behavioral_hash: behavioral_hash,
     device_fingerprint: current_composite_hash,
     timestamp_ms: Date.now()
   })
6. signature = session_key.sign(claim_payload)
7. POST /api/v1/0dentity/claims {
     subject_did: null,  // server assigns DID on first claim
     claim_type: "DisplayName",
     claim_hash: name_hash.hex(),
     behavioral_hash: behavioral_hash.hex(),
     device_fingerprint: current_composite_hash.hex(),
     signal_hashes: { ... },  // BTreeMap<FingerprintSignal, hex>
     signature: signature.hex(),
     public_key: session_key.publicKey.hex()
   }
8. Response: { did: "did:exo:abc123...", session_token: "...", claim_id: "..." }
9. Store DID + session_token in memory (not localStorage/cookies)
10. Update polar graph: behavioral_signature += 8, cryptographic_strength += 15
11. Advance to Step 2
```

**Normalization:**
```javascript
function normalize_name(raw) {
  return raw.trim().replace(/\s+/g, ' ');
  // Note: NO lowercasing — names are case-sensitive
}
```

### 4.3 Step 2: Email Input

**UI Components:**
- Progress: `✓ ● ○ ○ ○ ○` (2 of 6)
- Heading: "Where can the network reach you?"
- Subtext: "Email verification proves reachability. We send a one-time code; you prove possession."
- Input field: type=email, autofocus, placeholder "you@example.com"
- Button: "Send verification code →"
- Mini polar graph: behavioral_signature and cryptographic_strength slightly extended

**On submit:**
```
1. behavioral_summary = behavioralCollector.summarize()
2. email_normalized = input.value.trim().toLowerCase()
3. email_hash = BLAKE3(email_normalized)
4. POST /api/v1/0dentity/claims {
     subject_did: stored_did,
     claim_type: "Email",
     claim_hash: email_hash.hex(),
     behavioral_hash: BLAKE3(behavioral_summary).hex(),
     device_fingerprint: updated_composite_hash.hex(),
     signal_hashes: { ... },
     verification_channel: "email",
     // Current node build: creates an OTP challenge for the email channel.
     // The raw email address is not transmitted to this API.
     encrypted_channel_address: null
   }
5. Response: { challenge_id: "...", ttl_ms: 300000, channel: "email" }
6. Advance to Step 3 (Email OTP)
```

**Implementation status note:** the current node build does not route a server public-key endpoint for channel-address encryption. Clients must not depend on RSA-OAEP channel encryption in this build; the API stores only claim hashes and OTP challenge metadata.

### 4.4 Step 3: Email OTP Verification

**UI Components:**
- Progress: `✓ ✓ ● ○ ○ ○` (3 of 6)
- Heading: "Enter the code we sent to y•••@example.com"
- Six individual digit input boxes with auto-advance: `[_] [_] [_] [_] [_] [_]`
- Countdown timer: "Expires in 4:32" (counts down from 5:00)
- Resend link: "Resend code" (cooldown: 60 seconds between resends)
- Attempt counter: hidden, max 5 attempts before lockout
- Mini polar graph: shows projected growth on success (ghosted extension)

**Auto-advance behavior:**
- Each digit box accepts exactly 1 character (0–9)
- On input, focus advances to next box
- On backspace in empty box, focus moves to previous box
- On paste, distribute across all 6 boxes
- When all 6 filled, auto-submit (no button click needed)

**On submit:**
```
1. code = boxes.map(b => b.value).join('')
2. otp_keystroke_summary = behavioralCollector.summarize()  // OTP typing cadence
3. POST /api/v1/0dentity/verify {
     subject_did: stored_did,
     challenge_id: stored_challenge_id,
     code: code,  // server-side HMAC comparison
     behavioral_hash: BLAKE3(otp_keystroke_summary).hex(),
     device_fingerprint: updated_composite_hash.hex()
   }
4. Response on success: {
     verified: true,
     receipt_hash: "...",  // TrustReceipt emitted to DAG
     updated_score: { ... }  // partial PolarAxes update
   }
5. Update polar graph: communication += 35, device_trust += 12, temporal_stability += 8
6. Advance to Step 4
```

**On failure:** Increment attempt count. If < max_attempts, shake animation + "Incorrect code. X attempts remaining." If max_attempts reached, show lockout message with support contact.

**On expiry:** Timer hits 0:00, code becomes invalid, show "Code expired" with resend button.

### 4.5 Step 4: Phone Input

**UI Components:**
- Progress: `✓ ✓ ✓ ● ○ ○` (4 of 6)
- Heading: "Add a second channel"
- Subtext: "Two verified channels = exponentially higher trust. Phone adds an independent communication proof."
- Country picker dropdown (E.164 prefix)
- Phone input field: masked format `(___) ___-____`
- Button: "Send SMS code →"
- Mini polar graph: communication, device_trust, temporal_stability now visible

**On submit:**
```
1. phone_e164 = formatE164(country_code, raw_input)  // e.g., "+14155551234"
2. phone_hash = BLAKE3(phone_e164)
3. POST /api/v1/0dentity/claims {
     subject_did: stored_did,
     claim_type: "Phone",
     claim_hash: phone_hash.hex(),
     behavioral_hash: BLAKE3(behavioralCollector.summarize()).hex(),
     device_fingerprint: updated_composite_hash.hex(),
     signal_hashes: { ... },
     verification_channel: "sms",
     // Current node build: creates an OTP challenge for the SMS channel.
     // The raw phone number is not transmitted to this API.
     encrypted_channel_address: null
   }
4. Response: { challenge_id: "...", ttl_ms: 180000, channel: "sms" }
5. Advance to Step 5 (Phone OTP)
```

### 4.6 Step 5: Phone OTP Verification

Same UI pattern as Email OTP (Section 4.4) with differences:
- Timer starts at 3:00 (180s TTL — shorter = higher urgency signal)
- Heading: "Enter the code sent to +1 •••-•••-4827"
- On success: communication += 37, device_trust += 10, behavioral_signature += 8

### 4.7 Step 6: Score Reveal

**UI Components:**
- Progress: `✓ ✓ ✓ ✓ ✓ ●` (6 of 6)
- Full-bleed animated polar graph (see Section 6 for rendering spec)
- Composite score in center: large number "47 / 100"
- Eight axis labels around the perimeter with individual scores
- Per-axis breakdown list below the graph
- Metadata collection disclosure (collapsed, expandable)
- CTA button: **"View My Dashboard →"** (primary, prominent)
- Secondary link: "Explore Provenance API →"

**Score reveal animation:**
```
1. Start with empty graph (all axes at 0)
2. Animate each axis sequentially (200ms each, eased):
   - Communication: 0 → 72  (two verified channels)
   - Credential Depth: 0 → 15 (no gov ID yet)
   - Device Trust: 0 → 61 (strong fingerprint composite)
   - Behavioral Signature: 0 → 44 (baseline established)
   - Network Reputation: 0 → 10 (no peer attestations)
   - Temporal Stability: 0 → 20 (account minutes old)
   - Cryptographic Strength: 0 → 55 (Ed25519, good entropy)
   - Constitutional Standing: 0 → 30 (no governance yet)
3. Flash composite score: 0 → 47 (counter animation, 1.5s)
4. Pulse the polygon once (scale 1.0 → 1.05 → 1.0, 400ms)
```

**Metadata disclosure table** (collapsed by default, "What did we measure?" toggle):

| Signal | What It Tells Us | Stored As |
|--------|-----------------|-----------|
| Keystroke dynamics | Your unique typing rhythm | BLAKE3 histogram hash |
| Canvas rendering | Your GPU/driver combination | BLAKE3 hash |
| WebGL parameters | Your graphics hardware model | BLAKE3 hash |
| Screen geometry | Your display environment | BLAKE3 hash |
| Timezone + locale | Your geographic region | BLAKE3 hash |
| User-Agent | Your browser + OS | BLAKE3 hash |
| AudioContext | Your audio hardware stack | BLAKE3 hash |
| Font enumeration | Your installed software | BLAKE3 hash |
| IP geolocation | Your city-level location | BLAKE3 hash |
| Mouse/touch dynamics | Your interaction patterns | BLAKE3 histogram hash |
| Battery status | Device power state | BLAKE3 hash |
| Color depth + DPR | Display hardware profile | BLAKE3 hash |

Footer: "None of this raw data is stored. Each signal is hashed, and only the composite fingerprint — a single 32-byte BLAKE3 digest — persists. Your fingerprint exists as a proof, not a record."

---

## 5. Scoring Engine — The Polar Decomposition Algorithm

### 5.1 Axis Score Computation

Each axis is scored independently from 0 to 100. The algorithm is deterministic: given the same set of claims, any node must produce the identical score.

```rust
impl ZerodentityScore {
    /// Recompute the full score from the current claim set.
    /// This is the canonical scoring algorithm. All nodes must
    /// implement it identically for constitutional determinism.
    pub fn compute(
        subject_did: &Did,
        claims: &[IdentityClaim],
        fingerprints: &[DeviceFingerprint],
        behavioral_samples: &[BehavioralSample],
        now_ms: u64,
    ) -> Self {
        let axes = PolarAxes {
            communication: Self::score_communication(claims),
            credential_depth: Self::score_credential_depth(claims),
            device_trust: Self::score_device_trust(fingerprints),
            behavioral_signature: Self::score_behavioral(behavioral_samples),
            network_reputation: Self::score_network_reputation(claims),
            temporal_stability: Self::score_temporal_stability(claims, now_ms),
            cryptographic_strength: Self::score_cryptographic_strength(claims),
            constitutional_standing: Self::score_constitutional_standing(claims),
        };

        let axis_values = axes.as_array();
        let composite = axis_values.iter().sum::<f64>() / 8.0;
        let symmetry = Self::compute_symmetry(&axis_values);

        let dag_state_hash = Self::hash_claim_set(claims);
        let claim_count = claims.iter()
            .filter(|c| c.status == ClaimStatus::Verified)
            .count() as u32;

        ZerodentityScore {
            subject_did: subject_did.clone(),
            axes,
            composite,
            computed_ms: now_ms,
            dag_state_hash,
            claim_count,
            symmetry,
        }
    }
}
```

### 5.2 Per-Axis Scoring Functions

```rust
/// Communication axis (0–100)
/// Driven by verified email and phone claims.
fn score_communication(claims: &[IdentityClaim]) -> f64 {
    let mut score = 0.0;

    let verified_email = claims.iter().any(|c|
        c.claim_type == ClaimType::Email && c.status == ClaimStatus::Verified
    );
    let verified_phone = claims.iter().any(|c|
        c.claim_type == ClaimType::Phone && c.status == ClaimStatus::Verified
    );

    if verified_email { score += 35.0; }
    if verified_phone { score += 37.0; }

    // Bonus for having BOTH — independent channels multiply trust
    if verified_email && verified_phone { score += 15.0; }

    // Additional channels (future: Matrix, Signal, etc.)
    let extra_channels = claims.iter().filter(|c|
        matches!(c.claim_type, ClaimType::ProfessionalCredential { .. })
        && c.status == ClaimStatus::Verified
    ).count();
    score += (extra_channels as f64 * 4.0).min(13.0);

    score.min(100.0)
}

/// Credential Depth axis (0–100)
fn score_credential_depth(claims: &[IdentityClaim]) -> f64 {
    let mut score = 0.0;

    // Display name (basic claim, low value)
    if claims.iter().any(|c| c.claim_type == ClaimType::DisplayName) {
        score += 5.0;
    }

    // Government ID (high value)
    if claims.iter().any(|c|
        c.claim_type == ClaimType::GovernmentId && c.status == ClaimStatus::Verified
    ) { score += 35.0; }

    // Biometric liveness (high value)
    if claims.iter().any(|c|
        c.claim_type == ClaimType::BiometricLiveness && c.status == ClaimStatus::Verified
    ) { score += 30.0; }

    // Professional credentials (medium value each)
    let pro_count = claims.iter().filter(|c|
        matches!(c.claim_type, ClaimType::ProfessionalCredential { .. })
        && c.status == ClaimStatus::Verified
    ).count();
    score += (pro_count as f64 * 10.0).min(30.0);

    score.min(100.0)
}

/// Device Trust axis (0–100)
fn score_device_trust(fingerprints: &[DeviceFingerprint]) -> f64 {
    if fingerprints.is_empty() { return 0.0; }

    let mut score = 0.0;
    let latest = &fingerprints[fingerprints.len() - 1];

    // Base score for having ANY fingerprint
    score += 20.0;

    // Signal coverage (more signals = better fingerprint)
    let signal_count = latest.signal_hashes.len() as f64;
    let coverage = (signal_count / 15.0).min(1.0);  // 15 = max signals
    score += coverage * 25.0;

    // Consistency across sessions
    if let Some(consistency) = latest.consistency_score {
        // High consistency = same device = more trust
        score += consistency * 40.0;
    } else {
        // First session — partial credit
        score += 16.0;
    }

    // Bonus for multi-session consistency
    if fingerprints.len() >= 3 {
        let avg_consistency: f64 = fingerprints.iter()
            .filter_map(|f| f.consistency_score)
            .sum::<f64>() / fingerprints.len() as f64;
        score += avg_consistency * 15.0;
    }

    score.min(100.0)
}

/// Behavioral Signature axis (0–100)
fn score_behavioral(samples: &[BehavioralSample]) -> f64 {
    if samples.is_empty() { return 0.0; }

    let mut score = 0.0;

    // Base score for having behavioral data
    score += 10.0;

    // Diversity of signal types
    let signal_types: HashSet<_> = samples.iter()
        .map(|s| &s.signal_type)
        .collect();
    score += (signal_types.len() as f64 * 6.0).min(18.0);

    // Baseline similarity (higher = more consistent = more trust)
    let similarities: Vec<f64> = samples.iter()
        .filter_map(|s| s.baseline_similarity)
        .collect();
    if !similarities.is_empty() {
        let avg_sim = similarities.iter().sum::<f64>() / similarities.len() as f64;
        score += avg_sim * 40.0;
    } else {
        // First session — establishing baseline
        score += 16.0;
    }

    // Volume of samples (more data = stronger baseline)
    let sample_count = samples.len() as f64;
    score += (sample_count.ln() * 5.0).min(16.0);

    score.min(100.0)
}

/// Network Reputation axis (0–100)
fn score_network_reputation(claims: &[IdentityClaim]) -> f64 {
    let mut score = 0.0;

    // Peer attestations (5 points each, from unique attesters)
    let attestations: HashSet<_> = claims.iter()
        .filter_map(|c| match &c.claim_type {
            ClaimType::PeerAttestation { attester_did } if c.status == ClaimStatus::Verified
                => Some(attester_did.clone()),
            _ => None,
        })
        .collect();
    score += (attestations.len() as f64 * 5.0).min(40.0);

    // Delegation grants received
    let delegations = claims.iter().filter(|c|
        matches!(c.claim_type, ClaimType::DelegationGrant { .. })
        && c.status == ClaimStatus::Verified
    ).count();
    score += (delegations as f64 * 8.0).min(24.0);

    // Successfully resolved sybil challenges
    let resolved = claims.iter().filter(|c|
        matches!(c.claim_type, ClaimType::SybilChallengeResolution { .. })
        && c.status == ClaimStatus::Verified
    ).count();
    score += (resolved as f64 * 12.0).min(36.0);

    // Base: everyone starts with a small amount
    score += 10.0;

    score.min(100.0)
}

/// Temporal Stability axis (0–100)
fn score_temporal_stability(claims: &[IdentityClaim], now_ms: u64) -> f64 {
    if claims.is_empty() { return 0.0; }

    let mut score = 0.0;

    // Account age
    let oldest_claim_ms = claims.iter().map(|c| c.created_ms).min().unwrap_or(now_ms);
    let age_days = (now_ms - oldest_claim_ms) / 86_400_000;
    // Logarithmic: rapid initial growth, diminishing returns
    score += (age_days as f64).ln().max(0.0) * 8.0;
    score = score.min(35.0);

    // Verification freshness: are verified claims still within validity?
    let verified = claims.iter().filter(|c| c.status == ClaimStatus::Verified);
    let total_verified = verified.clone().count() as f64;
    let fresh_verified = verified.filter(|c| {
        match c.expires_ms {
            Some(exp) => exp > now_ms,  // not expired
            None => true,               // no expiry = always fresh
        }
    }).count() as f64;
    if total_verified > 0.0 {
        let freshness_ratio = fresh_verified / total_verified;
        score += freshness_ratio * 30.0;
    }

    // Claim renewal activity
    let renewals = claims.iter().filter(|c|
        c.verified_ms.map_or(false, |v| v != c.created_ms)  // re-verified
    ).count();
    score += (renewals as f64 * 5.0).min(20.0);

    // Session continuity
    let session_claims = claims.iter().filter(|c|
        c.claim_type == ClaimType::SessionContinuity
    ).count();
    score += (session_claims as f64 * 2.0).min(15.0);

    score.min(100.0)
}

/// Cryptographic Strength axis (0–100)
fn score_cryptographic_strength(claims: &[IdentityClaim]) -> f64 {
    let mut score = 0.0;

    // Base: having a signing key at all
    score += 15.0;

    // Key algorithm quality (from signature type of most recent claim)
    if let Some(latest) = claims.last() {
        match &latest.signature {
            Signature::Ed25519(_) => score += 25.0,
            Signature::Hybrid { .. } => score += 40.0,  // best: classical + PQ
            Signature::PostQuantum(_) => score += 35.0,
            Signature::Empty => {},
        }
    }

    // Key rotation history
    let rotations = claims.iter().filter(|c|
        matches!(c.claim_type, ClaimType::KeyRotation { .. })
    ).count();
    score += (rotations as f64 * 8.0).min(24.0);

    // Entropy attestation
    if claims.iter().any(|c| c.claim_type == ClaimType::EntropyAttestation) {
        score += 10.0;
    }

    // Penalize if key has never been rotated and account is > 90 days old
    let oldest = claims.iter().map(|c| c.created_ms).min().unwrap_or(0);
    let now_ms = claims.iter().map(|c| c.created_ms).max().unwrap_or(0);
    let age_days = (now_ms.saturating_sub(oldest)) / 86_400_000;
    if age_days > 90 && rotations == 0 {
        score -= 10.0;
    }

    score.max(0.0).min(100.0)
}

/// Constitutional Standing axis (0–100)
fn score_constitutional_standing(claims: &[IdentityClaim]) -> f64 {
    let mut score = 0.0;

    // Base: existing in the constitutional system
    score += 10.0;

    // Governance votes cast
    let votes = claims.iter().filter(|c|
        matches!(c.claim_type, ClaimType::GovernanceVote { .. })
    ).count();
    score += (votes as f64 * 4.0).min(20.0);

    // Proposals authored
    let proposals = claims.iter().filter(|c|
        matches!(c.claim_type, ClaimType::ProposalAuthored { .. })
    ).count();
    score += (proposals as f64 * 7.0).min(21.0);

    // Validator service
    let validator_rounds = claims.iter().filter(|c|
        matches!(c.claim_type, ClaimType::ValidatorService { .. })
    ).count();
    score += (validator_rounds as f64 * 5.0).min(25.0);

    // Sybil challenge participation (both sides)
    let challenge_resolutions = claims.iter().filter(|c|
        matches!(c.claim_type, ClaimType::SybilChallengeResolution { .. })
    ).count();
    score += (challenge_resolutions as f64 * 8.0).min(24.0);

    score.min(100.0)
}
```

### 5.3 Symmetry Computation

```rust
/// Symmetry index: how evenly distributed the score is across axes.
/// 1.0 = perfect octagon (all axes equal).
/// 0.0 = all score concentrated on a single axis.
///
/// Uses normalized standard deviation: symmetry = 1 - (σ / μ)
/// where σ = std dev of axis values, μ = mean.
fn compute_symmetry(axes: &[f64; 8]) -> f64 {
    let mean = axes.iter().sum::<f64>() / 8.0;
    if mean == 0.0 { return 0.0; }

    let variance = axes.iter()
        .map(|v| (v - mean).powi(2))
        .sum::<f64>() / 8.0;
    let std_dev = variance.sqrt();

    // Coefficient of variation, inverted
    let cv = std_dev / mean;
    (1.0 - cv).max(0.0).min(1.0)
}
```

### 5.4 Composite Score

```
composite = (Σ axis_values) / 8
```

Unweighted arithmetic mean. All axes are equally important by design — this incentivizes breadth over depth and prevents gaming by hyper-optimizing a single dimension.

---

## 6. Polar Graph Rendering Specification

### 6.1 SVG-Based Radar Chart

The polar graph is rendered as an inline SVG for resolution independence and animation support. No external charting libraries.

```javascript
class PolarGraph {
  constructor(container, options = {}) {
    this.container = container;
    this.size = options.size || 400;
    this.center = this.size / 2;
    this.radius = this.size * 0.38;  // leave room for labels
    this.axisCount = 8;
    this.axisAngle = (2 * Math.PI) / this.axisCount;
    this.startAngle = -Math.PI / 2;  // 12 o'clock

    this.axisLabels = [
      'Constitutional\nStanding',    // N  (0)
      'Communication',               // NE (1)
      'Credential\nDepth',           // E  (2)
      'Device\nTrust',               // SE (3)
      'Behavioral\nSignature',       // S  (4)
      'Network\nReputation',         // SW (5)
      'Temporal\nStability',         // W  (6)
      'Cryptographic\nStrength',     // NW (7)
    ];

    this.colors = {
      gridLine: 'rgba(148, 163, 184, 0.15)',     // slate-400 @ 15%
      axisLine: 'rgba(148, 163, 184, 0.3)',       // slate-400 @ 30%
      maxPolygon: 'rgba(56, 189, 248, 0.08)',     // sky-400 @ 8%
      maxStroke: 'rgba(56, 189, 248, 0.2)',       // sky-400 @ 20%
      scorePolygon: 'rgba(56, 189, 248, 0.25)',   // sky-400 @ 25%
      scoreStroke: 'rgba(56, 189, 248, 0.9)',     // sky-400 @ 90%
      scoreDot: '#38bdf8',                         // sky-400 solid
      labelText: '#94a3b8',                        // slate-400
      valueText: '#e2e8f0',                        // slate-200
      compositeText: '#f8fafc',                    // slate-50
    };

    this.svg = null;
    this.scorePolygon = null;
    this.valueDots = [];
    this.init();
  }

  init() {
    const ns = 'http://www.w3.org/2000/svg';
    this.svg = document.createElementNS(ns, 'svg');
    this.svg.setAttribute('viewBox', `0 0 ${this.size} ${this.size}`);
    this.svg.setAttribute('width', '100%');
    this.svg.setAttribute('height', '100%');
    this.svg.style.maxWidth = `${this.size}px`;

    // Concentric grid rings at 20%, 40%, 60%, 80%, 100%
    for (let ring = 1; ring <= 5; ring++) {
      const r = this.radius * (ring / 5);
      const circle = document.createElementNS(ns, 'circle');
      circle.setAttribute('cx', this.center);
      circle.setAttribute('cy', this.center);
      circle.setAttribute('r', r);
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', this.colors.gridLine);
      circle.setAttribute('stroke-width', ring === 5 ? '1.5' : '0.75');
      this.svg.appendChild(circle);
    }

    // Axis lines and labels
    for (let i = 0; i < this.axisCount; i++) {
      const angle = this.startAngle + i * this.axisAngle;
      const x2 = this.center + this.radius * Math.cos(angle);
      const y2 = this.center + this.radius * Math.sin(angle);

      // Axis line
      const line = document.createElementNS(ns, 'line');
      line.setAttribute('x1', this.center);
      line.setAttribute('y1', this.center);
      line.setAttribute('x2', x2);
      line.setAttribute('y2', y2);
      line.setAttribute('stroke', this.colors.axisLine);
      line.setAttribute('stroke-width', '1');
      this.svg.appendChild(line);

      // Label
      const labelR = this.radius + 28;
      const lx = this.center + labelR * Math.cos(angle);
      const ly = this.center + labelR * Math.sin(angle);
      const text = document.createElementNS(ns, 'text');
      text.setAttribute('x', lx);
      text.setAttribute('y', ly);
      text.setAttribute('text-anchor', 'middle');
      text.setAttribute('dominant-baseline', 'middle');
      text.setAttribute('fill', this.colors.labelText);
      text.setAttribute('font-size', '11');
      text.setAttribute('font-family', 'ui-monospace, monospace');
      // Handle multi-line labels
      const lines = this.axisLabels[i].split('\n');
      lines.forEach((lineText, li) => {
        const tspan = document.createElementNS(ns, 'tspan');
        tspan.setAttribute('x', lx);
        tspan.setAttribute('dy', li === 0 ? '0' : '1.2em');
        tspan.textContent = lineText;
        text.appendChild(tspan);
      });
      this.svg.appendChild(text);
    }

    // Max polygon (faint outline at 100% on all axes)
    const maxPoints = this._polygonPoints(Array(8).fill(100));
    const maxPoly = document.createElementNS(ns, 'polygon');
    maxPoly.setAttribute('points', maxPoints);
    maxPoly.setAttribute('fill', this.colors.maxPolygon);
    maxPoly.setAttribute('stroke', this.colors.maxStroke);
    maxPoly.setAttribute('stroke-width', '1');
    this.svg.appendChild(maxPoly);

    // Score polygon (will be animated)
    this.scorePolygon = document.createElementNS(ns, 'polygon');
    this.scorePolygon.setAttribute('points', this._polygonPoints(Array(8).fill(0)));
    this.scorePolygon.setAttribute('fill', this.colors.scorePolygon);
    this.scorePolygon.setAttribute('stroke', this.colors.scoreStroke);
    this.scorePolygon.setAttribute('stroke-width', '2');
    this.svg.appendChild(this.scorePolygon);

    // Score dots on each axis vertex
    for (let i = 0; i < this.axisCount; i++) {
      const dot = document.createElementNS(ns, 'circle');
      dot.setAttribute('cx', this.center);
      dot.setAttribute('cy', this.center);
      dot.setAttribute('r', '4');
      dot.setAttribute('fill', this.colors.scoreDot);
      this.svg.appendChild(dot);
      this.valueDots.push(dot);
    }

    this.container.appendChild(this.svg);
  }

  /// Animate from current values to new values.
  /// duration in ms, easing function applied per-axis.
  animateTo(values, duration = 1600) {
    // values: [f64; 8] in axis order
    const startValues = this._currentValues || Array(8).fill(0);
    const startTime = performance.now();

    const ease = t => t < 0.5
      ? 4 * t * t * t
      : 1 - Math.pow(-2 * t + 2, 3) / 2;  // cubic ease-in-out

    const animate = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const easedProgress = ease(progress);

      const current = startValues.map((start, i) =>
        start + (values[i] - start) * easedProgress
      );

      this._updatePolygon(current);

      if (progress < 1) {
        requestAnimationFrame(animate);
      } else {
        this._currentValues = values;
      }
    };

    requestAnimationFrame(animate);
  }

  _updatePolygon(values) {
    this.scorePolygon.setAttribute('points', this._polygonPoints(values));
    for (let i = 0; i < this.axisCount; i++) {
      const angle = this.startAngle + i * this.axisAngle;
      const r = this.radius * (values[i] / 100);
      this.valueDots[i].setAttribute('cx', this.center + r * Math.cos(angle));
      this.valueDots[i].setAttribute('cy', this.center + r * Math.sin(angle));
    }
  }

  _polygonPoints(values) {
    return values.map((v, i) => {
      const angle = this.startAngle + i * this.axisAngle;
      const r = this.radius * (v / 100);
      return `${this.center + r * Math.cos(angle)},${this.center + r * Math.sin(angle)}`;
    }).join(' ');
  }
}
```

---

## 7. API Specification

All endpoints under `/api/v1/0dentity/`. Authentication: session token from initial claim (Bearer header). Write operations require token; reads are public (constitutional transparency).

### 7.1 Onboarding Endpoints

```
POST /api/v1/0dentity/claims
  Description: Submit a new identity claim.
  Auth: Bearer token (or none for first claim — server issues DID + token)
  Request body (JSON):
    {
      "subject_did": "did:exo:..." | null,         // null on first claim
      "claim_type": "DisplayName" | "Email" | "Phone" | ...,
      "claim_hash": "hex-encoded BLAKE3 hash of claim value",
      "behavioral_hash": "hex-encoded BLAKE3 hash of behavioral summary",
      "device_fingerprint": "hex-encoded composite fingerprint hash",
      "signal_hashes": {                            // per-signal hashes
        "CanvasRendering": "hex...",
        "WebGLParameters": "hex...",
        ...
      },
      "verification_channel": "email" | "sms" | null,
      "encrypted_channel_address": null,
      "signature": "hex-encoded Ed25519 signature",
      "public_key": "hex-encoded Ed25519 public key"
    }
  Response 201:
    {
      "did": "did:exo:...",                        // assigned on first claim
      "session_token": "...",                      // issued on first claim
      "claim_id": "uuid",
      "claim_hash": "hex...",
      "dag_node_hash": "hex...",                   // where the claim was recorded
      "receipt_hash": "hex...",                    // TrustReceipt for this action
      "challenge_id": "uuid" | null,               // if verification needed
      "challenge_ttl_ms": 300000 | null,
      "updated_score": { ... }                     // partial PolarAxes
    }
  Response 400: { "error": "Invalid claim_hash format" }
  Response 409: { "error": "Claim type already exists for this DID" }

POST /api/v1/0dentity/verify
  Description: Submit OTP code to verify a claim.
  Auth: Bearer session_token
  Request body (JSON):
    {
      "subject_did": "did:exo:...",
      "challenge_id": "uuid",
      "code": "123456",
      "behavioral_hash": "hex...",
      "device_fingerprint": "hex..."
    }
  Response 200 (success):
    {
      "verified": true,
      "receipt_hash": "hex...",
      "claim_id": "uuid",
      "updated_score": { ... }
    }
  Response 200 (failure):
    {
      "verified": false,
      "attempts_remaining": 3,
      "error": "Incorrect code"
    }
  Response 410: { "error": "Challenge expired" }
  Response 423: { "error": "Too many attempts. Locked out." }

POST /api/v1/0dentity/verify/resend
  Description: Resend OTP code for an active challenge.
  Auth: Bearer session_token
  Request body (JSON):
    {
      "subject_did": "did:exo:...",
      "challenge_id": "uuid"
    }
  Response 200: { "new_challenge_id": "uuid", "ttl_ms": 300000 }
  Response 429: { "error": "Resend cooldown. Wait 45 seconds." }
```

### 7.2 Score & Identity Endpoints

```
GET /api/v1/0dentity/:did/score
  Description: Retrieve current 0dentity score for a DID.
  Auth: None (public — constitutional transparency)
  Response 200:
    {
      "subject_did": "did:exo:...",
      "composite": 47.125,
      "symmetry": 0.634,
      "axes": {
        "communication": 72.0,
        "credential_depth": 15.0,
        "device_trust": 61.0,
        "behavioral_signature": 44.0,
        "network_reputation": 10.0,
        "temporal_stability": 20.0,
        "cryptographic_strength": 55.0,
        "constitutional_standing": 30.0
      },
      "computed_ms": 1743724800000,
      "dag_state_hash": "hex...",
      "claim_count": 5,
      "history_available": true
    }
  Response 404: { "error": "DID not found" }

GET /api/v1/0dentity/:did/claims
  Description: List all claims for a DID.
  Auth: Bearer session_token (owner only — claims are private)
  Query params:
    ?status=verified         // filter by status
    ?type=Email              // filter by claim type
    ?limit=50&offset=0       // pagination
  Response 200:
    {
      "claims": [
        {
          "claim_id": "uuid",
          "claim_type": "Email",
          "claim_hash": "hex...",
          "status": "Verified",
          "created_ms": 1743724800000,
          "verified_ms": 1743724850000,
          "expires_ms": null,
          "dag_node_hash": "hex..."
        },
        ...
      ],
      "total": 5,
      "limit": 50,
      "offset": 0
    }

GET /api/v1/0dentity/:did/score/history
  Description: Score history over time (for dashboard graph).
  Auth: None (public)
  Query params:
    ?from_ms=...&to_ms=...   // time range
    ?resolution=daily        // daily | weekly | monthly
  Response 200:
    {
      "snapshots": [
        {
          "computed_ms": 1743724800000,
          "composite": 47.125,
          "axes": { ... },
          "claim_count": 5
        },
        ...
      ]
    }

GET /api/v1/0dentity/:did/fingerprints
  Description: Fingerprint consistency timeline (owner only).
  Auth: Bearer session_token
  Response 200:
    {
      "fingerprints": [
        {
          "composite_hash": "hex...",
          "captured_ms": 1743724800000,
          "consistency_score": 0.94,
          "signal_count": 14
        },
        ...
      ]
    }

POST /api/v1/0dentity/:did/attest
  Description: Attest/vouch for another identity (peer attestation).
  Auth: Bearer session_token (attester must be verified).
  Signature: Ed25519 over canonical CBOR tuple
    ("exo.zerodentity.attestation.v1", attester_did, target_did,
     attestation_type, message_hash, created_ms)
  Request body:
    {
      "target_did": "did:exo:...",
      "attestation_type": "Identity" | "Professional" | "Trustworthy" | "Character",
      "message_hash": "32-byte hex...",  // optional hash of attestation message
      "created_ms": 1743724800000,
      "attester_public_key": "32-byte Ed25519 public key hex",
      "signature": "64-byte Ed25519 signature hex"
    }
  Response 201:
    {
      "attestation_id": "deterministic blake3 hex",
      "receipt_hash": "hex...",
      "attester_score_impact": { "network_reputation": "+3" },
      "target_score_impact": { "network_reputation": "+5" }
    }
```

### 7.3 Server Public Key Endpoint

No server public-key endpoint is routed in the current node build. ONYX-4 R6 removed the previous `/api/v1/0dentity/server-key` handler because it advertised key-agreement semantics while returning a BLAKE3 digest wrapped as PEM. Clients must treat this endpoint as absent.

---

## 8. Dashboard — "View My Dashboard"

The dashboard is the persistent home of the user's 0dentity after onboarding. Self-contained HTML/CSS/JavaScript — zero framework dependencies — consistent with the existing ExoChain dashboard pattern (`dashboard.rs`, `receipt_dashboard.rs`).

### 8.1 Route

```
GET /0dentity/dashboard
```

Served as a single HTML document with all CSS and JavaScript inlined. Uses CSS custom properties for theming.

### 8.2 Layout

```
┌──────────────────────────────────────────────────────────────────┐
│  HEADER BAR                                                      │
│  [0dentity logo]   did:exo:abc123...   Score: 47   [⚙ Settings] │
├──────────────────────┬───────────────────────────────────────────┤
│                      │                                           │
│   POLAR GRAPH        │   SCORE BREAKDOWN                         │
│                      │                                           │
│   [interactive       │   Communication ████████████░░ 72         │
│    SVG radar         │   Cred. Depth   ██░░░░░░░░░░░░ 15         │
│    chart with        │   Device Trust  ████████████░░ 61         │
│    hover details]    │   Behavioral    ████████░░░░░░ 44         │
│                      │   Network Rep.  ██░░░░░░░░░░░░ 10         │
│   Composite: 47      │   Temporal      ████░░░░░░░░░░ 20         │
│   Symmetry: 0.63     │   Crypto Str.   ██████████░░░░ 55         │
│                      │   Constitutional████████░░░░░░ 30         │
│                      │                                           │
├──────────────────────┴───────────────────────────────────────────┤
│  CLAIMS TABLE                                                    │
│  ┌──────────┬──────────┬──────────┬───────────┬────────────────┐ │
│  │ Type     │ Hash     │ Status   │ Verified  │ Expires        │ │
│  ├──────────┼──────────┼──────────┼───────────┼────────────────┤ │
│  │ Name     │ b3:7f2a… │ Verified │ 2 min ago │ Never          │ │
│  │ Email    │ b3:c91e… │ Verified │ 1 min ago │ Never          │ │
│  │ Phone    │ b3:3d8f… │ Verified │ 30s ago   │ Never          │ │
│  │ Device   │ b3:a4c0… │ Verified │ 30s ago   │ 30 days        │ │
│  │ Behavior │ b3:f71b… │ Verified │ 30s ago   │ 7 days         │ │
│  └──────────┴──────────┴──────────┴───────────┴────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│  SCORE HISTORY TIMELINE                                          │
│  [sparkline graph showing composite score over time]             │
│  ────●────────●────────●────────────────── ● = score snapshot    │
│      47       47       47                                        │
├──────────────────────────────────────────────────────────────────┤
│  GROWTH ACTIONS                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ 🔑 Add Government ID          +35 Credential Depth    [ → ]│ │
│  │ 👤 Request Peer Attestation   +5  Network Reputation   [ → ]│ │
│  │ 🗳  Cast Governance Vote       +4  Constitutional      [ → ]│ │
│  │ 🔄 Rotate Signing Key         +8  Crypto Strength      [ → ]│ │
│  └─────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│  RECENT RECEIPTS                                                 │
│  [last 10 TrustReceipts with drill-down links to /receipts]     │
├──────────────────────────────────────────────────────────────────┤
│  DEVICE FINGERPRINT CONSISTENCY                                  │
│  Session 1: ████████████████████ 1.00 (baseline)                │
│  Session 2: ██████████████████░░ 0.94                           │
│  Session 3: ███████████████████░ 0.97                           │
├──────────────────────────────────────────────────────────────────┤
│  FOOTER                                                          │
│  Provenance API · Sentinels · Receipts · Constitutional Docs    │
└──────────────────────────────────────────────────────────────────┘
```

### 8.3 Polling & Real-Time Updates

```javascript
// Dashboard polls every 5 seconds for score updates
const POLL_INTERVAL = 5000;

async function pollDashboard() {
  const [score, claims, history, fingerprints] = await Promise.all([
    fetch(`/api/v1/0dentity/${myDid}/score`).then(r => r.json()),
    fetch(`/api/v1/0dentity/${myDid}/claims`, {
      headers: { 'Authorization': `Bearer ${sessionToken}` }
    }).then(r => r.json()),
    fetch(`/api/v1/0dentity/${myDid}/score/history?resolution=daily`)
      .then(r => r.json()),
    fetch(`/api/v1/0dentity/${myDid}/fingerprints`, {
      headers: { 'Authorization': `Bearer ${sessionToken}` }
    }).then(r => r.json()),
  ]);

  // Animate polar graph to new values if changed
  const newAxes = [
    score.axes.constitutional_standing,
    score.axes.communication,
    score.axes.credential_depth,
    score.axes.device_trust,
    score.axes.behavioral_signature,
    score.axes.network_reputation,
    score.axes.temporal_stability,
    score.axes.cryptographic_strength,
  ];
  polarGraph.animateTo(newAxes, 800);

  updateCompositeDisplay(score.composite, score.symmetry);
  updateClaimsTable(claims.claims);
  updateHistorySparkline(history.snapshots);
  updateFingerprintConsistency(fingerprints.fingerprints);
}

setInterval(pollDashboard, POLL_INTERVAL);
```

### 8.4 Interactive Polar Graph Behaviors

- **Hover on axis**: highlights that axis, shows tooltip with score value + contributing claims
- **Click on axis**: expands a detail panel below showing all claims feeding that axis, with individual contribution amounts
- **Hover on polygon fill**: shows composite score + symmetry index
- **Responsive**: on mobile viewports (< 768px), the graph scales to full width and the breakdown moves below

### 8.5 Growth Actions

Each growth action links to a flow or external integration:
- "Add Government ID" → opens modal with ID verification instructions (future: integration with verification provider)
- "Request Peer Attestation" → generates a shareable attestation request link
- "Cast Governance Vote" → links to `/` main dashboard's governance section
- "Rotate Signing Key" → opens key rotation flow (generate new keypair, sign transition)

### 8.6 Theme Constants

```css
:root {
  --bg-primary: #0a0e17;         /* deep navy */
  --bg-secondary: #111827;       /* card backgrounds */
  --bg-tertiary: #1e293b;        /* elevated surfaces */
  --text-primary: #f8fafc;       /* slate-50 */
  --text-secondary: #94a3b8;     /* slate-400 */
  --text-muted: #64748b;         /* slate-500 */
  --accent: #38bdf8;             /* sky-400 — primary accent */
  --accent-dim: rgba(56, 189, 248, 0.15);
  --success: #4ade80;            /* green-400 */
  --warning: #fbbf24;            /* amber-400 */
  --danger: #f87171;             /* red-400 */
  --border: rgba(148, 163, 184, 0.1);
  --font-mono: ui-monospace, 'Cascadia Code', 'Source Code Pro',
               'Fira Code', Menlo, Consolas, monospace;
  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont,
               'Segoe UI', Roboto, sans-serif;
  --radius: 8px;
  --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
}
```

---

## 9. Persistence Layer

### 9.1 New SQLite Tables

Extend the existing `SqliteDagStore` with 0dentity-specific tables.

```sql
-- Identity claims
CREATE TABLE IF NOT EXISTS identity_claims (
    claim_id       TEXT PRIMARY KEY,
    subject_did    TEXT NOT NULL,
    claim_type     TEXT NOT NULL,
    claim_hash     BLOB NOT NULL,        -- 32-byte BLAKE3
    status         TEXT NOT NULL DEFAULT 'Pending',
    created_ms     INTEGER NOT NULL,
    verified_ms    INTEGER,
    expires_ms     INTEGER,
    signature      BLOB NOT NULL,
    dag_node_hash  BLOB NOT NULL         -- FK to dag_nodes
);
CREATE INDEX IF NOT EXISTS idx_claims_did ON identity_claims(subject_did);
CREATE INDEX IF NOT EXISTS idx_claims_type ON identity_claims(claim_type);
CREATE INDEX IF NOT EXISTS idx_claims_status ON identity_claims(status);

-- Device fingerprints
CREATE TABLE IF NOT EXISTS device_fingerprints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_did     TEXT NOT NULL,
    composite_hash  BLOB NOT NULL,       -- 32-byte BLAKE3
    signal_hashes   BLOB NOT NULL,       -- CBOR-encoded BTreeMap
    captured_ms     INTEGER NOT NULL,
    consistency_score REAL               -- 0.0–1.0, NULL on first
);
CREATE INDEX IF NOT EXISTS idx_fp_did ON device_fingerprints(subject_did);

-- Behavioral samples
CREATE TABLE IF NOT EXISTS behavioral_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_did     TEXT NOT NULL,
    sample_hash     BLOB NOT NULL,
    signal_type     TEXT NOT NULL,
    captured_ms     INTEGER NOT NULL,
    baseline_similarity REAL             -- 0.0–1.0, NULL if no baseline
);
CREATE INDEX IF NOT EXISTS idx_behav_did ON behavioral_samples(subject_did);

-- Score snapshots (for history timeline)
CREATE TABLE IF NOT EXISTS score_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_did     TEXT NOT NULL,
    composite       REAL NOT NULL,
    symmetry        REAL NOT NULL,
    communication   REAL NOT NULL,
    credential_depth REAL NOT NULL,
    device_trust    REAL NOT NULL,
    behavioral_signature REAL NOT NULL,
    network_reputation REAL NOT NULL,
    temporal_stability REAL NOT NULL,
    cryptographic_strength REAL NOT NULL,
    constitutional_standing REAL NOT NULL,
    dag_state_hash  BLOB NOT NULL,
    claim_count     INTEGER NOT NULL,
    computed_ms     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_score_did_time
    ON score_snapshots(subject_did, computed_ms);

-- OTP challenges (ephemeral, cleaned up after TTL + grace period)
CREATE TABLE IF NOT EXISTS otp_challenges (
    challenge_id    TEXT PRIMARY KEY,
    subject_did     TEXT NOT NULL,
    channel         TEXT NOT NULL,        -- "email" or "sms"
    code_hmac       BLOB NOT NULL,        -- 32-byte HMAC
    dispatched_ms   INTEGER NOT NULL,
    ttl_ms          INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 5,
    state           TEXT NOT NULL DEFAULT 'Pending'
);

-- Peer attestations
CREATE TABLE IF NOT EXISTS peer_attestations (
    attestation_id  TEXT PRIMARY KEY,
    attester_did    TEXT NOT NULL,
    target_did      TEXT NOT NULL,
    attestation_type TEXT NOT NULL,
    message_hash    BLOB,
    created_ms      INTEGER NOT NULL,
    attester_public_key BLOB NOT NULL,
    signature       BLOB NOT NULL,
    dag_node_hash   BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attest_target ON peer_attestations(target_did);
CREATE INDEX IF NOT EXISTS idx_attest_attester ON peer_attestations(attester_did);

-- DID ↔ Session token mapping
CREATE TABLE IF NOT EXISTS identity_sessions (
    session_token   TEXT PRIMARY KEY,
    subject_did     TEXT NOT NULL,
    public_key      BLOB NOT NULL,
    created_ms      INTEGER NOT NULL,
    last_active_ms  INTEGER NOT NULL,
    revoked         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_session_did ON identity_sessions(subject_did);
```

### 9.2 Migration Strategy

Add a `schema_version` check in `SqliteDagStore::open()`:

```rust
const ZERODENTITY_SCHEMA_VERSION: u32 = 1;

fn migrate_zerodentity_schema(conn: &Connection) -> DagResult<()> {
    let current: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations WHERE module = '0dentity'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if current < ZERODENTITY_SCHEMA_VERSION {
        conn.execute_batch(ZERODENTITY_DDL)?;
        conn.execute(
            "INSERT INTO schema_migrations (module, version, applied_ms) VALUES ('0dentity', ?1, ?2)",
            params![ZERODENTITY_SCHEMA_VERSION, timestamp_ms()],
        )?;
    }
    Ok(())
}
```

---

## 10. Integration Points with Existing ExoChain

### 10.1 Claim → DAG Node

Every claim creates a DagNode in the existing DAG:
```rust
let claim_payload = serde_cbor::to_vec(&claim).unwrap();
let node = DagNode {
    hash: blake3_hash(&claim_payload),
    creator_did: subject_did.clone(),
    parents: current_tips,          // link to DAG tips
    payload_hash: blake3_hash(&claim_payload),
    timestamp: hlc.now(),
    signature: session_signature,
};
store.put(&node)?;
```

### 10.2 Claim Verification → Trust Receipt

Every successful verification emits a TrustReceipt:
```rust
let receipt = TrustReceipt::new(
    blake3_hash(&receipt_payload),
    subject_did.clone(),
    format!("claim_verified:{}", claim_type),
    claim_hash,
    ReceiptOutcome::Executed,
    authority_chain_hash,
    None,  // consent_reference
    None,  // challenge_reference
    timestamp_ms(),
);
store.save_receipt(&receipt)?;
```

### 10.3 Score → Passport API

The existing PassportAPI at `/api/v1/agents/:did/passport` is extended to include the 0dentity score:
```rust
// In passport.rs, add to PassportResponse:
pub zerodentity_score: Option<ZerodentityScore>,
```

### 10.4 Sentinel Integration

Add a new sentinel check: `ScoreIntegrity` — verifies that stored scores are deterministically reproducible from the claim DAG:
```rust
SentinelCheck::ScoreIntegrity => {
    // Pick a random DID, recompute score from claims, compare to stored
    let stored_score = load_latest_score(did)?;
    let claims = load_claims(did)?;
    let recomputed = ZerodentityScore::compute(did, &claims, ...);
    if (stored_score.composite - recomputed.composite).abs() > 0.001 {
        return SentinelStatus { healthy: false, message: "Score drift detected" };
    }
}
```

### 10.5 Telegram Adjutant Integration

Add 0dentity commands to the Telegram adjutant:
- `/0dentity <did>` — shows a user's polar graph summary via text
- `/0dentity-alerts` — shows score anomalies (sudden drops, fingerprint mismatches)
- Inline button: `[View Full Score →]` links to dashboard

### 10.6 Router Wiring (main.rs)

```rust
// In main.rs, alongside existing routers:
let zerodentity_state = ZerodentityState::new(store.clone());
let zerodentity_router = zerodentity_router(zerodentity_state);
let zerodentity_dashboard = zerodentity_dashboard_router();

let extra_router = Router::new()
    .merge(governance_router)
    .merge(passport_router)
    .merge(challenge_router)
    .merge(provenance_router)
    .merge(receipt_dashboard_router)
    .merge(sentinel_router)
    .merge(zerodentity_router)           // NEW
    .merge(zerodentity_dashboard)         // NEW
    .layer(auth_middleware);
```

---

## 11. Privacy & Security Specification

### 11.1 Data Classification

| Data Category | Classification | Storage | Retention |
|--------------|---------------|---------|-----------|
| Raw PII (name, email, phone) | **NEVER STORED** | Hashed client-side | 0 seconds |
| Raw fingerprint signals | **NEVER STORED** | Hashed client-side | 0 seconds |
| Raw behavioral biometrics | **NEVER STORED** | Summarized + hashed client-side | 0 seconds |
| BLAKE3 claim hashes | Pseudonymous | SQLite | Indefinite |
| Composite fingerprint hash | Pseudonymous | SQLite | Indefinite |
| Behavioral histogram hash | Pseudonymous | SQLite | Indefinite |
| Score snapshots | Public | SQLite | Indefinite |
| Session tokens | Secret | SQLite | Until revoked |
| OTP HMAC hashes | Ephemeral | SQLite | TTL + 1 hour grace |
| Ed25519 public keys | Public | SQLite | Indefinite |
| Encrypted channel addresses | Transit only | RAM only | Zeroed after OTP dispatch |

### 11.2 Cryptographic Primitives

| Operation | Algorithm | Parameters |
|-----------|-----------|------------|
| Content addressing | BLAKE3 | 256-bit output |
| Claim signing | Ed25519 | 64-byte signatures |
| OTP HMAC | SHA-256 HMAC | 256-bit key, 6-digit code |
| Channel encryption | Not routed in current node build | No server public-key endpoint |
| Session token | getrandom | 256-bit, hex-encoded |
| Fingerprint consistency | Jaccard similarity | Over signal hash sets |

### 11.3 Threat Model

| Threat | Mitigation |
|--------|------------|
| Server compromise | No PII to steal — only irreversible hashes |
| Fingerprint replay | Behavioral biometrics change per-session; composite includes behavioral hash |
| OTP interception | Time-limited (3–5 min), attempt-limited (5), HMAC-verified |
| Score manipulation | Deterministic recomputation from DAG; sentinel verifies integrity |
| Sybil identity | Behavioral signatures are unique; device fingerprints resist duplication; peer attestations require real trust relationships |
| Session hijack | Tokens bound to DID + public key; fingerprint consistency check on each request |

### 11.4 Right to Erasure

A user can request deletion of their 0dentity. This:
1. Revokes all active sessions
2. Marks all claims as `Revoked`
3. Zeroes score snapshots
4. Emits a TrustReceipt with action_type `"identity_erased"` and outcome `Executed`
5. The DAG nodes remain (append-only) but the claim payloads are replaced with a tombstone marker
6. The DID becomes permanently unusable

```
DELETE /api/v1/0dentity/:did
  Auth: Bearer session_token (owner only)
  Response 200: { "erased": true, "receipt_hash": "hex..." }
```

---

## 12. Implementation Modules

### 12.1 File Structure

```
crates/exo-node/src/
├── zerodentity/
│   ├── mod.rs              // Module root, re-exports
│   ├── types.rs            // IdentityClaim, ClaimType, PolarAxes, etc.
│   ├── scoring.rs          // ZerodentityScore::compute() and all axis functions
│   ├── onboarding.rs       // POST /claims, POST /verify, POST /verify/resend
│   ├── api.rs              // GET /score, GET /claims, GET /history, etc.
│   ├── fingerprint.rs      // DeviceFingerprint, consistency computation
│   ├── behavioral.rs       // BehavioralSample, baseline comparison
│   ├── otp.rs              // OtpChallenge state machine, HMAC generation/verification
│   ├── attestation.rs      // Peer attestation creation and validation
│   ├── dashboard.rs        // Self-contained HTML dashboard at /0dentity/dashboard
│   ├── onboarding_ui.rs    // Self-contained HTML onboarding flow at /0dentity
│   ├── store.rs            // SQLite persistence layer (tables, queries, migrations)
│   └── tests.rs            // Comprehensive test suite
```

### 12.2 Test Requirements

Minimum test coverage per module:

| Module | Required Tests |
|--------|---------------|
| `types.rs` | Serialization roundtrip for every type; ClaimType equality; ClaimStatus transitions |
| `scoring.rs` | Each axis function with zero claims, minimal claims, maximum claims; composite calculation; symmetry for uniform/skewed/zero distributions; determinism (same input → same output) |
| `onboarding.rs` | First claim creates DID; duplicate claim rejected; OTP dispatch returns challenge; OTP verify success/failure/expiry/lockout; resend cooldown |
| `api.rs` | Score lookup found/not-found; claims list with filters; history with resolution; fingerprint list auth-required; attestation creation |
| `fingerprint.rs` | Consistency score: identical = 1.0, completely different = 0.0, partial overlap = intermediate; composite hash determinism |
| `behavioral.rs` | Histogram quantization; baseline similarity with/without prior samples; empty sample handling |
| `otp.rs` | HMAC generation and verification; TTL expiry; attempt counting; lockout trigger |
| `attestation.rs` | Self-attestation rejected; duplicate attestation rejected; attestation from unverified DID rejected; score impact calculation |
| `dashboard.rs` | HTML response contains required elements; CSS variables present; JavaScript poll function present |
| `store.rs` | CRUD for all tables; index usage verification; migration idempotency |

---

## 13. Operational Readiness

### 13.1 Configuration (Environment Variables)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ZERODENTITY_ENABLED` | No | `true` | Enable/disable the 0dentity module |
| `ZERODENTITY_OTP_EMAIL_TTL_MS` | No | `300000` | Email OTP time-to-live |
| `ZERODENTITY_OTP_SMS_TTL_MS` | No | `180000` | SMS OTP time-to-live |
| `ZERODENTITY_OTP_MAX_ATTEMPTS` | No | `5` | Max OTP entry attempts |
| `ZERODENTITY_OTP_RESEND_COOLDOWN_MS` | No | `60000` | Cooldown between resends |
| `ZERODENTITY_SCORE_SNAPSHOT_INTERVAL_MS` | No | `3600000` | Score snapshot frequency |
| `ZERODENTITY_FINGERPRINT_EXPIRY_DAYS` | No | `30` | Days before fingerprint claim expires |
| `ZERODENTITY_BEHAVIORAL_EXPIRY_DAYS` | No | `7` | Days before behavioral claim expires |
| `SMTP_HOST` | Yes* | — | SMTP server for email OTP dispatch |
| `SMTP_PORT` | No | `587` | SMTP port |
| `SMTP_USERNAME` | Yes* | — | SMTP authentication |
| `SMTP_PASSWORD` | Yes* | — | SMTP authentication |
| `SMTP_FROM_ADDRESS` | No | `noreply@0dentity.io` | From address for OTP emails |
| `SMS_PROVIDER` | Yes* | — | SMS provider (twilio, vonage) |
| `SMS_API_KEY` | Yes* | — | SMS provider API key |
| `SMS_FROM_NUMBER` | Yes* | — | SMS sender number |

*Required only if OTP verification is active. Can run in hash-only mode without verification for development.

### 13.2 Metrics (Prometheus)

```
# TYPE zerodentity_claims_total counter
zerodentity_claims_total{claim_type="Email",status="Verified"} 142

# TYPE zerodentity_score_composite histogram
zerodentity_score_composite_bucket{le="25"} 23
zerodentity_score_composite_bucket{le="50"} 89
zerodentity_score_composite_bucket{le="75"} 134
zerodentity_score_composite_bucket{le="100"} 142

# TYPE zerodentity_otp_verifications_total counter
zerodentity_otp_verifications_total{channel="email",result="success"} 138
zerodentity_otp_verifications_total{channel="email",result="failure"} 12
zerodentity_otp_verifications_total{channel="sms",result="success"} 129

# TYPE zerodentity_fingerprint_consistency gauge
zerodentity_fingerprint_consistency_avg 0.94

# TYPE zerodentity_onboarding_completion_rate gauge
zerodentity_onboarding_completion_rate 0.87
```

### 13.3 Sentinel Checks

Two new sentinel checks specific to 0dentity:

1. **ScoreIntegrity**: randomly sample a DID, recompute score from claims, verify it matches stored score within ε = 0.001
2. **OtpCleanup**: verify that expired OTP challenges are cleaned up (state != Pending where dispatched_ms + ttl_ms < now)

---

## 14. Why This Liberates AIs

This specification is designed to be **picked up by any capable AI and implemented end-to-end** because:

1. **Every type is defined in Rust syntax** — no ambiguity about field names, types, or derive macros. Copy-paste into a `.rs` file and it compiles.

2. **Every algorithm is deterministic pseudocode** — the scoring functions are complete implementations, not descriptions of what they should do.

3. **Every API endpoint has request/response schemas** — an AI can generate the axum handlers, the client fetch calls, and the integration tests from the schema alone.

4. **Every UI component has behavioral specification** — the auto-advance OTP boxes, the polar graph animation easing function, the dashboard polling interval. No design decisions left to guess.

5. **Every signal collector is implemented in JavaScript** — the fingerprinting code is not "collect canvas fingerprint" but the actual `canvas.toDataURL()` call with exact rendering instructions.

6. **The database schema is complete DDL** — `CREATE TABLE` statements ready to execute, with indexes and data types.

7. **Integration points reference exact existing code** — not "integrate with the DAG" but "call `store.put(&node)` with these exact fields."

8. **The threat model enumerates attacks and mitigations** — security decisions are made, not deferred.

9. **Configuration is enumerated** — every environment variable, its default, its purpose. An AI deploying this knows exactly what to set.

10. **Test requirements are specific** — not "write tests" but "test that identical fingerprint → consistency 1.0, completely different → 0.0, partial overlap → intermediate value."

An AI reading this document has everything it needs to:
- Create the Rust module structure
- Implement every type, function, and handler
- Write the SQL migrations
- Build the self-contained HTML dashboards
- Generate comprehensive tests
- Wire it into the existing ExoChain codebase
- Deploy with correct configuration

The document is the prompt. The prompt is the product.

---

*0dentity — sovereign trust, cryptographically scored, perpetually evolving.*
