//! Foundational 0dentity types.
//!
//! All fractional values use **basis points** (0–10_000 = 0%–100.00%) so that
//! the workspace's `float_arithmetic = "deny"` lint is satisfied and all
//! computations remain fully deterministic across platforms.
//!
//! Spec reference: §2 (Foundational Types).

use std::{collections::BTreeMap, fmt};

pub use exo_core::types::Signature;
use exo_core::types::{Did, Hash256};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ClaimType
// ---------------------------------------------------------------------------

/// The universe of claim types recognised by 0dentity.
///
/// Each variant maps to one or more axes on the polar graph.
/// Spec §2.2.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

// ---------------------------------------------------------------------------
// ClaimStatus
// ---------------------------------------------------------------------------

/// Verification status of an identity claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

// ---------------------------------------------------------------------------
// IdentityClaim
// ---------------------------------------------------------------------------

/// A single atomic claim made by an identity.
///
/// Claims are content-addressed via BLAKE3. The `claim_hash` field is the
/// authoritative identifier; `dag_node_hash` links each claim into the
/// append-only DAG.
/// Spec §2.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// `None` = does not expire.
    pub expires_ms: Option<u64>,
    /// Signature of the subject over the claim payload.
    pub signature: Signature,
    /// Hash of the DAG node where this claim is recorded.
    pub dag_node_hash: Hash256,
}

// ---------------------------------------------------------------------------
// PolarAxes
// ---------------------------------------------------------------------------

/// The 8 axes of the 0dentity polar graph.
///
/// All values are in **basis points** (0–10_000 = 0%–100.00%) to satisfy the
/// workspace's no-floating-point determinism requirement.
/// Spec §2.2, §5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolarAxes {
    /// Verified reachability: email + phone channels (bp).
    pub communication: u32,
    /// KYC depth: government ID, biometric liveness (bp).
    pub credential_depth: u32,
    /// Fingerprint consistency: device binding stability (bp).
    pub device_trust: u32,
    /// Typing cadence, interaction patterns, session rhythm (bp).
    pub behavioral_signature: u32,
    /// Peer attestations, vouches, delegation history (bp).
    pub network_reputation: u32,
    /// Account age, verification freshness, claim renewal (bp).
    pub temporal_stability: u32,
    /// Key algorithm, entropy, rotation hygiene (bp).
    pub cryptographic_strength: u32,
    /// Governance participation, challenge record (bp).
    pub constitutional_standing: u32,
}

impl PolarAxes {
    /// Return all 8 axis values as an array (in basis points).
    #[must_use]
    pub fn as_array(&self) -> [u32; 8] {
        [
            self.communication,
            self.credential_depth,
            self.device_trust,
            self.behavioral_signature,
            self.network_reputation,
            self.temporal_stability,
            self.cryptographic_strength,
            self.constitutional_standing,
        ]
    }
}

// ---------------------------------------------------------------------------
// ZerodentityScore
// ---------------------------------------------------------------------------

/// Full 0dentity polar-decomposition score for a DID.
///
/// `composite` and `symmetry` are in basis points (0–10_000).
/// Spec §2.2, §5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZerodentityScore {
    /// The DID this score belongs to.
    pub subject_did: Did,
    /// Per-axis scores (each in basis points, 0–10_000).
    pub axes: PolarAxes,
    /// Composite score: unweighted mean of all axes (basis points).
    pub composite: u32,
    /// When this score was last computed (epoch ms).
    pub computed_ms: u64,
    /// Hash of the claim DAG state at computation time.
    pub dag_state_hash: Hash256,
    /// Number of verified claims contributing to this score.
    pub claim_count: u32,
    /// Shape symmetry index (0–10_000 bp; 10_000 = perfect octagon).
    pub symmetry: u32,
}

// ---------------------------------------------------------------------------
// DeviceFingerprint
// ---------------------------------------------------------------------------

/// A single device fingerprint composite.
///
/// `consistency_score_bp` is in basis points (0–10_000), or `None` on first
/// capture. Only composite hashes are ever persisted — raw signals are
/// hashed client-side and never transmitted.
/// Spec §2.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    /// BLAKE3 of all signal hashes concatenated in sorted-key order.
    pub composite_hash: Hash256,
    /// Individual signal hashes. Key = signal type, Value = BLAKE3 of signal.
    ///
    /// Note: `FingerprintSignal` is defined later in this file; the field
    /// uses `BTreeMap` so iteration order is deterministic.
    pub signal_hashes: BTreeMap<FingerprintSignal, Hash256>,
    /// When this fingerprint was captured (epoch ms).
    pub captured_ms: u64,
    /// Similarity vs. previous fingerprint (bp, 0–10_000). `None` on first capture.
    pub consistency_score_bp: Option<u32>,
}

// ---------------------------------------------------------------------------
// BehavioralSignalType / BehavioralSample
// ---------------------------------------------------------------------------

/// Type of behavioural biometric signal.
/// Spec §2.2, §3.5.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BehavioralSignalType {
    KeystrokeDynamics,
    MouseDynamics,
    TouchDynamics,
    ScrollBehavior,
    FormNavigationCadence,
}

/// A single behavioural biometric sample.
///
/// `baseline_similarity_bp` is in basis points (0–10_000), or `None` if no
/// baseline exists yet.
/// Spec §2.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehavioralSample {
    /// BLAKE3 hash of the raw sample data (never stored in raw form).
    pub sample_hash: Hash256,
    /// What kind of behavioural signal this is.
    pub signal_type: BehavioralSignalType,
    /// When captured (epoch ms).
    pub captured_ms: u64,
    /// Similarity to established baseline (bp, 0–10_000). `None` if no baseline.
    pub baseline_similarity_bp: Option<u32>,
}

// ---------------------------------------------------------------------------
// OtpChannel / OtpState / OtpChallenge
// ---------------------------------------------------------------------------

/// Communication channel used to deliver an OTP code.
/// Spec §2.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtpChannel {
    Email,
    Sms,
}

/// Lifecycle state of an OTP challenge.
/// Spec §2.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OtpState {
    /// Dispatched, awaiting user input.
    Pending,
    /// User entered correct code.
    Verified,
    /// TTL expired without verification.
    Expired,
    /// Too many failed attempts.
    LockedOut,
}

/// OTP challenge — state machine for one verification attempt.
///
/// The 32-byte HMAC secret is stored so the server can verify the user's code
/// without storing the code itself.
/// Spec §2.2, §4.3–4.6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtpChallenge {
    /// Unique challenge identifier (hex of BLAKE3 of creation inputs).
    pub challenge_id: String,
    /// The DID being verified.
    pub subject_did: Did,
    /// Delivery channel.
    pub channel: OtpChannel,
    /// HMAC-SHA256 secret (32 bytes). Used to verify the presented code.
    pub hmac_secret: [u8; 32],
    /// When the OTP was dispatched (epoch ms).
    pub dispatched_ms: u64,
    /// TTL in ms. Email: 300_000 (5 min). SMS: 180_000 (3 min).
    pub ttl_ms: u64,
    /// Number of verification attempts made.
    pub attempts: u32,
    /// Maximum allowed attempts before lockout.
    pub max_attempts: u32,
    /// Lifecycle state.
    pub state: OtpState,
}

// ---------------------------------------------------------------------------
// FingerprintSignal
// ---------------------------------------------------------------------------

/// The 15 client-side device signals used in fingerprinting.
///
/// Only their BLAKE3 hashes are transmitted — raw values are never sent.
/// Spec §3.1.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FingerprintSignal {
    AudioContext,
    BatteryStatus,
    CanvasRendering,
    ColorDepthDPR,
    DeviceMemory,
    DoNotTrack,
    FontEnumeration,
    HardwareConcurrency,
    Platform,
    ScreenGeometry,
    TimezoneLocale,
    TouchSupport,
    UserAgent,
    WebGLParameters,
    WebRTCLocalIPs,
}

impl fmt::Display for FingerprintSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AudioContext => "AudioContext",
            Self::BatteryStatus => "BatteryStatus",
            Self::CanvasRendering => "CanvasRendering",
            Self::ColorDepthDPR => "ColorDepthDPR",
            Self::DeviceMemory => "DeviceMemory",
            Self::DoNotTrack => "DoNotTrack",
            Self::FontEnumeration => "FontEnumeration",
            Self::HardwareConcurrency => "HardwareConcurrency",
            Self::Platform => "Platform",
            Self::ScreenGeometry => "ScreenGeometry",
            Self::TimezoneLocale => "TimezoneLocale",
            Self::TouchSupport => "TouchSupport",
            Self::UserAgent => "UserAgent",
            Self::WebGLParameters => "WebGLParameters",
            Self::WebRTCLocalIPs => "WebRTCLocalIPs",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// AttestationType / PeerAttestation
// ---------------------------------------------------------------------------

/// The kind of peer attestation being made.
/// Spec §7.2.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AttestationType {
    /// Attesting that the target DID is a real, unique person.
    Identity,
    /// Attesting that the target is a trustworthy participant.
    Trustworthy,
    /// Attesting the target has specific professional credentials.
    Professional,
    /// General character vouching.
    Character,
}

impl fmt::Display for AttestationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Identity => "Identity",
            Self::Trustworthy => "Trustworthy",
            Self::Professional => "Professional",
            Self::Character => "Character",
        };
        f.write_str(s)
    }
}

impl AttestationType {
    /// Parse from string representation.
    pub fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "Identity" => Ok(Self::Identity),
            "Trustworthy" => Ok(Self::Trustworthy),
            "Professional" => Ok(Self::Professional),
            "Character" => Ok(Self::Character),
            _ => Err(()),
        }
    }
}

/// A peer attestation record — created when one DID vouches for another.
/// Spec §7.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAttestation {
    /// Unique identifier for this attestation (UUID v4).
    pub attestation_id: String,
    /// The DID making the attestation.
    pub attester_did: Did,
    /// The DID being attested.
    pub target_did: Did,
    /// Kind of attestation.
    pub attestation_type: AttestationType,
    /// Optional message hash (e.g., signed statement).
    pub message_hash: Option<Hash256>,
    /// When this attestation was created (epoch ms).
    pub created_ms: u64,
    /// DAG node hash for this attestation.
    pub dag_node_hash: Hash256,
}

// ---------------------------------------------------------------------------
// IdentitySession
// ---------------------------------------------------------------------------

/// An authenticated session for a DID.
///
/// Created after successful OTP verification; carries the session token and
/// the public key used to verify subsequent requests.
/// Spec §8.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySession {
    /// Opaque session token (UUID v4 in hex).
    pub session_token: String,
    /// The DID authenticated by this session.
    pub subject_did: Did,
    /// The session public key (raw bytes).
    pub public_key: Vec<u8>,
    /// When the session was created (epoch ms).
    pub created_ms: u64,
    /// When the session was last used (epoch ms).
    pub last_active_ms: u64,
    /// Whether the session has been revoked.
    pub revoked: bool,
}

// ---------------------------------------------------------------------------
// Display / FromStr implementations for persistence
// ---------------------------------------------------------------------------

impl fmt::Display for ClaimType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DisplayName => f.write_str("DisplayName"),
            Self::Email => f.write_str("Email"),
            Self::Phone => f.write_str("Phone"),
            Self::GovernmentId => f.write_str("GovernmentId"),
            Self::BiometricLiveness => f.write_str("BiometricLiveness"),
            Self::ProfessionalCredential { provider } => {
                write!(f, "ProfessionalCredential:{provider}")
            }
            Self::DeviceFingerprint => f.write_str("DeviceFingerprint"),
            Self::BehavioralSignature => f.write_str("BehavioralSignature"),
            Self::GeographicConsistency => f.write_str("GeographicConsistency"),
            Self::SessionContinuity => f.write_str("SessionContinuity"),
            Self::PeerAttestation { attester_did } => {
                write!(f, "PeerAttestation:{}", attester_did.as_str())
            }
            Self::DelegationGrant { delegator_did } => {
                write!(f, "DelegationGrant:{}", delegator_did.as_str())
            }
            Self::SybilChallengeResolution { challenge_id } => {
                write!(f, "SybilChallengeResolution:{challenge_id}")
            }
            Self::GovernanceVote { proposal_hash } => write!(
                f,
                "GovernanceVote:{}",
                hex::encode(proposal_hash.as_bytes())
            ),
            Self::ProposalAuthored { proposal_hash } => write!(
                f,
                "ProposalAuthored:{}",
                hex::encode(proposal_hash.as_bytes())
            ),
            Self::ValidatorService {
                round_range: (start, end),
            } => write!(f, "ValidatorService:{start}:{end}"),
            Self::KeyRotation { old_key_hash } => {
                write!(f, "KeyRotation:{}", hex::encode(old_key_hash.as_bytes()))
            }
            Self::EntropyAttestation => f.write_str("EntropyAttestation"),
        }
    }
}

impl fmt::Display for ClaimStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Pending => "Pending",
            Self::Verified => "Verified",
            Self::Expired => "Expired",
            Self::Revoked => "Revoked",
            Self::Challenged => "Challenged",
        };
        f.write_str(s)
    }
}

impl ClaimStatus {
    /// Parse a `ClaimStatus` from its string representation.
    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "Pending" => Ok(Self::Pending),
            "Verified" => Ok(Self::Verified),
            "Expired" => Ok(Self::Expired),
            "Revoked" => Ok(Self::Revoked),
            "Challenged" => Ok(Self::Challenged),
            _ => Err(()),
        }
    }
}

impl fmt::Display for BehavioralSignalType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::KeystrokeDynamics => "KeystrokeDynamics",
            Self::MouseDynamics => "MouseDynamics",
            Self::TouchDynamics => "TouchDynamics",
            Self::ScrollBehavior => "ScrollBehavior",
            Self::FormNavigationCadence => "FormNavigationCadence",
        };
        f.write_str(s)
    }
}

impl BehavioralSignalType {
    /// Parse from string representation.
    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "KeystrokeDynamics" => Ok(Self::KeystrokeDynamics),
            "MouseDynamics" => Ok(Self::MouseDynamics),
            "TouchDynamics" => Ok(Self::TouchDynamics),
            "ScrollBehavior" => Ok(Self::ScrollBehavior),
            "FormNavigationCadence" => Ok(Self::FormNavigationCadence),
            _ => Err(()),
        }
    }
}

impl fmt::Display for OtpChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Email => "Email",
            Self::Sms => "Sms",
        };
        f.write_str(s)
    }
}

impl OtpChannel {
    /// Parse from string representation.
    pub fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "Email" => Ok(Self::Email),
            "Sms" => Ok(Self::Sms),
            _ => Err(()),
        }
    }

    /// Return the default TTL for this channel in milliseconds.
    ///
    /// - Email: 5 minutes (300_000 ms)
    /// - SMS:   3 minutes (180_000 ms)
    #[must_use]
    pub fn ttl_ms(&self) -> u64 {
        match self {
            Self::Email => 300_000,
            Self::Sms => 180_000,
        }
    }
}

impl fmt::Display for OtpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Pending => "Pending",
            Self::Verified => "Verified",
            Self::Expired => "Expired",
            Self::LockedOut => "LockedOut",
        };
        f.write_str(s)
    }
}

impl OtpState {
    /// Parse from string representation.
    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "Pending" => Ok(Self::Pending),
            "Verified" => Ok(Self::Verified),
            "Expired" => Ok(Self::Expired),
            "LockedOut" => Ok(Self::LockedOut),
            _ => Err(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ---- AttestationType ----

    #[test]
    fn attestation_type_from_str_roundtrips() {
        for s in ["Identity", "Trustworthy", "Professional", "Character"] {
            let t = AttestationType::from_str(s).unwrap();
            assert_eq!(t.to_string(), s);
        }
        assert!(AttestationType::from_str("Unknown").is_err());
    }

    // ---- ClaimStatus ----

    #[test]
    fn claim_status_from_str_roundtrips() {
        for s in ["Pending", "Verified", "Expired", "Revoked", "Challenged"] {
            let t = ClaimStatus::from_str(s).unwrap();
            assert_eq!(t.to_string(), s);
        }
        assert!(ClaimStatus::from_str("X").is_err());
    }

    // ---- BehavioralSignalType ----

    #[test]
    fn behavioral_signal_type_from_str_roundtrips() {
        for s in [
            "KeystrokeDynamics",
            "MouseDynamics",
            "TouchDynamics",
            "ScrollBehavior",
            "FormNavigationCadence",
        ] {
            let t = BehavioralSignalType::from_str(s).unwrap();
            assert_eq!(t.to_string(), s);
        }
        assert!(BehavioralSignalType::from_str("Unknown").is_err());
    }

    // ---- OtpChannel ----

    #[test]
    fn otp_channel_from_str_roundtrips() {
        assert_eq!(OtpChannel::from_str("Email").unwrap(), OtpChannel::Email);
        assert_eq!(OtpChannel::from_str("Sms").unwrap(), OtpChannel::Sms);
        assert!(OtpChannel::from_str("Unknown").is_err());
    }

    #[test]
    fn otp_channel_ttl_ms_email_5_min() {
        assert_eq!(OtpChannel::Email.ttl_ms(), 300_000);
    }

    #[test]
    fn otp_channel_ttl_ms_sms_3_min() {
        assert_eq!(OtpChannel::Sms.ttl_ms(), 180_000);
    }

    // ---- OtpState ----

    #[test]
    fn otp_state_from_str_roundtrips() {
        for s in ["Pending", "Verified", "Expired", "LockedOut"] {
            let t = OtpState::from_str(s).unwrap();
            assert_eq!(t.to_string(), s);
        }
        assert!(OtpState::from_str("X").is_err());
    }

    // ---- FingerprintSignal Display ----

    #[test]
    fn fingerprint_signal_display_all_variants() {
        let variants = [
            (FingerprintSignal::AudioContext, "AudioContext"),
            (FingerprintSignal::BatteryStatus, "BatteryStatus"),
            (FingerprintSignal::CanvasRendering, "CanvasRendering"),
            (FingerprintSignal::ColorDepthDPR, "ColorDepthDPR"),
            (FingerprintSignal::DeviceMemory, "DeviceMemory"),
            (FingerprintSignal::DoNotTrack, "DoNotTrack"),
            (FingerprintSignal::FontEnumeration, "FontEnumeration"),
            (
                FingerprintSignal::HardwareConcurrency,
                "HardwareConcurrency",
            ),
            (FingerprintSignal::Platform, "Platform"),
            (FingerprintSignal::ScreenGeometry, "ScreenGeometry"),
            (FingerprintSignal::TimezoneLocale, "TimezoneLocale"),
            (FingerprintSignal::TouchSupport, "TouchSupport"),
            (FingerprintSignal::UserAgent, "UserAgent"),
            (FingerprintSignal::WebGLParameters, "WebGLParameters"),
            (FingerprintSignal::WebRTCLocalIPs, "WebRTCLocalIPs"),
        ];
        for (v, expected) in &variants {
            assert_eq!(v.to_string(), *expected);
        }
    }

    // ---- ClaimType Display ----

    #[test]
    fn claim_type_display_simple_variants() {
        assert_eq!(ClaimType::DisplayName.to_string(), "DisplayName");
        assert_eq!(ClaimType::Email.to_string(), "Email");
        assert_eq!(ClaimType::Phone.to_string(), "Phone");
        assert_eq!(ClaimType::GovernmentId.to_string(), "GovernmentId");
        assert_eq!(
            ClaimType::BiometricLiveness.to_string(),
            "BiometricLiveness"
        );
        assert_eq!(
            ClaimType::DeviceFingerprint.to_string(),
            "DeviceFingerprint"
        );
        assert_eq!(
            ClaimType::BehavioralSignature.to_string(),
            "BehavioralSignature"
        );
        assert_eq!(
            ClaimType::GeographicConsistency.to_string(),
            "GeographicConsistency"
        );
        assert_eq!(
            ClaimType::SessionContinuity.to_string(),
            "SessionContinuity"
        );
        assert_eq!(
            ClaimType::EntropyAttestation.to_string(),
            "EntropyAttestation"
        );
    }

    #[test]
    fn claim_type_display_parameterised_variants() {
        let did = Did::new("did:exo:x").unwrap();

        let pc = ClaimType::ProfessionalCredential {
            provider: "ACME".into(),
        };
        assert_eq!(pc.to_string(), "ProfessionalCredential:ACME");

        let pa = ClaimType::PeerAttestation {
            attester_did: did.clone(),
        };
        assert!(pa.to_string().starts_with("PeerAttestation:did:exo:x"));

        let dg = ClaimType::DelegationGrant { delegator_did: did };
        assert!(dg.to_string().starts_with("DelegationGrant:did:exo:x"));

        let scr = ClaimType::SybilChallengeResolution {
            challenge_id: "ch1".into(),
        };
        assert_eq!(scr.to_string(), "SybilChallengeResolution:ch1");

        let vs = ClaimType::ValidatorService {
            round_range: (10, 20),
        };
        assert_eq!(vs.to_string(), "ValidatorService:10:20");
    }

    #[test]
    fn claim_type_display_hash_variants() {
        let hash = Hash256::digest(b"test");

        let gv = ClaimType::GovernanceVote {
            proposal_hash: hash,
        };
        assert!(gv.to_string().starts_with("GovernanceVote:"));

        let prop = ClaimType::ProposalAuthored {
            proposal_hash: hash,
        };
        assert!(prop.to_string().starts_with("ProposalAuthored:"));

        let kr = ClaimType::KeyRotation { old_key_hash: hash };
        assert!(kr.to_string().starts_with("KeyRotation:"));
    }

    // ---- PolarAxes ----

    #[test]
    fn polar_axes_as_array_returns_correct_order() {
        let axes = PolarAxes {
            communication: 1,
            credential_depth: 2,
            device_trust: 3,
            behavioral_signature: 4,
            network_reputation: 5,
            temporal_stability: 6,
            cryptographic_strength: 7,
            constitutional_standing: 8,
        };
        assert_eq!(axes.as_array(), [1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
