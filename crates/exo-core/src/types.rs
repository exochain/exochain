//! Core deterministic types for the EXOCHAIN trust fabric.
//!
//! **Determinism contract**: every type in this module has a canonical
//! representation.  `DeterministicMap` wraps `BTreeMap` so that iteration
//! order is always sorted-key.  No `HashMap` or floating-point value is
//! ever exposed.

use core::fmt;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    crypto,
    error::{ExoError, Result},
    hash::hash_structured,
};

// ---------------------------------------------------------------------------
// DeterministicMap
// ---------------------------------------------------------------------------

/// A map that guarantees deterministic iteration order (sorted by key).
///
/// This is the **only** map type permitted in EXOCHAIN.  It wraps
/// `BTreeMap` and re-exports a minimal surface so callers never
/// accidentally introduce a `HashMap`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeterministicMap<K: Ord, V> {
    inner: BTreeMap<K, V>,
}

impl<K: Ord, V> DeterministicMap<K, V> {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }

    /// Insert a key-value pair, returning the previous value if any.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    /// Get a reference to the value for `key`.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.inner.get(key)
    }

    /// Remove a key, returning its value if present.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.remove(key)
    }

    /// Returns `true` if the map contains `key`.
    #[must_use]
    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Is the map empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Deterministic iterator — always sorted by key.
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, K, V> {
        self.inner.iter()
    }

    /// Sorted keys iterator.
    pub fn keys(&self) -> std::collections::btree_map::Keys<'_, K, V> {
        self.inner.keys()
    }

    /// Values iterator (in key order).
    pub fn values(&self) -> std::collections::btree_map::Values<'_, K, V> {
        self.inner.values()
    }

    /// Consume self and return the inner `BTreeMap`.
    #[must_use]
    pub fn into_inner(self) -> BTreeMap<K, V> {
        self.inner
    }
}

impl<K: Ord, V> Default for DeterministicMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Ord, V> From<BTreeMap<K, V>> for DeterministicMap<K, V> {
    fn from(inner: BTreeMap<K, V>) -> Self {
        Self { inner }
    }
}

impl<K: Ord, V> IntoIterator for DeterministicMap<K, V> {
    type Item = (K, V);
    type IntoIter = std::collections::btree_map::IntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, K: Ord, V> IntoIterator for &'a DeterministicMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = std::collections::btree_map::Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

// ---------------------------------------------------------------------------
// Hash256
// ---------------------------------------------------------------------------

/// A 256-bit (32-byte) hash value, used as the canonical content-address
/// throughout EXOCHAIN.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// The all-zero hash, used as a sentinel / genesis value.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Create from a raw 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the inner bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute the blake3 hash of arbitrary data and wrap it.
    #[must_use]
    pub fn digest(data: &[u8]) -> Self {
        let h = blake3::hash(data);
        Self(*h.as_bytes())
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({self})")
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Signature — post-quantum ready
// ---------------------------------------------------------------------------

/// A cryptographic signature supporting multiple algorithms.
///
/// This enum enables migration from Ed25519 to post-quantum schemes
/// (e.g., Dilithium) or hybrid classical+PQ signatures without breaking
/// existing chains.
#[derive(Clone, PartialEq, Eq)]
pub enum Signature {
    /// Classical Ed25519 signature (64 bytes).
    Ed25519([u8; 64]),
    /// Post-quantum signature (variable length, e.g. Dilithium).
    PostQuantum(Vec<u8>),
    /// Hybrid: classical Ed25519 + post-quantum signature.
    Hybrid { classical: [u8; 64], pq: Vec<u8> },
    /// Empty placeholder — used before acceptance / during construction.
    Empty,
}

/// Serde-friendly proxy that mirrors `Signature` but uses `Vec<u8>` instead of `[u8; 64]`.
#[derive(Serialize, Deserialize)]
enum SignatureProxy {
    Ed25519(Vec<u8>),
    PostQuantum(Vec<u8>),
    Hybrid { classical: Vec<u8>, pq: Vec<u8> },
    Empty,
}

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        let proxy = match self {
            Self::Ed25519(b) => SignatureProxy::Ed25519(b.to_vec()),
            Self::PostQuantum(b) => SignatureProxy::PostQuantum(b.clone()),
            Self::Hybrid { classical, pq } => SignatureProxy::Hybrid {
                classical: classical.to_vec(),
                pq: pq.clone(),
            },
            Self::Empty => SignatureProxy::Empty,
        };
        proxy.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        let proxy = SignatureProxy::deserialize(deserializer)?;
        match proxy {
            SignatureProxy::Ed25519(b) => {
                if b.len() != 64 {
                    return Err(serde::de::Error::invalid_length(
                        b.len(),
                        &"64 bytes for Ed25519",
                    ));
                }
                let mut buf = [0u8; 64];
                buf.copy_from_slice(&b);
                Ok(Self::Ed25519(buf))
            }
            SignatureProxy::PostQuantum(b) => Ok(Self::PostQuantum(b)),
            SignatureProxy::Hybrid { classical, pq } => {
                if classical.len() != 64 {
                    return Err(serde::de::Error::invalid_length(
                        classical.len(),
                        &"64 bytes for classical",
                    ));
                }
                let mut buf = [0u8; 64];
                buf.copy_from_slice(&classical);
                Ok(Self::Hybrid { classical: buf, pq })
            }
            SignatureProxy::Empty => Ok(Self::Empty),
        }
    }
}

impl Signature {
    /// Create an Ed25519 signature from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self::Ed25519(bytes)
    }

    /// Return the inner bytes for legacy Ed25519 signatures.
    ///
    /// # Panics
    /// Panics if called on non-Ed25519 variants. Use [`Self::ed25519_bytes`]
    /// for fallible Ed25519-compatible access or [`Self::to_bytes`] for
    /// algorithm-agnostic byte serialization.
    #[deprecated(
        since = "0.1.0-beta",
        note = "use ed25519_bytes() for fallible Ed25519-compatible access or to_bytes() for algorithm-agnostic serialization"
    )]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        match self {
            Self::Ed25519(b) => b,
            Self::Hybrid { .. } | Self::PostQuantum(_) | Self::Empty => {
                panic!("Signature::as_bytes() is only valid for Ed25519 signatures")
            }
        }
    }

    /// Return Ed25519 bytes if this is an Ed25519 or Hybrid signature.
    #[must_use]
    pub fn ed25519_bytes(&self) -> Option<&[u8; 64]> {
        match self {
            Self::Ed25519(b) => Some(b),
            Self::Hybrid { classical, .. } => Some(classical),
            Self::PostQuantum(_) | Self::Empty => None,
        }
    }

    /// Return true when the Ed25519-compatible component is the all-zero sentinel.
    ///
    /// This preserves the explicit null-signature guard without relying on
    /// [`Self::as_bytes`], which is intentionally Ed25519-only.
    #[must_use]
    pub fn ed25519_component_is_zero(&self) -> bool {
        self.ed25519_bytes()
            .is_some_and(|raw| raw.iter().all(|b| *b == 0))
    }

    /// Return all signature bytes as a slice (algorithm-agnostic).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(b) => b.to_vec(),
            Self::PostQuantum(b) => b.clone(),
            Self::Hybrid { classical, pq } => {
                let mut v = classical.to_vec();
                v.extend_from_slice(pq);
                v
            }
            Self::Empty => Vec::new(),
        }
    }

    /// The empty signature placeholder.
    pub const EMPTY: Self = Self::Empty;

    /// Create an empty (placeholder) signature.
    #[must_use]
    pub const fn empty() -> Self {
        Self::Empty
    }

    /// Check if this signature is the empty placeholder.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Ed25519(b) => *b == [0u8; 64],
            Self::PostQuantum(b) => b.is_empty(),
            Self::Hybrid { classical, pq } => *classical == [0u8; 64] && pq.is_empty(),
        }
    }

    /// Returns the algorithm variant name.
    #[must_use]
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "Ed25519",
            Self::PostQuantum(_) => "PostQuantum",
            Self::Hybrid { .. } => "Hybrid",
            Self::Empty => "Empty",
        }
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519(b) => write!(f, "Signature::Ed25519({}..)", hex_prefix(b)),
            Self::PostQuantum(b) => {
                write!(f, "Signature::PostQuantum({}..{}B)", hex_prefix(b), b.len())
            }
            Self::Hybrid { classical, pq } => write!(
                f,
                "Signature::Hybrid({}..+{}B)",
                hex_prefix(classical),
                pq.len()
            ),
            Self::Empty => write!(f, "Signature::Empty"),
        }
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519(b) => {
                for byte in b {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::PostQuantum(b) => {
                for byte in b {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::Hybrid { classical, pq } => {
                for byte in classical {
                    write!(f, "{byte:02x}")?;
                }
                write!(f, ":")?;
                for byte in pq {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::Empty => write!(f, "empty"),
        }
    }
}

// ---------------------------------------------------------------------------
// PublicKey / SecretKey
// ---------------------------------------------------------------------------

/// An Ed25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}..)", hex_prefix(&self.0))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// An Ed25519 secret (signing) key.  Zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey(***)")
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison would be ideal but for PartialEq trait
        // we do a simple byte compare — the secret is zeroized on drop.
        self.0 == other.0
    }
}

impl Eq for SecretKey {}

// ---------------------------------------------------------------------------
// PqPublicKey / PqSecretKey — ML-DSA-65 post-quantum keys
// ---------------------------------------------------------------------------

/// An ML-DSA-65 (NIST FIPS 204) public verification key.
///
/// Stored as raw encoded bytes (1952 bytes for ML-DSA-65). Heap-allocated
/// for WASM32 compatibility — large fixed-size arrays are unreliable on the
/// wasm32 stack.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqPublicKey(pub Vec<u8>);

impl PqPublicKey {
    /// Create from raw encoded key bytes.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Return the raw encoded key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PqPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PqPublicKey({}..{}B)", hex_prefix(&self.0), self.0.len())
    }
}

impl fmt::Display for PqPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PqPublicKey({}..)", hex_prefix(&self.0))
    }
}

/// An ML-DSA-65 secret (signing) key. Zeroized on drop.
///
/// Stored as raw encoded bytes (4032 bytes for ML-DSA-65). The `Zeroize`
/// derive ensures key material is cleared from memory when this value is
/// dropped.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct PqSecretKey(pub Vec<u8>);

impl PqSecretKey {
    /// Create from raw encoded key bytes.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Return the raw encoded key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PqSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PqSecretKey(***)")
    }
}

// ---------------------------------------------------------------------------
// Did — Decentralized Identifier
// ---------------------------------------------------------------------------

/// A Decentralized Identifier conforming to the `did:exo:<method-specific>` format.
///
/// The method-specific portion must be non-empty and consist only of
/// alphanumeric characters, hyphens, underscores, and colons.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Did(String);

impl Did {
    /// Parse and validate a DID string.
    ///
    /// Accepted format: `did:exo:<id>` where `<id>` is `[a-zA-Z0-9_:-]+`.
    pub fn new(value: &str) -> Result<Self> {
        Self::validate(value)?;
        Ok(Self(value.to_owned()))
    }

    fn validate(value: &str) -> Result<()> {
        // Must start with "did:exo:"
        let rest = value
            .strip_prefix("did:exo:")
            .ok_or_else(|| ExoError::InvalidDid {
                value: value.to_owned(),
            })?;
        if rest.is_empty() {
            return Err(ExoError::InvalidDid {
                value: value.to_owned(),
            });
        }
        // Method-specific portion: alphanumeric, hyphen, underscore, colon
        if !rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ':')
        {
            return Err(ExoError::InvalidDid {
                value: value.to_owned(),
            });
        }
        Ok(())
    }

    /// Return the full DID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Did({})", self.0)
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// CorrelationId
// ---------------------------------------------------------------------------

/// A UUID v4 correlation identifier for tracking transactions end-to-end.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CorrelationId(Uuid);

impl CorrelationId {
    /// Generate a new random correlation ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wrap an existing UUID.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Return the inner UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CorrelationId({})", self.0)
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

// ---------------------------------------------------------------------------
// Timestamp — HLC timestamp (no floating point)
// ---------------------------------------------------------------------------

/// A Hybrid Logical Clock timestamp.
///
/// - `physical_ms`: milliseconds since Unix epoch (wall-clock component).
/// - `logical`: monotonic counter within the same millisecond.
///
/// Ordering: physical first, then logical.  **No floating-point** involved.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Timestamp {
    pub physical_ms: u64,
    pub logical: u32,
}

impl Timestamp {
    /// Create a new timestamp.
    #[must_use]
    pub const fn new(physical_ms: u64, logical: u32) -> Self {
        Self {
            physical_ms,
            logical,
        }
    }

    /// The zero / genesis timestamp.
    pub const ZERO: Self = Self {
        physical_ms: 0,
        logical: 0,
    };

    /// Create a timestamp from the current system clock (non-deterministic).
    #[must_use]
    pub fn now_utc() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let millis = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            u64::try_from(ms).unwrap_or(u64::MAX)
        };
        #[cfg(target_arch = "wasm32")]
        #[allow(clippy::as_conversions)] // js_sys::Date::now() returns f64; safe truncation
        let millis = js_sys::Date::now() as u64;

        Self {
            physical_ms: millis,
            logical: 0,
        }
    }

    /// Check if this timestamp is expired relative to `now`.
    /// Returns true if `self <= now`.
    #[must_use]
    pub fn is_expired(&self, now: &Timestamp) -> bool {
        self <= now
    }
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.physical_ms
            .cmp(&other.physical_ms)
            .then_with(|| self.logical.cmp(&other.logical))
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({}:{})", self.physical_ms, self.logical)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.physical_ms, self.logical)
    }
}

// ---------------------------------------------------------------------------
// SignerType — cryptographic AI identity binding
// ---------------------------------------------------------------------------

/// Key prefix byte embedded in the signed payload to cryptographically
/// distinguish human from AI signers. This prevents an AI key from
/// producing a signature that could be mistaken for a human signature,
/// because the prefix is part of the message digest.
pub const SIGNER_PREFIX_HUMAN: u8 = 0x01;
pub const SIGNER_PREFIX_AI: u8 = 0x02;

/// Cryptographic signer type — embedded in the signed payload, not a
/// caller-set flag. The signer type is bound into every signature via
/// a key prefix byte, ensuring an AI cannot impersonate a human even
/// if it possesses the same raw key material.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignerType {
    /// Human signer — key prefix 0x01.
    Human,
    /// AI agent signer — key prefix 0x02, with delegation reference.
    Ai {
        /// The delegation or session ID authorizing this AI's actions.
        delegation_id: Hash256,
    },
}

impl SignerType {
    /// The prefix byte for this signer type, embedded in signed payloads.
    #[must_use]
    pub fn prefix_byte(&self) -> u8 {
        match self {
            Self::Human => SIGNER_PREFIX_HUMAN,
            Self::Ai { .. } => SIGNER_PREFIX_AI,
        }
    }

    /// Build the canonical prefix bytes for inclusion in a signable payload.
    /// For Human: `[0x01]`
    /// For AI: `[0x02]` ++ delegation_id (32 bytes)
    #[must_use]
    pub fn to_payload_prefix(&self) -> Vec<u8> {
        match self {
            Self::Human => vec![SIGNER_PREFIX_HUMAN],
            Self::Ai { delegation_id } => {
                let mut v = vec![SIGNER_PREFIX_AI];
                v.extend_from_slice(delegation_id.as_bytes());
                v
            }
        }
    }

    #[must_use]
    pub fn is_human(&self) -> bool {
        matches!(self, Self::Human)
    }

    #[must_use]
    pub fn is_ai(&self) -> bool {
        matches!(self, Self::Ai { .. })
    }
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// A monotonically increasing version counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Version(pub u64);

impl Version {
    /// The initial version.
    pub const ZERO: Self = Self(0);

    /// Increment and return the next version.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Return the raw counter value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// TrustReceipt — signed, machine-verifiable record of agent action
// ---------------------------------------------------------------------------

/// Outcome of a trust-receipted action.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReceiptOutcome {
    /// Action was permitted and executed.
    Executed,
    /// Action was denied by the kernel.
    Denied,
    /// Action was escalated for review.
    Escalated,
    /// Action is pending consensus commit.
    Pending,
}

impl fmt::Display for ReceiptOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Executed => write!(f, "executed"),
            Self::Denied => write!(f, "denied"),
            Self::Escalated => write!(f, "escalated"),
            Self::Pending => write!(f, "pending"),
        }
    }
}

/// A signed, machine-verifiable trust receipt for an agent action.
///
/// Every material agent action emits a receipt suitable for later
/// dispute, replay, and audit. Receipts are the evidentiary basis
/// for the challenge/dispute pathway.
///
/// ## Fields
///
/// - `receipt_hash`: content-addressed identifier (BLAKE3 of canonical CBOR)
/// - `actor_did`: who performed the action
/// - `authority_chain_hash`: hash of the delegation chain authorizing the action
/// - `consent_reference`: hash of the governing bailment/consent record (if any)
/// - `action_type`: human-readable action descriptor
/// - `action_hash`: content hash of the action payload
/// - `outcome`: what happened (Executed, Denied, Escalated, Pending)
/// - `timestamp`: hybrid logical clock timestamp
/// - `signature`: actor's cryptographic signature over the receipt
/// - `challenge_reference`: hash linking to a filed challenge (if disputed)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustReceipt {
    /// Content-addressed receipt identifier.
    pub receipt_hash: Hash256,
    /// The agent who performed the action.
    pub actor_did: Did,
    /// Hash of the authority chain under which the action was performed.
    pub authority_chain_hash: Hash256,
    /// Reference to the governing consent/bailment record.
    pub consent_reference: Option<Hash256>,
    /// Human-readable action type (e.g., "governance.propose", "dag.commit").
    pub action_type: String,
    /// Content hash of the action payload.
    pub action_hash: Hash256,
    /// Outcome of the action.
    pub outcome: ReceiptOutcome,
    /// When the action occurred.
    pub timestamp: Timestamp,
    /// Actor's cryptographic signature over the receipt body.
    pub signature: Signature,
    /// Reference to a filed challenge, if this action is disputed.
    pub challenge_reference: Option<Hash256>,
}

const TRUST_RECEIPT_SIGNING_DOMAIN: &str = "exo.trust_receipt.v1";

#[derive(Serialize)]
struct TrustReceiptSigningPayload<'a> {
    domain: &'static str,
    actor_did: &'a str,
    authority_chain_hash: &'a Hash256,
    consent_reference: Option<&'a Hash256>,
    action_type: &'a str,
    action_hash: &'a Hash256,
    outcome: &'a ReceiptOutcome,
    timestamp: &'a Timestamp,
}

impl TrustReceipt {
    fn signing_payload_fields<'a>(
        actor_did: &'a Did,
        authority_chain_hash: &'a Hash256,
        consent_reference: Option<&'a Hash256>,
        action_type: &'a str,
        action_hash: &'a Hash256,
        outcome: &'a ReceiptOutcome,
        timestamp: &'a Timestamp,
    ) -> TrustReceiptSigningPayload<'a> {
        TrustReceiptSigningPayload {
            domain: TRUST_RECEIPT_SIGNING_DOMAIN,
            actor_did: actor_did.as_str(),
            authority_chain_hash,
            consent_reference,
            action_type,
            action_hash,
            outcome,
            timestamp,
        }
    }

    fn payload_for_signature(
        actor_did: &Did,
        authority_chain_hash: &Hash256,
        consent_reference: Option<&Hash256>,
        action_type: &str,
        action_hash: &Hash256,
        outcome: &ReceiptOutcome,
        timestamp: &Timestamp,
    ) -> Result<Vec<u8>> {
        let payload = Self::signing_payload_fields(
            actor_did,
            authority_chain_hash,
            consent_reference,
            action_type,
            action_hash,
            outcome,
            timestamp,
        );
        let mut encoded = Vec::new();
        ciborium::into_writer(&payload, &mut encoded).map_err(|e| {
            ExoError::SerializationError {
                reason: format!("trust receipt signing payload CBOR serialization failed: {e:?}"),
            }
        })?;
        Ok(encoded)
    }

    fn receipt_hash_for_content(
        actor_did: &Did,
        authority_chain_hash: &Hash256,
        consent_reference: Option<&Hash256>,
        action_type: &str,
        action_hash: &Hash256,
        outcome: &ReceiptOutcome,
        timestamp: &Timestamp,
    ) -> Result<Hash256> {
        let payload = Self::signing_payload_fields(
            actor_did,
            authority_chain_hash,
            consent_reference,
            action_type,
            action_hash,
            outcome,
            timestamp,
        );
        hash_structured(&payload).map_err(|e| ExoError::SerializationError {
            reason: format!("trust receipt hash payload CBOR serialization failed: {e}"),
        })
    }

    /// Create a new trust receipt and compute its content-addressed hash.
    ///
    /// The `sign_fn` is called with the canonical signable payload to
    /// produce the actor's signature.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actor_did: Did,
        authority_chain_hash: Hash256,
        consent_reference: Option<Hash256>,
        action_type: String,
        action_hash: Hash256,
        outcome: ReceiptOutcome,
        timestamp: Timestamp,
        sign_fn: &dyn Fn(&[u8]) -> Signature,
    ) -> Result<Self> {
        let payload = Self::payload_for_signature(
            &actor_did,
            &authority_chain_hash,
            consent_reference.as_ref(),
            &action_type,
            &action_hash,
            &outcome,
            &timestamp,
        )?;

        let signature = sign_fn(&payload);
        let receipt_hash = Self::receipt_hash_for_content(
            &actor_did,
            &authority_chain_hash,
            consent_reference.as_ref(),
            &action_type,
            &action_hash,
            &outcome,
            &timestamp,
        )?;

        Ok(Self {
            receipt_hash,
            actor_did,
            authority_chain_hash,
            consent_reference,
            action_type,
            action_hash,
            outcome,
            timestamp,
            signature,
            challenge_reference: None,
        })
    }

    /// Verify that the receipt hash matches the content.
    ///
    /// # Errors
    ///
    /// Returns `ExoError::SerializationError` if canonical receipt hashing
    /// fails.
    pub fn verify_hash(&self) -> Result<bool> {
        Ok(Self::receipt_hash_for_content(
            &self.actor_did,
            &self.authority_chain_hash,
            self.consent_reference.as_ref(),
            &self.action_type,
            &self.action_hash,
            &self.outcome,
            &self.timestamp,
        )? == self.receipt_hash)
    }

    /// Return the exact payload signed by the actor for this receipt.
    ///
    /// # Errors
    ///
    /// Returns `ExoError::SerializationError` if canonical receipt encoding
    /// fails.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        Self::payload_for_signature(
            &self.actor_did,
            &self.authority_chain_hash,
            self.consent_reference.as_ref(),
            &self.action_type,
            &self.action_hash,
            &self.outcome,
            &self.timestamp,
        )
    }

    /// Verify the actor signature over this receipt's signable payload.
    ///
    /// # Errors
    ///
    /// Returns `ExoError::SerializationError` if canonical receipt encoding
    /// fails.
    pub fn verify_signature(&self, public_key: &PublicKey) -> Result<bool> {
        if self.signature.is_empty() {
            return Ok(false);
        }
        Ok(crypto::verify(
            &self.signing_payload()?,
            &self.signature,
            public_key,
        ))
    }
}

impl fmt::Display for TrustReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TrustReceipt({} by {} -> {})",
            hex_prefix(&self.receipt_hash.0),
            self.actor_did,
            self.outcome,
        )
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// First 4 bytes as hex for debug displays.
fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    // -- DeterministicMap --------------------------------------------------

    #[test]
    fn map_new_is_empty() {
        let m: DeterministicMap<String, i32> = DeterministicMap::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn map_default_is_empty() {
        let m: DeterministicMap<String, i32> = DeterministicMap::default();
        assert!(m.is_empty());
    }

    #[test]
    fn map_insert_get_remove() {
        let mut m = DeterministicMap::new();
        assert_eq!(m.insert("a".to_string(), 1), None);
        assert_eq!(m.insert("a".to_string(), 2), Some(1));
        assert_eq!(m.get(&"a".to_string()), Some(&2));
        assert!(m.contains_key(&"a".to_string()));
        assert!(!m.contains_key(&"b".to_string()));
        assert_eq!(m.remove(&"a".to_string()), Some(2));
        assert!(m.is_empty());
    }

    #[test]
    fn map_deterministic_iteration_order() {
        let mut m = DeterministicMap::new();
        m.insert("c", 3);
        m.insert("a", 1);
        m.insert("b", 2);
        let keys: Vec<_> = m.keys().copied().collect();
        assert_eq!(keys, vec!["a", "b", "c"]);
        let values: Vec<_> = m.values().copied().collect();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[test]
    fn map_from_btreemap() {
        let mut bt = BTreeMap::new();
        bt.insert(1, "one");
        bt.insert(2, "two");
        let dm = DeterministicMap::from(bt.clone());
        assert_eq!(dm.len(), 2);
        assert_eq!(dm.into_inner(), bt);
    }

    #[test]
    fn map_into_iter() {
        let mut m = DeterministicMap::new();
        m.insert(1, "a");
        m.insert(2, "b");
        let pairs: Vec<_> = m.into_iter().collect();
        assert_eq!(pairs, vec![(1, "a"), (2, "b")]);
    }

    #[test]
    fn map_ref_into_iter() {
        let mut m = DeterministicMap::new();
        m.insert(1, "a");
        let pairs: Vec<_> = (&m).into_iter().collect();
        assert_eq!(pairs, vec![(&1, &"a")]);
    }

    #[test]
    fn map_iter() {
        let mut m = DeterministicMap::new();
        m.insert(10, "x");
        let pairs: Vec<_> = m.iter().collect();
        assert_eq!(pairs, vec![(&10, &"x")]);
    }

    #[test]
    fn map_serde_roundtrip() {
        let mut m = DeterministicMap::new();
        m.insert("key".to_string(), 42u32);
        let json = serde_json::to_string(&m).expect("serialize");
        let m2: DeterministicMap<String, u32> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m, m2);
    }

    #[test]
    fn map_clone_eq_ord_hash() {
        let mut m1 = DeterministicMap::new();
        m1.insert(1, 2);
        let m2 = m1.clone();
        assert_eq!(m1, m2);
        // Ord
        let mut m3 = DeterministicMap::new();
        m3.insert(2, 3);
        assert!(m1 < m3);
        // Hash
        use std::hash::{Hash, Hasher};
        let mut h1 = std::hash::DefaultHasher::new();
        m1.hash(&mut h1);
        let mut h2 = std::hash::DefaultHasher::new();
        m2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    // -- Hash256 -----------------------------------------------------------

    #[test]
    fn hash256_zero() {
        assert_eq!(Hash256::ZERO.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn hash256_from_bytes_roundtrip() {
        let bytes = [42u8; 32];
        let h = Hash256::from_bytes(bytes);
        assert_eq!(*h.as_bytes(), bytes);
    }

    #[test]
    fn hash256_digest() {
        let h1 = Hash256::digest(b"hello");
        let h2 = Hash256::digest(b"hello");
        assert_eq!(h1, h2);
        let h3 = Hash256::digest(b"world");
        assert_ne!(h1, h3);
    }

    #[test]
    fn hash256_display() {
        let h = Hash256::from_bytes([0xab; 32]);
        let s = h.to_string();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash256_debug() {
        let h = Hash256::ZERO;
        let dbg = format!("{h:?}");
        assert!(dbg.starts_with("Hash256("));
    }

    #[test]
    fn hash256_as_ref() {
        let h = Hash256::from_bytes([1u8; 32]);
        let slice: &[u8] = h.as_ref();
        assert_eq!(slice.len(), 32);
    }

    #[test]
    fn hash256_ord() {
        let a = Hash256::from_bytes([0u8; 32]);
        let b = Hash256::from_bytes([1u8; 32]);
        assert!(a < b);
    }

    #[test]
    fn hash256_serde_roundtrip() {
        let h = Hash256::digest(b"test");
        let cbor = {
            let mut buf = Vec::new();
            ciborium::into_writer(&h, &mut buf).expect("cbor encode");
            buf
        };
        let h2: Hash256 = ciborium::from_reader(&cbor[..]).expect("cbor decode");
        assert_eq!(h, h2);
    }

    // -- Signature ---------------------------------------------------------

    #[test]
    #[allow(deprecated)]
    fn signature_from_bytes() {
        let sig = Signature::from_bytes([0xffu8; 64]);
        assert_eq!(sig.as_bytes(), &[0xff; 64]);
    }

    #[test]
    #[should_panic(expected = "Signature::as_bytes() is only valid for Ed25519 signatures")]
    #[allow(deprecated)]
    fn signature_as_bytes_panics_for_empty_instead_of_returning_zero_sentinel() {
        let _ = Signature::Empty.as_bytes();
    }

    #[test]
    #[should_panic(expected = "Signature::as_bytes() is only valid for Ed25519 signatures")]
    #[allow(deprecated)]
    fn signature_as_bytes_panics_for_post_quantum_instead_of_returning_zero_sentinel() {
        let _ = Signature::PostQuantum(vec![1, 2, 3]).as_bytes();
    }

    #[test]
    #[should_panic(expected = "Signature::as_bytes() is only valid for Ed25519 signatures")]
    #[allow(deprecated)]
    fn signature_as_bytes_panics_for_hybrid_to_prevent_classical_downgrade() {
        let signature = Signature::Hybrid {
            classical: [0xab; 64],
            pq: vec![1, 2, 3],
        };

        let _ = signature.as_bytes();
    }

    #[test]
    fn signature_ed25519_bytes() {
        let sig = Signature::from_bytes([0xab; 64]);
        assert_eq!(sig.ed25519_bytes(), Some(&[0xab; 64]));
        assert_eq!(Signature::Empty.ed25519_bytes(), None);
        let pq = Signature::PostQuantum(vec![1, 2, 3]);
        assert_eq!(pq.ed25519_bytes(), None);
    }

    #[test]
    fn signature_ed25519_component_zero_detection_is_explicit() {
        assert!(Signature::from_bytes([0u8; 64]).ed25519_component_is_zero());
        assert!(!Signature::from_bytes([1u8; 64]).ed25519_component_is_zero());
        assert!(!Signature::PostQuantum(vec![1, 2, 3]).ed25519_component_is_zero());
        assert!(!Signature::Empty.ed25519_component_is_zero());

        let hybrid_zero_classical = Signature::Hybrid {
            classical: [0u8; 64],
            pq: vec![1, 2, 3],
        };
        assert!(hybrid_zero_classical.ed25519_component_is_zero());
    }

    #[test]
    fn signature_display() {
        let sig = Signature::from_bytes([0xab; 64]);
        let s = sig.to_string();
        assert_eq!(s.len(), 128);
    }

    #[test]
    fn signature_debug() {
        let sig = Signature::from_bytes([0; 64]);
        let dbg = format!("{sig:?}");
        assert!(dbg.contains("Ed25519"));
    }

    #[test]
    fn signature_clone_eq() {
        let s1 = Signature::from_bytes([1u8; 64]);
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }

    #[test]
    fn signature_serde_roundtrip() {
        let sig = Signature::from_bytes([0xab; 64]);
        let json = serde_json::to_string(&sig).expect("ser");
        let sig2: Signature = serde_json::from_str(&json).expect("de");
        assert_eq!(sig, sig2);
    }

    #[test]
    fn signature_post_quantum() {
        let pq = Signature::PostQuantum(vec![1, 2, 3, 4, 5]);
        assert!(!pq.is_empty());
        assert_eq!(pq.algorithm(), "PostQuantum");
        assert_eq!(pq.to_bytes(), vec![1, 2, 3, 4, 5]);
        let json = serde_json::to_string(&pq).expect("ser");
        let pq2: Signature = serde_json::from_str(&json).expect("de");
        assert_eq!(pq, pq2);
    }

    #[test]
    fn signature_hybrid() {
        let h = Signature::Hybrid {
            classical: [0xab; 64],
            pq: vec![1, 2, 3],
        };
        assert!(!h.is_empty());
        assert_eq!(h.algorithm(), "Hybrid");
        assert_eq!(h.ed25519_bytes(), Some(&[0xab; 64]));
        assert_eq!(h.to_bytes().len(), 67);
        let json = serde_json::to_string(&h).expect("ser");
        let h2: Signature = serde_json::from_str(&json).expect("de");
        assert_eq!(h, h2);
    }

    #[test]
    fn signature_empty_variant() {
        assert!(Signature::Empty.is_empty());
        assert!(Signature::empty().is_empty());
        assert_eq!(Signature::Empty.algorithm(), "Empty");
        assert!(Signature::Empty.to_bytes().is_empty());
    }

    #[test]
    fn signature_display_variants() {
        assert_eq!(Signature::Empty.to_string(), "empty");
        let pq = Signature::PostQuantum(vec![0xab, 0xcd]);
        assert_eq!(pq.to_string(), "abcd");
        let h = Signature::Hybrid {
            classical: [0; 64],
            pq: vec![0xff],
        };
        let hs = h.to_string();
        assert!(hs.contains(":"));
    }

    // -- PublicKey ----------------------------------------------------------

    #[test]
    fn public_key_basics() {
        let pk = PublicKey::from_bytes([7u8; 32]);
        assert_eq!(*pk.as_bytes(), [7u8; 32]);
        let pk2 = pk;
        assert_eq!(pk, pk2);
    }

    #[test]
    fn public_key_display_debug() {
        let pk = PublicKey::from_bytes([0xab; 32]);
        let disp = pk.to_string();
        assert_eq!(disp.len(), 64);
        let dbg = format!("{pk:?}");
        assert!(dbg.starts_with("PublicKey("));
    }

    #[test]
    fn public_key_ord_hash() {
        let a = PublicKey::from_bytes([0; 32]);
        let b = PublicKey::from_bytes([1; 32]);
        assert!(a < b);
        use std::hash::{Hash, Hasher};
        let mut h = std::hash::DefaultHasher::new();
        a.hash(&mut h);
        let _ = h.finish(); // just ensure it doesn't panic
    }

    #[test]
    fn public_key_serde() {
        let pk = PublicKey::from_bytes([42; 32]);
        let json = serde_json::to_string(&pk).expect("ser");
        let pk2: PublicKey = serde_json::from_str(&json).expect("de");
        assert_eq!(pk, pk2);
    }

    // -- SecretKey ----------------------------------------------------------

    #[test]
    fn secret_key_zeroize_on_drop() {
        // We can't observe the drop zeroize directly, but we can verify
        // that the type compiles with Zeroize derive and the bytes are
        // accessible before drop.
        let sk = SecretKey::from_bytes([99u8; 32]);
        assert_eq!(*sk.as_bytes(), [99u8; 32]);
    }

    #[test]
    fn secret_key_debug_redacted() {
        let sk = SecretKey::from_bytes([0; 32]);
        let dbg = format!("{sk:?}");
        assert_eq!(dbg, "SecretKey(***)");
        // Must NOT leak key material
        assert!(!dbg.contains("00"));
    }

    #[test]
    fn secret_key_eq() {
        let a = SecretKey::from_bytes([1; 32]);
        let b = SecretKey::from_bytes([1; 32]);
        let c = SecretKey::from_bytes([2; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn secret_key_clone() {
        let a = SecretKey::from_bytes([5; 32]);
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- Did ---------------------------------------------------------------

    #[test]
    fn did_valid() {
        let d = Did::new("did:exo:alice").expect("valid");
        assert_eq!(d.as_str(), "did:exo:alice");
        assert_eq!(d.to_string(), "did:exo:alice");
    }

    #[test]
    fn did_valid_with_special_chars() {
        Did::new("did:exo:node-1_alpha:sub").expect("valid with hyphens/underscores/colons");
    }

    #[test]
    fn did_invalid_prefix() {
        let err = Did::new("did:btc:abc").unwrap_err();
        assert!(matches!(err, ExoError::InvalidDid { .. }));
    }

    #[test]
    fn did_empty_method_specific() {
        let err = Did::new("did:exo:").unwrap_err();
        assert!(matches!(err, ExoError::InvalidDid { .. }));
    }

    #[test]
    fn did_invalid_chars() {
        let err = Did::new("did:exo:has space").unwrap_err();
        assert!(matches!(err, ExoError::InvalidDid { .. }));
    }

    #[test]
    fn did_no_prefix() {
        let err = Did::new("alice").unwrap_err();
        assert!(matches!(err, ExoError::InvalidDid { .. }));
    }

    #[test]
    fn did_debug() {
        let d = Did::new("did:exo:bob").expect("valid");
        let dbg = format!("{d:?}");
        assert!(dbg.contains("did:exo:bob"));
    }

    #[test]
    fn did_clone_ord_hash() {
        let a = Did::new("did:exo:a").expect("valid");
        let b = Did::new("did:exo:b").expect("valid");
        assert!(a < b);
        let c = a.clone();
        assert_eq!(a, c);
        use std::hash::{Hash, Hasher};
        let mut h = std::hash::DefaultHasher::new();
        a.hash(&mut h);
        let _ = h.finish();
    }

    #[test]
    fn did_serde_roundtrip() {
        let d = Did::new("did:exo:test123").expect("valid");
        let json = serde_json::to_string(&d).expect("ser");
        let d2: Did = serde_json::from_str(&json).expect("de");
        assert_eq!(d, d2);
    }

    // -- CorrelationId -----------------------------------------------------

    #[test]
    fn correlation_id_new() {
        let c1 = CorrelationId::new();
        let c2 = CorrelationId::new();
        assert_ne!(c1, c2);
    }

    #[test]
    fn correlation_id_default() {
        let _c = CorrelationId::default();
    }

    #[test]
    fn correlation_id_from_uuid() {
        let uuid = Uuid::new_v4();
        let c = CorrelationId::from_uuid(uuid);
        assert_eq!(*c.as_uuid(), uuid);
    }

    #[test]
    fn correlation_id_display_debug() {
        let c = CorrelationId::new();
        let disp = c.to_string();
        assert!(!disp.is_empty());
        let dbg = format!("{c:?}");
        assert!(dbg.starts_with("CorrelationId("));
    }

    #[test]
    fn correlation_id_ord() {
        let a = CorrelationId::from_uuid(Uuid::nil());
        let b = CorrelationId::from_uuid(Uuid::max());
        assert!(a < b);
    }

    #[test]
    fn correlation_id_serde() {
        let c = CorrelationId::new();
        let json = serde_json::to_string(&c).expect("ser");
        let c2: CorrelationId = serde_json::from_str(&json).expect("de");
        assert_eq!(c, c2);
    }

    // -- Timestamp ---------------------------------------------------------

    #[test]
    fn timestamp_zero() {
        let t = Timestamp::ZERO;
        assert_eq!(t.physical_ms, 0);
        assert_eq!(t.logical, 0);
    }

    #[test]
    fn timestamp_new() {
        let t = Timestamp::new(1000, 5);
        assert_eq!(t.physical_ms, 1000);
        assert_eq!(t.logical, 5);
    }

    #[test]
    fn timestamp_ordering() {
        let t1 = Timestamp::new(100, 0);
        let t2 = Timestamp::new(100, 1);
        let t3 = Timestamp::new(101, 0);
        assert!(t1 < t2);
        assert!(t2 < t3);
        assert!(t1 < t3);
        assert_eq!(t1, t1);
    }

    #[test]
    fn timestamp_partial_ord_consistent() {
        let a = Timestamp::new(1, 2);
        let b = Timestamp::new(1, 3);
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Less));
    }

    #[test]
    fn timestamp_display_debug() {
        let t = Timestamp::new(42, 7);
        assert_eq!(t.to_string(), "42:7");
        let dbg = format!("{t:?}");
        assert!(dbg.contains("42"));
    }

    #[test]
    fn timestamp_serde() {
        let t = Timestamp::new(123456, 78);
        let json = serde_json::to_string(&t).expect("ser");
        let t2: Timestamp = serde_json::from_str(&json).expect("de");
        assert_eq!(t, t2);
    }

    #[test]
    fn timestamp_hash() {
        use std::hash::{Hash, Hasher};
        let t = Timestamp::new(1, 1);
        let mut h = std::hash::DefaultHasher::new();
        t.hash(&mut h);
        let _ = h.finish();
    }

    // -- Version -----------------------------------------------------------

    #[test]
    fn version_zero() {
        assert_eq!(Version::ZERO.value(), 0);
    }

    #[test]
    fn version_next() {
        let v = Version::ZERO.next().next().next();
        assert_eq!(v.value(), 3);
    }

    #[test]
    fn version_display() {
        assert_eq!(Version(5).to_string(), "v5");
    }

    #[test]
    fn version_ord() {
        assert!(Version(1) < Version(2));
        assert_eq!(Version(3), Version(3));
    }

    #[test]
    fn version_serde() {
        let v = Version(99);
        let json = serde_json::to_string(&v).expect("ser");
        let v2: Version = serde_json::from_str(&json).expect("de");
        assert_eq!(v, v2);
    }

    // -- hex_prefix helper -------------------------------------------------

    #[test]
    fn hex_prefix_helper() {
        let result = hex_prefix(&[0xab, 0xcd, 0xef, 0x01, 0x99]);
        assert_eq!(result, "abcdef01");
    }

    #[test]
    fn hex_prefix_short_input() {
        let result = hex_prefix(&[0xff]);
        assert_eq!(result, "ff");
    }

    // -- TrustReceipt --------------------------------------------------------

    fn test_sign_fn(data: &[u8]) -> Signature {
        let h = blake3::hash(data);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(h.as_bytes());
        Signature::from_bytes(sig)
    }

    #[test]
    fn trust_receipt_creation_and_hash_verification() {
        let receipt = TrustReceipt::new(
            Did::new("did:exo:actor1").unwrap(),
            Hash256::digest(b"authority-chain"),
            None,
            "governance.propose".into(),
            Hash256::digest(b"action-payload"),
            ReceiptOutcome::Executed,
            Timestamp::new(1_700_000_000_000, 0),
            &test_sign_fn,
        )
        .expect("trust receipt should encode");

        assert!(receipt.verify_hash().expect("verify hash"));
        assert!(!receipt.signature.is_empty());
        assert_eq!(receipt.actor_did.to_string(), "did:exo:actor1");
        assert_eq!(receipt.action_type, "governance.propose");
        assert_eq!(receipt.outcome, ReceiptOutcome::Executed);
        assert!(receipt.challenge_reference.is_none());
    }

    #[derive(serde::Deserialize)]
    struct DecodedTrustReceiptSigningPayload {
        domain: String,
        actor_did: String,
        authority_chain_hash: Hash256,
        consent_reference: Option<Hash256>,
        action_type: String,
        action_hash: Hash256,
        outcome: ReceiptOutcome,
        timestamp: Timestamp,
    }

    #[test]
    fn trust_receipt_signing_payload_is_domain_tagged_cbor() {
        let authority_chain_hash = Hash256::digest(b"authority-chain");
        let consent_reference = Hash256::digest(b"consent-ref");
        let action_hash = Hash256::digest(b"action-payload");
        let timestamp = Timestamp::new(1_700_000_000_123, 7);
        let receipt = TrustReceipt::new(
            Did::new("did:exo:actor-cbor").unwrap(),
            authority_chain_hash,
            Some(consent_reference),
            "governance.propose".into(),
            action_hash,
            ReceiptOutcome::Executed,
            timestamp,
            &test_sign_fn,
        )
        .expect("trust receipt should encode");

        let signing_payload = receipt.signing_payload().expect("signing payload");
        let payload: DecodedTrustReceiptSigningPayload =
            ciborium::from_reader(&signing_payload[..]).expect("decode payload");
        assert_eq!(payload.domain, TRUST_RECEIPT_SIGNING_DOMAIN);
        assert_eq!(payload.actor_did, "did:exo:actor-cbor");
        assert_eq!(payload.authority_chain_hash, authority_chain_hash);
        assert_eq!(payload.consent_reference, Some(consent_reference));
        assert_eq!(payload.action_type, "governance.propose");
        assert_eq!(payload.action_hash, action_hash);
        assert_eq!(payload.outcome, ReceiptOutcome::Executed);
        assert_eq!(payload.timestamp, timestamp);
    }

    #[test]
    fn trust_receipt_hash_matches_structured_cbor_contract() {
        let actor_did = Did::new("did:exo:actor-hash-contract").unwrap();
        let authority_chain_hash = Hash256::digest(b"authority-chain");
        let consent_reference = Hash256::digest(b"consent-ref");
        let action_type = "governance.propose";
        let action_hash = Hash256::digest(b"action-payload");
        let outcome = ReceiptOutcome::Executed;
        let timestamp = Timestamp::new(1_700_000_000_456, 9);
        let receipt = TrustReceipt::new(
            actor_did.clone(),
            authority_chain_hash,
            Some(consent_reference),
            action_type.into(),
            action_hash,
            outcome.clone(),
            timestamp,
            &test_sign_fn,
        )
        .expect("trust receipt should encode");
        let expected_hash = crate::hash::hash_structured(&TrustReceiptSigningPayload {
            domain: TRUST_RECEIPT_SIGNING_DOMAIN,
            actor_did: actor_did.as_str(),
            authority_chain_hash: &authority_chain_hash,
            consent_reference: Some(&consent_reference),
            action_type,
            action_hash: &action_hash,
            outcome: &outcome,
            timestamp: &timestamp,
        })
        .expect("structured trust receipt hash");

        assert_eq!(receipt.receipt_hash, expected_hash);
        assert!(receipt.verify_hash().expect("verify hash"));
    }

    #[test]
    fn trust_receipt_hash_path_uses_hash_structured_helper() {
        let source = std::fs::read_to_string("src/types.rs").expect("read types source");
        let impl_start = source.find("impl TrustReceipt").expect("TrustReceipt impl");
        let display_start = source[impl_start..]
            .find("impl fmt::Display for TrustReceipt")
            .expect("TrustReceipt display impl");
        let trust_receipt_impl = &source[impl_start..impl_start + display_start];

        assert!(trust_receipt_impl.contains("hash_structured(&payload)"));
        assert!(!trust_receipt_impl.contains("Hash256::digest(&payload)"));
    }

    #[test]
    fn trust_receipt_signature_verifies_with_actor_key() {
        let keypair = crate::crypto::KeyPair::from_secret_bytes([42u8; 32]).unwrap();
        let public_key = *keypair.public_key();
        let receipt = TrustReceipt::new(
            Did::new("did:exo:actor-signer").unwrap(),
            Hash256::digest(b"authority-chain"),
            None,
            "governance.vote".into(),
            Hash256::digest(b"vote-payload"),
            ReceiptOutcome::Executed,
            Timestamp::new(1_700_000_003_000, 0),
            &|payload| keypair.sign(payload),
        )
        .expect("trust receipt should encode");

        assert!(
            receipt
                .verify_signature(&public_key)
                .expect("verify signature")
        );
    }

    #[test]
    fn trust_receipt_signature_rejects_empty_wrong_key_and_tamper() {
        let keypair = crate::crypto::KeyPair::from_secret_bytes([43u8; 32]).unwrap();
        let wrong_keypair = crate::crypto::KeyPair::from_secret_bytes([44u8; 32]).unwrap();
        let public_key = *keypair.public_key();
        let wrong_public_key = *wrong_keypair.public_key();
        let mut receipt = TrustReceipt::new(
            Did::new("did:exo:actor-signer").unwrap(),
            Hash256::digest(b"authority-chain"),
            None,
            "governance.vote".into(),
            Hash256::digest(b"vote-payload"),
            ReceiptOutcome::Executed,
            Timestamp::new(1_700_000_003_000, 0),
            &|payload| keypair.sign(payload),
        )
        .expect("trust receipt should encode");

        assert!(
            !receipt
                .verify_signature(&wrong_public_key)
                .expect("verify signature")
        );

        let signature = receipt.signature.clone();
        receipt.signature = Signature::Empty;
        assert!(
            !receipt
                .verify_signature(&public_key)
                .expect("verify signature")
        );

        receipt.signature = signature;
        receipt.action_type = "governance.escalate".into();
        assert!(
            !receipt
                .verify_signature(&public_key)
                .expect("verify signature")
        );
    }

    #[test]
    fn trust_receipt_serialization_roundtrip() {
        let receipt = TrustReceipt::new(
            Did::new("did:exo:actor2").unwrap(),
            Hash256::digest(b"chain"),
            Some(Hash256::digest(b"consent-ref")),
            "dag.commit".into(),
            Hash256::digest(b"payload"),
            ReceiptOutcome::Pending,
            Timestamp::new(1_700_000_001_000, 5),
            &test_sign_fn,
        )
        .expect("trust receipt should encode");

        let json = serde_json::to_string(&receipt).expect("serialize");
        let deserialized: TrustReceipt = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(receipt.receipt_hash, deserialized.receipt_hash);
        assert_eq!(receipt.actor_did, deserialized.actor_did);
        assert_eq!(receipt.action_type, deserialized.action_type);
        assert_eq!(receipt.outcome, deserialized.outcome);
        assert_eq!(receipt.consent_reference, deserialized.consent_reference);
        assert!(deserialized.verify_hash().expect("verify hash"));
    }

    #[test]
    fn trust_receipt_tampered_hash_fails_verification() {
        let mut receipt = TrustReceipt::new(
            Did::new("did:exo:actor3").unwrap(),
            Hash256::digest(b"chain"),
            None,
            "governance.vote".into(),
            Hash256::digest(b"vote-payload"),
            ReceiptOutcome::Executed,
            Timestamp::new(1_700_000_002_000, 0),
            &test_sign_fn,
        )
        .expect("trust receipt should encode");

        // Tamper with the action type.
        receipt.action_type = "governance.escalate".into();
        assert!(!receipt.verify_hash().expect("verify hash"));
    }

    #[test]
    fn trust_receipt_outcome_variants() {
        assert_eq!(ReceiptOutcome::Executed.to_string(), "executed");
        assert_eq!(ReceiptOutcome::Denied.to_string(), "denied");
        assert_eq!(ReceiptOutcome::Escalated.to_string(), "escalated");
        assert_eq!(ReceiptOutcome::Pending.to_string(), "pending");
    }

    #[test]
    fn trust_receipt_display() {
        let receipt = TrustReceipt::new(
            Did::new("did:exo:display-test").unwrap(),
            Hash256::digest(b"chain"),
            None,
            "test.action".into(),
            Hash256::digest(b"payload"),
            ReceiptOutcome::Executed,
            Timestamp::now_utc(),
            &test_sign_fn,
        )
        .expect("trust receipt should encode");

        let display = format!("{receipt}");
        assert!(display.contains("TrustReceipt("));
        assert!(display.contains("did:exo:display-test"));
        assert!(display.contains("executed"));
    }
}
