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

//! Versioned proof statement registry and proof envelope.
//!
//! Lane VCG-001a (see `GAP-REGISTRY.md` "VCG-001 - Production ZK Proof Backend
//! Absent", remediation track: "Define a versioned proof statement registry
//! covering governance compliance, DAG inclusion, execution receipt, model
//! inference, and compatibility-only pedagogical proofs.").
//!
//! [`ProofEnvelope`] binds together everything a verifier needs to know
//! *about* a proof before it ever looks at proof bytes: which kind of
//! statement is being proven ([`ProofStatementKind`]), which backend
//! produced it ([`BackendId`]), an envelope format version, the public
//! inputs, commitment roots, the verifier key or image id, and a domain
//! separator binding the proof to its intended context.
//!
//! ## Fail-closed backend registry
//!
//! [`BackendId`] is a closed set of *known* backends plus an
//! [`BackendId::Unknown`] catch-all for any numeric id that does not match a
//! known variant. [`ProofEnvelope::validate_backend`] refuses
//! `BackendId::Unknown` unconditionally — an envelope naming an
//! unrecognized or future backend id can never validate. This is the same
//! "never stub, fail loudly" doctrine that governs the rest of this crate
//! (see the crate-root docs and [`crate::guard_unaudited`]).
//!
//! ## Unaudited backend gating
//!
//! Two backends are currently registered (see [`default_registry`]): the
//! blake3 "stand-in" cryptography ([`BackendId::UnauditedBlake3Standin`],
//! marked [`AuditStatus::Pedagogical`]) described in the crate-root docs, and
//! the RISC Zero integration seam ([`BackendId::RiscZero`], marked
//! [`AuditStatus::PendingExternalReview`] — wired but not yet cryptographically
//! reviewed). Neither is exempt from the crate's unaudited-refusal doctrine:
//! [`ProofEnvelope::verify`] refuses the blake3 stand-in with
//! [`crate::error::ProofError::UnauditedImplementation`] unless the opt-in
//! `unaudited-pedagogical-proofs` Cargo feature is enabled (mirroring the
//! [`crate::guard_unaudited`] pattern used by `snark`, `stark`, and `zkml`),
//! and fails the RISC Zero seam closed unconditionally until its external
//! review lands.
//!
//! ## Wire format
//!
//! Per the crate's canonical-CBOR-not-JSON convention (see
//! `src/verifier.rs`), [`ProofEnvelope`] is (de)serialized with
//! [`ciborium`]'s canonical CBOR encoding, never JSON.

use exo_core::types::Hash256;
use serde::{Deserialize, Serialize};

use crate::error::{ProofError, Result};

// ---------------------------------------------------------------------------
// ProofStatementKind
// ---------------------------------------------------------------------------

/// The kind of statement a [`ProofEnvelope`] attests to.
///
/// This is the versioned proof statement registry named in the VCG-001
/// remediation track. Adding a new kind is additive (append a variant);
/// removing or renumbering an existing kind is a breaking wire-format
/// change and must not be done silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofStatementKind {
    /// The statement attests to compliance with a governance rule or
    /// constitutional constraint.
    GovernanceCompliance,
    /// The statement attests that a value is included in a DAG at a given
    /// position/commitment.
    DagInclusion,
    /// The statement attests to the authenticity of an execution receipt
    /// (e.g. a computation actually ran and produced a given result).
    ExecutionReceipt,
    /// The statement attests to properties of a model inference (e.g. that
    /// a committed model produced a committed output from a committed
    /// input).
    ModelInference,
    /// The statement attests only to structural/shape compatibility of a
    /// pedagogical proof — not a production cryptographic claim. Used by
    /// the unaudited blake3 stand-in backend.
    PedagogicalCompatibility,
}

// ---------------------------------------------------------------------------
// BackendId
// ---------------------------------------------------------------------------

/// Named alias for the crate's own unaudited pedagogical stand-in backend,
/// [`BackendId::UnauditedBlake3Standin`].
///
/// Exposed as a named constant (rather than only the enum variant) so that
/// callers and tests can construct envelopes that name this backend through
/// a stable public path.
pub const UNAUDITED_BLAKE3_STANDIN_BACKEND_ID: BackendId = BackendId::UnauditedBlake3Standin;

/// Identifies which proof backend produced (and must verify) a
/// [`ProofEnvelope`].
///
/// This is a closed registry: [`BackendId::Unknown`] is the only variant
/// that accepts arbitrary numeric ids, and it is the *only* variant that
/// [`ProofEnvelope::validate_backend`] ever refuses. Every other variant is
/// a backend this crate knows about by construction. Registering a new
/// backend means adding a new named variant here — not widening what
/// `Unknown` accepts.
///
/// Ratified decision D1 (2026-07-02, see `GAP-REGISTRY.md` VCG-001) selects
/// RISC Zero as the production backend family. Lane VCG-001b registers the
/// [`BackendId::RiscZero`] variant and a fail-closed verifier *seam* for it
/// (see [`RiscZeroReceiptVerifier`] and [`ProofEnvelope::verify`]) — but does
/// **not** vendor the `risc0-zkvm` crate or wire an actual cryptographic
/// verify call. Per D1, the audited risc0 proving/verification toolchain is
/// itself a reviewed-dependency supply-chain event that "carries the
/// external audit budget"; adding it is out of scope until that review
/// happens. Until then, [`BackendId::RiscZero`] is registered as
/// [`AuditStatus::PendingExternalReview`] and always fails closed at
/// verify-time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendId {
    /// The crate's existing unaudited blake3 "stand-in" cryptography
    /// (`circuit.rs` / `snark.rs` / `stark.rs` / `zkml.rs`). Gated behind
    /// the `unaudited-pedagogical-proofs` feature at verification time.
    UnauditedBlake3Standin,
    /// RISC Zero zkVM execution-receipt backend (ratified decision D1,
    /// 2026-07-02, `GAP-REGISTRY.md` VCG-001). This variant exists so
    /// envelopes can *name* the selected production backend family — it is
    /// the integration seam, not a working verifier. No external
    /// cryptographic review of the risc0 verify path has happened yet, so
    /// this backend is registered under [`AuditStatus::PendingExternalReview`]
    /// (never [`AuditStatus::ProductionReviewed`]) and
    /// [`ProofEnvelope::verify`] always fails closed for it. See
    /// [`RiscZeroReceiptVerifier`] for exactly where the audited risc0
    /// verify call plugs in once review lands.
    RiscZero,
    /// An unrecognized or future backend id. Always fails closed in
    /// [`ProofEnvelope::validate_backend`] — this crate refuses to treat an
    /// id it does not recognize as valid, regardless of the numeric value.
    Unknown(u32),
}

impl BackendId {
    /// Returns `true` for any of the crate's registered *known* backend
    /// variants (i.e. not [`BackendId::Unknown`]).
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        !matches!(self, BackendId::Unknown(_))
    }
}

// ---------------------------------------------------------------------------
// AuditStatus / backend descriptor registry
// ---------------------------------------------------------------------------

/// The audit/review status carried by each entry in [`default_registry`].
///
/// This is a minimal accessor, not a verification mechanism: it exists so
/// tests (and future callers) can ask "does a production-reviewed backend
/// exist yet?" without hardcoding backend ids. Today every registered
/// backend is either [`AuditStatus::Pedagogical`] or
/// [`AuditStatus::PendingExternalReview`] — no [`AuditStatus::ProductionReviewed`]
/// entry exists yet. Registering one is itself the claim that external
/// cryptographic review has happened; see `tests/refusal.rs`'s standing red
/// and `tests/riscz_verifier_scaffold.rs`'s anti-overclaim regression locks,
/// both of which must keep failing/holding until that review actually lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStatus {
    /// Structural/pedagogical stand-in only — not a production trust claim.
    /// Gated behind the `unaudited-pedagogical-proofs` feature at
    /// verification time (see [`crate::guard_unaudited`]).
    Pedagogical,
    /// Integration wired but **not yet cryptographically reviewed**; not a
    /// production trust claim. Used for backends (e.g.
    /// [`BackendId::RiscZero`]) whose envelope shape and verifier *seam*
    /// exist in-tree, but whose actual verify path has not undergone
    /// external cryptographic review. [`ProofEnvelope::verify`] always fails
    /// closed for backends in this status — the seam exists so that
    /// wiring in the audited verifier later is a small, localized change,
    /// not a claim that it is safe to trust today.
    PendingExternalReview,
    /// A production backend that has undergone cryptographic review and
    /// carries its own audit evidence. Exempt from the pedagogical
    /// unaudited-refusal gate. No backend holds this status yet — it is
    /// introduced here only so the registry has somewhere to record one
    /// once external review of a production backend actually lands.
    ProductionReviewed,
}

/// A single entry in [`default_registry`]: a known [`BackendId`] paired with
/// its [`AuditStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendDescriptor {
    /// The backend this descriptor describes.
    pub backend_id: BackendId,
    /// Whether this backend is pedagogical or has been production-reviewed.
    pub audit_status: AuditStatus,
}

/// Returns the crate's default backend registry as descriptors.
///
/// This is the minimal audit-status accessor named in the VCG-001a
/// hardening pass: it lets callers (and tests) inspect what backends are
/// registered and whether any of them are [`AuditStatus::ProductionReviewed`]
/// without reaching into [`ProofEnvelope::verify`] internals. Today this
/// returns two entries:
///
/// - the unaudited blake3 stand-in, marked [`AuditStatus::Pedagogical`];
/// - the RISC Zero integration seam (VCG-001b, ratified decision D1),
///   marked [`AuditStatus::PendingExternalReview`] — wired but not yet
///   cryptographically reviewed.
///
/// Neither entry is [`AuditStatus::ProductionReviewed`]: no backend has
/// undergone external cryptographic review yet. See
/// `tests/riscz_verifier_scaffold.rs`'s anti-overclaim regression locks.
#[must_use]
pub fn default_registry() -> Vec<BackendDescriptor> {
    vec![
        BackendDescriptor {
            backend_id: BackendId::UnauditedBlake3Standin,
            audit_status: AuditStatus::Pedagogical,
        },
        BackendDescriptor {
            backend_id: BackendId::RiscZero,
            audit_status: AuditStatus::PendingExternalReview,
        },
    ]
}

// ---------------------------------------------------------------------------
// RiscZero verifier-integration seam (VCG-001b)
// ---------------------------------------------------------------------------

/// Integration seam for the audited RISC Zero receipt verifier.
///
/// Ratified decision D1 (2026-07-02, `GAP-REGISTRY.md` VCG-001) selects RISC
/// Zero as the production backend family, with Groth16 wrapping for receipt
/// compression, server-side-only proving, and a verifier that "stays small,
/// in-workspace, and pinned, and carries the external audit budget." That
/// audit has not happened yet, and the `risc0-zkvm` crate itself is not a
/// workspace dependency — vendoring it is precisely the reviewed-dependency
/// supply-chain event D1 defers until review lands.
///
/// This trait exists so that event has exactly one, small, localized
/// plug-in point: **this is where the audited risc0 `Receipt::verify` (or
/// equivalent image-id-bound verification) call goes.** Implementing this
/// trait against the real `risc0-zkvm` verifier — and swapping
/// [`ProofEnvelope::verify`]'s `BackendId::RiscZero` arm to call it instead
/// of failing closed — is the entire VCG-001c (or later) green-stage change.
/// Until then, [`FailClosedRiscZeroVerifier`] is the only implementation,
/// and it never returns `Ok(true)`.
pub trait RiscZeroReceiptVerifier {
    /// Verifies a RISC Zero execution receipt against the given image id (or
    /// verifier key bytes) and the envelope's journal-binding digest.
    ///
    /// `receipt_bytes` are the serialized risc0 `Receipt`/proof bytes the
    /// audited verifier will decode and check (objective O-1.2): an audited
    /// implementation deserializes them into a risc0 `Receipt` and runs its
    /// verify path. The [`FailClosedRiscZeroVerifier`] default ignores them and
    /// refuses unconditionally — threading the bytes here now means wiring the
    /// audited verifier later is a small, localized change rather than a new
    /// signature break.
    ///
    /// `journal_digest` is [`ProofEnvelope::binding_digest`] — the canonical
    /// digest over the full envelope context (`statement_kind`,
    /// `commitment_roots`, `domain_separator`, `public_inputs`, ...). An audited
    /// implementation MUST check both that the receipt verifies against the
    /// image id AND that the receipt's journal commits to exactly this digest
    /// (objective O-1.1), so a receipt proven for one context can never be
    /// replayed under another.
    ///
    /// # Errors
    ///
    /// Real implementations return `Err` for any receipt that does not
    /// verify. The [`FailClosedRiscZeroVerifier`] default always returns
    /// `Err` — see its docs.
    fn verify_receipt(
        &self,
        receipt_bytes: &[u8],
        image_id_or_verifier_key: &[u8],
        journal_digest: &Hash256,
    ) -> Result<bool>;
}

/// Fail-closed default [`RiscZeroReceiptVerifier`]: refuses every receipt.
///
/// This is the only [`RiscZeroReceiptVerifier`] implementation in this
/// crate today. It exists so [`ProofEnvelope::verify`] has a concrete seam
/// to call for `BackendId::RiscZero` rather than inlining the refusal —
/// swapping this type out for one backed by the audited `risc0-zkvm`
/// verifier (once external cryptographic review lands) is the intended,
/// localized future change. It must never be changed to return `Ok(true)`
/// without that review having actually happened; doing so would be exactly
/// the false soundness claim ratified decision D1 and the VCG-001b
/// anti-overclaim regression locks (`tests/riscz_verifier_scaffold.rs`)
/// exist to prevent.
#[derive(Debug, Clone, Copy, Default)]
pub struct FailClosedRiscZeroVerifier;

impl RiscZeroReceiptVerifier for FailClosedRiscZeroVerifier {
    fn verify_receipt(
        &self,
        _receipt_bytes: &[u8],
        _image_id_or_verifier_key: &[u8],
        _journal_digest: &Hash256,
    ) -> Result<bool> {
        Err(ProofError::VerificationFailed(
            "BackendId::RiscZero verifier is a pending-review scaffold: no external \
             cryptographic review of the risc0 verify path has landed yet, so this refuses \
             closed rather than trust an unaudited verifier. See \
             RiscZeroReceiptVerifier for exactly where the audited risc0 verify call plugs \
             in once review lands."
                .to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// ProofEnvelope
// ---------------------------------------------------------------------------

/// A versioned envelope binding everything a verifier needs to know about a
/// proof, independent of the proof bytes themselves.
///
/// Field order mirrors the VCG-001 "Next red test" bullet: "statement kind,
/// backend id, version, public inputs, commitment roots, verifier key or
/// image id, and domain separator."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEnvelope {
    /// Which kind of statement this envelope attests to.
    pub statement_kind: ProofStatementKind,
    /// Which backend produced (and must verify) the wrapped proof.
    pub backend_id: BackendId,
    /// Envelope format version. Independent of the crate/package version;
    /// bump when the envelope's own field shape changes.
    pub version: u32,
    /// Public inputs to the statement, as opaque byte strings. Semantics
    /// are defined per [`ProofStatementKind`] / backend.
    pub public_inputs: Vec<Vec<u8>>,
    /// Commitment roots (e.g. DAG roots, state roots) the statement is
    /// anchored to.
    pub commitment_roots: Vec<Hash256>,
    /// The verifier key (SNARK/STARK) or image id (zkVM-style backends)
    /// needed to verify the wrapped proof, as opaque bytes.
    pub verifier_key_or_image_id: Vec<u8>,
    /// Domain separator binding this envelope to its intended context, so
    /// a valid proof for one domain cannot be replayed as valid for
    /// another.
    pub domain_separator: Vec<u8>,
}

/// Domain-separation tag for [`ProofEnvelope::binding_digest`]. Bump only if
/// the binding-tuple shape changes.
const ENVELOPE_BINDING_DOMAIN: &str = "exo-proofs:envelope-binding:v1";

/// The canonical, field-named binding tuple hashed by
/// [`ProofEnvelope::binding_digest`].
///
/// Serialized (canonical CBOR) instead of the [`ProofEnvelope`] struct itself
/// so the digest pre-image is an explicit, domain-tagged shape, and so
/// `backend_id`/`version` are bound alongside the statement context.
#[derive(Serialize)]
struct EnvelopeBinding<'a> {
    domain: &'a str,
    statement_kind: &'a ProofStatementKind,
    backend_id: &'a BackendId,
    version: u32,
    public_inputs: &'a [Vec<u8>],
    commitment_roots: &'a [Hash256],
    verifier_key_or_image_id: &'a [u8],
    domain_separator: &'a [u8],
}

impl ProofEnvelope {
    /// Validates that [`Self::backend_id`] names a known, registered
    /// backend.
    ///
    /// Fails closed: any [`BackendId::Unknown`] value — including ids that
    /// happen to coincide with a future backend not yet registered here —
    /// is refused. This must be called (directly, or transitively via
    /// [`Self::verify`]) before any proof bytes wrapped by this envelope
    /// are trusted.
    pub fn validate_backend(&self) -> Result<()> {
        if self.backend_id.is_registered() {
            Ok(())
        } else {
            Err(ProofError::InvalidProofFormat(format!(
                "proof envelope names unknown/unregistered backend id: {:?}",
                self.backend_id
            )))
        }
    }

    /// Canonical journal-binding digest for a RISC Zero receipt (objective
    /// O-1.1, 2026-07-04 ratification slate).
    ///
    /// Folds the ENTIRE envelope context — `statement_kind`, `backend_id`,
    /// `version`, `public_inputs`, `commitment_roots`,
    /// `verifier_key_or_image_id`, and `domain_separator` — into a single
    /// BLAKE3 digest over canonical CBOR, under a fixed domain tag. This is the
    /// value a RISC Zero receipt's journal must commit to: the audited
    /// [`RiscZeroReceiptVerifier`] checks the receipt verifies against the image
    /// id AND that its journal equals this digest, so a receipt proven for one
    /// (statement, roots, domain) context can never be replayed as valid under
    /// another. Before O-1.1 the seam received only the image id and the raw
    /// public inputs, dropping `statement_kind`, `commitment_roots`, and
    /// `domain_separator` — an unbound statement.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::InvalidProofFormat`] if canonical CBOR encoding of
    /// the binding tuple fails.
    /// Canonical CBOR bytes hashed by [`Self::binding_digest`].
    ///
    /// A RISC Zero guest must commit exactly these bytes so
    /// `blake3(journal.bytes)` equals the envelope binding digest.
    pub fn binding_payload(&self) -> Result<Vec<u8>> {
        let binding = EnvelopeBinding {
            domain: ENVELOPE_BINDING_DOMAIN,
            statement_kind: &self.statement_kind,
            backend_id: &self.backend_id,
            version: self.version,
            public_inputs: &self.public_inputs,
            commitment_roots: &self.commitment_roots,
            verifier_key_or_image_id: &self.verifier_key_or_image_id,
            domain_separator: &self.domain_separator,
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&binding, &mut encoded).map_err(|err| {
            ProofError::InvalidProofFormat(format!(
                "failed to canonical-CBOR encode envelope binding for digest: {err}"
            ))
        })?;
        Ok(encoded)
    }

    pub fn binding_digest(&self) -> Result<Hash256> {
        Ok(Hash256(*blake3::hash(&self.binding_payload()?).as_bytes()))
    }

    /// Runs the RISC Zero seam against `verifier`, threading the serialized
    /// `receipt_bytes` (objective O-1.2) and binding the full envelope context
    /// via [`Self::binding_digest`] (objective O-1.1). Production
    /// [`Self::verify`] passes [`FailClosedRiscZeroVerifier`]; tests inject a
    /// spy to assert the receipt bytes and the binding digest actually reach
    /// the verifier.
    fn verify_riscz(
        &self,
        receipt_bytes: &[u8],
        verifier: &dyn RiscZeroReceiptVerifier,
    ) -> Result<bool> {
        let journal_digest = self.binding_digest()?;
        verifier.verify_receipt(
            receipt_bytes,
            &self.verifier_key_or_image_id,
            &journal_digest,
        )
    }

    /// Verifies the envelope's named backend is both registered and, if
    /// unaudited, explicitly opted into.
    ///
    /// `receipt_bytes` are the serialized risc0 `Receipt`/proof bytes to check
    /// (objective O-1.2). They are threaded down to the
    /// [`RiscZeroReceiptVerifier`] seam for the [`BackendId::RiscZero`] arm so
    /// the future audited verifier can decode and check them; the
    /// [`FailClosedRiscZeroVerifier`] default ignores them and still refuses.
    /// The `UnauditedBlake3Standin` and `Unknown` arms never inspect
    /// `receipt_bytes` — for them it is simply an unused parameter — so passing
    /// any value (including `&[]`) cannot change their fail-closed outcomes.
    ///
    /// No backend has a working, externally-reviewed verifier wired yet:
    /// the unaudited blake3 stand-in is feature-gated and still a fail-closed
    /// stub even when opted into (VCG-001a), and the RISC Zero seam
    /// (VCG-001b, ratified decision D1) is wired but pending external
    /// cryptographic review (see [`RiscZeroReceiptVerifier`]). Fail-closed:
    /// **every** backend currently registered returns a typed error here —
    /// there is no verifier wired for any backend at this stage. This is a
    /// deliberate success-shaped surface trap avoidance: `verify()` must
    /// never report `Ok(true)` unless it actually verified something.
    ///
    /// Behavior:
    /// - Unknown/unregistered backend id → `Err(ProofError::InvalidProofFormat)`
    ///   (fail-closed registry, checked first via [`Self::validate_backend`]).
    /// - [`UNAUDITED_BLAKE3_STANDIN_BACKEND_ID`] → first refuses with
    ///   `Err(ProofError::UnauditedImplementation)` unless the
    ///   `unaudited-pedagogical-proofs` feature is enabled (mirroring
    ///   [`crate::guard_unaudited`]); if that guard passes, still refuses
    ///   with `Err(ProofError::VerificationFailed)` because no verifier is
    ///   wired for this backend yet — construction/wrapping of an envelope
    ///   for this backend is feature-gated as above, but *verification* is
    ///   not implemented at all.
    /// - [`BackendId::RiscZero`] → always refuses with
    ///   `Err(ProofError::VerificationFailed)` via
    ///   [`FailClosedRiscZeroVerifier`], independent of the
    ///   `unaudited-pedagogical-proofs` feature flag (that flag only gates
    ///   this crate's own blake3 stand-in, not the RiscZero seam). The
    ///   refusal reason names pending external review, not a missing
    ///   feature opt-in.
    pub fn verify(&self, receipt_bytes: &[u8]) -> Result<bool> {
        self.validate_backend()?;

        match self.backend_id {
            BackendId::UnauditedBlake3Standin => {
                crate::guard_unaudited("envelope::ProofEnvelope::verify")?;
                // Even once opted into the unaudited pedagogical stand-in,
                // no verifier is wired for it yet at this stage: this lane
                // (VCG-001a) only establishes the envelope/registry shape.
                // Returning `Ok(true)` here would be a success-shaped
                // surface that verifies nothing. Fail closed instead.
                Err(ProofError::VerificationFailed(format!(
                    "no verifier is wired for backend {:?} yet; \
                     ProofEnvelope::verify is a fail-closed stub until \
                     VCG-001b lands real per-backend verification",
                    self.backend_id
                )))
            }
            BackendId::RiscZero => {
                #[cfg(feature = "risc0-verifier")]
                {
                    self.verify_riscz(receipt_bytes, &crate::riscz::Risc0Groth16Verifier)
                }
                #[cfg(not(feature = "risc0-verifier"))]
                {
                    let _ = receipt_bytes;
                    Err(ProofError::VerificationFailed(
                        "risc0-verifier feature is disabled; cannot verify RISC Zero receipts"
                            .into(),
                    ))
                }
            }
            BackendId::Unknown(_) => unreachable!(
                "validate_backend() above must have already refused an unregistered backend id"
            ),
        }
    }
}

/// Public inputs a CGR RISC Zero guest must reproduce from combinator replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgrZkPublicInputs {
    pub combinator_hash: Hash256,
    pub input_hash: Hash256,
    pub output_hash: Hash256,
    pub trace_hash: Hash256,
}

impl CgrZkPublicInputs {
    #[must_use]
    pub fn to_public_inputs(&self) -> Vec<Vec<u8>> {
        vec![
            self.combinator_hash.as_bytes().to_vec(),
            self.input_hash.as_bytes().to_vec(),
            self.output_hash.as_bytes().to_vec(),
            self.trace_hash.as_bytes().to_vec(),
        ]
    }

    pub fn from_public_inputs(inputs: &[Vec<u8>]) -> Result<Self> {
        if inputs.len() != 4 {
            return Err(ProofError::InvalidProofFormat(format!(
                "CGR zk public inputs must be 4 hashes, got {}",
                inputs.len()
            )));
        }
        Ok(Self {
            combinator_hash: hash_from_bytes(&inputs[0], "combinator_hash")?,
            input_hash: hash_from_bytes(&inputs[1], "input_hash")?,
            output_hash: hash_from_bytes(&inputs[2], "output_hash")?,
            trace_hash: hash_from_bytes(&inputs[3], "trace_hash")?,
        })
    }
}

fn hash_from_bytes(bytes: &[u8], name: &str) -> Result<Hash256> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ProofError::InvalidProofFormat(format!("{name} must be exactly 32 bytes")))?;
    Ok(Hash256(arr))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod canonical_encoding_contract_tests {
    #[test]
    fn envelope_module_uses_canonical_cbor_not_json() {
        // Mirrors verifier.rs's `verify_any_uses_canonical_cbor_not_json`
        // source-grep guard: the envelope module itself must never reach
        // for JSON as a wire format for proof-adjacent data.
        let source = include_str!("envelope.rs");
        let production = source
            .split("// ---------------------------------------------------------------------------\n// Tests")
            .next()
            .expect("production section exists");

        assert!(
            !production.contains("serde_json"),
            "envelope module must not use serde_json anywhere in its production code path"
        );
    }

    #[test]
    fn backend_id_unknown_variant_is_the_only_unregistered_case() {
        use super::BackendId;

        assert!(BackendId::UnauditedBlake3Standin.is_registered());
        assert!(!BackendId::Unknown(0).is_registered());
        assert!(!BackendId::Unknown(u32::MAX).is_registered());
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod riscz_seam_binding_unit {
    //! O-1.1 (2026-07-04 slate): prove the RiscZero seam threads the envelope's
    //! binding digest to the verifier, so the audited verifier can bind the
    //! receipt to the full statement context rather than certify an unbound
    //! statement.
    use std::cell::RefCell;

    use super::*;

    /// Test-only verifier that records the journal digest it is handed, then
    /// still refuses — a spy must never manufacture a success-shaped result.
    struct SpyVerifier {
        seen_digest: RefCell<Option<Hash256>>,
    }

    impl RiscZeroReceiptVerifier for SpyVerifier {
        fn verify_receipt(
            &self,
            _receipt_bytes: &[u8],
            _image_id_or_verifier_key: &[u8],
            journal_digest: &Hash256,
        ) -> Result<bool> {
            *self.seen_digest.borrow_mut() = Some(*journal_digest);
            Err(ProofError::VerificationFailed(
                "spy verifier records the digest only; it never manufactures success".to_string(),
            ))
        }
    }

    fn riscz_env() -> ProofEnvelope {
        ProofEnvelope {
            statement_kind: ProofStatementKind::ExecutionReceipt,
            backend_id: BackendId::RiscZero,
            version: 1,
            public_inputs: vec![b"pi".to_vec()],
            commitment_roots: vec![Hash256([3u8; 32])],
            verifier_key_or_image_id: b"img".to_vec(),
            domain_separator: b"dom".to_vec(),
        }
    }

    #[test]
    fn seam_passes_binding_digest_to_verifier() {
        let env = riscz_env();
        let spy = SpyVerifier {
            seen_digest: RefCell::new(None),
        };
        // Refuses (fail-closed spy), but must have received the digest.
        let _ = env.verify_riscz(b"some-bytes", &spy);
        assert_eq!(
            *spy.seen_digest.borrow(),
            Some(env.binding_digest().expect("binding digest")),
            "the seam must hand the verifier exactly the envelope's binding digest"
        );
    }

    #[test]
    fn seam_binding_digest_reflects_domain_separator_change() {
        let mut env = riscz_env();
        let spy1 = SpyVerifier {
            seen_digest: RefCell::new(None),
        };
        let _ = env.verify_riscz(b"receipt-bytes-a", &spy1);

        env.domain_separator = b"dom-CHANGED".to_vec();
        let spy2 = SpyVerifier {
            seen_digest: RefCell::new(None),
        };
        let _ = env.verify_riscz(b"receipt-bytes-a", &spy2);

        assert!(
            spy1.seen_digest.borrow().is_some(),
            "spy1 verifier must have been called"
        );
        assert_ne!(
            *spy1.seen_digest.borrow(),
            *spy2.seen_digest.borrow(),
            "the digest reaching the verifier must change with domain_separator"
        );
    }

    /// O-1.2(A): test-only verifier that records the `receipt_bytes` it is
    /// handed, then STILL refuses — mirrors [`SpyVerifier`]'s discipline: a spy
    /// must never manufacture a success-shaped result.
    struct ReceiptBytesSpyVerifier {
        seen_receipt_bytes: RefCell<Option<Vec<u8>>>,
    }

    impl RiscZeroReceiptVerifier for ReceiptBytesSpyVerifier {
        fn verify_receipt(
            &self,
            receipt_bytes: &[u8],
            _image_id_or_verifier_key: &[u8],
            _journal_digest: &Hash256,
        ) -> Result<bool> {
            *self.seen_receipt_bytes.borrow_mut() = Some(receipt_bytes.to_vec());
            Err(ProofError::VerificationFailed(
                "spy verifier records the receipt bytes only; it never manufactures success"
                    .to_string(),
            ))
        }
    }

    #[test]
    fn verify_riscz_passes_receipt_bytes_to_seam() {
        let env = riscz_env();
        let spy = ReceiptBytesSpyVerifier {
            seen_receipt_bytes: RefCell::new(None),
        };
        // Refuses (fail-closed spy), but must have received the exact bytes.
        let _ = env.verify_riscz(b"distinct-receipt-bytes", &spy);
        assert_eq!(
            spy.seen_receipt_bytes.borrow().as_deref(),
            Some(b"distinct-receipt-bytes".as_slice()),
            "the seam must hand the verifier exactly the receipt bytes it was called with"
        );
    }

    #[test]
    fn verify_riscz_receipt_bytes_reflect_the_argument_change() {
        // Proves live plumbing, not a hardcoded constant: changing the bytes
        // passed in changes what the spy records.
        let env = riscz_env();

        let spy1 = ReceiptBytesSpyVerifier {
            seen_receipt_bytes: RefCell::new(None),
        };
        let _ = env.verify_riscz(b"receipt-bytes-one", &spy1);

        let spy2 = ReceiptBytesSpyVerifier {
            seen_receipt_bytes: RefCell::new(None),
        };
        let _ = env.verify_riscz(b"receipt-bytes-TWO", &spy2);

        assert!(
            spy1.seen_receipt_bytes.borrow().is_some(),
            "spy1 verifier must have been called"
        );
        assert_ne!(
            *spy1.seen_receipt_bytes.borrow(),
            *spy2.seen_receipt_bytes.borrow(),
            "the receipt bytes reaching the verifier must change with the argument passed"
        );
    }
}
