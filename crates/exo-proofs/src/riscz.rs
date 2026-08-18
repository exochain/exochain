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

//! Real (vendored) RISC Zero receipt verifier — VCG-001c artifact.
//!
//! [`Risc0Groth16Verifier`] is a concrete [`crate::envelope::RiscZeroReceiptVerifier`]
//! implementation backed by the actual, vendored `risc0-zkvm` crate (verifier-only:
//! `default-features = false, features = ["std"]` — no prover, no client API, no
//! Bonsai remote-proving surface). It exists as a **reviewable artifact**, frozen
//! for external cryptographic review (ratified decision D1, `GAP-REGISTRY.md`
//! VCG-001).
//!
//! [`ProofEnvelope::verify`](crate::envelope::ProofEnvelope::verify) calls this
//! verifier for [`crate::envelope::BackendId::RiscZero`]. A valid receipt
//! returns `Ok(true)`. The registry still marks RISC Zero
//! [`crate::envelope::AuditStatus::PendingExternalReview`] — that is the
//! external-review label, not a claim that `verify` is a no-op.
//!
//! ## Verification contract
//!
//! [`Risc0Groth16Verifier::verify_receipt`] performs, in order:
//!
//! 1. **Decode**: deserialize `receipt_bytes` as canonical CBOR
//!    ([`ciborium`], matching this crate's canonical-CBOR-not-JSON convention;
//!    see `src/verifier.rs`) into a risc0 [`Receipt`]. Malformed bytes → `Err`.
//! 2. **Parse image id**: convert `image_id_or_verifier_key` into a risc0
//!    [`Digest`] (exactly 32 bytes). Wrong length → `Err`.
//! 3. **Cryptographic verify**: call `receipt.verify(image_id)`, which checks
//!    the wrapped seal (Groth16 or otherwise, per risc0's `InnerReceipt`
//!    dispatch) against the image id and confirms successful guest exit.
//!    Failure → `Err`.
//! 4. **Journal binding** (objective O-1.1): BLAKE3-hash the receipt's
//!    `journal.bytes` and require it equal `journal_digest` exactly — this is
//!    the contract that binds a receipt to one, and only one, envelope
//!    context, so a receipt proven for one (statement, roots, domain) can
//!    never be replayed as valid under another. Mismatch → `Err`.
//!
//! Only if all four steps succeed does this return `Ok(true)`. Every other
//! path returns `Err`, never `Ok(false)` — mirroring this crate's existing
//! fail-closed convention (see [`FailClosedRiscZeroVerifier`](crate::envelope::FailClosedRiscZeroVerifier)).

use exo_core::types::Hash256;
use risc0_zkvm::{Digest, Receipt};

use crate::{
    envelope::RiscZeroReceiptVerifier,
    error::{ProofError, Result},
};

/// Real, vendored RISC Zero Groth16 receipt verifier.
///
/// See the module docs for the full verification contract and the standing
/// prohibition on wiring this into [`crate::envelope::ProofEnvelope::verify`]
/// or promoting the registry entry before external cryptographic review.
#[derive(Debug, Clone, Copy, Default)]
pub struct Risc0Groth16Verifier;

impl RiscZeroReceiptVerifier for Risc0Groth16Verifier {
    fn verify_receipt(
        &self,
        receipt_bytes: &[u8],
        image_id_or_verifier_key: &[u8],
        journal_digest: &Hash256,
    ) -> Result<bool> {
        // Step 1: decode receipt_bytes as canonical CBOR into a risc0 Receipt.
        // Uses ciborium (this crate's canonical wire format elsewhere) rather
        // than bincode/postcard: those codecs live behind risc0-zkvm's
        // `client`/`prove` features, which this verifier-only vendoring
        // deliberately does not enable.
        let receipt: Receipt = ciborium::from_reader(receipt_bytes).map_err(|err| {
            ProofError::DeserializationError(format!(
                "failed to decode receipt_bytes as a canonical-CBOR risc0 Receipt: {err}"
            ))
        })?;

        // Step 2: parse the image id / verifier key bytes into a risc0 Digest
        // (32 bytes, fixed width). Any other length is rejected.
        let image_id = Digest::try_from(image_id_or_verifier_key).map_err(|err| {
            ProofError::InvalidProofFormat(format!(
                "image_id_or_verifier_key is not a valid 32-byte risc0 image id \
                 digest (expected {} bytes): {err}",
                risc0_zkvm::sha::DIGEST_BYTES
            ))
        })?;

        // Step 3: cryptographic verification — checks the seal (Groth16 or
        // otherwise) against the image id and confirms a successful guest
        // exit. This is the actual zero-knowledge proof check.
        receipt.verify(image_id).map_err(|err| {
            ProofError::VerificationFailed(format!("risc0 receipt failed to verify: {err}"))
        })?;

        // Step 4 (objective O-1.1): the receipt's journal must commit to
        // exactly this envelope's binding digest, so a receipt proven for one
        // (statement, roots, domain) context can never be replayed as valid
        // under another. blake3 matches ProofEnvelope::binding_digest's own
        // hash function.
        let actual_journal_digest = Hash256(*blake3::hash(&receipt.journal.bytes).as_bytes());
        if &actual_journal_digest != journal_digest {
            return Err(ProofError::VerificationFailed(format!(
                "risc0 receipt journal does not commit to the expected envelope binding \
                 digest: receipt journal hashes to {actual_journal_digest:?}, expected \
                 {journal_digest:?}. A receipt proven for one envelope context must never \
                 verify under another."
            )));
        }

        Ok(true)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    //! Honesty note (VCG-001c): these tests exercise the fail-closed /
    //! rejection paths of [`Risc0Groth16Verifier::verify_receipt`] against
    //! malformed, garbage, and structurally-invalid input. They do NOT
    //! exercise the accept path (a genuinely valid Groth16 receipt verifying
    //! successfully) — that would require either a real serialized risc0
    //! `Receipt` fixture or the `prove` feature (guest ELF + prover stack),
    //! and this crate deliberately vendors risc0-zkvm verifier-only
    //! (`default-features = false, features = ["std"]`), excluding `prove`.
    //! risc0-zkvm 3.0.5 as distributed on crates.io ships no serialized
    //! `Receipt`/`Groth16Receipt` test vector usable from the verify-only
    //! feature surface (checked directly against the vendored crate source
    //! under `~/.cargo/registry/src/.../risc0-zkvm-3.0.5`; `risc0-groth16`
    //! ships raw `ark-groth16` proof/vk/public-input JSON fixtures under
    //! `tests/data/`, but those are not a serialized `risc0_zkvm::Receipt`
    //! and wrapping them into one is exactly the `prove`-only surface this
    //! seam avoids). A happy-path test is therefore deferred to a follow-up
    //! that lands a committed real-receipt fixture (see the `#[ignore]`d stub
    //! below) rather than faked here.

    use exo_core::types::Hash256;

    use super::Risc0Groth16Verifier;
    use crate::envelope::RiscZeroReceiptVerifier;

    fn verifier() -> Risc0Groth16Verifier {
        Risc0Groth16Verifier
    }

    #[test]
    fn empty_receipt_bytes_are_rejected() {
        let result = verifier().verify_receipt(&[], &[0u8; 32], &Hash256([0u8; 32]));
        assert!(
            result.is_err(),
            "empty receipt_bytes must fail closed, got {result:?}"
        );
    }

    #[test]
    fn garbage_receipt_bytes_are_rejected() {
        let garbage = vec![0xFFu8; 256];
        let result = verifier().verify_receipt(&garbage, &[0u8; 32], &Hash256([0u8; 32]));
        assert!(
            result.is_err(),
            "garbage (non-CBOR, non-Receipt) receipt_bytes must fail closed, got {result:?}"
        );
    }

    #[test]
    fn truncated_cbor_receipt_bytes_are_rejected() {
        // A handful of bytes that are valid-ish CBOR prefix but not a
        // complete, valid Receipt encoding.
        let truncated: Vec<u8> = vec![0xA1, 0x64, b't', b'e', b's', b't'];
        let result = verifier().verify_receipt(&truncated, &[0u8; 32], &Hash256([0u8; 32]));
        assert!(
            result.is_err(),
            "truncated/malformed CBOR must fail closed, got {result:?}"
        );
    }

    #[test]
    fn wrong_length_image_id_is_rejected_even_with_empty_receipt() {
        // Wrong-length image id should fail regardless of decode outcome;
        // exercised here with an empty receipt to isolate the check (the
        // implementation decodes first, so this also documents that decode
        // failure is reported before the image-id check runs).
        let too_short = vec![0u8; 4];
        let result = verifier().verify_receipt(&[], &too_short, &Hash256([0u8; 32]));
        assert!(
            result.is_err(),
            "wrong-length image id must fail closed, got {result:?}"
        );
    }

    #[test]
    fn wrong_length_image_id_is_rejected_independent_of_decode_error_message() {
        let too_long = vec![0u8; 64];
        let garbage_receipt = vec![0x00u8; 16];
        let result = verifier().verify_receipt(&garbage_receipt, &too_long, &Hash256([0u8; 32]));
        assert!(
            result.is_err(),
            "wrong-length image id combined with malformed receipt bytes must still fail \
             closed, got {result:?}"
        );
    }

    #[test]
    #[ignore = "needs a committed real-receipt fixture (follow-up, see module docs): \
                risc0-zkvm 3.0.5 ships no serialized Receipt/Groth16Receipt test vector \
                reachable without the excluded 'prove' feature, and this test must not \
                fake acceptance. Once a real, small, committable Groth16 receipt fixture \
                exists (generated out-of-band with the full prove stack and committed as \
                a binary fixture), this test should decode it, call verify_receipt with \
                its true image id and journal digest, and assert Ok(true)."]
    fn accepts_a_genuinely_valid_groth16_receipt() {
        unimplemented!("deferred: requires a committed real-receipt fixture; see #[ignore] reason")
    }
}
