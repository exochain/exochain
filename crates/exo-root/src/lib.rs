//! EXOCHAIN root genesis authority ceremony.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod bundle;
mod ceremony;
mod dkg;
mod error;
mod portal;
mod seal;
mod signing;

pub use bundle::{RootIssuerDelegation, RootTrustBundle, assemble_root_bundle, verify_root_bundle};
pub use ceremony::{
    CertifierContact, GenesisCeremonyConfig, ROOT_GENESIS_SIGNERS, ROOT_GENESIS_THRESHOLD,
};
pub use dkg::{
    RootDkgOutput, RootDkgRound1Output, RootDkgRound2Output, RootKeyPackage,
    RootParticipantDkgOutput, RootPublicKeyPackage, dkg_finalize_participant,
    dkg_finalize_participant_zeroizing, dkg_round1, dkg_round2, run_complete_dkg,
};
pub use error::{Result, RootError};
pub use portal::{
    CeremonyEnvelope, CeremonyEnvelopeDraft, CeremonyPayloadKind, CeremonyPhase,
    FINAL_KEY_CONFIRMATION_DOMAIN, FINAL_KEY_CONFIRMATION_SCHEMA_VERSION, FinalKeyConfirmation,
    PortalStore, build_final_key_confirmation, ceremony_config_hash,
    encode_final_key_confirmation_payload,
};
pub use seal::{
    PairwiseEncryptedPayload, SealedShare, decrypt_pairwise_payload, encrypt_pairwise_payload,
    seal_share, unseal_share,
};
pub use signing::{
    RootSignature, RootSignatureShareOutput, RootSigningCommitment, RootSigningNonces,
    RootSigningPackage, aggregate_signature, build_signing_package, sign_commit, sign_share,
    threshold_sign, verify_root_signature,
};
