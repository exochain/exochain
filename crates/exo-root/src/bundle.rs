//! Root trust bundle assembly and verification.

use std::fmt::Display;

use exo_authority::permission::Permission;
use exo_core::{Did, Hash256, PublicKey, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{
    GenesisCeremonyConfig, Result, RootError, RootPublicKeyPackage,
    dkg::validate_public_key_package,
    signing::{RootSignature, validate_root_signer_ids},
    verify_root_signature,
};

/// Operational AVC issuer authority delegated by the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootIssuerDelegation {
    /// Operational issuer DID.
    pub issuer_did: Did,
    /// Operational issuer public key.
    pub issuer_public_key: PublicKey,
    /// Permissions granted by the root authority.
    pub granted_permissions: Vec<Permission>,
    /// HLC activation timestamp.
    pub effective_at: Timestamp,
    /// Optional HLC expiry timestamp.
    pub expires_at: Option<Timestamp>,
    /// Human-readable bounded purpose.
    pub purpose: String,
}

/// Root trust bundle produced by genesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootTrustBundle {
    /// Ceremony configuration.
    pub config: GenesisCeremonyConfig,
    /// Public FROST package and root key.
    pub public_key_package: RootPublicKeyPackage,
    /// Root-signed AVC issuer delegation.
    pub issuer_delegation: RootIssuerDelegation,
    /// Canonical transcript hash.
    pub transcript_hash: Hash256,
    /// Root threshold signature over the trust artifact payload.
    pub root_signature: RootSignature,
    /// Canonical bundle content identifier.
    pub bundle_id: Hash256,
}

#[derive(Serialize)]
struct RootArtifactPayload<'a> {
    domain: &'static str,
    config_hash: Hash256,
    public_key_package_hash: Hash256,
    transcript_hash: Hash256,
    issuer_delegation_hash: Hash256,
    issuer_did: &'a Did,
    signer_ids: &'a [u16],
}

#[derive(Serialize)]
struct RootBundleIdPayload<'a> {
    domain: &'static str,
    artifact_payload_hash: Hash256,
    root_signature: &'a RootSignature,
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(canonical_encoding_error)?;
    Ok(bytes)
}

fn structured_hash<T: Serialize>(value: &T) -> Result<Hash256> {
    hash_structured(value).map_err(canonical_encoding_error)
}

fn canonical_encoding_error(error: impl Display) -> RootError {
    RootError::CanonicalEncoding {
        detail: error.to_string(),
    }
}

impl RootIssuerDelegation {
    /// Canonical payload signed by the root threshold authority for the
    /// predeclared deterministic signing set.
    pub fn root_artifact_payload(
        &self,
        config: &GenesisCeremonyConfig,
        public_key_package: &RootPublicKeyPackage,
        transcript_hash: Hash256,
    ) -> Result<Vec<u8>> {
        self.root_artifact_payload_for_signers(
            config,
            public_key_package,
            transcript_hash,
            config.signing_set.as_slice(),
        )
    }

    /// Canonical payload signed by the root threshold authority for the exact
    /// signer metadata carried by a root signature.
    pub fn root_artifact_payload_for_signers(
        &self,
        config: &GenesisCeremonyConfig,
        public_key_package: &RootPublicKeyPackage,
        transcript_hash: Hash256,
        signer_ids: &[u16],
    ) -> Result<Vec<u8>> {
        config.validate()?;
        validate_root_signer_ids(config, signer_ids)?;
        if self.purpose.trim().is_empty() {
            return Err(RootError::BundleRejected {
                reason: "issuer delegation purpose must not be empty".to_owned(),
            });
        }
        if self.granted_permissions.is_empty() {
            return Err(RootError::BundleRejected {
                reason: "issuer delegation must grant at least one permission".to_owned(),
            });
        }
        let payload = RootArtifactPayload {
            domain: "EXOCHAIN_ROOT_ARTIFACT_V1",
            config_hash: structured_hash(config)?,
            public_key_package_hash: structured_hash(public_key_package)?,
            transcript_hash,
            issuer_delegation_hash: structured_hash(self)?,
            issuer_did: &self.issuer_did,
            signer_ids,
        };
        canonical_bytes(&payload)
    }
}

fn bundle_id(
    delegation: &RootIssuerDelegation,
    config: &GenesisCeremonyConfig,
    public_key_package: &RootPublicKeyPackage,
    transcript_hash: Hash256,
    root_signature: &RootSignature,
) -> Result<Hash256> {
    let artifact_payload = delegation.root_artifact_payload_for_signers(
        config,
        public_key_package,
        transcript_hash,
        root_signature.signer_ids.as_slice(),
    )?;
    let id_payload = RootBundleIdPayload {
        domain: "EXOCHAIN_ROOT_BUNDLE_V1",
        artifact_payload_hash: Hash256::digest(&artifact_payload),
        root_signature,
    };
    structured_hash(&id_payload)
}

/// Assemble and verify a root trust bundle.
pub fn assemble_root_bundle(
    config: GenesisCeremonyConfig,
    public_key_package: RootPublicKeyPackage,
    issuer_delegation: RootIssuerDelegation,
    transcript_hash: Hash256,
    root_signature: RootSignature,
) -> Result<RootTrustBundle> {
    validate_public_key_package(&config, &public_key_package)?;
    validate_root_signer_ids(&config, root_signature.signer_ids.as_slice())?;
    let payload = issuer_delegation.root_artifact_payload_for_signers(
        &config,
        &public_key_package,
        transcript_hash,
        root_signature.signer_ids.as_slice(),
    )?;
    verify_root_signature(
        &public_key_package.root_public_key,
        &payload,
        root_signature.signature.as_slice(),
    )?;
    let bundle_id = bundle_id(
        &issuer_delegation,
        &config,
        &public_key_package,
        transcript_hash,
        &root_signature,
    )?;
    Ok(RootTrustBundle {
        config,
        public_key_package,
        issuer_delegation,
        transcript_hash,
        root_signature,
        bundle_id,
    })
}

/// Verify that a root trust bundle is self-consistent and root-signed.
pub fn verify_root_bundle(bundle: &RootTrustBundle) -> Result<()> {
    bundle.config.validate()?;
    validate_public_key_package(&bundle.config, &bundle.public_key_package)?;
    validate_root_signer_ids(&bundle.config, bundle.root_signature.signer_ids.as_slice())?;
    let payload = bundle.issuer_delegation.root_artifact_payload_for_signers(
        &bundle.config,
        &bundle.public_key_package,
        bundle.transcript_hash,
        bundle.root_signature.signer_ids.as_slice(),
    )?;
    verify_root_signature(
        &bundle.public_key_package.root_public_key,
        &payload,
        bundle.root_signature.signature.as_slice(),
    )?;
    let expected_id = bundle_id(
        &bundle.issuer_delegation,
        &bundle.config,
        &bundle.public_key_package,
        bundle.transcript_hash,
        &bundle.root_signature,
    )?;
    if expected_id != bundle.bundle_id {
        return Err(RootError::BundleRejected {
            reason: "bundle identifier does not match contents".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use exo_core::{Did, PublicKey};
    use frost_ristretto255 as frost;
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::{
        CertifierContact, RootKeyPackage,
        dkg::{deserialize_frost, serialize_frost},
        run_complete_dkg,
    };

    #[derive(Serialize)]
    struct LegacyRootArtifactPayload<'a> {
        domain: &'static str,
        config_hash: Hash256,
        public_key_package_hash: Hash256,
        transcript_hash: Hash256,
        issuer_delegation_hash: Hash256,
        issuer_did: &'a Did,
    }

    fn test_config() -> GenesisCeremonyConfig {
        let certifiers = (1..=13)
            .map(|identifier| {
                let byte = u8::try_from(identifier).expect("identifier fits");
                CertifierContact {
                    did: Did::new(&format!("did:exo:bundle-unit-{identifier:02}"))
                        .expect("valid did"),
                    frost_identifier: identifier,
                    signing_public_key: PublicKey::from_bytes([byte; 32]),
                    transport_public_key: [byte; 32],
                }
            })
            .collect();
        GenesisCeremonyConfig {
            ceremony_id: "bundle-root".into(),
            network_id: "unit-net".into(),
            repo_commit: "d8927686a34bdc28ba36d53938f665685d2c4c04".into(),
            constitution_hash: Hash256::digest(b"constitution"),
            threshold: 7,
            max_signers: 13,
            created_at: Timestamp::new(1, 0),
            certifiers,
            signing_set: (1..=7).collect(),
        }
    }

    fn issuer_delegation() -> RootIssuerDelegation {
        RootIssuerDelegation {
            issuer_did: Did::new("did:exo:bundle-avc-issuer").expect("valid did"),
            issuer_public_key: PublicKey::from_bytes([0x44; 32]),
            granted_permissions: vec![Permission::Govern, Permission::Delegate],
            effective_at: Timestamp::new(1_785_000_010_000, 0),
            expires_at: None,
            purpose: "Delegate operational AVC issuing authority".into(),
        }
    }

    fn legacy_unbound_root_artifact_payload(
        delegation: &RootIssuerDelegation,
        config: &GenesisCeremonyConfig,
        public_key_package: &RootPublicKeyPackage,
        transcript_hash: Hash256,
    ) -> Result<Vec<u8>> {
        let payload = LegacyRootArtifactPayload {
            domain: "EXOCHAIN_ROOT_ARTIFACT_V1",
            config_hash: structured_hash(config)?,
            public_key_package_hash: structured_hash(public_key_package)?,
            transcript_hash,
            issuer_delegation_hash: structured_hash(delegation)?,
            issuer_did: &delegation.issuer_did,
        };
        canonical_bytes(&payload)
    }

    fn raw_threshold_signature_without_signer_policy<R>(
        public_key_package: &RootPublicKeyPackage,
        shares: BTreeMap<u16, RootKeyPackage>,
        message: &[u8],
        rng: &mut R,
    ) -> RootSignature
    where
        R: frost::rand_core::RngCore + frost::rand_core::CryptoRng,
    {
        let public: frost::keys::PublicKeyPackage =
            deserialize_frost(public_key_package.public_key_package.as_slice())
                .expect("public key package");
        let mut key_packages = BTreeMap::new();
        let mut signing_nonces = BTreeMap::new();
        let mut signing_commitments = BTreeMap::new();

        for (identifier, share) in &shares {
            let frost_identifier = frost::Identifier::try_from(*identifier).expect("frost id");
            let key_package: frost::keys::KeyPackage =
                deserialize_frost(share.key_package.as_slice()).expect("key package");
            let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), rng);
            signing_nonces.insert(frost_identifier, nonces);
            signing_commitments.insert(frost_identifier, commitments);
            key_packages.insert(frost_identifier, key_package);
        }

        let signing_package = frost::SigningPackage::new(signing_commitments, message);
        let mut signature_shares = BTreeMap::new();
        for (identifier, key_package) in &key_packages {
            let share =
                frost::round2::sign(&signing_package, &signing_nonces[identifier], key_package)
                    .expect("signature share");
            signature_shares.insert(*identifier, share);
        }
        let aggregate =
            frost::aggregate(&signing_package, &signature_shares, &public).expect("aggregate");
        let signer_ids = shares.keys().copied().collect();
        RootSignature {
            signature: serialize_frost(&aggregate).expect("signature encoding"),
            signer_ids,
        }
    }

    #[test]
    fn canonical_error_conversion_is_diagnostic() {
        let error = canonical_encoding_error("encoder failed");
        assert!(error.to_string().contains("encoder failed"));
    }

    #[test]
    fn root_bundle_rejects_relabelled_signature_when_signer_metadata_was_unsigned() {
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(700);
        let mut dkg = run_complete_dkg(&config, &mut rng).expect("dkg");
        let delegation = issuer_delegation();
        let transcript_hash = Hash256::digest(b"transcript");
        let legacy_payload = legacy_unbound_root_artifact_payload(
            &delegation,
            &config,
            &dkg.public_key_package,
            transcript_hash,
        )
        .expect("legacy payload");
        let actual_signers = [1, 2, 3, 4, 5, 6, 8]
            .into_iter()
            .map(|identifier| {
                let package = dkg.key_packages.remove(&identifier).expect("key package");
                (identifier, package)
            })
            .collect();
        let mut root_signature = raw_threshold_signature_without_signer_policy(
            &dkg.public_key_package,
            actual_signers,
            &legacy_payload,
            &mut rng,
        );
        assert_eq!(root_signature.signer_ids, vec![1, 2, 3, 4, 5, 6, 8]);

        root_signature.signer_ids = config.signing_set.clone();

        assert!(
            assemble_root_bundle(
                config,
                dkg.public_key_package,
                delegation,
                transcript_hash,
                root_signature,
            )
            .is_err(),
            "bundle assembly must reject a threshold signature whose claimed signer metadata was not covered by the signed artifact"
        );
    }
}
