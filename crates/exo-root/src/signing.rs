//! Threshold root signing helpers.

use std::collections::BTreeMap;

use frost_ristretto255 as frost;
use serde::{Deserialize, Serialize};

use crate::{
    GenesisCeremonyConfig, Result, RootError, RootKeyPackage, RootPublicKeyPackage,
    dkg::{deserialize_frost, serialize_frost},
};

/// Serialized threshold signature over a root artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSignature {
    /// Serialized FROST signature.
    pub signature: Vec<u8>,
    /// Signer identifiers used for this signature.
    pub signer_ids: Vec<u16>,
}

fn frost_error(error: frost::Error) -> RootError {
    RootError::Frost {
        detail: error.to_string(),
    }
}

fn frost_sign_share(
    signing_package: &frost::SigningPackage,
    nonces: &frost::round1::SigningNonces,
    key_package: &frost::keys::KeyPackage,
) -> Result<frost::round2::SignatureShare> {
    frost::round2::sign(signing_package, nonces, key_package).map_err(frost_error)
}

fn frost_aggregate_signature(
    signing_package: &frost::SigningPackage,
    signature_shares: &BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
    public: &frost::keys::PublicKeyPackage,
) -> Result<frost::Signature> {
    frost::aggregate(signing_package, signature_shares, public).map_err(frost_error)
}

/// Create a FROST threshold signature from at least seven rostered shares.
pub fn threshold_sign<R>(
    config: &GenesisCeremonyConfig,
    public_key_package: &RootPublicKeyPackage,
    shares: BTreeMap<u16, RootKeyPackage>,
    message: &[u8],
    rng: &mut R,
) -> Result<RootSignature>
where
    R: frost::rand_core::RngCore + frost::rand_core::CryptoRng,
{
    config.validate()?;
    if shares.len() < usize::from(config.threshold) {
        let supplied = shares
            .keys()
            .take(usize::from(u16::MAX))
            .fold(0u16, |count, _| count.saturating_add(1));
        let error = RootError::ThresholdNotMet {
            required: config.threshold,
            supplied,
        };
        return Err(error);
    }

    let public = deserialize_frost(public_key_package.public_key_package.as_slice())?;

    let mut key_packages = BTreeMap::new();
    let mut signing_nonces = BTreeMap::new();
    let mut signing_commitments = BTreeMap::new();
    let mut signer_ids = Vec::new();

    for (identifier, share) in shares {
        if config.certifier_by_identifier(identifier).is_none() {
            return Err(RootError::InvalidConfig {
                reason: format!("signer {identifier} is not rostered"),
            });
        }
        if share.frost_identifier != identifier {
            let share_id = share.frost_identifier;
            let detail = format!("share id {share_id} mismatches key {identifier}");
            return Err(RootError::Frost { detail });
        }
        let frost_identifier = crate::dkg::frost_identifier(identifier)?;
        let key_package: frost::keys::KeyPackage = deserialize_frost(share.key_package.as_slice())?;
        if *key_package.identifier() != frost_identifier {
            return Err(RootError::Frost {
                detail: "deserialized key package identifier mismatch".to_owned(),
            });
        }
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), rng);
        signing_nonces.insert(frost_identifier, nonces);
        signing_commitments.insert(frost_identifier, commitments);
        key_packages.insert(frost_identifier, key_package);
        signer_ids.push(identifier);
    }

    let signing_package = frost::SigningPackage::new(signing_commitments, message);
    let mut signature_shares = BTreeMap::new();
    for (identifier, key_package) in &key_packages {
        let nonces = &signing_nonces[identifier];
        let share = frost_sign_share(&signing_package, nonces, key_package)?;
        signature_shares.insert(*identifier, share);
    }

    let sig = frost_aggregate_signature(&signing_package, &signature_shares, &public)?;
    let signature = serialize_frost(&sig)?;

    verify_root_signature(&public_key_package.root_public_key, message, &signature)?;

    Ok(RootSignature {
        signature,
        signer_ids,
    })
}

/// Verify a serialized root threshold signature against a root public key.
pub fn verify_root_signature(
    root_public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let verifying_key: frost::VerifyingKey = deserialize_frost(root_public_key)?;
    let signature: frost::Signature = deserialize_frost(signature)?;
    verifying_key
        .verify(message, &signature)
        .map_err(signature_rejected)
}

fn signature_rejected(error: frost::Error) -> RootError {
    RootError::SignatureRejected {
        reason: error.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Distributed (online) threshold signing.
//
// `threshold_sign` above performs the whole protocol in one process and so
// requires every key package in one place. The functions below run the same
// FROST protocol as a two-round distributed exchange: each signer keeps its
// own `RootKeyPackage` and only ever emits PUBLIC commitments and signature
// shares. A coordinator (holding no secrets) assembles the signing package and
// aggregates the shares. These map onto the portal's `RootSigningCommitment`
// and `RootSignatureShare` payload kinds.
// ---------------------------------------------------------------------------

/// One signer's round-one signing material. `commitments` is public and is
/// broadcast; `nonces` is SECRET and must be retained locally until `sign_share`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSigningCommitment {
    /// Owner's FROST identifier.
    pub frost_identifier: u16,
    /// Serialized public signing commitments (broadcast to the coordinator).
    pub commitments: Vec<u8>,
    /// Serialized secret signing nonces (retained by the signer; never shared).
    pub nonces: Vec<u8>,
}

/// Public signing package built by the coordinator from `>= threshold`
/// commitments. Distributed to the participating signers for round two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSigningPackage {
    /// Serialized FROST signing package (binds the commitments and message).
    pub signing_package: Vec<u8>,
    /// Identifiers whose commitments are bound into this package.
    pub signer_ids: Vec<u16>,
}

/// One signer's round-two signature share. Public; reveals nothing about the
/// signer's secret key share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSignatureShareOutput {
    /// Owner's FROST identifier.
    pub frost_identifier: u16,
    /// Serialized FROST signature share.
    pub signature_share: Vec<u8>,
}

fn ensure_rostered(config: &GenesisCeremonyConfig, identifier: u16, role: &str) -> Result<()> {
    if config.certifier_by_identifier(identifier).is_none() {
        return Err(RootError::InvalidConfig {
            reason: format!("{role} {identifier} is not rostered"),
        });
    }
    Ok(())
}

/// Distributed signing — round one. Produce one signer's public commitments and
/// secret nonces. Run by each participating certifier against its own share.
pub fn sign_commit<R>(
    config: &GenesisCeremonyConfig,
    key_package: &RootKeyPackage,
    rng: &mut R,
) -> Result<RootSigningCommitment>
where
    R: frost::rand_core::RngCore + frost::rand_core::CryptoRng,
{
    config.validate()?;
    ensure_rostered(config, key_package.frost_identifier, "signer")?;
    let parsed: frost::keys::KeyPackage = deserialize_frost(key_package.key_package.as_slice())?;
    let (nonces, commitments) = frost::round1::commit(parsed.signing_share(), rng);
    Ok(RootSigningCommitment {
        frost_identifier: key_package.frost_identifier,
        commitments: serialize_frost(&commitments)?,
        nonces: serialize_frost(&nonces)?,
    })
}

/// Distributed signing — coordinator assembles the signing package from at
/// least `threshold` public commitments bound to `message` (the root artifact).
pub fn build_signing_package(
    config: &GenesisCeremonyConfig,
    commitments: BTreeMap<u16, Vec<u8>>,
    message: &[u8],
) -> Result<RootSigningPackage> {
    config.validate()?;
    if commitments.len() < usize::from(config.threshold) {
        return Err(RootError::ThresholdNotMet {
            required: config.threshold,
            supplied: u16::try_from(commitments.len()).unwrap_or(u16::MAX),
        });
    }
    let mut parsed = BTreeMap::new();
    let mut signer_ids = Vec::new();
    for (identifier, bytes) in commitments {
        ensure_rostered(config, identifier, "signer")?;
        let frost_id = crate::dkg::frost_identifier(identifier)?;
        let commitment: frost::round1::SigningCommitments = deserialize_frost(bytes.as_slice())?;
        parsed.insert(frost_id, commitment);
        signer_ids.push(identifier);
    }
    let signing_package = frost::SigningPackage::new(parsed, message);
    Ok(RootSigningPackage {
        signing_package: serialize_frost(&signing_package)?,
        signer_ids,
    })
}

/// Distributed signing — round two. One signer produces its signature share
/// from its key package, its retained nonces, and the coordinator's package.
pub fn sign_share(
    config: &GenesisCeremonyConfig,
    key_package: &RootKeyPackage,
    nonces: &[u8],
    signing_package: &[u8],
) -> Result<RootSignatureShareOutput> {
    config.validate()?;
    ensure_rostered(config, key_package.frost_identifier, "signer")?;
    let parsed_key: frost::keys::KeyPackage =
        deserialize_frost(key_package.key_package.as_slice())?;
    let parsed_nonces: frost::round1::SigningNonces = deserialize_frost(nonces)?;
    let parsed_package: frost::SigningPackage = deserialize_frost(signing_package)?;
    let share =
        frost::round2::sign(&parsed_package, &parsed_nonces, &parsed_key).map_err(frost_error)?;
    Ok(RootSignatureShareOutput {
        frost_identifier: key_package.frost_identifier,
        signature_share: serialize_frost(&share)?,
    })
}

/// Distributed signing — coordinator aggregates `>= threshold` signature shares
/// into the final root signature and verifies it against the root public key.
pub fn aggregate_signature(
    config: &GenesisCeremonyConfig,
    public_key_package: &RootPublicKeyPackage,
    signing_package: &[u8],
    shares: BTreeMap<u16, Vec<u8>>,
    message: &[u8],
) -> Result<RootSignature> {
    config.validate()?;
    if shares.len() < usize::from(config.threshold) {
        return Err(RootError::ThresholdNotMet {
            required: config.threshold,
            supplied: u16::try_from(shares.len()).unwrap_or(u16::MAX),
        });
    }
    let public = deserialize_frost(public_key_package.public_key_package.as_slice())?;
    let parsed_package: frost::SigningPackage = deserialize_frost(signing_package)?;
    let mut parsed_shares = BTreeMap::new();
    let mut signer_ids = Vec::new();
    for (identifier, bytes) in shares {
        ensure_rostered(config, identifier, "signer")?;
        let frost_id = crate::dkg::frost_identifier(identifier)?;
        let share: frost::round2::SignatureShare = deserialize_frost(bytes.as_slice())?;
        parsed_shares.insert(frost_id, share);
        signer_ids.push(identifier);
    }
    let aggregated =
        frost::aggregate(&parsed_package, &parsed_shares, &public).map_err(frost_error)?;
    let signature = serialize_frost(&aggregated)?;
    verify_root_signature(&public_key_package.root_public_key, message, &signature)?;
    Ok(RootSignature {
        signature,
        signer_ids,
    })
}

#[cfg(test)]
mod tests {
    use exo_core::{Did, Hash256, PublicKey, Timestamp};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::CertifierContact;

    fn test_config() -> GenesisCeremonyConfig {
        let certifiers = (1..=13)
            .map(|identifier| {
                let byte = u8::try_from(identifier).expect("identifier fits");
                CertifierContact {
                    did: Did::new(&format!("did:exo:signing-unit-{identifier:02}"))
                        .expect("valid did"),
                    frost_identifier: identifier,
                    signing_public_key: PublicKey::from_bytes([byte; 32]),
                    transport_public_key: [byte; 32],
                }
            })
            .collect();
        GenesisCeremonyConfig {
            ceremony_id: "unit-root".into(),
            network_id: "unit-net".into(),
            repo_commit: "d8927686a34bdc28ba36d53938f665685d2c4c04".into(),
            constitution_hash: Hash256::digest(b"constitution"),
            threshold: 7,
            max_signers: 13,
            created_at: Timestamp::new(1, 0),
            certifiers,
        }
    }

    #[test]
    fn frost_error_conversion_is_diagnostic() {
        let error = frost::Identifier::try_from(0).expect_err("zero identifier");
        let converted = frost_error(error);
        assert!(converted.to_string().contains("frost operation failed"));
    }

    #[test]
    fn signature_rejection_conversion_is_diagnostic() {
        let error = frost::Identifier::try_from(0).expect_err("zero identifier");
        let converted = signature_rejected(error);
        assert!(
            converted
                .to_string()
                .contains("signature verification failed")
        );
    }

    #[test]
    fn threshold_sign_rejects_too_few_shares_before_public_deserialization() {
        let config = test_config();
        let public_key_package = RootPublicKeyPackage {
            public_key_package: b"not a public package".to_vec(),
            root_public_key: b"not a verifying key".to_vec(),
            verifying_shares: BTreeMap::new(),
        };
        let mut rng = StdRng::seed_from_u64(7);
        let error = threshold_sign(
            &config,
            &public_key_package,
            BTreeMap::new(),
            b"root artifact",
            &mut rng,
        )
        .expect_err("empty signer set");
        assert_eq!(
            error,
            RootError::ThresholdNotMet {
                required: 7,
                supplied: 0
            }
        );
    }

    #[test]
    fn threshold_sign_covers_success_and_share_mismatch_paths() {
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(71);
        let dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");
        let selected: BTreeMap<u16, _> = dkg
            .key_packages
            .iter()
            .take(7)
            .map(|(identifier, share)| (*identifier, share.clone()))
            .collect();
        let message = b"unit root signing artifact";
        let signature = threshold_sign(
            &config,
            &dkg.public_key_package,
            selected.clone(),
            message,
            &mut rng,
        )
        .expect("signature");

        verify_root_signature(
            &dkg.public_key_package.root_public_key,
            message,
            &signature.signature,
        )
        .expect("signature verifies");

        let mut mismatched = selected;
        let mut share = mismatched.remove(&1).expect("share one");
        share.frost_identifier = 2;
        mismatched.insert(1, share);
        let error = threshold_sign(
            &config,
            &dkg.public_key_package,
            mismatched,
            message,
            &mut rng,
        )
        .expect_err("share identifier mismatch");
        assert!(error.to_string().contains("mismatches key 1"));
    }

    #[test]
    fn distributed_signing_matches_one_shot_and_verifies() {
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(99);
        let dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");
        let message = b"distributed root signing artifact";

        // Seven signers, each keeping its own key package.
        let signers: Vec<(u16, _)> = dkg
            .key_packages
            .iter()
            .take(7)
            .map(|(id, kp)| (*id, kp.clone()))
            .collect();

        // Round one: each signer commits locally; only commitments are shared.
        let mut commitments = BTreeMap::new();
        let mut nonces = BTreeMap::new();
        for (id, kp) in &signers {
            let commitment = sign_commit(&config, kp, &mut rng).expect("commit");
            nonces.insert(*id, commitment.nonces.clone());
            commitments.insert(*id, commitment.commitments.clone());
        }

        // Coordinator builds the signing package from the commitments.
        let package = build_signing_package(&config, commitments, message).expect("package");
        assert_eq!(package.signer_ids.len(), 7);

        // Round two: each signer produces its share from its own nonces.
        let mut shares = BTreeMap::new();
        for (id, kp) in &signers {
            let share =
                sign_share(&config, kp, &nonces[id], &package.signing_package).expect("share");
            shares.insert(*id, share.signature_share);
        }

        // Coordinator aggregates; result verifies against the root key and
        // matches the threshold the one-shot path would accept.
        let signature = aggregate_signature(
            &config,
            &dkg.public_key_package,
            &package.signing_package,
            shares,
            message,
        )
        .expect("aggregate");
        verify_root_signature(
            &dkg.public_key_package.root_public_key,
            message,
            &signature.signature,
        )
        .expect("distributed signature verifies");
        assert_eq!(signature.signer_ids.len(), 7);
    }

    #[test]
    fn build_signing_package_rejects_sub_threshold_commitment_set() {
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(100);
        let dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");
        let mut commitments = BTreeMap::new();
        for (id, kp) in dkg.key_packages.iter().take(3) {
            let commitment = sign_commit(&config, kp, &mut rng).expect("commit");
            commitments.insert(*id, commitment.commitments);
        }
        let error = build_signing_package(&config, commitments, b"msg")
            .expect_err("sub-threshold commitments");
        assert!(matches!(
            error,
            RootError::ThresholdNotMet {
                required: 7,
                supplied: 3
            }
        ));
    }

    #[test]
    fn distributed_signing_rejects_unrostered_and_sub_threshold() {
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(123);
        let dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");

        // sign_commit rejects an unrostered key package.
        let mut stranger = dkg.key_packages[&1].clone();
        stranger.frost_identifier = 99;
        assert!(matches!(
            sign_commit(&config, &stranger, &mut rng).expect_err("unrostered commit"),
            RootError::InvalidConfig { .. }
        ));

        // build_signing_package rejects a commitment from an unrostered signer.
        let mut commitments = BTreeMap::new();
        for (id, kp) in dkg.key_packages.iter().take(7) {
            commitments.insert(*id, sign_commit(&config, kp, &mut rng).expect("commit").commitments);
        }
        let mut unrostered = commitments.clone();
        let stolen = unrostered.remove(&1).expect("commitment one");
        unrostered.insert(99, stolen);
        assert!(matches!(
            build_signing_package(&config, unrostered, b"msg").expect_err("unrostered commitment"),
            RootError::InvalidConfig { .. }
        ));

        // sign_share rejects an unrostered key package.
        let package = build_signing_package(&config, commitments, b"msg").expect("package");
        let commit = sign_commit(&config, &dkg.key_packages[&1], &mut rng).expect("commit");
        assert!(matches!(
            sign_share(&config, &stranger, &commit.nonces, &package.signing_package)
                .expect_err("unrostered share"),
            RootError::InvalidConfig { .. }
        ));

        // aggregate_signature enforces the threshold and rosters every share.
        assert!(matches!(
            aggregate_signature(
                &config,
                &dkg.public_key_package,
                &package.signing_package,
                BTreeMap::new(),
                b"msg",
            )
            .expect_err("sub-threshold aggregate"),
            RootError::ThresholdNotMet { required: 7, .. }
        ));
    }
}
