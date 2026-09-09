//! Threshold root signing helpers.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use exo_core::Hash256;
use frost_ristretto255 as frost;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    GenesisCeremonyConfig, Result, RootError, RootKeyPackage, RootPublicKeyPackage,
    dkg::{
        deserialize_frost, deserialize_zeroizing_bytes, serialize_frost, serialize_frost_secret,
    },
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

/// Create a FROST threshold signature from the exact predeclared signing set.
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
    let shares = shares
        .into_iter()
        .map(|(identifier, share)| (identifier, Zeroizing::new(share)))
        .collect();
    threshold_sign_zeroizing(config, public_key_package, shares, message, rng)
}

/// Sign from already guarded private key packages, retaining drop cleanup on
/// every validation or signing error and after successful signing.
///
/// Private ceremony tooling should deserialize map values into [`Zeroizing`]
/// before calling this entry point. The legacy [`threshold_sign`] entry point
/// keeps its caller-owned map signature and guards all shares before delegating.
pub fn threshold_sign_zeroizing<R>(
    config: &GenesisCeremonyConfig,
    public_key_package: &RootPublicKeyPackage,
    shares: BTreeMap<u16, Zeroizing<RootKeyPackage>>,
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
    let signer_ids: Vec<u16> = shares.keys().copied().collect();
    validate_root_signer_ids(config, signer_ids.as_slice())?;

    let public = deserialize_frost(public_key_package.public_key_package.as_slice())?;

    let mut key_packages = BTreeMap::new();
    let mut signing_nonces = BTreeMap::new();
    let mut signing_commitments = BTreeMap::new();

    for (identifier, share) in shares {
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

/// One signer's round-one PUBLIC commitment. Relay-safe: carries no secret
/// material and is the only round-one artifact broadcast to the coordinator.
/// Kept deliberately separate from [`RootSigningNonces`] so the secret nonces
/// can never be co-serialized with, or mistaken for, relay-safe data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSigningCommitment {
    /// Owner's FROST identifier.
    pub frost_identifier: u16,
    /// Serialized public signing commitments (broadcast to the coordinator).
    pub commitments: Vec<u8>,
}

/// One signer's round-one SECRET signing nonces. **LOCAL-ONLY** — this artifact
/// must never be broadcast, archived off the signer, copied to the coordinator,
/// or submitted through the portal. In FROST, disclosure of these nonces
/// together with the signer's later signature share can compromise the signer's
/// secret key share. It derives `Serialize`/`Deserialize` only so a signer can
/// persist it to a `0600` local file between `sign_commit` and `sign_share`; the
/// distinct type name keeps it from being confused with relay-safe data.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSigningNonces {
    /// Owner's FROST identifier.
    pub frost_identifier: u16,
    /// Ceremony these nonces were generated for; `sign_share` rejects reuse in a
    /// different ceremony.
    pub ceremony_id: String,
    /// blake3 of the exact root artifact (message) these nonces commit to.
    /// `sign_share` requires the message it signs to hash to this value, so a
    /// given nonce set can only ever sign its one bound artifact — this is what
    /// prevents a coordinator from getting the same nonces to sign two different
    /// messages (FROST nonce reuse exposes the signer's key share).
    pub artifact_hash: Hash256,
    /// blake3 of the public commitment these nonces pair with. `sign_share`
    /// requires this to equal the hash of the commitment bound for this signer in
    /// the signing package.
    pub commitment_hash: Hash256,
    /// Serialized secret signing nonces (retained by the signer; never shared).
    #[serde(deserialize_with = "deserialize_zeroizing_bytes")]
    pub nonces: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for RootSigningNonces {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootSigningNonces")
            .field("frost_identifier", &self.frost_identifier)
            .field("ceremony_id", &self.ceremony_id)
            .field("artifact_hash", &self.artifact_hash)
            .field("commitment_hash", &self.commitment_hash)
            .field("nonces", &"[REDACTED]")
            .finish()
    }
}

/// blake3 of a signer's serialized public commitment, used to bind nonces to the
/// signing instance.
fn commitment_hash(commitment_bytes: &[u8]) -> Hash256 {
    Hash256::digest(commitment_bytes)
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

pub(crate) fn validate_root_signer_ids(
    config: &GenesisCeremonyConfig,
    signer_ids: &[u16],
) -> Result<()> {
    if signer_ids.len() != usize::from(config.threshold) {
        return Err(RootError::InvalidConfig {
            reason: format!(
                "signing selection must contain exactly {} signers",
                config.threshold
            ),
        });
    }
    let mut selection = BTreeSet::new();
    for identifier in signer_ids {
        if config.certifier_by_identifier(*identifier).is_none() {
            return Err(RootError::InvalidConfig {
                reason: format!("signer {identifier} is not rostered"),
            });
        }
        if !selection.insert(*identifier) {
            return Err(RootError::InvalidConfig {
                reason: format!("duplicate signer {identifier}"),
            });
        }
    }
    config.validate_signing_selection(&selection)
}

/// Distributed signing — round one. Produce one signer's PUBLIC commitment and
/// SECRET nonces as two distinct artifacts, **bound to the exact root `artifact`
/// being signed**. Run by each participating certifier against its own share.
/// The caller MUST broadcast only the [`RootSigningCommitment`] and retain the
/// [`RootSigningNonces`] locally (never share, archive off-host, or submit it)
/// until [`sign_share`]. The artifact must be the bytes emitted by
/// `root_artifact_payload` and is known before commitments are produced.
pub fn sign_commit<R>(
    config: &GenesisCeremonyConfig,
    key_package: &RootKeyPackage,
    artifact: &[u8],
    rng: &mut R,
) -> Result<(RootSigningCommitment, RootSigningNonces)>
where
    R: frost::rand_core::RngCore + frost::rand_core::CryptoRng,
{
    config.validate()?;
    ensure_rostered(config, key_package.frost_identifier, "signer")?;
    let parsed: frost::keys::KeyPackage = deserialize_frost(key_package.key_package.as_slice())?;
    let (nonces, commitments) = frost::round1::commit(parsed.signing_share(), rng);
    let commitment_bytes = serialize_frost(&commitments)?;
    let commitment = RootSigningCommitment {
        frost_identifier: key_package.frost_identifier,
        commitments: commitment_bytes.clone(),
    };
    let signing_nonces = RootSigningNonces {
        frost_identifier: key_package.frost_identifier,
        ceremony_id: config.ceremony_id.clone(),
        artifact_hash: Hash256::digest(artifact),
        commitment_hash: commitment_hash(commitment_bytes.as_slice()),
        nonces: serialize_frost_secret(&nonces)?,
    };
    Ok((commitment, signing_nonces))
}

/// Distributed signing — coordinator assembles the signing package from at
/// the exact predeclared public commitments bound to `message` (the root artifact).
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
    // The participating signers must be exactly the predeclared signing set. Any
    // unavailability aborts the ceremony before commitments and requires a new
    // config/ceremony id.
    let signer_ids: Vec<u16> = commitments.keys().copied().collect();
    validate_root_signer_ids(config, signer_ids.as_slice())?;
    let mut parsed = BTreeMap::new();
    for (identifier, bytes) in commitments {
        ensure_rostered(config, identifier, "signer")?;
        let frost_id = crate::dkg::frost_identifier(identifier)?;
        let commitment: frost::round1::SigningCommitments = deserialize_frost(bytes.as_slice())?;
        parsed.insert(frost_id, commitment);
    }
    let signing_package = frost::SigningPackage::new(parsed, message);
    Ok(RootSigningPackage {
        signing_package: serialize_frost(&signing_package)?,
        signer_ids,
    })
}

/// Distributed signing — round two. One signer produces its signature share from
/// its key package, its retained local-only [`RootSigningNonces`], the
/// coordinator's [`RootSigningPackage`], and the `message` (root artifact) it
/// intends to sign.
///
/// The share is produced over a signing package **rebuilt from the supplied
/// commitments and the caller's `message`**, never over a coordinator-controlled
/// message. Combined with the nonce's `artifact_hash` binding, this means a given
/// nonce set can only ever sign the one artifact it committed to: a coordinator
/// cannot present two packages built from the same commitments but different
/// messages to obtain two shares under one nonce (which would expose the signer's
/// key share). The caller must additionally retire the nonces after one share.
pub fn sign_share(
    config: &GenesisCeremonyConfig,
    key_package: &RootKeyPackage,
    nonces: &RootSigningNonces,
    signing_package: &RootSigningPackage,
    message: &[u8],
) -> Result<RootSignatureShareOutput> {
    config.validate()?;
    ensure_rostered(config, key_package.frost_identifier, "signer")?;
    if nonces.frost_identifier != key_package.frost_identifier {
        let nonce_id = nonces.frost_identifier;
        let key_id = key_package.frost_identifier;
        return Err(RootError::Frost {
            detail: format!("nonces id {nonce_id} mismatches key {key_id}"),
        });
    }
    if nonces.ceremony_id != config.ceremony_id {
        return Err(RootError::Frost {
            detail: "nonces were generated for a different ceremony".to_owned(),
        });
    }
    // Bind the nonces to the exact artifact being signed. A nonce committed to one
    // artifact can never be used to sign a different message.
    if Hash256::digest(message) != nonces.artifact_hash {
        return Err(RootError::Frost {
            detail: "nonces are bound to a different artifact than the message".to_owned(),
        });
    }
    // Enforce the ratified deterministic signer-selection policy signer-side too:
    // a signer must refuse a signing package whose signer set is not exactly the
    // predeclared set, even when a coordinator builds the package outside
    // `build_signing_package`.
    validate_root_signer_ids(config, signing_package.signer_ids.as_slice())?;
    let parsed_key: frost::keys::KeyPackage =
        deserialize_frost(key_package.key_package.as_slice())?;
    let parsed_nonces: frost::round1::SigningNonces = deserialize_frost(nonces.nonces.as_slice())?;
    let parsed_package: frost::SigningPackage =
        deserialize_frost(signing_package.signing_package.as_slice())?;
    // Rebuild the signing package from the supplied commitments and the caller's
    // message, so the share is provably over `message` regardless of what message
    // the coordinator embedded in the distributed package.
    let mut commitments = BTreeMap::new();
    for identifier in &signing_package.signer_ids {
        let signer_frost_id = crate::dkg::frost_identifier(*identifier)?;
        let commitment = parsed_package
            .signing_commitment(&signer_frost_id)
            .ok_or_else(|| RootError::Frost {
                detail: format!("signing package is missing commitment for signer {identifier}"),
            })?;
        commitments.insert(signer_frost_id, commitment);
    }
    // The nonces must pair with this signer's commitment in the bound set.
    let frost_id = crate::dkg::frost_identifier(key_package.frost_identifier)?;
    let package_commitment = commitments.get(&frost_id).ok_or_else(|| RootError::Frost {
        detail: "signer is not in the signing package's signer set".to_owned(),
    })?;
    if commitment_hash(serialize_frost(package_commitment)?.as_slice()) != nonces.commitment_hash {
        return Err(RootError::Frost {
            detail: "nonces are not bound to this signing package's commitment".to_owned(),
        });
    }
    let rebuilt_package = frost::SigningPackage::new(commitments, message);
    let share =
        frost::round2::sign(&rebuilt_package, &parsed_nonces, &parsed_key).map_err(frost_error)?;
    Ok(RootSignatureShareOutput {
        frost_identifier: key_package.frost_identifier,
        signature_share: serialize_frost(&share)?,
    })
}

/// Distributed signing — coordinator aggregates the exact predeclared signature
/// shares into the final root signature and verifies it against the root public key.
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
    let signer_ids: Vec<u16> = shares.keys().copied().collect();
    validate_root_signer_ids(config, signer_ids.as_slice())?;
    let public = deserialize_frost(public_key_package.public_key_package.as_slice())?;
    let parsed_package: frost::SigningPackage = deserialize_frost(signing_package)?;
    let mut parsed_shares = BTreeMap::new();
    for (identifier, bytes) in shares {
        ensure_rostered(config, identifier, "signer")?;
        let frost_id = crate::dkg::frost_identifier(identifier)?;
        let share: frost::round2::SignatureShare = deserialize_frost(bytes.as_slice())?;
        parsed_shares.insert(frost_id, share);
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
    use serde::Serialize;

    use super::*;
    use crate::CertifierContact;

    #[derive(Serialize)]
    struct LegacySigningNonces<'a> {
        frost_identifier: u16,
        ceremony_id: &'a String,
        artifact_hash: Hash256,
        commitment_hash: Hash256,
        nonces: &'a Vec<u8>,
    }

    fn cbor_bytes(value: &impl Serialize) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).expect("CBOR encoding");
        bytes
    }

    fn assert_zeroizing_carrier<T: zeroize::Zeroize + zeroize::ZeroizeOnDrop>(_: &T) {}

    #[test]
    fn secret_signing_nonce_bytes_zeroize_on_drop() {
        let nonces = RootSigningNonces {
            frost_identifier: 7,
            ceremony_id: "root-secret-zeroize-v1".to_owned(),
            artifact_hash: Hash256::digest(b"artifact"),
            commitment_hash: Hash256::digest(b"commitment"),
            nonces: Zeroizing::new(vec![0xde, 0xad, 0xfa, 0xce]),
        };

        assert_zeroizing_carrier(&nonces.nonces);
    }

    #[test]
    fn secret_signing_nonce_debug_is_redacted_and_wire_compatible() {
        let secret = vec![0xde, 0xad, 0xfa, 0xce];
        let ceremony_id = "root-secret-wire-v1".to_owned();
        let artifact_hash = Hash256::digest(b"artifact");
        let commitment_hash = Hash256::digest(b"commitment");
        let nonces = RootSigningNonces {
            frost_identifier: 7,
            ceremony_id: ceremony_id.clone(),
            artifact_hash,
            commitment_hash,
            nonces: Zeroizing::new(secret.clone()),
        };
        let rendered = format!("{nonces:?}");
        assert!(
            rendered.contains("[REDACTED]"),
            "signing nonce debug output must visibly redact: {rendered}"
        );
        assert!(
            !rendered.contains(&format!("{secret:?}")),
            "signing nonce debug output exposed fixture bytes: {rendered}"
        );

        let legacy = LegacySigningNonces {
            frost_identifier: 7,
            ceremony_id: &ceremony_id,
            artifact_hash,
            commitment_hash,
            nonces: &secret,
        };
        assert_eq!(
            serde_json::to_vec(&nonces).expect("nonce JSON"),
            serde_json::to_vec(&legacy).expect("legacy nonce JSON")
        );
        assert_eq!(cbor_bytes(&nonces), cbor_bytes(&legacy));
    }

    #[test]
    fn secret_signing_nonce_deserializer_rejects_partial_json_and_cbor() {
        let malformed = serde_json::json!({
            "frost_identifier": 7,
            "ceremony_id": "root-secret-malformed-v1",
            "artifact_hash": Hash256::digest(b"artifact"),
            "commitment_hash": Hash256::digest(b"commitment"),
            "nonces": [1, 2, "bad"]
        });
        let json = serde_json::to_vec(&malformed).expect("malformed JSON fixture");
        assert!(serde_json::from_slice::<RootSigningNonces>(&json).is_err());
        let encoded = cbor_bytes(&malformed);
        assert!(ciborium::from_reader::<RootSigningNonces, _>(encoded.as_slice()).is_err());
    }

    #[test]
    fn public_signing_artifacts_keep_debug_and_wire_round_trips() {
        let commitment = RootSigningCommitment {
            frost_identifier: 7,
            commitments: vec![1, 2, 3, 4],
        };
        let share = RootSignatureShareOutput {
            frost_identifier: 7,
            signature_share: vec![5, 6, 7, 8],
        };
        let commitment_json = serde_json::to_vec(&commitment).expect("commitment JSON");
        let share_json = serde_json::to_vec(&share).expect("share JSON");
        assert!(format!("{commitment:?}").contains("commitments"));
        assert!(format!("{share:?}").contains("signature_share"));
        assert_eq!(
            serde_json::from_slice::<RootSigningCommitment>(&commitment_json)
                .expect("commitment JSON round trip"),
            commitment
        );
        assert_eq!(
            serde_json::from_slice::<RootSignatureShareOutput>(&share_json)
                .expect("share JSON round trip"),
            share
        );
        assert_eq!(
            ciborium::from_reader::<RootSigningCommitment, _>(cbor_bytes(&commitment).as_slice())
                .expect("commitment CBOR round trip"),
            commitment
        );
        assert_eq!(
            ciborium::from_reader::<RootSignatureShareOutput, _>(cbor_bytes(&share).as_slice())
                .expect("share CBOR round trip"),
            share
        );
    }

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
            signing_set: (1..=7).collect(),
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
    fn signer_id_validation_rejects_wrong_count_and_duplicates() {
        let config = test_config();
        let wrong_count = validate_root_signer_ids(&config, &[1, 2, 3, 4, 5, 6])
            .expect_err("signer set must match threshold count");
        assert!(wrong_count.to_string().contains("exactly 7 signers"));

        let duplicate = validate_root_signer_ids(&config, &[1, 2, 3, 4, 5, 6, 6])
            .expect_err("signer set must reject duplicates");
        assert!(duplicate.to_string().contains("duplicate signer 6"));
    }

    #[test]
    fn threshold_sign_covers_success_and_share_mismatch_paths() {
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(71);
        let mut dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");
        let selected: BTreeMap<u16, _> = (1..=7)
            .map(|identifier| {
                let share = dkg.key_packages.remove(&identifier).expect("key package");
                (identifier, share)
            })
            .collect();
        let message = b"unit root signing artifact";
        let guarded = selected
            .clone()
            .into_iter()
            .map(|(identifier, share)| (identifier, Zeroizing::new(share)))
            .collect();
        let mut guarded_rng = rng.clone();
        let signature = threshold_sign(
            &config,
            &dkg.public_key_package,
            selected,
            message,
            &mut rng,
        )
        .expect("signature");
        let guarded_signature = threshold_sign_zeroizing(
            &config,
            &dkg.public_key_package,
            guarded,
            message,
            &mut guarded_rng,
        )
        .expect("guarded signature");
        assert_eq!(
            guarded_signature, signature,
            "guarded entrypoint preserves exact signature"
        );

        verify_root_signature(
            &dkg.public_key_package.root_public_key,
            message,
            &signature.signature,
        )
        .expect("signature verifies");

        let mut second_rng = StdRng::seed_from_u64(71);
        let mut second_dkg = crate::run_complete_dkg(&config, &mut second_rng).expect("second dkg");
        let mut mismatched: BTreeMap<u16, _> = (1..=7)
            .map(|identifier| {
                let share = second_dkg
                    .key_packages
                    .remove(&identifier)
                    .expect("key package");
                (identifier, share)
            })
            .collect();
        let mut share = mismatched.remove(&1).expect("share one");
        share.frost_identifier = 2;
        mismatched.insert(1, share);
        let error = threshold_sign(
            &config,
            &second_dkg.public_key_package,
            mismatched,
            message,
            &mut rng,
        )
        .expect_err("share identifier mismatch");
        assert!(error.to_string().contains("mismatches key 1"));
    }

    #[test]
    fn threshold_sign_rejects_non_declared_signer_set_before_public_deserialization() {
        let config = test_config();
        let public_key_package = RootPublicKeyPackage {
            public_key_package: b"not a public package".to_vec(),
            root_public_key: b"not a verifying key".to_vec(),
            verifying_shares: BTreeMap::new(),
        };
        let shares = [1, 2, 3, 4, 5, 6, 9]
            .into_iter()
            .map(|identifier| {
                (
                    identifier,
                    RootKeyPackage {
                        frost_identifier: identifier,
                        key_package: Vec::new(),
                    },
                )
            })
            .collect();
        let mut rng = StdRng::seed_from_u64(72);
        let error = threshold_sign(&config, &public_key_package, shares, b"artifact", &mut rng)
            .expect_err("non-declared signer set");
        assert!(
            error.to_string().contains("predeclared signing_set"),
            "expected signer-set rejection before public package decoding, got: {error}"
        );
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
            .map(|(id, kp)| (*id, kp))
            .collect();

        // Round one: each signer commits locally; only commitments are shared.
        let mut commitments = BTreeMap::new();
        let mut nonces = BTreeMap::new();
        for (id, kp) in &signers {
            let (commitment, signer_nonces) =
                sign_commit(&config, kp, message, &mut rng).expect("commit");
            nonces.insert(*id, signer_nonces);
            commitments.insert(*id, commitment.commitments);
        }

        // Coordinator builds the signing package from the commitments.
        let package = build_signing_package(&config, commitments, message).expect("package");
        assert_eq!(package.signer_ids.len(), 7);

        // Round two: each signer produces its share from its own nonces, signing
        // the artifact its nonces are bound to.
        let mut shares = BTreeMap::new();
        for (id, kp) in &signers {
            let share = sign_share(&config, kp, &nonces[id], &package, message).expect("share");
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
            let (commitment, _nonces) = sign_commit(&config, kp, b"msg", &mut rng).expect("commit");
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
        let mut stranger_rng = StdRng::seed_from_u64(123);
        let mut stranger_dkg =
            crate::run_complete_dkg(&config, &mut stranger_rng).expect("stranger dkg");
        let mut stranger = stranger_dkg
            .key_packages
            .remove(&1)
            .expect("key package one");
        stranger.frost_identifier = 99;
        assert!(matches!(
            sign_commit(&config, &stranger, b"msg", &mut rng).expect_err("unrostered commit"),
            RootError::InvalidConfig { .. }
        ));

        // build_signing_package rejects a commitment from an unrostered signer.
        let mut commitments = BTreeMap::new();
        for (id, kp) in dkg.key_packages.iter().take(7) {
            let (commitment, _nonces) = sign_commit(&config, kp, b"msg", &mut rng).expect("commit");
            commitments.insert(*id, commitment.commitments);
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
        let (_commitment, commit_nonces) =
            sign_commit(&config, &dkg.key_packages[&1], b"msg", &mut rng).expect("commit");
        assert!(matches!(
            sign_share(&config, &stranger, &commit_nonces, &package, b"msg")
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

    #[test]
    fn aggregate_signature_rejects_non_declared_signer_set_before_deserialization() {
        let config = test_config();
        let public_key_package = RootPublicKeyPackage {
            public_key_package: b"not a public package".to_vec(),
            root_public_key: b"not a verifying key".to_vec(),
            verifying_shares: BTreeMap::new(),
        };
        let shares = [1, 2, 3, 4, 5, 6, 9]
            .into_iter()
            .map(|identifier| (identifier, vec![u8::try_from(identifier).expect("id fits")]))
            .collect();
        let error = aggregate_signature(
            &config,
            &public_key_package,
            b"not a signing package",
            shares,
            b"artifact",
        )
        .expect_err("non-declared aggregate signer set");
        assert!(
            error.to_string().contains("predeclared signing_set"),
            "expected signer-set rejection before signature artifacts decode, got: {error}"
        );
    }

    #[test]
    fn sign_share_rejects_nonces_bound_to_a_different_signer() {
        // Nonces must belong to the same signer as the key package. The identifier
        // check runs before any deserialization, so empty byte fields suffice and
        // no DKG is needed.
        let config = test_config();
        let key_package = RootKeyPackage {
            frost_identifier: 1,
            key_package: Vec::new(),
        };
        let foreign_nonces = RootSigningNonces {
            frost_identifier: 2,
            ceremony_id: config.ceremony_id.clone(),
            artifact_hash: Hash256::digest(b"artifact"),
            commitment_hash: Hash256::digest(b"unrelated commitment"),
            nonces: Vec::new().into(),
        };
        let empty_package = RootSigningPackage {
            signing_package: Vec::new(),
            signer_ids: Vec::new(),
        };
        let error = sign_share(
            &config,
            &key_package,
            &foreign_nonces,
            &empty_package,
            b"artifact",
        )
        .expect_err("nonces bound to a different signer must be rejected");
        assert!(error.to_string().contains("mismatches key 1"));
    }

    #[test]
    fn sign_share_rejects_nonces_from_a_different_ceremony() {
        // The ceremony-id check runs before any deserialization, so empty byte
        // fields suffice and no DKG is needed.
        let config = test_config();
        let key_package = RootKeyPackage {
            frost_identifier: 1,
            key_package: Vec::new(),
        };
        let foreign_nonces = RootSigningNonces {
            frost_identifier: 1,
            ceremony_id: "some-other-ceremony".to_owned(),
            artifact_hash: Hash256::digest(b"artifact"),
            commitment_hash: Hash256::digest(b"unrelated commitment"),
            nonces: Vec::new().into(),
        };
        let empty_package = RootSigningPackage {
            signing_package: Vec::new(),
            signer_ids: Vec::new(),
        };
        let error = sign_share(
            &config,
            &key_package,
            &foreign_nonces,
            &empty_package,
            b"artifact",
        )
        .expect_err("nonces from a different ceremony must be rejected");
        assert!(error.to_string().contains("different ceremony"));
    }

    #[test]
    fn sign_share_rejects_nonces_bound_to_a_different_signing_instance() {
        // A signer's nonces whose commitment hash does not match the commitment
        // bound for that signer in the signing package are rejected — this is what
        // ties a nonce to one artifact + signer set and prevents cross-instance reuse.
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(404);
        let dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");
        let mut commitments = BTreeMap::new();
        for (id, kp) in dkg.key_packages.iter().take(7) {
            let (commitment, _nonces) =
                sign_commit(&config, kp, b"artifact", &mut rng).expect("commit");
            commitments.insert(*id, commitment.commitments);
        }
        let package = build_signing_package(&config, commitments, b"artifact").expect("package");
        // Fresh nonces for signer 1 (same artifact) from a *different* commitment
        // than the one in the package (a second sign_commit produces a new commitment).
        let (_other_commitment, stale_nonces) =
            sign_commit(&config, &dkg.key_packages[&1], b"artifact", &mut rng).expect("commit");
        let error = sign_share(
            &config,
            &dkg.key_packages[&1],
            &stale_nonces,
            &package,
            b"artifact",
        )
        .expect_err("nonces not bound to the package commitment must be rejected");
        assert!(
            error
                .to_string()
                .contains("not bound to this signing package")
        );
    }

    #[test]
    fn sign_share_rejects_signer_absent_from_signing_package() {
        // Signers 1..7 are the canonical set; an alternate (id 8) that is not in
        // that set cannot sign against it.
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(606);
        let dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");
        let mut commitments = BTreeMap::new();
        for (id, kp) in dkg.key_packages.iter().take(7) {
            let (commitment, _nonces) =
                sign_commit(&config, kp, b"artifact", &mut rng).expect("commit");
            commitments.insert(*id, commitment.commitments);
        }
        let package = build_signing_package(&config, commitments, b"artifact").expect("package");
        let (_commitment8, nonces8) =
            sign_commit(&config, &dkg.key_packages[&8], b"artifact", &mut rng).expect("commit 8");
        let error = sign_share(
            &config,
            &dkg.key_packages[&8],
            &nonces8,
            &package,
            b"artifact",
        )
        .expect_err("a signer absent from the set must be rejected");
        assert!(
            error
                .to_string()
                .contains("signer is not in the signing package's signer set")
        );
    }

    #[test]
    fn sign_share_rejects_non_canonical_signer_set() {
        // Bob's regression: a coordinator must not bypass the ratified
        // signer-selection policy by hand-crafting a RootSigningPackage with a
        // non-declared signer set. Set [1,2,3,4,5,6,9] replaces signer 7 with
        // signer 9; sign_share must reject it even though build_signing_package
        // was never used.
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(909);
        let dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");
        let mut commitments = BTreeMap::new();
        let mut signer_one_nonces = None;
        for (id, kp) in dkg.key_packages.iter().take(7) {
            let (commitment, nonces) =
                sign_commit(&config, kp, b"artifact", &mut rng).expect("commit");
            if *id == 1 {
                signer_one_nonces = Some(nonces);
            }
            commitments.insert(*id, commitment.commitments);
        }
        let mut package =
            build_signing_package(&config, commitments, b"artifact").expect("package");
        // Hand-craft a non-canonical signer set (skips required alternate 8).
        package.signer_ids = vec![1, 2, 3, 4, 5, 6, 9];
        let error = sign_share(
            &config,
            &dkg.key_packages[&1],
            &signer_one_nonces.expect("signer one nonces"),
            &package,
            b"artifact",
        )
        .expect_err("a non-canonical signer set must be rejected");
        assert!(
            error.to_string().contains("predeclared signing_set"),
            "expected a signing-selection-policy rejection, got: {error}"
        );
    }

    #[test]
    fn sign_share_refuses_to_sign_a_second_different_message_with_one_nonce_set() {
        // Bob's blocker-2 regression: a coordinator must not be able to get one
        // RootSigningNonces object to sign two different messages (FROST nonce
        // reuse exposes the signer key share). The first share over the bound
        // artifact succeeds; a second share over a *different* message is rejected.
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(707);
        let dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");
        let artifact = b"the one true root artifact";
        let mut commitments = BTreeMap::new();
        let mut nonces = BTreeMap::new();
        for (id, kp) in dkg.key_packages.iter().take(7) {
            let (commitment, signer_nonces) =
                sign_commit(&config, kp, artifact, &mut rng).expect("commit");
            commitments.insert(*id, commitment.commitments);
            nonces.insert(*id, signer_nonces);
        }
        let package = build_signing_package(&config, commitments, artifact).expect("package");

        // First use over the bound artifact succeeds.
        sign_share(
            &config,
            &dkg.key_packages[&1],
            &nonces[&1],
            &package,
            artifact,
        )
        .expect("first share over the bound artifact");

        // Second use of the SAME nonces over a different message is refused.
        let error = sign_share(
            &config,
            &dkg.key_packages[&1],
            &nonces[&1],
            &package,
            b"a different message the coordinator wants signed",
        )
        .expect_err("a second, different message under the same nonces must be rejected");
        assert!(error.to_string().contains("bound to a different artifact"));
    }

    #[test]
    fn sign_share_rejects_a_signing_package_missing_a_declared_signer() {
        // A RootSigningPackage whose signer_ids claim a signer whose commitment is
        // absent from the embedded package is malformed; the rebuild fails closed.
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(808);
        let dkg = crate::run_complete_dkg(&config, &mut rng).expect("dkg");
        let mut commitments = BTreeMap::new();
        let mut signer_one_nonces = None;
        for (id, kp) in dkg.key_packages.iter().take(7) {
            let (commitment, nonces) =
                sign_commit(&config, kp, b"artifact", &mut rng).expect("commit");
            if *id == 1 {
                signer_one_nonces = Some(nonces);
            }
            commitments.insert(*id, commitment.commitments);
        }
        let mut package =
            build_signing_package(&config, commitments, b"artifact").expect("package");
        let parsed_package: frost::SigningPackage =
            deserialize_frost(package.signing_package.as_slice()).expect("parsed package");
        let mut embedded_commitments = BTreeMap::new();
        for id in 1..=6u16 {
            let signer_frost_id = crate::dkg::frost_identifier(id).expect("frost id");
            let commitment = parsed_package
                .signing_commitment(&signer_frost_id)
                .expect("commitment");
            embedded_commitments.insert(signer_frost_id, commitment);
        }
        let (commitment8, _nonces8) =
            sign_commit(&config, &dkg.key_packages[&8], b"artifact", &mut rng).expect("commit 8");
        embedded_commitments.insert(
            crate::dkg::frost_identifier(8).expect("frost id 8"),
            deserialize_frost(commitment8.commitments.as_slice()).expect("commitment 8"),
        );
        let malformed_package = frost::SigningPackage::new(embedded_commitments, b"artifact");
        package.signing_package = serialize_frost(&malformed_package).expect("serialize package");
        package.signer_ids = vec![1, 2, 3, 4, 5, 6, 7];
        let error = sign_share(
            &config,
            &dkg.key_packages[&1],
            &signer_one_nonces.expect("signer one nonces"),
            &package,
            b"artifact",
        )
        .expect_err("a signing package missing a declared signer must be rejected");
        assert!(
            error
                .to_string()
                .contains("missing commitment for signer 7")
        );
    }
}
