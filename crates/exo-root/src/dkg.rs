//! FROST DKG wrappers for root genesis.

use std::{
    collections::BTreeMap,
    fmt::{self, Display},
};

use frost_ristretto255 as frost;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::{GenesisCeremonyConfig, Result, RootError};

/// Serialized public key package and derived public metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootPublicKeyPackage {
    /// Serialized FROST public key package.
    pub public_key_package: Vec<u8>,
    /// Serialized root verifying key.
    pub root_public_key: Vec<u8>,
    /// Serialized verification shares by FROST identifier.
    pub verifying_shares: BTreeMap<u16, Vec<u8>>,
}

/// Serialized FROST key package held by one certifier.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootKeyPackage {
    /// Owner's FROST identifier.
    pub frost_identifier: u16,
    /// Serialized FROST key package.
    pub key_package: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for RootKeyPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootKeyPackage")
            .field("frost_identifier", &self.frost_identifier)
            .field("key_package", &"[REDACTED]")
            .finish()
    }
}

/// Complete in-memory DKG result for tests and offline ceremony tooling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootDkgOutput {
    /// Certifier key packages by FROST identifier.
    pub key_packages: BTreeMap<u16, RootKeyPackage>,
    /// Public key package common to all certifiers.
    pub public_key_package: RootPublicKeyPackage,
}

/// Serialized output from one certifier's DKG round one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootDkgRound1Output {
    /// Owner's FROST identifier.
    pub frost_identifier: u16,
    /// Private round-one state retained by the certifier.
    pub round1_secret_package: Zeroizing<Vec<u8>>,
    /// Public round-one package broadcast to every other certifier.
    pub round1_package: Vec<u8>,
}

impl fmt::Debug for RootDkgRound1Output {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootDkgRound1Output")
            .field("frost_identifier", &self.frost_identifier)
            .field("round1_secret_package", &"[REDACTED]")
            .field("round1_package", &self.round1_package)
            .finish()
    }
}

/// Serialized output from one certifier's DKG round two.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootDkgRound2Output {
    /// Owner's FROST identifier.
    pub frost_identifier: u16,
    /// Private round-two state retained by the certifier.
    pub round2_secret_package: Zeroizing<Vec<u8>>,
    /// Recipient-bound round-two packages by recipient FROST identifier.
    pub round2_packages: BTreeMap<u16, Vec<u8>>,
}

impl fmt::Debug for RootDkgRound2Output {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootDkgRound2Output")
            .field("frost_identifier", &self.frost_identifier)
            .field("round2_secret_package", &"[REDACTED]")
            .field("round2_packages", &self.round2_packages)
            .finish()
    }
}

/// Final DKG material derived by one certifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootParticipantDkgOutput {
    /// Owner's FROST key package.
    pub key_package: RootKeyPackage,
    /// Public root key package derived by the participant.
    pub public_key_package: RootPublicKeyPackage,
}

pub(crate) fn frost_identifier(identifier: u16) -> Result<frost::Identifier> {
    frost::Identifier::try_from(identifier).map_err(frost_error)
}

fn rostered_frost_identifier(
    config: &GenesisCeremonyConfig,
    identifier: u16,
    operation: &str,
) -> Result<frost::Identifier> {
    if config.certifier_by_identifier(identifier).is_none() {
        return Err(RootError::InvalidConfig {
            reason: format!("{operation} certifier {identifier} is not rostered"),
        });
    }
    frost_identifier(identifier)
}

fn frost_error(error: frost::Error) -> RootError {
    RootError::Frost {
        detail: error.to_string(),
    }
}

fn frost_encoding_error(error: impl Display) -> RootError {
    RootError::Frost {
        detail: format!("FROST artifact canonical encoding failed: {error}"),
    }
}

pub(crate) fn serialize_frost<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(frost_encoding_error)?;
    Ok(bytes)
}

pub(crate) fn deserialize_frost<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(frost_encoding_error)
}

fn identifier_value(
    config: &GenesisCeremonyConfig,
    frost_identifier: frost::Identifier,
) -> Result<u16> {
    for certifier in &config.certifiers {
        if crate::dkg::frost_identifier(certifier.frost_identifier)? == frost_identifier {
            return Ok(certifier.frost_identifier);
        }
    }
    Err(RootError::Frost {
        detail: "FROST identifier is not rostered".to_owned(),
    })
}

fn peer_packages_except(
    packages: &BTreeMap<u16, Vec<u8>>,
    excluded: u16,
) -> BTreeMap<u16, Vec<u8>> {
    packages
        .iter()
        .filter(|(peer, _)| **peer != excluded)
        .map(|(peer, package)| (*peer, package.clone()))
        .collect()
}

fn frost_dkg_round1<R>(
    identifier: frost::Identifier,
    max_signers: u16,
    threshold: u16,
    rng: &mut R,
) -> Result<(
    frost::keys::dkg::round1::SecretPackage,
    frost::keys::dkg::round1::Package,
)>
where
    R: frost::rand_core::RngCore + frost::rand_core::CryptoRng,
{
    frost::keys::dkg::part1(identifier, max_signers, threshold, rng).map_err(frost_error)
}

pub(crate) fn serialize_public_key_package(
    config: &GenesisCeremonyConfig,
    package: &frost::keys::PublicKeyPackage,
) -> Result<RootPublicKeyPackage> {
    let public_key_package = serialize_frost(package)?;
    let root_public_key = serialize_frost(package.verifying_key())?;
    let mut verifying_shares = BTreeMap::new();
    for certifier in &config.certifiers {
        let identifier = frost_identifier(certifier.frost_identifier)?;
        let share =
            package
                .verifying_shares()
                .get(&identifier)
                .ok_or_else(|| RootError::Frost {
                    detail: format!(
                        "missing verification share for identifier {}",
                        certifier.frost_identifier
                    ),
                })?;
        verifying_shares.insert(certifier.frost_identifier, serialize_frost(share)?);
    }
    Ok(RootPublicKeyPackage {
        public_key_package,
        root_public_key,
        verifying_shares,
    })
}

pub(crate) fn validate_public_key_package(
    config: &GenesisCeremonyConfig,
    package: &RootPublicKeyPackage,
) -> Result<()> {
    let frost_package: frost::keys::PublicKeyPackage =
        deserialize_frost(package.public_key_package.as_slice())?;
    let expected = serialize_public_key_package(config, &frost_package)?;
    if &expected != package {
        return Err(RootError::BundleRejected {
            reason: "public key package metadata does not match serialized FROST package"
                .to_owned(),
        });
    }
    Ok(())
}

/// Execute DKG round one for one rostered certifier.
pub fn dkg_round1<R>(
    config: &GenesisCeremonyConfig,
    frost_identifier_value: u16,
    rng: &mut R,
) -> Result<RootDkgRound1Output>
where
    R: frost::rand_core::RngCore + frost::rand_core::CryptoRng,
{
    config.validate()?;
    let identifier = rostered_frost_identifier(config, frost_identifier_value, "round-one")?;
    let max_signers = config.max_signers;
    let threshold = config.threshold;
    let round1 = frost_dkg_round1(identifier, max_signers, threshold, rng)?;
    let (secret_package, package) = round1;
    let output = RootDkgRound1Output {
        frost_identifier: frost_identifier_value,
        round1_secret_package: Zeroizing::new(serialize_frost(&secret_package)?),
        round1_package: serialize_frost(&package)?,
    };
    Ok(output)
}

/// Execute DKG round two for one certifier after all other round-one packages
/// have been authenticated and collected.
pub fn dkg_round2(
    config: &GenesisCeremonyConfig,
    frost_identifier_value: u16,
    round1_secret_package: &[u8],
    round1_packages: BTreeMap<u16, Vec<u8>>,
) -> Result<RootDkgRound2Output> {
    config.validate()?;
    if round1_packages.len() != usize::from(config.max_signers - 1) {
        return Err(RootError::Frost {
            detail: "round two requires all twelve peer round-one packages".to_owned(),
        });
    }
    let participant_identifier =
        rostered_frost_identifier(config, frost_identifier_value, "round-two")?;
    let secret_package = deserialize_frost(round1_secret_package)?;
    let inbound_round1 =
        deserialize_round1_packages(config, participant_identifier, round1_packages)?;
    let (round2_secret_package, outbound) =
        frost::keys::dkg::part2(secret_package, &inbound_round1).map_err(frost_error)?;
    let mut round2_packages = BTreeMap::new();
    for (recipient, package) in outbound {
        let recipient_value = identifier_value(config, recipient)?;
        round2_packages.insert(recipient_value, serialize_frost(&package)?);
    }
    Ok(RootDkgRound2Output {
        frost_identifier: frost_identifier_value,
        round2_secret_package: Zeroizing::new(serialize_frost(&round2_secret_package)?),
        round2_packages,
    })
}

/// Finalize one participant's DKG state after all peer round-one and round-two
/// packages have been authenticated and collected.
pub fn dkg_finalize_participant(
    config: &GenesisCeremonyConfig,
    frost_identifier_value: u16,
    round2_secret_package: &[u8],
    round1_packages: BTreeMap<u16, Vec<u8>>,
    round2_packages: BTreeMap<u16, Vec<u8>>,
) -> Result<RootParticipantDkgOutput> {
    config.validate()?;
    if round1_packages.len() != usize::from(config.max_signers - 1) {
        return Err(RootError::Frost {
            detail: "finalize requires all twelve peer round-one packages".to_owned(),
        });
    }
    if round2_packages.len() != usize::from(config.max_signers - 1) {
        return Err(RootError::Frost {
            detail: "finalize requires all twelve peer round-two packages".to_owned(),
        });
    }
    let participant_identifier =
        rostered_frost_identifier(config, frost_identifier_value, "finalize")?;
    let secret_package = deserialize_frost(round2_secret_package)?;
    let inbound_round1 =
        deserialize_round1_packages(config, participant_identifier, round1_packages)?;
    let inbound_round2 =
        deserialize_round2_packages(config, participant_identifier, round2_packages)?;
    let (key_package, public_key_package) =
        frost::keys::dkg::part3(&secret_package, &inbound_round1, &inbound_round2)
            .map_err(frost_error)?;
    let key_package = RootKeyPackage {
        frost_identifier: frost_identifier_value,
        key_package: Zeroizing::new(serialize_frost(&key_package)?),
    };
    Ok(RootParticipantDkgOutput {
        key_package,
        public_key_package: serialize_public_key_package(config, &public_key_package)?,
    })
}

fn deserialize_round1_packages(
    config: &GenesisCeremonyConfig,
    participant_identifier: frost::Identifier,
    packages: BTreeMap<u16, Vec<u8>>,
) -> Result<BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>> {
    let mut result = BTreeMap::new();
    for (sender, package_bytes) in packages {
        if config.certifier_by_identifier(sender).is_none() {
            return Err(RootError::InvalidConfig {
                reason: format!("round-one sender {sender} is not rostered"),
            });
        }
        let sender_identifier = frost_identifier(sender)?;
        if sender_identifier == participant_identifier {
            return Err(RootError::Frost {
                detail: "round-one peer packages must not include self".to_owned(),
            });
        }
        let package = deserialize_frost(package_bytes.as_slice())?;
        result.insert(sender_identifier, package);
    }
    Ok(result)
}

fn deserialize_round2_packages(
    config: &GenesisCeremonyConfig,
    participant_identifier: frost::Identifier,
    packages: BTreeMap<u16, Vec<u8>>,
) -> Result<BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>> {
    let mut result = BTreeMap::new();
    for (sender, package_bytes) in packages {
        if config.certifier_by_identifier(sender).is_none() {
            return Err(RootError::InvalidConfig {
                reason: format!("round-two sender {sender} is not rostered"),
            });
        }
        let sender_identifier = frost_identifier(sender)?;
        if sender_identifier == participant_identifier {
            return Err(RootError::Frost {
                detail: "round-two peer packages must not include self".to_owned(),
            });
        }
        let package = deserialize_frost(package_bytes.as_slice())?;
        result.insert(sender_identifier, package);
    }
    Ok(result)
}

/// Run the all-roster DKG ceremony locally.
///
/// Production ceremonies should exchange these packages through the portal and
/// pairwise encrypted channels. This function enforces the same all-thirteen
/// completion rule for deterministic regression tests and offline rehearsals.
pub fn run_complete_dkg<R>(config: &GenesisCeremonyConfig, rng: &mut R) -> Result<RootDkgOutput>
where
    R: frost::rand_core::RngCore + frost::rand_core::CryptoRng,
{
    config.validate()?;

    let mut round1_outputs = BTreeMap::new();
    let mut round1_public = BTreeMap::new();
    for certifier in &config.certifiers {
        let output = dkg_round1(config, certifier.frost_identifier, rng)?;
        round1_public.insert(certifier.frost_identifier, output.round1_package.clone());
        round1_outputs.insert(certifier.frost_identifier, output);
    }

    let mut round2_outputs = BTreeMap::new();
    let mut round2_by_recipient: BTreeMap<u16, BTreeMap<u16, Vec<u8>>> = BTreeMap::new();
    for (identifier, round1_output) in &round1_outputs {
        let peer_round1 = peer_packages_except(&round1_public, *identifier);
        let secret = &round1_output.round1_secret_package;
        let round2 = dkg_round2(config, *identifier, secret, peer_round1)?;
        for (recipient, package) in &round2.round2_packages {
            let recipient_packages = round2_by_recipient.entry(*recipient).or_default();
            recipient_packages.insert(*identifier, package.clone());
        }
        round2_outputs.insert(*identifier, round2);
    }

    let mut key_packages = BTreeMap::new();
    let finish = dkg_finalize_participant;
    let first_identifier = config.certifiers[0].frost_identifier;
    let output = &round2_outputs[&first_identifier];
    let fr1 = peer_packages_except(&round1_public, first_identifier);
    let fs = &output.round2_secret_package;
    let fr2 = round2_by_recipient[&first_identifier].clone();
    let first_participant = finish(config, first_identifier, fs, fr1, fr2)?;
    let public_key_package = first_participant.public_key_package;
    key_packages.insert(first_identifier, first_participant.key_package);

    for (identifier, round2_output) in round2_outputs
        .iter()
        .filter(|(identifier, _)| **identifier != first_identifier)
    {
        let identifier = *identifier;
        let peer_round1 = peer_packages_except(&round1_public, identifier);
        let secret = &round2_output.round2_secret_package;
        let round2 = round2_by_recipient[&identifier].clone();
        let participant = finish(config, identifier, secret, peer_round1, round2)?;
        key_packages.insert(identifier, participant.key_package);
    }

    Ok(RootDkgOutput {
        key_packages,
        public_key_package,
    })
}

#[cfg(test)]
mod tests {
    use exo_core::{Did, Hash256, PublicKey, Timestamp};
    use rand::{SeedableRng, rngs::StdRng};
    use serde::Serialize;

    use super::*;
    use crate::CertifierContact;

    fn test_config() -> GenesisCeremonyConfig {
        let certifiers = (1..=13)
            .map(|identifier| {
                let byte = u8::try_from(identifier).expect("identifier fits");
                CertifierContact {
                    did: Did::new(&format!("did:exo:unit-{identifier:02}")).expect("valid did"),
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

    #[derive(Serialize)]
    struct LegacyRootKeyPackage<'a> {
        frost_identifier: u16,
        key_package: &'a Vec<u8>,
    }

    #[derive(Serialize)]
    struct LegacyRound1Output<'a> {
        frost_identifier: u16,
        round1_secret_package: &'a Vec<u8>,
        round1_package: &'a Vec<u8>,
    }

    #[derive(Serialize)]
    struct LegacyRound2Output<'a> {
        frost_identifier: u16,
        round2_secret_package: &'a Vec<u8>,
        round2_packages: &'a BTreeMap<u16, Vec<u8>>,
    }

    fn cbor_bytes(value: &impl Serialize) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).expect("CBOR encoding");
        bytes
    }

    fn assert_zeroizing_carrier<T: zeroize::Zeroize + zeroize::ZeroizeOnDrop>(_: &T) {}

    #[test]
    fn secret_dkg_byte_carriers_zeroize_on_drop() {
        let key_package = RootKeyPackage {
            frost_identifier: 7,
            key_package: Zeroizing::new(vec![0xde, 0xad, 0xbe, 0xef]),
        };
        let round1 = RootDkgRound1Output {
            frost_identifier: 7,
            round1_secret_package: Zeroizing::new(vec![0xca, 0xfe, 0xba, 0xbe]),
            round1_package: vec![1, 2, 3],
        };
        let round2 = RootDkgRound2Output {
            frost_identifier: 7,
            round2_secret_package: Zeroizing::new(vec![0x12, 0x34, 0x56, 0x78]),
            round2_packages: BTreeMap::from([(8, vec![4, 5, 6])]),
        };

        assert_zeroizing_carrier(&key_package.key_package);
        assert_zeroizing_carrier(&round1.round1_secret_package);
        assert_zeroizing_carrier(&round2.round2_secret_package);
    }

    #[test]
    fn secret_dkg_debug_redacts_every_private_package() {
        let key_secret = vec![0xde, 0xad, 0xbe, 0xef];
        let round1_secret = vec![0xca, 0xfe, 0xba, 0xbe];
        let round2_secret = vec![0x12, 0x34, 0x56, 0x78];
        let key_package = RootKeyPackage {
            frost_identifier: 7,
            key_package: Zeroizing::new(key_secret.clone()),
        };
        let round1 = RootDkgRound1Output {
            frost_identifier: 7,
            round1_secret_package: Zeroizing::new(round1_secret.clone()),
            round1_package: vec![1, 2, 3],
        };
        let round2 = RootDkgRound2Output {
            frost_identifier: 7,
            round2_secret_package: Zeroizing::new(round2_secret.clone()),
            round2_packages: BTreeMap::from([(8, vec![4, 5, 6])]),
        };

        for (rendered, secret) in [
            (format!("{key_package:?}"), format!("{key_secret:?}")),
            (format!("{round1:?}"), format!("{round1_secret:?}")),
            (format!("{round2:?}"), format!("{round2_secret:?}")),
        ] {
            assert!(
                rendered.contains("[REDACTED]"),
                "secret-bearing DKG debug output must visibly redact: {rendered}"
            );
            assert!(
                !rendered.contains(&secret),
                "secret-bearing DKG debug output exposed fixture bytes: {rendered}"
            );
        }
    }

    #[test]
    fn secret_dkg_json_and_cbor_match_legacy_vec_wire_layout() {
        let key_secret = vec![0xde, 0xad, 0xbe, 0xef];
        let key_package = RootKeyPackage {
            frost_identifier: 7,
            key_package: Zeroizing::new(key_secret.clone()),
        };
        let legacy_key = LegacyRootKeyPackage {
            frost_identifier: 7,
            key_package: &key_secret,
        };
        assert_eq!(
            serde_json::to_vec(&key_package).expect("key JSON"),
            serde_json::to_vec(&legacy_key).expect("legacy key JSON")
        );
        assert_eq!(cbor_bytes(&key_package), cbor_bytes(&legacy_key));

        let round1_secret = vec![0xca, 0xfe, 0xba, 0xbe];
        let round1_public = vec![1, 2, 3];
        let round1 = RootDkgRound1Output {
            frost_identifier: 7,
            round1_secret_package: Zeroizing::new(round1_secret.clone()),
            round1_package: round1_public.clone(),
        };
        let legacy_round1 = LegacyRound1Output {
            frost_identifier: 7,
            round1_secret_package: &round1_secret,
            round1_package: &round1_public,
        };
        assert_eq!(
            serde_json::to_vec(&round1).expect("round-one JSON"),
            serde_json::to_vec(&legacy_round1).expect("legacy round-one JSON")
        );
        assert_eq!(cbor_bytes(&round1), cbor_bytes(&legacy_round1));

        let round2_secret = vec![0x12, 0x34, 0x56, 0x78];
        let round2_public = BTreeMap::from([(8, vec![4, 5, 6])]);
        let round2 = RootDkgRound2Output {
            frost_identifier: 7,
            round2_secret_package: Zeroizing::new(round2_secret.clone()),
            round2_packages: round2_public.clone(),
        };
        let legacy_round2 = LegacyRound2Output {
            frost_identifier: 7,
            round2_secret_package: &round2_secret,
            round2_packages: &round2_public,
        };
        assert_eq!(
            serde_json::to_vec(&round2).expect("round-two JSON"),
            serde_json::to_vec(&legacy_round2).expect("legacy round-two JSON")
        );
        assert_eq!(cbor_bytes(&round2), cbor_bytes(&legacy_round2));
    }

    #[test]
    fn identifier_value_rejects_unrostered_identifier() {
        let config = test_config();
        let identifier = frost_identifier(14).expect("identifier");
        assert!(identifier_value(&config, identifier).is_err());
    }

    #[test]
    fn frost_identifier_rejects_zero_identifier() {
        let error = frost_identifier(0).expect_err("zero identifier");
        assert!(error.to_string().contains("frost operation failed"));
    }

    #[test]
    fn rostered_identifier_and_encoding_helpers_are_diagnostic() {
        let config = test_config();
        let identifier = rostered_frost_identifier(&config, 1, "unit").expect("rostered");
        assert_eq!(identifier, frost_identifier(1).expect("identifier"));

        let error =
            rostered_frost_identifier(&config, 14, "unit").expect_err("unrostered certifier");
        assert!(
            error
                .to_string()
                .contains("unit certifier 14 is not rostered")
        );

        let encoding_error = frost_encoding_error("unit failure");
        assert!(
            encoding_error
                .to_string()
                .contains("FROST artifact canonical encoding failed")
        );

        let encoded = serialize_frost(&7u16).expect("serialize");
        let decoded: u16 = deserialize_frost(encoded.as_slice()).expect("deserialize");
        assert_eq!(decoded, 7);
        assert!(deserialize_frost::<u16>(b"not cbor").is_err());
    }

    #[test]
    fn peer_package_filter_retains_every_non_excluded_package() {
        let mut packages = BTreeMap::new();
        packages.insert(1, b"one".to_vec());
        packages.insert(2, b"two".to_vec());
        packages.insert(3, b"three".to_vec());

        let peers = peer_packages_except(&packages, 2);

        assert_eq!(peers.len(), 2);
        assert_eq!(peers.get(&1).expect("peer one"), b"one");
        assert_eq!(peers.get(&3).expect("peer three"), b"three");
        assert!(!peers.contains_key(&2));
    }

    #[test]
    fn round_one_and_complete_dkg_success_paths_are_diagnostic() {
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(11);

        let round1 = dkg_round1(&config, 1, &mut rng).expect("round one");
        assert_eq!(round1.frost_identifier, 1);
        assert!(!round1.round1_secret_package.is_empty());
        assert!(!round1.round1_package.is_empty());

        let dkg = run_complete_dkg(&config, &mut rng).expect("complete dkg");
        assert_eq!(dkg.key_packages.len(), usize::from(config.max_signers));
        assert_eq!(
            dkg.public_key_package.verifying_shares.len(),
            usize::from(config.max_signers)
        );
    }

    #[test]
    fn deserialize_peer_package_helpers_reject_bad_sender_sets() {
        let config = test_config();
        let participant = frost_identifier(1).expect("participant");

        assert!(
            deserialize_round1_packages(&config, participant, BTreeMap::new())
                .expect("empty round-one helper input")
                .is_empty()
        );
        assert!(
            deserialize_round2_packages(&config, participant, BTreeMap::new())
                .expect("empty round-two helper input")
                .is_empty()
        );

        let mut nonrostered_round1 = BTreeMap::new();
        nonrostered_round1.insert(14, Vec::new());
        assert!(deserialize_round1_packages(&config, participant, nonrostered_round1).is_err());

        let mut self_round1 = BTreeMap::new();
        self_round1.insert(1, Vec::new());
        assert!(deserialize_round1_packages(&config, participant, self_round1).is_err());

        let mut malformed_round1 = BTreeMap::new();
        malformed_round1.insert(2, b"not a round-one package".to_vec());
        assert!(deserialize_round1_packages(&config, participant, malformed_round1).is_err());

        let mut nonrostered_round2 = BTreeMap::new();
        nonrostered_round2.insert(14, Vec::new());
        assert!(deserialize_round2_packages(&config, participant, nonrostered_round2).is_err());

        let mut self_round2 = BTreeMap::new();
        self_round2.insert(1, Vec::new());
        assert!(deserialize_round2_packages(&config, participant, self_round2).is_err());

        let mut malformed_round2 = BTreeMap::new();
        malformed_round2.insert(2, b"not a round-two package".to_vec());
        assert!(deserialize_round2_packages(&config, participant, malformed_round2).is_err());
    }

    #[test]
    fn serialize_public_key_package_rejects_missing_verification_share() {
        let config = test_config();
        let mut rng = StdRng::seed_from_u64(7);
        let dkg = run_complete_dkg(&config, &mut rng).expect("dkg");
        let public: frost::keys::PublicKeyPackage =
            deserialize_frost(dkg.public_key_package.public_key_package.as_slice())
                .expect("public package");
        let mut changed_config = config;
        changed_config.certifiers[0].frost_identifier = 14;
        assert!(serialize_public_key_package(&changed_config, &public).is_err());
    }
}
