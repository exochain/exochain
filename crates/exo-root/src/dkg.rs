//! FROST DKG wrappers for root genesis.

use std::{
    collections::BTreeMap,
    fmt::{self, Display},
    io::Write,
};

use frost_ristretto255 as frost;
use serde::{
    Deserialize, Serialize,
    de::{DeserializeOwned, MapAccess, SeqAccess, Visitor},
};
use zeroize::{Zeroize, Zeroizing};

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
///
/// The byte field retains its original [`Vec`] shape and caller-owned move
/// semantics for patch-release source compatibility. Debug output is redacted;
/// callers that retain this legacy carrier can invoke [`Zeroize::zeroize`]
/// explicitly when the bytes are no longer needed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "ZeroizingRootKeyPackage")]
pub struct RootKeyPackage {
    /// Owner's FROST identifier.
    pub frost_identifier: u16,
    /// Serialized FROST key package.
    pub key_package: Vec<u8>,
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

impl RootKeyPackage {
    fn from_zeroizing(frost_identifier: u16, mut key_package: Zeroizing<Vec<u8>>) -> Self {
        let mut output = Self {
            frost_identifier,
            key_package: Vec::new(),
        };
        output.key_package = std::mem::take(&mut *key_package);
        output
    }
}

impl Zeroize for RootKeyPackage {
    fn zeroize(&mut self) {
        self.key_package.zeroize();
    }
}

#[derive(Deserialize)]
struct ZeroizingRootKeyPackage {
    frost_identifier: u16,
    #[serde(deserialize_with = "deserialize_zeroizing_bytes")]
    key_package: Zeroizing<Vec<u8>>,
}

impl From<ZeroizingRootKeyPackage> for RootKeyPackage {
    fn from(value: ZeroizingRootKeyPackage) -> Self {
        Self::from_zeroizing(value.frost_identifier, value.key_package)
    }
}

/// Complete in-memory DKG result for tests and offline ceremony tooling.
///
/// Cloning this value duplicates private key-package material. Callers should
/// keep copies short-lived and explicitly zeroize legacy private byte carriers
/// when they are no longer needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootDkgOutput {
    /// Certifier key packages by FROST identifier.
    pub key_packages: BTreeMap<u16, RootKeyPackage>,
    /// Public key package common to all certifiers.
    pub public_key_package: RootPublicKeyPackage,
}

/// Serialized output from one certifier's DKG round one.
///
/// The fields retain their original [`Vec`] shapes and caller-owned move
/// semantics for patch-release source compatibility. Debug output redacts the
/// private round-one bytes, which can also be explicitly zeroized in place.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "ZeroizingRootDkgRound1Output")]
pub struct RootDkgRound1Output {
    /// Owner's FROST identifier.
    pub frost_identifier: u16,
    /// Private round-one state retained by the certifier.
    pub round1_secret_package: Vec<u8>,
    /// Public round-one package broadcast to every other certifier.
    pub round1_package: Vec<u8>,
}

impl RootDkgRound1Output {
    fn from_zeroizing(
        frost_identifier: u16,
        mut round1_secret_package: Zeroizing<Vec<u8>>,
        round1_package: Vec<u8>,
    ) -> Self {
        let mut output = Self {
            frost_identifier,
            round1_secret_package: Vec::new(),
            round1_package,
        };
        output.round1_secret_package = std::mem::take(&mut *round1_secret_package);
        output
    }
}

impl Zeroize for RootDkgRound1Output {
    fn zeroize(&mut self) {
        self.round1_secret_package.zeroize();
    }
}

#[derive(Deserialize)]
struct ZeroizingRootDkgRound1Output {
    frost_identifier: u16,
    #[serde(deserialize_with = "deserialize_zeroizing_bytes")]
    round1_secret_package: Zeroizing<Vec<u8>>,
    round1_package: Vec<u8>,
}

impl From<ZeroizingRootDkgRound1Output> for RootDkgRound1Output {
    fn from(value: ZeroizingRootDkgRound1Output) -> Self {
        Self::from_zeroizing(
            value.frost_identifier,
            value.round1_secret_package,
            value.round1_package,
        )
    }
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
///
/// The fields retain their original [`Vec`] and [`BTreeMap`] shapes and
/// caller-owned move semantics for patch-release source compatibility. Debug
/// output redacts both private fields, which can also be explicitly zeroized in
/// place.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "ZeroizingRootDkgRound2Output")]
pub struct RootDkgRound2Output {
    /// Owner's FROST identifier.
    pub frost_identifier: u16,
    /// Private round-two state retained by the certifier.
    pub round2_secret_package: Vec<u8>,
    /// Recipient-bound round-two packages by recipient FROST identifier.
    pub round2_packages: BTreeMap<u16, Vec<u8>>,
}

type RecipientRound2Packages = BTreeMap<u16, Zeroizing<Vec<u8>>>;
type ZeroizingRound2Parts = (Zeroizing<Vec<u8>>, RecipientRound2Packages);

impl RootDkgRound2Output {
    fn from_zeroizing(
        frost_identifier: u16,
        mut round2_secret_package: Zeroizing<Vec<u8>>,
        mut round2_packages: BTreeMap<u16, Zeroizing<Vec<u8>>>,
    ) -> Self {
        let mut output = Self {
            frost_identifier,
            round2_secret_package: Vec::new(),
            round2_packages: BTreeMap::new(),
        };
        output.round2_secret_package = std::mem::take(&mut *round2_secret_package);
        while let Some((identifier, mut package)) = round2_packages.pop_first() {
            output
                .round2_packages
                .insert(identifier, std::mem::take(&mut *package));
        }
        output
    }

    fn take_zeroizing_parts(&mut self) -> ZeroizingRound2Parts {
        let secret_package = Zeroizing::new(std::mem::take(&mut self.round2_secret_package));
        let packages = zeroizing_byte_map(std::mem::take(&mut self.round2_packages));
        (secret_package, packages)
    }
}

impl Zeroize for RootDkgRound2Output {
    fn zeroize(&mut self) {
        self.round2_secret_package.zeroize();
        for package in self.round2_packages.values_mut() {
            package.zeroize();
        }
        self.round2_packages.clear();
    }
}

#[derive(Deserialize)]
struct ZeroizingRootDkgRound2Output {
    frost_identifier: u16,
    #[serde(deserialize_with = "deserialize_zeroizing_bytes")]
    round2_secret_package: Zeroizing<Vec<u8>>,
    #[serde(deserialize_with = "deserialize_zeroizing_byte_map")]
    round2_packages: BTreeMap<u16, Zeroizing<Vec<u8>>>,
}

impl From<ZeroizingRootDkgRound2Output> for RootDkgRound2Output {
    fn from(value: ZeroizingRootDkgRound2Output) -> Self {
        Self::from_zeroizing(
            value.frost_identifier,
            value.round2_secret_package,
            value.round2_packages,
        )
    }
}

impl fmt::Debug for RootDkgRound2Output {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootDkgRound2Output")
            .field("frost_identifier", &self.frost_identifier)
            .field("round2_secret_package", &"[REDACTED]")
            .field("round2_packages", &"[REDACTED]")
            .finish()
    }
}

const MAX_INITIAL_SECRET_CAPACITY: usize = 4096;
const MAX_SECRET_CAPACITY: usize = usize::MAX / 2;

struct ZeroizingByteAccumulator {
    bytes: Zeroizing<Vec<u8>>,
    logical_len: usize,
}

#[derive(Clone, Copy, Debug)]
struct SecretBufferError(&'static str);

fn next_secret_capacity(current_capacity: usize) -> std::result::Result<usize, SecretBufferError> {
    let next_capacity = current_capacity
        .checked_mul(2)
        .unwrap_or(MAX_SECRET_CAPACITY)
        .clamp(1, MAX_SECRET_CAPACITY);
    if next_capacity <= current_capacity {
        return Err(SecretBufferError(
            "root secret bytes exceed supported capacity",
        ));
    }
    Ok(next_capacity)
}

impl ZeroizingByteAccumulator {
    fn with_size_hint(size_hint: usize) -> std::result::Result<Self, SecretBufferError> {
        let initial_capacity = size_hint.min(MAX_INITIAL_SECRET_CAPACITY);
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(initial_capacity)
            .map_err(|_| SecretBufferError("unable to allocate root secret bytes"))?;
        bytes.resize(initial_capacity, 0);
        Ok(Self {
            bytes,
            logical_len: 0,
        })
    }

    fn push(&mut self, byte: u8) -> std::result::Result<(), SecretBufferError> {
        if self.logical_len == self.bytes.len() {
            self.grow()?;
        }
        self.bytes[self.logical_len] = byte;
        self.logical_len += 1;
        Ok(())
    }

    fn grow(&mut self) -> std::result::Result<(), SecretBufferError> {
        let current_capacity = self.bytes.len();
        let next_capacity = next_secret_capacity(current_capacity)?;
        let mut replacement = Zeroizing::new(Vec::new());
        replacement
            .try_reserve_exact(next_capacity)
            .map_err(|_| SecretBufferError("unable to allocate root secret bytes"))?;
        replacement.resize(next_capacity, 0);
        replacement[..self.logical_len].copy_from_slice(&self.bytes[..self.logical_len]);
        self.bytes.zeroize();
        self.bytes = replacement;
        Ok(())
    }

    fn finish(mut self) -> Zeroizing<Vec<u8>> {
        self.bytes.truncate(self.logical_len);
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for ZeroizingByteAccumulator {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.logical_len.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for ZeroizingByteAccumulator {}

struct ZeroizingByteWriter {
    accumulator: ZeroizingByteAccumulator,
}

impl ZeroizingByteWriter {
    fn new() -> Self {
        Self {
            accumulator: ZeroizingByteAccumulator {
                bytes: Zeroizing::new(Vec::new()),
                logical_len: 0,
            },
        }
    }

    fn finish(self) -> Zeroizing<Vec<u8>> {
        self.accumulator.finish()
    }
}

impl Write for ZeroizingByteWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        for byte in buffer {
            self.accumulator
                .push(*byte)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::OutOfMemory, error.0))?;
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl zeroize::ZeroizeOnDrop for ZeroizingByteWriter {}

struct ZeroizingBytesVisitor;

impl<'de> Visitor<'de> for ZeroizingBytesVisitor {
    type Value = Zeroizing<Vec<u8>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a sequence of root secret bytes")
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut accumulator =
            ZeroizingByteAccumulator::with_size_hint(sequence.size_hint().unwrap_or(0))
                .map_err(|error| <A::Error as serde::de::Error>::custom(error.0))?;
        while let Some(byte) = sequence.next_element::<u8>()? {
            accumulator
                .push(byte)
                .map_err(|error| <A::Error as serde::de::Error>::custom(error.0))?;
        }
        Ok(accumulator.finish())
    }
}

pub(crate) fn deserialize_zeroizing_bytes<'de, D>(
    deserializer: D,
) -> std::result::Result<Zeroizing<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserializer.deserialize_seq(ZeroizingBytesVisitor)
}

struct ZeroizingBytes(Zeroizing<Vec<u8>>);

impl<'de> Deserialize<'de> for ZeroizingBytes {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_zeroizing_bytes(deserializer).map(Self)
    }
}

struct ZeroizingByteMapVisitor;

impl<'de> Visitor<'de> for ZeroizingByteMapVisitor {
    type Value = BTreeMap<u16, Zeroizing<Vec<u8>>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map of recipient-bound root secret byte sequences")
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut packages = BTreeMap::new();
        while let Some((identifier, package)) = map.next_entry::<u16, ZeroizingBytes>()? {
            packages.insert(identifier, package.0);
        }
        Ok(packages)
    }
}

fn deserialize_zeroizing_byte_map<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<u16, Zeroizing<Vec<u8>>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserializer.deserialize_map(ZeroizingByteMapVisitor)
}

fn zeroizing_byte_map(mut packages: BTreeMap<u16, Vec<u8>>) -> BTreeMap<u16, Zeroizing<Vec<u8>>> {
    let mut zeroizing_packages = BTreeMap::new();
    while let Some((identifier, package)) = packages.pop_first() {
        let package = Zeroizing::new(package);
        zeroizing_packages.insert(identifier, package);
    }
    zeroizing_packages
}

/// Final DKG material derived by one certifier.
///
/// Cloning this value duplicates its private key package. Callers should keep
/// copies short-lived and explicitly zeroize legacy private byte carriers when
/// they are no longer needed.
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

pub(crate) fn serialize_frost_secret<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let mut writer = ZeroizingByteWriter::new();
    ciborium::into_writer(value, &mut writer).map_err(frost_encoding_error)?;
    Ok(writer.finish())
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
    let secret_package = serialize_frost_secret(&secret_package)?;
    let public_package = serialize_frost(&package)?;
    let output =
        RootDkgRound1Output::from_zeroizing(frost_identifier_value, secret_package, public_package);
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
        round2_packages.insert(recipient_value, serialize_frost_secret(&package)?);
    }
    let round2_secret_package = serialize_frost_secret(&round2_secret_package)?;
    Ok(RootDkgRound2Output::from_zeroizing(
        frost_identifier_value,
        round2_secret_package,
        round2_packages,
    ))
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
    let round2_packages = zeroizing_byte_map(round2_packages);
    dkg_finalize_participant_zeroizing(
        config,
        frost_identifier_value,
        round2_secret_package,
        round1_packages,
        round2_packages,
    )
}

/// Finalize one participant while retaining zeroizing ownership of decoded
/// recipient-bound round-two packages.
///
/// Ceremony tooling that already decodes private packages into [`Zeroizing`]
/// buffers should use this entry point. Existing callers with ordinary byte
/// vectors remain supported by [`dkg_finalize_participant`].
pub fn dkg_finalize_participant_zeroizing(
    config: &GenesisCeremonyConfig,
    frost_identifier_value: u16,
    round2_secret_package: &[u8],
    round1_packages: BTreeMap<u16, Vec<u8>>,
    round2_packages: BTreeMap<u16, Zeroizing<Vec<u8>>>,
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
    let key_package = RootKeyPackage::from_zeroizing(
        frost_identifier_value,
        serialize_frost_secret(&key_package)?,
    );
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
    packages: BTreeMap<u16, Zeroizing<Vec<u8>>>,
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

fn require_recipient_round2_packages(
    round2_packages: Option<RecipientRound2Packages>,
    identifier: u16,
) -> Result<RecipientRound2Packages> {
    round2_packages.ok_or_else(|| RootError::Frost {
        detail: format!("missing recipient-bound round-two packages for {identifier}"),
    })
}

fn require_first_public_key_package(
    public_key_package: Option<RootPublicKeyPackage>,
) -> Result<RootPublicKeyPackage> {
    public_key_package.ok_or_else(|| RootError::Frost {
        detail: "missing first participant public key package".to_owned(),
    })
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

    let mut round2_secrets = BTreeMap::new();
    let mut round2_by_recipient: BTreeMap<u16, RecipientRound2Packages> = BTreeMap::new();
    for (identifier, round1_output) in round1_outputs {
        let peer_round1 = peer_packages_except(&round1_public, identifier);
        let secret = &round1_output.round1_secret_package;
        let mut round2 = dkg_round2(config, identifier, secret, peer_round1)?;
        let (round2_secret, round2_packages) = round2.take_zeroizing_parts();
        for (recipient, package) in round2_packages {
            let recipient_packages = round2_by_recipient.entry(recipient).or_default();
            recipient_packages.insert(identifier, package);
        }
        round2_secrets.insert(identifier, round2_secret);
    }

    let mut key_packages = BTreeMap::new();
    let finish = dkg_finalize_participant_zeroizing;
    let first_identifier = config.certifiers[0].frost_identifier;
    let mut public_key_package = None;
    for (identifier, round2_secret) in round2_secrets {
        let peer_round1 = peer_packages_except(&round1_public, identifier);
        let round2 =
            require_recipient_round2_packages(round2_by_recipient.remove(&identifier), identifier)?;
        let participant = finish(config, identifier, &round2_secret, peer_round1, round2)?;
        if identifier == first_identifier {
            public_key_package = Some(participant.public_key_package);
        }
        key_packages.insert(identifier, participant.key_package);
    }
    let public_key_package = require_first_public_key_package(public_key_package)?;

    Ok(RootDkgOutput {
        key_packages,
        public_key_package,
    })
}

#[cfg(test)]
mod tests {
    use exo_core::{Did, Hash256, PublicKey, Timestamp};
    use rand::{SeedableRng, rngs::StdRng};
    use serde::{Serialize, ser::SerializeSeq};

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

    #[derive(Serialize)]
    struct MalformedKeyPackage {
        frost_identifier: u16,
        key_package: Vec<serde_json::Value>,
    }

    #[derive(Serialize)]
    struct MalformedRound1Output {
        frost_identifier: u16,
        round1_secret_package: Vec<serde_json::Value>,
        round1_package: Vec<u8>,
    }

    #[derive(Serialize)]
    struct MalformedRound2SecretOutput {
        frost_identifier: u16,
        round2_secret_package: Vec<serde_json::Value>,
        round2_packages: BTreeMap<u16, Vec<u8>>,
    }

    #[derive(Serialize)]
    struct MalformedRound2MapOutput {
        frost_identifier: u16,
        round2_secret_package: Vec<u8>,
        round2_packages: BTreeMap<u16, Vec<serde_json::Value>>,
    }

    struct FailingSecretSerialize;

    impl Serialize for FailingSecretSerialize {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(4))?;
            sequence.serialize_element(&0xdeu8)?;
            sequence.serialize_element(&0xadu8)?;
            Err(<S::Error as serde::ser::Error>::custom(
                "forced secret serialization failure",
            ))
        }
    }

    fn cbor_bytes(value: &impl Serialize) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).expect("CBOR encoding");
        bytes
    }

    fn assert_explicitly_zeroizable<T: zeroize::Zeroize>(_: &T) {}

    #[test]
    fn legacy_secret_dkg_byte_carriers_support_explicit_zeroize() {
        let mut key_package = RootKeyPackage {
            frost_identifier: 7,
            key_package: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let mut round1 = RootDkgRound1Output {
            frost_identifier: 7,
            round1_secret_package: vec![0xca, 0xfe, 0xba, 0xbe],
            round1_package: vec![1, 2, 3],
        };
        let mut round2 = RootDkgRound2Output {
            frost_identifier: 7,
            round2_secret_package: vec![0x12, 0x34, 0x56, 0x78],
            round2_packages: BTreeMap::from([(8, vec![4, 5, 6])]),
        };

        assert_explicitly_zeroizable(&key_package);
        assert_explicitly_zeroizable(&round1);
        assert_explicitly_zeroizable(&round2);

        key_package.zeroize();
        round1.zeroize();
        round2.zeroize();
        assert!(key_package.key_package.is_empty());
        assert!(round1.round1_secret_package.is_empty());
        assert!(round2.round2_secret_package.is_empty());
        assert!(round2.round2_packages.is_empty());
    }

    #[test]
    fn secret_dkg_debug_redacts_every_private_package() {
        let key_secret = vec![0xde, 0xad, 0xbe, 0xef];
        let round1_secret = vec![0xca, 0xfe, 0xba, 0xbe];
        let round2_secret = vec![0x12, 0x34, 0x56, 0x78];
        let key_package = RootKeyPackage {
            frost_identifier: 7,
            key_package: key_secret.clone(),
        };
        let round1 = RootDkgRound1Output {
            frost_identifier: 7,
            round1_secret_package: round1_secret.clone(),
            round1_package: vec![1, 2, 3],
        };
        let round2 = RootDkgRound2Output {
            frost_identifier: 7,
            round2_secret_package: round2_secret.clone(),
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
    fn secret_round_two_recipient_packages_are_fully_redacted() {
        let recipient_secret = vec![0x99, 0x88, 0x77, 0x66];
        let output = RootDkgRound2Output {
            frost_identifier: 7,
            round2_secret_package: vec![0x12, 0x34, 0x56, 0x78],
            round2_packages: BTreeMap::from([(8, recipient_secret.clone())]),
        };

        let rendered = format!("{output:?}");
        assert!(
            rendered.matches("[REDACTED]").count() >= 2,
            "both round-two secret fields must be visibly redacted: {rendered}"
        );
        assert!(
            !rendered.contains(&format!("{recipient_secret:?}")),
            "recipient-bound round-two package leaked through Debug: {rendered}"
        );
        assert_explicitly_zeroizable(&output);
    }

    #[test]
    fn secret_byte_deserializer_clamps_hints_and_grows_from_fully_initialized_storage() {
        let mut accumulator = ZeroizingByteAccumulator::with_size_hint(usize::MAX)
            .expect("bounded initial allocation");
        assert_eq!(accumulator.bytes.len(), accumulator.bytes.capacity());
        assert!(accumulator.bytes.capacity() <= 4096);

        let bytes_to_add = accumulator.bytes.capacity() + 1;
        for index in 0..bytes_to_add {
            accumulator
                .push(u8::try_from(index % 251).expect("fixture byte"))
                .expect("zeroizing growth");
        }
        assert_eq!(accumulator.bytes.len(), accumulator.bytes.capacity());
        let finished = accumulator.finish();
        assert_eq!(finished.len(), bytes_to_add);
        assert_explicitly_zeroizable(&finished);
    }

    #[test]
    fn secret_byte_capacity_guard_rejects_terminal_capacity() {
        let error = next_secret_capacity(MAX_SECRET_CAPACITY)
            .expect_err("the bounded secret buffer must never grow past its terminal capacity");
        assert_eq!(
            error.0, "root secret bytes exceed supported capacity",
            "capacity exhaustion must remain a typed, diagnostic failure"
        );
    }

    #[test]
    fn secret_byte_writer_wipes_before_growth_and_on_serialization_error() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ZeroizingByteAccumulator>();
        assert_zeroize_on_drop::<ZeroizingByteWriter>();

        let fixture: Vec<u8> = (0..=u16::try_from(MAX_INITIAL_SECRET_CAPACITY).unwrap_or(u16::MAX))
            .map(|index| u8::try_from(index % 251).expect("fixture byte"))
            .collect();
        let mut writer = ZeroizingByteWriter::new();
        writer.write_all(&fixture).expect("forced-growth write");
        writer
            .flush()
            .expect("the unbuffered writer flushes safely");
        assert_eq!(
            writer.accumulator.bytes.len(),
            writer.accumulator.bytes.capacity()
        );
        assert_eq!(writer.finish().as_slice(), fixture.as_slice());

        let error = serialize_frost_secret(&FailingSecretSerialize)
            .expect_err("serialization error must not release a secret buffer");
        assert!(
            error
                .to_string()
                .contains("forced secret serialization failure")
        );
    }

    fn derive_before<'a>(source: &'a str, declaration: &str) -> &'a str {
        let declaration_offset = source
            .find(declaration)
            .expect("secret carrier declaration");
        let prefix = &source[..declaration_offset];
        let derive_offset = prefix.rfind("#[derive(").expect("secret carrier derive");
        &prefix[derive_offset..]
    }

    #[test]
    fn complete_dkg_moves_internal_zeroizing_secret_packages_without_clone() {
        let dkg_source = include_str!("dkg.rs");
        let signing_source = include_str!("signing.rs");
        assert!(
            !derive_before(signing_source, "pub struct RootSigningNonces").contains("Clone"),
            "RootSigningNonces must not regain secret duplication through Clone"
        );
        assert_eq!(
            dkg_source
                .matches("#[serde(deserialize_with = \"deserialize_zeroizing_bytes\")]")
                .count(),
            3,
            "all three direct DKG secret-byte fields must use the shared visitor"
        );
        assert_eq!(
            dkg_source
                .matches("#[serde(deserialize_with = \"deserialize_zeroizing_byte_map\")]")
                .count(),
            1,
            "the recipient-bound round-two map must use the shared byte visitor"
        );
        assert_eq!(
            signing_source
                .matches("#[serde(deserialize_with = \"deserialize_zeroizing_bytes\")]")
                .count(),
            1,
            "signing nonces must use the shared visitor"
        );
        let complete_dkg = dkg_source
            .split("pub fn run_complete_dkg")
            .nth(1)
            .expect("complete DKG implementation")
            .split("#[cfg(test)]")
            .next()
            .expect("complete DKG ends before tests");
        for forbidden in [
            "recipient_packages.insert(*identifier, package.clone())",
            "round2_by_recipient[&first_identifier].clone()",
            "round2_by_recipient[&identifier].clone()",
        ] {
            assert!(
                !complete_dkg.contains(forbidden),
                "complete DKG must move each recipient secret exactly once: {forbidden}"
            );
        }
        assert!(
            complete_dkg.contains("for (recipient, package) in round2_packages"),
            "complete DKG must consume outbound recipient packages"
        );
        assert!(
            complete_dkg.contains("round2_by_recipient.remove(&identifier)"),
            "complete DKG must remove each recipient map for finalization"
        );
    }

    #[test]
    fn secret_dkg_deserializers_reject_partially_decoded_json_and_cbor() {
        let invalid_bytes = vec![
            serde_json::json!(1),
            serde_json::json!(2),
            serde_json::json!("bad"),
            serde_json::json!(3),
        ];
        let key = MalformedKeyPackage {
            frost_identifier: 7,
            key_package: invalid_bytes.clone(),
        };
        let round1 = MalformedRound1Output {
            frost_identifier: 7,
            round1_secret_package: invalid_bytes.clone(),
            round1_package: vec![3],
        };
        let round2_secret = MalformedRound2SecretOutput {
            frost_identifier: 7,
            round2_secret_package: invalid_bytes.clone(),
            round2_packages: BTreeMap::from([(8, vec![3])]),
        };
        let round2_map = MalformedRound2MapOutput {
            frost_identifier: 7,
            round2_secret_package: vec![1, 2, 3],
            round2_packages: BTreeMap::from([(8, invalid_bytes)]),
        };

        let key_json = serde_json::to_vec(&key).expect("key malformed JSON fixture");
        let round1_json = serde_json::to_vec(&round1).expect("round-one malformed JSON fixture");
        let round2_secret_json =
            serde_json::to_vec(&round2_secret).expect("round-two secret malformed JSON fixture");
        let round2_map_json =
            serde_json::to_vec(&round2_map).expect("round-two map malformed JSON fixture");
        assert!(serde_json::from_slice::<RootKeyPackage>(&key_json).is_err());
        assert!(serde_json::from_slice::<RootDkgRound1Output>(&round1_json).is_err());
        assert!(serde_json::from_slice::<RootDkgRound2Output>(&round2_secret_json).is_err());
        assert!(serde_json::from_slice::<RootDkgRound2Output>(&round2_map_json).is_err());

        let key_cbor = cbor_bytes(&key);
        let round1_cbor = cbor_bytes(&round1);
        let round2_secret_cbor = cbor_bytes(&round2_secret);
        let round2_map_cbor = cbor_bytes(&round2_map);
        assert!(ciborium::from_reader::<RootKeyPackage, _>(key_cbor.as_slice()).is_err());
        assert!(ciborium::from_reader::<RootDkgRound1Output, _>(round1_cbor.as_slice()).is_err());
        assert!(
            ciborium::from_reader::<RootDkgRound2Output, _>(round2_secret_cbor.as_slice()).is_err()
        );
        assert!(
            ciborium::from_reader::<RootDkgRound2Output, _>(round2_map_cbor.as_slice()).is_err()
        );
    }

    #[test]
    fn secret_dkg_deserializer_round_trips_recipient_packages() {
        let fixture = RootDkgRound2Output {
            frost_identifier: 7,
            round2_secret_package: vec![1, 2, 3],
            round2_packages: BTreeMap::from([(8, vec![4, 5, 6]), (9, vec![7, 8, 9])]),
        };

        let json = serde_json::to_vec(&fixture).expect("round-two JSON fixture");
        let json_round_trip = serde_json::from_slice::<RootDkgRound2Output>(&json)
            .expect("round-two JSON secret map");
        assert_eq!(json_round_trip, fixture);

        let cbor = cbor_bytes(&fixture);
        let cbor_round_trip = ciborium::from_reader::<RootDkgRound2Output, _>(cbor.as_slice())
            .expect("round-two CBOR secret map");
        assert_eq!(cbor_round_trip, fixture);
    }

    #[test]
    fn secret_dkg_deserializer_reports_expected_container_shapes() {
        let byte_sequence_error = serde_json::from_str::<RootKeyPackage>(
            r#"{"frost_identifier":7,"key_package":"not-a-sequence"}"#,
        )
        .expect_err("a root key secret must be encoded as a byte sequence");
        assert!(
            byte_sequence_error
                .to_string()
                .contains("a sequence of root secret bytes"),
            "unexpected byte-sequence diagnostic: {byte_sequence_error}"
        );

        let recipient_map_error = serde_json::from_str::<RootDkgRound2Output>(
            r#"{"frost_identifier":7,"round2_secret_package":[1,2,3],"round2_packages":[]}"#,
        )
        .expect_err("recipient-bound secrets must be encoded as a map");
        assert!(
            recipient_map_error
                .to_string()
                .contains("a map of recipient-bound root secret byte sequences"),
            "unexpected recipient-map diagnostic: {recipient_map_error}"
        );
    }

    #[test]
    fn secret_dkg_json_and_cbor_match_legacy_vec_wire_layout() {
        let key_secret = vec![0xde, 0xad, 0xbe, 0xef];
        let key_package = RootKeyPackage {
            frost_identifier: 7,
            key_package: key_secret.clone(),
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
            round1_secret_package: round1_secret.clone(),
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
            round2_secret_package: round2_secret.clone(),
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
    fn complete_dkg_fail_closed_helpers_reject_missing_assembly_state() {
        let recipient_error = require_recipient_round2_packages(None, 7)
            .expect_err("a missing recipient package set must abort local DKG assembly");
        assert_eq!(
            recipient_error,
            RootError::Frost {
                detail: "missing recipient-bound round-two packages for 7".to_owned()
            }
        );

        let public_error = require_first_public_key_package(None)
            .expect_err("a missing first-participant public package must abort assembly");
        assert_eq!(
            public_error,
            RootError::Frost {
                detail: "missing first participant public key package".to_owned()
            }
        );
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
        nonrostered_round2.insert(14, Zeroizing::new(Vec::new()));
        assert!(deserialize_round2_packages(&config, participant, nonrostered_round2).is_err());

        let mut self_round2 = BTreeMap::new();
        self_round2.insert(1, Zeroizing::new(Vec::new()));
        assert!(deserialize_round2_packages(&config, participant, self_round2).is_err());

        let mut malformed_round2 = BTreeMap::new();
        malformed_round2.insert(2, Zeroizing::new(b"not a round-two package".to_vec()));
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
