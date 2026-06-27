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

//! RFC 3161 timestamp request and response verification for AVC receipts.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier, SignerInfo},
};
use const_oid::db::rfc5911::ID_SIGNED_DATA;
use der::{Decode as _, Encode as _, asn1::OctetString};
use exo_avc::AvcReceiptEvidenceSubject;
use exo_core::{Hash256, Timestamp};
use ring::signature;
use sha2::{Digest as _, Sha256};
use x509_cert::{Certificate, ext::pkix::SubjectKeyIdentifier};

#[cfg(test)]
pub(crate) const MICROSOFT_ARTIFACT_SIGNING_POLICY_OID: &str = "1.3.6.1.4.1.601.10.3.1";
#[cfg(test)]
pub(crate) const MICROSOFT_ARTIFACT_SIGNING_TIMESTAMP_URL: &str =
    "http://timestamp.acs.microsoft.com";
pub(crate) const RFC3161_SHA256_ALGORITHM_OID: &str = "2.16.840.1.101.3.4.2.1";

const RFC3161_TST_INFO_CONTENT_TYPE_OID: &str = "1.2.840.113549.1.9.16.1.4";
const CMS_MESSAGE_DIGEST_ATTRIBUTE_OID: &str = "1.2.840.113549.1.9.4";
const CMS_CONTENT_TYPE_ATTRIBUTE_OID: &str = "1.2.840.113549.1.9.3";
const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";
const SHA256_WITH_RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.11";
const RFC3161_NONCE_DOMAIN: &[u8] = b"exo.avc.rfc3161.nonce.v1";
const DER_BOOLEAN: u8 = 0x01;
const DER_INTEGER: u8 = 0x02;
const DER_OCTET_STRING: u8 = 0x04;
const DER_NULL: u8 = 0x05;
const DER_OBJECT_IDENTIFIER: u8 = 0x06;
const DER_SEQUENCE: u8 = 0x30;
const DER_GENERALIZED_TIME: u8 = 0x18;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rfc3161TimestampRequest {
    pub der: Vec<u8>,
    pub nonce_hex: String,
    pub message_imprint_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rfc3161VerifiedTimestamp {
    pub issued_at: Timestamp,
    pub subject_hash: Hash256,
    pub message_imprint_sha256_hex: String,
    pub token_der_base64: String,
    pub policy_oid: String,
    pub serial_number_hex: String,
    pub nonce_hex: String,
    pub tsa_subject: String,
    pub tsa_public_key_spki_der_hex: String,
}

#[derive(Clone, Copy)]
struct DerTlv<'a> {
    tag: u8,
    value: &'a [u8],
    encoded: &'a [u8],
}

struct DerReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_tlv(&mut self) -> anyhow::Result<DerTlv<'a>> {
        let start = self.offset;
        let tag = *self.bytes.get(self.offset).ok_or_else(|| {
            anyhow::anyhow!("malformed DER: missing tag at offset {}", self.offset)
        })?;
        self.offset += 1;
        let first_len = *self.bytes.get(self.offset).ok_or_else(|| {
            anyhow::anyhow!("malformed DER: missing length at offset {}", self.offset)
        })?;
        self.offset += 1;
        let len = if first_len & 0x80 == 0 {
            usize::from(first_len)
        } else {
            let octets = usize::from(first_len & 0x7f);
            if octets == 0 {
                anyhow::bail!("malformed DER: indefinite length is not allowed");
            }
            if octets > core::mem::size_of::<usize>() {
                anyhow::bail!("malformed DER: length uses {octets} octets");
            }
            let mut value = 0usize;
            for _ in 0..octets {
                let byte = *self
                    .bytes
                    .get(self.offset)
                    .ok_or_else(|| anyhow::anyhow!("malformed DER: truncated long-form length"))?;
                self.offset += 1;
                value = value
                    .checked_mul(256)
                    .and_then(|acc| acc.checked_add(usize::from(byte)))
                    .ok_or_else(|| anyhow::anyhow!("malformed DER: length overflow"))?;
            }
            value
        };
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("malformed DER: length overflow"))?;
        if end > self.bytes.len() {
            anyhow::bail!("malformed DER: value overruns input");
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(DerTlv {
            tag,
            value,
            encoded: &self.bytes[start..end],
        })
    }
}

fn der_len(len: usize) -> Vec<u8> {
    if let Ok(short) = u8::try_from(len) {
        if short < 128 {
            return vec![short];
        }
    }
    let bytes = len.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let length_bytes = &bytes[first_non_zero..];
    let mut encoded = Vec::with_capacity(1 + length_bytes.len());
    encoded.push(0x80 | u8::try_from(length_bytes.len()).unwrap_or(8));
    encoded.extend_from_slice(length_bytes);
    encoded
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(1 + der_len(value.len()).len() + value.len());
    encoded.push(tag);
    encoded.extend_from_slice(&der_len(value.len()));
    encoded.extend_from_slice(value);
    encoded
}

fn der_sequence(value: &[u8]) -> Vec<u8> {
    der_tlv(DER_SEQUENCE, value)
}

fn der_null() -> Vec<u8> {
    der_tlv(DER_NULL, &[])
}

fn der_bool(value: bool) -> Vec<u8> {
    der_tlv(DER_BOOLEAN, &[if value { 0xff } else { 0x00 }])
}

fn der_integer_from_u8(value: u8) -> Vec<u8> {
    der_tlv(DER_INTEGER, &[value])
}

fn positive_integer_value_bytes(bytes: &[u8]) -> Vec<u8> {
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let mut value = bytes[first_non_zero..].to_vec();
    if value.is_empty() {
        value.push(0);
    }
    if value[0] & 0x80 != 0 {
        value.insert(0, 0);
    }
    value
}

fn der_integer_from_positive_bytes(bytes: &[u8]) -> Vec<u8> {
    der_tlv(DER_INTEGER, &positive_integer_value_bytes(bytes))
}

fn encode_oid_arc(mut arc: u32, out: &mut Vec<u8>) {
    let mut stack = [0u8; 5];
    let mut len = 1usize;
    stack[stack.len() - 1] = u8::try_from(arc & 0x7f).unwrap_or(0);
    arc >>= 7;
    while arc > 0 {
        len += 1;
        stack[stack.len() - len] = u8::try_from((arc & 0x7f) | 0x80).unwrap_or(0x80);
        arc >>= 7;
    }
    out.extend_from_slice(&stack[stack.len() - len..]);
}

fn der_oid(oid: &str) -> anyhow::Result<Vec<u8>> {
    let arcs = oid
        .split('.')
        .map(|part| {
            part.parse::<u32>()
                .map_err(|error| anyhow::anyhow!("invalid OID arc '{part}': {error}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if arcs.len() < 2 {
        anyhow::bail!("OID must contain at least two arcs");
    }
    if arcs[0] > 2 {
        anyhow::bail!("OID first arc must be 0, 1, or 2");
    }
    if arcs[0] < 2 && arcs[1] > 39 {
        anyhow::bail!("OID second arc must be <= 39 when first arc is {}", arcs[0]);
    }
    let first = arcs[0]
        .checked_mul(40)
        .and_then(|value| value.checked_add(arcs[1]))
        .ok_or_else(|| anyhow::anyhow!("OID first two arcs overflow"))?;
    let mut value = Vec::new();
    encode_oid_arc(first, &mut value);
    for arc in &arcs[2..] {
        encode_oid_arc(*arc, &mut value);
    }
    Ok(der_tlv(DER_OBJECT_IDENTIFIER, &value))
}

fn der_algorithm_identifier(oid: &str) -> anyhow::Result<Vec<u8>> {
    let mut value = Vec::new();
    value.extend_from_slice(&der_oid(oid)?);
    value.extend_from_slice(&der_null());
    Ok(der_sequence(&value))
}

fn deterministic_nonce(
    evidence_subject: &AvcReceiptEvidenceSubject,
    policy_oid: &str,
) -> anyhow::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(RFC3161_NONCE_DOMAIN);
    hasher.update(policy_oid.as_bytes());
    hasher.update(evidence_subject.canonical_bytes()?);
    let digest = hasher.finalize();
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&digest);
    Ok(nonce)
}

pub(crate) fn build_timestamp_request(
    evidence_subject: &AvcReceiptEvidenceSubject,
    policy_oid: &str,
) -> anyhow::Result<Rfc3161TimestampRequest> {
    let message_imprint_sha256 = evidence_subject.rfc3161_sha256_message_imprint()?;
    let nonce = deterministic_nonce(evidence_subject, policy_oid)?;
    let mut message_imprint = Vec::new();
    message_imprint.extend_from_slice(&der_algorithm_identifier(RFC3161_SHA256_ALGORITHM_OID)?);
    message_imprint.extend_from_slice(&der_tlv(DER_OCTET_STRING, &message_imprint_sha256));

    let mut request = Vec::new();
    request.extend_from_slice(&der_integer_from_u8(1));
    request.extend_from_slice(&der_sequence(&message_imprint));
    request.extend_from_slice(&der_oid(policy_oid)?);
    request.extend_from_slice(&der_integer_from_positive_bytes(&nonce));
    request.extend_from_slice(&der_bool(true));

    Ok(Rfc3161TimestampRequest {
        der: der_sequence(&request),
        nonce_hex: hex::encode(nonce),
        message_imprint_sha256,
    })
}

fn parse_oid_value(value: &[u8]) -> anyhow::Result<String> {
    if value.is_empty() {
        anyhow::bail!("malformed DER OID: empty value");
    }
    let mut arcs = Vec::new();
    let mut current = 0u32;
    let mut first_value: Option<u32> = None;
    for byte in value {
        current = current
            .checked_mul(128)
            .and_then(|acc| acc.checked_add(u32::from(byte & 0x7f)))
            .ok_or_else(|| anyhow::anyhow!("malformed DER OID: arc overflow"))?;
        if byte & 0x80 == 0 {
            if first_value.is_none() {
                first_value = Some(current);
            } else {
                arcs.push(current);
            }
            current = 0;
        }
    }
    if value.last().is_some_and(|byte| byte & 0x80 != 0) {
        anyhow::bail!("malformed DER OID: truncated base128 arc");
    }
    let first = first_value.ok_or_else(|| anyhow::anyhow!("malformed DER OID"))?;
    let (arc0, arc1) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    let mut text = format!("{arc0}.{arc1}");
    for arc in arcs {
        text.push('.');
        text.push_str(&arc.to_string());
    }
    Ok(text)
}

fn parse_oid(tlv: DerTlv<'_>) -> anyhow::Result<String> {
    if tlv.tag != DER_OBJECT_IDENTIFIER {
        anyhow::bail!("malformed DER: expected OID, got tag 0x{:02x}", tlv.tag);
    }
    parse_oid_value(tlv.value)
}

fn parse_positive_integer_bytes(tlv: DerTlv<'_>) -> anyhow::Result<Vec<u8>> {
    if tlv.tag != DER_INTEGER {
        anyhow::bail!("malformed DER: expected INTEGER, got tag 0x{:02x}", tlv.tag);
    }
    if tlv.value.is_empty() {
        anyhow::bail!("malformed DER INTEGER: empty value");
    }
    if tlv.value[0] & 0x80 != 0 {
        anyhow::bail!("malformed DER INTEGER: negative values are not supported");
    }
    let value = if tlv.value.len() > 1 && tlv.value[0] == 0 {
        tlv.value[1..].to_vec()
    } else {
        tlv.value.to_vec()
    };
    Ok(value)
}

fn parse_positive_integer_u8(tlv: DerTlv<'_>) -> anyhow::Result<u8> {
    let value = parse_positive_integer_bytes(tlv)?;
    if value.len() != 1 {
        anyhow::bail!(
            "malformed DER INTEGER: expected one byte, got {}",
            value.len()
        );
    }
    Ok(value[0])
}

fn parse_timestamp_response_status(response_der: &[u8]) -> anyhow::Result<(u8, &[u8])> {
    let mut outer = DerReader::new(response_der);
    let response = outer.read_tlv()?;
    if !outer.is_finished() || response.tag != DER_SEQUENCE {
        anyhow::bail!("malformed RFC 3161 timestamp response: expected outer sequence");
    }
    let mut response_fields = DerReader::new(response.value);
    let status_info = response_fields.read_tlv()?;
    if status_info.tag != DER_SEQUENCE {
        anyhow::bail!("malformed RFC 3161 timestamp response: expected status sequence");
    }
    let mut status_fields = DerReader::new(status_info.value);
    let status = parse_positive_integer_u8(status_fields.read_tlv()?)?;
    let token_der = if response_fields.is_finished() {
        &[][..]
    } else {
        response_fields.read_tlv()?.encoded
    };
    if !response_fields.is_finished() {
        anyhow::bail!("malformed RFC 3161 timestamp response: trailing fields");
    }
    Ok((status, token_der))
}

fn canonical_hex(raw: &str, label: &str) -> anyhow::Result<String> {
    let bytes = hex::decode(raw).map_err(|error| anyhow::anyhow!("{label} is not hex: {error}"))?;
    if bytes.is_empty() {
        anyhow::bail!("{label} must not be empty");
    }
    Ok(hex::encode(bytes))
}

fn parse_generalized_time_ms(value: &[u8]) -> anyhow::Result<u64> {
    let text = std::str::from_utf8(value)
        .map_err(|error| anyhow::anyhow!("TSTInfo genTime is not UTF-8: {error}"))?;
    let without_z = text
        .strip_suffix('Z')
        .ok_or_else(|| anyhow::anyhow!("TSTInfo genTime must be UTC and end in Z"))?;
    let (base, fraction) = match without_z.split_once('.') {
        Some((base, fraction)) => (base, Some(fraction)),
        None => (without_z, None),
    };
    if base.len() != 14 || !base.bytes().all(|byte| byte.is_ascii_digit()) {
        anyhow::bail!("TSTInfo genTime must use YYYYMMDDHHMMSSZ form");
    }
    let parse = |range: core::ops::Range<usize>, label: &str| -> anyhow::Result<u32> {
        base[range]
            .parse::<u32>()
            .map_err(|error| anyhow::anyhow!("TSTInfo genTime {label} is invalid: {error}"))
    };
    let year = parse(0..4, "year")?;
    let month = parse(4..6, "month")?;
    let day = parse(6..8, "day")?;
    let hour = parse(8..10, "hour")?;
    let minute = parse(10..12, "minute")?;
    let second = parse(12..14, "second")?;
    let millisecond = match fraction {
        Some(fraction) => {
            if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                anyhow::bail!("TSTInfo genTime fractional seconds are invalid");
            }
            let mut digits = fraction
                .as_bytes()
                .iter()
                .copied()
                .take(3)
                .collect::<Vec<_>>();
            while digits.len() < 3 {
                digits.push(b'0');
            }
            std::str::from_utf8(&digits)
                .map_err(|error| anyhow::anyhow!("TSTInfo milliseconds are invalid: {error}"))?
                .parse::<u32>()
                .map_err(|error| anyhow::anyhow!("TSTInfo milliseconds are invalid: {error}"))?
        }
        None => 0,
    };
    let year = i32::try_from(year).map_err(|_| anyhow::anyhow!("TSTInfo year is too large"))?;
    let date = chrono::NaiveDate::from_ymd_opt(year, month, day)
        .ok_or_else(|| anyhow::anyhow!("TSTInfo genTime date is invalid"))?;
    let time = date
        .and_hms_milli_opt(hour, minute, second, millisecond)
        .ok_or_else(|| anyhow::anyhow!("TSTInfo genTime clock is invalid"))?;
    let epoch_ms = time.and_utc().timestamp_millis();
    u64::try_from(epoch_ms).map_err(|_| anyhow::anyhow!("TSTInfo genTime predates Unix epoch"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTstInfo {
    policy_oid: String,
    message_imprint_sha256: [u8; 32],
    serial_number_hex: String,
    issued_at: Timestamp,
    nonce_hex: String,
}

fn parse_message_imprint(tlv: DerTlv<'_>) -> anyhow::Result<[u8; 32]> {
    if tlv.tag != DER_SEQUENCE {
        anyhow::bail!("TSTInfo messageImprint must be a sequence");
    }
    let mut fields = DerReader::new(tlv.value);
    let algorithm_identifier = fields.read_tlv()?;
    if algorithm_identifier.tag != DER_SEQUENCE {
        anyhow::bail!("TSTInfo messageImprint algorithm must be a sequence");
    }
    let mut algorithm_fields = DerReader::new(algorithm_identifier.value);
    let algorithm_oid = parse_oid(algorithm_fields.read_tlv()?)?;
    if algorithm_oid != RFC3161_SHA256_ALGORITHM_OID {
        anyhow::bail!("TSTInfo messageImprint hash algorithm {algorithm_oid} is not SHA-256");
    }
    if !algorithm_fields.is_finished() {
        let params = algorithm_fields.read_tlv()?;
        if params.tag != DER_NULL || !params.value.is_empty() {
            anyhow::bail!("TSTInfo messageImprint SHA-256 parameters must be NULL when present");
        }
    }
    if !algorithm_fields.is_finished() {
        anyhow::bail!("TSTInfo messageImprint algorithm has trailing fields");
    }
    let imprint = fields.read_tlv()?;
    if imprint.tag != DER_OCTET_STRING || imprint.value.len() != 32 {
        anyhow::bail!("TSTInfo messageImprint hashedMessage must be a 32-byte OCTET STRING");
    }
    if !fields.is_finished() {
        anyhow::bail!("TSTInfo messageImprint has trailing fields");
    }
    let mut message_imprint = [0u8; 32];
    message_imprint.copy_from_slice(imprint.value);
    Ok(message_imprint)
}

fn parse_tst_info(tst_info_der: &[u8]) -> anyhow::Result<ParsedTstInfo> {
    let mut outer = DerReader::new(tst_info_der);
    let sequence = outer.read_tlv()?;
    if !outer.is_finished() || sequence.tag != DER_SEQUENCE {
        anyhow::bail!("TSTInfo must be a DER sequence");
    }
    let mut fields = DerReader::new(sequence.value);
    let version = parse_positive_integer_u8(fields.read_tlv()?)?;
    if version != 1 {
        anyhow::bail!("TSTInfo version {version} is not supported");
    }
    let policy_oid = parse_oid(fields.read_tlv()?)?;
    let message_imprint_sha256 = parse_message_imprint(fields.read_tlv()?)?;
    let serial_number_hex = hex::encode(parse_positive_integer_bytes(fields.read_tlv()?)?);
    let gen_time = fields.read_tlv()?;
    if gen_time.tag != DER_GENERALIZED_TIME {
        anyhow::bail!("TSTInfo genTime must be GeneralizedTime");
    }
    let issued_at = Timestamp::new(parse_generalized_time_ms(gen_time.value)?, 0);
    let mut nonce_hex = None;
    while !fields.is_finished() {
        let field = fields.read_tlv()?;
        match field.tag {
            DER_SEQUENCE | DER_BOOLEAN | 0xa0 | 0xa1 => {}
            DER_INTEGER => {
                if nonce_hex.is_some() {
                    anyhow::bail!("TSTInfo contains multiple nonce integers");
                }
                nonce_hex = Some(hex::encode(parse_positive_integer_bytes(field)?));
            }
            _ => anyhow::bail!("TSTInfo contains unsupported field tag 0x{:02x}", field.tag),
        }
    }
    let nonce_hex = nonce_hex.ok_or_else(|| anyhow::anyhow!("TSTInfo nonce is missing"))?;
    Ok(ParsedTstInfo {
        policy_oid,
        message_imprint_sha256,
        serial_number_hex,
        issued_at,
        nonce_hex,
    })
}

fn certificate_set(signed_data: &SignedData) -> anyhow::Result<Vec<&Certificate>> {
    let certs = signed_data
        .certificates
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("RFC 3161 TimeStampToken has no embedded certificates"))?;
    let certificates = certs
        .0
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(cert) => Some(cert),
            CertificateChoices::Other(_) => None,
        })
        .collect::<Vec<_>>();
    if certificates.is_empty() {
        anyhow::bail!("RFC 3161 TimeStampToken has no X.509 signer certificate");
    }
    Ok(certificates)
}

fn signer_certificate<'a>(
    signer_info: &SignerInfo,
    certificates: &'a [&'a Certificate],
) -> anyhow::Result<&'a Certificate> {
    for cert in certificates {
        match &signer_info.sid {
            SignerIdentifier::IssuerAndSerialNumber(isn) => {
                if cert.tbs_certificate().issuer() == &isn.issuer
                    && cert.tbs_certificate().serial_number() == &isn.serial_number
                {
                    return Ok(cert);
                }
            }
            SignerIdentifier::SubjectKeyIdentifier(signer_ski) => {
                if let Ok(Some((_critical, cert_ski))) = cert
                    .tbs_certificate()
                    .get_extension::<SubjectKeyIdentifier>()
                    && cert_ski.0.as_bytes() == signer_ski.0.as_bytes()
                {
                    return Ok(cert);
                }
            }
        }
    }
    anyhow::bail!("RFC 3161 TimeStampToken signer certificate is missing")
}

fn signed_attribute_octet_string(
    signer_info: &SignerInfo,
    attr_oid: &str,
) -> anyhow::Result<Vec<u8>> {
    let attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("CMS signed attributes are missing"))?;
    let mut values = attrs
        .iter()
        .filter(|attr| attr.oid.to_string() == attr_oid)
        .flat_map(|attr| attr.values.iter())
        .collect::<Vec<_>>();
    if values.len() != 1 {
        anyhow::bail!("CMS signed attribute {attr_oid} must appear exactly once");
    }
    let value = values.remove(0);
    let octet = OctetString::from_der(&value.to_der()?)
        .map_err(|error| anyhow::anyhow!("CMS signed attribute {attr_oid} is invalid: {error}"))?;
    Ok(octet.as_bytes().to_vec())
}

fn signed_attribute_oid(signer_info: &SignerInfo, attr_oid: &str) -> anyhow::Result<String> {
    let attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("CMS signed attributes are missing"))?;
    let mut values = attrs
        .iter()
        .filter(|attr| attr.oid.to_string() == attr_oid)
        .flat_map(|attr| attr.values.iter())
        .collect::<Vec<_>>();
    if values.len() != 1 {
        anyhow::bail!("CMS signed attribute {attr_oid} must appear exactly once");
    }
    let value = values.remove(0);
    parse_oid_value(value.value())
        .map_err(|error| anyhow::anyhow!("CMS signed attribute {attr_oid} is invalid: {error}"))
}

fn der_positive_integer_bytes(value: &[u8], field_name: &str) -> anyhow::Result<Vec<u8>> {
    if value.is_empty() {
        anyhow::bail!("RSA public key {field_name} integer is empty");
    }
    if value[0] & 0x80 != 0 {
        anyhow::bail!("RSA public key {field_name} integer is negative");
    }
    let first_non_zero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len() - 1);
    let positive = &value[first_non_zero..];
    if positive.iter().all(|byte| *byte == 0) {
        anyhow::bail!("RSA public key {field_name} integer is zero");
    }
    Ok(positive.to_vec())
}

fn rsa_public_key_components_from_certificate(
    signer_cert: &Certificate,
) -> anyhow::Result<(String, Vec<u8>, Vec<u8>)> {
    let spki = signer_cert.tbs_certificate().subject_public_key_info();
    let spki_algorithm_oid = spki.algorithm.oid.to_string();
    if spki_algorithm_oid != RSA_ENCRYPTION_OID {
        anyhow::bail!("TSA signer public key algorithm {spki_algorithm_oid} is not RSA");
    }
    let spki_der = spki
        .to_der()
        .map_err(|error| anyhow::anyhow!("TSA signer SPKI DER encoding failed: {error}"))?;
    let rsa_public_key_der = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow::anyhow!("TSA signer RSA public key has unused BIT STRING bits"))?;
    let mut public_key_reader = DerReader::new(rsa_public_key_der);
    let public_key_sequence = public_key_reader
        .read_tlv()
        .map_err(|error| anyhow::anyhow!("TSA signer RSA public key DER is malformed: {error}"))?;
    if public_key_sequence.tag != DER_SEQUENCE || !public_key_reader.is_finished() {
        anyhow::bail!("TSA signer RSA public key is not a single DER SEQUENCE");
    }
    let mut components_reader = DerReader::new(public_key_sequence.value);
    let modulus = components_reader
        .read_tlv()
        .map_err(|error| anyhow::anyhow!("TSA signer RSA modulus is malformed: {error}"))?;
    let exponent = components_reader
        .read_tlv()
        .map_err(|error| anyhow::anyhow!("TSA signer RSA exponent is malformed: {error}"))?;
    if modulus.tag != DER_INTEGER {
        anyhow::bail!("TSA signer RSA modulus is not a DER INTEGER");
    }
    if exponent.tag != DER_INTEGER {
        anyhow::bail!("TSA signer RSA exponent is not a DER INTEGER");
    }
    if !components_reader.is_finished() {
        anyhow::bail!("TSA signer RSA public key has trailing DER fields");
    }
    Ok((
        hex::encode(spki_der),
        der_positive_integer_bytes(modulus.value, "modulus")?,
        der_positive_integer_bytes(exponent.value, "exponent")?,
    ))
}

fn verify_cms_signature(
    signer_info: &SignerInfo,
    signer_cert: &Certificate,
    signed_attrs_der: &[u8],
) -> anyhow::Result<String> {
    let digest_oid = signer_info.digest_alg.oid.to_string();
    if digest_oid != RFC3161_SHA256_ALGORITHM_OID {
        anyhow::bail!("CMS signer digest algorithm {digest_oid} is not SHA-256");
    }
    let signature_oid = signer_info.signature_algorithm.oid.to_string();
    if signature_oid != SHA256_WITH_RSA_ENCRYPTION_OID && signature_oid != RSA_ENCRYPTION_OID {
        anyhow::bail!("CMS signer signature algorithm {signature_oid} is not RSA SHA-256");
    }
    let (spki_der_hex, modulus, exponent) =
        rsa_public_key_components_from_certificate(signer_cert)?;
    let public_key = signature::RsaPublicKeyComponents {
        n: modulus.as_slice(),
        e: exponent.as_slice(),
    };
    public_key
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            signed_attrs_der,
            signer_info.signature.as_bytes(),
        )
        .map_err(|_| anyhow::anyhow!("CMS signature verification failed"))?;
    Ok(spki_der_hex)
}

fn verify_timestamp_response_with_optional_spki_pin(
    response_der: &[u8],
    expected_subject_hash: Hash256,
    expected_message_imprint_sha256: [u8; 32],
    expected_nonce_hex: &str,
    expected_policy_oid: &str,
    expected_tsa_spki_der_hexes: Option<&[String]>,
) -> anyhow::Result<Rfc3161VerifiedTimestamp> {
    let (status, token_der) = parse_timestamp_response_status(response_der)
        .map_err(|error| anyhow::anyhow!("malformed RFC 3161 timestamp response: {error}"))?;
    if status != 0 && status != 1 {
        anyhow::bail!("RFC 3161 timestamp response denied with status {status}");
    }
    if token_der.is_empty() {
        anyhow::bail!("malformed RFC 3161 timestamp response: missing TimeStampToken");
    }
    let content_info = ContentInfo::from_der(token_der)
        .map_err(|error| anyhow::anyhow!("malformed CMS TimeStampToken: {error}"))?;
    if content_info.content_type != ID_SIGNED_DATA {
        anyhow::bail!("CMS TimeStampToken content type is not signedData");
    }
    let signed_data = SignedData::from_der(&content_info.content.to_der()?)
        .map_err(|error| anyhow::anyhow!("malformed CMS SignedData: {error}"))?;
    if signed_data.encap_content_info.econtent_type.to_string() != RFC3161_TST_INFO_CONTENT_TYPE_OID
    {
        anyhow::bail!("CMS SignedData content type is not RFC 3161 TSTInfo");
    }
    let tst_info_der = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("CMS SignedData TSTInfo content is missing"))?
        .value();
    let tst_info = parse_tst_info(tst_info_der)?;
    if tst_info.policy_oid != expected_policy_oid {
        anyhow::bail!(
            "RFC 3161 policy {} did not match expected {}",
            tst_info.policy_oid,
            expected_policy_oid
        );
    }
    if tst_info.message_imprint_sha256 != expected_message_imprint_sha256 {
        anyhow::bail!("RFC 3161 message imprint did not match evidence subject");
    }
    if tst_info.nonce_hex != canonical_hex(expected_nonce_hex, "RFC 3161 expected nonce")? {
        anyhow::bail!("RFC 3161 nonce did not match request nonce");
    }
    let mut tst_info_digest = Sha256::new();
    tst_info_digest.update(tst_info_der);
    let computed_message_digest = tst_info_digest.finalize().to_vec();
    let signer_infos = signed_data.signer_infos.0.iter().collect::<Vec<_>>();
    if signer_infos.len() != 1 {
        anyhow::bail!(
            "CMS SignedData must contain exactly one signer info, got {}",
            signer_infos.len()
        );
    }
    let certificates = certificate_set(&signed_data)?;
    let certificate_refs = certificates.into_iter().collect::<Vec<_>>();
    let signer_info = signer_infos[0];
    let content_type = signed_attribute_oid(signer_info, CMS_CONTENT_TYPE_ATTRIBUTE_OID)?;
    if content_type != RFC3161_TST_INFO_CONTENT_TYPE_OID {
        anyhow::bail!("CMS signed content-type attribute is not RFC 3161 TSTInfo");
    }
    let message_digest =
        signed_attribute_octet_string(signer_info, CMS_MESSAGE_DIGEST_ATTRIBUTE_OID)?;
    if message_digest != computed_message_digest {
        anyhow::bail!("CMS signed messageDigest does not match TSTInfo content");
    }
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("CMS signed attributes are missing"))?;
    let signed_attrs_der = signed_attrs
        .to_der()
        .map_err(|error| anyhow::anyhow!("CMS signed attributes DER encoding failed: {error}"))?;
    let signer_cert = signer_certificate(signer_info, &certificate_refs)?;
    let signer_spki_der_hex = verify_cms_signature(signer_info, signer_cert, &signed_attrs_der)?;
    let verified_signer_subject = signer_cert.tbs_certificate().subject().to_string();
    if let Some(expected_tsa_spki_der_hexes) = expected_tsa_spki_der_hexes {
        if expected_tsa_spki_der_hexes.is_empty() {
            anyhow::bail!("expected TSA SPKI DER pin set must not be empty");
        }
        let mut signer_matched_pin = false;
        for expected_tsa_spki_der_hex in expected_tsa_spki_der_hexes {
            let expected_spki = canonical_hex(expected_tsa_spki_der_hex, "expected TSA SPKI DER")?;
            if signer_spki_der_hex == expected_spki {
                signer_matched_pin = true;
                break;
            }
        }
        if !signer_matched_pin {
            anyhow::bail!("RFC 3161 TSA signer public key did not match any pinned SPKI DER");
        }
    }
    Ok(Rfc3161VerifiedTimestamp {
        issued_at: tst_info.issued_at,
        subject_hash: expected_subject_hash,
        message_imprint_sha256_hex: hex::encode(tst_info.message_imprint_sha256),
        token_der_base64: BASE64_STANDARD.encode(token_der),
        policy_oid: tst_info.policy_oid,
        serial_number_hex: tst_info.serial_number_hex,
        nonce_hex: tst_info.nonce_hex,
        tsa_subject: verified_signer_subject,
        tsa_public_key_spki_der_hex: signer_spki_der_hex,
    })
}

#[cfg(test)]
fn verify_timestamp_response(
    response_der: &[u8],
    expected_subject_hash: Hash256,
    expected_message_imprint_sha256: [u8; 32],
    expected_nonce_hex: &str,
    expected_policy_oid: &str,
    expected_tsa_spki_der_hex: &str,
) -> anyhow::Result<Rfc3161VerifiedTimestamp> {
    verify_timestamp_response_with_spki_pins(
        response_der,
        expected_subject_hash,
        expected_message_imprint_sha256,
        expected_nonce_hex,
        expected_policy_oid,
        &[expected_tsa_spki_der_hex.to_owned()],
    )
}

pub(crate) fn verify_timestamp_response_with_spki_pins(
    response_der: &[u8],
    expected_subject_hash: Hash256,
    expected_message_imprint_sha256: [u8; 32],
    expected_nonce_hex: &str,
    expected_policy_oid: &str,
    expected_tsa_spki_der_hexes: &[String],
) -> anyhow::Result<Rfc3161VerifiedTimestamp> {
    verify_timestamp_response_with_optional_spki_pin(
        response_der,
        expected_subject_hash,
        expected_message_imprint_sha256,
        expected_nonce_hex,
        expected_policy_oid,
        Some(expected_tsa_spki_der_hexes),
    )
}

#[cfg(test)]
fn inspect_timestamp_response_without_spki_pin(
    response_der: &[u8],
    expected_subject_hash: Hash256,
    expected_message_imprint_sha256: [u8; 32],
    expected_nonce_hex: &str,
    expected_policy_oid: &str,
) -> anyhow::Result<Rfc3161VerifiedTimestamp> {
    verify_timestamp_response_with_optional_spki_pin(
        response_der,
        expected_subject_hash,
        expected_message_imprint_sha256,
        expected_nonce_hex,
        expected_policy_oid,
        None,
    )
}

#[cfg(test)]
pub(crate) fn microsoft_fixture_timestamp_token_der_base64() -> anyhow::Result<String> {
    let response_der = BASE64_STANDARD
        .decode(include_str!("fixtures/microsoft_rfc3161_timestamp_response.b64").trim())?;
    let (_status, token_der) = parse_timestamp_response_status(&response_der)?;
    Ok(BASE64_STANDARD.encode(token_der))
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTimestampRequestForTest {
    hash_algorithm_oid: String,
    message_imprint_sha256: [u8; 32],
    policy_oid: String,
    nonce_hex: String,
    cert_req: bool,
}

#[cfg(test)]
fn parse_timestamp_request_for_test(der: &[u8]) -> anyhow::Result<ParsedTimestampRequestForTest> {
    let mut outer = DerReader::new(der);
    let request = outer.read_tlv()?;
    if !outer.is_finished() || request.tag != DER_SEQUENCE {
        anyhow::bail!("timestamp request must be an outer DER sequence");
    }
    let mut fields = DerReader::new(request.value);
    assert_eq!(parse_positive_integer_u8(fields.read_tlv()?)?, 1);
    let message_imprint = fields.read_tlv()?;
    assert_eq!(message_imprint.tag, DER_SEQUENCE);
    let mut imprint_fields = DerReader::new(message_imprint.value);
    let algorithm_identifier = imprint_fields.read_tlv()?;
    assert_eq!(algorithm_identifier.tag, DER_SEQUENCE);
    let mut algorithm_fields = DerReader::new(algorithm_identifier.value);
    let hash_algorithm_oid = parse_oid(algorithm_fields.read_tlv()?)?;
    let algorithm_null = algorithm_fields.read_tlv()?;
    assert_eq!(algorithm_null.tag, DER_NULL);
    assert!(algorithm_fields.is_finished());
    let imprint = imprint_fields.read_tlv()?;
    if imprint.tag != DER_OCTET_STRING || imprint.value.len() != 32 {
        anyhow::bail!("timestamp request imprint must be a 32-byte OCTET STRING");
    }
    let mut message_imprint_sha256 = [0u8; 32];
    message_imprint_sha256.copy_from_slice(imprint.value);
    assert!(imprint_fields.is_finished());
    let policy_oid = parse_oid(fields.read_tlv()?)?;
    let nonce_hex = hex::encode(parse_positive_integer_bytes(fields.read_tlv()?)?);
    let cert_req = fields.read_tlv()?;
    if cert_req.tag != DER_BOOLEAN || cert_req.value != [0xff] {
        anyhow::bail!("timestamp request certReq must be BOOLEAN TRUE");
    }
    assert!(fields.is_finished());
    Ok(ParsedTimestampRequestForTest {
        hash_algorithm_oid,
        message_imprint_sha256,
        policy_oid,
        nonce_hex,
        cert_req: true,
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use exo_avc::AvcReceiptEvidenceSubject;
    use exo_core::{Hash256, Timestamp};

    use super::*;

    const MICROSOFT_FIXTURE_RESPONSE_DER_BASE64: &str =
        include_str!("fixtures/microsoft_rfc3161_timestamp_response.b64");
    const MICROSOFT_FIXTURE_IMPRINT_HEX: &str =
        "891d95ab4a3aedc63c9c32b800ad15679ecd94917eb35967004f9882ac6ae69a";
    const MICROSOFT_FIXTURE_NONCE_HEX: &str = "a173ce171bc853e8";
    const MICROSOFT_FIXTURE_SIGNER_SPKI_HEX: &str = "30820222300d06092a864886f70d01010105000382020f003082020a0282020100b4a59f9bfba5d36eff77c4656fc327fe0d1052fbcba98d95b32ded23c536b454aca53668999383dc11d3f0b911f91ae130981bd558c0285372b1a2bd70b49789f3c648806b3c282cf4fe32db896b2449ab57a439cf8066a8c8483eb66112f6675a9092e073bb8d849e8bf9f1982effd44afe9792e0dcf992c5bf1dd8855c011c52c350789b107a5c8d2791e97dc1ad5d61bdb07c6a687eb6859b164ec53f5e361b782c7d1105256e79b6ba64da634bfd20b5f9bbaa2222c8fea9e8f4734d36cc9d5aac1e757f77fad6d331f1f90f90359e7052a2a64d9241f6153ce77fb6a57e6b0df2b7dae358f7f5813809b36ea82911d4246e231abd43325034a19b2708be01dd4274b6d3bb138fc33e9092f7b4e75a84fb8fa8cc2c6820a075fc30431d0ef5329eec54af6c0118b3502795d0a5fca1c6642395bd436a8f22f5d092ded3ff860fdff29ea5c6585a573a36ae9ef67f70a44e8633783397bac71d1bda68aa70f8a2e3f8a2d9985e29a9652444fb08a96915286cdf0ca0e85fdfa2343142f3e76d60f8372c7a9618d68f09a82dcc7ac351520ad6af2c2972df704b452953538a8a53169af1ded837b12aa67f573b4498d2e98ebca157ad61fbaf197ef626a2722b5d9d34e4b009d18ef7a474a4f7960ee544c7e67d953cbd73623745182734fd123aa3466d2e37f874a17c4f84d7cf62a7856f23d7186c73698533eb3c77a9370203010001";

    fn evidence_subject() -> AvcReceiptEvidenceSubject {
        AvcReceiptEvidenceSubject {
            credential_id: Hash256::from_bytes([0x11; 32]),
            action_id: Hash256::from_bytes([0x22; 32]),
            action_commitment_hash: Hash256::from_bytes([0x33; 32]),
            action_descriptor_hash: Hash256::from_bytes([0x44; 32]),
            previous_receipt_hash: Some(Hash256::from_bytes([0x55; 32])),
        }
    }

    fn denied_timestamp_response() -> Vec<u8> {
        vec![0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]
    }

    fn microsoft_fixture_subject_hash() -> Hash256 {
        Hash256::from_bytes([0x66; 32])
    }

    fn microsoft_fixture_response_der() -> Vec<u8> {
        BASE64_STANDARD
            .decode(MICROSOFT_FIXTURE_RESPONSE_DER_BASE64.trim())
            .unwrap()
    }

    fn microsoft_fixture_message_imprint() -> [u8; 32] {
        let bytes = hex::decode(MICROSOFT_FIXTURE_IMPRINT_HEX).unwrap();
        let mut imprint = [0u8; 32];
        imprint.copy_from_slice(&bytes);
        imprint
    }

    fn verify_microsoft_fixture(response_der: &[u8]) -> anyhow::Result<Rfc3161VerifiedTimestamp> {
        verify_timestamp_response(
            response_der,
            microsoft_fixture_subject_hash(),
            microsoft_fixture_message_imprint(),
            MICROSOFT_FIXTURE_NONCE_HEX,
            MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            MICROSOFT_FIXTURE_SIGNER_SPKI_HEX,
        )
    }

    fn read_tlv_error(bytes: &[u8]) -> String {
        let mut reader = DerReader::new(bytes);
        match reader.read_tlv() {
            Ok(_) => panic!("expected malformed DER to fail"),
            Err(error) => error.to_string(),
        }
    }

    fn single_tlv(bytes: &[u8]) -> DerTlv<'_> {
        let mut reader = DerReader::new(bytes);
        let tlv = reader.read_tlv().unwrap();
        assert!(reader.is_finished());
        tlv
    }

    fn strip_embedded_certificates(response_der: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut outer = DerReader::new(response_der);
        let response = outer.read_tlv()?;
        if response.tag != DER_SEQUENCE || !outer.is_finished() {
            anyhow::bail!("test fixture response must be one DER sequence");
        }
        let mut response_fields = DerReader::new(response.value);
        let status_info = response_fields.read_tlv()?;
        let token = response_fields.read_tlv()?;
        if !response_fields.is_finished() {
            anyhow::bail!("test fixture response has trailing fields");
        }
        let stripped_token = strip_token_certificates(token.encoded)?;
        let mut stripped_response = Vec::new();
        stripped_response.extend_from_slice(status_info.encoded);
        stripped_response.extend_from_slice(&stripped_token);
        Ok(der_sequence(&stripped_response))
    }

    fn strip_token_certificates(token_der: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut outer = DerReader::new(token_der);
        let content_info = outer.read_tlv()?;
        if content_info.tag != DER_SEQUENCE || !outer.is_finished() {
            anyhow::bail!("test fixture token must be one DER sequence");
        }
        let mut content_fields = DerReader::new(content_info.value);
        let content_type = content_fields.read_tlv()?;
        let explicit_content = content_fields.read_tlv()?;
        if explicit_content.tag != 0xa0 || !content_fields.is_finished() {
            anyhow::bail!("test fixture token content must be explicit signedData");
        }
        let mut explicit_fields = DerReader::new(explicit_content.value);
        let signed_data = explicit_fields.read_tlv()?;
        if signed_data.tag != DER_SEQUENCE || !explicit_fields.is_finished() {
            anyhow::bail!("test fixture signedData must be one DER sequence");
        }
        let stripped_signed_data = strip_signed_data_certificates(signed_data.encoded)?;
        let mut stripped_content_info = Vec::new();
        stripped_content_info.extend_from_slice(content_type.encoded);
        stripped_content_info.extend_from_slice(&der_tlv(0xa0, &stripped_signed_data));
        Ok(der_sequence(&stripped_content_info))
    }

    fn strip_signed_data_certificates(signed_data_der: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut outer = DerReader::new(signed_data_der);
        let signed_data = outer.read_tlv()?;
        if signed_data.tag != DER_SEQUENCE || !outer.is_finished() {
            anyhow::bail!("test fixture signedData must be one DER sequence");
        }
        let mut fields = DerReader::new(signed_data.value);
        let mut stripped = Vec::new();
        for _ in 0..3 {
            stripped.extend_from_slice(fields.read_tlv()?.encoded);
        }
        let next = fields.read_tlv()?;
        if next.tag != 0xa0 {
            anyhow::bail!("test fixture signedData did not contain certificate set");
        }
        while !fields.is_finished() {
            stripped.extend_from_slice(fields.read_tlv()?.encoded);
        }
        Ok(der_sequence(&stripped))
    }

    #[test]
    fn request_generation_uses_sha256_deterministic_nonce_certs_and_exact_imprint() {
        let subject = evidence_subject();
        let request =
            build_timestamp_request(&subject, MICROSOFT_ARTIFACT_SIGNING_POLICY_OID).unwrap();
        let replay =
            build_timestamp_request(&subject, MICROSOFT_ARTIFACT_SIGNING_POLICY_OID).unwrap();
        let parsed = parse_timestamp_request_for_test(&request.der).unwrap();

        assert_eq!(request.der, replay.der);
        assert_eq!(
            request.message_imprint_sha256,
            subject.rfc3161_sha256_message_imprint().unwrap()
        );
        assert_eq!(parsed.hash_algorithm_oid, RFC3161_SHA256_ALGORITHM_OID);
        assert_eq!(
            parsed.message_imprint_sha256,
            subject.rfc3161_sha256_message_imprint().unwrap()
        );
        assert_eq!(parsed.policy_oid, MICROSOFT_ARTIFACT_SIGNING_POLICY_OID);
        assert_eq!(parsed.nonce_hex, request.nonce_hex);
        assert!(
            parsed.cert_req,
            "RFC 3161 request must ask Microsoft to embed signing certificates"
        );
    }

    #[test]
    fn verifier_rejects_denied_and_malformed_timestamp_responses_before_receipt_storage() {
        let subject = evidence_subject();
        let request =
            build_timestamp_request(&subject, MICROSOFT_ARTIFACT_SIGNING_POLICY_OID).unwrap();
        let expected_spki = "30820122300d06092a864886f70d01010105000382010f";

        let denied = verify_timestamp_response(
            &denied_timestamp_response(),
            subject.hash().unwrap(),
            subject.rfc3161_sha256_message_imprint().unwrap(),
            &request.nonce_hex,
            MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            expected_spki,
        )
        .unwrap_err()
        .to_string();
        assert!(denied.contains("denied"));

        let malformed = verify_timestamp_response(
            &[0x30, 0x03, 0x02],
            subject.hash().unwrap(),
            subject.rfc3161_sha256_message_imprint().unwrap(),
            &request.nonce_hex,
            MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            expected_spki,
        )
        .unwrap_err()
        .to_string();
        assert!(malformed.contains("malformed"));
    }

    #[test]
    fn verifier_accepts_microsoft_artifact_signing_fixture_with_pinned_signer_spki() {
        let verified = verify_microsoft_fixture(&microsoft_fixture_response_der()).unwrap();

        assert_eq!(verified.subject_hash, microsoft_fixture_subject_hash());
        assert_eq!(
            verified.message_imprint_sha256_hex,
            MICROSOFT_FIXTURE_IMPRINT_HEX
        );
        assert_eq!(verified.policy_oid, MICROSOFT_ARTIFACT_SIGNING_POLICY_OID);
        assert_eq!(verified.serial_number_hex, "6a1c57054080");
        assert_eq!(verified.nonce_hex, MICROSOFT_FIXTURE_NONCE_HEX);
        assert_eq!(verified.issued_at, Timestamp::new(1_782_571_620_539, 0));
        assert_eq!(
            verified.tsa_public_key_spki_der_hex,
            MICROSOFT_FIXTURE_SIGNER_SPKI_HEX
        );
        assert!(
            verified
                .tsa_subject
                .contains("Microsoft Public RSA Time Stamping Authority")
        );
        assert!(!verified.token_der_base64.is_empty());
    }

    #[test]
    fn verifier_rejects_fixture_with_wrong_nonce_imprint_policy_missing_cert_pin_or_signature() {
        let response_der = microsoft_fixture_response_der();

        let wrong_nonce = verify_timestamp_response(
            &response_der,
            microsoft_fixture_subject_hash(),
            microsoft_fixture_message_imprint(),
            "a173ce171bc853e9",
            MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            MICROSOFT_FIXTURE_SIGNER_SPKI_HEX,
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_nonce.contains("nonce"));

        let mut wrong_imprint = microsoft_fixture_message_imprint();
        wrong_imprint[0] ^= 0x01;
        let wrong_imprint = verify_timestamp_response(
            &response_der,
            microsoft_fixture_subject_hash(),
            wrong_imprint,
            MICROSOFT_FIXTURE_NONCE_HEX,
            MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            MICROSOFT_FIXTURE_SIGNER_SPKI_HEX,
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_imprint.contains("message imprint"));

        let wrong_policy = verify_timestamp_response(
            &response_der,
            microsoft_fixture_subject_hash(),
            microsoft_fixture_message_imprint(),
            MICROSOFT_FIXTURE_NONCE_HEX,
            "1.2.3.4",
            MICROSOFT_FIXTURE_SIGNER_SPKI_HEX,
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_policy.contains("policy"));

        let missing_cert =
            verify_microsoft_fixture(&strip_embedded_certificates(&response_der).unwrap())
                .unwrap_err()
                .to_string();
        assert!(missing_cert.contains("certificate"));

        let wrong_pin = verify_timestamp_response(
            &response_der,
            microsoft_fixture_subject_hash(),
            microsoft_fixture_message_imprint(),
            MICROSOFT_FIXTURE_NONCE_HEX,
            MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            "30820122300d06092a864886f70d01010105000382010f",
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_pin.contains("public key"));

        let accepted_by_second_pin = verify_timestamp_response_with_spki_pins(
            &response_der,
            microsoft_fixture_subject_hash(),
            microsoft_fixture_message_imprint(),
            MICROSOFT_FIXTURE_NONCE_HEX,
            MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            &[
                "30820122300d06092a864886f70d01010105000382010f".to_owned(),
                MICROSOFT_FIXTURE_SIGNER_SPKI_HEX.to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(
            accepted_by_second_pin.tsa_public_key_spki_der_hex,
            MICROSOFT_FIXTURE_SIGNER_SPKI_HEX
        );

        let empty_pin_set = verify_timestamp_response_with_spki_pins(
            &response_der,
            microsoft_fixture_subject_hash(),
            microsoft_fixture_message_imprint(),
            MICROSOFT_FIXTURE_NONCE_HEX,
            MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(empty_pin_set.contains("must not be empty"));

        let mut bad_signature = response_der;
        *bad_signature.last_mut().unwrap() ^= 0x01;
        let bad_signature = verify_microsoft_fixture(&bad_signature)
            .unwrap_err()
            .to_string();
        assert!(bad_signature.contains("signature"));
    }

    #[test]
    fn der_parser_rejects_non_canonical_rfc3161_primitives() {
        assert!(read_tlv_error(&[]).contains("missing tag"));

        assert!(read_tlv_error(&[DER_SEQUENCE, 0x80]).contains("indefinite length"));

        assert!(
            read_tlv_error(&[DER_SEQUENCE, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                .contains("length uses")
        );

        assert!(read_tlv_error(&[DER_SEQUENCE, 0x02, 0x00]).contains("overruns"));

        assert!(
            der_oid("3.1")
                .unwrap_err()
                .to_string()
                .contains("first arc")
        );
        assert!(
            der_oid("1.40")
                .unwrap_err()
                .to_string()
                .contains("second arc")
        );
        assert!(
            der_oid("1.bad")
                .unwrap_err()
                .to_string()
                .contains("invalid OID arc")
        );
        assert!(
            parse_oid_value(&[0x80])
                .unwrap_err()
                .to_string()
                .contains("truncated")
        );
        assert!(
            parse_oid(DerTlv {
                tag: DER_INTEGER,
                value: &[1],
                encoded: &[DER_INTEGER, 1, 1],
            })
            .unwrap_err()
            .to_string()
            .contains("expected OID")
        );

        assert!(
            parse_positive_integer_bytes(DerTlv {
                tag: DER_OCTET_STRING,
                value: &[1],
                encoded: &[DER_OCTET_STRING, 1, 1],
            })
            .unwrap_err()
            .to_string()
            .contains("expected INTEGER")
        );
        assert!(
            parse_positive_integer_bytes(DerTlv {
                tag: DER_INTEGER,
                value: &[],
                encoded: &[DER_INTEGER, 0],
            })
            .unwrap_err()
            .to_string()
            .contains("empty")
        );
        assert!(
            parse_positive_integer_bytes(DerTlv {
                tag: DER_INTEGER,
                value: &[0x80],
                encoded: &[DER_INTEGER, 1, 0x80],
            })
            .unwrap_err()
            .to_string()
            .contains("negative")
        );
        assert!(
            parse_positive_integer_u8(DerTlv {
                tag: DER_INTEGER,
                value: &[0x01, 0x00],
                encoded: &[DER_INTEGER, 2, 1, 0],
            })
            .unwrap_err()
            .to_string()
            .contains("one byte")
        );

        assert!(
            canonical_hex("zz", "test hex")
                .unwrap_err()
                .to_string()
                .contains("not hex")
        );
        assert!(
            canonical_hex("", "test hex")
                .unwrap_err()
                .to_string()
                .contains("must not be empty")
        );
        assert!(
            der_positive_integer_bytes(&[], "modulus")
                .unwrap_err()
                .to_string()
                .contains("empty")
        );
        assert!(
            der_positive_integer_bytes(&[0x80], "modulus")
                .unwrap_err()
                .to_string()
                .contains("negative")
        );
        assert!(
            der_positive_integer_bytes(&[0], "modulus")
                .unwrap_err()
                .to_string()
                .contains("zero")
        );
        assert_eq!(
            der_positive_integer_bytes(&[0, 0, 1], "modulus").unwrap(),
            vec![1]
        );

        let status_info = der_sequence(&der_integer_from_u8(0));
        let mut response_with_trailing_field = Vec::new();
        response_with_trailing_field.extend_from_slice(&status_info);
        response_with_trailing_field.extend_from_slice(&der_null());
        response_with_trailing_field.extend_from_slice(&der_null());
        assert!(
            parse_timestamp_response_status(&der_sequence(&response_with_trailing_field))
                .unwrap_err()
                .to_string()
                .contains("trailing fields")
        );

        assert!(
            parse_generalized_time_ms(b"20260627120000")
                .unwrap_err()
                .to_string()
                .contains("end in Z")
        );
        assert!(
            parse_generalized_time_ms(b"20260627120000.badZ")
                .unwrap_err()
                .to_string()
                .contains("fractional seconds")
        );
        assert!(
            parse_generalized_time_ms(b"20261327120000Z")
                .unwrap_err()
                .to_string()
                .contains("date")
        );
        assert!(
            parse_generalized_time_ms(b"20260627250000Z")
                .unwrap_err()
                .to_string()
                .contains("clock")
        );

        assert_eq!(
            parse_generalized_time_ms(b"20260627120000.7Z").unwrap(),
            1_782_561_600_700
        );
        assert_eq!(
            parse_generalized_time_ms(b"20260627120000.7899Z").unwrap(),
            1_782_561_600_789
        );
    }

    #[test]
    fn message_imprint_parser_rejects_ambiguous_algorithm_and_imprint_shapes() {
        let imprint = [0x7a; 32];
        let algorithm_without_params =
            der_sequence(&der_oid(RFC3161_SHA256_ALGORITHM_OID).unwrap());
        let mut valid_without_params = Vec::new();
        valid_without_params.extend_from_slice(&algorithm_without_params);
        valid_without_params.extend_from_slice(&der_tlv(DER_OCTET_STRING, &imprint));
        assert_eq!(
            parse_message_imprint(single_tlv(&der_sequence(&valid_without_params))).unwrap(),
            imprint
        );

        let wrong_algorithm = der_algorithm_identifier("1.2.3.4").unwrap();
        let mut wrong_algorithm_imprint = Vec::new();
        wrong_algorithm_imprint.extend_from_slice(&wrong_algorithm);
        wrong_algorithm_imprint.extend_from_slice(&der_tlv(DER_OCTET_STRING, &imprint));
        assert!(
            parse_message_imprint(single_tlv(&der_sequence(&wrong_algorithm_imprint)))
                .unwrap_err()
                .to_string()
                .contains("not SHA-256")
        );

        let mut non_null_algorithm = Vec::new();
        non_null_algorithm.extend_from_slice(&der_oid(RFC3161_SHA256_ALGORITHM_OID).unwrap());
        non_null_algorithm.extend_from_slice(&der_tlv(DER_OCTET_STRING, &[0]));
        let mut non_null_imprint = Vec::new();
        non_null_imprint.extend_from_slice(&der_sequence(&non_null_algorithm));
        non_null_imprint.extend_from_slice(&der_tlv(DER_OCTET_STRING, &imprint));
        assert!(
            parse_message_imprint(single_tlv(&der_sequence(&non_null_imprint)))
                .unwrap_err()
                .to_string()
                .contains("parameters")
        );

        let mut trailing_algorithm = Vec::new();
        trailing_algorithm.extend_from_slice(&der_oid(RFC3161_SHA256_ALGORITHM_OID).unwrap());
        trailing_algorithm.extend_from_slice(&der_null());
        trailing_algorithm.extend_from_slice(&der_null());
        let mut trailing_algorithm_imprint = Vec::new();
        trailing_algorithm_imprint.extend_from_slice(&der_sequence(&trailing_algorithm));
        trailing_algorithm_imprint.extend_from_slice(&der_tlv(DER_OCTET_STRING, &imprint));
        assert!(
            parse_message_imprint(single_tlv(&der_sequence(&trailing_algorithm_imprint)))
                .unwrap_err()
                .to_string()
                .contains("trailing fields")
        );

        let mut short_imprint = Vec::new();
        short_imprint.extend_from_slice(&algorithm_without_params);
        short_imprint.extend_from_slice(&der_tlv(DER_OCTET_STRING, &[0x7a; 31]));
        assert!(
            parse_message_imprint(single_tlv(&der_sequence(&short_imprint)))
                .unwrap_err()
                .to_string()
                .contains("32-byte")
        );

        let mut trailing_imprint = valid_without_params;
        trailing_imprint.extend_from_slice(&der_null());
        assert!(
            parse_message_imprint(single_tlv(&der_sequence(&trailing_imprint)))
                .unwrap_err()
                .to_string()
                .contains("messageImprint has trailing")
        );

        assert!(
            parse_generalized_time_ms(b"2026062712000AZ")
                .unwrap_err()
                .to_string()
                .contains("YYYYMMDDHHMMSSZ")
        );
        assert!(
            parse_generalized_time_ms(b"19691231235959Z")
                .unwrap_err()
                .to_string()
                .contains("predates Unix epoch")
        );
    }

    #[tokio::test]
    #[ignore = "live Microsoft TSA preflight; set EXO_AVC_RFC3161_LIVE_PREFLIGHT=1"]
    async fn live_microsoft_rfc3161_preflight_extracts_and_verifies_pinned_spki() {
        if std::env::var("EXO_AVC_RFC3161_LIVE_PREFLIGHT")
            .ok()
            .as_deref()
            != Some("1")
        {
            eprintln!(
                "skipping live Microsoft RFC 3161 preflight; set EXO_AVC_RFC3161_LIVE_PREFLIGHT=1"
            );
            return;
        }
        let subject = evidence_subject();
        let request =
            build_timestamp_request(&subject, MICROSOFT_ARTIFACT_SIGNING_POLICY_OID).unwrap();
        let response = reqwest::Client::new()
            .post(MICROSOFT_ARTIFACT_SIGNING_TIMESTAMP_URL)
            .header("Content-Type", "application/timestamp-query")
            .header("Accept", "application/timestamp-reply")
            .body(request.der)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "Microsoft TSA returned {}",
            response.status()
        );
        let response_der = response.bytes().await.unwrap();
        let verified = inspect_timestamp_response_without_spki_pin(
            &response_der,
            subject.hash().unwrap(),
            request.message_imprint_sha256,
            &request.nonce_hex,
            MICROSOFT_ARTIFACT_SIGNING_POLICY_OID,
        )
        .unwrap();
        if let Ok(existing_pin) =
            std::env::var(crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV)
        {
            let configured_pins = existing_pin
                .split(',')
                .map(|pin| {
                    canonical_hex(
                        pin.trim(),
                        crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            assert!(
                configured_pins.contains(&verified.tsa_public_key_spki_der_hex),
                "live Microsoft TSA signer SPKI was not present in configured pin set"
            );
        }
        println!(
            "{}={}",
            crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_ENV,
            crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_KIND_RFC3161
        );
        println!(
            "{}={}",
            crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_URL_ENV,
            MICROSOFT_ARTIFACT_SIGNING_TIMESTAMP_URL
        );
        println!(
            "{}=did:exo:microsoft-public-rsa-tsa",
            crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_DID_ENV
        );
        println!(
            "{}={}",
            crate::avc::AVC_EXTERNAL_TIMESTAMP_AUTHORITY_PUBLIC_KEY_HEX_ENV,
            verified.tsa_public_key_spki_der_hex
        );
        println!(
            "{}={}",
            crate::avc::AVC_RFC3161_TIMESTAMP_POLICY_OID_ENV,
            verified.policy_oid
        );
        println!(
            "{}=true",
            crate::avc::AVC_REQUIRE_EXTERNAL_TIMESTAMP_AUTHORITY_ENV
        );
        println!("RFC3161_TSA_SUBJECT={}", verified.tsa_subject);
        println!("RFC3161_SERIAL_NUMBER={}", verified.serial_number_hex);
        println!("RFC3161_NONCE={}", verified.nonce_hex);
        println!(
            "RFC3161_MESSAGE_IMPRINT_SHA256={}",
            verified.message_imprint_sha256_hex
        );
    }
}
