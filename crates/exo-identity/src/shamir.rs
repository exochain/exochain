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

//! Shamir Secret Sharing over GF(256) for Sybil defense.
//!
//! Constant-time GF(256) field arithmetic to prevent timing side-channels.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::IdentityError;

/// Minimum caller-supplied entropy bytes required for threshold Shamir splitting.
pub const SHAMIR_ENTROPY_MIN_BYTES: usize = 32;

#[inline]
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut i = 0;
    while i < 8 {
        let mask = 0u8.wrapping_sub(b & 1);
        result ^= a & mask;
        let carry = (a >> 7) & 1;
        a <<= 1;
        a ^= 0x1b & 0u8.wrapping_sub(carry);
        b >>= 1;
        i += 1;
    }
    result
}

#[inline]
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let a2 = gf256_mul(a, a);
    let a3 = gf256_mul(a2, a);
    let a6 = gf256_mul(a3, a3);
    let a7 = gf256_mul(a6, a);
    let a14 = gf256_mul(a7, a7);
    let a15 = gf256_mul(a14, a);
    let a30 = gf256_mul(a15, a15);
    let a31 = gf256_mul(a30, a);
    let a62 = gf256_mul(a31, a31);
    let a63 = gf256_mul(a62, a);
    let a126 = gf256_mul(a63, a63);
    let a127 = gf256_mul(a126, a);
    gf256_mul(a127, a127)
}

/// Configuration for a Shamir secret sharing scheme specifying threshold and total share count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShamirConfig {
    pub threshold: u8,
    pub shares: u8,
}

impl ShamirConfig {
    /// Validate that threshold and shares are non-zero and that threshold does not exceed shares.
    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.threshold == 0 || self.shares == 0 || self.threshold > self.shares {
            return Err(IdentityError::InvalidShamirConfig {
                threshold: self.threshold,
                shares: self.shares,
            });
        }
        Ok(())
    }
}

/// A single share produced by Shamir secret splitting, with a blake3 commitment to the original secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    pub index: u8,
    pub data: Vec<u8>,
    pub commitment: [u8; 32],
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share")
            .field("index", &self.index)
            .field("data", &"<redacted>")
            .field("data_len", &self.data.len())
            .field("commitment", &self.commitment)
            .finish()
    }
}

/// Split a secret into `config.shares` shares, any `config.threshold` of which can reconstruct it.
pub fn split(secret: &[u8], config: &ShamirConfig) -> Result<Vec<Share>, IdentityError> {
    config.validate()?;

    if config.threshold > 1 {
        return Err(IdentityError::InvalidShamirEntropy {
            min_bytes: SHAMIR_ENTROPY_MIN_BYTES,
            got_bytes: 0,
            reason: "threshold greater than one requires caller-supplied entropy".into(),
        });
    }

    split_with_entropy(secret, config, &[])
}

/// Split a secret using caller-supplied entropy to derive deterministic Shamir coefficients.
pub fn split_with_entropy(
    secret: &[u8],
    config: &ShamirConfig,
    entropy: &[u8],
) -> Result<Vec<Share>, IdentityError> {
    config.validate()?;
    validate_shamir_entropy(config, entropy)?;

    let commitment: [u8; 32] = *blake3::hash(secret).as_bytes();
    let k: usize = config.threshold.into();
    let n: usize = config.shares.into();

    let mut shares: Vec<Share> = (1..=n)
        .map(|i| {
            let index = u8::try_from(i).map_err(|_| IdentityError::InvalidShamirConfig {
                threshold: config.threshold,
                shares: config.shares,
            })?;
            Ok(Share {
                index,
                data: Vec::with_capacity(secret.len()),
                commitment,
            })
        })
        .collect::<Result<Vec<_>, IdentityError>>()?;

    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        let mut coeffs = vec![0u8; k];
        coeffs[0] = secret_byte;
        for (coeff_idx, coeff) in coeffs.iter_mut().enumerate().skip(1) {
            *coeff = derive_shamir_coefficient(
                entropy,
                secret,
                &commitment,
                config,
                byte_idx,
                coeff_idx,
            )?;
        }

        for share in shares.iter_mut() {
            let x = share.index;
            let mut y: u8 = 0;
            let mut x_pow: u8 = 1;
            for &c in &coeffs {
                y ^= gf256_mul(c, x_pow);
                x_pow = gf256_mul(x_pow, x);
            }
            share.data.push(y);
        }
    }

    Ok(shares)
}

fn validate_shamir_entropy(config: &ShamirConfig, entropy: &[u8]) -> Result<(), IdentityError> {
    if config.threshold <= 1 {
        return Ok(());
    }

    if entropy.len() < SHAMIR_ENTROPY_MIN_BYTES {
        return Err(IdentityError::InvalidShamirEntropy {
            min_bytes: SHAMIR_ENTROPY_MIN_BYTES,
            got_bytes: entropy.len(),
            reason: "threshold greater than one requires at least 32 entropy bytes".into(),
        });
    }

    if entropy.iter().all(|byte| *byte == 0) {
        return Err(IdentityError::InvalidShamirEntropy {
            min_bytes: SHAMIR_ENTROPY_MIN_BYTES,
            got_bytes: entropy.len(),
            reason: "caller-supplied Shamir entropy must not be all-zero".into(),
        });
    }

    Ok(())
}

fn encode_usize_for_shamir(value: usize, field: &'static str) -> Result<[u8; 8], IdentityError> {
    let value = u64::try_from(value).map_err(|_| IdentityError::ShamirInputTooLarge {
        field,
        max: u64::MAX,
        got: value,
    })?;
    Ok(value.to_be_bytes())
}

fn derive_shamir_coefficient(
    entropy: &[u8],
    secret: &[u8],
    commitment: &[u8; 32],
    config: &ShamirConfig,
    byte_idx: usize,
    coeff_idx: usize,
) -> Result<u8, IdentityError> {
    let entropy_len = encode_usize_for_shamir(entropy.len(), "entropy_len")?;
    let secret_len = encode_usize_for_shamir(secret.len(), "secret_len")?;
    let byte_idx = encode_usize_for_shamir(byte_idx, "byte_idx")?;
    let coeff_idx = encode_usize_for_shamir(coeff_idx, "coefficient_idx")?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"exo.identity.shamir.coefficient.v2");
    hasher.update(&entropy_len);
    hasher.update(entropy);
    hasher.update(&secret_len);
    hasher.update(secret);
    hasher.update(commitment);
    hasher.update(&[config.threshold, config.shares]);
    hasher.update(&byte_idx);
    hasher.update(&coeff_idx);
    let digest = hasher.finalize();
    Ok(digest.as_bytes()[0])
}

fn validate_shares(
    shares: &[Share],
    config: &ShamirConfig,
) -> Result<([u8; 32], usize), IdentityError> {
    let mut seen = std::collections::BTreeSet::new();
    let expected_commitment = shares[0].commitment;
    let expected_len = shares[0].data.len();

    for share in shares {
        if share.index == 0 {
            return Err(IdentityError::InvalidShareIndex(0));
        }
        if share.index > config.shares {
            return Err(IdentityError::ShareIndexOutOfRange {
                index: share.index,
                shares: config.shares,
            });
        }
        if !seen.insert(share.index) {
            return Err(IdentityError::DuplicateShareIndices);
        }
        if share.data.len() != expected_len {
            return Err(IdentityError::InvalidShareLength {
                index: share.index,
                expected: expected_len,
                got: share.data.len(),
            });
        }
        if share.commitment != expected_commitment {
            return Err(IdentityError::ShareCommitmentMismatch {
                index: share.index,
                expected: expected_commitment,
                got: share.commitment,
            });
        }
    }

    Ok((expected_commitment, expected_len))
}

fn interpolate_byte_at(shares: &[Share], byte_idx: usize, x: u8) -> u8 {
    let mut value: u8 = 0;

    for (i, share_i) in shares.iter().enumerate() {
        let xi = share_i.index;
        let yi = share_i.data[byte_idx];

        let mut basis: u8 = 1;
        for (j, share_j) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = share_j.index;
            let num = x ^ xj;
            let den = xi ^ xj;
            basis = gf256_mul(basis, gf256_mul(num, gf256_inv(den)));
        }

        value ^= gf256_mul(yi, basis);
    }

    value
}

/// Reconstruct a secret from at least `config.threshold` shares using Lagrange interpolation.
pub fn reconstruct(shares: &[Share], config: &ShamirConfig) -> Result<Vec<u8>, IdentityError> {
    config.validate()?;

    let k: usize = config.threshold.into();
    let got = u8::try_from(shares.len()).unwrap_or(u8::MAX);
    if shares.len() < k {
        return Err(IdentityError::InsufficientShares {
            need: config.threshold,
            got,
        });
    }

    let (expected_commitment, secret_len) = validate_shares(shares, config)?;
    let used = &shares[..k];
    let mut secret = vec![0u8; secret_len];

    for (byte_idx, out_byte) in secret.iter_mut().enumerate().take(secret_len) {
        *out_byte = interpolate_byte_at(used, byte_idx, 0);
    }

    let reconstructed_commitment: [u8; 32] = *blake3::hash(&secret).as_bytes();
    if reconstructed_commitment != expected_commitment {
        return Err(IdentityError::ReconstructedSecretCommitmentMismatch {
            expected: expected_commitment,
            got: reconstructed_commitment,
        });
    }

    for share in shares {
        for (byte_idx, &got) in share.data.iter().enumerate() {
            let expected = interpolate_byte_at(used, byte_idx, share.index);
            if expected != got {
                return Err(IdentityError::InvalidShareValue {
                    index: share.index,
                    byte_index: byte_idx,
                    expected,
                    got,
                });
            }
        }
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SHAMIR_ENTROPY: &[u8] = b"exo-identity-test-shamir-entropy-v1";
    const OTHER_TEST_SHAMIR_ENTROPY: &[u8] = b"exo-identity-test-shamir-entropy-v2";

    #[test]
    fn gf256_mul_identity() {
        for a in 0..=255u16 {
            #[allow(clippy::as_conversions)]
            let a = a as u8;
            assert_eq!(gf256_mul(a, 1), a);
            assert_eq!(gf256_mul(1, a), a);
            assert_eq!(gf256_mul(a, 0), 0);
            assert_eq!(gf256_mul(0, a), 0);
        }
    }

    #[test]
    fn gf256_inv_roundtrip() {
        for a in 1..=255u16 {
            #[allow(clippy::as_conversions)]
            let a = a as u8;
            let inv = gf256_inv(a);
            assert_ne!(inv, 0);
            assert_eq!(gf256_mul(a, inv), 1, "a={a}, inv={inv}");
        }
    }

    #[test]
    fn gf256_inv_zero() {
        assert_eq!(gf256_inv(0), 0);
    }

    #[test]
    fn split_and_reconstruct_2_of_3() {
        let secret = b"hello shamir";
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let shares = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
        assert_eq!(shares.len(), 3);

        for combo in [[0, 1], [0, 2], [1, 2]] {
            let subset: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
            let recovered = reconstruct(&subset, &config).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn split_requires_caller_supplied_entropy_for_threshold_above_one() {
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };

        assert!(
            split(b"entropy must be explicit", &config).is_err(),
            "threshold > 1 Shamir splitting must fail closed unless entropy is caller supplied"
        );
    }

    #[test]
    fn split_with_entropy_is_deterministic_for_same_inputs() {
        let secret = b"deterministic coefficient derivation";
        let config = ShamirConfig {
            threshold: 3,
            shares: 5,
        };

        let first = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
        let second = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn split_with_entropy_changes_share_data_when_entropy_changes() {
        let secret = b"entropy-bound coefficient derivation";
        let config = ShamirConfig {
            threshold: 3,
            shares: 5,
        };

        let first = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
        let second = split_with_entropy(secret, &config, OTHER_TEST_SHAMIR_ENTROPY).unwrap();

        assert_ne!(
            first.iter().map(|share| &share.data).collect::<Vec<_>>(),
            second.iter().map(|share| &share.data).collect::<Vec<_>>()
        );
    }

    #[test]
    fn split_with_entropy_rejects_short_entropy() {
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };

        let err = split_with_entropy(b"short entropy", &config, b"short").unwrap_err();

        assert!(matches!(
            err,
            IdentityError::InvalidShamirEntropy {
                min_bytes: SHAMIR_ENTROPY_MIN_BYTES,
                got_bytes: 5,
                ..
            }
        ));
    }

    #[test]
    fn split_with_entropy_rejects_all_zero_entropy() {
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let entropy = [0u8; SHAMIR_ENTROPY_MIN_BYTES];

        let err = split_with_entropy(b"zero entropy", &config, &entropy).unwrap_err();

        assert!(matches!(
            err,
            IdentityError::InvalidShamirEntropy {
                min_bytes: SHAMIR_ENTROPY_MIN_BYTES,
                got_bytes: SHAMIR_ENTROPY_MIN_BYTES,
                ..
            }
        ));
    }

    #[test]
    fn share_debug_redacts_secret_share_data() {
        let share = Share {
            index: 1,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            commitment: [0x42; 32],
        };

        let debug = format!("{share:?}");

        assert!(
            !debug.contains("222, 173, 190, 239"),
            "Debug output must not expose raw Shamir share data"
        );
        assert!(
            debug.contains("<redacted>"),
            "Debug output must make share data redaction explicit"
        );
        assert!(
            debug.contains("data_len"),
            "Debug output should retain non-sensitive share length context"
        );
    }

    #[test]
    fn split_and_reconstruct_3_of_5() {
        let secret = b"constitutional trust fabric";
        let config = ShamirConfig {
            threshold: 3,
            shares: 5,
        };
        let shares = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
        assert_eq!(shares.len(), 5);

        let combos = [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]];
        for combo in &combos {
            let subset: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
            let recovered = reconstruct(&subset, &config).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn one_of_one() {
        let secret = b"single share";
        let config = ShamirConfig {
            threshold: 1,
            shares: 1,
        };
        let shares = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
        assert_eq!(shares.len(), 1);
        let recovered = reconstruct(&shares, &config).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn n_of_n() {
        let secret = b"all shares required";
        let config = ShamirConfig {
            threshold: 5,
            shares: 5,
        };
        let shares = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
        let recovered = reconstruct(&shares, &config).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn insufficient_shares_fails() {
        let secret = b"need three";
        let config = ShamirConfig {
            threshold: 3,
            shares: 5,
        };
        let shares = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
        let subset = vec![shares[0].clone(), shares[1].clone()];
        let err = reconstruct(&subset, &config).unwrap_err();
        assert!(matches!(
            err,
            IdentityError::InsufficientShares { need: 3, got: 2 }
        ));
    }

    #[test]
    fn invalid_config_zero_threshold() {
        let config = ShamirConfig {
            threshold: 0,
            shares: 3,
        };
        let err = split(b"test", &config).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidShamirConfig { .. }));
    }

    #[test]
    fn invalid_config_zero_shares() {
        let config = ShamirConfig {
            threshold: 1,
            shares: 0,
        };
        let err = split(b"test", &config).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidShamirConfig { .. }));
    }

    #[test]
    fn invalid_config_threshold_exceeds_shares() {
        let config = ShamirConfig {
            threshold: 5,
            shares: 3,
        };
        let err = split(b"test", &config).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidShamirConfig { .. }));
    }

    #[test]
    fn invalid_share_index_zero() {
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let shares = vec![
            Share {
                index: 0,
                data: vec![1],
                commitment: [0; 32],
            },
            Share {
                index: 1,
                data: vec![2],
                commitment: [0; 32],
            },
        ];
        let err = reconstruct(&shares, &config).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidShareIndex(0)));
    }

    #[test]
    fn duplicate_share_indices_fail() {
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let shares = vec![
            Share {
                index: 1,
                data: vec![1],
                commitment: [0; 32],
            },
            Share {
                index: 1,
                data: vec![2],
                commitment: [0; 32],
            },
        ];
        let err = reconstruct(&shares, &config).unwrap_err();
        assert!(matches!(err, IdentityError::DuplicateShareIndices));
    }

    fn split_for_test(secret: &[u8], config: &ShamirConfig) -> Vec<Share> {
        match split_with_entropy(secret, config, TEST_SHAMIR_ENTROPY) {
            Ok(shares) => shares,
            Err(err) => panic!("test split must succeed: {err}"),
        }
    }

    fn reconstruct_error_for_test(shares: &[Share], config: &ShamirConfig) -> IdentityError {
        match reconstruct(shares, config) {
            Ok(secret) => panic!("test reconstruction must fail, got {secret:?}"),
            Err(err) => err,
        }
    }

    fn derive_public_coefficient_for_attack(
        entropy: &[u8],
        commitment: &[u8; 32],
        config: &ShamirConfig,
        secret_len: usize,
        byte_idx: usize,
        coeff_idx: usize,
    ) -> u8 {
        let entropy_len =
            encode_usize_for_shamir(entropy.len(), "entropy_len").expect("entropy length");
        let secret_len = encode_usize_for_shamir(secret_len, "secret_len").expect("secret length");
        let byte_idx = encode_usize_for_shamir(byte_idx, "byte_idx").expect("byte index");
        let coeff_idx =
            encode_usize_for_shamir(coeff_idx, "coefficient_idx").expect("coefficient index");

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"exo.identity.shamir.coefficient.v1");
        hasher.update(&entropy_len);
        hasher.update(entropy);
        hasher.update(commitment);
        hasher.update(&[config.threshold, config.shares]);
        hasher.update(&secret_len);
        hasher.update(&byte_idx);
        hasher.update(&coeff_idx);
        let digest = hasher.finalize();
        digest.as_bytes()[0]
    }

    fn recover_with_known_public_coefficients(
        share: &Share,
        config: &ShamirConfig,
        entropy: &[u8],
    ) -> Vec<u8> {
        let mut recovered = Vec::with_capacity(share.data.len());
        let k: usize = config.threshold.into();

        for (byte_idx, share_byte) in share.data.iter().enumerate() {
            let mut non_secret_terms = 0u8;
            let mut x_pow = share.index;
            for coeff_idx in 1..k {
                let coefficient = derive_public_coefficient_for_attack(
                    entropy,
                    &share.commitment,
                    config,
                    share.data.len(),
                    byte_idx,
                    coeff_idx,
                );
                non_secret_terms ^= gf256_mul(coefficient, x_pow);
                x_pow = gf256_mul(x_pow, share.index);
            }
            recovered.push(*share_byte ^ non_secret_terms);
        }

        recovered
    }

    #[test]
    fn known_entropy_and_one_share_do_not_recover_threshold_secret() {
        let secret = b"public entropy must not collapse Shamir threshold";

        for config in [
            ShamirConfig {
                threshold: 2,
                shares: 3,
            },
            ShamirConfig {
                threshold: 3,
                shares: 5,
            },
        ] {
            let shares = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
            let recovered =
                recover_with_known_public_coefficients(&shares[0], &config, TEST_SHAMIR_ENTROPY);

            assert_ne!(
                recovered, secret,
                "known public entropy plus one share must not recover the secret for threshold {}",
                config.threshold
            );
        }
    }

    #[test]
    fn reconstruct_rejects_share_index_above_config() {
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let shares = vec![
            Share {
                index: 1,
                data: vec![1],
                commitment: [0; 32],
            },
            Share {
                index: 4,
                data: vec![2],
                commitment: [0; 32],
            },
        ];

        let err = reconstruct_error_for_test(&shares, &config);
        assert!(matches!(
            err,
            IdentityError::ShareIndexOutOfRange {
                index: 4,
                shares: 3
            }
        ));
    }

    #[test]
    fn reconstruct_rejects_inconsistent_lengths_without_panic() {
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let shares = vec![
            Share {
                index: 1,
                data: vec![1, 2],
                commitment: [0; 32],
            },
            Share {
                index: 2,
                data: vec![3],
                commitment: [0; 32],
            },
        ];

        let result = std::panic::catch_unwind(|| reconstruct(&shares, &config));
        match result {
            Ok(Err(IdentityError::InvalidShareLength {
                index: 2,
                expected: 2,
                got: 1,
            })) => {}
            other => panic!("expected typed share-length error without panic, got {other:?}"),
        }
    }

    #[test]
    fn reconstruct_rejects_mismatched_share_commitments() {
        let secret = b"commitment mismatch";
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let mut shares = split_for_test(secret, &config);
        let expected = shares[0].commitment;
        shares[1].commitment[0] ^= 0x01;
        let got = shares[1].commitment;

        let err = reconstruct_error_for_test(&shares[..2], &config);
        assert!(matches!(
            err,
            IdentityError::ShareCommitmentMismatch {
                index: 2,
                expected: actual_expected,
                got: actual_got,
            } if actual_expected == expected && actual_got == got
        ));
    }

    #[test]
    fn reconstruct_rejects_tampered_share_data_with_original_commitment() {
        let secret = b"tamper-resistant shares";
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let mut shares = split_for_test(secret, &config);
        let expected = shares[0].commitment;
        shares[0].data[0] ^= 0x01;

        let err = reconstruct_error_for_test(&shares[..2], &config);
        assert!(matches!(
            err,
            IdentityError::ReconstructedSecretCommitmentMismatch {
                expected: actual_expected,
                got,
            } if actual_expected == expected && got != expected
        ));
    }

    #[test]
    fn reconstruct_rejects_tampered_extra_share_not_used_for_threshold() {
        let secret = b"extra share consistency";
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let mut shares = split_for_test(secret, &config);
        let got = shares[2].data[0] ^ 0x01;
        shares[2].data[0] = got;

        let err = reconstruct_error_for_test(&shares, &config);
        assert!(matches!(
            err,
            IdentityError::InvalidShareValue {
                index: 3,
                byte_index: 0,
                expected,
                got: actual_got,
            } if expected != actual_got && actual_got == got
        ));
    }

    #[test]
    fn split_does_not_use_internal_randomness_for_coefficients() {
        let source = include_str!("shamir.rs");
        let split_source = source
            .split("pub fn split(")
            .nth(1)
            .expect("split source exists")
            .split("fn validate_shares")
            .next()
            .expect("split source ends before share validation");

        assert!(
            !split_source.contains("OsRng"),
            "Shamir coefficients must not draw hidden entropy from the operating system"
        );
        assert!(
            !split_source.contains("fill_bytes"),
            "Shamir coefficients must not use internal RNG byte filling"
        );
    }

    #[test]
    fn split_uses_checked_share_index_conversion() {
        let source = include_str!("shamir.rs");
        let split_source = source
            .split("pub fn split(")
            .nth(1)
            .expect("split source exists")
            .split("fn validate_shares")
            .next()
            .expect("split source ends before share validation");
        let forbidden_cast = ["i", " as ", "u8"].concat();

        assert!(
            !split_source.contains("clippy::as_conversions"),
            "Shamir share index conversion must not suppress checked conversion lints"
        );
        assert!(
            !split_source.contains(&forbidden_cast),
            "Shamir share index conversion must not use an unchecked narrowing cast"
        );
    }

    #[test]
    fn coefficient_derivation_binds_secret_bytes_not_public_commitment_only() {
        let source = include_str!("shamir.rs");
        let derivation_source = source
            .split("fn derive_shamir_coefficient")
            .nth(1)
            .expect("coefficient derivation source exists")
            .split("fn validate_shares")
            .next()
            .expect("coefficient derivation source ends before share validation");

        assert!(
            derivation_source.contains("coefficient.v2"),
            "Shamir coefficient derivation must use the secret-bound domain version"
        );
        assert!(
            derivation_source.contains("secret: &[u8]"),
            "Shamir coefficient derivation must take secret bytes as non-public input"
        );
        assert!(
            derivation_source.contains("hasher.update(secret)"),
            "Shamir coefficient derivation must bind secret bytes, not only the public commitment"
        );
    }

    #[test]
    fn commitment_matches_secret() {
        let secret = b"verify commitment";
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let shares = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
        let expected: [u8; 32] = *blake3::hash(secret).as_bytes();
        for share in &shares {
            assert_eq!(share.commitment, expected);
        }
    }

    #[test]
    fn empty_secret() {
        let secret = b"";
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let shares = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
        let recovered = reconstruct(&shares[..2], &config).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn single_byte_secret() {
        let secret = &[42u8];
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let shares = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
        let recovered = reconstruct(&shares[..2], &config).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn more_shares_than_threshold_still_works() {
        let secret = b"extra shares";
        let config = ShamirConfig {
            threshold: 2,
            shares: 5,
        };
        let shares = split_with_entropy(secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
        let recovered = reconstruct(&shares, &config).unwrap();
        assert_eq!(recovered, secret);
    }
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    const TEST_SHAMIR_ENTROPY: &[u8] = b"exo-identity-proptest-shamir-entropy";

    proptest! {
        #[test]
        fn any_k_of_n_reconstructs(
            secret in prop::collection::vec(any::<u8>(), 1..32),
            k in 1u8..6,
            extra in 0u8..4,
        ) {
            let n = k.saturating_add(extra).max(k);
            if n == 0 || k == 0 || k > n {
                return Ok(());
            }
            let config = ShamirConfig { threshold: k, shares: n };
            let shares = split_with_entropy(&secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
            let subset: Vec<Share> = shares.into_iter().take(usize::from(k)).collect();
            let recovered = reconstruct(&subset, &config).unwrap();
            prop_assert_eq!(recovered, secret);
        }

        #[test]
        fn fewer_than_k_fails(
            secret in prop::collection::vec(any::<u8>(), 1..16),
            k in 2u8..6,
        ) {
            let n = k.saturating_add(2);
            let config = ShamirConfig { threshold: k, shares: n };
            let shares = split_with_entropy(&secret, &config, TEST_SHAMIR_ENTROPY).unwrap();
            let subset: Vec<Share> = shares.into_iter().take(usize::from(k - 1)).collect();
            let result = reconstruct(&subset, &config);
            prop_assert!(result.is_err());
        }
    }
}
