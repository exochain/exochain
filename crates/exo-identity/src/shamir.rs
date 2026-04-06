//! Shamir Secret Sharing over GF(256) for Sybil defense.
//!
//! Constant-time GF(256) field arithmetic to prevent timing side-channels.

use serde::{Deserialize, Serialize};

use crate::error::IdentityError;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    pub index: u8,
    pub data: Vec<u8>,
    pub commitment: [u8; 32],
}

/// Split a secret into `config.shares` shares, any `config.threshold` of which can reconstruct it.
pub fn split(secret: &[u8], config: &ShamirConfig) -> Result<Vec<Share>, IdentityError> {
    config.validate()?;

    let commitment: [u8; 32] = *blake3::hash(secret).as_bytes();
    let k: usize = config.threshold.into();
    let n: usize = config.shares.into();

    let mut shares: Vec<Share> = (1..=n)
        .map(|i| Share {
            #[allow(clippy::as_conversions)]
            index: i as u8,
            data: Vec::with_capacity(secret.len()),
            commitment,
        })
        .collect();

    let mut rng = rand::thread_rng();

    for &secret_byte in secret {
        let mut coeffs = vec![0u8; k];
        coeffs[0] = secret_byte;
        for coeff in coeffs.iter_mut().skip(1) {
            *coeff = rand::Rng::r#gen(&mut rng);
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

    for s in shares {
        if s.index == 0 {
            return Err(IdentityError::InvalidShareIndex(0));
        }
    }

    let mut seen = std::collections::BTreeSet::new();
    for s in shares {
        if !seen.insert(s.index) {
            return Err(IdentityError::DuplicateShareIndices);
        }
    }

    let used = &shares[..k];
    let secret_len = used[0].data.len();
    let mut secret = vec![0u8; secret_len];

    for (byte_idx, out_byte) in secret.iter_mut().enumerate().take(secret_len) {
        let mut value: u8 = 0;

        for (i, share_i) in used.iter().enumerate() {
            let xi = share_i.index;
            let yi = share_i.data[byte_idx];

            let mut basis: u8 = 1;
            for (j, share_j) in used.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = share_j.index;
                let num = xj;
                let den = xj ^ xi;
                basis = gf256_mul(basis, gf256_mul(num, gf256_inv(den)));
            }

            value ^= gf256_mul(yi, basis);
        }

        *out_byte = value;
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let shares = split(secret, &config).unwrap();
        assert_eq!(shares.len(), 3);

        for combo in [[0, 1], [0, 2], [1, 2]] {
            let subset: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
            let recovered = reconstruct(&subset, &config).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn split_and_reconstruct_3_of_5() {
        let secret = b"constitutional trust fabric";
        let config = ShamirConfig {
            threshold: 3,
            shares: 5,
        };
        let shares = split(secret, &config).unwrap();
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
        let shares = split(secret, &config).unwrap();
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
        let shares = split(secret, &config).unwrap();
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
        let shares = split(secret, &config).unwrap();
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

    #[test]
    fn commitment_matches_secret() {
        let secret = b"verify commitment";
        let config = ShamirConfig {
            threshold: 2,
            shares: 3,
        };
        let shares = split(secret, &config).unwrap();
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
        let shares = split(secret, &config).unwrap();
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
        let shares = split(secret, &config).unwrap();
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
        let shares = split(secret, &config).unwrap();
        let recovered = reconstruct(&shares, &config).unwrap();
        assert_eq!(recovered, secret);
    }
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    use super::*;

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
            let shares = split(&secret, &config).unwrap();
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
            let shares = split(&secret, &config).unwrap();
            let subset: Vec<Share> = shares.into_iter().take(usize::from(k - 1)).collect();
            let result = reconstruct(&subset, &config);
            prop_assert!(result.is_err());
        }
    }
}
