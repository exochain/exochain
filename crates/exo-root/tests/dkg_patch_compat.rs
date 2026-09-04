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

//! Patch-release source compatibility checks for the public DKG data model.
//!
//! This is an integration test deliberately compiled as an external consumer.

use std::collections::BTreeMap;

use exo_root::{
    GenesisCeremonyConfig, RootDkgOutput, RootDkgRound1Output, RootDkgRound2Output, RootKeyPackage,
    RootParticipantDkgOutput, RootPublicKeyPackage, dkg_finalize_participant,
};

fn assert_clone<T: Clone>() {}

type LegacyFinalizeFn = fn(
    &GenesisCeremonyConfig,
    u16,
    &[u8],
    BTreeMap<u16, Vec<u8>>,
    BTreeMap<u16, Vec<u8>>,
) -> exo_root::Result<RootParticipantDkgOutput>;

const LEGACY_FINALIZE: LegacyFinalizeFn = dkg_finalize_participant;

#[test]
fn legacy_vec_struct_literals_and_clone_bounds_still_compile() {
    assert_clone::<RootKeyPackage>();
    assert_clone::<RootDkgOutput>();
    assert_clone::<RootDkgRound1Output>();
    assert_clone::<RootDkgRound2Output>();
    assert_clone::<RootParticipantDkgOutput>();

    let key_package = RootKeyPackage {
        frost_identifier: 1,
        key_package: vec![1, 2, 3],
    };
    let key_bytes: Vec<u8> = key_package.key_package.clone();
    assert_eq!(key_bytes, vec![1, 2, 3]);

    let round1 = RootDkgRound1Output {
        frost_identifier: 1,
        round1_secret_package: vec![4, 5, 6],
        round1_package: vec![7, 8, 9],
    };
    let round1_secret: Vec<u8> = round1.round1_secret_package.clone();
    assert_eq!(round1_secret, vec![4, 5, 6]);

    let round2 = RootDkgRound2Output {
        frost_identifier: 1,
        round2_secret_package: vec![10, 11, 12],
        round2_packages: BTreeMap::from([(2, vec![13, 14, 15])]),
    };
    let round2_secret: Vec<u8> = round2.round2_secret_package.clone();
    let recipient_packages: BTreeMap<u16, Vec<u8>> = round2.round2_packages.clone();
    assert_eq!(round2_secret, vec![10, 11, 12]);
    assert_eq!(recipient_packages[&2], vec![13, 14, 15]);

    let public_key_package = RootPublicKeyPackage {
        public_key_package: vec![16],
        root_public_key: vec![17],
        verifying_shares: BTreeMap::from([(1, vec![18])]),
    };
    let dkg = RootDkgOutput {
        key_packages: BTreeMap::from([(1, key_package.clone())]),
        public_key_package: public_key_package.clone(),
    };
    let participant = RootParticipantDkgOutput {
        key_package,
        public_key_package,
    };

    assert_eq!(dkg.clone(), dkg);
    assert_eq!(round1.clone(), round1);
    assert_eq!(round2.clone(), round2);
    assert_eq!(participant.clone(), participant);
}

// The body need not execute: compiling it proves the 0.2.5 caller-owned map
// shape remains accepted by the public 0.2.6 finalization function.
#[allow(dead_code)]
fn finalize_with_legacy_vec_map(
    config: &GenesisCeremonyConfig,
    frost_identifier: u16,
    round2_secret_package: &[u8],
    round1_packages: BTreeMap<u16, Vec<u8>>,
    round2_packages: BTreeMap<u16, Vec<u8>>,
) -> exo_root::Result<RootParticipantDkgOutput> {
    LEGACY_FINALIZE(
        config,
        frost_identifier,
        round2_secret_package,
        round1_packages,
        round2_packages,
    )
}
