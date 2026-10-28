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

//! Exhaustive check of the BCTS lifecycle in `Transaction::transition`.
//!
//! The state space is the 14 `BctsState` values. This test explores every
//! path `Transaction::transition` actually accepts and requires that every
//! path from `Draft` to `Executed` has already passed identity resolution,
//! consent validation, deliberation, verification, governance, and approval.

#![allow(clippy::expect_used)]

use std::{
    collections::{BTreeSet, VecDeque},
    sync::atomic::{AtomicU64, Ordering},
};

use exo_core::{
    bcts::{
        BailmentTransaction, BctsState, BctsTransitionAdjudicator, BctsTransitionRequest,
        Transaction,
    },
    error::ExoError,
    hlc::HybridClock,
    types::{CorrelationId, Did},
};

const GATES: [BctsState; 6] = [
    BctsState::IdentityResolved,
    BctsState::ConsentValidated,
    BctsState::Deliberated,
    BctsState::Verified,
    BctsState::Governed,
    BctsState::Approved,
];

const ALL_GATES: u8 = (1 << GATES.len()) - 1;

struct AllowAllAdjudicator;

impl BctsTransitionAdjudicator for AllowAllAdjudicator {
    fn adjudicate_transition(
        &self,
        _request: &BctsTransitionRequest,
    ) -> exo_core::error::Result<()> {
        Ok(())
    }
}

fn states() -> [BctsState; 14] {
    use BctsState::{
        Approved, Closed, ConsentValidated, Deliberated, Denied, Draft, Escalated, Executed,
        Governed, IdentityResolved, Recorded, Remediated, Submitted, Verified,
    };
    [
        Draft,
        Submitted,
        IdentityResolved,
        ConsentValidated,
        Deliberated,
        Verified,
        Governed,
        Approved,
        Executed,
        Recorded,
        Closed,
        Denied,
        Escalated,
        Remediated,
    ]
}

fn gate_bit(state: BctsState) -> Option<u8> {
    GATES
        .iter()
        .position(|gate| *gate == state)
        .map(|index| u8::try_from(index).expect("gate index fits in u8"))
}

fn missing_gates(mask: u8) -> String {
    GATES
        .iter()
        .enumerate()
        .filter(|(index, _)| mask & (1 << index) == 0)
        .map(|(_, gate)| gate.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn path_text(path: &[BctsState]) -> String {
    path.iter()
        .map(|state| state.as_str())
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn explore() -> Result<(), String> {
    let actor = Did::new("did:exo:formal-bcts").expect("formal actor DID");
    let mut clock = HybridClock::with_wall_clock({
        let ticks = AtomicU64::new(1_000);
        move || ticks.fetch_add(1, Ordering::Relaxed)
    });
    let adjudicator = AllowAllAdjudicator;
    let start = Transaction::new(CorrelationId::from_uuid(uuid::Uuid::from_u128(1)));
    let mut queue = VecDeque::from([(start, 0_u8, vec![BctsState::Draft])]);
    let mut seen = BTreeSet::new();
    let mut reached_executed_with_all_gates = false;

    while let Some((tx, mask, path)) = queue.pop_front() {
        let state = tx.state();
        if !seen.insert((state, mask)) {
            continue;
        }
        if state == BctsState::Executed {
            if mask != ALL_GATES {
                return Err(format!(
                    "path {} reaches Executed without {}",
                    path_text(&path),
                    missing_gates(mask)
                ));
            }
            reached_executed_with_all_gates = true;
        }

        for target in states() {
            let mut next = tx.clone();
            match next.transition(target, &actor, &mut clock, &adjudicator) {
                Ok(_) => {
                    if next.state() != target {
                        return Err(format!(
                            "transition to {} left the transaction in {}",
                            target.as_str(),
                            next.state().as_str()
                        ));
                    }
                    let mut next_mask = mask;
                    if let Some(bit) = gate_bit(target) {
                        next_mask |= 1 << bit;
                    }
                    let mut next_path = path.clone();
                    next_path.push(target);
                    queue.push_back((next, next_mask, next_path));
                }
                Err(ExoError::InvalidTransition { .. }) => {}
                Err(error) => {
                    return Err(format!(
                        "transition {} -> {} failed outside the state machine: {error}",
                        state.as_str(),
                        target.as_str()
                    ));
                }
            }
        }
    }

    if !reached_executed_with_all_gates {
        return Err(
            "no path from Draft reaches Executed after IdentityResolved, ConsentValidated, Deliberated, Verified, Governed, and Approved"
                .to_string(),
        );
    }
    Ok(())
}

#[test]
fn every_path_to_executed_passed_identity_consent_and_governance() {
    let result = explore();
    assert!(result.is_ok(), "{result:?}");
}
