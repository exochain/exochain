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

//! Consume-once reserve / commit / release around a mandate hash.

use std::collections::BTreeMap;

use exo_core::{Hash256, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::{PdpError, Result};

/// Lifecycle of a consume-once mandate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    Reserved,
    Committed,
    Released,
}

/// A single reservation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    pub mandate_hash: Hash256,
    pub state: ReservationState,
    pub created: Timestamp,
}

/// Book of consume-once reservations keyed by mandate hash.
#[derive(Debug, Default)]
pub struct ReservationBook {
    entries: BTreeMap<Hash256, Reservation>,
}

impl ReservationBook {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve a mandate. Fails if already reserved or committed.
    pub fn reserve(&mut self, mandate_hash: Hash256, now: Timestamp) -> Result<()> {
        match self.entries.get(&mandate_hash) {
            Some(r) if r.state == ReservationState::Released => {}
            Some(r) if r.state == ReservationState::Committed => {
                return Err(PdpError::AlreadyConsumed);
            }
            Some(_) => return Err(PdpError::AlreadyReserved),
            None => {}
        }
        self.entries.insert(
            mandate_hash,
            Reservation {
                mandate_hash,
                state: ReservationState::Reserved,
                created: now,
            },
        );
        Ok(())
    }

    /// Commit a reserved mandate (consume-once).
    pub fn commit(&mut self, mandate_hash: &Hash256) -> Result<()> {
        let entry = self
            .entries
            .get_mut(mandate_hash)
            .ok_or_else(|| PdpError::ReservationNotFound(mandate_hash.to_string()))?;
        if entry.state != ReservationState::Reserved {
            return Err(PdpError::ReservationState);
        }
        entry.state = ReservationState::Committed;
        Ok(())
    }

    /// Release a reservation so the mandate may be retried.
    pub fn release(&mut self, mandate_hash: &Hash256) -> Result<()> {
        let entry = self
            .entries
            .get_mut(mandate_hash)
            .ok_or_else(|| PdpError::ReservationNotFound(mandate_hash.to_string()))?;
        if entry.state == ReservationState::Committed {
            return Err(PdpError::AlreadyConsumed);
        }
        entry.state = ReservationState::Released;
        Ok(())
    }

    #[must_use]
    pub fn get(&self, mandate_hash: &Hash256) -> Option<&Reservation> {
        self.entries.get(mandate_hash)
    }

    #[must_use]
    pub fn is_consumed(&self, mandate_hash: &Hash256) -> bool {
        matches!(
            self.entries.get(mandate_hash).map(|r| r.state),
            Some(ReservationState::Committed)
        )
    }

    #[must_use]
    pub fn is_reserved(&self, mandate_hash: &Hash256) -> bool {
        matches!(
            self.entries.get(mandate_hash).map(|r| r.state),
            Some(ReservationState::Reserved)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Hash256 {
        Hash256::digest(s.as_bytes())
    }
    fn ts() -> Timestamp {
        Timestamp::new(1, 0)
    }

    #[test]
    fn reserve_commit() {
        let mut b = ReservationBook::new();
        let id = h("m");
        b.reserve(id, ts()).unwrap();
        assert!(b.is_reserved(&id));
        b.commit(&id).unwrap();
        assert!(b.is_consumed(&id));
    }

    #[test]
    fn double_reserve_fails() {
        let mut b = ReservationBook::new();
        let id = h("m");
        b.reserve(id, ts()).unwrap();
        assert_eq!(b.reserve(id, ts()), Err(PdpError::AlreadyReserved));
    }

    #[test]
    fn release_then_rereserve() {
        let mut b = ReservationBook::new();
        let id = h("m");
        b.reserve(id, ts()).unwrap();
        b.release(&id).unwrap();
        assert!(b.reserve(id, ts()).is_ok());
    }

    #[test]
    fn cannot_release_committed() {
        let mut b = ReservationBook::new();
        let id = h("m");
        b.reserve(id, ts()).unwrap();
        b.commit(&id).unwrap();
        assert_eq!(b.release(&id), Err(PdpError::AlreadyConsumed));
    }
}
