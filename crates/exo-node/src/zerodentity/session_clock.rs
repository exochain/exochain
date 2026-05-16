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

//! Trusted 0dentity session clock boundary.

use std::sync::{Arc, Mutex};

use exo_core::{error::ExoError, hlc::HybridClock};

pub(crate) const TRUSTED_SESSION_CLOCK_UNAVAILABLE: &str =
    "Trusted 0dentity session clock unavailable";

#[derive(Clone)]
pub(crate) enum SessionClock {
    #[cfg_attr(not(test), allow(dead_code))]
    Trusted(Arc<Mutex<HybridClock>>),
    Unavailable,
}

impl SessionClock {
    #[must_use]
    pub(crate) fn unavailable() -> Self {
        Self::Unavailable
    }

    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn trusted(clock: HybridClock) -> Self {
        Self::Trusted(Arc::new(Mutex::new(clock)))
    }

    pub(crate) fn now_ms(&self) -> Result<u64, SessionClockError> {
        match self {
            Self::Unavailable => Err(SessionClockError::Unavailable),
            Self::Trusted(clock) => {
                let mut clock = clock.lock().map_err(|_| SessionClockError::LockPoisoned)?;
                clock
                    .now()
                    .map(|timestamp| timestamp.physical_ms)
                    .map_err(SessionClockError::Exhausted)
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum SessionClockError {
    Unavailable,
    LockPoisoned,
    Exhausted(ExoError),
}
