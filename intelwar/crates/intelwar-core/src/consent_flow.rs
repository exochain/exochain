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

//! Consent gate helpers for Living Log append (IW-1).

use exo_gatekeeper::{
    invariants::consent_scope_covers_permissions,
    types::{BailmentState, ConsentRecord, Permission, PermissionSet},
};
use exo_core::Did;

use crate::error::{IntelwarError, Result};

/// Canonical append permission string.
pub const LOG_APPEND_PERMISSION: &str = "log:append";

/// Evaluate whether bailment + consent records authorize Log append for actor.
pub fn consent_allows_log_append(
    actor: &Did,
    bailment_state: &BailmentState,
    consent_records: &[ConsentRecord],
) -> Result<()> {
    let (bailor, bailee, scope) = match bailment_state {
        BailmentState::Active {
            bailor,
            bailee,
            scope,
        } => (bailor, bailee, scope),
        _ => {
            return Err(IntelwarError::Consent {
                reason: "no active bailment for Living Log append".into(),
            });
        }
    };

    if bailee != actor {
        return Err(IntelwarError::Consent {
            reason: format!("bailment bailee {bailee} does not match actor {actor}"),
        });
    }

    let has_active = consent_records.iter().any(|c| {
        c.subject == *bailor && c.granted_to == *actor && c.scope == *scope && c.active
    });
    if !has_active {
        return Err(IntelwarError::Consent {
            reason: "no active consent record matching bailor, actor, and scope".into(),
        });
    }

    let requested = PermissionSet::new(vec![Permission::new(LOG_APPEND_PERMISSION)]);
    if !consent_scope_covers_permissions(scope, &requested) {
        return Err(IntelwarError::Consent {
            reason: format!(
                "consent scope '{scope}' does not cover '{LOG_APPEND_PERMISSION}'"
            ),
        });
    }

    Ok(())
}
