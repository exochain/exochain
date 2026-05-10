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

//! Invariant checking primitives for EXOCHAIN.
//!
//! Every operation in the system must pass a set of invariants before it
//! is committed.  This module provides the trait, context, and set
//! abstractions to express and enforce those invariants.

use serde::{Deserialize, Serialize};

use crate::{
    error::{ExoError, Result},
    types::{DeterministicMap, Did, Hash256, Timestamp},
};

// ---------------------------------------------------------------------------
// InvariantViolation
// ---------------------------------------------------------------------------

/// A detailed report of a single invariant violation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantViolation {
    /// Human-readable name of the violated invariant.
    pub invariant_name: String,
    /// Description of what went wrong.
    pub description: String,
    /// Severity level.
    pub severity: ViolationSeverity,
    /// Optional context key-value pairs for diagnostics.
    pub context: DeterministicMap<String, String>,
}

/// Severity of an invariant violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Advisory — logged but does not block.
    Warning,
    /// Blocks the current operation.
    Error,
    /// Critical system integrity issue.
    Critical,
}

impl core::fmt::Display for ViolationSeverity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ViolationSeverity::Warning => write!(f, "WARNING"),
            ViolationSeverity::Error => write!(f, "ERROR"),
            ViolationSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ---------------------------------------------------------------------------
// InvariantContext
// ---------------------------------------------------------------------------

/// Snapshot of current state available to invariant checks.
#[derive(Clone, Debug)]
pub struct InvariantContext {
    /// The actor performing the current operation.
    pub actor_did: Did,
    /// The current HLC timestamp.
    pub timestamp: Timestamp,
    /// The hash of the current state being validated.
    pub state_hash: Hash256,
    /// Arbitrary string properties for flexible invariant checking.
    pub properties: DeterministicMap<String, String>,
}

impl InvariantContext {
    /// Create a new context.
    #[must_use]
    pub fn new(actor_did: Did, timestamp: Timestamp, state_hash: Hash256) -> Self {
        Self {
            actor_did,
            timestamp,
            state_hash,
            properties: DeterministicMap::new(),
        }
    }

    /// Add a property to the context.
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }

    /// Retrieve a property.
    #[must_use]
    pub fn get_property(&self, key: &str) -> Option<&String> {
        self.properties.get(&key.to_owned())
    }
}

// ---------------------------------------------------------------------------
// Invariant trait
// ---------------------------------------------------------------------------

/// A single invariant that can be checked against a context.
pub trait Invariant: core::fmt::Debug {
    /// The name of this invariant for reporting.
    fn name(&self) -> &str;

    /// Check the invariant.  Return `Ok(())` if it holds, or an
    /// `InvariantViolation` describing the failure.
    fn check(&self, context: &InvariantContext) -> core::result::Result<(), InvariantViolation>;
}

// ---------------------------------------------------------------------------
// InvariantSet
// ---------------------------------------------------------------------------

/// A collection of invariants that must all pass.
pub struct InvariantSet {
    invariants: Vec<Box<dyn Invariant>>,
}

impl InvariantSet {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            invariants: Vec::new(),
        }
    }

    /// Add an invariant to the set.
    pub fn add(&mut self, invariant: impl Invariant + 'static) {
        self.invariants.push(Box::new(invariant));
    }

    /// Number of invariants in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.invariants.len()
    }

    /// Is the set empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.invariants.is_empty()
    }

    /// Check all invariants, collecting every violation.
    ///
    /// Returns `Ok(())` if all invariants pass, or `Err` with the first
    /// blocking violation found.
    pub fn check_all(&self, context: &InvariantContext) -> Result<()> {
        for inv in &self.invariants {
            if let Err(violation) = inv.check(context) {
                return Err(ExoError::InvariantViolation {
                    description: format!(
                        "[{}] {}: {}",
                        violation.severity, violation.invariant_name, violation.description
                    ),
                });
            }
        }
        Ok(())
    }

    /// Check all invariants and return all violations (does not short-circuit).
    #[must_use]
    pub fn check_all_collect(&self, context: &InvariantContext) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();
        for inv in &self.invariants {
            if let Err(v) = inv.check(context) {
                violations.push(v);
            }
        }
        violations
    }
}

impl Default for InvariantSet {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for InvariantSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InvariantSet")
            .field("count", &self.invariants.len())
            .finish()
    }
}

/// Convenience function: check all invariants in a set against a context.
///
/// # Errors
///
/// Returns `ExoError::InvariantViolation` on the first failure.
pub fn check_all(invariants: &InvariantSet, context: &InvariantContext) -> Result<()> {
    invariants.check_all(context)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Did, Hash256, Timestamp};

    // -- Test invariant implementations ------------------------------------

    /// An invariant that always passes.
    #[derive(Debug)]
    struct AlwaysPass;

    impl Invariant for AlwaysPass {
        fn name(&self) -> &str {
            "always_pass"
        }

        fn check(
            &self,
            _context: &InvariantContext,
        ) -> core::result::Result<(), InvariantViolation> {
            Ok(())
        }
    }

    /// An invariant that always fails.
    #[derive(Debug)]
    struct AlwaysFail {
        severity: ViolationSeverity,
    }

    impl Invariant for AlwaysFail {
        fn name(&self) -> &str {
            "always_fail"
        }

        fn check(
            &self,
            _context: &InvariantContext,
        ) -> core::result::Result<(), InvariantViolation> {
            Err(InvariantViolation {
                invariant_name: self.name().to_string(),
                description: "this always fails".to_string(),
                severity: self.severity,
                context: DeterministicMap::new(),
            })
        }
    }

    /// An invariant that checks a property value.
    #[derive(Debug)]
    struct RequireProperty {
        key: String,
        expected: String,
    }

    impl Invariant for RequireProperty {
        fn name(&self) -> &str {
            "require_property"
        }

        fn check(
            &self,
            context: &InvariantContext,
        ) -> core::result::Result<(), InvariantViolation> {
            match context.get_property(&self.key) {
                Some(v) if v == &self.expected => Ok(()),
                Some(v) => {
                    let mut ctx = DeterministicMap::new();
                    ctx.insert("expected".to_string(), self.expected.clone());
                    ctx.insert("actual".to_string(), v.clone());
                    Err(InvariantViolation {
                        invariant_name: self.name().to_string(),
                        description: format!("property '{}' mismatch", self.key),
                        severity: ViolationSeverity::Error,
                        context: ctx,
                    })
                }
                None => Err(InvariantViolation {
                    invariant_name: self.name().to_string(),
                    description: format!("property '{}' missing", self.key),
                    severity: ViolationSeverity::Error,
                    context: DeterministicMap::new(),
                }),
            }
        }
    }

    fn test_context() -> InvariantContext {
        InvariantContext::new(
            Did::new("did:exo:tester").expect("valid"),
            Timestamp::new(1000, 0),
            Hash256::ZERO,
        )
    }

    // -- InvariantViolation ------------------------------------------------

    #[test]
    fn violation_serde_roundtrip() {
        let v = InvariantViolation {
            invariant_name: "test".into(),
            description: "something broke".into(),
            severity: ViolationSeverity::Critical,
            context: DeterministicMap::new(),
        };
        let json = serde_json::to_string(&v).expect("ser");
        let v2: InvariantViolation = serde_json::from_str(&json).expect("de");
        assert_eq!(v, v2);
    }

    #[test]
    fn violation_severity_display() {
        assert_eq!(ViolationSeverity::Warning.to_string(), "WARNING");
        assert_eq!(ViolationSeverity::Error.to_string(), "ERROR");
        assert_eq!(ViolationSeverity::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn violation_severity_ord() {
        assert!(ViolationSeverity::Warning < ViolationSeverity::Error);
        assert!(ViolationSeverity::Error < ViolationSeverity::Critical);
    }

    // -- InvariantContext ---------------------------------------------------

    #[test]
    fn context_new() {
        let ctx = test_context();
        assert_eq!(ctx.actor_did.as_str(), "did:exo:tester");
        assert_eq!(ctx.timestamp, Timestamp::new(1000, 0));
        assert_eq!(ctx.state_hash, Hash256::ZERO);
        assert!(ctx.properties.is_empty());
    }

    #[test]
    fn context_set_get_property() {
        let mut ctx = test_context();
        ctx.set_property("role", "admin");
        assert_eq!(ctx.get_property("role"), Some(&"admin".to_string()));
        assert_eq!(ctx.get_property("missing"), None);
    }

    // -- Invariant implementations -----------------------------------------

    #[test]
    fn always_pass_passes() {
        let inv = AlwaysPass;
        assert_eq!(inv.name(), "always_pass");
        let ctx = test_context();
        assert!(inv.check(&ctx).is_ok());
    }

    #[test]
    fn always_fail_fails() {
        let inv = AlwaysFail {
            severity: ViolationSeverity::Error,
        };
        let ctx = test_context();
        let err = inv.check(&ctx).unwrap_err();
        assert_eq!(err.invariant_name, "always_fail");
        assert_eq!(err.severity, ViolationSeverity::Error);
    }

    #[test]
    fn require_property_pass() {
        let inv = RequireProperty {
            key: "mode".into(),
            expected: "production".into(),
        };
        let mut ctx = test_context();
        ctx.set_property("mode", "production");
        assert!(inv.check(&ctx).is_ok());
    }

    #[test]
    fn require_property_mismatch() {
        let inv = RequireProperty {
            key: "mode".into(),
            expected: "production".into(),
        };
        let mut ctx = test_context();
        ctx.set_property("mode", "debug");
        let err = inv.check(&ctx).unwrap_err();
        assert!(err.description.contains("mismatch"));
        assert!(err.context.contains_key(&"expected".to_string()));
        assert!(err.context.contains_key(&"actual".to_string()));
    }

    #[test]
    fn require_property_missing() {
        let inv = RequireProperty {
            key: "mode".into(),
            expected: "production".into(),
        };
        let ctx = test_context();
        let err = inv.check(&ctx).unwrap_err();
        assert!(err.description.contains("missing"));
    }

    // -- InvariantSet ------------------------------------------------------

    #[test]
    fn empty_set_passes() {
        let set = InvariantSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        let ctx = test_context();
        assert!(set.check_all(&ctx).is_ok());
        assert!(set.check_all_collect(&ctx).is_empty());
    }

    #[test]
    fn set_all_pass() {
        let mut set = InvariantSet::new();
        set.add(AlwaysPass);
        set.add(AlwaysPass);
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
        let ctx = test_context();
        assert!(set.check_all(&ctx).is_ok());
        assert!(set.check_all_collect(&ctx).is_empty());
    }

    #[test]
    fn set_one_fails() {
        let mut set = InvariantSet::new();
        set.add(AlwaysPass);
        set.add(AlwaysFail {
            severity: ViolationSeverity::Critical,
        });
        set.add(AlwaysPass);
        let ctx = test_context();
        let err = set.check_all(&ctx).unwrap_err();
        assert!(matches!(err, ExoError::InvariantViolation { .. }));
    }

    #[test]
    fn set_collect_all_violations() {
        let mut set = InvariantSet::new();
        set.add(AlwaysFail {
            severity: ViolationSeverity::Warning,
        });
        set.add(AlwaysPass);
        set.add(AlwaysFail {
            severity: ViolationSeverity::Critical,
        });
        let ctx = test_context();
        let violations = set.check_all_collect(&ctx);
        assert_eq!(violations.len(), 2);
        assert_eq!(violations[0].severity, ViolationSeverity::Warning);
        assert_eq!(violations[1].severity, ViolationSeverity::Critical);
    }

    #[test]
    fn check_all_function() {
        let mut set = InvariantSet::new();
        set.add(AlwaysPass);
        let ctx = test_context();
        assert!(check_all(&set, &ctx).is_ok());

        let mut failing = InvariantSet::new();
        failing.add(AlwaysFail {
            severity: ViolationSeverity::Error,
        });
        let err = check_all(&failing, &ctx).unwrap_err();
        assert!(matches!(err, ExoError::InvariantViolation { .. }));
    }

    #[test]
    fn set_default() {
        let set = InvariantSet::default();
        assert!(set.is_empty());
    }

    #[test]
    fn set_debug() {
        let mut set = InvariantSet::new();
        set.add(AlwaysPass);
        let dbg = format!("{set:?}");
        assert!(dbg.contains("InvariantSet"));
        assert!(dbg.contains("1"));
    }

    #[test]
    fn set_with_property_check() {
        let mut set = InvariantSet::new();
        set.add(RequireProperty {
            key: "consent".into(),
            expected: "granted".into(),
        });

        // Fails without property
        let ctx = test_context();
        assert!(set.check_all(&ctx).is_err());

        // Passes with correct property
        let mut ctx2 = test_context();
        ctx2.set_property("consent", "granted");
        assert!(set.check_all(&ctx2).is_ok());
    }

    #[test]
    fn violation_context_is_deterministic() {
        let inv = RequireProperty {
            key: "x".into(),
            expected: "y".into(),
        };
        let mut ctx = test_context();
        ctx.set_property("x", "wrong");
        let v1 = inv.check(&ctx).unwrap_err();
        let v2 = inv.check(&ctx).unwrap_err();
        assert_eq!(v1, v2);
    }
}
