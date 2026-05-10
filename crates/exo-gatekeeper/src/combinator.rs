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

//! Combinator algebra engine.
//!
//! Provides a deterministic algebra for composing governance operations.
//! Every reduction is pure: same input always produces same output.

use std::{cell::Cell, collections::BTreeMap};

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::error::GatekeeperError;

// ---------------------------------------------------------------------------
// Combinator types
// ---------------------------------------------------------------------------

/// Maximum allowed nesting depth for a combinator tree.
pub const MAX_COMBINATOR_DEPTH: usize = 128;

/// Maximum children allowed in any sequence, parallel, or choice branch list.
pub const MAX_COMBINATOR_BRANCH_WIDTH: usize = 256;

/// Maximum total nodes allowed in a combinator tree.
pub const MAX_COMBINATOR_NODE_COUNT: usize = 10_000;

/// Maximum retry budget accepted for a retry combinator.
pub const MAX_RETRY_ATTEMPTS: u32 = 100;

/// A predicate that guards combinator execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Predicate {
    /// Name of the predicate (for tracing).
    pub name: String,
    /// The key in the input that must exist and be truthy.
    pub required_key: String,
    /// Expected value (if None, just check existence).
    pub expected_value: Option<String>,
}

impl Predicate {
    pub fn evaluate(&self, input: &CombinatorInput) -> bool {
        match input.fields.get(&self.required_key) {
            None => false,
            Some(val) => match &self.expected_value {
                None => true,
                Some(expected) => val == expected,
            },
        }
    }
}

/// A transform function applied to combinator output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformFn {
    /// Name of the transform (for tracing).
    pub name: String,
    /// Key to add to the output.
    pub output_key: String,
    /// Value to set.
    pub output_value: String,
}

/// Policy for retrying a combinator.
#[derive(Debug, Clone, Serialize)]
pub struct RetryPolicy {
    /// Maximum number of retries.
    pub max_retries: u32,
    /// Current attempt (used during reduction).
    pub current_attempt: u32,
}

impl RetryPolicy {
    fn validate(&self) -> Result<(), GatekeeperError> {
        if self.max_retries > MAX_RETRY_ATTEMPTS {
            return Err(GatekeeperError::CombinatorError(format!(
                "maximum retry budget exceeded: {} > {}",
                self.max_retries, MAX_RETRY_ATTEMPTS
            )));
        }
        if self.current_attempt > self.max_retries {
            return Err(GatekeeperError::CombinatorError(format!(
                "retry current_attempt {} exceeds max_retries {}",
                self.current_attempt, self.max_retries
            )));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct RetryPolicyProxy {
    max_retries: u32,
    current_attempt: u32,
}

impl<'de> Deserialize<'de> for RetryPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let proxy = RetryPolicyProxy::deserialize(deserializer)?;
        let policy = Self {
            max_retries: proxy.max_retries,
            current_attempt: proxy.current_attempt,
        };
        policy.validate().map_err(de::Error::custom)?;
        Ok(policy)
    }
}

/// A checkpoint identifier for resumable combinators.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CheckpointId(pub String);

/// Duration in milliseconds (deterministic, no floating-point).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Duration(pub u64);

/// The combinator algebra terms.
#[derive(Debug, Clone, Serialize)]
pub enum Combinator {
    /// Pass-through: returns the input as output.
    Identity,
    /// All must succeed in order.
    Sequence(Vec<Combinator>),
    /// All must succeed (order-independent; we process left-to-right).
    Parallel(Vec<Combinator>),
    /// First success wins.
    Choice(Vec<Combinator>),
    /// Proceed only if predicate holds.
    Guard(Box<Combinator>, Predicate),
    /// Modify the result of the inner combinator.
    Transform(Box<Combinator>, TransformFn),
    /// Retry with policy.
    Retry(Box<Combinator>, RetryPolicy),
    /// Time-bounded (simulated in deterministic mode).
    Timeout(Box<Combinator>, Duration),
    /// Resumable checkpoint.
    Checkpoint(Box<Combinator>, CheckpointId),
}

thread_local! {
    static COMBINATOR_DESERIALIZE_DEPTH: Cell<usize> = const { Cell::new(0) };
    static COMBINATOR_DESERIALIZE_NODE_COUNT: Cell<usize> = const { Cell::new(0) };
}

struct CombinatorDeserializeDepthGuard {
    is_root: bool,
}

impl Drop for CombinatorDeserializeDepthGuard {
    fn drop(&mut self) {
        COMBINATOR_DESERIALIZE_DEPTH.with(|depth| {
            depth.set(depth.get().saturating_sub(1));
        });
        if self.is_root {
            COMBINATOR_DESERIALIZE_NODE_COUNT.with(|nodes| {
                nodes.set(0);
            });
        }
    }
}

fn enter_combinator_deserialize_depth<E>() -> Result<CombinatorDeserializeDepthGuard, E>
where
    E: de::Error,
{
    COMBINATOR_DESERIALIZE_DEPTH.with(|depth| {
        let current = depth.get();
        let is_root = current == 0;
        if current > MAX_COMBINATOR_DEPTH {
            return Err(de::Error::custom(format!(
                "maximum combinator nesting depth exceeded during deserialization: {} > {}",
                current, MAX_COMBINATOR_DEPTH
            )));
        }
        COMBINATOR_DESERIALIZE_NODE_COUNT.with(|nodes| {
            if is_root {
                nodes.set(0);
            }
            let current_nodes = nodes.get();
            if current_nodes >= MAX_COMBINATOR_NODE_COUNT {
                return Err(de::Error::custom(format!(
                    "maximum combinator node count exceeded during deserialization: more than {}",
                    MAX_COMBINATOR_NODE_COUNT
                )));
            }
            nodes.set(current_nodes + 1);
            depth.set(current + 1);
            Ok(CombinatorDeserializeDepthGuard { is_root })
        })
    })
}

struct BoundedCombinators(Vec<Combinator>);

impl<'de> Deserialize<'de> for BoundedCombinators {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedCombinatorsVisitor)
    }
}

struct BoundedCombinatorsVisitor;

impl<'de> de::Visitor<'de> for BoundedCombinatorsVisitor {
    type Value = BoundedCombinators;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded combinator sequence")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        if seq
            .size_hint()
            .is_some_and(|hint| hint > MAX_COMBINATOR_BRANCH_WIDTH)
        {
            return Err(de::Error::custom(format!(
                "maximum combinator branch width exceeded: more than {}",
                MAX_COMBINATOR_BRANCH_WIDTH
            )));
        }

        let mut combinators = Vec::new();
        while let Some(combinator) = seq.next_element()? {
            if combinators.len() >= MAX_COMBINATOR_BRANCH_WIDTH {
                return Err(de::Error::custom(format!(
                    "maximum combinator branch width exceeded: more than {}",
                    MAX_COMBINATOR_BRANCH_WIDTH
                )));
            }
            combinators.push(combinator);
        }

        Ok(BoundedCombinators(combinators))
    }
}

#[derive(Deserialize)]
enum CombinatorProxy {
    Identity,
    Sequence(BoundedCombinators),
    Parallel(BoundedCombinators),
    Choice(BoundedCombinators),
    Guard(Box<Combinator>, Predicate),
    Transform(Box<Combinator>, TransformFn),
    Retry(Box<Combinator>, RetryPolicy),
    Timeout(Box<Combinator>, Duration),
    Checkpoint(Box<Combinator>, CheckpointId),
}

impl<'de> Deserialize<'de> for Combinator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let _depth_guard = enter_combinator_deserialize_depth::<D::Error>()?;
        let proxy = CombinatorProxy::deserialize(deserializer)?;
        Ok(match proxy {
            CombinatorProxy::Identity => Self::Identity,
            CombinatorProxy::Sequence(BoundedCombinators(combinators)) => {
                Self::Sequence(combinators)
            }
            CombinatorProxy::Parallel(BoundedCombinators(combinators)) => {
                Self::Parallel(combinators)
            }
            CombinatorProxy::Choice(BoundedCombinators(combinators)) => Self::Choice(combinators),
            CombinatorProxy::Guard(inner, predicate) => Self::Guard(inner, predicate),
            CombinatorProxy::Transform(inner, transform) => Self::Transform(inner, transform),
            CombinatorProxy::Retry(inner, policy) => Self::Retry(inner, policy),
            CombinatorProxy::Timeout(inner, duration) => Self::Timeout(inner, duration),
            CombinatorProxy::Checkpoint(inner, checkpoint_id) => {
                Self::Checkpoint(inner, checkpoint_id)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Input / Output envelopes
// ---------------------------------------------------------------------------

/// Typed input envelope for combinator reduction.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CombinatorInput {
    /// Key-value fields.
    pub fields: BTreeMap<String, String>,
}

impl CombinatorInput {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.insert(key.into(), value.into());
    }

    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.set(key, value);
        self
    }
}

/// Typed output envelope from combinator reduction.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CombinatorOutput {
    /// Key-value fields.
    pub fields: BTreeMap<String, String>,
    /// Checkpoint data if a checkpoint was reached.
    pub checkpoint: Option<CheckpointId>,
}

impl CombinatorOutput {
    #[must_use]
    pub fn from_input(input: &CombinatorInput) -> Self {
        Self {
            fields: input.fields.clone(),
            checkpoint: None,
        }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.insert(key.into(), value.into());
    }

    pub fn merge(&mut self, other: &CombinatorOutput) {
        for (k, v) in &other.fields {
            self.fields.insert(k.clone(), v.clone());
        }
        if other.checkpoint.is_some() {
            self.checkpoint.clone_from(&other.checkpoint);
        }
    }
}

// ---------------------------------------------------------------------------
// Reduction engine
// ---------------------------------------------------------------------------

/// Reduce a combinator with the given input.
///
/// Reduction is deterministic: same combinator + same input = same output.
pub fn reduce(
    combinator: &Combinator,
    input: &CombinatorInput,
) -> Result<CombinatorOutput, GatekeeperError> {
    validate_combinator_structure(combinator)?;
    reduce_inner(combinator, input, 0)
}

fn validate_combinator_structure(combinator: &Combinator) -> Result<(), GatekeeperError> {
    let mut stack = vec![(combinator, 0usize)];
    let mut node_count = 0usize;

    while let Some((current, depth)) = stack.pop() {
        if depth > MAX_COMBINATOR_DEPTH {
            return Err(GatekeeperError::CombinatorError(format!(
                "maximum combinator nesting depth exceeded: {} > {}",
                depth, MAX_COMBINATOR_DEPTH
            )));
        }

        if node_count >= MAX_COMBINATOR_NODE_COUNT {
            return Err(GatekeeperError::CombinatorError(format!(
                "maximum combinator node count exceeded: more than {}",
                MAX_COMBINATOR_NODE_COUNT
            )));
        }
        node_count += 1;

        match current {
            Combinator::Identity => {}
            Combinator::Sequence(combinators) => {
                enforce_branch_width("Sequence", combinators.len())?;
                for child in combinators.iter().rev() {
                    stack.push((child, depth + 1));
                }
            }
            Combinator::Parallel(combinators) => {
                enforce_branch_width("Parallel", combinators.len())?;
                for child in combinators.iter().rev() {
                    stack.push((child, depth + 1));
                }
            }
            Combinator::Choice(combinators) => {
                enforce_branch_width("Choice", combinators.len())?;
                for child in combinators.iter().rev() {
                    stack.push((child, depth + 1));
                }
            }
            Combinator::Guard(inner, _) | Combinator::Transform(inner, _) => {
                stack.push((inner, depth + 1));
            }
            Combinator::Retry(inner, policy) => {
                policy.validate()?;
                stack.push((inner, depth + 1));
            }
            Combinator::Timeout(inner, _) | Combinator::Checkpoint(inner, _) => {
                stack.push((inner, depth + 1));
            }
        }
    }

    Ok(())
}

fn reduce_inner(
    combinator: &Combinator,
    input: &CombinatorInput,
    depth: usize,
) -> Result<CombinatorOutput, GatekeeperError> {
    if depth > MAX_COMBINATOR_DEPTH {
        return Err(GatekeeperError::CombinatorError(format!(
            "maximum combinator nesting depth exceeded: {} > {}",
            depth, MAX_COMBINATOR_DEPTH
        )));
    }

    match combinator {
        Combinator::Identity => Ok(CombinatorOutput::from_input(input)),

        Combinator::Sequence(combinators) => {
            enforce_branch_width("Sequence", combinators.len())?;
            let mut current_input = input.clone();
            let mut last_output = CombinatorOutput::from_input(input);

            for (i, c) in combinators.iter().enumerate() {
                match reduce_inner(c, &current_input, depth + 1) {
                    Ok(output) => {
                        // Feed output as next input.
                        current_input = CombinatorInput {
                            fields: output.fields.clone(),
                        };
                        last_output = output;
                    }
                    Err(e) => {
                        return Err(GatekeeperError::CombinatorError(format!(
                            "Sequence step {} failed: {}",
                            i, e
                        )));
                    }
                }
            }
            Ok(last_output)
        }

        Combinator::Parallel(combinators) => {
            enforce_branch_width("Parallel", combinators.len())?;
            let mut merged = CombinatorOutput::from_input(input);

            for (i, c) in combinators.iter().enumerate() {
                match reduce_inner(c, input, depth + 1) {
                    Ok(output) => {
                        merged.merge(&output);
                    }
                    Err(e) => {
                        return Err(GatekeeperError::CombinatorError(format!(
                            "Parallel branch {} failed: {}",
                            i, e
                        )));
                    }
                }
            }
            Ok(merged)
        }

        Combinator::Choice(combinators) => {
            enforce_branch_width("Choice", combinators.len())?;
            for c in combinators {
                match reduce_inner(c, input, depth + 1) {
                    Ok(output) => return Ok(output),
                    Err(_) => continue,
                }
            }
            Err(GatekeeperError::CombinatorError(
                "Choice: all alternatives failed".into(),
            ))
        }

        Combinator::Guard(inner, predicate) => {
            if !predicate.evaluate(input) {
                return Err(GatekeeperError::CombinatorError(format!(
                    "Guard predicate '{}' failed",
                    predicate.name
                )));
            }
            reduce_inner(inner, input, depth + 1)
        }

        Combinator::Transform(inner, transform) => {
            let mut output = reduce_inner(inner, input, depth + 1)?;
            output.set(transform.output_key.clone(), transform.output_value.clone());
            Ok(output)
        }

        Combinator::Retry(inner, policy) => {
            policy.validate()?;
            let mut last_err = None;
            for attempt in 0..=policy.max_retries {
                match reduce_inner(inner, input, depth + 1) {
                    Ok(mut output) => {
                        output.set("retry_attempts", attempt.to_string());
                        return Ok(output);
                    }
                    Err(e) => {
                        last_err = Some(e);
                    }
                }
            }
            Err(last_err
                .unwrap_or_else(|| GatekeeperError::CombinatorError("Retry exhausted".into())))
        }

        Combinator::Timeout(inner, duration) => {
            // In deterministic mode, we simulate timeout by simply running.
            // Real timeout enforcement is at the Holon runtime level.
            let mut output = reduce_inner(inner, input, depth + 1)?;
            output.set("timeout_budget_ms", duration.0.to_string());
            Ok(output)
        }

        Combinator::Checkpoint(inner, checkpoint_id) => {
            let mut output = reduce_inner(inner, input, depth + 1)?;
            output.checkpoint = Some(checkpoint_id.clone());
            Ok(output)
        }
    }
}

fn enforce_branch_width(kind: &str, len: usize) -> Result<(), GatekeeperError> {
    if len > MAX_COMBINATOR_BRANCH_WIDTH {
        return Err(GatekeeperError::CombinatorError(format!(
            "maximum combinator branch width exceeded in {}: {} > {}",
            kind, len, MAX_COMBINATOR_BRANCH_WIDTH
        )));
    }
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> CombinatorInput {
        CombinatorInput::new()
            .with("name", "alice")
            .with("role", "judge")
    }

    fn branch_bounded_sequence(total_leaves: usize) -> Combinator {
        let mut remaining = total_leaves;
        let mut branches = Vec::new();
        while remaining > 0 {
            let chunk = remaining.min(MAX_COMBINATOR_BRANCH_WIDTH);
            branches.push(Combinator::Sequence(vec![Combinator::Identity; chunk]));
            remaining -= chunk;
        }
        Combinator::Sequence(branches)
    }

    fn branch_bounded_sequence_json(total_leaves: usize) -> String {
        let mut remaining = total_leaves;
        let mut json = String::from("{\"Sequence\":[");
        let mut outer_idx = 0;
        while remaining > 0 {
            if outer_idx > 0 {
                json.push(',');
            }
            let chunk = remaining.min(MAX_COMBINATOR_BRANCH_WIDTH);
            json.push_str("{\"Sequence\":[");
            for inner_idx in 0..chunk {
                if inner_idx > 0 {
                    json.push(',');
                }
                json.push_str("\"Identity\"");
            }
            json.push_str("]}");
            remaining -= chunk;
            outer_idx += 1;
        }
        json.push_str("]}");
        json
    }

    // --- Identity ---

    #[test]
    fn identity_passes_through() {
        let input = sample_input();
        let output = reduce(&Combinator::Identity, &input).unwrap();
        assert_eq!(output.fields, input.fields);
    }

    // --- Sequence ---

    #[test]
    fn sequence_empty_returns_input() {
        let input = sample_input();
        let output = reduce(&Combinator::Sequence(vec![]), &input).unwrap();
        assert_eq!(output.fields, input.fields);
    }

    #[test]
    fn sequence_chains_results() {
        let input = sample_input();
        let seq = Combinator::Sequence(vec![
            Combinator::Transform(
                Box::new(Combinator::Identity),
                TransformFn {
                    name: "add_step1".into(),
                    output_key: "step1".into(),
                    output_value: "done".into(),
                },
            ),
            Combinator::Transform(
                Box::new(Combinator::Identity),
                TransformFn {
                    name: "add_step2".into(),
                    output_key: "step2".into(),
                    output_value: "done".into(),
                },
            ),
        ]);
        let output = reduce(&seq, &input).unwrap();
        assert_eq!(output.fields.get("step1"), Some(&"done".to_string()));
        assert_eq!(output.fields.get("step2"), Some(&"done".to_string()));
    }

    #[test]
    fn sequence_fails_if_any_step_fails() {
        let input = sample_input();
        let seq = Combinator::Sequence(vec![
            Combinator::Identity,
            Combinator::Guard(
                Box::new(Combinator::Identity),
                Predicate {
                    name: "requires_admin".into(),
                    required_key: "admin".into(),
                    expected_value: None,
                },
            ),
        ]);
        let result = reduce(&seq, &input);
        assert!(result.is_err());
    }

    // --- Parallel ---

    #[test]
    fn parallel_merges_results() {
        let input = sample_input();
        let par = Combinator::Parallel(vec![
            Combinator::Transform(
                Box::new(Combinator::Identity),
                TransformFn {
                    name: "branch_a".into(),
                    output_key: "a".into(),
                    output_value: "1".into(),
                },
            ),
            Combinator::Transform(
                Box::new(Combinator::Identity),
                TransformFn {
                    name: "branch_b".into(),
                    output_key: "b".into(),
                    output_value: "2".into(),
                },
            ),
        ]);
        let output = reduce(&par, &input).unwrap();
        assert_eq!(output.fields.get("a"), Some(&"1".to_string()));
        assert_eq!(output.fields.get("b"), Some(&"2".to_string()));
    }

    #[test]
    fn parallel_fails_if_any_branch_fails() {
        let input = sample_input();
        let par = Combinator::Parallel(vec![
            Combinator::Identity,
            Combinator::Guard(
                Box::new(Combinator::Identity),
                Predicate {
                    name: "impossible".into(),
                    required_key: "nonexistent".into(),
                    expected_value: None,
                },
            ),
        ]);
        assert!(reduce(&par, &input).is_err());
    }

    // --- Choice ---

    #[test]
    fn choice_returns_first_success() {
        let input = sample_input();
        let choice = Combinator::Choice(vec![
            Combinator::Guard(
                Box::new(Combinator::Transform(
                    Box::new(Combinator::Identity),
                    TransformFn {
                        name: "fail_branch".into(),
                        output_key: "branch".into(),
                        output_value: "first".into(),
                    },
                )),
                Predicate {
                    name: "impossible".into(),
                    required_key: "nonexistent".into(),
                    expected_value: None,
                },
            ),
            Combinator::Transform(
                Box::new(Combinator::Identity),
                TransformFn {
                    name: "success_branch".into(),
                    output_key: "branch".into(),
                    output_value: "second".into(),
                },
            ),
        ]);
        let output = reduce(&choice, &input).unwrap();
        assert_eq!(output.fields.get("branch"), Some(&"second".to_string()));
    }

    #[test]
    fn choice_fails_if_all_alternatives_fail() {
        let input = sample_input();
        let guard = |key: &str| {
            Combinator::Guard(
                Box::new(Combinator::Identity),
                Predicate {
                    name: "fail".into(),
                    required_key: key.into(),
                    expected_value: None,
                },
            )
        };
        let choice = Combinator::Choice(vec![guard("x"), guard("y"), guard("z")]);
        assert!(reduce(&choice, &input).is_err());
    }

    // --- Guard ---

    #[test]
    fn guard_passes_when_predicate_holds() {
        let input = sample_input();
        let guarded = Combinator::Guard(
            Box::new(Combinator::Identity),
            Predicate {
                name: "has_name".into(),
                required_key: "name".into(),
                expected_value: None,
            },
        );
        assert!(reduce(&guarded, &input).is_ok());
    }

    #[test]
    fn guard_fails_when_predicate_does_not_hold() {
        let input = sample_input();
        let guarded = Combinator::Guard(
            Box::new(Combinator::Identity),
            Predicate {
                name: "has_admin".into(),
                required_key: "admin".into(),
                expected_value: None,
            },
        );
        assert!(reduce(&guarded, &input).is_err());
    }

    #[test]
    fn guard_checks_expected_value() {
        let input = sample_input();
        let guarded = Combinator::Guard(
            Box::new(Combinator::Identity),
            Predicate {
                name: "name_is_alice".into(),
                required_key: "name".into(),
                expected_value: Some("alice".into()),
            },
        );
        assert!(reduce(&guarded, &input).is_ok());

        let guarded_wrong = Combinator::Guard(
            Box::new(Combinator::Identity),
            Predicate {
                name: "name_is_bob".into(),
                required_key: "name".into(),
                expected_value: Some("bob".into()),
            },
        );
        assert!(reduce(&guarded_wrong, &input).is_err());
    }

    // --- Transform ---

    #[test]
    fn transform_adds_key_to_output() {
        let input = sample_input();
        let transformed = Combinator::Transform(
            Box::new(Combinator::Identity),
            TransformFn {
                name: "add_status".into(),
                output_key: "status".into(),
                output_value: "verified".into(),
            },
        );
        let output = reduce(&transformed, &input).unwrap();
        assert_eq!(output.fields.get("status"), Some(&"verified".to_string()));
        // Original fields preserved.
        assert_eq!(output.fields.get("name"), Some(&"alice".to_string()));
    }

    // --- Retry ---

    #[test]
    fn retry_succeeds_on_first_attempt_for_identity() {
        let input = sample_input();
        let retried = Combinator::Retry(
            Box::new(Combinator::Identity),
            RetryPolicy {
                max_retries: 3,
                current_attempt: 0,
            },
        );
        let output = reduce(&retried, &input).unwrap();
        assert_eq!(output.fields.get("retry_attempts"), Some(&"0".to_string()));
    }

    #[test]
    fn retry_exhausts_on_permanent_failure() {
        let input = sample_input();
        let retried = Combinator::Retry(
            Box::new(Combinator::Guard(
                Box::new(Combinator::Identity),
                Predicate {
                    name: "impossible".into(),
                    required_key: "nonexistent".into(),
                    expected_value: None,
                },
            )),
            RetryPolicy {
                max_retries: 2,
                current_attempt: 0,
            },
        );
        assert!(reduce(&retried, &input).is_err());
    }

    #[test]
    fn retry_rejects_excessive_retry_budget_before_looping() {
        let input = sample_input();
        let retried = Combinator::Retry(
            Box::new(Combinator::Guard(
                Box::new(Combinator::Identity),
                Predicate {
                    name: "impossible".into(),
                    required_key: "nonexistent".into(),
                    expected_value: None,
                },
            )),
            RetryPolicy {
                max_retries: 101,
                current_attempt: 0,
            },
        );

        let err = match reduce(&retried, &input) {
            Ok(output) => panic!("excessive retries must fail fast: {output:?}"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("maximum retry"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reduce_rejects_excessive_combinator_depth() {
        let input = sample_input();
        let mut combinator = Combinator::Identity;
        for _ in 0..129 {
            combinator = Combinator::Timeout(Box::new(combinator), Duration(1));
        }

        let err = match reduce(&combinator, &input) {
            Ok(output) => panic!("excessive depth must fail: {output:?}"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("maximum combinator nesting depth"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reduce_rejects_excessive_branch_width() {
        let input = sample_input();
        let combinator = Combinator::Sequence(vec![Combinator::Identity; 257]);

        let err = match reduce(&combinator, &input) {
            Ok(output) => panic!("excessive branch width must fail: {output:?}"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("maximum combinator branch width"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reduce_rejects_excessive_total_node_count() {
        let input = sample_input();
        let combinator = branch_bounded_sequence(MAX_COMBINATOR_NODE_COUNT + 1);

        let err = match reduce(&combinator, &input) {
            Ok(_) => panic!("excessive node count must fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("maximum combinator node count"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn combinator_deserialization_is_not_directly_derived() {
        let source = include_str!("combinator.rs");
        assert!(
            !source
                .contains("#[derive(Debug, Clone, Serialize, Deserialize)]\npub enum Combinator"),
            "Combinator deserialization must enforce structural limits"
        );
    }

    #[test]
    fn deserialization_rejects_excessive_branch_width() {
        let mut json = String::from("{\"Sequence\":[");
        for idx in 0..257 {
            if idx > 0 {
                json.push(',');
            }
            json.push_str("\"Identity\"");
        }
        json.push_str("]}");

        let err = match serde_json::from_str::<Combinator>(&json) {
            Ok(combinator) => panic!("wide sequence must be rejected: {combinator:?}"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("maximum combinator branch width"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn deserialization_rejects_excessive_total_node_count() {
        let json = branch_bounded_sequence_json(MAX_COMBINATOR_NODE_COUNT + 1);

        let err = match serde_json::from_str::<Combinator>(&json) {
            Ok(_) => panic!("oversized combinator tree must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("maximum combinator node count"),
            "unexpected error: {err}"
        );
    }

    // --- Timeout ---

    #[test]
    fn timeout_runs_inner_and_records_budget() {
        let input = sample_input();
        let timed = Combinator::Timeout(Box::new(Combinator::Identity), Duration(5000));
        let output = reduce(&timed, &input).unwrap();
        assert_eq!(
            output.fields.get("timeout_budget_ms"),
            Some(&"5000".to_string())
        );
    }

    // --- Checkpoint ---

    #[test]
    fn checkpoint_records_id_in_output() {
        let input = sample_input();
        let cp = Combinator::Checkpoint(
            Box::new(Combinator::Identity),
            CheckpointId("cp-001".into()),
        );
        let output = reduce(&cp, &input).unwrap();
        assert_eq!(output.checkpoint, Some(CheckpointId("cp-001".into())));
    }

    // --- Determinism ---

    #[test]
    fn reduction_is_deterministic() {
        let input = sample_input();
        let combinator = Combinator::Sequence(vec![
            Combinator::Transform(
                Box::new(Combinator::Identity),
                TransformFn {
                    name: "step1".into(),
                    output_key: "x".into(),
                    output_value: "1".into(),
                },
            ),
            Combinator::Checkpoint(Box::new(Combinator::Identity), CheckpointId("cp".into())),
        ]);

        let output1 = reduce(&combinator, &input).unwrap();
        let output2 = reduce(&combinator, &input).unwrap();
        assert_eq!(output1.fields, output2.fields);
        assert_eq!(output1.checkpoint, output2.checkpoint);
    }

    // --- Composition ---

    #[test]
    fn complex_composition() {
        let input = CombinatorInput::new()
            .with("authorized", "true")
            .with("user", "alice");

        let program = Combinator::Sequence(vec![
            Combinator::Guard(
                Box::new(Combinator::Identity),
                Predicate {
                    name: "is_authorized".into(),
                    required_key: "authorized".into(),
                    expected_value: Some("true".into()),
                },
            ),
            Combinator::Parallel(vec![
                Combinator::Transform(
                    Box::new(Combinator::Identity),
                    TransformFn {
                        name: "audit".into(),
                        output_key: "audited".into(),
                        output_value: "yes".into(),
                    },
                ),
                Combinator::Transform(
                    Box::new(Combinator::Identity),
                    TransformFn {
                        name: "log".into(),
                        output_key: "logged".into(),
                        output_value: "yes".into(),
                    },
                ),
            ]),
            Combinator::Checkpoint(Box::new(Combinator::Identity), CheckpointId("final".into())),
        ]);

        let output = reduce(&program, &input).unwrap();
        assert_eq!(output.fields.get("audited"), Some(&"yes".to_string()));
        assert_eq!(output.fields.get("logged"), Some(&"yes".to_string()));
        assert_eq!(output.checkpoint, Some(CheckpointId("final".into())));
    }

    // --- CombinatorInput helpers ---

    #[test]
    fn combinator_input_new_is_empty() {
        let input = CombinatorInput::new();
        assert!(input.fields.is_empty());
    }

    #[test]
    fn combinator_input_with_chaining() {
        let input = CombinatorInput::new().with("a", "1").with("b", "2");
        assert_eq!(input.fields.len(), 2);
    }

    // --- CombinatorOutput helpers ---

    #[test]
    fn combinator_output_merge() {
        let mut out1 = CombinatorOutput::default();
        out1.set("a", "1");
        let mut out2 = CombinatorOutput::default();
        out2.set("b", "2");
        out2.checkpoint = Some(CheckpointId("cp".into()));

        out1.merge(&out2);
        assert_eq!(out1.fields.get("a"), Some(&"1".to_string()));
        assert_eq!(out1.fields.get("b"), Some(&"2".to_string()));
        assert_eq!(out1.checkpoint, Some(CheckpointId("cp".into())));
    }

    // --- Predicate ---

    #[test]
    fn predicate_evaluate_missing_key() {
        let input = CombinatorInput::new();
        let pred = Predicate {
            name: "test".into(),
            required_key: "missing".into(),
            expected_value: None,
        };
        assert!(!pred.evaluate(&input));
    }

    #[test]
    fn predicate_evaluate_key_exists_no_value_check() {
        let input = CombinatorInput::new().with("key", "anything");
        let pred = Predicate {
            name: "test".into(),
            required_key: "key".into(),
            expected_value: None,
        };
        assert!(pred.evaluate(&input));
    }

    #[test]
    fn predicate_evaluate_value_mismatch() {
        let input = CombinatorInput::new().with("key", "actual");
        let pred = Predicate {
            name: "test".into(),
            required_key: "key".into(),
            expected_value: Some("expected".into()),
        };
        assert!(!pred.evaluate(&input));
    }

    // --- Parallel empty ---

    #[test]
    fn parallel_empty_returns_input() {
        let input = sample_input();
        let output = reduce(&Combinator::Parallel(vec![]), &input).unwrap();
        assert_eq!(output.fields, input.fields);
    }

    // --- Choice single ---

    #[test]
    fn choice_single_returns_it() {
        let input = sample_input();
        let choice = Combinator::Choice(vec![Combinator::Identity]);
        let output = reduce(&choice, &input).unwrap();
        assert_eq!(output.fields, input.fields);
    }
}
