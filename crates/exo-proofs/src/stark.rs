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

//! STARK proof system -- hash-based, post-quantum.
//!
//! Uses blake3 for all commitments (no elliptic curves).
//! This is a pedagogical implementation demonstrating the STARK structure.

use std::collections::BTreeSet;

use exo_core::{
    hash::{merkle_proof, merkle_root, verify_merkle_proof},
    types::Hash256,
};
use serde::{Deserialize, Serialize};

use crate::error::{ProofError, Result};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for STARK proof generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkConfig {
    /// Size of the field (we use u64 arithmetic modulo this).
    pub field_size: u64,
    /// Expansion factor for the low-degree extension.
    pub expansion_factor: usize,
    /// Number of query rounds for soundness.
    pub num_queries: usize,
}

impl StarkConfig {
    /// Default configuration suitable for testing.
    #[must_use]
    pub fn default_config() -> Self {
        Self {
            field_size: (1u64 << 31) - 1, // Mersenne prime 2^31 - 1
            expansion_factor: 4,
            num_queries: 8,
        }
    }
}

// ---------------------------------------------------------------------------
// Constraint
// ---------------------------------------------------------------------------

/// A STARK constraint over the execution trace.
///
/// Constraints are transition rules: given `row[i]` and `row[i+1]`,
/// the constraint function must evaluate to 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarkConstraint {
    /// Human-readable name.
    pub name: String,
    /// Indices of columns involved in this constraint.
    pub column_indices: Vec<usize>,
    /// Coefficients for a polynomial constraint.
    /// Format: pairs of (current_row_coeff, next_row_coeff) per column.
    /// The constraint is: `sum(current_coeff[i] * trace[row][col_i] + next_coeff[i] * trace[row+1][col_i]) == 0`
    pub coefficients: Vec<(u64, u64)>,
}

// ---------------------------------------------------------------------------
// FRI Proof
// ---------------------------------------------------------------------------

/// A FRI (Fast Reed-Solomon IOP of Proximity) proof component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriProof {
    /// Commitment hashes at each folding round.
    pub layer_commitments: Vec<Hash256>,
    /// Query responses at each layer.
    pub query_values: Vec<Vec<u64>>,
}

/// Merkle-authenticated trace row opened by a STARK query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceQueryProof {
    /// Query index in the committed trace.
    pub index: usize,
    /// Trace row value at `index`.
    pub row: Vec<u64>,
    /// Merkle authentication path from `hash_row(row)` to the trace root.
    pub authentication_path: Vec<Hash256>,
    /// Trace row value at `index + 1`, used for transition constraints.
    pub next_row: Vec<u64>,
    /// Merkle authentication path from `hash_row(next_row)` to the trace root.
    pub next_authentication_path: Vec<Hash256>,
}

// ---------------------------------------------------------------------------
// StarkProof
// ---------------------------------------------------------------------------

/// A complete STARK proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarkProof {
    /// Commitment to the execution trace.
    pub trace_commitment: Hash256,
    /// Commitment to the constraint polynomial.
    pub constraint_commitment: Hash256,
    /// Query indices (deterministic, derived from commitments).
    pub query_indices: Vec<usize>,
    /// FRI proof of low degree.
    pub fri_proof: FriProof,
    /// Configuration used.
    pub config: StarkConfig,
    /// Number of rows in the trace (needed for verification).
    pub trace_length: usize,
    /// Hash of the public inputs (first row of trace) for verification.
    pub public_input_hash: Hash256,
    /// Public transition constraints for the statement being proven.
    pub constraints: Vec<StarkConstraint>,
    /// Merkle authentication path from the public input row to trace root.
    pub public_input_authentication_path: Vec<Hash256>,
    /// Merkle-authenticated trace openings for every Fiat-Shamir query.
    pub trace_query_proofs: Vec<TraceQueryProof>,
    /// Complete committed trace rows.
    ///
    /// This keeps the unaudited pedagogical verifier fail-closed: it can
    /// recompute the trace root, recompute the constraint commitment, and
    /// evaluate every transition instead of trusting sampled openings as a
    /// production STARK soundness argument.
    pub trace_rows: Vec<Vec<u64>>,
}

impl PartialEq for StarkConfig {
    fn eq(&self, other: &Self) -> bool {
        self.field_size == other.field_size
            && self.expansion_factor == other.expansion_factor
            && self.num_queries == other.num_queries
    }
}

impl Eq for StarkConfig {}

// ---------------------------------------------------------------------------
// Prove
// ---------------------------------------------------------------------------

/// Generate a STARK proof from an execution trace and constraints.
///
/// `trace` is a 2D array: trace[row][column].
/// `constraints` define the transition rules between consecutive rows.
///
/// **Unaudited** — gated behind the `unaudited-pedagogical-proofs` feature.
pub fn prove_stark(
    trace: &[Vec<u64>],
    constraints: &[StarkConstraint],
    config: &StarkConfig,
) -> Result<StarkProof> {
    crate::guard_unaudited("stark::prove_stark")?;
    if trace.is_empty() {
        return Err(ProofError::ProofGenerationFailed("empty trace".to_string()));
    }
    if trace.len() < 2 {
        return Err(ProofError::ProofGenerationFailed(
            "trace must have at least 2 rows".to_string(),
        ));
    }
    if constraints.is_empty() {
        return Err(ProofError::ProofGenerationFailed(
            "STARK proof requires at least one constraint".to_string(),
        ));
    }

    let num_cols = trace[0].len();
    for row in trace {
        if row.len() != num_cols {
            return Err(ProofError::ProofGenerationFailed(
                "inconsistent column count".to_string(),
            ));
        }
    }
    for constraint in constraints {
        validate_constraint_shape(constraint, num_cols)?;
    }

    // Step 1: Verify constraints are satisfied
    for (row_idx, window) in trace.windows(2).enumerate() {
        let current = &window[0];
        let next = &window[1];

        for constraint in constraints {
            let val = evaluate_constraint(constraint, current, next, config.field_size)?;
            if val != 0 {
                return Err(ProofError::ProofGenerationFailed(format!(
                    "constraint '{}' not satisfied at row {row_idx}",
                    constraint.name
                )));
            }
        }
    }

    let trace_leaves = trace_leaf_hashes(trace);

    // Step 2: Commit to the trace
    let trace_commitment = commit_trace_from_leaves(&trace_leaves);

    // Step 3: Commit to the constraint polynomial
    let constraint_commitment = commit_constraints(trace, constraints, config.field_size)?;

    // Step 4: Derive query indices (Fiat-Shamir)
    let query_indices = derive_queries(
        &trace_commitment,
        &constraint_commitment,
        config.num_queries,
        trace.len() - 1,
    )?;

    // Step 5: Build FRI proof
    let fri_proof = build_fri_proof(
        trace,
        &query_indices,
        config,
        &trace_commitment,
        &constraint_commitment,
    );
    let public_input_authentication_path = merkle_proof(&trace_leaves, 0).map_err(|_| {
        ProofError::ProofGenerationFailed(
            "failed to build public input authentication path".to_string(),
        )
    })?;
    let trace_query_proofs = build_trace_query_proofs(trace, &trace_leaves, &query_indices)?;

    Ok(StarkProof {
        trace_commitment,
        constraint_commitment,
        query_indices,
        fri_proof,
        config: config.clone(),
        trace_length: trace.len(),
        public_input_hash: hash_row(&trace[0]),
        constraints: constraints.to_vec(),
        public_input_authentication_path,
        trace_query_proofs,
        trace_rows: trace.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/// Verify a STARK proof given public inputs.
///
/// Public inputs are the first row of the trace.
///
/// **Unaudited** — gated behind the `unaudited-pedagogical-proofs` feature.
/// Returns `Err(UnauditedImplementation)` when the feature is disabled.
pub fn verify_stark(proof: &StarkProof, public_inputs: &[u64]) -> Result<bool> {
    crate::guard_unaudited("stark::verify_stark")?;
    verify_stark_with_constraints(proof, public_inputs, &proof.constraints)
}

/// Verify a STARK proof for caller-supplied public constraints.
///
/// Prefer this API when the verifier knows the statement constraints out of
/// band. [`verify_stark`] remains available for serialized proof bundles that
/// embed their public constraints.
pub fn verify_stark_with_constraints(
    proof: &StarkProof,
    public_inputs: &[u64],
    constraints: &[StarkConstraint],
) -> Result<bool> {
    crate::guard_unaudited("stark::verify_stark")?;
    if proof.trace_length < 2
        || constraints.is_empty()
        || proof.constraints.is_empty()
        || proof.constraints != constraints
        || proof.trace_rows.len() != proof.trace_length
    {
        return Ok(false);
    }

    if validate_trace_shape(&proof.trace_rows).is_err() {
        return Ok(false);
    }

    let trace_leaves = trace_leaf_hashes(&proof.trace_rows);
    if commit_trace_from_leaves(&trace_leaves) != proof.trace_commitment {
        return Ok(false);
    }

    let expected_constraint_commitment =
        match commit_constraints(&proof.trace_rows, constraints, proof.config.field_size) {
            Ok(commitment) => commitment,
            Err(_) => return Ok(false),
        };
    if expected_constraint_commitment != proof.constraint_commitment {
        return Ok(false);
    }

    for window in proof.trace_rows.windows(2) {
        for constraint in constraints {
            let constraint_value = match evaluate_constraint(
                constraint,
                &window[0],
                &window[1],
                proof.config.field_size,
            ) {
                Ok(value) => value,
                Err(_) => return Ok(false),
            };
            if constraint_value != 0 {
                return Ok(false);
            }
        }
    }

    // Step 1: Re-derive query indices from commitments (Fiat-Shamir)
    let expected_queries = match derive_queries(
        &proof.trace_commitment,
        &proof.constraint_commitment,
        proof.config.num_queries,
        proof.trace_length - 1,
    ) {
        Ok(q) => q,
        Err(_) => return Ok(false),
    };

    if expected_queries != proof.query_indices {
        return Ok(false);
    }

    // Step 2: Verify FRI proof structure
    if proof.fri_proof.layer_commitments.is_empty() {
        return Ok(false);
    }

    // Step 3: Verify the public inputs match what was committed.
    let Some(first_row) = proof.trace_rows.first() else {
        return Ok(false);
    };
    if first_row.as_slice() != public_inputs {
        return Ok(false);
    }
    let public_hash = hash_row(public_inputs);
    if public_hash != proof.public_input_hash {
        return Ok(false);
    }
    if !verify_merkle_proof(
        &proof.trace_commitment,
        &proof.public_input_hash,
        &proof.public_input_authentication_path,
        0,
    ) {
        return Ok(false);
    }

    // Step 4: Verify every Fiat-Shamir trace opening against the trace
    // commitment and the query values carried by the FRI component.
    if proof.trace_query_proofs.len() != proof.query_indices.len()
        || proof.fri_proof.query_values.len() != proof.query_indices.len()
    {
        return Ok(false);
    }

    for ((expected_index, query_proof), query_values) in proof
        .query_indices
        .iter()
        .zip(&proof.trace_query_proofs)
        .zip(&proof.fri_proof.query_values)
    {
        if query_proof.index != *expected_index || query_values != &query_proof.row {
            return Ok(false);
        }

        let Some(committed_row) = proof.trace_rows.get(query_proof.index) else {
            return Ok(false);
        };
        if committed_row != &query_proof.row {
            return Ok(false);
        }

        let Some(next_index) = query_proof.index.checked_add(1) else {
            return Ok(false);
        };
        if next_index >= proof.trace_length {
            return Ok(false);
        }
        let Some(committed_next_row) = proof.trace_rows.get(next_index) else {
            return Ok(false);
        };
        if committed_next_row != &query_proof.next_row {
            return Ok(false);
        }

        let leaf = hash_row(&query_proof.row);
        if !verify_merkle_proof(
            &proof.trace_commitment,
            &leaf,
            &query_proof.authentication_path,
            query_proof.index,
        ) {
            return Ok(false);
        }

        let next_leaf = hash_row(&query_proof.next_row);
        if !verify_merkle_proof(
            &proof.trace_commitment,
            &next_leaf,
            &query_proof.next_authentication_path,
            next_index,
        ) {
            return Ok(false);
        }

        for constraint in constraints {
            let constraint_value = match evaluate_constraint(
                constraint,
                &query_proof.row,
                &query_proof.next_row,
                proof.config.field_size,
            ) {
                Ok(value) => value,
                Err(_) => return Ok(false),
            };
            if constraint_value != 0 {
                return Ok(false);
            }
        }
    }

    // Step 5: Verify consistency between trace commitment, constraint commitment,
    // and FRI proof.
    let expected_fri_base =
        compute_fri_base_commitment(&proof.trace_commitment, &proof.constraint_commitment);

    if proof.fri_proof.layer_commitments[0] != expected_fri_base {
        return Ok(false);
    }

    // Step 6: Verify FRI layer transitions
    for window in proof.fri_proof.layer_commitments.windows(2) {
        let mut h = blake3::Hasher::new();
        h.update(b"stark:fri:fold:");
        h.update(window[0].as_bytes());
        let expected_next = Hash256::from_bytes(*h.finalize().as_bytes());
        if window[1] != expected_next {
            return Ok(false);
        }
    }

    Ok(true)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn evaluate_constraint(
    constraint: &StarkConstraint,
    current: &[u64],
    next: &[u64],
    field_size: u64,
) -> Result<u64> {
    if field_size == 0 {
        return Err(ProofError::ProofGenerationFailed(
            "field_size must be non-zero".to_string(),
        ));
    }
    if current.len() != next.len() {
        return Err(ProofError::ConstraintError(format!(
            "constraint '{}' cannot evaluate rows with mismatched widths: current {} != next {}",
            constraint.name,
            current.len(),
            next.len()
        )));
    }
    validate_constraint_shape(constraint, current.len())?;

    let modulus = u128::from(field_size);
    let mut sum: u128 = 0;
    for (i, &col_idx) in constraint.column_indices.iter().enumerate() {
        let (curr_coeff, next_coeff) = constraint.coefficients[i];
        let curr_val = current[col_idx];
        let next_val = next[col_idx];
        let curr_term = (u128::from(curr_coeff) * u128::from(curr_val)) % modulus;
        let next_term = (u128::from(next_coeff) * u128::from(next_val)) % modulus;
        sum = (sum + curr_term + next_term) % modulus;
    }
    u64::try_from(sum).map_err(|_| {
        ProofError::ProofGenerationFailed("constraint evaluation overflowed u64".to_string())
    })
}

fn validate_constraint_shape(constraint: &StarkConstraint, trace_width: usize) -> Result<()> {
    if constraint.column_indices.is_empty() {
        return Err(ProofError::ConstraintError(format!(
            "constraint '{}' must reference at least one trace column",
            constraint.name
        )));
    }
    if constraint.column_indices.len() != constraint.coefficients.len() {
        return Err(ProofError::ConstraintError(format!(
            "constraint '{}' column_indices length {} must match coefficients length {}",
            constraint.name,
            constraint.column_indices.len(),
            constraint.coefficients.len()
        )));
    }
    for &col_idx in &constraint.column_indices {
        if col_idx >= trace_width {
            return Err(ProofError::ConstraintError(format!(
                "constraint '{}' column index {col_idx} is outside trace width {trace_width}",
                constraint.name
            )));
        }
    }
    Ok(())
}

fn hash_row(row: &[u64]) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stark:row:");
    for &val in row {
        hasher.update(&val.to_le_bytes());
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

fn trace_leaf_hashes(trace: &[Vec<u64>]) -> Vec<Hash256> {
    trace.iter().map(|row| hash_row(row)).collect()
}

fn commit_trace_from_leaves(leaves: &[Hash256]) -> Hash256 {
    merkle_root(leaves)
}

fn validate_trace_shape(trace: &[Vec<u64>]) -> Result<()> {
    let Some(first_row) = trace.first() else {
        return Err(ProofError::ProofGenerationFailed("empty trace".to_string()));
    };
    let trace_width = first_row.len();
    if trace_width == 0 {
        return Err(ProofError::ProofGenerationFailed(
            "trace rows must contain at least one column".to_string(),
        ));
    }
    for (row_idx, row) in trace.iter().enumerate() {
        if row.len() != trace_width {
            return Err(ProofError::ProofGenerationFailed(format!(
                "trace row {row_idx} has width {}, expected {trace_width}",
                row.len()
            )));
        }
    }
    Ok(())
}

fn commit_constraints(
    trace: &[Vec<u64>],
    constraints: &[StarkConstraint],
    field_size: u64,
) -> Result<Hash256> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stark:constraints:");
    for window in trace.windows(2) {
        for constraint in constraints {
            let val = evaluate_constraint(constraint, &window[0], &window[1], field_size)?;
            hasher.update(&val.to_le_bytes());
        }
    }
    Ok(Hash256::from_bytes(*hasher.finalize().as_bytes()))
}

fn derive_queries(
    trace_commitment: &Hash256,
    constraint_commitment: &Hash256,
    num_queries: usize,
    trace_len: usize,
) -> Result<Vec<usize>> {
    if num_queries == 0 {
        return Ok(Vec::new());
    }
    if num_queries > trace_len {
        return Err(ProofError::ProofGenerationFailed(format!(
            "query budget {num_queries} exceeds available transition rows {trace_len}"
        )));
    }
    let trace_len_u64 = u64::try_from(trace_len).map_err(|_| {
        ProofError::ProofGenerationFailed(format!("trace length {trace_len} overflows u64"))
    })?;
    let mut seen = BTreeSet::new();
    let mut indices = Vec::with_capacity(num_queries);

    for i in 0..num_queries {
        let query_round = u64::try_from(i).map_err(|_| {
            ProofError::ProofGenerationFailed(format!("query round {i} overflows u64"))
        })?;
        let mut attempt = 0u64;

        loop {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"stark:query_index:");
            hasher.update(trace_commitment.as_bytes());
            hasher.update(constraint_commitment.as_bytes());
            hasher.update(&query_round.to_le_bytes());
            hasher.update(&attempt.to_le_bytes());
            let seed = hasher.finalize();
            let mut idx_bytes = [0u8; 8];
            idx_bytes.copy_from_slice(&seed.as_bytes()[..8]);

            let idx_u64 = u64::from_le_bytes(idx_bytes) % trace_len_u64;
            let idx = usize::try_from(idx_u64).map_err(|_| {
                ProofError::ProofGenerationFailed(format!("query index {idx_u64} overflows usize"))
            })?;

            if seen.insert(idx) {
                indices.push(idx);
                break;
            }

            attempt = attempt.checked_add(1).ok_or_else(|| {
                ProofError::ProofGenerationFailed(format!(
                    "query index derivation exhausted attempts for round {i}"
                ))
            })?;
        }
    }

    Ok(indices)
}

fn compute_fri_base_commitment(
    trace_commitment: &Hash256,
    constraint_commitment: &Hash256,
) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stark:fri:base:");
    hasher.update(trace_commitment.as_bytes());
    hasher.update(constraint_commitment.as_bytes());
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

fn build_fri_proof(
    trace: &[Vec<u64>],
    query_indices: &[usize],
    config: &StarkConfig,
    trace_commitment: &Hash256,
    constraint_commitment: &Hash256,
) -> FriProof {
    let base = compute_fri_base_commitment(trace_commitment, constraint_commitment);

    let num_layers = config.expansion_factor;
    let mut layer_commitments = Vec::with_capacity(num_layers);
    let mut current = base;
    layer_commitments.push(current);

    for _ in 1..num_layers {
        let mut h = blake3::Hasher::new();
        h.update(b"stark:fri:fold:");
        h.update(current.as_bytes());
        current = Hash256::from_bytes(*h.finalize().as_bytes());
        layer_commitments.push(current);
    }

    // Query values: for each query, return the trace row
    let query_values: Vec<Vec<u64>> = query_indices
        .iter()
        .map(|&idx| {
            if idx < trace.len() {
                trace[idx].clone()
            } else {
                Vec::new()
            }
        })
        .collect();

    FriProof {
        layer_commitments,
        query_values,
    }
}

fn build_trace_query_proofs(
    trace: &[Vec<u64>],
    trace_leaves: &[Hash256],
    query_indices: &[usize],
) -> Result<Vec<TraceQueryProof>> {
    query_indices
        .iter()
        .map(|&idx| {
            let Some(row) = trace.get(idx) else {
                return Err(ProofError::ProofGenerationFailed(format!(
                    "query index {idx} is outside trace length {}",
                    trace.len()
                )));
            };
            let Some(next_idx) = idx.checked_add(1) else {
                return Err(ProofError::ProofGenerationFailed(format!(
                    "query index {idx} cannot address a successor row"
                )));
            };
            let Some(next_row) = trace.get(next_idx) else {
                return Err(ProofError::ProofGenerationFailed(format!(
                    "query index {idx} has no successor row in trace length {}",
                    trace.len()
                )));
            };
            let authentication_path = merkle_proof(trace_leaves, idx).map_err(|_| {
                ProofError::ProofGenerationFailed(format!(
                    "failed to build trace authentication path for query index {idx}"
                ))
            })?;
            let next_authentication_path = merkle_proof(trace_leaves, next_idx).map_err(|_| {
                ProofError::ProofGenerationFailed(format!(
                    "failed to build trace authentication path for successor query index {next_idx}"
                ))
            })?;
            Ok(TraceQueryProof {
                index: idx,
                row: row.clone(),
                authentication_path,
                next_row: next_row.clone(),
                next_authentication_path,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "unaudited-pedagogical-proofs"))]
mod tests {
    use super::*;

    fn make_fibonacci_trace(n: usize, field_size: u64) -> Vec<Vec<u64>> {
        let mut trace = Vec::with_capacity(n);
        trace.push(vec![0, 1]);
        for i in 1..n {
            let prev = &trace[i - 1];
            let next_val = (prev[0] + prev[1]) % field_size;
            trace.push(vec![prev[1], next_val]);
        }
        trace
    }

    fn fib_constraint() -> StarkConstraint {
        // Constraint: current[1] + current[0] - next[1] == 0
        // i.e., current[0]*1 + current[1]*1 + next[1]*(-1) == 0
        // But we use positive arithmetic mod field_size.
        // Rewrite: current[0] + current[1] = next[1]
        // In our format: col0_curr=1, col0_next=0, col1_curr=1, col1_next=(field_size-1)
        let field_size = (1u64 << 31) - 1;
        StarkConstraint {
            name: "fibonacci".to_string(),
            column_indices: vec![0, 1],
            coefficients: vec![(1, 0), (1, field_size - 1)],
        }
    }

    fn equality_constraint() -> StarkConstraint {
        let field_size = (1u64 << 31) - 1;
        StarkConstraint {
            name: "same-value".to_string(),
            column_indices: vec![0],
            coefficients: vec![(1, field_size - 1)],
        }
    }

    #[test]
    fn prove_and_verify_fibonacci() {
        let config = StarkConfig::default_config();
        let trace = make_fibonacci_trace(16, config.field_size);
        let constraints = vec![fib_constraint()];

        let proof = prove_stark(&trace, &constraints, &config).unwrap();
        let public_inputs = &trace[0];
        assert!(verify_stark_with_constraints(&proof, public_inputs, &constraints).unwrap());
    }

    #[test]
    fn verify_stark_uses_embedded_constraints() {
        let config = StarkConfig::default_config();
        let trace = make_fibonacci_trace(16, config.field_size);
        let constraints = vec![fib_constraint()];

        let proof = prove_stark(&trace, &constraints, &config).unwrap();

        assert!(verify_stark(&proof, &trace[0]).unwrap());
    }

    #[test]
    fn empty_trace_rejected() {
        let config = StarkConfig::default_config();
        let err = prove_stark(&[], &[], &config).unwrap_err();
        assert!(matches!(err, ProofError::ProofGenerationFailed(_)));
    }

    #[test]
    fn single_row_trace_rejected() {
        let config = StarkConfig::default_config();
        let constraints = vec![equality_constraint()];
        let err = prove_stark(&[vec![1, 2]], &constraints, &config).unwrap_err();
        assert!(matches!(err, ProofError::ProofGenerationFailed(_)));
    }

    #[test]
    fn inconsistent_columns_rejected() {
        let config = StarkConfig::default_config();
        let trace = vec![vec![1, 2], vec![3]];
        let constraints = vec![equality_constraint()];
        let err = prove_stark(&trace, &constraints, &config).unwrap_err();
        assert!(matches!(err, ProofError::ProofGenerationFailed(_)));
    }

    #[test]
    fn unsatisfied_constraint_rejected() {
        let config = StarkConfig::default_config();
        let trace = vec![vec![0, 1], vec![1, 999]]; // wrong fibonacci
        let constraints = vec![fib_constraint()];
        let err = prove_stark(&trace, &constraints, &config).unwrap_err();
        assert!(matches!(err, ProofError::ProofGenerationFailed(_)));
    }

    #[test]
    fn zero_field_size_rejected_without_panic() {
        let config = StarkConfig {
            field_size: 0,
            expansion_factor: 4,
            num_queries: 2,
        };
        let trace = vec![vec![1], vec![1]];
        let constraints = vec![equality_constraint()];

        let err = prove_stark(&trace, &constraints, &config).unwrap_err();

        assert!(matches!(err, ProofError::ProofGenerationFailed(_)));
    }

    #[test]
    fn large_constraint_terms_do_not_overflow_before_modular_reduction() {
        let config = StarkConfig {
            field_size: u64::MAX - 58,
            expansion_factor: 4,
            num_queries: 2,
        };
        let trace = vec![vec![1, 1], vec![1, 1]];
        let constraint = StarkConstraint {
            name: "large-terms".to_string(),
            column_indices: vec![0, 1],
            coefficients: vec![(u64::MAX, 0), (u64::MAX, 0)],
        };

        let result = prove_stark(&trace, &[constraint], &config);

        assert!(matches!(result, Err(ProofError::ProofGenerationFailed(_))));
    }

    #[test]
    fn proof_deterministic() {
        let config = StarkConfig::default_config();
        let trace = make_fibonacci_trace(16, config.field_size);
        let constraints = vec![fib_constraint()];

        let p1 = prove_stark(&trace, &constraints, &config).unwrap();
        let p2 = prove_stark(&trace, &constraints, &config).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn different_traces_different_proofs() {
        let config = StarkConfig::default_config();
        let t1 = make_fibonacci_trace(16, config.field_size);
        let t2 = {
            let mut t = vec![vec![1, 1]];
            for i in 1..16 {
                let prev = &t[i - 1];
                let next_val = (prev[0] + prev[1]) % config.field_size;
                t.push(vec![prev[1], next_val]);
            }
            t
        };
        let constraints = vec![fib_constraint()];

        let p1 = prove_stark(&t1, &constraints, &config).unwrap();
        let p2 = prove_stark(&t2, &constraints, &config).unwrap();
        assert_ne!(p1.trace_commitment, p2.trace_commitment);
    }

    #[test]
    fn verify_rejects_wrong_public_inputs() {
        let config = StarkConfig::default_config();
        let trace = make_fibonacci_trace(16, config.field_size);
        let constraints = vec![fib_constraint()];

        let proof = prove_stark(&trace, &constraints, &config).unwrap();
        // Wrong public inputs
        assert!(!verify_stark_with_constraints(&proof, &[99, 99], &constraints).unwrap());
    }

    #[test]
    fn verify_rejects_public_inputs_not_bound_to_trace_commitment() {
        let config = StarkConfig::default_config();
        let trace = make_fibonacci_trace(16, config.field_size);
        let constraints = vec![fib_constraint()];

        let mut proof = prove_stark(&trace, &constraints, &config).unwrap();
        let forged_public_inputs = vec![99, 99];
        proof.public_input_hash = hash_row(&forged_public_inputs);

        assert!(
            !verify_stark_with_constraints(&proof, &forged_public_inputs, &constraints).unwrap()
        );
    }

    #[test]
    fn verify_rejects_tampered_query_values() {
        let config = StarkConfig::default_config();
        let trace = make_fibonacci_trace(16, config.field_size);
        let constraints = vec![fib_constraint()];

        let mut proof = prove_stark(&trace, &constraints, &config).unwrap();
        proof.fri_proof.query_values = vec![vec![u64::MAX; 4]; config.num_queries];

        assert!(!verify_stark_with_constraints(&proof, &trace[0], &constraints).unwrap());
    }

    #[test]
    fn verify_with_constraints_rejects_authenticated_trace_that_violates_constraints() {
        let config = StarkConfig {
            num_queries: 5,
            ..StarkConfig::default_config()
        };
        let constraints = vec![equality_constraint()];
        let trace = vec![vec![0], vec![1], vec![2], vec![3], vec![4], vec![5]];
        let trace_leaves = trace_leaf_hashes(&trace);
        let trace_commitment = commit_trace_from_leaves(&trace_leaves);
        let constraint_commitment =
            commit_constraints(&trace, &constraints, config.field_size).unwrap();
        let query_indices = derive_queries(
            &trace_commitment,
            &constraint_commitment,
            config.num_queries,
            trace.len() - 1,
        )
        .unwrap();
        let fri_proof = build_fri_proof(
            &trace,
            &query_indices,
            &config,
            &trace_commitment,
            &constraint_commitment,
        );
        let public_input_authentication_path = merkle_proof(&trace_leaves, 0).unwrap();
        let trace_query_proofs =
            build_trace_query_proofs(&trace, &trace_leaves, &query_indices).unwrap();
        let proof = StarkProof {
            trace_commitment,
            constraint_commitment,
            query_indices,
            fri_proof,
            config,
            trace_length: trace.len(),
            public_input_hash: hash_row(&trace[0]),
            constraints: constraints.clone(),
            public_input_authentication_path,
            trace_query_proofs,
            trace_rows: trace.clone(),
        };

        assert!(!verify_stark_with_constraints(&proof, &trace[0], &constraints).unwrap());
    }

    #[test]
    fn verify_rejects_forged_trace_with_unqueried_constraint_violation() {
        let config = StarkConfig {
            num_queries: 4,
            ..StarkConfig::default_config()
        };
        let constraints = vec![equality_constraint()];
        let trace_len = 32usize;

        let mut forged = None;
        for bad_row in 1..(trace_len - 1) {
            let mut trace = vec![vec![7u64]; trace_len];
            trace[bad_row] = vec![9u64];
            let trace_leaves = trace_leaf_hashes(&trace);
            let trace_commitment = commit_trace_from_leaves(&trace_leaves);
            let constraint_commitment =
                commit_constraints(&trace, &constraints, config.field_size).unwrap();
            let query_indices = derive_queries(
                &trace_commitment,
                &constraint_commitment,
                config.num_queries,
                trace.len() - 1,
            )
            .unwrap();
            let queried: BTreeSet<usize> = query_indices.iter().copied().collect();
            if !queried.contains(&(bad_row - 1)) && !queried.contains(&bad_row) {
                forged = Some((
                    trace,
                    trace_leaves,
                    trace_commitment,
                    constraint_commitment,
                    query_indices,
                ));
                break;
            }
        }

        let Some((trace, trace_leaves, trace_commitment, constraint_commitment, query_indices)) =
            forged
        else {
            panic!("test fixture must find an unqueried bad transition");
        };
        let fri_proof = build_fri_proof(
            &trace,
            &query_indices,
            &config,
            &trace_commitment,
            &constraint_commitment,
        );
        let public_input_authentication_path = merkle_proof(&trace_leaves, 0).unwrap();
        let trace_query_proofs =
            build_trace_query_proofs(&trace, &trace_leaves, &query_indices).unwrap();
        let proof = StarkProof {
            trace_commitment,
            constraint_commitment,
            query_indices,
            fri_proof,
            config,
            trace_length: trace.len(),
            public_input_hash: hash_row(&trace[0]),
            constraints: constraints.clone(),
            public_input_authentication_path,
            trace_query_proofs,
            trace_rows: trace.clone(),
        };

        assert!(!verify_stark_with_constraints(&proof, &trace[0], &constraints).unwrap());
    }

    #[test]
    fn derive_queries_produces_unique_indices_when_domain_permits() {
        let trace_commitment = Hash256::from_bytes([1u8; 32]);
        let constraint_commitment = Hash256::from_bytes([2u8; 32]);
        let queries = derive_queries(&trace_commitment, &constraint_commitment, 16, 64).unwrap();
        let unique: std::collections::BTreeSet<usize> = queries.iter().copied().collect();

        assert_eq!(queries.len(), 16);
        assert_eq!(unique.len(), queries.len());
    }

    #[test]
    fn derive_queries_rejects_query_budget_exceeding_transition_domain() {
        let trace_commitment = Hash256::from_bytes([1u8; 32]);
        let constraint_commitment = Hash256::from_bytes([2u8; 32]);
        let err = derive_queries(&trace_commitment, &constraint_commitment, 8, 7).unwrap_err();

        assert!(
            err.to_string()
                .contains("exceeds available transition rows"),
            "query derivation must not silently reuse duplicate indices: {err}"
        );
    }

    #[test]
    fn prove_rejects_query_budget_exceeding_transition_domain() {
        let config = StarkConfig::default_config();
        let trace = make_fibonacci_trace(8, config.field_size);
        let constraints = vec![fib_constraint()];

        let err = prove_stark(&trace, &constraints, &config).unwrap_err();

        assert!(
            err.to_string()
                .contains("exceeds available transition rows"),
            "proof generation must fail closed instead of proving duplicate query indices: {err}"
        );
    }

    #[test]
    fn verify_rejects_tampered_proof() {
        let config = StarkConfig::default_config();
        let trace = make_fibonacci_trace(16, config.field_size);
        let constraints = vec![fib_constraint()];

        let mut proof = prove_stark(&trace, &constraints, &config).unwrap();
        proof.trace_commitment = Hash256::ZERO;
        assert!(!verify_stark_with_constraints(&proof, &trace[0], &constraints).unwrap());
    }

    #[test]
    fn prove_stark_rejects_empty_constraints() {
        let config = StarkConfig {
            num_queries: 2,
            ..StarkConfig::default_config()
        };
        let trace = vec![vec![1, 2], vec![3, 4], vec![5, 6]];

        let err = prove_stark(&trace, &[], &config).unwrap_err();

        assert!(
            err.to_string().contains("at least one constraint"),
            "empty STARK constraints must fail closed: {err}"
        );
    }

    #[test]
    fn verify_rejects_manually_constructed_empty_constraint_proof() {
        let config = StarkConfig {
            num_queries: 2,
            ..StarkConfig::default_config()
        };
        let trace = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
        let constraints = Vec::new();
        let trace_leaves = trace_leaf_hashes(&trace);
        let trace_commitment = commit_trace_from_leaves(&trace_leaves);
        let constraint_commitment =
            commit_constraints(&trace, &constraints, config.field_size).unwrap();
        let query_indices = derive_queries(
            &trace_commitment,
            &constraint_commitment,
            config.num_queries,
            trace.len() - 1,
        )
        .unwrap();
        let fri_proof = build_fri_proof(
            &trace,
            &query_indices,
            &config,
            &trace_commitment,
            &constraint_commitment,
        );
        let public_input_authentication_path = merkle_proof(&trace_leaves, 0).unwrap();
        let trace_query_proofs =
            build_trace_query_proofs(&trace, &trace_leaves, &query_indices).unwrap();
        let proof = StarkProof {
            trace_commitment,
            constraint_commitment,
            query_indices,
            fri_proof,
            config,
            trace_length: trace.len(),
            public_input_hash: hash_row(&trace[0]),
            constraints: constraints.clone(),
            public_input_authentication_path,
            trace_query_proofs,
            trace_rows: trace.clone(),
        };

        assert!(!verify_stark_with_constraints(&proof, &trace[0], &constraints).unwrap());
    }

    #[test]
    fn stark_config_eq() {
        let c1 = StarkConfig::default_config();
        let c2 = StarkConfig::default_config();
        assert_eq!(c1, c2);
    }

    #[test]
    fn fri_proof_structure() {
        let config = StarkConfig::default_config();
        let trace = make_fibonacci_trace(16, config.field_size);
        let constraints = vec![fib_constraint()];
        let proof = prove_stark(&trace, &constraints, &config).unwrap();

        assert_eq!(
            proof.fri_proof.layer_commitments.len(),
            config.expansion_factor
        );
        assert_eq!(proof.fri_proof.query_values.len(), config.num_queries);
    }

    #[test]
    fn malformed_constraint_oob_column_is_rejected() {
        let config = StarkConfig::default_config();
        let trace = vec![vec![7u64], vec![11u64]];
        let constraint = StarkConstraint {
            name: "oob".to_string(),
            column_indices: vec![5],
            coefficients: vec![(1, 1)],
        };
        let constraints = vec![constraint];
        let err = prove_stark(&trace, &constraints, &config).unwrap_err();
        assert!(
            err.to_string().contains("outside trace width"),
            "out-of-bounds constraint columns must fail closed: {err}"
        );
    }

    #[test]
    fn malformed_constraint_missing_coefficients_is_rejected() {
        let config = StarkConfig::default_config();
        let trace = vec![vec![0u64, 5u64], vec![0u64, 7u64]];
        let constraint = StarkConstraint {
            name: "partial".to_string(),
            column_indices: vec![0, 1],
            coefficients: vec![(1, 1)],
        };
        let constraints = vec![constraint];
        let err = prove_stark(&trace, &constraints, &config).unwrap_err();
        assert!(
            err.to_string().contains("must match coefficients"),
            "constraint columns without matching coefficients must fail closed: {err}"
        );
    }
}
