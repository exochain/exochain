//! STARK proof system -- hash-based, post-quantum.
//!
//! Uses blake3 for all commitments (no elliptic curves).
//! This is a pedagogical implementation demonstrating the STARK structure.

use exo_core::types::Hash256;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    let num_cols = trace[0].len();
    for row in trace {
        if row.len() != num_cols {
            return Err(ProofError::ProofGenerationFailed(
                "inconsistent column count".to_string(),
            ));
        }
    }

    // Step 1: Verify constraints are satisfied
    for (row_idx, window) in trace.windows(2).enumerate() {
        let current = &window[0];
        let next = &window[1];

        for constraint in constraints {
            let val = evaluate_constraint(constraint, current, next, config.field_size);
            if val != 0 {
                return Err(ProofError::ProofGenerationFailed(format!(
                    "constraint '{}' not satisfied at row {row_idx}",
                    constraint.name
                )));
            }
        }
    }

    // Step 2: Commit to the trace
    let trace_commitment = commit_trace(trace);

    // Step 3: Commit to the constraint polynomial
    let constraint_commitment = commit_constraints(trace, constraints, config.field_size);

    // Step 4: Derive query indices (Fiat-Shamir)
    let query_indices = derive_queries(
        &trace_commitment,
        &constraint_commitment,
        config.num_queries,
        trace.len(),
    )?;

    // Step 5: Build FRI proof
    let fri_proof = build_fri_proof(
        trace,
        &query_indices,
        config,
        &trace_commitment,
        &constraint_commitment,
    );

    Ok(StarkProof {
        trace_commitment,
        constraint_commitment,
        query_indices,
        fri_proof,
        config: config.clone(),
        trace_length: trace.len(),
        public_input_hash: hash_row(&trace[0]),
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
    // Step 1: Re-derive query indices from commitments (Fiat-Shamir)
    let expected_queries = match derive_queries(
        &proof.trace_commitment,
        &proof.constraint_commitment,
        proof.config.num_queries,
        proof.trace_length,
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
    let public_hash = hash_row(public_inputs);
    if public_hash != proof.public_input_hash {
        return Ok(false);
    }

    // Step 4: Verify consistency between trace commitment, constraint commitment,
    // and FRI proof.
    let expected_fri_base =
        compute_fri_base_commitment(&proof.trace_commitment, &proof.constraint_commitment);

    if proof.fri_proof.layer_commitments[0] != expected_fri_base {
        return Ok(false);
    }

    // Step 5: Verify FRI layer transitions
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
) -> u64 {
    let mut sum: u64 = 0;
    for (i, &col_idx) in constraint.column_indices.iter().enumerate() {
        if i < constraint.coefficients.len() {
            let (curr_coeff, next_coeff) = constraint.coefficients[i];
            let curr_val = if col_idx < current.len() {
                current[col_idx]
            } else {
                0
            };
            let next_val = if col_idx < next.len() {
                next[col_idx]
            } else {
                0
            };
            sum = (sum + curr_coeff.wrapping_mul(curr_val) + next_coeff.wrapping_mul(next_val))
                % field_size;
        }
    }
    sum
}

fn hash_row(row: &[u64]) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stark:row:");
    for &val in row {
        hasher.update(&val.to_le_bytes());
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

fn commit_trace(trace: &[Vec<u64>]) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stark:trace:");
    for row in trace {
        let row_hash = hash_row(row);
        hasher.update(row_hash.as_bytes());
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

fn commit_constraints(
    trace: &[Vec<u64>],
    constraints: &[StarkConstraint],
    field_size: u64,
) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stark:constraints:");
    for window in trace.windows(2) {
        for constraint in constraints {
            let val = evaluate_constraint(constraint, &window[0], &window[1], field_size);
            hasher.update(&val.to_le_bytes());
        }
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

fn derive_queries(
    trace_commitment: &Hash256,
    constraint_commitment: &Hash256,
    num_queries: usize,
    trace_len: usize,
) -> Result<Vec<usize>> {
    if trace_len == 0 {
        return Ok(Vec::new());
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"stark:queries:");
    hasher.update(trace_commitment.as_bytes());
    hasher.update(constraint_commitment.as_bytes());
    let seed = hasher.finalize();
    let seed_bytes = seed.as_bytes();

    let mut indices = Vec::with_capacity(num_queries);
    for i in 0..num_queries {
        let byte_offset = (i * 4) % 32;
        let mut idx_bytes = [0u8; 4];
        for j in 0..4 {
            idx_bytes[j] = seed_bytes[(byte_offset + j) % 32];
        }
        let raw = u32::from_le_bytes(idx_bytes);
        let raw_usize = usize::try_from(raw).map_err(|_| {
            ProofError::ProofGenerationFailed(format!("query index {raw} overflows usize"))
        })?;
        let idx = raw_usize % trace_len;
        indices.push(idx);
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

    #[test]
    fn prove_and_verify_fibonacci() {
        let config = StarkConfig::default_config();
        let trace = make_fibonacci_trace(16, config.field_size);
        let constraints = vec![fib_constraint()];

        let proof = prove_stark(&trace, &constraints, &config).unwrap();
        let public_inputs = &trace[0];
        assert!(verify_stark(&proof, public_inputs).unwrap());
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
        let err = prove_stark(&[vec![1, 2]], &[], &config).unwrap_err();
        assert!(matches!(err, ProofError::ProofGenerationFailed(_)));
    }

    #[test]
    fn inconsistent_columns_rejected() {
        let config = StarkConfig::default_config();
        let trace = vec![vec![1, 2], vec![3]];
        let err = prove_stark(&trace, &[], &config).unwrap_err();
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
    fn proof_deterministic() {
        let config = StarkConfig::default_config();
        let trace = make_fibonacci_trace(8, config.field_size);
        let constraints = vec![fib_constraint()];

        let p1 = prove_stark(&trace, &constraints, &config).unwrap();
        let p2 = prove_stark(&trace, &constraints, &config).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn different_traces_different_proofs() {
        let config = StarkConfig::default_config();
        let t1 = make_fibonacci_trace(8, config.field_size);
        let t2 = {
            let mut t = vec![vec![1, 1]];
            for i in 1..8 {
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
        let trace = make_fibonacci_trace(8, config.field_size);
        let constraints = vec![fib_constraint()];

        let proof = prove_stark(&trace, &constraints, &config).unwrap();
        // Wrong public inputs
        assert!(!verify_stark(&proof, &[99, 99]).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_proof() {
        let config = StarkConfig::default_config();
        let trace = make_fibonacci_trace(8, config.field_size);
        let constraints = vec![fib_constraint()];

        let mut proof = prove_stark(&trace, &constraints, &config).unwrap();
        proof.trace_commitment = Hash256::ZERO;
        assert!(!verify_stark(&proof, &trace[0]).unwrap());
    }

    #[test]
    fn no_constraints_trace() {
        let config = StarkConfig::default_config();
        let trace = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
        let proof = prove_stark(&trace, &[], &config).unwrap();
        assert!(verify_stark(&proof, &trace[0]).unwrap());
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
        let trace = make_fibonacci_trace(8, config.field_size);
        let proof = prove_stark(&trace, &[], &config).unwrap();

        assert_eq!(
            proof.fri_proof.layer_commitments.len(),
            config.expansion_factor
        );
        assert_eq!(proof.fri_proof.query_values.len(), config.num_queries);
    }

    #[test]
    fn evaluate_constraint_oob_column() {
        // col_idx beyond trace width — the else branches return 0.
        // Non-zero trace values (7, 11) ensure the test catches regressions where the OOB
        // branch returns a wrong non-zero value (e.g. current[col_idx % len]): that would
        // give sum = 1*7 + 1*11 = 18 ≠ 0, causing prove_stark to return Err.
        let config = StarkConfig::default_config();
        let trace = vec![vec![7u64], vec![11u64]]; // 1-column trace, non-zero values
        let constraint = StarkConstraint {
            name: "oob".to_string(),
            column_indices: vec![5], // beyond trace width → curr_val and next_val both become 0
            coefficients: vec![(1, 1)], // non-zero: 1*0 + 1*0 == 0, but would be non-zero if OOB returned column data
        };
        let proof = prove_stark(&trace, &[constraint], &config).unwrap();
        assert!(verify_stark(&proof, &trace[0]).unwrap());
    }

    #[test]
    fn evaluate_constraint_fewer_coefficients_than_columns() {
        // column_indices has more entries than coefficients — the extra column index is skipped.
        // Column 1 has non-zero values (5, 7) to catch regressions in the loop guard
        // (if i < constraint.coefficients.len()):
        //   - Removing the guard would panic at coefficients[1] (index out of bounds).
        //   - A wrap-around regression (coefficients[i % len]) would silently produce
        //     sum = 1*5 + 1*7 = 12 ≠ 0, causing prove_stark to return Err.
        // Column 0 stays 0 so the constraint sum == 0 (test passes correctly).
        let config = StarkConfig::default_config();
        let trace = vec![vec![0u64, 5u64], vec![0u64, 7u64]];
        let constraint = StarkConstraint {
            name: "partial".to_string(),
            column_indices: vec![0, 1], // two indices
            coefficients: vec![(1, 1)], // non-zero, one entry — index 1 is silently skipped
        };
        let proof = prove_stark(&trace, &[constraint], &config).unwrap();
        assert!(verify_stark(&proof, &trace[0]).unwrap());
    }
}
