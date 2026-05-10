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

//! Circuit abstraction -- R1CS constraint system.
//!
//! Provides the `Circuit` trait and a `ConstraintSystem` for expressing
//! arithmetic circuits as rank-1 constraint systems (A * B = C).

use serde::{Deserialize, Serialize};

use crate::error::{ProofError, Result};

// ---------------------------------------------------------------------------
// Variable
// ---------------------------------------------------------------------------

/// A variable in the constraint system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Variable {
    /// Index into the constraint system's variable list.
    pub index: usize,
    /// The witness value (populated during proving, None during setup).
    pub value: Option<u64>,
}

// ---------------------------------------------------------------------------
// LinearCombination
// ---------------------------------------------------------------------------

/// A linear combination of variables: sum of (coefficient, variable_index) pairs.
/// The constant term uses index `usize::MAX` as a sentinel for the "one" variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearCombination {
    pub terms: Vec<(u64, usize)>,
}

impl LinearCombination {
    /// Create an empty linear combination.
    #[must_use]
    pub fn zero() -> Self {
        Self { terms: Vec::new() }
    }

    /// Create a linear combination with a single variable.
    #[must_use]
    pub fn from_variable(var: Variable) -> Self {
        Self {
            terms: vec![(1, var.index)],
        }
    }

    /// Create a constant linear combination.
    #[must_use]
    pub fn constant(value: u64) -> Self {
        Self {
            terms: vec![(value, usize::MAX)],
        }
    }

    /// Add a term.
    pub fn add_term(&mut self, coeff: u64, var_index: usize) {
        self.terms.push((coeff, var_index));
    }

    /// Evaluate the linear combination given variable assignments.
    /// `vars[i]` = value of variable i. The "one" variable (index MAX) = 1.
    pub fn evaluate(&self, vars: &[u64]) -> Result<u64> {
        let mut sum: u64 = 0;
        for &(coeff, idx) in &self.terms {
            let val = if idx == usize::MAX {
                1u64
            } else if idx < vars.len() {
                vars[idx]
            } else {
                return Err(ProofError::ConstraintError(format!(
                    "linear combination references unallocated variable index {idx}; allocated variables: {}",
                    vars.len()
                )));
            };
            let term = coeff.checked_mul(val).ok_or_else(|| {
                ProofError::ConstraintError(format!(
                    "linear combination term overflows u64: coefficient {coeff} multiplied by value {val}"
                ))
            })?;
            sum = sum.checked_add(term).ok_or_else(|| {
                ProofError::ConstraintError(format!(
                    "linear combination sum overflows u64 when adding term {term}"
                ))
            })?;
        }
        Ok(sum)
    }

    fn references_only_allocated_variables(&self, variable_count: usize) -> bool {
        self.terms
            .iter()
            .all(|&(_, idx)| idx == usize::MAX || idx < variable_count)
    }
}

// ---------------------------------------------------------------------------
// Constraint
// ---------------------------------------------------------------------------

/// An R1CS constraint: A * B = C, where A, B, C are linear combinations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    pub a_terms: LinearCombination,
    pub b_terms: LinearCombination,
    pub c_terms: LinearCombination,
}

// ---------------------------------------------------------------------------
// ConstraintSystem
// ---------------------------------------------------------------------------

/// A constraint system accumulating R1CS constraints.
#[derive(Debug, Clone)]
pub struct ConstraintSystem {
    /// All allocated variables.
    pub variables: Vec<Variable>,
    /// All constraints.
    pub constraints: Vec<Constraint>,
    /// Number of public input variables.
    pub num_public_inputs: usize,
    /// Indices of public input variables.
    pub public_input_indices: Vec<usize>,
}

impl ConstraintSystem {
    /// Create a new empty constraint system.
    #[must_use]
    pub fn new() -> Self {
        Self {
            variables: Vec::new(),
            constraints: Vec::new(),
            num_public_inputs: 0,
            public_input_indices: Vec::new(),
        }
    }

    /// Number of variables.
    #[must_use]
    pub fn num_variables(&self) -> usize {
        self.variables.len()
    }

    /// Number of constraints.
    #[must_use]
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Check if all constraints are satisfied by the current variable assignments.
    pub fn is_satisfied(&self) -> bool {
        let mut vals = Vec::with_capacity(self.variables.len());
        for variable in &self.variables {
            let Some(value) = variable.value else {
                return false;
            };
            vals.push(value);
        }

        for c in &self.constraints {
            if !c.a_terms.references_only_allocated_variables(vals.len())
                || !c.b_terms.references_only_allocated_variables(vals.len())
                || !c.c_terms.references_only_allocated_variables(vals.len())
            {
                return false;
            }
            let (Ok(a), Ok(b), Ok(c_val)) = (
                c.a_terms.evaluate(&vals),
                c.b_terms.evaluate(&vals),
                c.c_terms.evaluate(&vals),
            ) else {
                return false;
            };
            let Some(product) = a.checked_mul(b) else {
                return false;
            };
            if product != c_val {
                return false;
            }
        }
        true
    }
}

impl Default for ConstraintSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Allocate a variable in the constraint system.
pub fn allocate(cs: &mut ConstraintSystem, value: Option<u64>) -> Variable {
    let index = cs.variables.len();
    let var = Variable { index, value };
    cs.variables.push(var);
    var
}

/// Allocate a public input variable.
pub fn allocate_public(cs: &mut ConstraintSystem, value: Option<u64>) -> Variable {
    let var = allocate(cs, value);
    cs.public_input_indices.push(var.index);
    cs.num_public_inputs += 1;
    var
}

/// Enforce an R1CS constraint: A * B = C.
pub fn enforce(
    cs: &mut ConstraintSystem,
    a: &LinearCombination,
    b: &LinearCombination,
    c: &LinearCombination,
) {
    cs.constraints.push(Constraint {
        a_terms: a.clone(),
        b_terms: b.clone(),
        c_terms: c.clone(),
    });
}

// ---------------------------------------------------------------------------
// Circuit trait
// ---------------------------------------------------------------------------

/// A circuit that can synthesize constraints.
pub trait Circuit {
    /// Synthesize the circuit's constraints into the given constraint system.
    fn synthesize(&self, cs: &mut ConstraintSystem) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple circuit: x * y = z
    #[derive(Debug)]
    struct MultiplyCircuit {
        x: Option<u64>,
        y: Option<u64>,
        z: Option<u64>,
    }

    impl Circuit for MultiplyCircuit {
        fn synthesize(&self, cs: &mut ConstraintSystem) -> Result<()> {
            let x = allocate_public(cs, self.x);
            let y = allocate(cs, self.y);
            let z = allocate_public(cs, self.z);

            // x * y = z
            let a = LinearCombination::from_variable(x);
            let b = LinearCombination::from_variable(y);
            let c = LinearCombination::from_variable(z);
            enforce(cs, &a, &b, &c);

            Ok(())
        }
    }

    /// A circuit that checks a + b = c using a * 1 = (c - a) pattern: (a + b) * 1 = c
    #[derive(Debug)]
    struct AddCircuit {
        a: Option<u64>,
        b: Option<u64>,
        c: Option<u64>,
    }

    impl Circuit for AddCircuit {
        fn synthesize(&self, cs: &mut ConstraintSystem) -> Result<()> {
            let a_var = allocate_public(cs, self.a);
            let b_var = allocate(cs, self.b);
            let c_var = allocate_public(cs, self.c);

            // (a + b) * 1 = c
            let mut a_lc = LinearCombination::zero();
            a_lc.add_term(1, a_var.index);
            a_lc.add_term(1, b_var.index);
            let b_lc = LinearCombination::constant(1);
            let c_lc = LinearCombination::from_variable(c_var);
            enforce(cs, &a_lc, &b_lc, &c_lc);

            Ok(())
        }
    }

    #[test]
    fn empty_constraint_system() {
        let cs = ConstraintSystem::new();
        assert_eq!(cs.num_variables(), 0);
        assert_eq!(cs.num_constraints(), 0);
        assert!(cs.is_satisfied());
    }

    #[test]
    fn default_constraint_system() {
        let cs = ConstraintSystem::default();
        assert!(cs.is_satisfied());
    }

    #[test]
    fn allocate_variable() {
        let mut cs = ConstraintSystem::new();
        let v = allocate(&mut cs, Some(42));
        assert_eq!(v.index, 0);
        assert_eq!(v.value, Some(42));
        assert_eq!(cs.num_variables(), 1);
    }

    #[test]
    fn allocate_public_input() {
        let mut cs = ConstraintSystem::new();
        let v = allocate_public(&mut cs, Some(10));
        assert_eq!(v.index, 0);
        assert_eq!(cs.num_public_inputs, 1);
    }

    #[test]
    fn multiply_circuit_satisfied() {
        let circuit = MultiplyCircuit {
            x: Some(3),
            y: Some(4),
            z: Some(12),
        };
        let mut cs = ConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();
        assert_eq!(cs.num_variables(), 3);
        assert_eq!(cs.num_constraints(), 1);
        assert_eq!(cs.num_public_inputs, 2);
        assert!(cs.is_satisfied());
    }

    #[test]
    fn multiply_circuit_not_satisfied() {
        let circuit = MultiplyCircuit {
            x: Some(3),
            y: Some(4),
            z: Some(13), // wrong
        };
        let mut cs = ConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();
        assert!(!cs.is_satisfied());
    }

    #[test]
    fn add_circuit_satisfied() {
        let circuit = AddCircuit {
            a: Some(5),
            b: Some(7),
            c: Some(12),
        };
        let mut cs = ConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();
        assert!(cs.is_satisfied());
    }

    #[test]
    fn add_circuit_not_satisfied() {
        let circuit = AddCircuit {
            a: Some(5),
            b: Some(7),
            c: Some(11), // wrong
        };
        let mut cs = ConstraintSystem::new();
        circuit.synthesize(&mut cs).unwrap();
        assert!(!cs.is_satisfied());
    }

    #[test]
    fn linear_combination_evaluate() {
        let mut lc = LinearCombination::zero();
        lc.add_term(2, 0); // 2 * x0
        lc.add_term(3, 1); // 3 * x1
        lc.add_term(5, usize::MAX); // 5 * 1

        let vars = vec![10, 20]; // x0=10, x1=20
        assert_eq!(lc.evaluate(&vars).unwrap(), 2 * 10 + 3 * 20 + 5);
    }

    #[test]
    fn linear_combination_zero() {
        let lc = LinearCombination::zero();
        assert_eq!(lc.evaluate(&[1, 2, 3]).unwrap(), 0);
    }

    #[test]
    fn linear_combination_constant() {
        let lc = LinearCombination::constant(42);
        assert_eq!(lc.evaluate(&[]).unwrap(), 42);
    }

    #[test]
    fn linear_combination_from_variable() {
        let v = Variable {
            index: 2,
            value: Some(7),
        };
        let lc = LinearCombination::from_variable(v);
        assert_eq!(lc.evaluate(&[0, 0, 7]).unwrap(), 7);
    }

    #[test]
    fn enforce_constraint() {
        let mut cs = ConstraintSystem::new();
        let x = allocate(&mut cs, Some(5));
        let y = allocate(&mut cs, Some(5));
        let z = allocate(&mut cs, Some(25));

        let a = LinearCombination::from_variable(x);
        let b = LinearCombination::from_variable(y);
        let c = LinearCombination::from_variable(z);
        enforce(&mut cs, &a, &b, &c);

        assert!(cs.is_satisfied());
    }

    #[test]
    fn multiple_constraints() {
        let mut cs = ConstraintSystem::new();
        let x = allocate(&mut cs, Some(2));
        let y = allocate(&mut cs, Some(3));
        let z = allocate(&mut cs, Some(6)); // x*y
        let w = allocate(&mut cs, Some(36)); // z*z

        // x * y = z
        enforce(
            &mut cs,
            &LinearCombination::from_variable(x),
            &LinearCombination::from_variable(y),
            &LinearCombination::from_variable(z),
        );

        // z * z = w
        enforce(
            &mut cs,
            &LinearCombination::from_variable(z),
            &LinearCombination::from_variable(z),
            &LinearCombination::from_variable(w),
        );

        assert_eq!(cs.num_constraints(), 2);
        assert!(cs.is_satisfied());
    }

    #[test]
    fn constraint_system_with_missing_witness_is_not_satisfied() {
        let mut cs = ConstraintSystem::new();
        let x = allocate(&mut cs, None);

        enforce(
            &mut cs,
            &LinearCombination::from_variable(x),
            &LinearCombination::constant(1),
            &LinearCombination::constant(0),
        );

        assert!(
            !cs.is_satisfied(),
            "missing witness variables must not be substituted with zero"
        );
    }

    #[test]
    fn constraint_system_with_unallocated_variable_reference_is_not_satisfied() {
        let mut cs = ConstraintSystem::new();
        let x = allocate(&mut cs, Some(0));
        let mut unallocated = LinearCombination::zero();
        unallocated.add_term(1, x.index + 1);

        enforce(
            &mut cs,
            &unallocated,
            &LinearCombination::constant(1),
            &LinearCombination::constant(0),
        );

        assert!(
            !cs.is_satisfied(),
            "constraints must not satisfy by treating unallocated variables as zero"
        );
    }

    #[test]
    fn constraint_system_with_overflowing_linear_combination_is_not_satisfied() {
        let mut cs = ConstraintSystem::new();
        let x = allocate(&mut cs, Some(u64::MAX));
        let y = allocate(&mut cs, Some(1));

        let mut overflowing_sum = LinearCombination::zero();
        overflowing_sum.add_term(1, x.index);
        overflowing_sum.add_term(1, y.index);

        enforce(
            &mut cs,
            &overflowing_sum,
            &LinearCombination::constant(1),
            &LinearCombination::constant(0),
        );

        assert!(
            !cs.is_satisfied(),
            "linear combination overflow must fail closed instead of wrapping to zero"
        );
    }

    #[test]
    fn constraint_system_with_overflowing_constraint_product_is_not_satisfied() {
        let mut cs = ConstraintSystem::new();
        let x = allocate(&mut cs, Some(u64::MAX));
        let y = allocate(&mut cs, Some(2));
        let z = allocate(&mut cs, Some(u64::MAX - 1));

        enforce(
            &mut cs,
            &LinearCombination::from_variable(x),
            &LinearCombination::from_variable(y),
            &LinearCombination::from_variable(z),
        );

        assert!(
            !cs.is_satisfied(),
            "constraint multiplication overflow must fail closed instead of wrapping"
        );
    }

    #[test]
    fn variable_without_value() {
        let mut cs = ConstraintSystem::new();
        let _v = allocate(&mut cs, None);
        assert_eq!(cs.variables[0].value, None);
    }

    #[test]
    fn constraint_clone_eq() {
        let c = Constraint {
            a_terms: LinearCombination::constant(1),
            b_terms: LinearCombination::constant(2),
            c_terms: LinearCombination::constant(2),
        };
        let c2 = c.clone();
        assert_eq!(c, c2);
    }
}
