<!--
Copyright 2026 Exochain Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# ULTRAPLAN: GAP-005 & GAP-006 — Gateway Auth, RBAC, and Custom Constraints

## 1. Gateway Auth & RBAC (GAP-005)

### Identity Verification & The Authenticator
The gateway will act as the single point of entry for all API requests. We will introduce an `Authenticator` struct in `exo-gateway/src/auth.rs` which wraps the `LocalDidRegistry` and a mock or real `RiskAttestation` registry.
1. **Request Verification**: A new method `verify_request` will take a signed request, a target risk threshold, and a target permission. 
2. **Signature & DID Check**: It will resolve the DID from the registry and cryptographically verify the request signature (building upon the existing `authenticate` function).
3. **Risk Scoring**: It will query the risk score for the resolved DID (via `VerificationCeremony` or pre-calculated attestation) and ensure it meets the required threshold.

### Role-Based Access Control (RBAC)
We will introduce `Role` and `Permission` enums to express static access control lists.
- **Roles**: `Admin`, `ExecutiveChair`, `BoardMember`, `Observer`.
- **Permissions**: `Read`, `Write`, `Vote`, `Manage`.
- **Mapping**: 
  - `Admin` has all permissions.
  - `ExecutiveChair` has `Read`, `Write`, `Vote`, `Manage`.
  - `BoardMember` has `Read`, `Vote`.
  - `Observer` has `Read`.
The `has_permission` function will enforce this statically. Tenant isolation and conflict declarations are enforced by ensuring that actions crossing tenant boundaries or matching specific conflict DIDs are rejected by the gateway before reaching the internal DAG engines.

## 2. Custom Constitutional Constraints (GAP-006)

### Deterministic AST Evaluator
To allow tenants to define custom constraints safely (no WASM overhead, no floating point, no unsafe code), we will implement a structured Abstract Syntax Tree (AST) evaluator in `exo-governance/src/constitution.rs`.
- **AST Nodes**:
  - `Expr::Variable(String)`: Looks up a value in the `DeterministicMap` context.
  - `Expr::Literal(String)`: A constant string value.
  - `Expr::Eq(Box<Expr>, Box<Expr>)`: String equality.
  - `Expr::GreaterThan(Box<Expr>, Box<Expr>)`: Numeric comparison (strings parsed as u64).
  - `Expr::Contains(Box<Expr>, Box<Expr>)`: Substring check.

### Evaluation Engine
We define `CustomConstraint`:
```rust
pub struct CustomConstraint {
    pub id: String,
    pub description: String,
    pub expression: Expr,
}
```
The function `evaluate_custom_constraints(constraints: &[CustomConstraint], context: &DeterministicMap<String, String>) -> Result<(), GovernanceError>` will iterate over the constraints. If any `Expr` evaluates to `false`, it returns a `GovernanceError::ConstitutionalViolation`. This deterministic engine guarantees that the same state and context will always yield the same authorization result across all nodes.

## 3. Integration
When a request arrives at the Gateway:
1. `Authenticator::verify_request` authenticates the DID, verifies the risk score, and checks RBAC permissions.
2. If the request represents a governance action, the gateway pulls the tenant's `CustomConstraint` list and the current `DeterministicMap` context.
3. `evaluate_custom_constraints` runs. If it passes, the action is routed to the consensus engine and appended to the DAG.