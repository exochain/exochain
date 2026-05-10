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

'use strict';

/**
 * Catapult Service Layer
 *
 * Wraps all WASM catapult exports into named, documented JavaScript functions.
 * Handles franchise blueprints, newco lifecycle, ODA roster management,
 * heartbeat monitoring, budget enforcement, and goal alignment.
 *
 * Usage:
 *   const catapult = require('./services/catapult');
 *   const newco = catapult.instantiateNewco(blueprint, 'Acme Corp', hrDid, researcherDid);
 *
 * Every function throws on WASM error — callers are responsible for try/catch.
 */

const wasm = require('../../../packages/exochain-wasm/wasm');

// ── Internal helpers ─────────────────────────────────────────────────────────

function s(v) {
  return JSON.stringify(v);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1: FRANCHISE BLUEPRINTS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a new franchise blueprint.
 * @param {string} name - Blueprint name
 * @param {string|object} businessModel - BusinessModel enum ('SaaS', 'Marketplace', etc.)
 * @param {string} constitutionHashHex - 64-char hex hash of constitutional corpus
 * @returns {object} FranchiseBlueprint
 */
function createFranchiseBlueprint(name, businessModel, constitutionHashHex) {
  return wasm.wasm_create_franchise_blueprint(name, s(businessModel), constitutionHashHex);
}

/**
 * List all blueprints in a franchise registry.
 * @param {object} registry - FranchiseRegistry
 * @returns {object[]} Array of FranchiseBlueprint
 */
function listFranchiseBlueprints(registry) {
  return wasm.wasm_list_franchise_blueprints(s(registry));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2: NEWCO LIFECYCLE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Instantiate a new company from a blueprint with two founding agents.
 * @param {object} blueprint - FranchiseBlueprint
 * @param {string} name - Company name
 * @param {string} hrDid - DID of the HR/People Ops founding agent
 * @param {string} researcherDid - DID of the Deep Researcher founding agent
 * @returns {object} Newco (in Assessment phase with founders hired)
 */
function instantiateNewco(blueprint, name, hrDid, researcherDid) {
  return wasm.wasm_instantiate_newco(s(blueprint), name, hrDid, researcherDid);
}

/**
 * Advance a newco to the next operational phase.
 * @param {object} newco - Current Newco state
 * @param {string} targetPhase - Target OperationalPhase
 * @returns {object} Updated Newco
 */
function transitionPhase(newco, targetPhase) {
  return wasm.wasm_transition_newco_phase(s(newco), s(targetPhase));
}

/**
 * Get valid phase transitions from the current phase.
 * @param {string} phase - Current OperationalPhase
 * @returns {string[]} Valid target phases
 */
function validPhaseTransitions(phase) {
  return wasm.wasm_valid_phase_transitions(s(phase));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3: ODA ROSTER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Hire an agent into an ODA slot.
 * @param {object} newco - Current Newco state
 * @param {object} agent - CatapultAgent to hire
 * @returns {object} Updated Newco
 */
function hireAgent(newco, agent) {
  return wasm.wasm_hire_agent(s(newco), s(agent));
}

/**
 * Release an agent from an ODA slot.
 * @param {object} newco - Current Newco state
 * @param {string} slot - OdaSlot to release
 * @returns {object} { newco, released_agent }
 */
function releaseAgent(newco, slot) {
  return wasm.wasm_release_agent(s(newco), s(slot));
}

/**
 * Get roster status summary.
 * @param {object} newco - Current Newco state
 * @returns {object} { filled, vacancies, active, complete, has_founders }
 */
function rosterStatus(newco) {
  return wasm.wasm_roster_status(s(newco));
}

/**
 * Get ODA authority chain and PACE configuration.
 * @param {object} newco - Current Newco state
 * @returns {object} { primary, alternates, contingency, emergency }
 */
function odaAuthorityChain(newco) {
  return wasm.wasm_oda_authority_chain(s(newco));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4: HEARTBEAT
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Record a heartbeat from an agent.
 * @param {object} monitor - HeartbeatMonitor state
 * @param {object} record - HeartbeatRecord
 * @returns {object} Updated HeartbeatMonitor
 */
function recordHeartbeat(monitor, record) {
  return wasm.wasm_record_heartbeat(s(monitor), s(record));
}

/**
 * Check heartbeat health at the given time.
 * @param {object} monitor - HeartbeatMonitor state
 * @param {number} nowMs - Current time in milliseconds
 * @returns {object} { alerts, agent_count }
 */
function checkHeartbeatHealth(monitor, nowMs) {
  return wasm.wasm_check_heartbeat_health(s(monitor), nowMs);
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5: BUDGET
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Record a cost event in the budget ledger.
 * @param {object} ledger - BudgetLedger state
 * @param {object} event - CostEvent
 * @returns {object} Updated BudgetLedger
 */
function recordCostEvent(ledger, event) {
  return wasm.wasm_record_cost_event(s(ledger), s(event));
}

/**
 * Check budget enforcement for a given scope.
 * @param {object} ledger - BudgetLedger state
 * @param {string|object} scope - BudgetScope ('Company' or { Agent: { slot } })
 * @returns {object} { status: 'Ok'|'Warning'|'HardStop', spent?, limit? }
 */
function checkBudgetStatus(ledger, scope) {
  return wasm.wasm_check_budget_status(s(ledger), s(scope));
}

/**
 * Enforce budget across all company-level policies.
 * @param {object} newco - Current Newco state
 * @returns {object} { action: 'none'|'warn'|'suspend', status, spent?, limit? }
 */
function enforceBudget(newco) {
  return wasm.wasm_enforce_budget(s(newco));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6: GOALS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Add a goal to the goal tree.
 * @param {object} tree - GoalTree state
 * @param {object} goal - Goal to add
 * @returns {object} Updated GoalTree
 */
function createGoal(tree, goal) {
  return wasm.wasm_create_goal(s(tree), s(goal));
}

/**
 * Update a goal's status.
 * @param {object} tree - GoalTree state
 * @param {string} goalId - UUID of the goal
 * @param {string} status - GoalStatus ('Planned'|'Active'|'Completed'|'Blocked'|'Cancelled')
 * @returns {object} Updated GoalTree
 */
function updateGoalStatus(tree, goalId, status) {
  return wasm.wasm_update_goal_status(s(tree), goalId, s(status));
}

/**
 * Compute goal alignment score (0–10000 basis points).
 * @param {object} tree - GoalTree state
 * @returns {number} Alignment score in basis points
 */
function goalAlignmentScore(tree) {
  return wasm.wasm_goal_alignment_score(s(tree));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 7: TRUST RECEIPTS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generate a franchise trust receipt for an operation.
 * @param {string} newcoId - UUID of the newco
 * @param {object} operation - FranchiseOperation
 * @param {string} actorDid - DID of the actor
 * @returns {object} FranchiseReceipt
 */
function generateFranchiseReceipt(newcoId, operation, actorDid) {
  return wasm.wasm_generate_franchise_receipt(newcoId, s(operation), actorDid);
}

/**
 * Verify a franchise receipt chain's integrity.
 * @param {object} chain - ReceiptChain
 * @returns {boolean} True if chain is valid
 */
function verifyFranchiseReceiptChain(chain) {
  return wasm.wasm_verify_franchise_receipt_chain(s(chain));
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = {
  // Franchise
  createFranchiseBlueprint,
  listFranchiseBlueprints,
  // Newco
  instantiateNewco,
  transitionPhase,
  validPhaseTransitions,
  // ODA
  hireAgent,
  releaseAgent,
  rosterStatus,
  odaAuthorityChain,
  // Heartbeat
  recordHeartbeat,
  checkHeartbeatHealth,
  // Budget
  recordCostEvent,
  checkBudgetStatus,
  enforceBudget,
  // Goals
  createGoal,
  updateGoalStatus,
  goalAlignmentScore,
  // Receipts
  generateFranchiseReceipt,
  verifyFranchiseReceiptChain,
};
