//! Catapult bindings: franchise incubator, ODA team management, lifecycle

use wasm_bindgen::prelude::*;

use crate::serde_bridge::*;

// ---------------------------------------------------------------------------
// Franchise Blueprints
// ---------------------------------------------------------------------------

/// Create a new franchise blueprint.
#[wasm_bindgen]
pub fn wasm_create_franchise_blueprint(
    name: &str,
    business_model_json: &str,
    constitution_hash_hex: &str,
) -> Result<JsValue, JsValue> {
    let business_model: exo_catapult::BusinessModel = from_json_str(business_model_json)?;
    let hash_bytes =
        hex::decode(constitution_hash_hex).map_err(|e| JsValue::from_str(&format!("hex: {e}")))?;
    let hash_arr: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| JsValue::from_str("constitution hash must be 32 bytes"))?;
    let constitution_hash = exo_core::Hash256::from_bytes(hash_arr);

    let blueprint = exo_catapult::FranchiseBlueprint {
        id: uuid::Uuid::new_v4(),
        name: name.to_owned(),
        version: exo_core::Version::ZERO.next(),
        description: String::new(),
        business_model,
        constitution_hash,
        required_slots: exo_catapult::OdaSlot::ALL.to_vec(),
        budget_template: exo_catapult::budget::BudgetTemplate::default(),
        goal_template: exo_catapult::goal::GoalTemplate::default(),
        created: exo_core::Timestamp::ZERO,
        content_hash: exo_core::Hash256::ZERO,
    };
    to_js_value(&blueprint)
}

/// List all blueprints in a franchise registry.
#[wasm_bindgen]
pub fn wasm_list_franchise_blueprints(registry_json: &str) -> Result<JsValue, JsValue> {
    let registry: exo_catapult::FranchiseRegistry = from_json_str(registry_json)?;
    let list: Vec<&exo_catapult::FranchiseBlueprint> = registry.list();
    to_js_value(&list)
}

// ---------------------------------------------------------------------------
// Newco Lifecycle
// ---------------------------------------------------------------------------

/// Instantiate a new company from a franchise blueprint with founding agents.
#[wasm_bindgen]
pub fn wasm_instantiate_newco(
    blueprint_json: &str,
    name: &str,
    hr_did: &str,
    researcher_did: &str,
) -> Result<JsValue, JsValue> {
    let blueprint: exo_catapult::FranchiseBlueprint = from_json_str(blueprint_json)?;
    let hr =
        exo_core::Did::new(hr_did).map_err(|e| JsValue::from_str(&format!("HR DID error: {e}")))?;
    let researcher = exo_core::Did::new(researcher_did)
        .map_err(|e| JsValue::from_str(&format!("Researcher DID error: {e}")))?;

    let mut newco = exo_catapult::newco::Newco::new(
        name.to_owned(),
        blueprint.id,
        uuid::Uuid::new_v4(),
        blueprint.constitution_hash,
        hr.clone(),
        exo_core::Timestamp::ZERO,
    );

    // Hire founding agents
    let hr_agent = exo_catapult::CatapultAgent {
        did: hr.clone(),
        slot: exo_catapult::OdaSlot::HrPeopleOps1,
        display_name: "HR / People Ops 1".into(),
        capabilities: vec!["assessment".into(), "selection".into(), "talent".into()],
        status: exo_catapult::AgentStatus::Active,
        last_heartbeat: exo_core::Timestamp::ZERO,
        budget_spent_cents: 0,
        budget_limit_cents: 1_000_000,
        hired_at: exo_core::Timestamp::ZERO,
        hired_by: hr.clone(),
        commandbase_profile: None,
    };
    newco
        .hire_agent(hr_agent)
        .map_err(|e| JsValue::from_str(&format!("Hire HR error: {e}")))?;

    let researcher_agent = exo_catapult::CatapultAgent {
        did: researcher.clone(),
        slot: exo_catapult::OdaSlot::DeepResearcher,
        display_name: "Deep Researcher".into(),
        capabilities: vec![
            "intelligence".into(),
            "analysis".into(),
            "market-research".into(),
        ],
        status: exo_catapult::AgentStatus::Active,
        last_heartbeat: exo_core::Timestamp::ZERO,
        budget_spent_cents: 0,
        budget_limit_cents: 1_000_000,
        hired_at: exo_core::Timestamp::ZERO,
        hired_by: hr,
        commandbase_profile: None,
    };
    newco
        .hire_agent(researcher_agent)
        .map_err(|e| JsValue::from_str(&format!("Hire Researcher error: {e}")))?;

    to_js_value(&newco)
}

/// Advance a newco to the next operational phase.
#[wasm_bindgen]
pub fn wasm_transition_newco_phase(
    newco_json: &str,
    target_phase_json: &str,
) -> Result<JsValue, JsValue> {
    let mut newco: exo_catapult::newco::Newco = from_json_str(newco_json)?;
    let target: exo_catapult::phase::OperationalPhase = from_json_str(target_phase_json)?;
    newco
        .advance_phase(target)
        .map_err(|e| JsValue::from_str(&format!("Phase transition error: {e}")))?;
    to_js_value(&newco)
}

/// Get valid transitions from the current phase.
#[wasm_bindgen]
pub fn wasm_valid_phase_transitions(phase_json: &str) -> Result<JsValue, JsValue> {
    let phase: exo_catapult::phase::OperationalPhase = from_json_str(phase_json)?;
    let transitions = phase.valid_transitions();
    to_js_value(&transitions)
}

// ---------------------------------------------------------------------------
// ODA Roster
// ---------------------------------------------------------------------------

/// Hire an agent into an ODA slot.
#[wasm_bindgen]
pub fn wasm_hire_agent(newco_json: &str, agent_json: &str) -> Result<JsValue, JsValue> {
    let mut newco: exo_catapult::newco::Newco = from_json_str(newco_json)?;
    let agent: exo_catapult::CatapultAgent = from_json_str(agent_json)?;
    newco
        .hire_agent(agent)
        .map_err(|e| JsValue::from_str(&format!("Hire error: {e}")))?;
    to_js_value(&newco)
}

/// Release an agent from an ODA slot.
#[wasm_bindgen]
pub fn wasm_release_agent(newco_json: &str, slot_json: &str) -> Result<JsValue, JsValue> {
    let mut newco: exo_catapult::newco::Newco = from_json_str(newco_json)?;
    let slot: exo_catapult::OdaSlot = from_json_str(slot_json)?;
    let released = newco
        .release_agent(&slot)
        .map_err(|e| JsValue::from_str(&format!("Release error: {e}")))?;
    to_js_value(&serde_json::json!({
        "newco": newco,
        "released_agent": released,
    }))
}

/// Get roster status summary.
#[wasm_bindgen]
pub fn wasm_roster_status(newco_json: &str) -> Result<JsValue, JsValue> {
    let newco: exo_catapult::newco::Newco = from_json_str(newco_json)?;
    to_js_value(&serde_json::json!({
        "filled": newco.roster.filled_count(),
        "vacancies": newco.roster.vacancy_count(),
        "active": newco.roster.active_count(),
        "complete": newco.roster.is_complete(),
        "has_founders": newco.has_founders(),
    }))
}

/// Get the ODA authority chain and PACE configuration.
#[wasm_bindgen]
pub fn wasm_oda_authority_chain(newco_json: &str) -> Result<JsValue, JsValue> {
    let newco: exo_catapult::newco::Newco = from_json_str(newco_json)?;
    let pace = exo_catapult::integration::build_pace_config(&newco);
    to_js_value(&serde_json::json!({
        "primary": pace.primary.map(|d| d.to_string()),
        "alternates": pace.alternates.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        "contingency": pace.contingency.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        "emergency": pace.emergency.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
    }))
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

/// Record a heartbeat from an agent.
#[wasm_bindgen]
pub fn wasm_record_heartbeat(monitor_json: &str, record_json: &str) -> Result<JsValue, JsValue> {
    let mut monitor: exo_catapult::HeartbeatMonitor = from_json_str(monitor_json)?;
    let record: exo_catapult::HeartbeatRecord = from_json_str(record_json)?;
    monitor.record(record);
    to_js_value(&monitor)
}

/// Check heartbeat health at the given time, returning alerts.
#[wasm_bindgen]
pub fn wasm_check_heartbeat_health(monitor_json: &str, now_ms: u64) -> Result<JsValue, JsValue> {
    let monitor: exo_catapult::HeartbeatMonitor = from_json_str(monitor_json)?;
    let now = exo_core::Timestamp {
        physical_ms: now_ms,
        logical: 0,
    };
    let alerts = monitor.check_health(&now);
    to_js_value(&serde_json::json!({
        "alerts": alerts.iter().map(|a| serde_json::json!({
            "agent_did": a.agent_did.to_string(),
            "last_seen_ms": a.last_seen.physical_ms,
            "elapsed_ms": a.elapsed_ms,
            "severity": format!("{:?}", a.severity),
        })).collect::<Vec<_>>(),
        "agent_count": monitor.agent_count(),
    }))
}

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

/// Record a cost event in the budget ledger.
#[wasm_bindgen]
pub fn wasm_record_cost_event(ledger_json: &str, event_json: &str) -> Result<JsValue, JsValue> {
    let mut ledger: exo_catapult::BudgetLedger = from_json_str(ledger_json)?;
    let event: exo_catapult::CostEvent = from_json_str(event_json)?;
    ledger.record_cost(event);
    to_js_value(&ledger)
}

/// Check budget enforcement for a given scope.
#[wasm_bindgen]
pub fn wasm_check_budget_status(ledger_json: &str, scope_json: &str) -> Result<JsValue, JsValue> {
    let ledger: exo_catapult::BudgetLedger = from_json_str(ledger_json)?;
    let scope: exo_catapult::BudgetScope = from_json_str(scope_json)?;
    let verdict = ledger.check_enforcement(&scope);
    let json = match verdict {
        exo_catapult::BudgetVerdict::Ok => serde_json::json!({"status": "Ok"}),
        exo_catapult::BudgetVerdict::Warning { spent, limit } => {
            serde_json::json!({"status": "Warning", "spent": spent, "limit": limit})
        }
        exo_catapult::BudgetVerdict::HardStop { spent, limit } => {
            serde_json::json!({"status": "HardStop", "spent": spent, "limit": limit})
        }
    };
    to_js_value(&json)
}

/// Enforce budget across all company-level policies, returning actions needed.
#[wasm_bindgen]
pub fn wasm_enforce_budget(newco_json: &str) -> Result<JsValue, JsValue> {
    let newco: exo_catapult::newco::Newco = from_json_str(newco_json)?;
    let company_verdict = newco
        .budget
        .check_enforcement(&exo_catapult::BudgetScope::Company);
    let json = match company_verdict {
        exo_catapult::BudgetVerdict::Ok => {
            serde_json::json!({"action": "none", "status": "Ok"})
        }
        exo_catapult::BudgetVerdict::Warning { spent, limit } => {
            serde_json::json!({"action": "warn", "status": "Warning", "spent": spent, "limit": limit})
        }
        exo_catapult::BudgetVerdict::HardStop { spent, limit } => {
            serde_json::json!({"action": "suspend", "status": "HardStop", "spent": spent, "limit": limit})
        }
    };
    to_js_value(&json)
}

// ---------------------------------------------------------------------------
// Goals
// ---------------------------------------------------------------------------

/// Add a goal to the goal tree.
#[wasm_bindgen]
pub fn wasm_create_goal(tree_json: &str, goal_json: &str) -> Result<JsValue, JsValue> {
    let mut tree: exo_catapult::GoalTree = from_json_str(tree_json)?;
    let goal: exo_catapult::Goal = from_json_str(goal_json)?;
    tree.add(goal)
        .map_err(|e| JsValue::from_str(&format!("Goal error: {e}")))?;
    to_js_value(&tree)
}

/// Update a goal's status.
#[wasm_bindgen]
pub fn wasm_update_goal_status(
    tree_json: &str,
    goal_id: &str,
    status_json: &str,
) -> Result<JsValue, JsValue> {
    let mut tree: exo_catapult::GoalTree = from_json_str(tree_json)?;
    let id: uuid::Uuid = goal_id
        .parse()
        .map_err(|e| JsValue::from_str(&format!("UUID error: {e}")))?;
    let status: exo_catapult::GoalStatus = from_json_str(status_json)?;
    tree.update_status(&id, status)
        .map_err(|e| JsValue::from_str(&format!("Goal update error: {e}")))?;
    to_js_value(&tree)
}

/// Compute goal alignment score (0–10000 basis points).
#[wasm_bindgen]
pub fn wasm_goal_alignment_score(tree_json: &str) -> Result<u32, JsValue> {
    let tree: exo_catapult::GoalTree = from_json_str(tree_json)?;
    Ok(tree.alignment_score())
}

// ---------------------------------------------------------------------------
// Trust Receipts
// ---------------------------------------------------------------------------

/// Generate a franchise trust receipt for an operation.
#[wasm_bindgen]
pub fn wasm_generate_franchise_receipt(
    newco_id: &str,
    operation_json: &str,
    actor_did: &str,
) -> Result<JsValue, JsValue> {
    let id: uuid::Uuid = newco_id
        .parse()
        .map_err(|e| JsValue::from_str(&format!("UUID error: {e}")))?;
    let operation: exo_catapult::FranchiseOperation = from_json_str(operation_json)?;
    let actor =
        exo_core::Did::new(actor_did).map_err(|e| JsValue::from_str(&format!("DID error: {e}")))?;

    let receipt = exo_catapult::FranchiseReceipt::new(
        id,
        operation,
        actor,
        exo_core::Timestamp::ZERO,
        exo_core::Hash256::digest(b"state"),
        exo_core::Hash256::ZERO,
    );
    to_js_value(&receipt)
}

/// Verify a franchise receipt chain's integrity.
#[wasm_bindgen]
pub fn wasm_verify_franchise_receipt_chain(chain_json: &str) -> Result<bool, JsValue> {
    let chain: exo_catapult::receipt::ReceiptChain = from_json_str(chain_json)?;
    Ok(chain.verify_chain())
}
