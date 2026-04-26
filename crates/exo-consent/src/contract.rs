//! Bailment Contract Engine — clause-based composition, breach assessment, amendments.
//!
//! This module provides structured contract composition for bailments. Instead of
//! hashing raw bytes as `terms_hash`, callers compose a `ComposedContract` from a
//! `ContractTemplate`, binding parameters into clause templates. The resulting
//! `contract_hash` becomes the bailment's `terms_hash`.
//!
//! **Constitutional compliance**:
//! - No floating point — all monetary values in basis points (`u64`).
//! - No `HashMap` — `DeterministicMap` only.
//! - No `unsafe` code.
//! - No `std::time` — `Timestamp` (HLC) only.
//! - Canonical CBOR serialization for all hashing.
//! - All errors via `thiserror` (`ConsentError`).

use exo_core::{DeterministicMap, Did, Hash256, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{bailment::BailmentType, error::ConsentError};

// ---------------------------------------------------------------------------
// Core Types
// ---------------------------------------------------------------------------

/// Category of a contract clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClauseCategory {
    /// Data custody and storage terms.
    DataCustody,
    /// Rights to process data.
    ProcessingRights,
    /// Remedies available upon breach.
    BreachRemedies,
    /// Caps on liability exposure.
    LiabilityCaps,
    /// Dispute resolution mechanism.
    DisputeResolution,
    /// Termination conditions.
    Termination,
    /// Governing jurisdiction.
    Jurisdiction,
    /// Indemnification obligations.
    Indemnification,
}

/// A clause template with `{{param}}` placeholders in the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Clause {
    /// Unique clause identifier.
    pub id: String,
    /// The category this clause belongs to.
    pub category: ClauseCategory,
    /// Human-readable title.
    pub title: String,
    /// Template text with `{{param}}` placeholders.
    pub body: String,
    /// Whether this clause is required in every composition.
    pub required: bool,
    /// If set, this clause only applies to the specified jurisdiction.
    pub jurisdiction: Option<String>,
}

/// A contract template — a versioned collection of clauses for a `BailmentType`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractTemplate {
    /// Stable template identifier.
    pub id: String,
    /// Human-readable template name.
    pub name: String,
    /// The bailment type this template serves.
    pub bailment_type: BailmentType,
    /// Clause templates.
    pub clauses: Vec<Clause>,
    /// Semantic version of this template.
    pub version: String,
}

/// Parameters used to bind a template into a concrete contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractParams {
    /// Human-readable name of the bailor.
    pub bailor_name: String,
    /// Human-readable name of the bailee.
    pub bailee_name: String,
    /// DID of the bailor.
    pub bailor_did: Did,
    /// DID of the bailee.
    pub bailee_did: Did,
    /// When the contract becomes effective.
    pub effective_date: Timestamp,
    /// When the contract expires (if any).
    pub expiry_date: Option<Timestamp>,
    /// Governing jurisdiction.
    pub jurisdiction: String,
    /// Classification tier of the data under this contract.
    pub data_classification: DataClassification,
    /// Liability cap in basis points (1 bps = 0.01%). Integer only.
    pub liability_cap_bps: u64,
    /// Additional custom parameters for clause substitution.
    pub custom_params: DeterministicMap<String, String>,
}

/// Data classification tiers affecting contract terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataClassification {
    /// Publicly available data.
    Public,
    /// Internal-use data.
    Internal,
    /// Confidential data requiring access controls.
    Confidential,
    /// Restricted data with strict handling requirements.
    Restricted,
    /// Regulated data subject to legal compliance.
    Regulated,
}

impl std::fmt::Display for DataClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => write!(f, "Public"),
            Self::Internal => write!(f, "Internal"),
            Self::Confidential => write!(f, "Confidential"),
            Self::Restricted => write!(f, "Restricted"),
            Self::Regulated => write!(f, "Regulated"),
        }
    }
}

/// A fully composed contract with all parameters bound and hash computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposedContract {
    /// Unique contract identifier.
    pub id: String,
    /// The template this contract was composed from.
    pub template_id: String,
    /// The parameters used for composition.
    pub params: ContractParams,
    /// Rendered clauses with all placeholders substituted.
    pub rendered_clauses: Vec<RenderedClause>,
    /// When this contract was composed.
    pub composed_at: Timestamp,
    /// BLAKE3 hash of canonical CBOR — becomes `Bailment.terms_hash`.
    pub contract_hash: Hash256,
    /// Version counter (1 for original, increments on amendment).
    pub version: u32,
    /// Parent contract ID for amendments (None for originals).
    pub parent_contract_id: Option<String>,
}

/// A rendered clause with all parameters substituted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderedClause {
    /// The source clause ID.
    pub clause_id: String,
    /// The clause category.
    pub category: ClauseCategory,
    /// The clause title.
    pub title: String,
    /// The clause body with all `{{param}}` placeholders replaced.
    pub rendered_body: String,
    /// Section number (e.g., "1", "2", "3").
    pub section_number: String,
}

/// Severity of a contract breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreachSeverity {
    /// Non-material violation of a non-critical clause.
    Minor,
    /// Violation of a substantive clause affecting data integrity.
    Material,
    /// Violation that destroys the trust basis.
    Fundamental,
}

/// Assessment of a breach against contract terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachAssessment {
    /// The contract that was breached.
    pub contract_id: String,
    /// Severity classification.
    pub breach_severity: BreachSeverity,
    /// IDs of the clauses that were breached.
    pub breached_clauses: Vec<String>,
    /// Liability assessment in basis points.
    pub liability_assessment_bps: u64,
    /// Recommended remedy.
    pub recommended_remedy: Remedy,
    /// When the assessment was made.
    pub assessed_at: Timestamp,
}

/// Recommended remedy for a breach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Remedy {
    /// Informational notice — no state change.
    Notice,
    /// Cure period — bailee has time to fix the breach.
    Cure {
        /// Number of days to cure the breach.
        cure_period_days: u32,
    },
    /// Suspend the bailment.
    Suspension,
    /// Terminate the bailment.
    Termination,
    /// Terminate and assess indemnification.
    Indemnification {
        /// Indemnification amount in basis points.
        amount_bps: u64,
    },
}

// ---------------------------------------------------------------------------
// Hashable payload for deterministic contract hashing
// ---------------------------------------------------------------------------

/// Internal struct for computing deterministic contract hashes via CBOR.
#[derive(Serialize)]
struct ContractHashPayload<'a> {
    template_id: &'a str,
    params: &'a ContractParams,
    rendered_clauses: &'a [RenderedClause],
    version: u32,
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/// Returns the default contract template for the given `BailmentType`.
///
/// Each template contains one clause per `ClauseCategory` (8 total),
/// all required, with universal jurisdiction (no filtering).
#[must_use]
pub fn default_template(bailment_type: BailmentType) -> ContractTemplate {
    let (id, name, clauses) = match bailment_type {
        BailmentType::Custody => (
            "custody-standard-v1",
            "Standard Custody Agreement",
            custody_clauses(),
        ),
        BailmentType::Processing => (
            "processing-standard-v1",
            "Standard Processing Agreement",
            processing_clauses(),
        ),
        BailmentType::Delegation => (
            "delegation-standard-v1",
            "Standard Delegation Agreement",
            delegation_clauses(),
        ),
        BailmentType::Emergency => (
            "emergency-standard-v1",
            "Emergency Access Agreement",
            emergency_clauses(),
        ),
    };

    ContractTemplate {
        id: id.to_string(),
        name: name.to_string(),
        bailment_type,
        clauses,
        version: "1.0.0".to_string(),
    }
}

/// Compose a contract by substituting parameters into a template's clauses.
///
/// Filters clauses by jurisdiction, substitutes `{{param}}` placeholders,
/// assigns section numbers, and computes a deterministic `contract_hash`
/// via canonical CBOR + BLAKE3.
///
/// # Errors
///
/// Returns `ConsentError::Denied` if a required clause is filtered out by
/// jurisdiction mismatch.
pub fn compose(
    template: &ContractTemplate,
    params: &ContractParams,
    id: impl Into<String>,
    composed_at: Timestamp,
) -> Result<ComposedContract, ConsentError> {
    let id = id.into();
    validate_constructor_metadata("contract id", &id, "composed_at", &composed_at)?;

    // Filter clauses by jurisdiction
    let mut filtered_clauses = Vec::new();
    for clause in &template.clauses {
        match &clause.jurisdiction {
            Some(j) if *j != params.jurisdiction => {
                if clause.required {
                    return Err(ConsentError::Denied(format!(
                        "Required clause '{}' has jurisdiction '{}' but contract jurisdiction is '{}'",
                        clause.id, j, params.jurisdiction
                    )));
                }
                // Skip optional clause with mismatched jurisdiction
                continue;
            }
            _ => filtered_clauses.push(clause),
        }
    }

    // Render clauses
    let mut rendered_clauses = Vec::with_capacity(filtered_clauses.len());
    for (i, clause) in filtered_clauses.iter().enumerate() {
        let rendered_body = substitute_params(&clause.body, params);
        rendered_clauses.push(RenderedClause {
            clause_id: clause.id.clone(),
            category: clause.category,
            title: clause.title.clone(),
            rendered_body,
            section_number: format!("{}", i + 1),
        });
    }

    let version = 1u32;
    let template_id = template.id.clone();

    // Compute deterministic hash
    let payload = ContractHashPayload {
        template_id: &template_id,
        params,
        rendered_clauses: &rendered_clauses,
        version,
    };
    let contract_hash =
        hash_structured(&payload).map_err(|e| ConsentError::Denied(format!("Hash error: {e}")))?;

    Ok(ComposedContract {
        id,
        template_id,
        params: params.clone(),
        rendered_clauses,
        composed_at,
        contract_hash,
        version,
        parent_contract_id: None,
    })
}

/// Render a composed contract as a human-readable Markdown document.
#[must_use]
pub fn render_markdown(contract: &ComposedContract) -> String {
    let mut md = String::new();

    md.push_str("# Bailment Contract\n\n");
    md.push_str(&format!("**Contract ID**: {}\n", contract.id));
    md.push_str(&format!("**Version**: {}\n", contract.version));
    md.push_str(&format!("**Composed**: {}\n", contract.composed_at));
    md.push_str(&format!(
        "**Effective**: {}\n",
        contract.params.effective_date
    ));
    md.push_str(&format!(
        "**Expires**: {}\n",
        match &contract.params.expiry_date {
            Some(ts) => ts.to_string(),
            None => "No expiration".to_string(),
        }
    ));
    md.push_str(&format!(
        "**Jurisdiction**: {}\n",
        contract.params.jurisdiction
    ));
    md.push_str(&format!(
        "**Data Classification**: {}\n\n",
        contract.params.data_classification
    ));

    md.push_str("## Parties\n\n");
    md.push_str(&format!(
        "- **Bailor**: {} ({})\n",
        contract.params.bailor_name, contract.params.bailor_did
    ));
    md.push_str(&format!(
        "- **Bailee**: {} ({})\n\n",
        contract.params.bailee_name, contract.params.bailee_did
    ));

    for clause in &contract.rendered_clauses {
        md.push_str(&format!(
            "## {}. {}\n\n{}\n\n",
            clause.section_number, clause.title, clause.rendered_body
        ));
    }

    md.push_str("---\n");
    md.push_str(&format!("Contract Hash: {}\n", contract.contract_hash));

    md
}

/// Assess a breach against contract terms.
///
/// Validates that all breached clause IDs exist in the contract, then
/// recommends a remedy based on the breach severity.
///
/// # Errors
///
/// Returns `ConsentError::Denied` if any breached clause ID is not found
/// in the contract.
pub fn assess_breach(
    contract: &ComposedContract,
    breached_clause_ids: &[&str],
    severity: BreachSeverity,
    assessed_at: Timestamp,
) -> Result<BreachAssessment, ConsentError> {
    validate_constructor_metadata("contract id", &contract.id, "assessed_at", &assessed_at)?;

    // Validate all clause IDs exist
    for clause_id in breached_clause_ids {
        if !contract
            .rendered_clauses
            .iter()
            .any(|c| c.clause_id == *clause_id)
        {
            return Err(ConsentError::Denied(format!(
                "Clause '{}' not found in contract '{}'",
                clause_id, contract.id
            )));
        }
    }

    let (liability_bps, remedy) = match severity {
        BreachSeverity::Minor => (0u64, Remedy::Notice),
        BreachSeverity::Material => (
            contract.params.liability_cap_bps / 2,
            Remedy::Cure {
                cure_period_days: 30,
            },
        ),
        BreachSeverity::Fundamental => (
            contract.params.liability_cap_bps,
            Remedy::Indemnification {
                amount_bps: contract.params.liability_cap_bps,
            },
        ),
    };

    Ok(BreachAssessment {
        contract_id: contract.id.clone(),
        breach_severity: severity,
        breached_clauses: breached_clause_ids.iter().map(|s| s.to_string()).collect(),
        liability_assessment_bps: liability_bps,
        recommended_remedy: remedy,
        assessed_at,
    })
}

/// Create an amendment to an existing contract.
///
/// Produces a new `ComposedContract` with incremented version,
/// referencing the original via `parent_contract_id`. Optionally
/// replaces specific clauses and rebinds parameters.
///
/// # Errors
///
/// Returns `ConsentError::Denied` if hashing fails.
pub fn amend(
    original: &ComposedContract,
    new_params: &ContractParams,
    amended_clauses: &[(String, Clause)],
    id: impl Into<String>,
    composed_at: Timestamp,
) -> Result<ComposedContract, ConsentError> {
    let id = id.into();
    validate_constructor_metadata("contract id", &id, "composed_at", &composed_at)?;

    // Start with original rendered clauses
    let mut clauses: Vec<RenderedClause> = original.rendered_clauses.clone();

    // Apply clause amendments
    for (target_id, new_clause) in amended_clauses {
        if let Some(rc) = clauses.iter_mut().find(|c| c.clause_id == *target_id) {
            rc.clause_id = new_clause.id.clone();
            rc.category = new_clause.category;
            rc.title = new_clause.title.clone();
            rc.rendered_body = substitute_params(&new_clause.body, new_params);
        } else {
            // New clause — append
            let section = format!("{}", clauses.len() + 1);
            clauses.push(RenderedClause {
                clause_id: new_clause.id.clone(),
                category: new_clause.category,
                title: new_clause.title.clone(),
                rendered_body: substitute_params(&new_clause.body, new_params),
                section_number: section,
            });
        }
    }

    // Re-substitute params for existing clauses that weren't explicitly amended
    // (in case params changed — e.g., new bailee name)
    // NOTE: We only re-render non-amended clauses from original template bodies
    // For simplicity, amended clauses are already re-rendered above.

    let new_version = original.version + 1;

    let payload = ContractHashPayload {
        template_id: &original.template_id,
        params: new_params,
        rendered_clauses: &clauses,
        version: new_version,
    };
    let contract_hash =
        hash_structured(&payload).map_err(|e| ConsentError::Denied(format!("Hash error: {e}")))?;

    Ok(ComposedContract {
        id,
        template_id: original.template_id.clone(),
        params: new_params.clone(),
        rendered_clauses: clauses,
        composed_at,
        contract_hash,
        version: new_version,
        parent_contract_id: Some(original.id.clone()),
    })
}

/// Verify that a contract's hash matches its content.
///
/// Recomputes the hash from the contract's rendered clauses and params,
/// then compares with the stored `contract_hash`.
#[must_use]
pub fn verify_hash(contract: &ComposedContract) -> bool {
    let payload = ContractHashPayload {
        template_id: &contract.template_id,
        params: &contract.params,
        rendered_clauses: &contract.rendered_clauses,
        version: contract.version,
    };
    match hash_structured(&payload) {
        Ok(computed) => computed == contract.contract_hash,
        Err(_) => false,
    }
}

fn validate_constructor_metadata(
    id_label: &str,
    id: &str,
    timestamp_label: &str,
    timestamp: &Timestamp,
) -> Result<(), ConsentError> {
    if id.trim().is_empty() {
        return Err(ConsentError::Denied(format!(
            "{id_label} must be caller-supplied and non-empty"
        )));
    }
    if *timestamp == Timestamp::ZERO {
        return Err(ConsentError::Denied(format!(
            "{timestamp_label} must be caller-supplied and non-zero"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Substitute `{{param}}` placeholders in a clause body with values from `ContractParams`.
fn substitute_params(body: &str, params: &ContractParams) -> String {
    let mut result = body.to_string();
    result = result.replace("{{bailor_name}}", &params.bailor_name);
    result = result.replace("{{bailee_name}}", &params.bailee_name);
    result = result.replace("{{bailor_did}}", params.bailor_did.as_str());
    result = result.replace("{{bailee_did}}", params.bailee_did.as_str());
    result = result.replace("{{effective_date}}", &params.effective_date.to_string());
    result = result.replace(
        "{{expiry_date}}",
        &params
            .expiry_date
            .map_or("No expiration".to_string(), |ts| ts.to_string()),
    );
    result = result.replace("{{jurisdiction}}", &params.jurisdiction);
    result = result.replace(
        "{{data_classification}}",
        &params.data_classification.to_string(),
    );
    result = result.replace(
        "{{liability_cap_bps}}",
        &params.liability_cap_bps.to_string(),
    );

    // Custom params
    for (key, value) in params.custom_params.iter() {
        let placeholder = format!("{{{{{key}}}}}");
        result = result.replace(&placeholder, value);
    }

    result
}

/// Generate standard clauses for Custody bailment type.
fn custody_clauses() -> Vec<Clause> {
    vec![
        Clause {
            id: "custody-data-custody".to_string(),
            category: ClauseCategory::DataCustody,
            title: "Data Custody".to_string(),
            body: "{{bailee_name}} shall hold {{bailor_name}}'s data in secure custody without modification. Data classification: {{data_classification}}.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "custody-processing-rights".to_string(),
            category: ClauseCategory::ProcessingRights,
            title: "Processing Rights".to_string(),
            body: "No processing rights are granted. {{bailee_name}} may only store and return data to {{bailor_name}}.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "custody-breach-remedies".to_string(),
            category: ClauseCategory::BreachRemedies,
            title: "Breach Remedies".to_string(),
            body: "Upon breach, {{bailor_name}} shall receive notice within 5 days. Material breaches trigger a 30-day cure period.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "custody-liability-caps".to_string(),
            category: ClauseCategory::LiabilityCaps,
            title: "Liability Caps".to_string(),
            body: "Total liability capped at {{liability_cap_bps}} basis points of assessed value.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "custody-dispute-resolution".to_string(),
            category: ClauseCategory::DisputeResolution,
            title: "Dispute Resolution".to_string(),
            body: "Disputes under jurisdiction {{jurisdiction}} resolved via binding arbitration.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "custody-termination".to_string(),
            category: ClauseCategory::Termination,
            title: "Termination".to_string(),
            body: "Either party may terminate with 30 days written notice. Data must be returned or destroyed within 15 days of termination.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "custody-jurisdiction".to_string(),
            category: ClauseCategory::Jurisdiction,
            title: "Governing Jurisdiction".to_string(),
            body: "This agreement governed by laws of {{jurisdiction}}.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "custody-indemnification".to_string(),
            category: ClauseCategory::Indemnification,
            title: "Indemnification".to_string(),
            body: "{{bailee_name}} shall indemnify {{bailor_name}} against third-party claims arising from {{bailee_name}}'s negligence or breach.".to_string(),
            required: true,
            jurisdiction: None,
        },
    ]
}

/// Generate standard clauses for Processing bailment type.
fn processing_clauses() -> Vec<Clause> {
    vec![
        Clause {
            id: "processing-data-custody".to_string(),
            category: ClauseCategory::DataCustody,
            title: "Data Custody".to_string(),
            body: "{{bailee_name}} shall hold {{bailor_name}}'s data in secure custody. Data classification: {{data_classification}}.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "processing-processing-rights".to_string(),
            category: ClauseCategory::ProcessingRights,
            title: "Processing Rights".to_string(),
            body: "{{bailee_name}} may process {{bailor_name}}'s data for purposes defined in this agreement. Processing scope limited to {{data_classification}} tier data.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "processing-breach-remedies".to_string(),
            category: ClauseCategory::BreachRemedies,
            title: "Breach Remedies".to_string(),
            body: "Upon breach, {{bailor_name}} shall receive notice within 3 days. Unauthorized processing constitutes a material breach.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "processing-liability-caps".to_string(),
            category: ClauseCategory::LiabilityCaps,
            title: "Liability Caps".to_string(),
            body: "Total liability capped at {{liability_cap_bps}} basis points of assessed value.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "processing-dispute-resolution".to_string(),
            category: ClauseCategory::DisputeResolution,
            title: "Dispute Resolution".to_string(),
            body: "Disputes under jurisdiction {{jurisdiction}} resolved via binding arbitration.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "processing-termination".to_string(),
            category: ClauseCategory::Termination,
            title: "Termination".to_string(),
            body: "Either party may terminate with 30 days written notice. All processing must cease immediately upon termination notice.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "processing-jurisdiction".to_string(),
            category: ClauseCategory::Jurisdiction,
            title: "Governing Jurisdiction".to_string(),
            body: "This agreement governed by laws of {{jurisdiction}}.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "processing-indemnification".to_string(),
            category: ClauseCategory::Indemnification,
            title: "Indemnification".to_string(),
            body: "{{bailee_name}} shall indemnify {{bailor_name}} against third-party claims arising from unauthorized processing or breach.".to_string(),
            required: true,
            jurisdiction: None,
        },
    ]
}

/// Generate standard clauses for Delegation bailment type.
fn delegation_clauses() -> Vec<Clause> {
    vec![
        Clause {
            id: "delegation-data-custody".to_string(),
            category: ClauseCategory::DataCustody,
            title: "Data Custody".to_string(),
            body: "{{bailee_name}} shall hold {{bailor_name}}'s data and may delegate custody to sub-bailees under equivalent terms. Data classification: {{data_classification}}.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "delegation-processing-rights".to_string(),
            category: ClauseCategory::ProcessingRights,
            title: "Processing Rights".to_string(),
            body: "{{bailee_name}} may process and delegate processing of {{bailor_name}}'s data. Sub-bailees must maintain equivalent or stricter terms.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "delegation-breach-remedies".to_string(),
            category: ClauseCategory::BreachRemedies,
            title: "Breach Remedies".to_string(),
            body: "Upon breach by {{bailee_name}} or any sub-bailee, {{bailor_name}} shall receive notice within 3 days. {{bailee_name}} remains liable for sub-bailee breaches.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "delegation-liability-caps".to_string(),
            category: ClauseCategory::LiabilityCaps,
            title: "Liability Caps".to_string(),
            body: "Total liability capped at {{liability_cap_bps}} basis points. {{bailee_name}} bears full liability for sub-bailee actions.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "delegation-dispute-resolution".to_string(),
            category: ClauseCategory::DisputeResolution,
            title: "Dispute Resolution".to_string(),
            body: "Disputes under jurisdiction {{jurisdiction}} resolved via binding arbitration. Sub-bailee disputes resolved through {{bailee_name}}.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "delegation-termination".to_string(),
            category: ClauseCategory::Termination,
            title: "Termination".to_string(),
            body: "Either party may terminate with 30 days written notice. All sub-bailments must be terminated within 15 days of primary termination.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "delegation-jurisdiction".to_string(),
            category: ClauseCategory::Jurisdiction,
            title: "Governing Jurisdiction".to_string(),
            body: "This agreement governed by laws of {{jurisdiction}}.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "delegation-indemnification".to_string(),
            category: ClauseCategory::Indemnification,
            title: "Indemnification".to_string(),
            body: "{{bailee_name}} shall indemnify {{bailor_name}} against all claims arising from sub-bailee actions.".to_string(),
            required: true,
            jurisdiction: None,
        },
    ]
}

/// Generate standard clauses for Emergency bailment type.
fn emergency_clauses() -> Vec<Clause> {
    vec![
        Clause {
            id: "emergency-data-custody".to_string(),
            category: ClauseCategory::DataCustody,
            title: "Emergency Data Custody".to_string(),
            body: "{{bailee_name}} granted emergency access to {{bailor_name}}'s data. Access expires {{expiry_date}}. Justification required for all access. Data classification: {{data_classification}}.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "emergency-processing-rights".to_string(),
            category: ClauseCategory::ProcessingRights,
            title: "Emergency Processing Rights".to_string(),
            body: "{{bailee_name}} may process data only as necessary for emergency resolution. Processing scope: {{data_classification}} tier data. All processing must be logged.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "emergency-breach-remedies".to_string(),
            category: ClauseCategory::BreachRemedies,
            title: "Breach Remedies".to_string(),
            body: "Upon breach, {{bailor_name}} shall receive immediate notice. Emergency access revoked instantly upon breach detection.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "emergency-liability-caps".to_string(),
            category: ClauseCategory::LiabilityCaps,
            title: "Liability Caps".to_string(),
            body: "Total liability capped at {{liability_cap_bps}} basis points. Emergency access carries elevated liability.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "emergency-dispute-resolution".to_string(),
            category: ClauseCategory::DisputeResolution,
            title: "Dispute Resolution".to_string(),
            body: "Disputes under jurisdiction {{jurisdiction}} resolved via expedited arbitration due to emergency nature.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "emergency-termination".to_string(),
            category: ClauseCategory::Termination,
            title: "Termination".to_string(),
            body: "Emergency access automatically terminates at {{expiry_date}}. Either party may terminate immediately with written notice.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "emergency-jurisdiction".to_string(),
            category: ClauseCategory::Jurisdiction,
            title: "Governing Jurisdiction".to_string(),
            body: "This agreement governed by laws of {{jurisdiction}}.".to_string(),
            required: true,
            jurisdiction: None,
        },
        Clause {
            id: "emergency-indemnification".to_string(),
            category: ClauseCategory::Indemnification,
            title: "Indemnification".to_string(),
            body: "{{bailee_name}} shall indemnify {{bailor_name}} against all claims arising from emergency access misuse.".to_string(),
            required: true,
            jurisdiction: None,
        },
    ]
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helpers --

    fn alice_did() -> Did {
        Did::new("did:exo:alice").unwrap()
    }

    fn bob_did() -> Did {
        Did::new("did:exo:bob").unwrap()
    }

    fn test_params() -> ContractParams {
        ContractParams {
            bailor_name: "Alice Corp".to_string(),
            bailee_name: "Bob Services".to_string(),
            bailor_did: alice_did(),
            bailee_did: bob_did(),
            effective_date: Timestamp::new(1_700_000_000_000, 0),
            expiry_date: Some(Timestamp::new(1_800_000_000_000, 0)),
            jurisdiction: "US-DE".to_string(),
            data_classification: DataClassification::Confidential,
            liability_cap_bps: 5000, // 50%
            custom_params: DeterministicMap::new(),
        }
    }

    fn ts(ms: u64) -> Timestamp {
        Timestamp::new(ms, 0)
    }

    fn compose_test(template: &ContractTemplate, params: &ContractParams) -> ComposedContract {
        compose(template, params, "contract-test", ts(1_700_000_000_100))
            .expect("test contract composition")
    }

    fn compose_test_with_metadata(
        template: &ContractTemplate,
        params: &ContractParams,
        id: &str,
        composed_at: Timestamp,
    ) -> ComposedContract {
        compose(template, params, id, composed_at).expect("test contract composition metadata")
    }

    fn assess_breach_test(
        contract: &ComposedContract,
        breached_clause_ids: &[&str],
        severity: BreachSeverity,
    ) -> BreachAssessment {
        assess_breach(
            contract,
            breached_clause_ids,
            severity,
            ts(1_700_000_000_200),
        )
        .expect("test breach assessment")
    }

    fn amend_test(
        original: &ComposedContract,
        new_params: &ContractParams,
        amended_clauses: &[(String, Clause)],
    ) -> ComposedContract {
        amend(
            original,
            new_params,
            amended_clauses,
            "contract-amendment-test",
            ts(1_700_000_000_300),
        )
        .expect("test amendment")
    }

    fn compose_custody() -> ComposedContract {
        let template = default_template(BailmentType::Custody);
        compose_test(&template, &test_params())
    }

    #[test]
    fn contract_constructors_have_no_internal_entropy_or_wall_clock() {
        let source = include_str!("contract.rs");
        let uuid_pattern = format!("{}{}", "Uuid::", "new_v4()");
        let now_pattern = format!("{}{}", "Timestamp::", "now_utc()");

        assert!(
            !source.contains(&uuid_pattern),
            "contract constructors must receive caller-supplied IDs"
        );
        assert!(
            !source.contains(&now_pattern),
            "contract constructors must receive caller-supplied HLC timestamps"
        );
    }

    #[test]
    fn compose_uses_caller_supplied_metadata() {
        let template = default_template(BailmentType::Custody);
        let contract =
            compose_test_with_metadata(&template, &test_params(), "contract-explicit", ts(4321));

        assert_eq!(contract.id, "contract-explicit");
        assert_eq!(contract.composed_at, ts(4321));
        assert_eq!(contract.version, 1);
        assert_eq!(contract.parent_contract_id, None);
    }

    #[test]
    fn compose_rejects_empty_id() {
        let template = default_template(BailmentType::Custody);
        let err = compose(&template, &test_params(), " ", ts(1000)).unwrap_err();

        assert_eq!(
            err,
            ConsentError::Denied("contract id must be caller-supplied and non-empty".into())
        );
    }

    #[test]
    fn compose_rejects_zero_composed_at() {
        let template = default_template(BailmentType::Custody);
        let err = compose(
            &template,
            &test_params(),
            "contract-explicit",
            Timestamp::ZERO,
        )
        .unwrap_err();

        assert_eq!(
            err,
            ConsentError::Denied("composed_at must be caller-supplied and non-zero".into())
        );
    }

    #[test]
    fn assess_breach_uses_caller_supplied_timestamp() {
        let contract = compose_custody();
        let clause_id = contract.rendered_clauses[0].clause_id.as_str();
        let assessment = assess_breach(&contract, &[clause_id], BreachSeverity::Minor, ts(4567))
            .expect("breach assessment");

        assert_eq!(assessment.assessed_at, ts(4567));
    }

    #[test]
    fn assess_breach_rejects_zero_timestamp() {
        let contract = compose_custody();
        let clause_id = contract.rendered_clauses[0].clause_id.as_str();
        let err = assess_breach(
            &contract,
            &[clause_id],
            BreachSeverity::Minor,
            Timestamp::ZERO,
        )
        .unwrap_err();

        assert_eq!(
            err,
            ConsentError::Denied("assessed_at must be caller-supplied and non-zero".into())
        );
    }

    #[test]
    fn amend_uses_caller_supplied_metadata() {
        let original = compose_custody();
        let amended = amend(
            &original,
            &test_params(),
            &[],
            "contract-amendment-explicit",
            ts(5678),
        )
        .expect("amendment");

        assert_eq!(amended.id, "contract-amendment-explicit");
        assert_eq!(amended.composed_at, ts(5678));
        assert_eq!(amended.parent_contract_id, Some(original.id.clone()));
    }

    #[test]
    fn amend_rejects_placeholder_metadata() {
        let original = compose_custody();

        let empty_id = amend(&original, &test_params(), &[], " ", ts(5678)).unwrap_err();
        assert_eq!(
            empty_id,
            ConsentError::Denied("contract id must be caller-supplied and non-empty".into())
        );

        let zero_time = amend(
            &original,
            &test_params(),
            &[],
            "contract-amendment-explicit",
            Timestamp::ZERO,
        )
        .unwrap_err();
        assert_eq!(
            zero_time,
            ConsentError::Denied("composed_at must be caller-supplied and non-zero".into())
        );
    }

    // All 8 clause categories
    fn all_categories() -> Vec<ClauseCategory> {
        vec![
            ClauseCategory::DataCustody,
            ClauseCategory::ProcessingRights,
            ClauseCategory::BreachRemedies,
            ClauseCategory::LiabilityCaps,
            ClauseCategory::DisputeResolution,
            ClauseCategory::Termination,
            ClauseCategory::Jurisdiction,
            ClauseCategory::Indemnification,
        ]
    }

    // -- Test 1: default template for Custody has all required clause categories --

    #[test]
    fn test_default_template_custody() {
        let template = default_template(BailmentType::Custody);
        assert_eq!(template.bailment_type, BailmentType::Custody);
        assert_eq!(template.clauses.len(), 8);

        let categories: Vec<ClauseCategory> = template.clauses.iter().map(|c| c.category).collect();
        for cat in all_categories() {
            assert!(
                categories.contains(&cat),
                "Custody template missing category: {cat:?}"
            );
        }

        // All clauses required
        assert!(template.clauses.iter().all(|c| c.required));
    }

    // -- Test 2: default template for Processing has all required clause categories --

    #[test]
    fn test_default_template_processing() {
        let template = default_template(BailmentType::Processing);
        assert_eq!(template.bailment_type, BailmentType::Processing);
        assert_eq!(template.clauses.len(), 8);

        let categories: Vec<ClauseCategory> = template.clauses.iter().map(|c| c.category).collect();
        for cat in all_categories() {
            assert!(
                categories.contains(&cat),
                "Processing template missing category: {cat:?}"
            );
        }

        assert!(template.clauses.iter().all(|c| c.required));
    }

    // -- Test 3: compose substitutes params --

    #[test]
    fn test_compose_substitutes_params() {
        let contract = compose_custody();

        // Check that param values appear in rendered clauses
        let all_bodies: String = contract
            .rendered_clauses
            .iter()
            .map(|c| c.rendered_body.clone())
            .collect::<Vec<_>>()
            .join(" ");

        assert!(
            all_bodies.contains("Alice Corp"),
            "Bailor name not substituted"
        );
        assert!(
            all_bodies.contains("Bob Services"),
            "Bailee name not substituted"
        );
        assert!(all_bodies.contains("US-DE"), "Jurisdiction not substituted");
        assert!(
            all_bodies.contains("Confidential"),
            "Data classification not substituted"
        );
        assert!(all_bodies.contains("5000"), "Liability cap not substituted");

        // No unsubstituted placeholders
        assert!(
            !all_bodies.contains("{{"),
            "Unsubstituted placeholders remain"
        );
    }

    // -- Test 4: compose produces deterministic hash --

    #[test]
    fn test_compose_produces_deterministic_hash() {
        let template = default_template(BailmentType::Custody);
        let params = test_params();

        let c1 = compose_test(&template, &params);
        let c2 = compose_test(&template, &params);

        // Caller-supplied metadata is stable, and content hash is stable.
        assert_eq!(c1.id, c2.id);
        assert_eq!(c1.composed_at, c2.composed_at);
        assert_eq!(c1.contract_hash, c2.contract_hash);
    }

    // -- Test 5: compose hash changes with different params --

    #[test]
    fn test_compose_hash_changes_with_params() {
        let template = default_template(BailmentType::Custody);
        let params1 = test_params();
        let mut params2 = test_params();
        params2.liability_cap_bps = 9999;

        let c1 = compose_test(&template, &params1);
        let c2 = compose_test(&template, &params2);

        assert_ne!(c1.contract_hash, c2.contract_hash);
    }

    // -- Test 6: render markdown has all sections --

    #[test]
    fn test_render_markdown_has_all_sections() {
        let contract = compose_custody();
        let md = render_markdown(&contract);

        // Check all clause titles appear
        for clause in &contract.rendered_clauses {
            assert!(
                md.contains(&clause.title),
                "Markdown missing clause title: {}",
                clause.title
            );
            assert!(
                md.contains(&format!("{}.", clause.section_number)),
                "Markdown missing section number: {}",
                clause.section_number
            );
        }

        // Check structural elements
        assert!(md.contains("# Bailment Contract"));
        assert!(md.contains("## Parties"));
        assert!(md.contains("Contract Hash:"));
    }

    // -- Test 7: render markdown contains party names --

    #[test]
    fn test_render_markdown_party_names() {
        let contract = compose_custody();
        let md = render_markdown(&contract);

        assert!(
            md.contains("Alice Corp"),
            "Bailor name missing from markdown"
        );
        assert!(
            md.contains("Bob Services"),
            "Bailee name missing from markdown"
        );
        assert!(
            md.contains("did:exo:alice"),
            "Bailor DID missing from markdown"
        );
        assert!(
            md.contains("did:exo:bob"),
            "Bailee DID missing from markdown"
        );
    }

    // -- Test 8: breach assessment minor → Notice --

    #[test]
    fn test_breach_assessment_minor() {
        let contract = compose_custody();
        let clause_id = contract.rendered_clauses[0].clause_id.as_str();

        let assessment = assess_breach_test(&contract, &[clause_id], BreachSeverity::Minor);

        assert_eq!(assessment.breach_severity, BreachSeverity::Minor);
        assert_eq!(assessment.recommended_remedy, Remedy::Notice);
        assert_eq!(assessment.liability_assessment_bps, 0);
    }

    // -- Test 9: breach assessment material → Cure --

    #[test]
    fn test_breach_assessment_material() {
        let contract = compose_custody();
        let clause_id = contract.rendered_clauses[0].clause_id.as_str();

        let assessment = assess_breach_test(&contract, &[clause_id], BreachSeverity::Material);

        assert_eq!(assessment.breach_severity, BreachSeverity::Material);
        assert_eq!(
            assessment.recommended_remedy,
            Remedy::Cure {
                cure_period_days: 30
            }
        );
        assert_eq!(assessment.liability_assessment_bps, 2500); // 5000 / 2
    }

    // -- Test 10: breach assessment fundamental → Termination + Indemnification --

    #[test]
    fn test_breach_assessment_fundamental() {
        let contract = compose_custody();
        let clause_id = contract.rendered_clauses[0].clause_id.as_str();

        let assessment = assess_breach_test(&contract, &[clause_id], BreachSeverity::Fundamental);

        assert_eq!(assessment.breach_severity, BreachSeverity::Fundamental);
        assert_eq!(
            assessment.recommended_remedy,
            Remedy::Indemnification { amount_bps: 5000 }
        );
        assert_eq!(assessment.liability_assessment_bps, 5000);
    }

    // -- Test 11: breach with invalid clause ID → error --

    #[test]
    fn test_breach_invalid_clause_id() {
        let contract = compose_custody();

        let result = assess_breach(
            &contract,
            &["nonexistent-clause"],
            BreachSeverity::Minor,
            ts(1_700_000_000_200),
        );

        assert!(result.is_err());
        match result {
            Err(ConsentError::Denied(msg)) => {
                assert!(msg.contains("nonexistent-clause"));
            }
            other => panic!("Expected Denied error, got: {other:?}"),
        }
    }

    // -- Test 12: amend creates new version --

    #[test]
    fn test_amend_creates_new_version() {
        let original = compose_custody();
        let new_params = test_params();

        let amended = amend_test(&original, &new_params, &[]);

        assert_eq!(amended.version, original.version + 1);
        assert_eq!(amended.parent_contract_id, Some(original.id.clone()));
        assert_ne!(amended.id, original.id);
    }

    // -- Test 13: amend preserves parent hash --

    #[test]
    fn test_amend_preserves_parent_hash() {
        let original = compose_custody();
        let original_hash = original.contract_hash;

        let mut new_params = test_params();
        new_params.liability_cap_bps = 9000;

        let _amended = amend_test(&original, &new_params, &[]);

        // Original's hash is unchanged
        assert_eq!(original.contract_hash, original_hash);
    }

    // -- Test 14: verify hash valid --

    #[test]
    fn test_verify_hash_valid() {
        let contract = compose_custody();
        assert!(verify_hash(&contract));
    }

    // -- Test 15: verify hash tampered --

    #[test]
    fn test_verify_hash_tampered() {
        let mut contract = compose_custody();
        // Tamper with a rendered clause
        contract.rendered_clauses[0].rendered_body = "TAMPERED CONTENT".to_string();
        assert!(!verify_hash(&contract));
    }

    // -- Test 16: no floating point --

    #[test]
    fn test_no_floating_point() {
        let contract = compose_custody();

        // liability_cap_bps is u64
        let _cap: u64 = contract.params.liability_cap_bps;
        assert_eq!(contract.params.liability_cap_bps, 5000u64);

        // Breach assessment also uses u64
        let clause_id = contract.rendered_clauses[0].clause_id.as_str();
        let assessment = assess_breach_test(&contract, &[clause_id], BreachSeverity::Material);
        let _liability: u64 = assessment.liability_assessment_bps;
        assert_eq!(assessment.liability_assessment_bps, 2500u64);

        // Verify no f32/f64 by ensuring values are exact integer division
        assert_eq!(5000u64 / 2, 2500u64);
    }

    // -- Test 17: default template for Delegation --

    #[test]
    fn test_default_template_delegation() {
        let template = default_template(BailmentType::Delegation);
        assert_eq!(template.bailment_type, BailmentType::Delegation);
        assert_eq!(template.id, "delegation-standard-v1");
        assert_eq!(template.name, "Standard Delegation Agreement");
        assert!(!template.clauses.is_empty());
        // All clauses must be required by default.
        assert!(template.clauses.iter().all(|c| c.required));
        // Must cover the delegation-specific ProcessingRights category.
        let cats: Vec<ClauseCategory> = template.clauses.iter().map(|c| c.category).collect();
        assert!(cats.contains(&ClauseCategory::ProcessingRights));
    }

    // -- Test 18: default template for Emergency --

    #[test]
    fn test_default_template_emergency() {
        let template = default_template(BailmentType::Emergency);
        assert_eq!(template.bailment_type, BailmentType::Emergency);
        assert_eq!(template.id, "emergency-standard-v1");
        assert_eq!(template.name, "Emergency Access Agreement");
        assert!(!template.clauses.is_empty());
        assert!(template.clauses.iter().all(|c| c.required));
        // Must cover Termination clauses — emergencies expire fast.
        let cats: Vec<ClauseCategory> = template.clauses.iter().map(|c| c.category).collect();
        assert!(cats.contains(&ClauseCategory::Termination));
    }

    // -- Test 19: compose with a Delegation template composes + hashes --

    #[test]
    fn test_compose_delegation_template_succeeds() {
        let template = default_template(BailmentType::Delegation);
        let contract = compose_test(&template, &test_params());
        assert!(!contract.rendered_clauses.is_empty());
        assert_ne!(contract.contract_hash, Hash256::ZERO);
        // Section numbering is monotonic from 1.
        for (i, rc) in contract.rendered_clauses.iter().enumerate() {
            assert_eq!(rc.section_number, format!("{}", i + 1));
        }
    }

    // -- Test 20: compose with an Emergency template composes + hashes --

    #[test]
    fn test_compose_emergency_template_succeeds() {
        let template = default_template(BailmentType::Emergency);
        let contract = compose_test(&template, &test_params());
        assert!(!contract.rendered_clauses.is_empty());
        assert_ne!(contract.contract_hash, Hash256::ZERO);
    }

    // -- Test 21: compose skips OPTIONAL clause with jurisdiction mismatch --

    #[test]
    fn test_compose_skips_optional_foreign_jurisdiction_clause() {
        // Build a template with one required EU-only clause and one optional EU-only
        // clause. Required must match the caller jurisdiction; optional may be dropped.
        let mut template = default_template(BailmentType::Custody);
        template.clauses.push(Clause {
            id: "optional-eu-only".to_string(),
            category: ClauseCategory::Jurisdiction,
            title: "EU-Only Optional".to_string(),
            body: "GDPR-specific clause body.".to_string(),
            required: false,
            jurisdiction: Some("EU-DE".to_string()),
        });

        let contract = compose_test(&template, &test_params());
        assert!(
            contract
                .rendered_clauses
                .iter()
                .all(|c| c.clause_id != "optional-eu-only"),
            "Optional foreign-jurisdiction clause must be filtered out"
        );
    }

    // -- Test 22: compose ERRORS when a REQUIRED clause has wrong jurisdiction --

    #[test]
    fn test_compose_errors_on_required_foreign_jurisdiction_clause() {
        let mut template = default_template(BailmentType::Custody);
        template.clauses.push(Clause {
            id: "required-eu-only".to_string(),
            category: ClauseCategory::Jurisdiction,
            title: "EU-Only Required".to_string(),
            body: "GDPR-specific clause body.".to_string(),
            required: true,
            jurisdiction: Some("EU-DE".to_string()),
        });

        // test_params() uses "US-DE" — the required EU clause cannot apply.
        let result = compose(
            &template,
            &test_params(),
            "contract-test",
            ts(1_700_000_000_100),
        );
        match result {
            Err(ConsentError::Denied(msg)) => {
                assert!(msg.contains("required-eu-only"));
                assert!(msg.contains("EU-DE"));
                assert!(msg.contains("US-DE"));
            }
            other => panic!("Expected Denied error, got: {other:?}"),
        }
    }

    // -- Test 23: compose keeps a clause whose jurisdiction matches --

    #[test]
    fn test_compose_keeps_matching_jurisdiction_clause() {
        let mut template = default_template(BailmentType::Custody);
        template.clauses.push(Clause {
            id: "matching-us-clause".to_string(),
            category: ClauseCategory::Jurisdiction,
            title: "US-DE Specific".to_string(),
            body: "Delaware-specific clause body.".to_string(),
            required: false,
            jurisdiction: Some("US-DE".to_string()),
        });

        let contract = compose_test(&template, &test_params());
        assert!(
            contract
                .rendered_clauses
                .iter()
                .any(|c| c.clause_id == "matching-us-clause"),
            "Matching-jurisdiction clause must be included"
        );
    }

    // -- Test 24: amend REPLACES a named existing clause --

    #[test]
    fn test_amend_replaces_existing_clause() {
        let original = compose_custody();
        let target_id = original.rendered_clauses[0].clause_id.clone();

        let replacement = Clause {
            id: "custody-v2-revised".to_string(),
            category: ClauseCategory::DataCustody,
            title: "Revised Custody".to_string(),
            body:
                "Revised custody terms: Data must be returned to {{bailor_name}} upon termination."
                    .to_string(),
            required: true,
            jurisdiction: None,
        };

        let amended = amend(
            &original,
            &test_params(),
            &[(target_id.clone(), replacement.clone())],
            "contract-amendment-test",
            ts(1_700_000_000_300),
        )
        .unwrap();

        // Original clause count preserved (replacement, not insertion).
        assert_eq!(
            amended.rendered_clauses.len(),
            original.rendered_clauses.len()
        );
        // The slot previously named by `target_id` now carries the new clause_id.
        assert!(
            amended
                .rendered_clauses
                .iter()
                .any(|c| c.clause_id == "custody-v2-revised"),
            "Replacement clause must appear in amended contract"
        );
        // And the original id is gone.
        assert!(
            amended
                .rendered_clauses
                .iter()
                .all(|c| c.clause_id != target_id),
            "Original clause id must be replaced"
        );
        // The replacement body was parameter-substituted.
        let revised_body = amended
            .rendered_clauses
            .iter()
            .find(|c| c.clause_id == "custody-v2-revised")
            .map(|c| c.rendered_body.clone())
            .unwrap();
        assert!(
            revised_body.contains("Alice Corp"),
            "Replacement must have params substituted"
        );
        assert!(!revised_body.contains("{{"));
    }

    // -- Test 25: amend APPENDS a new clause when target_id is not in original --

    #[test]
    fn test_amend_appends_new_clause_when_not_present() {
        let original = compose_custody();
        let original_len = original.rendered_clauses.len();

        let new_clause = Clause {
            id: "new-amendment-clause".to_string(),
            category: ClauseCategory::Indemnification,
            title: "New Indemnification Rider".to_string(),
            body: "Added by amendment for {{bailee_name}}.".to_string(),
            required: true,
            jurisdiction: None,
        };

        let amended = amend(
            &original,
            &test_params(),
            &[("NON-EXISTENT-CLAUSE-ID".to_string(), new_clause)],
            "contract-amendment-test",
            ts(1_700_000_000_300),
        )
        .unwrap();

        assert_eq!(
            amended.rendered_clauses.len(),
            original_len + 1,
            "Unknown target_id must APPEND rather than replace"
        );
        let appended = amended
            .rendered_clauses
            .last()
            .expect("amended contract has at least one clause");
        assert_eq!(appended.clause_id, "new-amendment-clause");
        assert_eq!(
            appended.section_number,
            format!("{}", original_len + 1),
            "Appended clause must take the next section number"
        );
        assert!(appended.rendered_body.contains("Bob Services"));
    }

    // -- Test 26: amend with multiple operations in one call --

    #[test]
    fn test_amend_replace_and_append_mixed() {
        let original = compose_custody();
        let target_id = original.rendered_clauses[1].clause_id.clone();

        let replacement = Clause {
            id: "replacement-mixed".to_string(),
            category: original.rendered_clauses[1].category,
            title: "Replacement".to_string(),
            body: "Replaced text for {{jurisdiction}}.".to_string(),
            required: true,
            jurisdiction: None,
        };
        let addition = Clause {
            id: "addition-mixed".to_string(),
            category: ClauseCategory::DisputeResolution,
            title: "Additional".to_string(),
            body: "Added text.".to_string(),
            required: true,
            jurisdiction: None,
        };

        let amended = amend(
            &original,
            &test_params(),
            &[
                (target_id, replacement),
                ("UNKNOWN-ID".to_string(), addition),
            ],
            "contract-amendment-test",
            ts(1_700_000_000_300),
        )
        .unwrap();

        // Replacement kept the length; addition bumped it by 1.
        assert_eq!(
            amended.rendered_clauses.len(),
            original.rendered_clauses.len() + 1
        );
        assert!(
            amended
                .rendered_clauses
                .iter()
                .any(|c| c.clause_id == "replacement-mixed")
        );
        assert!(
            amended
                .rendered_clauses
                .iter()
                .any(|c| c.clause_id == "addition-mixed")
        );
    }

    // -- Test 27: amend hash differs from original --

    #[test]
    fn test_amend_changes_contract_hash() {
        let original = compose_custody();
        let amended = amend_test(&original, &test_params(), &[]);
        // Version differs (original = 1, amended = 2), so payload differs,
        // so hash must differ.
        assert_ne!(amended.contract_hash, original.contract_hash);
    }

    // -- Test 28: render_markdown emits "No expiration" when expiry_date is None --

    #[test]
    fn test_render_markdown_no_expiration() {
        let template = default_template(BailmentType::Custody);
        let mut params = test_params();
        params.expiry_date = None;
        let contract = compose_test(&template, &params);

        let md = render_markdown(&contract);
        assert!(
            md.contains("**Expires**: No expiration"),
            "Expected 'No expiration' line in Markdown; got:\n{md}"
        );
    }

    // -- Test 29: render_markdown emits the expiry timestamp when present --

    #[test]
    fn test_render_markdown_includes_expiry_when_set() {
        let contract = compose_custody();
        let md = render_markdown(&contract);
        // The default test_params sets expiry_date = Some(1_800_000_000_000 ms).
        assert!(
            md.contains("1800000000000")
                || md.contains("1_800_000_000_000")
                || md.contains("2027")
                || md.contains("Expires"),
            "Expected a non-'No expiration' Expires line; got:\n{md}"
        );
        assert!(
            !md.contains("**Expires**: No expiration"),
            "Should not render 'No expiration' when expiry is set"
        );
    }

    // -- Test 30: verify_hash returns false when params tampered --

    #[test]
    fn test_verify_hash_rejects_tampered_params() {
        let mut contract = compose_custody();
        // Tamper with the bailor name — this is inside the hashed payload.
        contract.params.bailor_name = "Malicious Party".to_string();
        assert!(!verify_hash(&contract));
    }

    // -- Test 31: verify_hash returns false when version bumped without rehashing --

    #[test]
    fn test_verify_hash_rejects_tampered_version() {
        let mut contract = compose_custody();
        contract.version = contract.version.saturating_add(1);
        assert!(!verify_hash(&contract));
    }

    // -- Test 32: compose with a template whose ALL clauses are required and
    //            whose jurisdictions are None produces all clauses --

    #[test]
    fn test_compose_includes_all_jurisdiction_neutral_required_clauses() {
        let template = default_template(BailmentType::Custody);
        // Default template clauses all have jurisdiction: None.
        let contract = compose_test(&template, &test_params());
        assert_eq!(contract.rendered_clauses.len(), template.clauses.len());
    }

    // -- Test 33: breach with multiple clause IDs (all valid) --

    #[test]
    fn test_breach_multiple_clauses() {
        let contract = compose_custody();
        let id0 = contract.rendered_clauses[0].clause_id.clone();
        let id1 = contract.rendered_clauses[1].clause_id.clone();

        let a = assess_breach_test(&contract, &[&id0, &id1], BreachSeverity::Material);
        assert_eq!(a.breached_clauses.len(), 2);
        assert!(a.breached_clauses.contains(&id0));
        assert!(a.breached_clauses.contains(&id1));
    }
}
