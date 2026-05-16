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

//! Settlement: build, sign, and chain a [`SettlementReceipt`] for a
//! validated [`SettlementQuote`].
//!
//! The settlement path performs the same fail-closed checks as the
//! quote path, plus quote freshness and quote-hash integrity. The
//! resulting receipt is content-hashed and signed by the caller.

use std::collections::BTreeMap;

use exo_core::{Hash256, Signature, Timestamp, hash::hash_structured};
use serde::{Deserialize, Serialize};

use crate::{
    adoption::{AdoptionEvent, UseEvent, ValueBasis, ValueEvent},
    bailment::{BailmentWrapper, BailmentWrapperStatus},
    error::EconomyError,
    legacy::LegalEffect,
    quote::SettlementQuote,
    receipt::{SettlementReceipt, canonical_content_hash},
    ruleset::{
        HonorGoodRuleset, RulesetRecipientType, RulesetShareLine, RulesetStatus, SettlementBasis,
        validate_basis_allocations,
    },
    types::{BasisPoints, MAX_BASIS_POINTS, MicroExo, ZeroFeeReason},
    value_contribution::{
        AuthorityEnvelopeRef, ParticipantRef, ValueContributionNode, ValueContributionStatus,
        require_nonzero_hash, require_nonzero_timestamp,
    },
};

pub const MISSION_SETTLEMENT_HASH_DOMAIN: &str = "exo.economy.mission_settlement.v1";
pub const AUTOMATED_SETTLEMENT_EVENT_HASH_DOMAIN: &str =
    "exo.economy.automated_settlement_event.v1";

/// Caller-supplied settlement context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementContext {
    pub receipt_id: String,
    pub custody_transaction_hash: Hash256,
    pub prev_settlement_receipt: Hash256,
    pub now: Timestamp,
}

impl SettlementContext {
    /// Validate structural invariants on the context.
    ///
    /// # Errors
    /// Returns [`EconomyError::EmptyField`] when `receipt_id` is blank.
    pub fn validate(&self) -> Result<(), EconomyError> {
        if self.receipt_id.trim().is_empty() {
            return Err(EconomyError::EmptyField {
                field: "settlement.receipt_id",
            });
        }
        Ok(())
    }
}

/// Settle a quote: validate freshness and hash integrity, build the
/// receipt, content-hash it, and invoke the caller's `sign` closure
/// once over the canonical content hash.
///
/// # Errors
/// Returns [`EconomyError`] when the quote is expired, tampered, or the
/// context is structurally invalid.
pub fn settle<F>(
    quote: &SettlementQuote,
    context: &SettlementContext,
    sign: F,
) -> Result<SettlementReceipt, EconomyError>
where
    F: FnOnce(&[u8]) -> Signature,
{
    context.validate()?;
    if !quote.verify_hash()? {
        return Err(EconomyError::QuoteHashMismatch);
    }
    if quote.is_expired(&context.now) {
        return Err(EconomyError::QuoteExpired);
    }

    let mut receipt = SettlementReceipt {
        id: context.receipt_id.clone(),
        quote_hash: quote.quote_hash,
        actor_did: quote.actor_did.clone(),
        event_class: quote.event_class,
        charged_amount_micro_exo: quote.charged_amount_micro_exo,
        zero_fee_reason: quote.zero_fee_reason,
        revenue_shares: quote.revenue_shares.clone(),
        custody_transaction_hash: context.custody_transaction_hash,
        prev_settlement_receipt: context.prev_settlement_receipt,
        timestamp: context.now,
        content_hash: Hash256::ZERO,
        signature: Signature::empty(),
    };
    receipt.content_hash = canonical_content_hash(&receipt)?;
    let signature = sign(receipt.content_hash.as_bytes());
    if signature.is_empty() {
        return Err(EconomyError::EmptySettlementSignature {
            receipt_id: context.receipt_id.clone(),
        });
    }
    receipt.signature = signature;
    Ok(receipt)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementLine {
    pub recipient: ParticipantRef,
    pub recipient_type: RulesetRecipientType,
    pub basis: SettlementBasis,
    pub share_bp: BasisPoints,
    pub amount_micro_exo: MicroExo,
    pub zero_fee_reason: Option<ZeroFeeReason>,
    pub source_receipt_id: Option<Hash256>,
    pub legacy_receipt_id: Option<Hash256>,
}

impl SettlementLine {
    pub fn validate(&self) -> Result<(), EconomyError> {
        self.recipient.validate("settlement_line.recipient")?;
        if self.share_bp > MAX_BASIS_POINTS {
            return Err(EconomyError::BasisPointOutOfRange {
                field: "settlement_line.share_bp",
                value: self.share_bp,
                max: MAX_BASIS_POINTS,
            });
        }
        if self.amount_micro_exo == 0 && self.zero_fee_reason.is_none() {
            return Err(EconomyError::InvalidInput {
                reason: "zero settlement line requires explicit zero_fee_reason".into(),
            });
        }
        if let Some(id) = self.source_receipt_id {
            require_nonzero_hash(id, "settlement_line.source_receipt_id")?;
        }
        if let Some(id) = self.legacy_receipt_id {
            require_nonzero_hash(id, "settlement_line.legacy_receipt_id")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionSettlement {
    pub settlement_id: Hash256,
    pub mission_id: Hash256,
    pub ruleset_id: Hash256,
    pub gross_revenue_micro_exo: MicroExo,
    pub pass_through_expenses_micro_exo: MicroExo,
    pub net_revenue_micro_exo: MicroExo,
    pub settlement_lines: Vec<SettlementLine>,
    pub charged_amount_micro_exo: MicroExo,
    pub zero_fee_reason: Option<ZeroFeeReason>,
    pub prev_settlement_hash: Option<Hash256>,
    pub created_at: Timestamp,
    pub content_hash: Hash256,
    pub signature: Option<Signature>,
}

#[derive(Serialize)]
struct MissionSettlementHashPayload<'a> {
    domain: &'static str,
    mission_id: &'a Hash256,
    ruleset_id: &'a Hash256,
    gross_revenue_micro_exo: MicroExo,
    pass_through_expenses_micro_exo: MicroExo,
    net_revenue_micro_exo: MicroExo,
    settlement_lines: &'a [SettlementLine],
    charged_amount_micro_exo: MicroExo,
    zero_fee_reason: Option<ZeroFeeReason>,
    prev_settlement_hash: Option<&'a Hash256>,
    created_at: &'a Timestamp,
}

impl MissionSettlement {
    pub fn from_ruleset(
        mission_id: Hash256,
        ruleset: &HonorGoodRuleset,
        gross_revenue_micro_exo: MicroExo,
        pass_through_expenses_micro_exo: MicroExo,
        zero_fee_reason: Option<ZeroFeeReason>,
        prev_settlement_hash: Option<Hash256>,
        created_at: Timestamp,
    ) -> Result<Self, EconomyError> {
        ruleset.validate()?;
        require_nonzero_hash(mission_id, "mission_settlement.mission_id")?;
        let net_revenue_micro_exo = gross_revenue_micro_exo
            .checked_sub(pass_through_expenses_micro_exo)
            .ok_or(EconomyError::ArithmeticUnderflow {
                operation: "mission_settlement.net_revenue",
            })?;
        let mut basis_amounts = BTreeMap::new();
        basis_amounts.insert(SettlementBasis::NetRevenue, net_revenue_micro_exo);
        basis_amounts.insert(SettlementBasis::ProtocolFee, net_revenue_micro_exo);
        basis_amounts.insert(SettlementBasis::ChannelFee, net_revenue_micro_exo);
        basis_amounts.insert(SettlementBasis::MissionSurplus, net_revenue_micro_exo);
        basis_amounts.insert(SettlementBasis::SoftwareArr, net_revenue_micro_exo);
        basis_amounts.insert(SettlementBasis::ImplementationFee, net_revenue_micro_exo);
        basis_amounts.insert(SettlementBasis::RecognitionOnly, 0);
        let settlement_lines =
            settlement_lines_from_ruleset(ruleset, &basis_amounts, zero_fee_reason)?;
        let charged_amount_micro_exo = checked_line_total(&settlement_lines)?;
        let settlement = Self {
            settlement_id: Hash256::ZERO,
            mission_id,
            ruleset_id: ruleset.ruleset_id,
            gross_revenue_micro_exo,
            pass_through_expenses_micro_exo,
            net_revenue_micro_exo,
            settlement_lines,
            charged_amount_micro_exo,
            zero_fee_reason,
            prev_settlement_hash,
            created_at,
            content_hash: Hash256::ZERO,
            signature: None,
        };
        settlement.anchor()
    }

    pub fn validate(&self) -> Result<(), EconomyError> {
        require_nonzero_hash(self.mission_id, "mission_settlement.mission_id")?;
        require_nonzero_hash(self.ruleset_id, "mission_settlement.ruleset_id")?;
        let expected_net = self
            .gross_revenue_micro_exo
            .checked_sub(self.pass_through_expenses_micro_exo)
            .ok_or(EconomyError::ArithmeticUnderflow {
                operation: "mission_settlement.net_revenue",
            })?;
        if expected_net != self.net_revenue_micro_exo {
            return Err(EconomyError::InvalidInput {
                reason: "mission settlement net revenue does not match gross minus pass-through"
                    .into(),
            });
        }
        if self.settlement_lines.is_empty() {
            return Err(EconomyError::InvalidInput {
                reason: "mission settlement requires at least one settlement line".into(),
            });
        }
        for line in &self.settlement_lines {
            line.validate()?;
        }
        let total = checked_line_total(&self.settlement_lines)?;
        if total != self.charged_amount_micro_exo {
            return Err(EconomyError::SettlementOverAllocated {
                amount: self.charged_amount_micro_exo,
                charged: total,
            });
        }
        if self.charged_amount_micro_exo == 0 && self.zero_fee_reason.is_none() {
            return Err(EconomyError::InvalidInput {
                reason: "zero mission settlement requires explicit zero_fee_reason".into(),
            });
        }
        if let Some(prev) = self.prev_settlement_hash {
            require_nonzero_hash(prev, "mission_settlement.prev_settlement_hash")?;
        }
        if let Some(signature) = &self.signature {
            if signature.is_empty() {
                return Err(EconomyError::EmptySettlementSignature {
                    receipt_id: "mission_settlement".into(),
                });
            }
        }
        require_nonzero_timestamp(self.created_at, "mission_settlement.created_at")
    }

    pub fn recompute_content_hash(&self) -> Result<Hash256, EconomyError> {
        hash_structured(&MissionSettlementHashPayload {
            domain: MISSION_SETTLEMENT_HASH_DOMAIN,
            mission_id: &self.mission_id,
            ruleset_id: &self.ruleset_id,
            gross_revenue_micro_exo: self.gross_revenue_micro_exo,
            pass_through_expenses_micro_exo: self.pass_through_expenses_micro_exo,
            net_revenue_micro_exo: self.net_revenue_micro_exo,
            settlement_lines: &self.settlement_lines,
            charged_amount_micro_exo: self.charged_amount_micro_exo,
            zero_fee_reason: self.zero_fee_reason,
            prev_settlement_hash: self.prev_settlement_hash.as_ref(),
            created_at: &self.created_at,
        })
        .map_err(EconomyError::from)
    }

    pub fn anchor(mut self) -> Result<Self, EconomyError> {
        self.settlement_lines.sort_by(|left, right| {
            (
                &left.basis,
                left.recipient_type,
                left.share_bp,
                &left.recipient,
                left.source_receipt_id,
                left.legacy_receipt_id,
            )
                .cmp(&(
                    &right.basis,
                    right.recipient_type,
                    right.share_bp,
                    &right.recipient,
                    right.source_receipt_id,
                    right.legacy_receipt_id,
                ))
        });
        self.validate()?;
        let hash = self.recompute_content_hash()?;
        self.settlement_id = hash;
        self.content_hash = hash;
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomatedSettlementPreconditions {
    pub accepted_offer_exists: bool,
    pub valid_acceptance_exists: bool,
    pub valid_bailment_wrapper_exists: bool,
    pub authority_valid: bool,
    pub ruleset_hash_matches: bool,
    pub value_event_valid: bool,
    pub dispute_active: bool,
    pub revocation_active: bool,
    pub materiality_disputed: bool,
    pub legal_effect: LegalEffect,
}

impl AutomatedSettlementPreconditions {
    pub fn validate(&self) -> Result<(), EconomyError> {
        for (valid, reason) in [
            (self.accepted_offer_exists, "accepted offer is missing"),
            (self.valid_acceptance_exists, "valid acceptance is missing"),
            (
                self.valid_bailment_wrapper_exists,
                "valid bailment wrapper is missing",
            ),
            (self.authority_valid, "delegated authority is invalid"),
            (self.ruleset_hash_matches, "ruleset hash does not match"),
            (self.value_event_valid, "value event is invalid"),
        ] {
            if !valid {
                return Err(EconomyError::AutomatedSettlementRejected {
                    reason: reason.into(),
                });
            }
        }
        if self.dispute_active || self.revocation_active || self.materiality_disputed {
            return Err(EconomyError::AutomatedSettlementRejected {
                reason: "dispute, revocation, or materiality dispute is active".into(),
            });
        }
        if !self.legal_effect.permits_settlement() {
            return Err(EconomyError::AutomatedSettlementRejected {
                reason: "legal effect is insufficient for automated settlement".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomatedSettlementEvent {
    pub automated_settlement_id: Hash256,
    pub value_event_id: Hash256,
    pub contribution_node_id: Hash256,
    pub adoption_id: Hash256,
    pub ruleset_id: Hash256,
    pub settlement_lines: Vec<SettlementLine>,
    pub automation_authority_ref: AuthorityEnvelopeRef,
    pub preapproved_terms_hash: Hash256,
    pub bailment_wrapper_id: Hash256,
    pub human_approval_required: bool,
    pub fail_closed_checks: Vec<String>,
    pub created_at_hlc: Timestamp,
    pub content_hash: Hash256,
}

#[derive(Serialize)]
struct AutomatedSettlementHashPayload<'a> {
    domain: &'static str,
    value_event_id: &'a Hash256,
    contribution_node_id: &'a Hash256,
    adoption_id: &'a Hash256,
    ruleset_id: &'a Hash256,
    settlement_lines: &'a [SettlementLine],
    automation_authority_ref: &'a AuthorityEnvelopeRef,
    preapproved_terms_hash: &'a Hash256,
    bailment_wrapper_id: &'a Hash256,
    human_approval_required: bool,
    fail_closed_checks: &'a [String],
    created_at_hlc: &'a Timestamp,
}

pub struct AutomatedSettlementInputs<'a> {
    pub value_event: &'a ValueEvent,
    pub use_event: &'a UseEvent,
    pub contribution_node: &'a ValueContributionNode,
    pub adoption: &'a AdoptionEvent,
    pub ruleset: &'a HonorGoodRuleset,
    pub wrapper: &'a BailmentWrapper,
    pub automation_authority_ref: AuthorityEnvelopeRef,
    pub preapproved_terms_hash: Hash256,
    pub basis_amounts: &'a BTreeMap<SettlementBasis, MicroExo>,
    pub zero_fee_reason: Option<ZeroFeeReason>,
    pub preconditions: AutomatedSettlementPreconditions,
    pub created_at_hlc: Timestamp,
}

impl AutomatedSettlementEvent {
    pub fn from_inputs(input: AutomatedSettlementInputs<'_>) -> Result<Self, EconomyError> {
        input.preconditions.validate()?;
        input.automation_authority_ref.validate()?;
        if input.automation_authority_ref.authority_proof_hash
            != input.adoption.authority_proof_hash
        {
            return Err(EconomyError::HashMismatch {
                field: "automated_settlement.authority_proof_hash",
            });
        }
        input.use_event.validate_against_adoption(input.adoption)?;
        input
            .value_event
            .validate_against_use_event(input.use_event)?;
        if !input.value_event.settlement_triggered {
            return Err(EconomyError::AutomatedSettlementRejected {
                reason: "value event did not trigger settlement".into(),
            });
        }
        if input.ruleset.requires_human_approval {
            return Err(EconomyError::AutomatedSettlementRejected {
                reason: "ruleset requires human approval".into(),
            });
        }
        if !matches!(input.ruleset.status, RulesetStatus::Active) {
            return Err(EconomyError::AutomatedSettlementRejected {
                reason: "ruleset must be active".into(),
            });
        }
        if !matches!(
            input.contribution_node.status,
            ValueContributionStatus::Active
        ) {
            return Err(EconomyError::AutomatedSettlementRejected {
                reason: "contribution node must be active".into(),
            });
        }
        if input.ruleset.ruleset_id != input.contribution_node.settlement_ruleset_id
            || input.ruleset.ruleset_id != input.wrapper.settlement_ruleset_id
        {
            return Err(EconomyError::HashMismatch {
                field: "automated_settlement.ruleset_id",
            });
        }
        if input.contribution_node.contribution_node_id != input.value_event.contribution_node_id
            || input.contribution_node.contribution_node_id != input.adoption.contribution_node_id
            || input.contribution_node.contribution_node_id != input.wrapper.contribution_node_id
        {
            return Err(EconomyError::HashMismatch {
                field: "automated_settlement.contribution_node_id",
            });
        }
        if input.wrapper.wrapper_id != input.adoption.bailment_wrapper_id {
            return Err(EconomyError::HashMismatch {
                field: "automated_settlement.bailment_wrapper_id",
            });
        }
        if !matches!(input.wrapper.status, BailmentWrapperStatus::Active) {
            return Err(EconomyError::AutomatedSettlementRejected {
                reason: "bailment wrapper is not active".into(),
            });
        }
        if input.preapproved_terms_hash != input.contribution_node.honor_good_terms_hash {
            return Err(EconomyError::HashMismatch {
                field: "automated_settlement.preapproved_terms_hash",
            });
        }
        if settlement_basis_from_value_basis(&input.value_event.value_basis).is_none() {
            return Err(EconomyError::UnsupportedSettlementBasis {
                basis: "value_event.unsupported".into(),
            });
        }
        let settlement_lines = settlement_lines_from_ruleset(
            input.ruleset,
            input.basis_amounts,
            input.zero_fee_reason,
        )?;
        let event = Self {
            automated_settlement_id: Hash256::ZERO,
            value_event_id: input.value_event.value_event_id,
            contribution_node_id: input.contribution_node.contribution_node_id,
            adoption_id: input.adoption.adoption_id,
            ruleset_id: input.ruleset.ruleset_id,
            settlement_lines,
            automation_authority_ref: input.automation_authority_ref,
            preapproved_terms_hash: input.preapproved_terms_hash,
            bailment_wrapper_id: input.wrapper.wrapper_id,
            human_approval_required: false,
            fail_closed_checks: vec![
                "accepted_offer".into(),
                "accepted_terms".into(),
                "active_bailment_wrapper".into(),
                "delegated_authority".into(),
                "active_ruleset".into(),
                "active_contribution_node".into(),
                "validated_value_event".into(),
            ],
            created_at_hlc: input.created_at_hlc,
            content_hash: Hash256::ZERO,
        };
        event.anchor()
    }

    pub fn validate(&self) -> Result<(), EconomyError> {
        require_nonzero_hash(self.value_event_id, "automated_settlement.value_event_id")?;
        require_nonzero_hash(
            self.contribution_node_id,
            "automated_settlement.contribution_node_id",
        )?;
        require_nonzero_hash(self.adoption_id, "automated_settlement.adoption_id")?;
        require_nonzero_hash(self.ruleset_id, "automated_settlement.ruleset_id")?;
        if self.settlement_lines.is_empty() {
            return Err(EconomyError::InvalidInput {
                reason: "automated settlement requires settlement lines".into(),
            });
        }
        for line in &self.settlement_lines {
            line.validate()?;
        }
        self.automation_authority_ref.validate()?;
        require_nonzero_hash(
            self.preapproved_terms_hash,
            "automated_settlement.preapproved_terms_hash",
        )?;
        require_nonzero_hash(
            self.bailment_wrapper_id,
            "automated_settlement.bailment_wrapper_id",
        )?;
        if self.human_approval_required {
            return Err(EconomyError::AutomatedSettlementRejected {
                reason: "automated settlement cannot execute when human approval is required"
                    .into(),
            });
        }
        if self.fail_closed_checks.is_empty() {
            return Err(EconomyError::InvalidInput {
                reason: "automated settlement requires recorded fail-closed checks".into(),
            });
        }
        for check in &self.fail_closed_checks {
            if check.trim().is_empty() {
                return Err(EconomyError::EmptyField {
                    field: "automated_settlement.fail_closed_checks",
                });
            }
        }
        require_nonzero_timestamp(self.created_at_hlc, "automated_settlement.created_at_hlc")
    }

    pub fn recompute_content_hash(&self) -> Result<Hash256, EconomyError> {
        hash_structured(&AutomatedSettlementHashPayload {
            domain: AUTOMATED_SETTLEMENT_EVENT_HASH_DOMAIN,
            value_event_id: &self.value_event_id,
            contribution_node_id: &self.contribution_node_id,
            adoption_id: &self.adoption_id,
            ruleset_id: &self.ruleset_id,
            settlement_lines: &self.settlement_lines,
            automation_authority_ref: &self.automation_authority_ref,
            preapproved_terms_hash: &self.preapproved_terms_hash,
            bailment_wrapper_id: &self.bailment_wrapper_id,
            human_approval_required: self.human_approval_required,
            fail_closed_checks: &self.fail_closed_checks,
            created_at_hlc: &self.created_at_hlc,
        })
        .map_err(EconomyError::from)
    }

    pub fn anchor(mut self) -> Result<Self, EconomyError> {
        self.fail_closed_checks.sort();
        self.fail_closed_checks.dedup();
        self.settlement_lines.sort_by(|left, right| {
            (
                &left.basis,
                left.recipient_type,
                left.share_bp,
                &left.recipient,
                left.source_receipt_id,
                left.legacy_receipt_id,
            )
                .cmp(&(
                    &right.basis,
                    right.recipient_type,
                    right.share_bp,
                    &right.recipient,
                    right.source_receipt_id,
                    right.legacy_receipt_id,
                ))
        });
        self.validate()?;
        let hash = self.recompute_content_hash()?;
        self.automated_settlement_id = hash;
        self.content_hash = hash;
        Ok(self)
    }
}

pub fn checked_basis_point_amount(
    amount_micro_exo: MicroExo,
    share_bp: BasisPoints,
) -> Result<MicroExo, EconomyError> {
    if share_bp > MAX_BASIS_POINTS {
        return Err(EconomyError::BasisPointOutOfRange {
            field: "settlement.share_bp",
            value: share_bp,
            max: MAX_BASIS_POINTS,
        });
    }
    let product = amount_micro_exo
        .checked_mul(MicroExo::from(share_bp))
        .ok_or(EconomyError::ArithmeticOverflow {
            operation: "settlement.amount_mul_bp",
        })?;
    product
        .checked_div(MicroExo::from(MAX_BASIS_POINTS))
        .ok_or(EconomyError::ArithmeticUnderflow {
            operation: "settlement.amount_div_bp",
        })
}

pub fn settlement_lines_from_ruleset(
    ruleset: &HonorGoodRuleset,
    basis_amounts: &BTreeMap<SettlementBasis, MicroExo>,
    zero_fee_reason: Option<ZeroFeeReason>,
) -> Result<Vec<SettlementLine>, EconomyError> {
    ruleset.validate()?;
    validate_basis_allocations(&ruleset.share_lines)?;
    let mut lines = Vec::with_capacity(ruleset.share_lines.len());
    for template in &ruleset.share_lines {
        let base_amount = basis_amount_for_line(template, basis_amounts)?;
        let amount_micro_exo = checked_basis_point_amount(base_amount, template.share_bp)?;
        if amount_micro_exo == 0 && zero_fee_reason.is_none() {
            return Err(EconomyError::InvalidInput {
                reason: "zero settlement amount requires explicit zero_fee_reason".into(),
            });
        }
        lines.push(SettlementLine {
            recipient: template.recipient.clone(),
            recipient_type: template.recipient_type,
            basis: template.basis.clone(),
            share_bp: template.share_bp,
            amount_micro_exo,
            zero_fee_reason: if amount_micro_exo == 0 {
                zero_fee_reason
            } else {
                None
            },
            source_receipt_id: template.source_receipt_id,
            legacy_receipt_id: template.legacy_receipt_id,
        });
    }
    Ok(lines)
}

fn basis_amount_for_line(
    line: &RulesetShareLine,
    basis_amounts: &BTreeMap<SettlementBasis, MicroExo>,
) -> Result<MicroExo, EconomyError> {
    if matches!(line.basis, SettlementBasis::RecognitionOnly) {
        return Ok(0);
    }
    let Some(value) = basis_amounts.get(&line.basis) else {
        return Err(EconomyError::UnsupportedSettlementBasis {
            basis: line.basis.label(),
        });
    };
    Ok(*value)
}

fn checked_line_total(lines: &[SettlementLine]) -> Result<MicroExo, EconomyError> {
    let mut total: MicroExo = 0;
    for line in lines {
        total =
            total
                .checked_add(line.amount_micro_exo)
                .ok_or(EconomyError::ArithmeticOverflow {
                    operation: "settlement.line_total",
                })?;
    }
    Ok(total)
}

fn settlement_basis_from_value_basis(value_basis: &ValueBasis) -> Option<SettlementBasis> {
    match value_basis {
        ValueBasis::Revenue => Some(SettlementBasis::NetRevenue),
        ValueBasis::ProtocolFee => Some(SettlementBasis::ProtocolFee),
        ValueBasis::ChannelFee => Some(SettlementBasis::ChannelFee),
        ValueBasis::MissionSurplus => Some(SettlementBasis::MissionSurplus),
        ValueBasis::CostSavings => Some(SettlementBasis::CostSavings),
        ValueBasis::UsageMetric => Some(SettlementBasis::UsageMetric),
        ValueBasis::Other(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use exo_core::{Did, Timestamp};

    use super::*;
    use crate::{
        adoption::test_support::{sample_adoption, sample_use_event, sample_value_event},
        bailment::test_support::sample_wrapper,
        legacy::LegalEffect,
        policy::PricingPolicy,
        price::PricingInputs,
        quote::quote,
        ruleset::test_support::sample_ruleset,
        types::{ActorClass, AssuranceClass, EventClass},
        value_contribution::test_support::{authority, h, sample_node, ts},
    };

    fn fixed_signature() -> Signature {
        Signature::from_bytes([7u8; 64])
    }

    fn baseline_inputs() -> PricingInputs {
        PricingInputs {
            actor_did: Did::new("did:exo:agent").unwrap(),
            actor_class: ActorClass::Holon,
            event_class: EventClass::HolonCommercialAction,
            assurance_class: AssuranceClass::Standard,
            declared_value_micro_exo: Some(1_000_000),
            realized_value_micro_exo: None,
            compute_units: 100,
            storage_bytes: 4_096,
            verification_ops: 5,
            network_load_bp: 10_000,
            risk_bp: 1_500,
            market_domain: None,
            timestamp: Timestamp::new(1_000_000, 0),
        }
    }

    fn baseline_context() -> SettlementContext {
        SettlementContext {
            receipt_id: "rec-1".into(),
            custody_transaction_hash: Hash256::from_bytes([0x33; 32]),
            prev_settlement_receipt: Hash256::ZERO,
            now: Timestamp::new(1_010_000, 0),
        }
    }

    #[test]
    fn settle_zero_quote_succeeds() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let receipt = settle(&q, &baseline_context(), |_| fixed_signature()).unwrap();
        assert_eq!(receipt.charged_amount_micro_exo, 0);
        assert_eq!(receipt.signature, fixed_signature());
        assert_ne!(receipt.content_hash, Hash256::ZERO);
        assert!(receipt.verify_content_hash().unwrap());
    }

    #[test]
    fn settle_chains_prev_receipt_hash_into_receipt() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let mut ctx = baseline_context();
        ctx.prev_settlement_receipt = Hash256::from_bytes([0xAB; 32]);
        let receipt = settle(&q, &ctx, |_| fixed_signature()).unwrap();
        assert_eq!(
            receipt.prev_settlement_receipt,
            Hash256::from_bytes([0xAB; 32])
        );
    }

    #[test]
    fn settle_rejects_blank_receipt_id() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let mut ctx = baseline_context();
        ctx.receipt_id = "   ".into();
        assert!(matches!(
            settle(&q, &ctx, |_| fixed_signature()).unwrap_err(),
            EconomyError::EmptyField { .. }
        ));
    }

    #[test]
    fn settle_rejects_tampered_quote() {
        let policy = PricingPolicy::zero_launch_default();
        let mut q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        q.charged_amount_micro_exo = 9_999_999;
        let err = settle(&q, &baseline_context(), |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, EconomyError::QuoteHashMismatch));
    }

    #[test]
    fn settle_rejects_expired_quote() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let mut ctx = baseline_context();
        ctx.now = Timestamp::new(q.expires_at.physical_ms + 1, q.expires_at.logical);
        let err = settle(&q, &ctx, |_| fixed_signature()).unwrap_err();
        assert!(matches!(err, EconomyError::QuoteExpired));
    }

    #[test]
    fn settle_rejects_empty_signer_output() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let err = settle(&q, &baseline_context(), |_| Signature::empty()).unwrap_err();
        assert!(matches!(
            err,
            EconomyError::EmptySettlementSignature { receipt_id } if receipt_id == "rec-1"
        ));
    }

    #[test]
    fn settle_records_zero_fee_reason_from_quote() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let receipt = settle(&q, &baseline_context(), |_| fixed_signature()).unwrap();
        assert_eq!(receipt.zero_fee_reason, q.zero_fee_reason);
    }

    #[test]
    fn settle_carries_revenue_share_lines_with_zero_amounts() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let receipt = settle(&q, &baseline_context(), |_| fixed_signature()).unwrap();
        assert!(!receipt.revenue_shares.is_empty());
        for line in &receipt.revenue_shares {
            assert_eq!(line.amount_micro_exo, 0);
        }
    }

    #[test]
    fn settle_round_trip_serialization() {
        let policy = PricingPolicy::zero_launch_default();
        let q = quote(&policy, &baseline_inputs(), "q-1".into()).unwrap();
        let receipt = settle(&q, &baseline_context(), |_| fixed_signature()).unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&receipt, &mut buf).unwrap();
        let decoded: SettlementReceipt = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn basis_point_calculation_uses_checked_integer_arithmetic() {
        assert_eq!(
            checked_basis_point_amount(1_000_000, 1_000).unwrap(),
            100_000
        );
        assert!(matches!(
            checked_basis_point_amount(MicroExo::MAX, 10_000),
            Err(EconomyError::ArithmeticOverflow { .. })
        ));
        assert!(matches!(
            checked_basis_point_amount(1_000, 10_001),
            Err(EconomyError::BasisPointOutOfRange { .. })
        ));
    }

    #[test]
    fn mission_settlement_zero_launch_requires_explicit_reason() {
        let ruleset = sample_ruleset().anchor().unwrap();
        assert!(
            MissionSettlement::from_ruleset(h(0xC0), &ruleset, 0, 0, None, None, ts(3_000),)
                .is_err()
        );
        let settlement = MissionSettlement::from_ruleset(
            h(0xC0),
            &ruleset,
            0,
            0,
            Some(ZeroFeeReason::PolicyConfiguredZero),
            None,
            ts(3_000),
        )
        .unwrap();
        assert_eq!(settlement.charged_amount_micro_exo, 0);
        assert_ne!(settlement.content_hash, Hash256::ZERO);
    }

    #[test]
    fn mission_settlement_rejects_pass_through_underflow() {
        let ruleset = sample_ruleset().anchor().unwrap();
        assert!(matches!(
            MissionSettlement::from_ruleset(
                h(0xC0),
                &ruleset,
                10,
                11,
                Some(ZeroFeeReason::PolicyConfiguredZero),
                None,
                ts(3_000),
            ),
            Err(EconomyError::ArithmeticUnderflow { .. })
        ));
    }

    fn active_ruleset_and_node() -> (
        HonorGoodRuleset,
        crate::value_contribution::ValueContributionNode,
    ) {
        let ruleset = sample_ruleset().anchor().unwrap();
        let mut node = sample_node();
        node.status = ValueContributionStatus::Active;
        node.settlement_ruleset_id = ruleset.ruleset_id;
        node.honor_good_terms_hash = h(0x51);
        (ruleset, node.anchor().unwrap())
    }

    fn coherent_settlement_objects() -> (
        HonorGoodRuleset,
        crate::value_contribution::ValueContributionNode,
        AdoptionEvent,
        UseEvent,
        BailmentWrapper,
        ValueEvent,
    ) {
        let (ruleset, node) = active_ruleset_and_node();
        let mut wrapper = sample_wrapper();
        wrapper.contribution_node_id = node.contribution_node_id;
        wrapper.settlement_ruleset_id = ruleset.ruleset_id;
        let wrapper = wrapper.anchor().unwrap();
        let mut adoption = sample_adoption();
        adoption.contribution_node_id = node.contribution_node_id;
        adoption.offer_id = wrapper.offer_id;
        adoption.acceptance_id = wrapper.acceptance_id;
        adoption.accepted_terms_hash = wrapper.accepted_terms_hash;
        adoption.bailment_wrapper_id = wrapper.wrapper_id;
        let adoption = adoption.anchor().unwrap();
        let mut use_event = sample_use_event();
        use_event.adoption_id = adoption.adoption_id;
        use_event.contribution_node_id = node.contribution_node_id;
        use_event.mission_id = adoption.mission_id;
        use_event.bailment_wrapper_id = adoption.bailment_wrapper_id;
        let use_event = use_event.anchor().unwrap();
        let mut value_event = sample_value_event();
        value_event.use_event_id = use_event.use_event_id;
        value_event.contribution_node_id = node.contribution_node_id;
        value_event.mission_id = adoption.mission_id;
        let value_event = value_event.anchor().unwrap();
        (ruleset, node, adoption, use_event, wrapper, value_event)
    }

    fn basis_amounts() -> BTreeMap<SettlementBasis, MicroExo> {
        let mut amounts = BTreeMap::new();
        amounts.insert(SettlementBasis::NetRevenue, 0);
        amounts.insert(SettlementBasis::ProtocolFee, 0);
        amounts
    }

    fn settlement_preconditions() -> AutomatedSettlementPreconditions {
        AutomatedSettlementPreconditions {
            accepted_offer_exists: true,
            valid_acceptance_exists: true,
            valid_bailment_wrapper_exists: true,
            authority_valid: true,
            ruleset_hash_matches: true,
            value_event_valid: true,
            dispute_active: false,
            revocation_active: false,
            materiality_disputed: false,
            legal_effect: LegalEffect::AcceptedTerms,
        }
    }

    #[test]
    fn automated_settlement_succeeds_inside_preapproved_terms() {
        let (ruleset, node, adoption, use_event, wrapper, value_event) =
            coherent_settlement_objects();
        let event = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: authority("adopter-principal"),
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions: settlement_preconditions(),
            created_at_hlc: ts(3_100),
        })
        .unwrap();
        assert!(!event.human_approval_required);
        assert_ne!(event.automated_settlement_id, Hash256::ZERO);
    }

    #[test]
    fn automated_settlement_rejects_authority_proof_not_bound_to_adoption() {
        let (ruleset, node, adoption, use_event, wrapper, value_event) =
            coherent_settlement_objects();
        let mut forged_authority = authority("adopter-principal");
        forged_authority.authority_proof_hash = h(0xA7);
        let err = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: forged_authority,
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions: settlement_preconditions(),
            created_at_hlc: ts(3_100),
        })
        .unwrap_err();
        assert!(matches!(err, EconomyError::HashMismatch { .. }));
    }

    #[test]
    fn automated_settlement_fails_when_human_approval_required() {
        let (mut ruleset, node, adoption, use_event, wrapper, value_event) =
            coherent_settlement_objects();
        ruleset.requires_human_approval = true;
        let err = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: authority("adopter-principal"),
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions: settlement_preconditions(),
            created_at_hlc: ts(3_100),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            EconomyError::AutomatedSettlementRejected { .. }
        ));
    }

    #[test]
    fn automated_settlement_fails_for_revoked_node() {
        let (ruleset, mut node, adoption, use_event, wrapper, value_event) =
            coherent_settlement_objects();
        node.status = ValueContributionStatus::Revoked;
        let err = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: authority("adopter-principal"),
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions: settlement_preconditions(),
            created_at_hlc: ts(3_100),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            EconomyError::AutomatedSettlementRejected { .. }
        ));
    }

    #[test]
    fn automated_settlement_fails_for_insufficient_legal_effect() {
        let (ruleset, node, adoption, use_event, wrapper, value_event) =
            coherent_settlement_objects();
        let mut preconditions = settlement_preconditions();
        preconditions.legal_effect = LegalEffect::VoluntaryRecognitionOnly;
        let err = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: authority("adopter-principal"),
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions,
            created_at_hlc: ts(3_100),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            EconomyError::AutomatedSettlementRejected { .. }
        ));
    }

    #[test]
    fn mission_settlement_validate_rejects_mutated_totals_and_empty_lines() {
        let ruleset = sample_ruleset().anchor().unwrap();
        let settlement = MissionSettlement::from_ruleset(
            h(0xC0),
            &ruleset,
            1_000_000,
            100_000,
            None,
            None,
            ts(3_000),
        )
        .unwrap();

        let mut wrong_net = settlement.clone();
        wrong_net.net_revenue_micro_exo = 1;
        assert!(matches!(
            wrong_net.validate().unwrap_err(),
            EconomyError::InvalidInput { .. }
        ));

        let mut empty_lines = settlement.clone();
        empty_lines.settlement_lines.clear();
        assert!(matches!(
            empty_lines.validate().unwrap_err(),
            EconomyError::InvalidInput { .. }
        ));

        let mut wrong_total = settlement;
        wrong_total.charged_amount_micro_exo += 1;
        assert!(matches!(
            wrong_total.validate().unwrap_err(),
            EconomyError::SettlementOverAllocated { .. }
        ));
    }

    #[test]
    fn mission_settlement_validate_rejects_zero_previous_hash_and_empty_signature() {
        let ruleset = sample_ruleset().anchor().unwrap();
        let settlement = MissionSettlement::from_ruleset(
            h(0xC0),
            &ruleset,
            1_000_000,
            100_000,
            None,
            Some(h(0xA0)),
            ts(3_000),
        )
        .unwrap();

        let mut zero_previous = settlement.clone();
        zero_previous.prev_settlement_hash = Some(Hash256::ZERO);
        assert!(matches!(
            zero_previous.validate().unwrap_err(),
            EconomyError::InvalidInput { .. }
        ));

        let mut empty_signature = settlement;
        empty_signature.signature = Some(Signature::empty());
        assert!(matches!(
            empty_signature.validate().unwrap_err(),
            EconomyError::EmptySettlementSignature { .. }
        ));
    }

    #[test]
    fn settlement_line_validate_rejects_zero_amount_without_reason_and_zero_links() {
        let mut line = settlement_lines_from_ruleset(
            &sample_ruleset().anchor().unwrap(),
            &basis_amounts(),
            Some(ZeroFeeReason::PolicyConfiguredZero),
        )
        .unwrap()
        .remove(0);

        line.zero_fee_reason = None;
        assert!(matches!(
            line.validate().unwrap_err(),
            EconomyError::InvalidInput { .. }
        ));

        line.zero_fee_reason = Some(ZeroFeeReason::PolicyConfiguredZero);
        line.source_receipt_id = Some(Hash256::ZERO);
        assert!(matches!(
            line.validate().unwrap_err(),
            EconomyError::InvalidInput { .. }
        ));

        line.source_receipt_id = None;
        line.legacy_receipt_id = Some(Hash256::ZERO);
        assert!(matches!(
            line.validate().unwrap_err(),
            EconomyError::InvalidInput { .. }
        ));
    }

    #[test]
    fn settlement_lines_from_ruleset_rejects_missing_basis_and_zero_without_reason() {
        let ruleset = sample_ruleset().anchor().unwrap();
        let empty_amounts = BTreeMap::new();
        assert!(matches!(
            settlement_lines_from_ruleset(
                &ruleset,
                &empty_amounts,
                Some(ZeroFeeReason::PolicyConfiguredZero),
            )
            .unwrap_err(),
            EconomyError::UnsupportedSettlementBasis { .. }
        ));

        assert!(matches!(
            settlement_lines_from_ruleset(&ruleset, &basis_amounts(), None).unwrap_err(),
            EconomyError::InvalidInput { .. }
        ));
    }

    #[test]
    fn automated_preconditions_fail_closed_for_missing_authority_and_active_dispute() {
        let mut missing_authority = settlement_preconditions();
        missing_authority.authority_valid = false;
        assert!(matches!(
            missing_authority.validate().unwrap_err(),
            EconomyError::AutomatedSettlementRejected { .. }
        ));

        let mut disputed = settlement_preconditions();
        disputed.materiality_disputed = true;
        assert!(matches!(
            disputed.validate().unwrap_err(),
            EconomyError::AutomatedSettlementRejected { .. }
        ));
    }

    #[test]
    fn automated_settlement_fails_when_value_event_does_not_trigger() {
        let (ruleset, node, adoption, use_event, wrapper, mut value_event) =
            coherent_settlement_objects();
        value_event.settlement_triggered = false;
        let value_event = value_event.anchor().unwrap();
        let err = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: authority("adopter-principal"),
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions: settlement_preconditions(),
            created_at_hlc: ts(3_100),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            EconomyError::AutomatedSettlementRejected { .. }
        ));
    }

    #[test]
    fn automated_settlement_fails_for_inactive_ruleset_or_wrapper() {
        let (mut ruleset, node, adoption, use_event, wrapper, value_event) =
            coherent_settlement_objects();
        ruleset.status = RulesetStatus::Suspended;
        let err = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: authority("adopter-principal"),
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions: settlement_preconditions(),
            created_at_hlc: ts(3_100),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            EconomyError::AutomatedSettlementRejected { .. }
        ));

        let (ruleset, node, adoption, use_event, mut wrapper, value_event) =
            coherent_settlement_objects();
        wrapper.status = BailmentWrapperStatus::Suspended;
        let err = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: authority("adopter-principal"),
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions: settlement_preconditions(),
            created_at_hlc: ts(3_100),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            EconomyError::AutomatedSettlementRejected { .. }
        ));
    }

    #[test]
    fn automated_settlement_fails_for_hash_mismatches_and_unsupported_basis() {
        let (ruleset, node, adoption, use_event, mut wrapper, value_event) =
            coherent_settlement_objects();
        wrapper.settlement_ruleset_id = h(0x99);
        let err = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: authority("adopter-principal"),
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions: settlement_preconditions(),
            created_at_hlc: ts(3_100),
        })
        .unwrap_err();
        assert!(matches!(err, EconomyError::HashMismatch { .. }));

        let (ruleset, node, adoption, use_event, mut wrapper, value_event) =
            coherent_settlement_objects();
        wrapper.wrapper_id = h(0x98);
        let err = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: authority("adopter-principal"),
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions: settlement_preconditions(),
            created_at_hlc: ts(3_100),
        })
        .unwrap_err();
        assert!(matches!(err, EconomyError::HashMismatch { .. }));

        let (ruleset, node, adoption, use_event, wrapper, value_event) =
            coherent_settlement_objects();
        let err = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: authority("adopter-principal"),
            preapproved_terms_hash: h(0x97),
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions: settlement_preconditions(),
            created_at_hlc: ts(3_100),
        })
        .unwrap_err();
        assert!(matches!(err, EconomyError::HashMismatch { .. }));

        let (ruleset, node, adoption, use_event, wrapper, mut value_event) =
            coherent_settlement_objects();
        value_event.value_basis = ValueBasis::Other("unsupported".into());
        let err = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: authority("adopter-principal"),
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions: settlement_preconditions(),
            created_at_hlc: ts(3_100),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            EconomyError::UnsupportedSettlementBasis { .. }
        ));
    }

    #[test]
    fn automated_settlement_validate_rejects_mutated_event_shape() {
        let (ruleset, node, adoption, use_event, wrapper, value_event) =
            coherent_settlement_objects();
        let event = AutomatedSettlementEvent::from_inputs(AutomatedSettlementInputs {
            value_event: &value_event,
            use_event: &use_event,
            contribution_node: &node,
            adoption: &adoption,
            ruleset: &ruleset,
            wrapper: &wrapper,
            automation_authority_ref: authority("adopter-principal"),
            preapproved_terms_hash: node.honor_good_terms_hash,
            basis_amounts: &basis_amounts(),
            zero_fee_reason: Some(ZeroFeeReason::PolicyConfiguredZero),
            preconditions: settlement_preconditions(),
            created_at_hlc: ts(3_100),
        })
        .unwrap();

        let mut empty_lines = event.clone();
        empty_lines.settlement_lines.clear();
        assert!(matches!(
            empty_lines.validate().unwrap_err(),
            EconomyError::InvalidInput { .. }
        ));

        let mut invalid_authority = event.clone();
        invalid_authority.automation_authority_ref.envelope_id = Hash256::ZERO;
        assert!(matches!(
            invalid_authority.validate().unwrap_err(),
            EconomyError::InvalidInput { .. }
        ));

        let mut human_approval = event.clone();
        human_approval.human_approval_required = true;
        assert!(matches!(
            human_approval.validate().unwrap_err(),
            EconomyError::AutomatedSettlementRejected { .. }
        ));

        let mut empty_checks = event.clone();
        empty_checks.fail_closed_checks.clear();
        assert!(matches!(
            empty_checks.validate().unwrap_err(),
            EconomyError::InvalidInput { .. }
        ));

        let mut blank_check = event;
        blank_check.fail_closed_checks.push("   ".into());
        assert!(matches!(
            blank_check.validate().unwrap_err(),
            EconomyError::EmptyField { .. }
        ));
    }
}
