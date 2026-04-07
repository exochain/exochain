/**
 * panels.js — 5-panel council review system for ExoForge.
 *
 * Implements the multi-panel governance review process modeled on
 * ExoChain's three-branch (legislative/executive/judicial) structure.
 * Each panel evaluates proposals within its scope and casts a weighted vote.
 */

/**
 * The 5 standing council panels.
 * Each panel has a defined scope, voting weight, and review criteria.
 */
const PANELS = [
  {
    name: 'Governance',
    scope: 'Constitutional compliance, TNC enforcement, quorum rules, delegation ceilings, authority chains',
    weight: 0.25,
    branch: 'legislative',
    criteria: [
      'Does the proposal comply with all 10 TNCs?',
      'Are authority chains properly delegated and unexpired?',
      'Does it respect the AI delegation ceiling?',
      'Is the human gate satisfied for this decision class?',
      'Does it require constitutional amendment?'
    ]
  },
  {
    name: 'Legal',
    scope: 'Fiduciary duty, safe harbor (DGCL 144), evidence handling, privilege assertions, bailment terms',
    weight: 0.20,
    branch: 'judicial',
    criteria: [
      'Does the proposal create fiduciary duty conflicts?',
      'Are safe harbor requirements met for interested-party transactions?',
      'Is evidence chain of custody preserved?',
      'Are privilege assertions properly documented?',
      'Does it comply with data retention and eDiscovery obligations?'
    ]
  },
  {
    name: 'Architecture',
    scope: 'System design, WASM kernel integrity, Merkle tree structures, combinator correctness, holon lifecycle',
    weight: 0.20,
    branch: 'executive',
    criteria: [
      'Does the change maintain Merkle tree integrity?',
      'Are combinator reductions correct?',
      'Does it affect BCTS state transitions?',
      'Is the WASM boundary properly respected?',
      'Does holon lifecycle management remain sound?'
    ]
  },
  {
    name: 'Security',
    scope: 'Threat assessment, PACE escalation, Shamir secret management, risk attestations, detection signals',
    weight: 0.20,
    branch: 'judicial',
    criteria: [
      'Does the proposal introduce new attack surfaces?',
      'Are PACE escalation paths properly configured?',
      'Is secret management (Shamir splitting) correctly handled?',
      'Are risk attestations current and unexpired?',
      'Do detection signals indicate active threats?'
    ]
  },
  {
    name: 'Operations',
    scope: 'Deployment readiness, succession planning, emergency actions, monitoring, governance health',
    weight: 0.15,
    branch: 'executive',
    criteria: [
      'Is the deployment path safe and reversible?',
      'Are succession plans activated or updated as needed?',
      'Does it affect emergency action capabilities?',
      'Is monitoring and health reporting adequate?',
      'Are governance receipts properly chained?'
    ]
  }
];

/**
 * Get all panel definitions.
 * @returns {Array} Array of panel objects
 */
export function getPanels() {
  return PANELS.map(p => ({ ...p }));
}

/**
 * Get a specific panel by name.
 * @param {string} name - Panel name (case-insensitive)
 * @returns {object|null} Panel definition or null if not found
 */
export function getPanel(name) {
  const panel = PANELS.find(p => p.name.toLowerCase() === name.toLowerCase());
  return panel ? { ...panel } : null;
}

/**
 * Conduct a multi-panel review of a proposal.
 *
 * Each panel evaluates the proposal against its criteria and produces
 * a structured assessment. This function returns the raw assessments;
 * use tallyVotes() to compute the final verdict.
 *
 * @param {Array} panels - Array of panel definitions (from getPanels())
 * @param {object} proposal - Proposal to review:
 *   { title, description, type, affectedSystems, author }
 * @returns {Array} Array of panel assessments:
 *   { panel, vote, confidence, findings, criteria_met, criteria_failed }
 */
export function conductReview(panels, proposal) {
  const assessments = [];

  for (const panel of panels) {
    const assessment = evaluatePanel(panel, proposal);
    assessments.push(assessment);
  }

  return assessments;
}

/**
 * Evaluate a single panel's review of a proposal.
 *
 * Performs heuristic analysis based on the proposal's described impact
 * areas and the panel's criteria. In production, this would invoke
 * Claude Code for deeper semantic analysis.
 *
 * @param {object} panel - Panel definition
 * @param {object} proposal - Proposal to evaluate
 * @returns {object} Panel assessment
 */
function evaluatePanel(panel, proposal) {
  const desc = (proposal.description || '').toLowerCase();
  const title = (proposal.title || '').toLowerCase();
  const combined = `${title} ${desc}`;
  const affectedSystems = (proposal.affectedSystems || []).map(s => s.toLowerCase());

  const criteriaMet = [];
  const criteriaFailed = [];
  const findings = [];

  // Governance panel checks
  if (panel.name === 'Governance') {
    if (/tnc|terms|conditions|constitutional/.test(combined)) {
      criteriaFailed.push('May affect TNC enforcement — requires detailed review');
      findings.push('Proposal touches constitutional compliance area');
    } else {
      criteriaMet.push('No direct TNC impact detected');
    }
    if (/delegation|authority|chain/.test(combined)) {
      findings.push('Authority chain or delegation changes detected');
      criteriaFailed.push('Delegation changes require human gate verification');
    } else {
      criteriaMet.push('No delegation changes');
    }
    if (/amendment|constitutional/.test(combined)) {
      criteriaFailed.push('Constitutional amendment requires supermajority');
      findings.push('CRITICAL: Constitutional amendment proposed');
    } else {
      criteriaMet.push('No constitutional amendment required');
    }
  }

  // Legal panel checks
  if (panel.name === 'Legal') {
    if (/fiduciary|duty|conflict|interest/.test(combined)) {
      criteriaFailed.push('Fiduciary duty implications detected');
      findings.push('Proposal may create conflicts of interest');
    } else {
      criteriaMet.push('No fiduciary conflicts detected');
    }
    if (/evidence|custody|chain/.test(combined)) {
      findings.push('Evidence handling implications');
      criteriaMet.push('Evidence chain review required but non-blocking');
    }
    if (/safe.?harbor|dgcl|144|interested/.test(combined)) {
      criteriaFailed.push('Safe harbor transaction — requires disinterested vote');
      findings.push('DGCL 144 safe harbor process must be followed');
    } else {
      criteriaMet.push('No safe harbor implications');
    }
  }

  // Architecture panel checks
  if (panel.name === 'Architecture') {
    if (/merkle|hash|tree|integrity/.test(combined)) {
      findings.push('Merkle tree structure may be affected');
      criteriaFailed.push('Merkle integrity verification needed');
    } else {
      criteriaMet.push('No Merkle tree impact');
    }
    if (/wasm|kernel|combinator|holon/.test(combined)) {
      findings.push('WASM kernel boundary changes detected');
      criteriaFailed.push('Kernel changes require full regression test');
    } else {
      criteriaMet.push('WASM boundary unchanged');
    }
    if (/bcts|state|transition|lifecycle/.test(combined)) {
      findings.push('BCTS state transitions may be affected');
      criteriaMet.push('State transition review recommended');
    } else {
      criteriaMet.push('No BCTS lifecycle impact');
    }
  }

  // Security panel checks
  if (panel.name === 'Security') {
    if (/threat|attack|vulnerab|exploit|cve/.test(combined)) {
      criteriaFailed.push('Security threat indicators present');
      findings.push('ALERT: Potential security implications');
    } else {
      criteriaMet.push('No immediate threat indicators');
    }
    if (/pace|escalat|emergency/.test(combined)) {
      findings.push('PACE escalation path changes');
      criteriaFailed.push('Escalation path changes need security review');
    } else {
      criteriaMet.push('PACE configuration unchanged');
    }
    if (/secret|shamir|key|encrypt|sign/.test(combined)) {
      findings.push('Cryptographic operations affected');
      criteriaFailed.push('Secret management changes require security audit');
    } else {
      criteriaMet.push('No cryptographic changes');
    }
  }

  // Operations panel checks
  if (panel.name === 'Operations') {
    if (/deploy|release|rollback|migration/.test(combined)) {
      findings.push('Deployment path changes detected');
      criteriaMet.push('Deployment plan should be documented');
    } else {
      criteriaMet.push('No deployment changes');
    }
    if (/succession|failover|backup/.test(combined)) {
      findings.push('Succession planning affected');
      criteriaFailed.push('Succession plan update required');
    } else {
      criteriaMet.push('Succession plans unaffected');
    }
    if (/monitor|health|metric|alert/.test(combined)) {
      findings.push('Monitoring configuration changes');
      criteriaMet.push('Health reporting updates noted');
    } else {
      criteriaMet.push('Monitoring unchanged');
    }
  }

  // Default criteria for panels without specific matching
  if (criteriaMet.length === 0 && criteriaFailed.length === 0) {
    criteriaMet.push('No specific concerns identified for this panel');
  }

  // Compute vote: approve if more criteria met than failed
  const vote = criteriaFailed.length === 0 ? 'approve'
    : criteriaFailed.length <= criteriaMet.length ? 'approve_with_conditions'
    : 'reject';

  // Confidence based on how many criteria were definitively evaluated
  const totalEvaluated = criteriaMet.length + criteriaFailed.length;
  const confidence = Math.min(1.0, totalEvaluated / panel.criteria.length);

  return {
    panel: panel.name,
    branch: panel.branch,
    weight: panel.weight,
    vote,
    confidence: Math.round(confidence * 100) / 100,
    findings,
    criteria_met: criteriaMet,
    criteria_failed: criteriaFailed,
    reviewed_at: new Date().toISOString()
  };
}

/**
 * Tally votes from panel assessments and produce a final verdict.
 *
 * Voting weights are applied to each panel's vote:
 *   approve = +1.0, approve_with_conditions = +0.5, reject = -1.0
 *
 * The final score is the weighted sum normalized to [-1, +1].
 * Verdict thresholds:
 *   score > 0.3  => APPROVED
 *   score > 0.0  => APPROVED_WITH_CONDITIONS
 *   score > -0.3 => DEFERRED (needs further review)
 *   score <= -0.3 => REJECTED
 *
 * A single Security or Governance REJECT acts as a veto regardless of score.
 *
 * @param {Array} votes - Array of panel assessments (from conductReview)
 * @returns {object} { verdict, score, breakdown, vetoed_by, total_findings }
 */
export function tallyVotes(votes) {
  const voteValues = {
    approve: 1.0,
    approve_with_conditions: 0.5,
    reject: -1.0
  };

  let weightedSum = 0;
  let totalWeight = 0;
  const breakdown = [];
  let vetoedBy = null;
  let totalFindings = 0;

  for (const assessment of votes) {
    const value = voteValues[assessment.vote] || 0;
    const weightedValue = value * assessment.weight * assessment.confidence;
    weightedSum += weightedValue;
    totalWeight += assessment.weight;
    totalFindings += assessment.findings.length;

    breakdown.push({
      panel: assessment.panel,
      vote: assessment.vote,
      weight: assessment.weight,
      confidence: assessment.confidence,
      weighted_value: Math.round(weightedValue * 1000) / 1000,
      findings_count: assessment.findings.length
    });

    // Veto power: Security or Governance rejection blocks approval
    if (assessment.vote === 'reject' && (assessment.panel === 'Security' || assessment.panel === 'Governance')) {
      vetoedBy = assessment.panel;
    }
  }

  const normalizedScore = totalWeight > 0 ? weightedSum / totalWeight : 0;
  const score = Math.round(normalizedScore * 1000) / 1000;

  let verdict;
  if (vetoedBy) {
    verdict = 'REJECTED';
  } else if (score > 0.3) {
    verdict = 'APPROVED';
  } else if (score > 0.0) {
    verdict = 'APPROVED_WITH_CONDITIONS';
  } else if (score > -0.3) {
    verdict = 'DEFERRED';
  } else {
    verdict = 'REJECTED';
  }

  return {
    verdict,
    score,
    breakdown,
    vetoed_by: vetoedBy,
    total_findings: totalFindings,
    panels_reviewed: votes.length,
    reviewed_at: new Date().toISOString()
  };
}
