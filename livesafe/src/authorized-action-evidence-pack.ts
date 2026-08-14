import {
  type AdapterState,
  type ExochainResponseState,
  type SurfaceClassification,
  evaluateExochainBoundary,
} from "./exochain-boundary.js";

const HEX_64 = /^[0-9a-f]{64}$/;
const ZERO_HEX = "0".repeat(64);

export const AUTHORIZED_ACTION_EVIDENCE_PACK_RECORD_TYPE = "hashes" as const;

export interface AuthorizedActionEvidencePackView {
  presented: boolean;
  recordType: typeof AUTHORIZED_ACTION_EVIDENCE_PACK_RECORD_TYPE | null;
  insuranceUnderwritable: false;
  exochainProtected: boolean;
  reasons: string[];
}

export interface PresentAuthorizedActionEvidencePackRequest {
  packHash: string;
  actionCommitmentHash: string;
  classification: SurfaceClassification;
  adapterState: AdapterState;
  exochainResponse: ExochainResponseState;
  claimsInsuranceUnderwritable: boolean;
  storesRawPhi: boolean;
}

function isBoundHash(value: string): boolean {
  return HEX_64.test(value) && value !== ZERO_HEX;
}

/**
 * Present a hosted Authorized Action Evidence Pack as hash commitments only.
 * LiveSafe remains an adjacent design partner: no insurance underwriting and
 * no EXOCHAIN protection claim unless the verified adapter permits.
 */
export function presentAuthorizedActionEvidencePack(
  request: PresentAuthorizedActionEvidencePackRequest,
): AuthorizedActionEvidencePackView {
  const reasons: string[] = [];

  if (!isBoundHash(request.packHash)) {
    reasons.push("Evidence pack hash must be a non-zero 64-character hex digest.");
  }
  if (!isBoundHash(request.actionCommitmentHash)) {
    reasons.push("Action commitment hash must be a non-zero 64-character hex digest.");
  }
  if (request.claimsInsuranceUnderwritable) {
    reasons.push("LiveSafe cannot claim an insurance-underwritable event.");
  }
  if (request.storesRawPhi) {
    reasons.push("Raw PHI must remain off-chain; only hashes and commitments are presentable.");
  }

  const boundary = evaluateExochainBoundary({
    classification: request.classification,
    adapterState: request.adapterState,
    exochainResponse: request.exochainResponse,
    claimsExochainTrust: true,
    readsExochainCoreState: true,
    writesExochainCoreState: false,
    storesRawSensitiveDataOnChain: request.storesRawPhi,
  });
  reasons.push(...boundary.reasons);

  const presented = reasons.length === 0;
  return {
    presented,
    recordType: presented ? AUTHORIZED_ACTION_EVIDENCE_PACK_RECORD_TYPE : null,
    insuranceUnderwritable: false,
    exochainProtected: presented,
    reasons,
  };
}
