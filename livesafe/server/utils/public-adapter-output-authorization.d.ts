export type PublicAdapterOutputAuthorizationResponseState =
  | "permit"
  | "deny"
  | "rejected"
  | "timeout"
  | "unavailable"
  | "not-called"
  | "stale"
  | "revoked"
  | "contradicted";

export interface PublicAdapterOutputAuthorizationDto {
  schema: "livesafe.public_adapter_output_authorization.v1";
  subject: "livesafe.ai";
  audience: "https://livesafe.ai/api/trust/status";
  timestamp_basis?: "exochain_hlc";
  claims: string[];
  evidence_hash: string;
  receipt_id: string;
  proof_id: string;
  proof_ref: string;
  generated_at: string;
  valid_from: string;
  expires_at: string;
  proof: {
    type: string;
    signature: string;
  };
  revoked?: boolean;
  contradicted?: boolean;
}

export interface PublicAdapterOutputAuthorizationDecision {
  allowed: boolean;
  responseState: PublicAdapterOutputAuthorizationResponseState | string;
  transportCalled: boolean;
  value: unknown;
}

export interface PublicAdapterOutputAuthorizationMetadata {
  schema: "livesafe.public_adapter_output_authorization.v1";
  subject: "livesafe.ai";
  audience: "https://livesafe.ai/api/trust/status";
  claims: string[];
  evidence_hash: string;
  receipt_id: string;
  proof_id: string;
  proof_ref: string;
  generated_at: string;
  valid_from: string;
  expires_at: string;
  proof_type: string;
  response_state: "permit";
  transport_called: true;
}

export interface PublicAdapterOutputAuthorizationEvaluation {
  allowed: boolean;
  reasons: string[];
  required_evidence: string[];
  responseState: string;
  transportCalled: boolean;
  metadata: PublicAdapterOutputAuthorizationMetadata | null;
}

export const ALLOWED_PUBLIC_ADAPTER_OUTPUT_CLAIMS: readonly string[];
export const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_AUDIENCE: "https://livesafe.ai/api/trust/status";
export const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SCHEMA: "livesafe.public_adapter_output_authorization.v1";
export const PUBLIC_ADAPTER_OUTPUT_AUTHORIZATION_SUBJECT: "livesafe.ai";

export function evaluatePublicAdapterOutputAuthorization(
  adapterOutputAuthorization: unknown,
  options?: {
    currentAt?: string;
    subject?: string;
    audience?: string;
  }
): PublicAdapterOutputAuthorizationEvaluation;
