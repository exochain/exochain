import type { LlmProxyConfig } from "../src/index.js";

/**
 * Caller-provided, cryptographically valid AVC authority material. The
 * examples deliberately require this input because placeholder credentials or
 * signatures cannot be accepted by the EXOCHAIN receipt route. The trusted
 * validator identity and public key are caller-pinned trust roots; they must
 * never be learned from a receipt response.
 */
export type ReceiptAuthority = Pick<
  LlmProxyConfig,
  | "validation"
  | "subjectSignature"
  | "subjectPublicKey"
  | "adapterSignature"
  | "adapterPublicKey"
> & Required<Pick<
  LlmProxyConfig,
  "trustedValidatorDid" | "trustedValidatorPublicKey"
>>;
