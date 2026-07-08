import {
  createReceiptedOpenAIClient,
  hashProviderPayload,
  type FetchLike,
  type KmsLike,
  type LlmProxyConfig,
  type ObjectStoreLike,
} from "../src/index.js";

export const exampleExternalPayloadConfig = (
  fetchImpl: FetchLike,
  kms: KmsLike,
  objectStore: ObjectStoreLike,
): LlmProxyConfig => ({
  mode: "production",
  gatewayUrl: "https://exochain.example",
  tenantId: "tenant-alpha",
  namespace: "default",
  actorDid: "did:exo:agent",
  adapterDid: "did:exo:lynk-adapter",
  custodyPolicyHash: hashProviderPayload("customer-custody-policy-v1"),
  storageMode: "external_payload_ref",
  validation: { action: "llm.usage.receipt.emit" },
  subjectSignature: "subject-signature-placeholder",
  adapterSignature: "adapter-signature-placeholder",
  fetch: fetchImpl,
  kms,
  objectStore,
});

export async function runExternalPayloadRefExample(
  fetchImpl: FetchLike,
  kms: KmsLike,
  objectStore: ObjectStoreLike,
): Promise<unknown> {
  const client = createReceiptedOpenAIClient(
    exampleExternalPayloadConfig(fetchImpl, kms, objectStore),
    {
      openAIBaseUrl: "https://api.openai.com",
      apiKey: process.env.OPENAI_API_KEY,
    },
  );

  return client.responses.create(
    {
      model: "gpt-4.1-mini",
      input: "Use only public release notes.",
    },
    {
      idempotencyKey: "tenant-alpha-external-001",
      createdAt: { physical_ms: 1_770_000_000_000, logical: 0 },
    },
  );
}
