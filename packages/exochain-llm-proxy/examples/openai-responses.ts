import {
  createReceiptedOpenAIClient,
  hashProviderPayload,
  type FetchLike,
  type LlmProxyConfig,
} from "../src/index.js";

export const exampleResponsesConfig = (fetchImpl: FetchLike): LlmProxyConfig => ({
  mode: "production",
  gatewayUrl: "https://exochain.example",
  tenantId: "tenant-alpha",
  namespace: "default",
  actorDid: "did:exo:agent",
  adapterDid: "did:exo:lynk-adapter",
  custodyPolicyHash: hashProviderPayload("customer-custody-policy-v1"),
  storageMode: "receipt_minimized",
  validation: { action: "llm.usage.receipt.emit" },
  subjectSignature: "subject-signature-placeholder",
  adapterSignature: "adapter-signature-placeholder",
  fetch: fetchImpl,
});

export async function runOpenAIResponsesExample(fetchImpl: FetchLike): Promise<unknown> {
  const client = createReceiptedOpenAIClient(exampleResponsesConfig(fetchImpl), {
    openAIBaseUrl: "https://api.openai.com",
    apiKey: process.env.OPENAI_API_KEY,
  });

  return client.responses.create(
    {
      model: "gpt-4.1-mini",
      input: "Use only public release notes.",
    },
    {
      idempotencyKey: "tenant-alpha-responses-001",
      createdAt: { physical_ms: 1_770_000_000_000, logical: 0 },
    },
  );
}
