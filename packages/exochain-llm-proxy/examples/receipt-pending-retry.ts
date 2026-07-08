import {
  createReceiptedOpenAIClient,
  hashProviderPayload,
  resolveReceiptPending,
  type FetchLike,
  type LlmProxyConfig,
  type ReceiptEmissionResult,
} from "../src/index.js";

export const exampleRetryConfig = (fetchImpl: FetchLike): LlmProxyConfig => ({
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

export async function runReceiptPendingRetryExample(
  fetchImpl: FetchLike,
): Promise<ReceiptEmissionResult | undefined> {
  const config = exampleRetryConfig(fetchImpl);
  const client = createReceiptedOpenAIClient(config, {
    openAIBaseUrl: "https://api.openai.com",
    apiKey: process.env.OPENAI_API_KEY,
  });
  const result = await client.responses.create(
    {
      model: "gpt-4.1-mini",
      input: "Use only public release notes.",
    },
    {
      idempotencyKey: "tenant-alpha-retry-001",
      createdAt: { physical_ms: 1_770_000_000_000, logical: 0 },
    },
  );

  if (result.status !== "receipt_pending") {
    return undefined;
  }
  return resolveReceiptPending(config, result);
}
