import {
  createReceiptedOpenAIClient,
  hashProviderPayload,
  type FetchLike,
  type LlmProxyConfig,
} from "../src/index.js";
import type { ReceiptAuthority } from "./receipt-authority.js";

export const exampleChatConfig = (
  fetchImpl: FetchLike,
  authority: ReceiptAuthority,
): LlmProxyConfig => ({
  mode: "production",
  gatewayUrl: "https://exochain.example",
  tenantId: "tenant-alpha",
  namespace: "default",
  actorDid: "did:exo:agent",
  adapterDid: "did:exo:lynk-adapter",
  custodyPolicyHash: hashProviderPayload("customer-custody-policy-v1"),
  storageMode: "receipt_minimized",
  ...authority,
  fetch: fetchImpl,
});

export async function runChatCompletionsExample(
  fetchImpl: FetchLike,
  authority: ReceiptAuthority,
): Promise<unknown> {
  const client = createReceiptedOpenAIClient(exampleChatConfig(fetchImpl, authority), {
    openAIBaseUrl: "https://api.openai.com",
    apiKey: process.env.OPENAI_API_KEY,
  });
  const userMessage = { role: "user", content: "Use only public release notes." };

  return client.chat.completions.create(
    Object.fromEntries([
      ["model", "gpt-4.1-mini"],
      ["messages", [userMessage]],
    ]),
    {
      idempotencyKey: "tenant-alpha-chat-001",
      createdAt: { physical_ms: 1_770_000_000_000, logical: 0 },
    },
  );
}
