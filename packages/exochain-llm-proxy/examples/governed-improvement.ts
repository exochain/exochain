// Copyright 2026 Exochain Foundation
// SPDX-License-Identifier: Apache-2.0
import { createGovernedAgent, type AgentRuntimeConfig, type AgentMission } from "../src/index.js";

/**
 * Configure propose_change and evaluate_candidate as scoped MCP tools on an
 * isolated checkout. The host's acceptance check must verify the evaluator's
 * receipted report, source commit, required tests and measured baseline.
 * Neither model receives signing keys or a publish/merge tool.
 */
export async function runGovernedImprovement(
  host: Pick<AgentRuntimeConfig, "planner" | "reviewer" | "now" | "verifyCompletion">,
  tools: AgentRuntimeConfig["tools"],
  mission: AgentMission,
  signal?: AbortSignal,
) {
  const runner = createGovernedAgent({
    ...host,
    tools: tools.filter(tool => ["propose_change", "evaluate_candidate"].includes(tool.name)),
    loop: {
      max_iterations: 8,
      max_model_calls: 16,
      max_tool_calls: 6,
      stop_condition: "reviewed_verified_completion",
      escalation: "return_to_human",
    },
    operationTimeoutMs: 60_000,
  });
  return runner.run(mission, { signal });
}
