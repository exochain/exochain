import type { AgentMission, AgentRunResult, AgentRuntimeConfig } from "./agent-types.js";
export declare function createGovernedAgent(config: AgentRuntimeConfig): {
    run(mission: AgentMission, options?: {
        signal?: AbortSignal;
    }): Promise<AgentRunResult>;
};
//# sourceMappingURL=agent.d.ts.map