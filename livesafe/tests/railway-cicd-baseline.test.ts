import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = resolve(process.cwd(), "..");

function readRepoFile(relativePath: string): string {
  const absolutePath = resolve(repoRoot, relativePath);

  expect(existsSync(absolutePath), `${relativePath} should exist`).toBe(true);

  return readFileSync(absolutePath, "utf8");
}

function readWorkflowJob(workflow: string, jobId: string): string {
  const jobStart = workflow.indexOf(`  ${jobId}:\n`);

  expect(jobStart, `${jobId} job should exist`).toBeGreaterThanOrEqual(0);

  const afterJobStart = jobStart + 1;
  const nextJobMatch = workflow.slice(afterJobStart).match(/\n  [a-z0-9-]+:\n/);
  const jobEnd = nextJobMatch?.index;

  if (jobEnd === undefined) {
    return workflow.slice(jobStart);
  }

  return workflow.slice(jobStart, afterJobStart + jobEnd);
}

function readWorkflowGlobalEnv(workflow: string): string {
  const envStart = workflow.indexOf("\nenv:\n");
  const jobsStart = workflow.indexOf("\njobs:\n");

  expect(envStart, "workflow should define top-level env").toBeGreaterThanOrEqual(0);
  expect(jobsStart, "workflow should define jobs").toBeGreaterThan(envStart);

  return workflow.slice(envStart, jobsStart);
}

function expectRailwayAuthSecret(
  workflow: string,
  jobId: string,
  secretName: string,
): void {
  const job = readWorkflowJob(workflow, jobId);

  expect(job, `${jobId} should use ${secretName} for Railway auth`).toContain(
    `RAILWAY_TOKEN: \${{ secrets.${secretName} }}`,
  );
  expect(job, `${jobId} must not use the stale global Railway token`).not.toContain(
    "secrets.RAILWAY_TOKEN",
  );
  expect(job, `${jobId} must not require a Railway API token fallback`).not.toContain(
    "secrets.RAILWAY_API_TOKEN",
  );
}

function expectExplicitSmokeTimeoutBudget(workflow: string, jobId: string): void {
  const envName = "LIVESAFE_RAILWAY_SMOKE_TIMEOUT_SECONDS";
  const job = readWorkflowJob(workflow, jobId);
  const jobTimeoutMatch = job.match(
    new RegExp(`\\n\\s{6}${envName}:\\s*"?([0-9]+)"?`),
  );
  const globalTimeoutMatch = readWorkflowGlobalEnv(workflow).match(
    new RegExp(`\\n\\s{2}${envName}:\\s*"?([0-9]+)"?`),
  );
  const timeoutSeconds = Number(jobTimeoutMatch?.[1] ?? globalTimeoutMatch?.[1]);

  expect(
    timeoutSeconds,
    `${jobId} should explicitly budget Railway smoke above the 600 second script default`,
  ).toBeGreaterThan(600);
}

function expectPromotionSmokePublicClaimsEnv(workflow: string, jobId: string): void {
  const job = readWorkflowJob(workflow, jobId);

  expect(job, `${jobId} should pass expected public claims mode to smoke`).toContain(
    "LIVESAFE_EXPECT_PUBLIC_CLAIMS_ALLOWED: ${{ inputs.expected_public_claims_allowed || 'false' }}",
  );
  expect(job, `${jobId} should run the smoke script for the selected target`).toContain(
    'scripts/livesafe-railway-smoke.sh "$TARGET_ENVIRONMENT"',
  );
}

function writeExecutable(filePath: string, content: string): void {
  writeFileSync(filePath, content, "utf8");
  chmodSync(filePath, 0o755);
}

describe("LiveSafe Railway CI/CD baseline", () => {
  it("declares the ARMORCLOUD LiveSafe project environments and service names without secrets", () => {
    const manifest = JSON.parse(
      readRepoFile("livesafe/config/railway-environments.json"),
    ) as {
      projectId: string;
      workspace: string;
      environments: Array<{ id: string; name: string; livesafeDomain?: string }>;
      services: Array<{ id: string; name: string }>;
      productionDomain: string;
    };

    expect(manifest).toEqual({
      projectId: "372de75b-5f44-46c2-ab70-3c3185b5d81e",
      workspace: "ARMORCLOUD",
      environments: [
        {
          id: "3dc06fb6-c3df-4fe4-8807-0da0e62e4028",
          livesafeDomain: "https://livesafe-development.up.railway.app",
          name: "development",
        },
        {
          id: "a223bc12-fbe4-430f-abce-8e3ee7c9abd3",
          livesafeDomain: "https://livesafe-staging.up.railway.app",
          name: "staging",
        },
        {
          id: "1e5153e1-15f4-4447-bf7c-029af33927fb",
          name: "production",
        },
      ],
      services: [
        { id: "8ed3bd1a-f872-4e22-9a39-ac38953fae26", name: "livesafe" },
        { id: "4d8384d3-be5d-48d6-a914-97eb6133e53d", name: "exochain-node" },
        { id: "2ab3f445-d6f7-4245-940c-985a14e974f9", name: "exochain-node-db" },
        { id: "691122bb-025b-463d-8033-7f94f7678748", name: "Postgres" },
      ],
      productionDomain: "https://livesafe.ai",
    });
  });

  it("adds a protected Railway promotion workflow for development, staging, and production", () => {
    const workflow = readRepoFile(".github/workflows/livesafe-railway-deploy.yml");

    expect(workflow).toContain("name: LiveSafe Railway Deploy");
    expect(workflow).toContain(
      "RAILWAY_PROJECT_ID: 372de75b-5f44-46c2-ab70-3c3185b5d81e",
    );
    expect(workflow).toContain(
      "RAILWAY_DEVELOPMENT_ENVIRONMENT_ID: 3dc06fb6-c3df-4fe4-8807-0da0e62e4028",
    );
    expect(workflow).toContain(
      "RAILWAY_STAGING_ENVIRONMENT_ID: a223bc12-fbe4-430f-abce-8e3ee7c9abd3",
    );
    expect(workflow).toContain(
      "RAILWAY_PRODUCTION_ENVIRONMENT_ID: 1e5153e1-15f4-4447-bf7c-029af33927fb",
    );
    expect(workflow).toContain(
      "EXOCHAIN_NODE_SERVICE_ID: 4d8384d3-be5d-48d6-a914-97eb6133e53d",
    );
    expect(workflow).toContain(
      "LIVESAFE_SERVICE_ID: 8ed3bd1a-f872-4e22-9a39-ac38953fae26",
    );
    expect(workflow).toContain("environment: livesafe-development");
    expect(workflow).toContain("environment: livesafe-staging");
    expect(workflow).toContain("environment: livesafe-production");
    expectRailwayAuthSecret(
      workflow,
      "deploy-development",
      "RAILWAY_DEVELOPMENT_TOKEN",
    );
    expectRailwayAuthSecret(workflow, "deploy-staging", "RAILWAY_STAGING_TOKEN");
    expectRailwayAuthSecret(
      workflow,
      "deploy-production",
      "RAILWAY_PRODUCTION_TOKEN",
    );
    expect(workflow).toContain("verify-livesafe:");
    expect(workflow).toContain("uses: ./.github/workflows/livesafe-ci.yml");
    expect(workflow).toContain("commit_sha: ${{ inputs.commit_sha || github.sha }}");
    expect(workflow).toContain("needs: verify-livesafe");
    expect(workflow).toContain(
      'railway up . --path-as-root --project "$RAILWAY_PROJECT_ID" --environment "$RAILWAY_DEVELOPMENT_ENVIRONMENT_ID" --service "$EXOCHAIN_NODE_SERVICE_ID"',
    );
    expect(workflow).toContain(
      'railway up . --path-as-root --project "$RAILWAY_PROJECT_ID" --environment "$RAILWAY_DEVELOPMENT_ENVIRONMENT_ID" --service "$LIVESAFE_SERVICE_ID"',
    );
    expect(workflow).toContain(
      'railway up . --path-as-root --project "$RAILWAY_PROJECT_ID" --environment "$TARGET_ENVIRONMENT_ID" --service "$EXOCHAIN_NODE_SERVICE_ID"',
    );
    expect(workflow).toContain(
      'railway up . --path-as-root --project "$RAILWAY_PROJECT_ID" --environment "$TARGET_ENVIRONMENT_ID" --service "$LIVESAFE_SERVICE_ID"',
    );
    expect(workflow).not.toContain("railway up livesafe --path-as-root");
    expect(workflow).toContain(
      'scripts/livesafe-railway-smoke.sh "$TARGET_ENVIRONMENT"',
    );
  });

  it("sets an explicit Railway smoke timeout above the 600 second script default", () => {
    const workflow = readRepoFile(".github/workflows/livesafe-railway-deploy.yml");

    expectExplicitSmokeTimeoutBudget(workflow, "deploy-development");
    expectExplicitSmokeTimeoutBudget(workflow, "deploy-staging");
    expectExplicitSmokeTimeoutBudget(workflow, "deploy-production");
  });

  it("threads the expected public-claims dispatch choice into staging and production smoke only", () => {
    const workflow = readRepoFile(".github/workflows/livesafe-railway-deploy.yml");
    const developmentJob = readWorkflowJob(workflow, "deploy-development");

    expect(workflow).toContain("expected_public_claims_allowed:");
    expect(workflow).toContain(
      'description: "Expected public claims state for staging/production smoke"',
    );
    expect(workflow).toContain("type: choice");
    expect(workflow).toContain('default: "false"');
    expect(workflow).toContain('          - "false"');
    expect(workflow).toContain('          - "true"');
    expectPromotionSmokePublicClaimsEnv(workflow, "deploy-staging");
    expectPromotionSmokePublicClaimsEnv(workflow, "deploy-production");
    expect(developmentJob).toContain('scripts/livesafe-railway-smoke.sh "development"');
    expect(developmentJob).not.toContain("LIVESAFE_EXPECT_PUBLIC_CLAIMS_ALLOWED");
  });

  it("provides a bounded smoke probe script that never prints Railway variables", () => {
    const script = readRepoFile("scripts/livesafe-railway-smoke.sh");

    expect(script).toContain(
      'railway service list --project "$RAILWAY_PROJECT_ID" --environment "$railway_environment_id" --json',
    );
    expect(script).toContain(
      'railway service status --project "$RAILWAY_PROJECT_ID" --environment "$railway_environment_id" --service "$LIVESAFE_SERVICE_ID" --json',
    );
    expect(script).toContain(
      'railway service status --project "$RAILWAY_PROJECT_ID" --environment "$railway_environment_id" --service "$EXOCHAIN_NODE_SERVICE_ID" --json',
    );
    expect(script).toContain('railway_environment_id="3dc06fb6-c3df-4fe4-8807-0da0e62e4028"');
    expect(script).toContain('railway_environment_id="a223bc12-fbe4-430f-abce-8e3ee7c9abd3"');
    expect(script).toContain('railway_environment_id="1e5153e1-15f4-4447-bf7c-029af33927fb"');
    expect(script).toContain('LIVESAFE_SERVICE_ID="${LIVESAFE_SERVICE_ID:-8ed3bd1a-f872-4e22-9a39-ac38953fae26}"');
    expect(script).toContain('EXOCHAIN_NODE_SERVICE_ID="${EXOCHAIN_NODE_SERVICE_ID:-4d8384d3-be5d-48d6-a914-97eb6133e53d}"');
    expect(script).toContain("deadline_seconds=");
    expect(script).toContain("while [ \"$SECONDS\" -lt \"$deadline_seconds\" ]; do");
    expect(script).toContain("sleep 10");
    expect(script).toContain('.status == "SUCCESS"');
    expect(script).toContain(".stopped == false");
    expect(script).toContain('curl -fsS "$livesafe_url/api/health"');
    expect(script).toContain('curl -fsS "$livesafe_url/api/trust/status"');
    expect(script).toContain("public_claims_allowed == false");
    expect(script).not.toContain("railway variable list");
    expect(script).not.toContain("--kv");
  });

  it("rejects a stopped latest deployment before URL health can pass", () => {
    const testRoot = mkdtempSync(join(tmpdir(), "livesafe-railway-smoke-"));
    const binDir = join(testRoot, "bin");
    const railwayCallLog = join(testRoot, "railway.log");
    const curlCallLog = join(testRoot, "curl.log");

    mkdirSync(binDir);

    writeExecutable(
      join(binDir, "railway"),
      `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$RAILWAY_FAKE_CALL_LOG"

case "\${1:-} \${2:-}" in
  "service list")
    cat <<'JSON'
[
  {
    "id": "8ed3bd1a-f872-4e22-9a39-ac38953fae26",
    "name": "livesafe",
    "status": "SUCCESS",
    "deploymentStopped": false,
    "deploymentId": "9a1cf48c-fbe3-4149-b6e3-a6dab107607c",
    "latestDeployment": {
      "id": "a595f677-fc70-43e5-b68c-f75fc8f84ce0",
      "status": "FAILED",
      "deploymentStopped": true
    },
    "url": "https://livesafe-development.up.railway.app"
  },
  {
    "id": "4d8384d3-be5d-48d6-a914-97eb6133e53d",
    "name": "exochain-node",
    "status": "SUCCESS",
    "deploymentStopped": false,
    "deploymentId": "ec12cdf4-75e0-41a1-986c-c326aeec978f",
    "latestDeployment": {
      "id": "ec12cdf4-75e0-41a1-986c-c326aeec978f",
      "status": "SUCCESS",
      "deploymentStopped": false
    }
  },
  { "id": "2ab3f445-d6f7-4245-940c-985a14e974f9", "name": "exochain-node-db", "status": "SUCCESS" },
  { "id": "691122bb-025b-463d-8033-7f94f7678748", "name": "Postgres", "status": "SUCCESS" }
]
JSON
    ;;
  "service status")
    service=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --service|-s)
          shift
          service="\${1:-}"
          ;;
      esac
      shift || break
    done

    if [ "$service" = "8ed3bd1a-f872-4e22-9a39-ac38953fae26" ]; then
      cat <<'JSON'
{
  "id": "8ed3bd1a-f872-4e22-9a39-ac38953fae26",
  "name": "livesafe",
  "deploymentId": "a595f677-fc70-43e5-b68c-f75fc8f84ce0",
  "status": "FAILED",
  "stopped": true
}
JSON
    elif [ "$service" = "4d8384d3-be5d-48d6-a914-97eb6133e53d" ]; then
      cat <<'JSON'
{
  "id": "4d8384d3-be5d-48d6-a914-97eb6133e53d",
  "name": "exochain-node",
  "deploymentId": "ec12cdf4-75e0-41a1-986c-c326aeec978f",
  "status": "SUCCESS",
  "stopped": false
}
JSON
    else
      printf 'unexpected service %s\\n' "$service" >&2
      exit 2
    fi
    ;;
  *)
    printf 'unexpected railway command: %s\\n' "$*" >&2
    exit 2
    ;;
esac
`,
    );

    writeExecutable(
      join(binDir, "curl"),
      `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$CURL_FAKE_CALL_LOG"
url="\${@: -1}"

case "$url" in
  */api/health)
    printf '%s\\n' '{"status":"ok","database":"connected","exochain_connected":true}'
    ;;
  */api/trust/status)
    printf '%s\\n' '{"exochain_connected":true,"verified_runtime_adapter":true,"runtime_adapter_state":"verified","public_claims_allowed":false}'
    ;;
  *)
    printf 'unexpected curl url: %s\\n' "$url" >&2
    exit 2
    ;;
esac
`,
    );

    try {
      const result = spawnSync(
        "/usr/bin/env",
        ["bash", resolve(repoRoot, "scripts/livesafe-railway-smoke.sh"), "development"],
        {
          cwd: repoRoot,
          encoding: "utf8",
          env: {
            ...process.env,
            CURL_FAKE_CALL_LOG: curlCallLog,
            LIVESAFE_RAILWAY_SMOKE_TIMEOUT_SECONDS: "60",
            PATH: `${binDir}:${process.env.PATH ?? ""}`,
            RAILWAY_FAKE_CALL_LOG: railwayCallLog,
          },
        },
      );

      expect(result.status, result.stdout + result.stderr).not.toBe(0);
      expect(result.stderr).toContain("livesafe");
      expect(readFileSync(railwayCallLog, "utf8")).toContain("service status");
      expect(existsSync(curlCallLog) ? readFileSync(curlCallLog, "utf8") : "").toBe(
        "",
      );
    } finally {
      rmSync(testRoot, { force: true, recursive: true });
    }
  });

  it("waits through transient initializing stopped status before URL smoke", () => {
    const testRoot = mkdtempSync(join(tmpdir(), "livesafe-railway-smoke-"));
    const binDir = join(testRoot, "bin");
    const railwayCallLog = join(testRoot, "railway.log");
    const curlCallLog = join(testRoot, "curl.log");
    const sleepCallLog = join(testRoot, "sleep.log");
    const livesafeStatusCount = join(testRoot, "livesafe-status-count");

    mkdirSync(binDir);

    writeExecutable(
      join(binDir, "railway"),
      `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$RAILWAY_FAKE_CALL_LOG"

case "\${1:-} \${2:-}" in
  "service list")
    cat <<'JSON'
[
  {
    "id": "8ed3bd1a-f872-4e22-9a39-ac38953fae26",
    "name": "livesafe",
    "status": "SUCCESS",
    "deploymentStopped": false,
    "deploymentId": "23f5fa75-9f52-44ef-b23e-8769276c7cca",
    "latestDeployment": {
      "id": "23f5fa75-9f52-44ef-b23e-8769276c7cca",
      "status": "SUCCESS",
      "deploymentStopped": false
    },
    "url": "https://livesafe-development.up.railway.app"
  },
  {
    "id": "4d8384d3-be5d-48d6-a914-97eb6133e53d",
    "name": "exochain-node",
    "status": "SUCCESS",
    "deploymentStopped": false,
    "deploymentId": "ec12cdf4-75e0-41a1-986c-c326aeec978f",
    "latestDeployment": {
      "id": "ec12cdf4-75e0-41a1-986c-c326aeec978f",
      "status": "SUCCESS",
      "deploymentStopped": false
    }
  },
  { "id": "2ab3f445-d6f7-4245-940c-985a14e974f9", "name": "exochain-node-db", "status": "SUCCESS" },
  { "id": "691122bb-025b-463d-8033-7f94f7678748", "name": "Postgres", "status": "SUCCESS" }
]
JSON
    ;;
  "service status")
    service=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --service|-s)
          shift
          service="\${1:-}"
          ;;
      esac
      shift || break
    done

    if [ "$service" = "8ed3bd1a-f872-4e22-9a39-ac38953fae26" ]; then
      count="0"
      if [ -f "$LIVESAFE_STATUS_COUNT_FILE" ]; then
        count="$(cat "$LIVESAFE_STATUS_COUNT_FILE")"
      fi
      count="$((count + 1))"
      printf '%s\\n' "$count" > "$LIVESAFE_STATUS_COUNT_FILE"

      if [ "$count" -eq 1 ]; then
        cat <<'JSON'
{
  "id": "8ed3bd1a-f872-4e22-9a39-ac38953fae26",
  "name": "livesafe",
  "deploymentId": "23f5fa75-9f52-44ef-b23e-8769276c7cca",
  "status": "INITIALIZING",
  "stopped": true
}
JSON
      else
        cat <<'JSON'
{
  "id": "8ed3bd1a-f872-4e22-9a39-ac38953fae26",
  "name": "livesafe",
  "deploymentId": "23f5fa75-9f52-44ef-b23e-8769276c7cca",
  "status": "SUCCESS",
  "stopped": false
}
JSON
      fi
    elif [ "$service" = "4d8384d3-be5d-48d6-a914-97eb6133e53d" ]; then
      cat <<'JSON'
{
  "id": "4d8384d3-be5d-48d6-a914-97eb6133e53d",
  "name": "exochain-node",
  "deploymentId": "ec12cdf4-75e0-41a1-986c-c326aeec978f",
  "status": "SUCCESS",
  "stopped": false
}
JSON
    else
      printf 'unexpected service %s\\n' "$service" >&2
      exit 2
    fi
    ;;
  *)
    printf 'unexpected railway command: %s\\n' "$*" >&2
    exit 2
    ;;
esac
`,
    );

    writeExecutable(
      join(binDir, "curl"),
      `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$CURL_FAKE_CALL_LOG"
url="\${@: -1}"

case "$url" in
  */api/health)
    printf '%s\\n' '{"status":"ok","database":"connected","exochain_connected":true}'
    ;;
  */api/trust/status)
    printf '%s\\n' '{"exochain_connected":true,"verified_runtime_adapter":true,"runtime_adapter_state":"verified","public_claims_allowed":false}'
    ;;
  *)
    printf 'unexpected curl url: %s\\n' "$url" >&2
    exit 2
    ;;
esac
`,
    );

    writeExecutable(
      join(binDir, "sleep"),
      `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$SLEEP_FAKE_CALL_LOG"
`,
    );

    try {
      const result = spawnSync(
        "/usr/bin/env",
        ["bash", resolve(repoRoot, "scripts/livesafe-railway-smoke.sh"), "development"],
        {
          cwd: repoRoot,
          encoding: "utf8",
          env: {
            ...process.env,
            CURL_FAKE_CALL_LOG: curlCallLog,
            LIVESAFE_RAILWAY_SMOKE_TIMEOUT_SECONDS: "60",
            LIVESAFE_STATUS_COUNT_FILE: livesafeStatusCount,
            PATH: `${binDir}:${process.env.PATH ?? ""}`,
            RAILWAY_FAKE_CALL_LOG: railwayCallLog,
            SLEEP_FAKE_CALL_LOG: sleepCallLog,
          },
        },
      );

      expect(result.status, result.stdout + result.stderr).toBe(0);
      expect(result.stdout).toContain("LiveSafe development Railway smoke passed");
      expect(readFileSync(livesafeStatusCount, "utf8").trim()).toBe("2");
      expect(readFileSync(sleepCallLog, "utf8")).toBe("10\n");
      expect(readFileSync(curlCallLog, "utf8")).toContain("/api/health");
      expect(readFileSync(curlCallLog, "utf8")).toContain("/api/trust/status");
    } finally {
      rmSync(testRoot, { force: true, recursive: true });
    }
  });

  it("supports explicit fail-closed and authorized-green public-claims smoke contracts", () => {
    const script = readRepoFile("scripts/livesafe-railway-smoke.sh");

    expect(script).toContain(
      'expected_public_claims_allowed="${LIVESAFE_EXPECT_PUBLIC_CLAIMS_ALLOWED:-false}"',
    );
    expect(script).toContain('case "$expected_public_claims_allowed" in');
    expect(script).toContain("public_claims_allowed == false");
    expect(script).toContain("public_claims_allowed == true");
    expect(script).toContain('.machine_state == "public_trust_claims_allowed"');
    expect(script).toContain(
      ".public_adapter_output_authorization.response_state == \"permit\"",
    );
    expect(script).toContain(
      ".public_adapter_output_authorization.transport_called == true",
    );
    expect(script).not.toContain("railway variable list");
    expect(script).not.toContain("--kv");
  });
});
