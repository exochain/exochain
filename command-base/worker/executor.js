// Executes tasks via Claude Code CLI (claude -p)

const { spawn } = require('child_process');
const { buildMemberPrompt, getSetting } = require('./profiles');

function chooseModel(db, task) {
  const defaultModel = getSetting(db, 'autonomous_model') || 'sonnet';
  const complexModel = getSetting(db, 'autonomous_model_complex') || 'opus';

  // Use complex model for urgent/high priority with substantial descriptions
  if (
    (task.priority === 'urgent' || task.priority === 'high') &&
    task.description && task.description.length > 300
  ) {
    return complexModel;
  }
  return defaultModel;
}

function buildTaskPrompt(task, member, linkedRepos, linkedPaths) {
  let prompt = '';

  // Member persona
  if (member) {
    prompt += buildMemberPrompt(member);
  }

  // Task context
  prompt += `## Task\n`;
  prompt += `**Title:** ${task.title}\n`;
  prompt += `**Priority:** ${task.priority}\n`;
  if (task.description) {
    prompt += `\n${task.description}\n`;
  }

  // Linked repos context
  if (linkedRepos && linkedRepos.length > 0) {
    prompt += `\n## Available Repositories\n`;
    for (const repo of linkedRepos) {
      prompt += `- ${repo.owner}/${repo.name}: ${repo.url}${repo.description ? ' — ' + repo.description : ''}\n`;
    }
  }

  // Linked paths context
  if (linkedPaths && linkedPaths.length > 0) {
    prompt += `\n## Available Local Paths\n`;
    for (const p of linkedPaths) {
      prompt += `- [${p.type}] ${p.path}${p.description ? ' — ' + p.description : ''}\n`;
    }
  }

  prompt += `\n## Instructions\n`;
  prompt += `Complete this task thoroughly. Provide your full output below.\n`;

  return prompt;
}

function buildReviewPrompt(task, memberName, output) {
  return `You are Gray, Orchestrator & Team Lead.

Review the following work by ${memberName} for quality.

## Task
**Title:** ${task.title}
**Priority:** ${task.priority}
${task.description || ''}

## ${memberName}'s Output
${output}

## Review Instructions
Evaluate the output:
1. Does it fully address the task?
2. Is the quality acceptable?
3. Are there any errors, omissions, or issues?

If the work PASSES quality review, respond with exactly:
REVIEW: PASS

If the work FAILS, respond with:
REVIEW: FAIL
ISSUES: [describe what needs fixing]
`;
}

function executeClaudeCommand(prompt, model, oauthToken, timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env };
    if (oauthToken) {
      env.CLAUDE_CODE_OAUTH_TOKEN = oauthToken;
    }

    const modelFlag = model === 'opus' ? 'claude-opus-4-6'
      : model === 'haiku' ? 'claude-haiku-4-5-20251001'
      : 'claude-sonnet-4-6';

    const args = ['-p', prompt, '--output-format', 'text', '--model', modelFlag];

    const child = spawn('claude', args, {
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: timeoutMs
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data) => { stdout += data.toString(); });
    child.stderr.on('data', (data) => { stderr += data.toString(); });

    child.on('close', (code) => {
      if (code === 0) {
        resolve(stdout.trim());
      } else {
        reject(new Error(`Claude CLI exited with code ${code}: ${stderr || stdout}`));
      }
    });

    child.on('error', (err) => {
      reject(new Error(`Failed to spawn claude CLI: ${err.message}`));
    });
  });
}

module.exports = { chooseModel, buildTaskPrompt, buildReviewPrompt, executeClaudeCommand };
