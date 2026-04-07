/**
 * github.js — GitHub integration for ExoForge.
 *
 * Uses the `gh` CLI (GitHub CLI) for all GitHub operations.
 * This avoids token management and leverages the user's existing
 * gh authentication context.
 */

import { execFileSync } from 'child_process';

/**
 * Execute a `gh` CLI command and return parsed JSON output.
 *
 * @param {Array} args - Arguments to pass to `gh`
 * @param {object} [opts] - Options: { json: true, maxBuffer }
 * @returns {object|string} Parsed JSON if opts.json, raw string otherwise
 * @throws {Error} If `gh` is not installed or the command fails
 */
function ghExec(args, opts = {}) {
  const { json = true, maxBuffer = 10 * 1024 * 1024 } = opts;
  try {
    const result = execFileSync('gh', args, {
      encoding: 'utf-8',
      maxBuffer,
      timeout: 30000,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    if (json && result.trim()) {
      return JSON.parse(result.trim());
    }
    return result.trim();
  } catch (err) {
    const stderr = err.stderr ? err.stderr.toString().trim() : '';
    throw new Error(`gh command failed: gh ${args.join(' ')}\n${stderr || err.message}`);
  }
}

/**
 * List open issues from a GitHub repository.
 *
 * @param {string} repo - Repository in owner/name format (e.g. 'exochain/exochain')
 * @param {object} [opts] - Options: { limit, labels, state, assignee }
 * @returns {Array} Array of issue objects
 */
export function listIssues(repo, opts = {}) {
  const { limit = 30, labels, state = 'open', assignee } = opts;
  const args = [
    'issue', 'list',
    '--repo', repo,
    '--state', state,
    '--limit', String(limit),
    '--json', 'number,title,body,labels,assignees,state,createdAt,updatedAt,url,author'
  ];
  if (labels) {
    args.push('--label', Array.isArray(labels) ? labels.join(',') : labels);
  }
  if (assignee) {
    args.push('--assignee', assignee);
  }
  return ghExec(args);
}

/**
 * Get a single issue by number.
 *
 * @param {string} repo - Repository in owner/name format
 * @param {number} number - Issue number
 * @returns {object} Issue object with full details
 */
export function getIssue(repo, number) {
  const args = [
    'issue', 'view',
    String(number),
    '--repo', repo,
    '--json', 'number,title,body,labels,assignees,state,createdAt,updatedAt,url,author,comments,milestone'
  ];
  return ghExec(args);
}

/**
 * Create a pull request.
 *
 * @param {string} repo - Repository in owner/name format
 * @param {string} title - PR title
 * @param {string} body - PR body (markdown)
 * @param {string} branch - Source branch name
 * @param {object} [opts] - Options: { base, draft, labels, assignees, reviewers }
 * @returns {object} Created PR object
 */
export function createPR(repo, title, body, branch, opts = {}) {
  const { base = 'main', draft = false, labels, assignees, reviewers } = opts;
  const args = [
    'pr', 'create',
    '--repo', repo,
    '--title', title,
    '--body', body,
    '--head', branch,
    '--base', base
  ];
  if (draft) args.push('--draft');
  if (labels) {
    const labelStr = Array.isArray(labels) ? labels.join(',') : labels;
    args.push('--label', labelStr);
  }
  if (assignees) {
    const assigneeStr = Array.isArray(assignees) ? assignees.join(',') : assignees;
    args.push('--assignee', assigneeStr);
  }
  if (reviewers) {
    const reviewerStr = Array.isArray(reviewers) ? reviewers.join(',') : reviewers;
    args.push('--reviewer', reviewerStr);
  }
  return ghExec(args, { json: false });
}

/**
 * Add labels to an issue or pull request.
 *
 * @param {string} repo - Repository in owner/name format
 * @param {number} number - Issue or PR number
 * @param {Array<string>} labels - Labels to add
 * @returns {string} Command output
 */
export function addLabels(repo, number, labels) {
  const args = [
    'issue', 'edit',
    String(number),
    '--repo', repo,
    '--add-label', labels.join(',')
  ];
  return ghExec(args, { json: false });
}

/**
 * Remove labels from an issue or pull request.
 *
 * @param {string} repo - Repository in owner/name format
 * @param {number} number - Issue or PR number
 * @param {Array<string>} labels - Labels to remove
 * @returns {string} Command output
 */
export function removeLabels(repo, number, labels) {
  const args = [
    'issue', 'edit',
    String(number),
    '--repo', repo,
    '--remove-label', labels.join(',')
  ];
  return ghExec(args, { json: false });
}

/**
 * List pull requests from a repository.
 *
 * @param {string} repo - Repository in owner/name format
 * @param {object} [opts] - Options: { limit, state, base, head }
 * @returns {Array} Array of PR objects
 */
export function listPRs(repo, opts = {}) {
  const { limit = 30, state = 'open', base, head } = opts;
  const args = [
    'pr', 'list',
    '--repo', repo,
    '--state', state,
    '--limit', String(limit),
    '--json', 'number,title,body,labels,state,createdAt,url,author,headRefName,baseRefName,isDraft'
  ];
  if (base) args.push('--base', base);
  if (head) args.push('--head', head);
  return ghExec(args);
}

/**
 * Add a comment to an issue or PR.
 *
 * @param {string} repo - Repository in owner/name format
 * @param {number} number - Issue or PR number
 * @param {string} body - Comment body (markdown)
 * @returns {string} Command output
 */
export function addComment(repo, number, body) {
  const args = [
    'issue', 'comment',
    String(number),
    '--repo', repo,
    '--body', body
  ];
  return ghExec(args, { json: false });
}
