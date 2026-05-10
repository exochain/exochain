// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

'use strict';

/**
 * Catapult Bootstrap — Seeds initial tasks for founding agents.
 *
 * When a newco enters the Selection phase, this module creates the
 * inaugural tasks that kick off autonomous agent execution:
 *
 * 1. HR Agent → "Assess and select ODA team members"
 * 2. Deep Researcher → "Produce market intelligence report"
 *
 * These tasks are inserted into the standard tasks table with
 * assignments to the founding agents, making them immediately
 * eligible for the worker's autonomous dispatch pipeline.
 */

/**
 * ODA slot descriptions for the hiring brief.
 */
const HIRING_SLOTS = [
  { slot: 'VentureCommander', title: 'Venture Commander', priority: 'high', description: 'Strategic mission authority — sets commander\'s intent and resource allocation.' },
  { slot: 'OperationsDeputy', title: 'Operations Deputy', priority: 'high', description: 'Operational continuity — day-to-day coordination, PACE alternate.' },
  { slot: 'ProcessArchitect', title: 'Process Architect', priority: 'high', description: 'Workflow orchestration — SOP design, team training, Syntaxis composition.' },
  { slot: 'GrowthEngineer1', title: 'Growth Engineer 1', priority: 'medium', description: 'Revenue generation — acquisition funnels, market attack vectors.' },
  { slot: 'GrowthEngineer2', title: 'Growth Engineer 2', priority: 'medium', description: 'Retention and partnerships — channel development, expansion revenue.' },
  { slot: 'Communications1', title: 'Communications 1', priority: 'medium', description: 'External communications — brand voice, PR, stakeholder messaging.' },
  { slot: 'Communications2', title: 'Communications 2', priority: 'medium', description: 'Internal communications — documentation, community, knowledge base.' },
  { slot: 'HrPeopleOps2', title: 'HR / People Ops 2', priority: 'low', description: 'Culture and performance — training delivery, team wellness.' },
  { slot: 'PlatformEngineer1', title: 'Platform Engineer 1', priority: 'medium', description: 'System architecture — core development, infrastructure, deployment.' },
  { slot: 'PlatformEngineer2', title: 'Platform Engineer 2', priority: 'medium', description: 'Quality and security — testing, CI/CD, hardening, performance.' },
];

/**
 * Seed initial tasks for founding agents when a newco enters Selection phase.
 *
 * @param {object} db - SQLite database handle
 * @param {string} newcoId - Newco UUID
 * @param {string} newcoName - Company name
 * @param {string} businessModel - Business model type
 * @param {Function} broadcast - WebSocket broadcast function
 * @returns {{ hrTaskId: number, researchTaskId: number }}
 */
function seedFoundingTasks(db, newcoId, newcoName, businessModel, broadcast) {
  const shortId = newcoId.substring(0, 8);

  // Find the founding agent member IDs
  const hrMember = db.prepare(
    "SELECT id FROM team_members WHERE name = ? AND status = 'active'"
  ).get(`catapult-${shortId}-hrpeopleops1`);

  const researcherMember = db.prepare(
    "SELECT id FROM team_members WHERE name = ? AND status = 'active'"
  ).get(`catapult-${shortId}-deepresearcher`);

  // Find or create a project for this newco
  let project = db.prepare("SELECT id FROM projects WHERE name = ?").get(`Catapult: ${newcoName}`);
  if (!project) {
    const info = db.prepare(
      "INSERT INTO projects (name, description, status, exochain_governed) VALUES (?, ?, 'active', 1)"
    ).run(`Catapult: ${newcoName}`, `Franchise newco — ${businessModel} — ID: ${newcoId}`);
    project = { id: info.lastInsertRowid };
  }

  // ── Task 1: HR Agent — Assessment & Selection ──────────────────────────

  const hiringBrief = HIRING_SLOTS.map(s =>
    `- **${s.title}** (${s.slot}) [${s.priority}]: ${s.description}`
  ).join('\n');

  const hrTaskInfo = db.prepare(`
    INSERT INTO tasks (title, description, status, priority, project_id)
    VALUES (?, ?, 'open', 'high', ?)
  `).run(
    `[Catapult] Assess and select ODA team for ${newcoName}`,
    `## Mission

You are the founding HR / People Ops agent for **${newcoName}**, a new ${businessModel} company launched via the Catapult franchise incubator.

Your mission is to assess and select the remaining 10 ODA team members. You and the Deep Researcher are the two founding agents — the rest of the team depends on your judgment.

## Hiring Brief

The following ODA slots need to be filled (priority order):

${hiringBrief}

## Process

For each slot:
1. Define the ideal candidate profile based on the slot description and business model
2. Evaluate available agent capabilities against requirements
3. Recommend hire via the \`POST /api/catapult/newco/${newcoId}/hire\` endpoint
4. Document your assessment rationale in a comment

## Constraints
- All hiring decisions produce governance receipts
- Budget-aware: each agent has a monthly budget allocation
- The VentureCommander, OperationsDeputy, and ProcessArchitect must be hired first (Preparation phase requirement)
- Full ODA (12 agents) required before Execution phase

## Newco ID
${newcoId}`,
    project.id
  );

  if (hrMember) {
    db.prepare("INSERT OR IGNORE INTO task_assignments (task_id, member_id) VALUES (?, ?)")
      .run(hrTaskInfo.lastInsertRowid, hrMember.id);
  }

  // ── Task 2: Deep Researcher — Market Intelligence Report ───────────────

  const researchTaskInfo = db.prepare(`
    INSERT INTO tasks (title, description, status, priority, project_id)
    VALUES (?, ?, 'open', 'high', ?)
  `).run(
    `[Catapult] Produce market intelligence report for ${newcoName}`,
    `## Mission

You are the founding Deep Researcher for **${newcoName}**, a new ${businessModel} company launched via the Catapult franchise incubator.

Your mission is to produce a comprehensive market intelligence report that will inform the team's strategy during the Preparation and Execution phases.

## Deliverables

1. **Market Landscape** — Size, growth trajectory, key segments, and trends
2. **Competitive Analysis** — Direct and indirect competitors, their strengths, weaknesses, and positioning
3. **Opportunity Assessment** — Underserved segments, unmet needs, entry points
4. **Threat Assessment** — Regulatory risks, market disruptions, competitive threats
5. **Strategic Recommendations** — Prioritized list of opportunities with risk/reward assessment

## Process

1. Research the ${businessModel} market landscape using available tools
2. Identify and analyze key competitors
3. Synthesize findings into a structured intelligence brief
4. Post the report as a deliverable on this task

## Constraints
- Evidence-based analysis only — cite sources
- Quantitative where possible (market size, growth rates, share)
- Produce the report within the Selection phase timeline
- All findings governance-receipted for provenance

## Newco ID
${newcoId}`,
    project.id
  );

  if (researcherMember) {
    db.prepare("INSERT OR IGNORE INTO task_assignments (task_id, member_id) VALUES (?, ?)")
      .run(researchTaskInfo.lastInsertRowid, researcherMember.id);
  }

  // Broadcast task creation events
  if (broadcast) {
    broadcast('catapult:tasks:seeded', {
      newcoId,
      hrTaskId: hrTaskInfo.lastInsertRowid,
      researchTaskId: researchTaskInfo.lastInsertRowid,
    });
  }

  return {
    hrTaskId: hrTaskInfo.lastInsertRowid,
    researchTaskId: researchTaskInfo.lastInsertRowid,
  };
}

module.exports = {
  seedFoundingTasks,
  HIRING_SLOTS,
};
