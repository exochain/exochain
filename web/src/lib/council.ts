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

/** Council AI — Types, ticket model, and API integration for the
 *  agentic conversational elicitation system.
 *
 *  Every user interaction can produce a CouncilTicket — a tagged,
 *  contextualized card event that flows through council triage,
 *  human presentment, and council-advised implementation planning.
 */

// ---------------------------------------------------------------------------
// Ticket tag taxonomy
// ---------------------------------------------------------------------------

export type TicketTag =
  | 'help'
  | 'feature'
  | 'bug'
  | 'question'
  | 'feedback'
  | 'escalation'
  | 'proposal'
  | 'triage'
  | 'implementation'
  | 'test-plan'
  | 'config'
  | 'security'
  | 'governance'

export type TicketPriority = 'immediate' | 'urgent' | 'standard' | 'deferred' | 'backlog'

export type TicketStatus =
  | 'open'
  | 'council-triage'
  | 'human-review'
  | 'council-advised'
  | 'implementation'
  | 'testing'
  | 'resolved'
  | 'dismissed'

// ---------------------------------------------------------------------------
// Council Ticket
// ---------------------------------------------------------------------------

export interface CouncilTicket {
  id: string
  title: string
  description: string
  tags: TicketTag[]
  priority: TicketPriority
  status: TicketStatus
  sourceModule: string
  sourceWidgetId?: string
  author: string
  assignee?: string
  councilNotes: string[]
  implementationPlan?: ImplementationPlan
  conversationId: string
  createdAt: number
  updatedAt: number
}

export interface ImplementationPlan {
  summary: string
  steps: ImplementationStep[]
  testCriteria: string[]
  estimatedEffort: string
  affectedModules: string[]
  requiresHumanApproval: boolean
}

export interface ImplementationStep {
  order: number
  description: string
  module: string
  type: 'code' | 'config' | 'test' | 'review' | 'deploy'
  completed: boolean
}

// ---------------------------------------------------------------------------
// Conversation model
// ---------------------------------------------------------------------------

export type MessageRole = 'user' | 'council' | 'system'

export interface ConversationMessage {
  id: string
  role: MessageRole
  content: string
  timestamp: number
  ticketRef?: string
  suggestedTags?: TicketTag[]
  suggestedPriority?: TicketPriority
}

export interface Conversation {
  id: string
  moduleContext: string
  widgetId?: string
  messages: ConversationMessage[]
  tickets: string[]
  createdAt: number
  isActive: boolean
}

// ---------------------------------------------------------------------------
// Council response generation (client-side inference)
// ---------------------------------------------------------------------------

const TAG_PATTERNS: Array<{ pattern: RegExp; tags: TicketTag[]; priority: TicketPriority }> = [
  { pattern: /\b(crash|error|broken|fail|exception|bug|wrong|incorrect)\b/i, tags: ['bug'], priority: 'urgent' },
  { pattern: /\b(security|vulnerability|exploit|attack|breach|unauthorized)\b/i, tags: ['security', 'escalation'], priority: 'immediate' },
  { pattern: /\b(help|how\s+do|how\s+to|what\s+is|explain|guide|tutorial)\b/i, tags: ['help', 'question'], priority: 'standard' },
  { pattern: /\b(feature|add|implement|create|build|new|request|wish|want)\b/i, tags: ['feature', 'proposal'], priority: 'standard' },
  { pattern: /\b(feedback|suggest|improve|better|opinion|think)\b/i, tags: ['feedback'], priority: 'deferred' },
  { pattern: /\b(urgent|critical|emergency|immediate|asap|blocking)\b/i, tags: ['escalation', 'triage'], priority: 'immediate' },
  { pattern: /\b(test|testing|tdd|coverage|spec|assert)\b/i, tags: ['test-plan', 'implementation'], priority: 'standard' },
  { pattern: /\b(config|setting|parameter|option|toggle|preference)\b/i, tags: ['config', 'help'], priority: 'deferred' },
  { pattern: /\b(govern|policy|rule|constitution|delegate|authority|vote)\b/i, tags: ['governance', 'proposal'], priority: 'standard' },
]

export function inferTags(text: string): { tags: TicketTag[]; priority: TicketPriority } {
  const matchedTags = new Set<TicketTag>()
  let highestPriority: TicketPriority = 'backlog'

  const priorityRank: Record<TicketPriority, number> = {
    immediate: 0, urgent: 1, standard: 2, deferred: 3, backlog: 4,
  }

  for (const rule of TAG_PATTERNS) {
    if (rule.pattern.test(text)) {
      rule.tags.forEach(t => matchedTags.add(t))
      if (priorityRank[rule.priority] < priorityRank[highestPriority]) {
        highestPriority = rule.priority
      }
    }
  }

  if (matchedTags.size === 0) {
    matchedTags.add('feedback')
    highestPriority = 'deferred'
  }

  return { tags: Array.from(matchedTags), priority: highestPriority }
}

// ---------------------------------------------------------------------------
// Council AI response templates by module context
// ---------------------------------------------------------------------------

const MODULE_PROMPTS: Record<string, string> = {
  metrics: 'I can help you understand governance KPIs, set alert thresholds, configure metric dashboards, or investigate anomalies in your governance data.',
  decisions: 'I can assist with decision lifecycle questions, voting guidance, status transitions, or help you draft new proposals.',
  escalation: 'I monitor adverse events and can help you triage escalations, configure detection rules, adjust severity thresholds, or investigate anomalies.',
  identity: 'I can help with trust score interpretation, PACE enrollment steps, identity verification, or delegation authority questions.',
  audit: 'I can explain audit chain integrity, help investigate gaps, export forensic reports, or configure audit retention policies.',
  delegation: 'I can help with authority chain analysis, delegation scope management, expiry monitoring, or sub-delegation policies.',
  agents: 'I can assist with agent enrollment, capability management, alignment monitoring, or holon lifecycle questions.',
  kernel: 'I can explain CGR Kernel invariants, combinator graph reduction, constitutional constraints, or help diagnose invariant violations.',
  'pace-wizard': 'I can guide you through PACE enrollment — Shamir\'s Secret Sharing key sharding, choosing trustworthy contacts, threshold configuration, and secure share distribution. Ask me anything about key sovereignty.',
  'dev-completeness': 'I can help prioritize development cards, explain implementation requirements, generate TDD plans for gap items, or discuss architectural trade-offs for bringing subsystems to 100%.',
  livesafe: 'LiveSafe.ai integration assistant. I can help with EXOCHAIN identity anchoring, PACE trustee ceremonies, audit chain verification, and the 0dentity scoring system.',
  general: 'I\'m your governance council AI. I can help with any aspect of the platform — decisions, identity, audit, delegations, agents, or constitutional governance.',
}

export function getModuleGreeting(moduleType: string): string {
  const prompt = MODULE_PROMPTS[moduleType] || MODULE_PROMPTS.general
  return `Welcome to the Council AI assistant for this module.\n\n${prompt}\n\nEvery interaction creates a contextualized ticket that flows through council triage. What can I help you with?`
}

export function generateCouncilResponse(
  userMessage: string,
  moduleContext: string,
  conversationHistory: ConversationMessage[],
): ConversationMessage {
  const { tags, priority } = inferTags(userMessage)
  const isFirstMessage = conversationHistory.filter(m => m.role === 'user').length === 0

  let content: string

  if (isFirstMessage) {
    // Acknowledge and classify
    const tagLabels = tags.map(t => `**${t}**`).join(', ')
    content = `I've classified this as: ${tagLabels} (priority: **${priority}**).\n\n`

    if (tags.includes('bug')) {
      content += 'I\'ll create a bug ticket for council triage. Can you provide:\n- Steps to reproduce\n- Expected vs actual behavior\n- Which module/page this affects'
    } else if (tags.includes('feature') || tags.includes('proposal')) {
      content += 'I\'ll draft a proposal ticket. To build a proper implementation plan, I need:\n- What problem does this solve?\n- Who benefits from this change?\n- Any constraints or dependencies?'
    } else if (tags.includes('help') || tags.includes('question')) {
      content += `Let me help you with that. ${MODULE_PROMPTS[moduleContext] || ''}\n\nCould you be more specific about what you need?`
    } else if (tags.includes('security') || tags.includes('escalation')) {
      content += 'This has been flagged for **immediate council triage**. I\'m creating an escalation ticket with high priority. Please provide any additional details about the incident.'
    } else {
      content += 'I\'ve captured your feedback. Would you like me to:\n1. Create a formal proposal for the council\n2. Add this to the backlog for review\n3. Connect you with more specific guidance'
    }
  } else {
    // Follow-up responses
    const lastCouncilMsg = [...conversationHistory].reverse().find(m => m.role === 'council')
    if (lastCouncilMsg?.content.includes('Steps to reproduce')) {
      content = 'Thank you for the details. I\'ve updated the ticket with reproduction steps.\n\n**Council recommendation**: This should be triaged at the next review cycle. I\'ll generate a test-driven implementation plan once the ticket is approved.\n\nAnything else to add?'
    } else if (lastCouncilMsg?.content.includes('implementation plan')) {
      content = 'I\'ll generate a TDD implementation plan with the following structure:\n\n1. **Test criteria** — Define expected behavior\n2. **Affected modules** — Identify code surfaces\n3. **Implementation steps** — Ordered task breakdown\n4. **Human review gate** — Council approval checkpoint\n\nShall I proceed?'
    } else {
      content = `Noted. I've added this context to the ticket.\n\nDetected tags: ${tags.map(t => `\`${t}\``).join(', ')} | Priority: \`${priority}\`\n\nWould you like me to escalate this, or shall I route it to the standard triage queue?`
    }
  }

  return {
    id: `msg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    role: 'council',
    content,
    timestamp: Date.now(),
    suggestedTags: tags,
    suggestedPriority: priority,
  }
}

// ---------------------------------------------------------------------------
// Ticket creation helper
// ---------------------------------------------------------------------------

export function createTicketFromConversation(
  conversation: Conversation,
  title: string,
  tags: TicketTag[],
  priority: TicketPriority,
  author: string,
): CouncilTicket {
  const description = conversation.messages
    .filter(m => m.role === 'user')
    .map(m => m.content)
    .join('\n\n---\n\n')

  const councilNotes = conversation.messages
    .filter(m => m.role === 'council')
    .map(m => m.content)

  return {
    id: `TKT-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    title,
    description,
    tags,
    priority,
    status: priority === 'immediate' ? 'council-triage' : 'open',
    sourceModule: conversation.moduleContext,
    sourceWidgetId: conversation.widgetId,
    author,
    councilNotes,
    conversationId: conversation.id,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  }
}

// ---------------------------------------------------------------------------
// Local persistence
// ---------------------------------------------------------------------------

const TICKETS_KEY = 'df_council_tickets'
const CONVERSATIONS_KEY = 'df_council_conversations'

export function persistTickets(tickets: CouncilTicket[]): void {
  localStorage.setItem(TICKETS_KEY, JSON.stringify(tickets))
}

export function loadTickets(): CouncilTicket[] {
  try {
    const raw = localStorage.getItem(TICKETS_KEY)
    return raw ? JSON.parse(raw) : []
  } catch { return [] }
}

export function persistConversations(conversations: Conversation[]): void {
  localStorage.setItem(CONVERSATIONS_KEY, JSON.stringify(conversations))
}

export function loadConversations(): Conversation[] {
  try {
    const raw = localStorage.getItem(CONVERSATIONS_KEY)
    return raw ? JSON.parse(raw) : []
  } catch { return [] }
}
