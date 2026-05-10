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

import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  inferTags,
  generateCouncilResponse,
  createTicketFromConversation,
  getModuleGreeting,
  persistTickets,
  loadTickets,
  persistConversations,
  loadConversations,
  type TicketTag,
  type TicketPriority,
  type CouncilTicket,
  type Conversation,
  type ConversationMessage,
} from './council'

describe('council.ts — Council AI and ticket system', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
  })

  // ─────────────────────────────────────────────────────────────
  // inferTags tests
  // ─────────────────────────────────────────────────────────────

  describe('inferTags', () => {
    describe('bug pattern matching', () => {
      it('detects bug from crash keyword', () => {
        const result = inferTags('The app had a crash when I clicked save')
        expect(result.tags).toContain('bug')
        expect(result.priority).toBe('urgent')
      })

      it('detects bug from error keyword', () => {
        const result = inferTags('I got an error message')
        expect(result.tags).toContain('bug')
      })

      it('detects bug from broken keyword', () => {
        const result = inferTags('This feature is completely broken')
        expect(result.tags).toContain('bug')
      })

      it('detects bug from incorrect keyword', () => {
        const result = inferTags('The calculation is incorrect')
        expect(result.tags).toContain('bug')
      })
    })

    describe('security pattern matching', () => {
      it('detects security from vulnerability keyword', () => {
        const result = inferTags('There is a vulnerability in the login system')
        expect(result.tags).toContain('security')
        expect(result.tags).toContain('escalation')
        expect(result.priority).toBe('immediate')
      })

      it('detects security from exploit keyword', () => {
        const result = inferTags('This exploit could be used by malicious users')
        expect(result.tags).toContain('security')
        expect(result.tags).toContain('escalation')
        expect(result.priority).toBe('immediate')
      })

      it('detects security from breach keyword', () => {
        const result = inferTags('Data breach detected in the system')
        expect(result.tags).toContain('security')
      })
    })

    describe('help/question pattern matching', () => {
      it('detects help from how do keyword', () => {
        const result = inferTags('How do I create a new decision?')
        expect(result.tags).toContain('help')
        expect(result.tags).toContain('question')
        expect(result.priority).toBe('standard')
      })

      it('detects help from explain keyword', () => {
        const result = inferTags('Can you explain the voting process?')
        expect(result.tags).toContain('help')
      })

      it('detects help from guide keyword', () => {
        const result = inferTags('I need a guide on delegation')
        expect(result.tags).toContain('help')
      })
    })

    describe('feature/proposal pattern matching', () => {
      it('detects feature from feature keyword', () => {
        const result = inferTags('I want a new feature for notifications')
        expect(result.tags).toContain('feature')
        expect(result.tags).toContain('proposal')
        expect(result.priority).toBe('standard')
      })

      it('detects feature from add keyword', () => {
        const result = inferTags('We should add a dark mode')
        expect(result.tags).toContain('feature')
      })

      it('detects feature from implement keyword', () => {
        const result = inferTags('Can we implement better filtering?')
        expect(result.tags).toContain('feature')
      })

      it('detects feature from request keyword', () => {
        const result = inferTags('Feature request: export to PDF')
        expect(result.tags).toContain('feature')
      })
    })

    describe('feedback pattern matching', () => {
      it('detects feedback from feedback keyword', () => {
        const result = inferTags('I have feedback about the UI')
        expect(result.tags).toContain('feedback')
        expect(result.priority).toBe('deferred')
      })

      it('detects feedback from suggest keyword', () => {
        const result = inferTags('I suggest we improve the layout')
        expect(result.tags).toContain('feedback')
      })

      it('detects feedback from opinion keyword', () => {
        const result = inferTags('In my opinion, the color scheme could be better')
        expect(result.tags).toContain('feedback')
      })
    })

    describe('escalation pattern matching', () => {
      it('detects escalation from urgent keyword', () => {
        const result = inferTags('This is urgent!')
        expect(result.tags).toContain('escalation')
        expect(result.tags).toContain('triage')
        expect(result.priority).toBe('immediate')
      })

      it('detects escalation from critical keyword', () => {
        const result = inferTags('Critical issue needs attention')
        expect(result.tags).toContain('escalation')
        expect(result.priority).toBe('immediate')
      })

      it('detects escalation from blocking keyword', () => {
        const result = inferTags('This is blocking our production deployment')
        expect(result.tags).toContain('escalation')
      })
    })

    describe('test-plan pattern matching', () => {
      it('detects test-plan from testing keyword', () => {
        const result = inferTags('We need testing for this feature')
        expect(result.tags).toContain('test-plan')
        expect(result.tags).toContain('implementation')
        expect(result.priority).toBe('standard')
      })

      it('detects test-plan from tdd keyword', () => {
        const result = inferTags('Let us follow TDD approach')
        expect(result.tags).toContain('test-plan')
      })

      it('detects test-plan from coverage keyword', () => {
        const result = inferTags('What is the test coverage?')
        expect(result.tags).toContain('test-plan')
      })
    })

    describe('config pattern matching', () => {
      it('detects config from config keyword', () => {
        const result = inferTags('I need to update the config for this module')
        expect(result.tags).toContain('config')
        expect(result.tags).toContain('help')
        expect(result.priority).toBe('deferred')
      })

      it('detects config from setting keyword', () => {
        const result = inferTags('Where is the setting for notifications?')
        expect(result.tags).toContain('config')
        expect(result.tags).toContain('help')
        expect(result.priority).toBe('deferred')
      })

      it('detects config from toggle keyword', () => {
        const result = inferTags('I can toggle this option')
        expect(result.tags).toContain('config')
      })
    })

    describe('governance pattern matching', () => {
      it('detects governance from govern keyword', () => {
        const result = inferTags('How should we govern this decision?')
        expect(result.tags).toContain('governance')
        expect(result.tags).toContain('proposal')
        expect(result.priority).toBe('standard')
      })

      it('detects governance from policy keyword', () => {
        const result = inferTags('We need a new policy on voting')
        expect(result.tags).toContain('governance')
      })

      it('detects governance from delegate keyword', () => {
        const result = inferTags('Can I delegate authority to another person?')
        expect(result.tags).toContain('governance')
      })

      it('detects governance from vote keyword', () => {
        const result = inferTags('How do I vote on this proposal?')
        expect(result.tags).toContain('governance')
      })
    })

    describe('priority ranking', () => {
      it('immediate has highest priority', () => {
        const result = inferTags('urgent bug with security vulnerability')
        expect(result.priority).toBe('immediate')
      })

      it('urgent has higher priority than standard', () => {
        const result = inferTags('I found a bug')
        expect(result.priority).toBe('urgent')
      })

      it('defaults to deferred for generic feedback', () => {
        const result = inferTags('Random thought about the system')
        expect(result.priority).toBe('deferred')
      })

      it('multiple patterns use highest priority', () => {
        const result = inferTags('urgent security bug needs immediate testing')
        expect(result.priority).toBe('immediate')
      })
    })

    describe('edge cases', () => {
      it('handles empty string', () => {
        const result = inferTags('')
        expect(result.tags).toContain('feedback')
        expect(result.priority).toBe('deferred')
      })

      it('handles case-insensitive matching', () => {
        const result = inferTags('BUG: CRASH ERROR')
        expect(result.tags).toContain('bug')
      })

      it('handles multiple matching patterns', () => {
        const result = inferTags('There is a critical bug in the security system')
        expect(result.tags.length).toBeGreaterThan(1)
        expect(result.tags).toContain('bug')
        expect(result.tags).toContain('security')
        expect(result.priority).toBe('immediate')
      })

      it('deduplicates tags', () => {
        const result = inferTags('bug bug bug test test test')
        expect(result.tags.filter(t => t === 'bug').length).toBe(1)
      })
    })
  })

  // ─────────────────────────────────────────────────────────────
  // generateCouncilResponse tests
  // ─────────────────────────────────────────────────────────────

  describe('generateCouncilResponse', () => {
    it('generates response for first message with bug tags', () => {
      const response = generateCouncilResponse(
        'There is a bug when I save',
        'decisions',
        []
      )
      expect(response.role).toBe('council')
      expect(response.content).toContain('I\'ve classified')
      expect(response.suggestedTags).toContain('bug')
      expect(response.suggestedPriority).toBe('urgent')
    })

    it('generates response for first message with feature tags', () => {
      const response = generateCouncilResponse(
        'Can we add dark mode?',
        'metrics',
        []
      )
      expect(response.content).toContain('proposal')
      expect(response.suggestedTags).toContain('feature')
    })

    it('generates response for first message with help tags', () => {
      const response = generateCouncilResponse(
        'How do I create a decision?',
        'decisions',
        []
      )
      expect(response.content).toContain('help')
      expect(response.suggestedTags).toContain('help')
    })

    it('generates response for first message with security tags', () => {
      const response = generateCouncilResponse(
        'There is a vulnerability',
        'kernel',
        []
      )
      expect(response.content).toContain('immediate')
      expect(response.suggestedTags).toContain('security')
    })

    it('generates follow-up response after bug details', () => {
      const history: ConversationMessage[] = [
        {
          id: '1',
          role: 'user',
          content: 'App crashes',
          timestamp: Date.now(),
        },
        {
          id: '2',
          role: 'council',
          content: 'Steps to reproduce: ...',
          timestamp: Date.now(),
        },
      ]
      const response = generateCouncilResponse(
        'It happens when I click save',
        'decisions',
        history
      )
      expect(response.role).toBe('council')
      expect(response.content).toContain('details')
    })

    it('includes timestamp in response', () => {
      const before = Date.now()
      const response = generateCouncilResponse('test message', 'decisions', [])
      const after = Date.now()
      expect(response.timestamp).toBeGreaterThanOrEqual(before)
      expect(response.timestamp).toBeLessThanOrEqual(after)
    })

    it('generates unique message IDs', () => {
      const response1 = generateCouncilResponse('msg1', 'decisions', [])
      const response2 = generateCouncilResponse('msg2', 'decisions', [])
      expect(response1.id).not.toBe(response2.id)
    })

    it('includes module context in help response', () => {
      const response = generateCouncilResponse(
        'How can I help?',
        'identity',
        []
      )
      expect(response.content).toContain('trust')
    })
  })

  // ─────────────────────────────────────────────────────────────
  // createTicketFromConversation tests
  // ─────────────────────────────────────────────────────────────

  describe('createTicketFromConversation', () => {
    let conversation: Conversation

    beforeEach(() => {
      conversation = {
        id: 'conv-123',
        moduleContext: 'decisions',
        widgetId: 'widget-456',
        messages: [
          {
            id: 'msg-1',
            role: 'user',
            content: 'First user message',
            timestamp: Date.now(),
          },
          {
            id: 'msg-2',
            role: 'council',
            content: 'First council response',
            timestamp: Date.now(),
          },
          {
            id: 'msg-3',
            role: 'user',
            content: 'Second user message',
            timestamp: Date.now(),
          },
        ],
        tickets: [],
        createdAt: Date.now(),
        isActive: true,
      }
    })

    it('creates ticket with correct title', () => {
      const ticket = createTicketFromConversation(
        conversation,
        'Test Ticket',
        ['bug'],
        'urgent',
        'user123'
      )
      expect(ticket.title).toBe('Test Ticket')
    })

    it('includes all user messages in description', () => {
      const ticket = createTicketFromConversation(
        conversation,
        'Test',
        ['bug'],
        'standard',
        'user123'
      )
      expect(ticket.description).toContain('First user message')
      expect(ticket.description).toContain('Second user message')
    })

    it('excludes council messages from description', () => {
      const ticket = createTicketFromConversation(
        conversation,
        'Test',
        ['bug'],
        'standard',
        'user123'
      )
      expect(ticket.description).not.toContain('First council response')
    })

    it('includes all council notes', () => {
      const ticket = createTicketFromConversation(
        conversation,
        'Test',
        ['bug'],
        'standard',
        'user123'
      )
      expect(ticket.councilNotes).toContain('First council response')
    })

    it('sets status to council-triage for immediate priority', () => {
      const ticket = createTicketFromConversation(
        conversation,
        'Test',
        ['security'],
        'immediate',
        'user123'
      )
      expect(ticket.status).toBe('council-triage')
    })

    it('sets status to open for non-immediate priority', () => {
      const ticket = createTicketFromConversation(
        conversation,
        'Test',
        ['bug'],
        'standard',
        'user123'
      )
      expect(ticket.status).toBe('open')
    })

    it('copies all provided tags', () => {
      const tags: TicketTag[] = ['bug', 'security', 'escalation']
      const ticket = createTicketFromConversation(
        conversation,
        'Test',
        tags,
        'urgent',
        'user123'
      )
      expect(ticket.tags).toEqual(tags)
    })

    it('includes source module and widget info', () => {
      const ticket = createTicketFromConversation(
        conversation,
        'Test',
        ['bug'],
        'standard',
        'user123'
      )
      expect(ticket.sourceModule).toBe('decisions')
      expect(ticket.sourceWidgetId).toBe('widget-456')
    })

    it('sets author correctly', () => {
      const ticket = createTicketFromConversation(
        conversation,
        'Test',
        ['bug'],
        'standard',
        'author-789'
      )
      expect(ticket.author).toBe('author-789')
    })

    it('links to conversation ID', () => {
      const ticket = createTicketFromConversation(
        conversation,
        'Test',
        ['bug'],
        'standard',
        'user123'
      )
      expect(ticket.conversationId).toBe('conv-123')
    })

    it('generates unique ticket IDs', () => {
      const ticket1 = createTicketFromConversation(
        conversation,
        'Test 1',
        ['bug'],
        'standard',
        'user123'
      )
      const ticket2 = createTicketFromConversation(
        conversation,
        'Test 2',
        ['bug'],
        'standard',
        'user123'
      )
      expect(ticket1.id).not.toBe(ticket2.id)
    })

    it('handles empty conversation messages', () => {
      const emptyConv: Conversation = {
        id: 'conv-empty',
        moduleContext: 'decisions',
        messages: [],
        tickets: [],
        createdAt: Date.now(),
        isActive: false,
      }
      const ticket = createTicketFromConversation(
        emptyConv,
        'Empty Ticket',
        ['feedback'],
        'deferred',
        'user123'
      )
      expect(ticket.description).toBe('')
      expect(ticket.councilNotes).toHaveLength(0)
    })
  })

  // ─────────────────────────────────────────────────────────────
  // getModuleGreeting tests
  // ─────────────────────────────────────────────────────────────

  describe('getModuleGreeting', () => {
    it('returns metrics greeting for metrics module', () => {
      const greeting = getModuleGreeting('metrics')
      expect(greeting).toContain('KPIs')
      expect(greeting).toContain('metric')
    })

    it('returns decisions greeting for decisions module', () => {
      const greeting = getModuleGreeting('decisions')
      expect(greeting).toContain('decision')
      expect(greeting).toContain('voting')
    })

    it('returns escalation greeting for escalation module', () => {
      const greeting = getModuleGreeting('escalation')
      expect(greeting).toContain('escalation')
      expect(greeting).toContain('triage')
    })

    it('returns identity greeting for identity module', () => {
      const greeting = getModuleGreeting('identity')
      expect(greeting).toContain('trust')
      expect(greeting).toContain('identity')
    })

    it('returns audit greeting for audit module', () => {
      const greeting = getModuleGreeting('audit')
      expect(greeting).toContain('audit')
      expect(greeting).toContain('integrity')
    })

    it('returns delegation greeting for delegation module', () => {
      const greeting = getModuleGreeting('delegation')
      expect(greeting).toContain('delegation')
      expect(greeting).toContain('authority')
    })

    it('returns agents greeting for agents module', () => {
      const greeting = getModuleGreeting('agents')
      expect(greeting).toContain('agent')
      expect(greeting).toContain('enrollment')
    })

    it('returns kernel greeting for kernel module', () => {
      const greeting = getModuleGreeting('kernel')
      expect(greeting).toContain('Kernel')
      expect(greeting).toContain('invariant')
    })

    it('returns pace-wizard greeting for pace-wizard module', () => {
      const greeting = getModuleGreeting('pace-wizard')
      expect(greeting).toContain('PACE')
      expect(greeting).toContain('enrollment')
    })

    it('returns dev-completeness greeting for dev-completeness module', () => {
      const greeting = getModuleGreeting('dev-completeness')
      expect(greeting).toContain('development cards')
      expect(greeting).toContain('TDD')
    })

    it('returns livesafe greeting for livesafe module', () => {
      const greeting = getModuleGreeting('livesafe')
      expect(greeting).toContain('LiveSafe')
      expect(greeting).toContain('EXOCHAIN')
    })

    it('returns general greeting for unknown module', () => {
      const greeting = getModuleGreeting('unknown-module')
      expect(greeting).toContain('Council AI')
      expect(greeting).toContain('platform')
    })

    it('always includes footer text', () => {
      const greeting = getModuleGreeting('decisions')
      expect(greeting).toContain('ticket')
      expect(greeting).toContain('triage')
    })
  })

  // ─────────────────────────────────────────────────────────────
  // Persistence tests
  // ─────────────────────────────────────────────────────────────

  describe('persistTickets and loadTickets', () => {
    it('persists tickets to localStorage', () => {
      const tickets: CouncilTicket[] = [
        {
          id: 'tkt-1',
          title: 'Test Ticket',
          description: 'Test description',
          tags: ['bug'],
          priority: 'urgent',
          status: 'open',
          sourceModule: 'decisions',
          author: 'user1',
          councilNotes: [],
          conversationId: 'conv-1',
          createdAt: Date.now(),
          updatedAt: Date.now(),
        },
      ]
      persistTickets(tickets)
      const loaded = loadTickets()
      expect(loaded).toHaveLength(1)
      expect(loaded[0].id).toBe('tkt-1')
    })

    it('loads empty array when no tickets persisted', () => {
      const loaded = loadTickets()
      expect(loaded).toEqual([])
    })

    it('overwrites previous tickets', () => {
      const tickets1: CouncilTicket[] = [
        {
          id: 'tkt-1',
          title: 'First',
          description: '',
          tags: [],
          priority: 'standard',
          status: 'open',
          sourceModule: 'decisions',
          author: 'user1',
          councilNotes: [],
          conversationId: 'conv-1',
          createdAt: Date.now(),
          updatedAt: Date.now(),
        },
      ]
      persistTickets(tickets1)
      const tickets2: CouncilTicket[] = [
        {
          id: 'tkt-2',
          title: 'Second',
          description: '',
          tags: [],
          priority: 'standard',
          status: 'open',
          sourceModule: 'decisions',
          author: 'user2',
          councilNotes: [],
          conversationId: 'conv-2',
          createdAt: Date.now(),
          updatedAt: Date.now(),
        },
      ]
      persistTickets(tickets2)
      const loaded = loadTickets()
      expect(loaded).toHaveLength(1)
      expect(loaded[0].id).toBe('tkt-2')
    })

    it('handles corrupted localStorage gracefully', () => {
      localStorage.setItem('df_council_tickets', 'not valid json')
      const loaded = loadTickets()
      expect(loaded).toEqual([])
    })
  })

  describe('persistConversations and loadConversations', () => {
    it('persists conversations to localStorage', () => {
      const conversations: Conversation[] = [
        {
          id: 'conv-1',
          moduleContext: 'decisions',
          messages: [],
          tickets: [],
          createdAt: Date.now(),
          isActive: true,
        },
      ]
      persistConversations(conversations)
      const loaded = loadConversations()
      expect(loaded).toHaveLength(1)
      expect(loaded[0].id).toBe('conv-1')
    })

    it('loads empty array when no conversations persisted', () => {
      const loaded = loadConversations()
      expect(loaded).toEqual([])
    })

    it('overwrites previous conversations', () => {
      const convs1: Conversation[] = [
        {
          id: 'conv-1',
          moduleContext: 'decisions',
          messages: [],
          tickets: [],
          createdAt: Date.now(),
          isActive: true,
        },
      ]
      persistConversations(convs1)
      const convs2: Conversation[] = [
        {
          id: 'conv-2',
          moduleContext: 'metrics',
          messages: [],
          tickets: [],
          createdAt: Date.now(),
          isActive: false,
        },
      ]
      persistConversations(convs2)
      const loaded = loadConversations()
      expect(loaded).toHaveLength(1)
      expect(loaded[0].id).toBe('conv-2')
    })

    it('handles corrupted localStorage gracefully', () => {
      localStorage.setItem('df_council_conversations', 'invalid json xyz')
      const loaded = loadConversations()
      expect(loaded).toEqual([])
    })
  })
})
