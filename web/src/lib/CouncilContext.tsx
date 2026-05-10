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

/** CouncilContext — Global state for the AI Council system.
 *
 *  Provides ticket management, conversation tracking, and panel
 *  visibility across all modules and widgets.
 */

import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'
import {
  type CouncilTicket, type Conversation, type ConversationMessage, type TicketTag, type TicketPriority,
  loadTickets, persistTickets, loadConversations, persistConversations,
  createTicketFromConversation, generateCouncilResponse, getModuleGreeting,
  inferTags,
} from './council'

interface CouncilContextType {
  // Panel state
  isPanelOpen: boolean
  openPanel: (moduleContext?: string, widgetId?: string) => void
  closePanel: () => void
  togglePanel: () => void

  // Active conversation
  activeConversation: Conversation | null
  activeModuleContext: string

  // Conversation actions
  sendMessage: (content: string) => void
  startConversation: (moduleContext: string, widgetId?: string) => void

  // Tickets
  tickets: CouncilTicket[]
  createTicket: (title: string, tags?: TicketTag[], priority?: TicketPriority) => CouncilTicket | null
  updateTicketStatus: (ticketId: string, status: CouncilTicket['status']) => void
  ticketCount: number
  openTicketCount: number

  // Conversations
  conversations: Conversation[]
}

const CouncilCtx = createContext<CouncilContextType | null>(null)

export function useCouncil(): CouncilContextType {
  const ctx = useContext(CouncilCtx)
  if (!ctx) throw new Error('useCouncil must be used within CouncilProvider')
  return ctx
}

export function CouncilProvider({ children, userName }: { children: ReactNode; userName?: string }) {
  const [isPanelOpen, setIsPanelOpen] = useState(false)
  const [activeModuleContext, setActiveModuleContext] = useState('general')
  const [activeConversation, setActiveConversation] = useState<Conversation | null>(null)
  const [conversations, setConversations] = useState<Conversation[]>(() => loadConversations())
  const [tickets, setTickets] = useState<CouncilTicket[]>(() => loadTickets())

  const startConversation = useCallback((moduleContext: string, widgetId?: string) => {
    const greeting: ConversationMessage = {
      id: `msg-${Date.now()}-greeting`,
      role: 'council',
      content: getModuleGreeting(moduleContext),
      timestamp: Date.now(),
    }

    const conv: Conversation = {
      id: `conv-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      moduleContext,
      widgetId,
      messages: [greeting],
      tickets: [],
      createdAt: Date.now(),
      isActive: true,
    }

    setActiveConversation(conv)
    setActiveModuleContext(moduleContext)
    setConversations(prev => {
      const next = [...prev, conv]
      persistConversations(next)
      return next
    })
  }, [])

  const openPanel = useCallback((moduleContext?: string, widgetId?: string) => {
    const ctx = moduleContext || 'general'
    setActiveModuleContext(ctx)
    setIsPanelOpen(true)

    // Start a new conversation if none active or module changed
    if (!activeConversation || activeConversation.moduleContext !== ctx) {
      startConversation(ctx, widgetId)
    }
  }, [activeConversation, startConversation])

  const closePanel = useCallback(() => setIsPanelOpen(false), [])
  const togglePanel = useCallback(() => {
    setIsPanelOpen(prev => {
      if (!prev && !activeConversation) {
        startConversation('general')
      }
      return !prev
    })
  }, [activeConversation, startConversation])

  const sendMessage = useCallback((content: string) => {
    if (!activeConversation) return

    const userMsg: ConversationMessage = {
      id: `msg-${Date.now()}-user`,
      role: 'user',
      content,
      timestamp: Date.now(),
    }

    // Generate council response
    const councilMsg = generateCouncilResponse(
      content,
      activeConversation.moduleContext,
      activeConversation.messages,
    )

    const updatedConv: Conversation = {
      ...activeConversation,
      messages: [...activeConversation.messages, userMsg, councilMsg],
    }

    setActiveConversation(updatedConv)
    setConversations(prev => {
      const next = prev.map(c => c.id === updatedConv.id ? updatedConv : c)
      persistConversations(next)
      return next
    })
  }, [activeConversation])

  const createTicket = useCallback((title: string, tags?: TicketTag[], priority?: TicketPriority): CouncilTicket | null => {
    if (!activeConversation) return null

    // Infer tags from conversation if not provided
    const allUserText = activeConversation.messages
      .filter(m => m.role === 'user')
      .map(m => m.content)
      .join(' ')
    const inferred = inferTags(allUserText)

    const ticket = createTicketFromConversation(
      activeConversation,
      title,
      tags || inferred.tags,
      priority || inferred.priority,
      userName || 'anonymous',
    )

    setTickets(prev => {
      const next = [...prev, ticket]
      persistTickets(next)
      return next
    })

    // Link ticket to conversation
    const updatedConv: Conversation = {
      ...activeConversation,
      tickets: [...activeConversation.tickets, ticket.id],
    }
    setActiveConversation(updatedConv)
    setConversations(prev => {
      const next = prev.map(c => c.id === updatedConv.id ? updatedConv : c)
      persistConversations(next)
      return next
    })

    // Add system message about ticket creation
    const sysMsg: ConversationMessage = {
      id: `msg-${Date.now()}-sys`,
      role: 'system',
      content: `Ticket **${ticket.id}** created: "${title}" [${ticket.tags.join(', ')}] — Status: ${ticket.status}`,
      timestamp: Date.now(),
      ticketRef: ticket.id,
    }
    const convWithSys: Conversation = {
      ...updatedConv,
      messages: [...updatedConv.messages, sysMsg],
    }
    setActiveConversation(convWithSys)
    setConversations(prev => {
      const next = prev.map(c => c.id === convWithSys.id ? convWithSys : c)
      persistConversations(next)
      return next
    })

    return ticket
  }, [activeConversation, userName])

  const updateTicketStatus = useCallback((ticketId: string, status: CouncilTicket['status']) => {
    setTickets(prev => {
      const next = prev.map(t => t.id === ticketId ? { ...t, status, updatedAt: Date.now() } : t)
      persistTickets(next)
      return next
    })
  }, [])

  const openTicketCount = tickets.filter(t =>
    !['resolved', 'dismissed'].includes(t.status)
  ).length

  return (
    <CouncilCtx.Provider value={{
      isPanelOpen,
      openPanel,
      closePanel,
      togglePanel,
      activeConversation,
      activeModuleContext,
      sendMessage,
      startConversation,
      tickets,
      createTicket,
      updateTicketStatus,
      ticketCount: tickets.length,
      openTicketCount,
      conversations,
    }}>
      {children}
    </CouncilCtx.Provider>
  )
}
