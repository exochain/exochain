/** CouncilAIPanel — Slide-out conversational AI panel.
 *
 *  The council assistant that transforms every interaction into
 *  ticketed, tagged, contextualized governance events. Accessible
 *  from the header menu, every widget, and the keyboard shortcut.
 */

import { useState, useRef, useEffect, useCallback } from 'react'
import { useCouncil } from '../lib/CouncilContext'
import { cn, escapeHtml } from '../lib/utils'
import type { TicketTag, TicketPriority, ConversationMessage } from '../lib/council'

// ---------------------------------------------------------------------------
// Tag & priority display helpers
// ---------------------------------------------------------------------------

const TAG_COLORS: Record<TicketTag, string> = {
  help: 'bg-blue-100 text-blue-700',
  feature: 'bg-purple-100 text-purple-700',
  bug: 'bg-red-100 text-red-700',
  question: 'bg-cyan-100 text-cyan-700',
  feedback: 'bg-slate-100 text-slate-600',
  escalation: 'bg-orange-100 text-orange-700',
  proposal: 'bg-violet-100 text-violet-700',
  triage: 'bg-amber-100 text-amber-700',
  implementation: 'bg-emerald-100 text-emerald-700',
  'test-plan': 'bg-green-100 text-green-700',
  config: 'bg-gray-100 text-gray-600',
  security: 'bg-red-200 text-red-800',
  governance: 'bg-indigo-100 text-indigo-700',
}

const PRIORITY_COLORS: Record<TicketPriority, string> = {
  immediate: 'bg-red-500 text-white',
  urgent: 'bg-orange-500 text-white',
  standard: 'bg-blue-500 text-white',
  deferred: 'bg-slate-400 text-white',
  backlog: 'bg-slate-300 text-slate-700',
}

// ---------------------------------------------------------------------------
// Message bubble
// ---------------------------------------------------------------------------

function MessageBubble({ message }: { message: ConversationMessage }) {
  const isUser = message.role === 'user'
  const isSystem = message.role === 'system'

  if (isSystem) {
    return (
      <div className="flex justify-center my-2">
        <div className="px-3 py-1.5 rounded-full bg-[var(--accent-muted)] text-2xs text-[var(--accent-primary)] font-medium max-w-[90%] text-center">
          {message.content.replace(/\*\*/g, '')}
        </div>
      </div>
    )
  }

  return (
    <div className={cn('flex mb-3', isUser ? 'justify-end' : 'justify-start')}>
      <div className={cn(
        'max-w-[85%] rounded-xl px-3 py-2 text-sm',
        isUser
          ? 'bg-[var(--accent-primary)] text-white rounded-br-sm'
          : 'bg-[var(--surface-overlay)] text-[var(--text-primary)] rounded-bl-sm border border-[var(--border-subtle)]',
      )}>
        {/* Council avatar */}
        {!isUser && (
          <div className="flex items-center gap-1.5 mb-1.5">
            <div className="w-5 h-5 rounded-full bg-gradient-to-br from-violet-500 to-blue-500 flex items-center justify-center">
              <svg className="w-3 h-3 text-white" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
              </svg>
            </div>
            <span className="text-2xs font-semibold text-[var(--text-secondary)]">Council AI</span>
          </div>
        )}

        {/* Render markdown-lite content.
            A-030: HTML-escape the raw line FIRST so any untrusted characters
            in message.content render as literal text, then apply the bold /
            code regex replacements that insert the only real HTML tags we
            want. Previously, backend-provided markdown could include raw
            <script>/<img onerror=...> that flowed straight into
            dangerouslySetInnerHTML. */}
        <div className="whitespace-pre-wrap leading-relaxed">
          {message.content.split('\n').map((line, i) => {
            const escaped = escapeHtml(line)
            const withBold = escaped.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            const withCode = withBold.replace(/`(.+?)`/g, '<code class="px-1 py-0.5 rounded bg-black/10 text-xs font-mono">$1</code>')
            return <p key={i} className={cn(line === '' && 'h-2')} dangerouslySetInnerHTML={{ __html: withCode }} />
          })}
        </div>

        {/* Suggested tags */}
        {message.suggestedTags && message.suggestedTags.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2 pt-2 border-t border-white/20">
            {message.suggestedTags.map(tag => (
              <span key={tag} className={cn('rounded-full px-1.5 py-0.5 text-2xs font-medium', TAG_COLORS[tag])}>
                {tag}
              </span>
            ))}
            {message.suggestedPriority && (
              <span className={cn('rounded-full px-1.5 py-0.5 text-2xs font-bold', PRIORITY_COLORS[message.suggestedPriority])}>
                {message.suggestedPriority}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Ticket list mini-view
// ---------------------------------------------------------------------------

function TicketList() {
  const { tickets } = useCouncil()
  const [showAll, setShowAll] = useState(false)

  const visible = showAll ? tickets : tickets.slice(-5)

  if (tickets.length === 0) {
    return (
      <div className="text-center text-xs text-[var(--text-muted)] py-4">
        No tickets yet. Start a conversation to create tickets.
      </div>
    )
  }

  return (
    <div className="space-y-1.5">
      {!showAll && tickets.length > 5 && (
        <button
          onClick={() => setShowAll(true)}
          className="text-2xs text-[var(--accent-primary)] hover:underline w-full text-center"
        >
          Show all {tickets.length} tickets
        </button>
      )}
      {visible.map(ticket => (
        <div key={ticket.id} className="flex items-start gap-2 p-2 rounded-lg bg-[var(--surface-overlay)] border border-[var(--border-subtle)]">
          <span className={cn(
            'w-2 h-2 rounded-full mt-1.5 flex-shrink-0',
            ticket.priority === 'immediate' ? 'bg-red-500' :
            ticket.priority === 'urgent' ? 'bg-orange-500' :
            ticket.priority === 'standard' ? 'bg-blue-500' : 'bg-slate-400',
          )} />
          <div className="min-w-0 flex-1">
            <div className="text-xs font-medium text-[var(--text-primary)] leading-tight truncate">{ticket.title}</div>
            <div className="flex items-center gap-1 mt-0.5 flex-wrap">
              <span className="text-2xs text-[var(--text-muted)] font-mono">{ticket.id.slice(0, 16)}</span>
              <span className="text-2xs text-[var(--text-muted)]">{ticket.status}</span>
            </div>
            <div className="flex gap-1 mt-1 flex-wrap">
              {ticket.tags.slice(0, 3).map(tag => (
                <span key={tag} className={cn('rounded-full px-1.5 py-0 text-2xs', TAG_COLORS[tag])}>
                  {tag}
                </span>
              ))}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// CouncilAIPanel
// ---------------------------------------------------------------------------

type PanelTab = 'chat' | 'tickets'

export function CouncilAIPanel() {
  const {
    isPanelOpen, closePanel, activeConversation, activeModuleContext,
    sendMessage, createTicket, openTicketCount,
  } = useCouncil()

  const [input, setInput] = useState('')
  const [activeTab, setActiveTab] = useState<PanelTab>('chat')
  const [showTicketForm, setShowTicketForm] = useState(false)
  const [ticketTitle, setTicketTitle] = useState('')
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [activeConversation?.messages])

  // Focus input when panel opens
  useEffect(() => {
    if (isPanelOpen && activeTab === 'chat') {
      setTimeout(() => inputRef.current?.focus(), 200)
    }
  }, [isPanelOpen, activeTab])

  const handleSend = useCallback(() => {
    const trimmed = input.trim()
    if (!trimmed) return
    sendMessage(trimmed)
    setInput('')
  }, [input, sendMessage])

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }, [handleSend])

  const handleCreateTicket = useCallback(() => {
    if (!ticketTitle.trim()) return
    createTicket(ticketTitle.trim())
    setTicketTitle('')
    setShowTicketForm(false)
    setActiveTab('tickets')
  }, [ticketTitle, createTicket])

  // Keyboard shortcut: Escape to close
  useEffect(() => {
    function handleEsc(e: KeyboardEvent) {
      if (e.key === 'Escape' && isPanelOpen) closePanel()
    }
    window.addEventListener('keydown', handleEsc)
    return () => window.removeEventListener('keydown', handleEsc)
  }, [isPanelOpen, closePanel])

  return (
    <>
      {/* Backdrop */}
      {isPanelOpen && (
        <div
          className="fixed inset-0 bg-black/20 z-40 desktop:hidden"
          onClick={closePanel}
          aria-hidden="true"
        />
      )}

      {/* Panel */}
      <aside
        className={cn(
          'fixed top-0 right-0 bottom-0 z-50 w-full tablet:w-[420px] bg-[var(--surface-raised)] border-l border-[var(--border-subtle)] shadow-xl flex flex-col transition-transform duration-300',
          isPanelOpen ? 'translate-x-0' : 'translate-x-full',
        )}
        role="complementary"
        aria-label="Council AI assistant panel"
      >
        {/* Panel header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)] bg-gradient-to-r from-violet-600/10 to-blue-600/10">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-violet-500 to-blue-500 flex items-center justify-center shadow-sm">
              <svg className="w-5 h-5 text-white" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
              </svg>
            </div>
            <div>
              <h2 className="text-sm font-bold text-[var(--text-primary)]">Council AI</h2>
              <span className="text-2xs text-[var(--text-muted)]">
                Module: {activeModuleContext}
              </span>
            </div>
          </div>
          <button
            onClick={closePanel}
            className="p-1.5 rounded-lg hover:bg-[var(--surface-overlay)] text-[var(--text-secondary)]"
            aria-label="Close Council AI panel"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-[var(--border-subtle)]">
          <button
            onClick={() => setActiveTab('chat')}
            className={cn(
              'flex-1 py-2 text-xs font-semibold transition-colors',
              activeTab === 'chat'
                ? 'text-[var(--accent-primary)] border-b-2 border-[var(--accent-primary)]'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]',
            )}
          >
            Conversation
          </button>
          <button
            onClick={() => setActiveTab('tickets')}
            className={cn(
              'flex-1 py-2 text-xs font-semibold transition-colors relative',
              activeTab === 'tickets'
                ? 'text-[var(--accent-primary)] border-b-2 border-[var(--accent-primary)]'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]',
            )}
          >
            Tickets
            {openTicketCount > 0 && (
              <span className="absolute top-1 ml-1 inline-flex items-center justify-center min-w-[1.25rem] h-5 rounded-full bg-red-500 text-white text-2xs font-bold px-1">
                {openTicketCount}
              </span>
            )}
          </button>
        </div>

        {/* Content area */}
        {activeTab === 'chat' ? (
          <>
            {/* Messages */}
            <div className="flex-1 overflow-y-auto px-4 py-3">
              {activeConversation?.messages.map(msg => (
                <MessageBubble key={msg.id} message={msg} />
              ))}
              <div ref={messagesEndRef} />
            </div>

            {/* Ticket creation form */}
            {showTicketForm && (
              <div className="px-4 py-2 border-t border-[var(--border-subtle)] bg-[var(--surface-overlay)]">
                <div className="text-xs font-semibold text-[var(--text-primary)] mb-1.5">Create Ticket from Conversation</div>
                <input
                  type="text"
                  value={ticketTitle}
                  onChange={e => setTicketTitle(e.target.value)}
                  placeholder="Ticket title..."
                  className="w-full px-3 py-1.5 text-sm rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-widget)] text-[var(--text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-primary)]"
                  onKeyDown={e => e.key === 'Enter' && handleCreateTicket()}
                  autoFocus
                />
                <div className="flex gap-2 mt-2">
                  <button
                    onClick={handleCreateTicket}
                    className="flex-1 px-3 py-1.5 text-xs font-semibold rounded-lg bg-[var(--accent-primary)] text-white hover:bg-[var(--accent-hover)]"
                  >
                    Create Ticket
                  </button>
                  <button
                    onClick={() => setShowTicketForm(false)}
                    className="px-3 py-1.5 text-xs rounded-lg border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:bg-[var(--surface-overlay)]"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {/* Input area */}
            <div className="px-4 py-3 border-t border-[var(--border-subtle)]">
              <div className="flex items-end gap-2">
                <div className="flex-1 relative">
                  <textarea
                    ref={inputRef}
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask the council anything..."
                    rows={1}
                    className="w-full px-3 py-2 text-sm rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-widget)] text-[var(--text-primary)] resize-none focus:outline-none focus:ring-2 focus:ring-[var(--accent-primary)] max-h-24"
                    style={{ minHeight: '40px' }}
                  />
                </div>
                <div className="flex gap-1">
                  <button
                    onClick={() => setShowTicketForm(!showTicketForm)}
                    className="p-2 rounded-xl border border-[var(--border-subtle)] text-[var(--text-secondary)] hover:bg-[var(--surface-overlay)] hover:text-[var(--accent-primary)]"
                    aria-label="Create ticket from conversation"
                    title="Create ticket"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
                    </svg>
                  </button>
                  <button
                    onClick={handleSend}
                    disabled={!input.trim()}
                    className={cn(
                      'p-2 rounded-xl transition-colors',
                      input.trim()
                        ? 'bg-[var(--accent-primary)] text-white hover:bg-[var(--accent-hover)]'
                        : 'bg-[var(--surface-overlay)] text-[var(--text-muted)]',
                    )}
                    aria-label="Send message"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                    </svg>
                  </button>
                </div>
              </div>
              <div className="text-2xs text-[var(--text-muted)] mt-1.5 text-center">
                Press Enter to send &middot; Shift+Enter for new line &middot; Every message creates contextualized tickets
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 overflow-y-auto px-4 py-3">
            <TicketList />
          </div>
        )}
      </aside>
    </>
  )
}
