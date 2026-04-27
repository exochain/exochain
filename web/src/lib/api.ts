/** API client for decision.forum gateway — connects to real Rust backend. */

import type {
  Decision, Delegation, AuditEntry, AuditIntegrity, ConstitutionInfo,
  LoginResponse, RegisterResponse, UserProfile, AgentIdentity, IdentityScore,
} from './types'

const API_BASE = '/api/v1'

/**
 * HTTP methods that mutate server state and therefore require a CSRF
 * token. GET / HEAD / OPTIONS are read-only and excluded. (A-082)
 */
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

function getToken(): string | null {
  return localStorage.getItem('df_token')
}

/**
 * Read the XSRF-TOKEN cookie and echo it back in an X-CSRF-Token header
 * on mutating requests. The gateway rejects mutations when that cookie is
 * present and the header is absent or mismatched. (A-082)
 */
function getCsrfToken(): string | null {
  const cookie = document.cookie
    .split(';')
    .map(c => c.trim())
    .find(c => c.startsWith('XSRF-TOKEN='))
  if (!cookie) return null
  return decodeURIComponent(cookie.slice('XSRF-TOKEN='.length))
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  // Attach CSRF token on mutating requests (double-submit pattern, A-082).
  const method = (init?.method ?? 'GET').toUpperCase()
  if (MUTATING_METHODS.has(method)) {
    const csrf = getCsrfToken()
    if (csrf !== null) headers['X-CSRF-Token'] = csrf
  }

  const res = await fetch(`${API_BASE}${path}`, {
    headers,
    ...init,
  })
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`API ${res.status}: ${body}`)
  }
  return res.json()
}

export const api = {
  health: () =>
    fetchJson<{
      status: string
      decisions: number
      delegations: number
      auditEntries: number
      auditIntegrity: boolean
    }>('/health'),

  decisions: {
    list: () => fetchJson<Decision[]>('/decisions'),
    get: (id: string) => fetchJson<Decision>(`/decisions/${id}`),
    create: (data: { title: string; body: string; decisionClass: string; author: string }) =>
      fetchJson<Decision>('/decisions', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    advance: (id: string, newStatus: string, actor: string, reason?: string) =>
      fetchJson<Decision>(`/decisions/${id}/advance`, {
        method: 'POST',
        body: JSON.stringify({ newStatus, actor, reason }),
      }),
    vote: (id: string, voter: string, choice: string, rationale?: string) =>
      fetchJson<Decision>(`/decisions/${id}/vote`, {
        method: 'POST',
        body: JSON.stringify({ voter, choice, rationale }),
      }),
    tally: (id: string, actor: string) =>
      fetchJson<Decision>(`/decisions/${id}/tally`, {
        method: 'POST',
        body: JSON.stringify({ actor }),
      }),
  },

  delegations: {
    list: () => fetchJson<Delegation[]>('/delegations'),
  },

  audit: {
    trail: () => fetchJson<AuditEntry[]>('/audit'),
    verify: () => fetchJson<AuditIntegrity>('/audit/verify'),
  },

  constitution: {
    get: () => fetchJson<ConstitutionInfo>('/constitution'),
  },

  auth: {
    register: (data: { displayName: string; email: string; password: string }) =>
      fetchJson<RegisterResponse>('/auth/register', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    login: (data: { email: string; password: string }) =>
      fetchJson<LoginResponse>('/auth/login', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    refresh: (refreshToken: string) =>
      fetchJson<{ token: string; refreshToken: string }>('/auth/refresh', {
        method: 'POST',
        body: JSON.stringify({ refreshToken }),
      }),
    me: () => fetchJson<UserProfile>('/auth/me'),
    logout: () =>
      fetchJson<void>('/auth/logout', { method: 'POST' }),
  },

  agents: {
    list: () => fetchJson<AgentIdentity[]>('/agents'),
    get: (did: string) => fetchJson<AgentIdentity>(`/agents/${did}`),
    enroll: (data: {
      agentName: string
      agentType: string
      capabilities: string[]
      maxDecisionClass: string
    }) =>
      fetchJson<AgentIdentity>('/agents', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    advancePace: (did: string, step: string) =>
      fetchJson<AgentIdentity>(`/agents/${did}/pace`, {
        method: 'POST',
        body: JSON.stringify({ step }),
      }),
  },

  users: {
    list: () => fetchJson<UserProfile[]>('/users'),
    advancePace: (did: string, step: string) =>
      fetchJson<UserProfile>(`/users/${did}/pace`, {
        method: 'POST',
        body: JSON.stringify({ step }),
      }),
  },

  identity: {
    score: (did: string) => fetchJson<IdentityScore>(`/identity/${did}/score`),
  },
}
