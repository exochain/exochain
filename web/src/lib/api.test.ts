import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { api } from './api'

const API_BASE = '/api/v1'

describe('API Client', () => {
  beforeEach(() => {
    // Clear all mocks and storage
    vi.clearAllMocks()
    localStorage.clear()
    global.fetch = vi.fn()
  })

  // ============ Helper Functions Tests ============

  describe('getToken', () => {
    it('should return token from localStorage', async () => {
      localStorage.setItem('df_token', 'test-token-123')

      // Import and test getToken by checking it's used in fetch
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ status: 'ok' })
      })

      await api.health()

      expect(mockFetch).toHaveBeenCalledWith(
        `${API_BASE}/health`,
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token-123'
          })
        })
      )
    })

    it('should not add Authorization header when no token', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ status: 'ok' })
      })

      await api.health()

      expect(mockFetch).toHaveBeenCalledWith(
        `${API_BASE}/health`,
        expect.objectContaining({
          headers: expect.not.objectContaining({
            'Authorization': expect.anything()
          })
        })
      )
    })
  })

  describe('fetchJson helper', () => {
    it('should always include Content-Type header', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({})
      })

      await api.health()

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json'
          })
        })
      )
    })

    it('should throw error when response is not ok', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: () => Promise.resolve('Unauthorized')
      })

      await expect(api.health()).rejects.toThrow('API 401: Unauthorized')
    })

    it('should construct correct URL with API_BASE prefix', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({})
      })

      await api.health()

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/v1/health',
        expect.any(Object)
      )
    })

    it('should parse and return JSON response', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      const responseData = { status: 'healthy', decisions: 42 }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(responseData)
      })

      const result = await api.health()

      expect(result).toEqual(responseData)
    })

    it('should merge custom init options with headers', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({})
      })

      localStorage.setItem('df_token', 'token123')

      // Simulate a POST request
      await api.decisions.create({
        title: 'Test',
        body: 'Test body',
        decisionClass: 'normal',
        author: 'user1'
      })

      expect(mockFetch).toHaveBeenCalledWith(
        `${API_BASE}/decisions`,
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'Authorization': 'Bearer token123'
          }),
          body: expect.any(String)
        })
      )
    })
  })

  // ============ Health Endpoint Tests ============

  describe('api.health', () => {
    it('should fetch health status', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      const healthData = {
        status: 'healthy',
        decisions: 10,
        delegations: 5,
        auditEntries: 20,
        auditIntegrity: true
      }
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(healthData)
      })

      const result = await api.health()

      expect(result).toEqual(healthData)
      expect(mockFetch).toHaveBeenCalledWith(
        `${API_BASE}/health`,
        expect.any(Object)
      )
    })
  })

  // ============ Decisions Endpoint Tests ============

  describe('api.decisions', () => {
    describe('list', () => {
      it('should list all decisions', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const decisions = [
          { id: 'dec1', title: 'Decision 1' },
          { id: 'dec2', title: 'Decision 2' }
        ]
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(decisions)
        })

        const result = await api.decisions.list()

        expect(result).toEqual(decisions)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/decisions`,
          expect.any(Object)
        )
      })
    })

    describe('get', () => {
      it('should fetch a specific decision by id', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const decision = { id: 'dec1', title: 'Decision 1', body: 'Body text' }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(decision)
        })

        const result = await api.decisions.get('dec1')

        expect(result).toEqual(decision)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/decisions/dec1`,
          expect.any(Object)
        )
      })
    })

    describe('create', () => {
      it('should create a new decision with POST', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const newDecision = {
          id: 'dec-new',
          title: 'New Decision',
          body: 'New body',
          decisionClass: 'urgent',
          author: 'user1'
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(newDecision)
        })

        const input = {
          title: 'New Decision',
          body: 'New body',
          decisionClass: 'urgent',
          author: 'user1'
        }
        const result = await api.decisions.create(input)

        expect(result).toEqual(newDecision)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/decisions`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify(input)
          })
        )
      })
    })

    describe('advance', () => {
      it('should advance decision status', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const updatedDecision = {
          id: 'dec1',
          title: 'Decision 1',
          status: 'voting'
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(updatedDecision)
        })

        const result = await api.decisions.advance('dec1', 'voting', 'admin1', 'Time to vote')

        expect(result).toEqual(updatedDecision)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/decisions/dec1/advance`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
              newStatus: 'voting',
              actor: 'admin1',
              reason: 'Time to vote'
            })
          })
        )
      })

      it('should advance decision without optional reason', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ id: 'dec1' })
        })

        await api.decisions.advance('dec1', 'closed', 'admin1')

        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/decisions/dec1/advance`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
              newStatus: 'closed',
              actor: 'admin1',
              reason: undefined
            })
          })
        )
      })
    })

    describe('vote', () => {
      it('should cast a vote on a decision', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const updatedDecision = { id: 'dec1', voteCount: 1 }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(updatedDecision)
        })

        const result = await api.decisions.vote('dec1', 'user1', 'yes', 'I agree')

        expect(result).toEqual(updatedDecision)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/decisions/dec1/vote`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
              voter: 'user1',
              choice: 'yes',
              rationale: 'I agree'
            })
          })
        )
      })

      it('should cast a vote without optional rationale', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ id: 'dec1' })
        })

        await api.decisions.vote('dec1', 'user1', 'no')

        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/decisions/dec1/vote`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
              voter: 'user1',
              choice: 'no',
              rationale: undefined
            })
          })
        )
      })
    })

    describe('tally', () => {
      it('should tally votes on a decision', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const tallyResult = {
          id: 'dec1',
          yesVotes: 10,
          noVotes: 3,
          result: 'passed'
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(tallyResult)
        })

        const result = await api.decisions.tally('dec1', 'admin1')

        expect(result).toEqual(tallyResult)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/decisions/dec1/tally`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
              actor: 'admin1'
            })
          })
        )
      })
    })
  })

  // ============ Delegations Endpoint Tests ============

  describe('api.delegations', () => {
    describe('list', () => {
      it('should list all delegations', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const delegations = [
          { id: 'del1', from: 'user1', to: 'user2' },
          { id: 'del2', from: 'user2', to: 'user3' }
        ]
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(delegations)
        })

        const result = await api.delegations.list()

        expect(result).toEqual(delegations)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/delegations`,
          expect.any(Object)
        )
      })
    })
  })

  // ============ Audit Endpoint Tests ============

  describe('api.audit', () => {
    describe('trail', () => {
      it('should fetch audit trail', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const trail = [
          { id: 'audit1', action: 'create', entity: 'decision', timestamp: '2025-01-01' },
          { id: 'audit2', action: 'vote', entity: 'decision', timestamp: '2025-01-02' }
        ]
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(trail)
        })

        const result = await api.audit.trail()

        expect(result).toEqual(trail)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/audit`,
          expect.any(Object)
        )
      })
    })

    describe('verify', () => {
      it('should verify audit integrity', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const integrity = {
          isValid: true,
          lastVerified: '2025-01-10',
          integrityHash: 'abc123'
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(integrity)
        })

        const result = await api.audit.verify()

        expect(result).toEqual(integrity)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/audit/verify`,
          expect.any(Object)
        )
      })
    })
  })

  // ============ Constitution Endpoint Tests ============

  describe('api.constitution', () => {
    describe('get', () => {
      it('should fetch constitution info', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const constitution = {
          id: 'const1',
          version: '1.0.0',
          lastUpdated: '2025-01-01',
          rules: []
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(constitution)
        })

        const result = await api.constitution.get()

        expect(result).toEqual(constitution)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/constitution`,
          expect.any(Object)
        )
      })
    })
  })

  // ============ Auth Endpoint Tests ============

  describe('api.auth', () => {
    describe('register', () => {
      it('should register a new user', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const registerResponse = {
          userId: 'user-123',
          email: 'newuser@example.com',
          displayName: 'New User'
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(registerResponse)
        })

        const input = {
          displayName: 'New User',
          email: 'newuser@example.com',
          password: 'securepass123'
        }
        const result = await api.auth.register(input)

        expect(result).toEqual(registerResponse)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/auth/register`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify(input)
          })
        )
      })
    })

    describe('login', () => {
      it('should login user and return token', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const loginResponse = {
          token: 'jwt-token-abc123',
          refreshToken: 'refresh-token-def456'
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(loginResponse)
        })

        const input = {
          email: 'user@example.com',
          password: 'password123'
        }
        const result = await api.auth.login(input)

        expect(result).toEqual(loginResponse)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/auth/login`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify(input)
          })
        )
      })
    })

    describe('refresh', () => {
      it('should refresh auth token', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const refreshResponse = {
          token: 'new-jwt-token-xyz',
          refreshToken: 'new-refresh-token-uvw'
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(refreshResponse)
        })

        const result = await api.auth.refresh('old-refresh-token')

        expect(result).toEqual(refreshResponse)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/auth/refresh`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
              refreshToken: 'old-refresh-token'
            })
          })
        )
      })
    })

    describe('me', () => {
      it('should fetch current user profile', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        localStorage.setItem('df_token', 'user-token-123')

        const userProfile = {
          id: 'user-123',
          email: 'user@example.com',
          displayName: 'Test User'
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(userProfile)
        })

        const result = await api.auth.me()

        expect(result).toEqual(userProfile)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/auth/me`,
          expect.objectContaining({
            headers: expect.objectContaining({
              'Authorization': 'Bearer user-token-123'
            })
          })
        )
      })
    })

    describe('logout', () => {
      it('should logout current user', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        localStorage.setItem('df_token', 'user-token-123')

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(null)
        })

        await api.auth.logout()

        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/auth/logout`,
          expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({
              'Authorization': 'Bearer user-token-123'
            })
          })
        )
      })
    })
  })

  // ============ Agents Endpoint Tests ============

  describe('api.agents', () => {
    describe('list', () => {
      it('should list all agents', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const agents = [
          { did: 'agent-1', agentName: 'Agent 1', agentType: 'bot' },
          { did: 'agent-2', agentName: 'Agent 2', agentType: 'human' }
        ]
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(agents)
        })

        const result = await api.agents.list()

        expect(result).toEqual(agents)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/agents`,
          expect.any(Object)
        )
      })
    })

    describe('get', () => {
      it('should fetch a specific agent by did', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const agent = {
          did: 'agent-123',
          agentName: 'Test Agent',
          agentType: 'bot'
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(agent)
        })

        const result = await api.agents.get('agent-123')

        expect(result).toEqual(agent)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/agents/agent-123`,
          expect.any(Object)
        )
      })
    })

    describe('enroll', () => {
      it('should enroll a new agent', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const enrolledAgent = {
          did: 'agent-new',
          agentName: 'New Agent',
          agentType: 'bot',
          capabilities: ['vote', 'delegate']
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(enrolledAgent)
        })

        const input = {
          agentName: 'New Agent',
          agentType: 'bot',
          capabilities: ['vote', 'delegate'],
          maxDecisionClass: 'normal'
        }
        const result = await api.agents.enroll(input)

        expect(result).toEqual(enrolledAgent)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/agents`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify(input)
          })
        )
      })
    })

    describe('advancePace', () => {
      it('should advance agent pace', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const updatedAgent = {
          did: 'agent-123',
          pace: 'accelerated'
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(updatedAgent)
        })

        const result = await api.agents.advancePace('agent-123', 'accelerated')

        expect(result).toEqual(updatedAgent)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/agents/agent-123/pace`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
              step: 'accelerated'
            })
          })
        )
      })
    })
  })

  // ============ Users Endpoint Tests ============

  describe('api.users', () => {
    describe('list', () => {
      it('should list all users', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const users = [
          { id: 'user-1', displayName: 'User 1', email: 'user1@example.com' },
          { id: 'user-2', displayName: 'User 2', email: 'user2@example.com' }
        ]
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(users)
        })

        const result = await api.users.list()

        expect(result).toEqual(users)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/users`,
          expect.any(Object)
        )
      })
    })

    describe('advancePace', () => {
      it('should advance user pace', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const updatedUser = {
          id: 'user-123',
          pace: 'moderate'
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(updatedUser)
        })

        const result = await api.users.advancePace('user-123', 'moderate')

        expect(result).toEqual(updatedUser)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/users/user-123/pace`,
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({
              step: 'moderate'
            })
          })
        )
      })
    })
  })

  // ============ Identity Endpoint Tests ============

  describe('api.identity', () => {
    describe('score', () => {
      it('should fetch identity score for a did', async () => {
        const mockFetch = vi.fn()
        global.fetch = mockFetch
        const score = {
          did: 'agent-123',
          score: 95,
          level: 'gold'
        }
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(score)
        })

        const result = await api.identity.score('agent-123')

        expect(result).toEqual(score)
        expect(mockFetch).toHaveBeenCalledWith(
          `${API_BASE}/identity/agent-123/score`,
          expect.any(Object)
        )
      })
    })
  })

  // ============ Error Handling Tests ============

  describe('Error Handling', () => {
    it('should throw error with status code and response body on API error', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        text: () => Promise.resolve('Decision not found')
      })

      await expect(api.decisions.get('nonexistent')).rejects.toThrow(
        'API 404: Decision not found'
      )
    })

    it('should handle empty error responses', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: () => Promise.resolve('')
      })

      await expect(api.health()).rejects.toThrow('API 500: ')
    })

    it('should throw error with network issues', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockRejectedValueOnce(new Error('Network error'))

      await expect(api.health()).rejects.toThrow('Network error')
    })

    it('should throw error with 403 Forbidden status', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        text: () => Promise.resolve('Insufficient permissions')
      })

      await expect(api.auth.me()).rejects.toThrow('API 403: Insufficient permissions')
    })

    it('should throw error with 500 Internal Server Error', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal server error')
      })

      await expect(api.decisions.list()).rejects.toThrow('API 500: Internal server error')
    })
  })

  // ============ Integration Tests ============

  describe('Integration', () => {
    it('should handle full auth flow: register -> login -> me -> logout', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch

      // Register
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ userId: 'user-123', email: 'test@example.com' })
      })
      await api.auth.register({
        displayName: 'Test User',
        email: 'test@example.com',
        password: 'password123'
      })

      // Login
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ token: 'jwt-token', refreshToken: 'refresh-token' })
      })
      await api.auth.login({ email: 'test@example.com', password: 'password123' })

      localStorage.setItem('df_token', 'jwt-token')

      // Me
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ id: 'user-123', email: 'test@example.com' })
      })
      await api.auth.me()

      // Logout
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(null)
      })
      await api.auth.logout()

      expect(mockFetch).toHaveBeenCalledTimes(4)
    })

    it('should handle decision lifecycle: create -> advance -> vote -> tally', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch

      // Create
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ id: 'dec-123', title: 'Test Decision' })
      })
      await api.decisions.create({
        title: 'Test Decision',
        body: 'Body',
        decisionClass: 'normal',
        author: 'user1'
      })

      // Advance
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ id: 'dec-123', status: 'voting' })
      })
      await api.decisions.advance('dec-123', 'voting', 'admin')

      // Vote
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ id: 'dec-123', voteCount: 1 })
      })
      await api.decisions.vote('dec-123', 'user1', 'yes')

      // Tally
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ id: 'dec-123', result: 'passed' })
      })
      await api.decisions.tally('dec-123', 'admin')

      expect(mockFetch).toHaveBeenCalledTimes(4)
    })

    it('should send auth headers on all requests when token is present', async () => {
      localStorage.setItem('df_token', 'test-token-999')
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({})
      })

      // Make multiple requests
      await api.health()
      await api.decisions.list()
      await api.auth.me()
      await api.agents.list()

      // Verify all calls included auth header
      expect(mockFetch).toHaveBeenCalledTimes(4)
      mockFetch.mock.calls.forEach(call => {
        const [, options] = call
        expect(options.headers).toHaveProperty('Authorization', 'Bearer test-token-999')
      })
    })
  })

  // ============ JSON Serialization Tests ============

  describe('JSON Serialization', () => {
    it('should properly serialize POST request bodies', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({})
      })

      const testData = {
        title: 'Test with "quotes"',
        body: 'Test with\nnewlines',
        decisionClass: 'normal',
        author: 'user1'
      }

      await api.decisions.create(testData)

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: JSON.stringify(testData)
        })
      )

      // Verify body is valid JSON
      const callArgs = mockFetch.mock.calls[0]
      const serializedBody = callArgs[1].body
      expect(() => JSON.parse(serializedBody)).not.toThrow()
    })
  })

  // ============ HTTP Method Tests ============

  describe('HTTP Methods', () => {
    it('should use GET by default for read operations', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({})
      })

      await api.decisions.list()

      const [, options] = mockFetch.mock.calls[0]
      expect(options.method).toBeUndefined() // GET is default
    })

    it('should use POST for create operations', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({})
      })

      await api.decisions.create({
        title: 'Test',
        body: 'Body',
        decisionClass: 'normal',
        author: 'user1'
      })

      const [, options] = mockFetch.mock.calls[0]
      expect(options.method).toBe('POST')
    })

    it('should use POST for action operations (advance, vote, tally)', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({})
      })

      await api.decisions.advance('dec1', 'voting', 'admin')
      await api.decisions.vote('dec1', 'user1', 'yes')
      await api.decisions.tally('dec1', 'admin')

      mockFetch.mock.calls.forEach(call => {
        const [, options] = call
        expect(options.method).toBe('POST')
      })
    })
  })

  // ============ URL Construction Tests ============

  describe('URL Construction', () => {
    it('should properly construct URLs with path parameters', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({})
      })

      await api.decisions.get('my-decision-id-123')
      await api.agents.get('agent-xyz-789')
      await api.identity.score('did:example:abc')

      expect(mockFetch).toHaveBeenNthCalledWith(1, `${API_BASE}/decisions/my-decision-id-123`, expect.any(Object))
      expect(mockFetch).toHaveBeenNthCalledWith(2, `${API_BASE}/agents/agent-xyz-789`, expect.any(Object))
      expect(mockFetch).toHaveBeenNthCalledWith(3, `${API_BASE}/identity/did:example:abc/score`, expect.any(Object))
    })

    it('should handle special characters in path parameters', async () => {
      const mockFetch = vi.fn()
      global.fetch = mockFetch
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({})
      })

      const idWithSpecialChars = 'id-with-dashes_and_underscores'
      await api.decisions.get(idWithSpecialChars)

      expect(mockFetch).toHaveBeenCalledWith(
        `${API_BASE}/decisions/${idWithSpecialChars}`,
        expect.any(Object)
      )
    })
  })

  // A-082: CSRF double-submit — mutating requests must attach the
  // X-CSRF-Token header whose value comes from the XSRF-TOKEN cookie.
  describe('CSRF protection', () => {
    const originalCookie = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie')

    afterEach(() => {
      if (originalCookie) {
        Object.defineProperty(Document.prototype, 'cookie', originalCookie)
      }
    })

    function setCookieString(value: string) {
      Object.defineProperty(Document.prototype, 'cookie', {
        configurable: true,
        get: () => value,
      })
    }

    it('attaches X-CSRF-Token header on POST when XSRF-TOKEN cookie is present', async () => {
      setCookieString('session=abc; XSRF-TOKEN=tok-123; other=xyz')
      const mockFetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ id: 'dec-1' }),
      })
      global.fetch = mockFetch

      await api.decisions.create({ title: 'x', kind: 'Operational' } as never)

      const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
      const headers = init.headers as Record<string, string>
      expect(headers['X-CSRF-Token']).toBe('tok-123')
    })

    it('does not attach X-CSRF-Token on GET requests', async () => {
      setCookieString('XSRF-TOKEN=tok-123')
      const mockFetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([]),
      })
      global.fetch = mockFetch

      await api.decisions.list()

      const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
      const headers = init.headers as Record<string, string>
      expect(headers['X-CSRF-Token']).toBeUndefined()
    })

    it('omits X-CSRF-Token when no XSRF-TOKEN cookie is set', async () => {
      setCookieString('session=abc')
      const mockFetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ id: 'dec-1' }),
      })
      global.fetch = mockFetch

      await api.decisions.create({ title: 'x', kind: 'Operational' } as never)

      const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
      const headers = init.headers as Record<string, string>
      expect(headers['X-CSRF-Token']).toBeUndefined()
    })

    it('URL-decodes the CSRF token so quoted values roundtrip', async () => {
      setCookieString('XSRF-TOKEN=' + encodeURIComponent('tok/with+special=chars'))
      const mockFetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      })
      global.fetch = mockFetch

      await api.decisions.create({ title: 'x', kind: 'Operational' } as never)

      const [, init] = mockFetch.mock.calls[0] as [string, RequestInit]
      const headers = init.headers as Record<string, string>
      expect(headers['X-CSRF-Token']).toBe('tok/with+special=chars')
    })
  })
})
