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

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useDecisions, useDecision } from './useDecisions'
import * as apiModule from '../lib/api'
import type { Decision } from '../lib/types'

// Mock the api module
vi.mock('../lib/api', () => ({
  api: {
    decisions: {
      list: vi.fn(),
      get: vi.fn(),
    },
  },
}))

const mockApi = apiModule.api

describe('useDecisions — Decision hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // ─────────────────────────────────────────────────────────────
  // useDecisions tests
  // ─────────────────────────────────────────────────────────────

  describe('useDecisions', () => {
    it('returns initial loading state', () => {
      vi.mocked(mockApi.decisions.list).mockImplementation(() => new Promise(() => {}))

      const { result } = renderHook(() => useDecisions())

      expect(result.current.loading).toBe(true)
      expect(result.current.decisions).toEqual([])
      expect(result.current.error).toBeNull()
    })

    it('loads decisions on mount', async () => {
      const mockDecisions: Decision[] = [
        {
          id: 'd1',
          tenantId: 'tenant1',
          status: 'Created',
          title: 'Decision 1',
          decisionClass: 'Strategic',
          author: 'user1',
          createdAt: Date.now(),
          constitutionVersion: '1.0',
          votes: [],
          challenges: [],
          transitionLog: [],
          isTerminal: false,
          validNextStatuses: ['Deliberation'],
        },
        {
          id: 'd2',
          tenantId: 'tenant1',
          status: 'Deliberation',
          title: 'Decision 2',
          decisionClass: 'Operational',
          author: 'user2',
          createdAt: Date.now(),
          constitutionVersion: '1.0',
          votes: [],
          challenges: [],
          transitionLog: [],
          isTerminal: false,
          validNextStatuses: ['Voting'],
        },
      ]

      vi.mocked(mockApi.decisions.list).mockResolvedValue(mockDecisions)

      const { result } = renderHook(() => useDecisions())

      expect(result.current.loading).toBe(true)

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.decisions).toEqual(mockDecisions)
      expect(result.current.error).toBeNull()
    })

    it('returns empty decisions array on successful load', async () => {
      vi.mocked(mockApi.decisions.list).mockResolvedValue([])

      const { result } = renderHook(() => useDecisions())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.decisions).toEqual([])
      expect(result.current.error).toBeNull()
    })

    it('handles error on list failure', async () => {
      const error = new Error('Failed to fetch decisions')
      vi.mocked(mockApi.decisions.list).mockRejectedValue(error)

      const { result } = renderHook(() => useDecisions())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.decisions).toEqual([])
      expect(result.current.error).toBe('Failed to fetch decisions')
    })

    it('provides refresh function', async () => {
      const mockDecisions: Decision[] = [
        {
          id: 'd1',
          tenantId: 'tenant1',
          status: 'Created',
          title: 'Decision 1',
          decisionClass: 'Strategic',
          author: 'user1',
          createdAt: Date.now(),
          constitutionVersion: '1.0',
          votes: [],
          challenges: [],
          transitionLog: [],
          isTerminal: false,
          validNextStatuses: [],
        },
      ]

      vi.mocked(mockApi.decisions.list).mockResolvedValue(mockDecisions)

      const { result } = renderHook(() => useDecisions())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.decisions).toEqual(mockDecisions)

      // Call refresh
      await act(async () => {
        result.current.refresh()
      })

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(vi.mocked(mockApi.decisions.list)).toHaveBeenCalledTimes(2)
    })

    it('clears error on refresh', async () => {
      const error = new Error('Network error')
      vi.mocked(mockApi.decisions.list).mockRejectedValueOnce(error)

      const { result } = renderHook(() => useDecisions())

      await waitFor(() => {
        expect(result.current.error).toBe('Network error')
      })

      vi.mocked(mockApi.decisions.list).mockResolvedValueOnce([])

      await act(async () => {
        result.current.refresh()
      })

      await waitFor(() => {
        expect(result.current.error).toBeNull()
      })
    })

    it('calls api.decisions.list exactly once on mount', async () => {
      vi.mocked(mockApi.decisions.list).mockResolvedValue([])

      renderHook(() => useDecisions())

      await waitFor(() => {
        expect(vi.mocked(mockApi.decisions.list)).toHaveBeenCalledTimes(1)
      })
    })
  })

  // ─────────────────────────────────────────────────────────────
  // useDecision tests
  // ─────────────────────────────────────────────────────────────

  describe('useDecision', () => {
    const mockDecision: Decision = {
      id: 'd1',
      tenantId: 'tenant1',
      status: 'Created',
      title: 'Test Decision',
      decisionClass: 'Strategic',
      author: 'user1',
      createdAt: Date.now(),
      constitutionVersion: '1.0',
      votes: [],
      challenges: [],
      transitionLog: [],
      isTerminal: false,
      validNextStatuses: ['Deliberation'],
    }

    it('returns initial loading state with empty id', () => {
      vi.mocked(mockApi.decisions.get).mockImplementation(() => new Promise(() => {}))

      const { result } = renderHook(() => useDecision(''))

      expect(result.current.loading).toBe(true)
      expect(result.current.decision).toBeNull()
      expect(result.current.error).toBeNull()
    })

    it('does not fetch when id is empty', async () => {
      vi.mocked(mockApi.decisions.get).mockResolvedValue(mockDecision)

      renderHook(() => useDecision(''))

      await waitFor(() => {
        expect(vi.mocked(mockApi.decisions.get)).not.toHaveBeenCalled()
      }, { timeout: 100 })
    })

    it('loads decision by id on mount', async () => {
      vi.mocked(mockApi.decisions.get).mockResolvedValue(mockDecision)

      const { result } = renderHook(() => useDecision('d1'))

      expect(result.current.loading).toBe(true)

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.decision).toEqual(mockDecision)
      expect(result.current.error).toBeNull()
      expect(vi.mocked(mockApi.decisions.get)).toHaveBeenCalledWith('d1')
    })

    it('handles error on get failure', async () => {
      const error = new Error('Decision not found')
      vi.mocked(mockApi.decisions.get).mockRejectedValue(error)

      const { result } = renderHook(() => useDecision('d1'))

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.decision).toBeNull()
      expect(result.current.error).toBe('Decision not found')
    })

    it('refetches when id changes', async () => {
      vi.mocked(mockApi.decisions.get).mockResolvedValue(mockDecision)

      const { result, rerender } = renderHook(
        ({ id }: { id: string }) => useDecision(id),
        { initialProps: { id: 'd1' } }
      )

      await waitFor(() => {
        expect(result.current.decision).toEqual(mockDecision)
      })

      const mockDecision2: Decision = { ...mockDecision, id: 'd2', title: 'Decision 2' }
      vi.mocked(mockApi.decisions.get).mockResolvedValue(mockDecision2)

      rerender({ id: 'd2' })

      await waitFor(() => {
        expect(result.current.decision).toEqual(mockDecision2)
      })

      expect(vi.mocked(mockApi.decisions.get)).toHaveBeenCalledWith('d1')
      expect(vi.mocked(mockApi.decisions.get)).toHaveBeenCalledWith('d2')
    })

    it('provides refresh function', async () => {
      vi.mocked(mockApi.decisions.get).mockResolvedValue(mockDecision)

      const { result } = renderHook(() => useDecision('d1'))

      await waitFor(() => {
        expect(result.current.decision).toEqual(mockDecision)
      })

      await act(async () => {
        result.current.refresh()
      })

      await waitFor(() => {
        expect(vi.mocked(mockApi.decisions.get)).toHaveBeenCalledTimes(2)
      })
    })

    it('clears error on successful refresh', async () => {
      const error = new Error('Fetch error')
      vi.mocked(mockApi.decisions.get).mockRejectedValueOnce(error)

      const { result } = renderHook(() => useDecision('d1'))

      await waitFor(() => {
        expect(result.current.error).toBe('Fetch error')
      })

      vi.mocked(mockApi.decisions.get).mockResolvedValueOnce(mockDecision)

      await act(async () => {
        result.current.refresh()
      })

      await waitFor(() => {
        expect(result.current.error).toBeNull()
        expect(result.current.decision).toEqual(mockDecision)
      })
    })

    it('maintains loading state during refresh', async () => {
      vi.mocked(mockApi.decisions.get).mockResolvedValue(mockDecision)

      const { result } = renderHook(() => useDecision('d1'))

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      vi.mocked(mockApi.decisions.get).mockImplementation(() => new Promise(() => {}))

      await act(async () => {
        result.current.refresh()
      })

      expect(result.current.loading).toBe(true)
    })

    it('handles different decision classes', async () => {
      const operationalDecision: Decision = {
        ...mockDecision,
        decisionClass: 'Operational',
      }
      vi.mocked(mockApi.decisions.get).mockResolvedValue(operationalDecision)

      const { result } = renderHook(() => useDecision('d-ops'))

      await waitFor(() => {
        expect(result.current.decision?.decisionClass).toBe('Operational')
      })
    })

    it('handles decisions with votes and challenges', async () => {
      const complexDecision: Decision = {
        ...mockDecision,
        votes: [
          { voter: 'user1', choice: 'Approve', signerType: 'human', timestamp: Date.now() },
          { voter: 'user2', choice: 'Reject', rationale: 'Too risky', signerType: 'human', timestamp: Date.now() },
        ],
        challenges: [
          { id: 'c1', grounds: 'Constitutional violation', status: 'open' },
        ],
      }
      vi.mocked(mockApi.decisions.get).mockResolvedValue(complexDecision)

      const { result } = renderHook(() => useDecision('d1'))

      await waitFor(() => {
        expect(result.current.decision?.votes).toHaveLength(2)
        expect(result.current.decision?.challenges).toHaveLength(1)
      })
    })

    it('handles terminal decisions', async () => {
      const terminalDecision: Decision = {
        ...mockDecision,
        status: 'Approved',
        isTerminal: true,
        validNextStatuses: [],
      }
      vi.mocked(mockApi.decisions.get).mockResolvedValue(terminalDecision)

      const { result } = renderHook(() => useDecision('d1'))

      await waitFor(() => {
        expect(result.current.decision?.isTerminal).toBe(true)
        expect(result.current.decision?.validNextStatuses).toHaveLength(0)
      })
    })
  })

  // ─────────────────────────────────────────────────────────────
  // Integration-like tests
  // ─────────────────────────────────────────────────────────────

  describe('Integration scenarios', () => {
    it('handles multiple instances of useDecisions independently', async () => {
      const decisions1: Decision[] = [
        {
          id: 'd1',
          tenantId: 'tenant1',
          status: 'Created',
          title: 'Decision 1',
          decisionClass: 'Strategic',
          author: 'user1',
          createdAt: Date.now(),
          constitutionVersion: '1.0',
          votes: [],
          challenges: [],
          transitionLog: [],
          isTerminal: false,
          validNextStatuses: [],
        },
      ]

      const decisions2: Decision[] = [
        {
          id: 'd2',
          tenantId: 'tenant1',
          status: 'Voting',
          title: 'Decision 2',
          decisionClass: 'Operational',
          author: 'user2',
          createdAt: Date.now(),
          constitutionVersion: '1.0',
          votes: [],
          challenges: [],
          transitionLog: [],
          isTerminal: false,
          validNextStatuses: [],
        },
      ]

      vi.mocked(mockApi.decisions.list)
        .mockResolvedValueOnce(decisions1)
        .mockResolvedValueOnce(decisions2)

      const { result: result1 } = renderHook(() => useDecisions())
      const { result: result2 } = renderHook(() => useDecisions())

      await waitFor(() => {
        expect(result1.current.decisions).toEqual(decisions1)
        expect(result2.current.decisions).toEqual(decisions2)
      })
    })

    it('handles rapid refresh calls gracefully', async () => {
      const mockDecision: Decision = {
        id: 'd1',
        tenantId: 'tenant1',
        status: 'Created',
        title: 'Test Decision',
        decisionClass: 'Strategic',
        author: 'user1',
        createdAt: Date.now(),
        constitutionVersion: '1.0',
        votes: [],
        challenges: [],
        transitionLog: [],
        isTerminal: false,
        validNextStatuses: [],
      }

      vi.mocked(mockApi.decisions.get).mockResolvedValue(mockDecision)

      const { result } = renderHook(() => useDecision('d1'))

      await waitFor(() => {
        expect(result.current.decision).toEqual(mockDecision)
      })

      const callCountBefore = vi.mocked(mockApi.decisions.get).mock.calls.length

      await act(async () => {
        result.current.refresh()
        result.current.refresh()
        result.current.refresh()
      })

      const callCountAfter = vi.mocked(mockApi.decisions.get).mock.calls.length

      expect(callCountAfter).toBe(callCountBefore + 3)
    })
  })
})
