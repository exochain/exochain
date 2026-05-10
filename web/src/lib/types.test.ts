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

import { describe, it, expect } from 'vitest'
import {
  isTerminalStatus,
  statusColor,
  urgencyLevel,
  statusDotColor,
  type DecisionStatus,
  type UrgencyLevel,
} from './types'

describe('types.ts — Status utility functions', () => {
  // ─────────────────────────────────────────────────────────────
  // isTerminalStatus tests
  // ─────────────────────────────────────────────────────────────

  describe('isTerminalStatus', () => {
    it('returns true for Approved status', () => {
      expect(isTerminalStatus('Approved')).toBe(true)
    })

    it('returns true for Rejected status', () => {
      expect(isTerminalStatus('Rejected')).toBe(true)
    })

    it('returns true for Void status', () => {
      expect(isTerminalStatus('Void')).toBe(true)
    })

    it('returns true for RatificationExpired status', () => {
      expect(isTerminalStatus('RatificationExpired')).toBe(true)
    })

    it('returns false for Created status', () => {
      expect(isTerminalStatus('Created')).toBe(false)
    })

    it('returns false for Deliberation status', () => {
      expect(isTerminalStatus('Deliberation')).toBe(false)
    })

    it('returns false for Voting status', () => {
      expect(isTerminalStatus('Voting')).toBe(false)
    })

    it('returns false for Contested status', () => {
      expect(isTerminalStatus('Contested')).toBe(false)
    })

    it('returns false for RatificationRequired status', () => {
      expect(isTerminalStatus('RatificationRequired')).toBe(false)
    })

    it('returns false for DegradedGovernance status', () => {
      expect(isTerminalStatus('DegradedGovernance')).toBe(false)
    })
  })

  // ─────────────────────────────────────────────────────────────
  // statusColor tests
  // ─────────────────────────────────────────────────────────────

  describe('statusColor', () => {
    it('returns correct color class for Created status', () => {
      expect(statusColor('Created')).toBe('bg-gray-100 text-gray-800')
    })

    it('returns correct color class for Deliberation status', () => {
      expect(statusColor('Deliberation')).toBe('bg-blue-100 text-blue-800')
    })

    it('returns correct color class for Voting status', () => {
      expect(statusColor('Voting')).toBe('bg-yellow-100 text-yellow-800')
    })

    it('returns correct color class for Approved status', () => {
      expect(statusColor('Approved')).toBe('bg-green-100 text-green-800')
    })

    it('returns correct color class for Rejected status', () => {
      expect(statusColor('Rejected')).toBe('bg-red-100 text-red-800')
    })

    it('returns correct color class for Void status', () => {
      expect(statusColor('Void')).toBe('bg-gray-200 text-gray-600')
    })

    it('returns correct color class for Contested status', () => {
      expect(statusColor('Contested')).toBe('bg-orange-100 text-orange-800')
    })

    it('returns correct color class for RatificationRequired status', () => {
      expect(statusColor('RatificationRequired')).toBe('bg-purple-100 text-purple-800')
    })

    it('returns correct color class for RatificationExpired status', () => {
      expect(statusColor('RatificationExpired')).toBe('bg-red-200 text-red-900')
    })

    it('returns correct color class for DegradedGovernance status', () => {
      expect(statusColor('DegradedGovernance')).toBe('bg-amber-100 text-amber-800')
    })

    it('returns default color class for unknown status', () => {
      expect(statusColor('Unknown' as DecisionStatus)).toBe('bg-gray-100 text-gray-800')
    })
  })

  // ─────────────────────────────────────────────────────────────
  // urgencyLevel tests
  // ─────────────────────────────────────────────────────────────

  describe('urgencyLevel', () => {
    describe('critical urgency', () => {
      it('returns critical for Contested status', () => {
        expect(urgencyLevel('Contested')).toBe('critical')
      })

      it('returns critical for RatificationExpired status', () => {
        expect(urgencyLevel('RatificationExpired')).toBe('critical')
      })

      it('returns critical for DegradedGovernance status', () => {
        expect(urgencyLevel('DegradedGovernance')).toBe('critical')
      })
    })

    describe('high urgency', () => {
      it('returns high for Voting status', () => {
        expect(urgencyLevel('Voting')).toBe('high')
      })

      it('returns high for RatificationRequired status', () => {
        expect(urgencyLevel('RatificationRequired')).toBe('high')
      })
    })

    describe('moderate urgency', () => {
      it('returns moderate for Deliberation status', () => {
        expect(urgencyLevel('Deliberation')).toBe('moderate')
      })
    })

    describe('low urgency', () => {
      it('returns low for Created status', () => {
        expect(urgencyLevel('Created')).toBe('low')
      })
    })

    describe('neutral urgency', () => {
      it('returns neutral for Approved status', () => {
        expect(urgencyLevel('Approved')).toBe('neutral')
      })

      it('returns neutral for Rejected status', () => {
        expect(urgencyLevel('Rejected')).toBe('neutral')
      })

      it('returns neutral for Void status', () => {
        expect(urgencyLevel('Void')).toBe('neutral')
      })
    })

    it('returns neutral for unknown status', () => {
      expect(urgencyLevel('Unknown' as DecisionStatus)).toBe('neutral')
    })
  })

  // ─────────────────────────────────────────────────────────────
  // statusDotColor tests
  // ─────────────────────────────────────────────────────────────

  describe('statusDotColor', () => {
    it('returns correct dot color class for Created status', () => {
      expect(statusDotColor('Created')).toBe('bg-status-created')
    })

    it('returns correct dot color class for Deliberation status', () => {
      expect(statusDotColor('Deliberation')).toBe('bg-status-deliberation')
    })

    it('returns correct dot color class for Voting status', () => {
      expect(statusDotColor('Voting')).toBe('bg-status-voting')
    })

    it('returns correct dot color class for Approved status', () => {
      expect(statusDotColor('Approved')).toBe('bg-status-approved')
    })

    it('returns correct dot color class for Rejected status', () => {
      expect(statusDotColor('Rejected')).toBe('bg-status-rejected')
    })

    it('returns correct dot color class for Void status', () => {
      expect(statusDotColor('Void')).toBe('bg-status-void')
    })

    it('returns correct dot color class for Contested status', () => {
      expect(statusDotColor('Contested')).toBe('bg-status-contested')
    })

    it('returns correct dot color class for RatificationRequired status', () => {
      expect(statusDotColor('RatificationRequired')).toBe('bg-status-ratification')
    })

    it('returns correct dot color class for RatificationExpired status', () => {
      expect(statusDotColor('RatificationExpired')).toBe('bg-status-expired')
    })

    it('returns correct dot color class for DegradedGovernance status', () => {
      expect(statusDotColor('DegradedGovernance')).toBe('bg-status-degraded')
    })

    it('returns default dot color class for unknown status', () => {
      expect(statusDotColor('Unknown' as DecisionStatus)).toBe('bg-status-created')
    })
  })

  // ─────────────────────────────────────────────────────────────
  // Cross-function consistency tests
  // ─────────────────────────────────────────────────────────────

  describe('consistency across functions', () => {
    const allStatuses: DecisionStatus[] = [
      'Created',
      'Deliberation',
      'Voting',
      'Approved',
      'Rejected',
      'Void',
      'Contested',
      'RatificationRequired',
      'RatificationExpired',
      'DegradedGovernance',
    ]

    it('statusColor returns a string for all statuses', () => {
      allStatuses.forEach(status => {
        expect(typeof statusColor(status)).toBe('string')
        expect(statusColor(status).length).toBeGreaterThan(0)
      })
    })

    it('urgencyLevel returns a valid UrgencyLevel for all statuses', () => {
      const validLevels: UrgencyLevel[] = ['critical', 'high', 'moderate', 'low', 'neutral']
      allStatuses.forEach(status => {
        const level = urgencyLevel(status)
        expect(validLevels).toContain(level)
      })
    })

    it('statusDotColor returns a string for all statuses', () => {
      allStatuses.forEach(status => {
        expect(typeof statusDotColor(status)).toBe('string')
        expect(statusDotColor(status).length).toBeGreaterThan(0)
      })
    })

    it('terminal statuses match isTerminalStatus definition', () => {
      const terminalStatuses = allStatuses.filter(s => isTerminalStatus(s))
      expect(terminalStatuses).toEqual(['Approved', 'Rejected', 'Void', 'RatificationExpired'])
    })
  })
})
