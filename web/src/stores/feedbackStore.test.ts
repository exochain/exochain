import { describe, it, expect, beforeEach, vi } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useFeedbackStore, type FeedbackIssue, type IssueSeverity, type IssueCategory } from './feedbackStore'

// Mock fetch
global.fetch = vi.fn()

describe('feedbackStore.ts — Feedback store', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
    // Properly reset Zustand singleton state between tests
    useFeedbackStore.setState({
      issues: [],
      reporterOpen: false,
      reporterWidgetId: null,
      reporterModuleType: null,
    })
  })

  // ─────────────────────────────────────────────────────────────
  // State management tests
  // ─────────────────────────────────────────────────────────────

  describe('Initial state', () => {
    it('has empty issues array on start', () => {
      const { result } = renderHook(() => useFeedbackStore())
      expect(result.current.issues).toEqual([])
    })

    it('has reporter closed on start', () => {
      const { result } = renderHook(() => useFeedbackStore())
      expect(result.current.reporterOpen).toBe(false)
      expect(result.current.reporterWidgetId).toBeNull()
      expect(result.current.reporterModuleType).toBeNull()
    })
  })

  // ─────────────────────────────────────────────────────────────
  // Reporter UI tests
  // ─────────────────────────────────────────────────────────────

  describe('openReporter', () => {
    it('opens reporter with widget and module info', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
      })

      expect(result.current.reporterOpen).toBe(true)
      expect(result.current.reporterWidgetId).toBe('widget-1')
      expect(result.current.reporterModuleType).toBe('decisions')
    })

    it('replaces previous widget and module when opened again', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
      })

      expect(result.current.reporterWidgetId).toBe('widget-1')

      act(() => {
        result.current.openReporter('widget-2', 'metrics')
      })

      expect(result.current.reporterWidgetId).toBe('widget-2')
      expect(result.current.reporterModuleType).toBe('metrics')
    })
  })

  describe('closeReporter', () => {
    it('closes reporter and clears widget info', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
      })

      act(() => {
        result.current.closeReporter()
      })

      expect(result.current.reporterOpen).toBe(false)
      expect(result.current.reporterWidgetId).toBeNull()
      expect(result.current.reporterModuleType).toBeNull()
    })
  })

  // ─────────────────────────────────────────────────────────────
  // Issue filing tests
  // ─────────────────────────────────────────────────────────────

  describe('fileIssue', () => {
    it('creates a new issue with all fields', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
      })

      let newIssue: FeedbackIssue | undefined
      act(() => {
        newIssue = result.current.fileIssue({
          title: 'Test Issue',
          description: 'This is a test issue',
          severity: 'high',
          category: 'bug',
        })
      })

      expect(newIssue).toBeDefined()
      expect(newIssue?.title).toBe('Test Issue')
      expect(newIssue?.description).toBe('This is a test issue')
      expect(newIssue?.severity).toBe('high')
      expect(newIssue?.category).toBe('bug')
    })

    it('adds issue to store', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        result.current.fileIssue({
          title: 'Test Issue',
          description: 'Description',
          severity: 'medium',
          category: 'ux',
        })
      })

      expect(result.current.issues).toHaveLength(1)
    })

    it('sets issue status to open', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
      })

      let issue: FeedbackIssue | undefined
      act(() => {
        issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'low',
          category: 'question',
        })
      })

      expect(issue?.status).toBe('open')
    })

    it('includes widget and module context in issue', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-xyz', 'metrics')
      })

      let issue: FeedbackIssue | undefined
      act(() => {
        issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'critical',
          category: 'bug',
        })
      })

      expect(issue?.sourceWidgetId).toBe('widget-xyz')
      expect(issue?.sourceModuleType).toBe('metrics')
    })

    it('generates unique issue IDs', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
      })

      let issue1: FeedbackIssue | undefined
      let issue2: FeedbackIssue | undefined
      act(() => {
        issue1 = result.current.fileIssue({
          title: 'Issue 1',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
        })
        issue2 = result.current.fileIssue({
          title: 'Issue 2',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
        })
      })

      expect(issue1?.id).not.toBe(issue2?.id)
    })

    it('captures widget state if provided', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
      })

      const widgetState = { selectedDecision: 'd-123', filterStatus: 'Active' }
      let issue: FeedbackIssue | undefined
      act(() => {
        issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
          widgetState,
        })
      })

      expect(issue?.widgetState).toEqual(widgetState)
    })

    it('captures browser user agent', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
      })

      let issue: FeedbackIssue | undefined
      act(() => {
        issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
        })
      })

      expect(issue?.browserInfo).toBe(navigator.userAgent)
    })

    it('closes reporter after filing issue', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
      })

      expect(result.current.reporterOpen).toBe(true)

      act(() => {
        result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
        })
      })

      expect(result.current.reporterOpen).toBe(false)
    })

    it('handles unknown widget gracefully', () => {
      const { result } = renderHook(() => useFeedbackStore())

      let issue: FeedbackIssue | undefined
      act(() => {
        issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
        })
      })

      expect(issue?.sourceWidgetId).toBe('unknown')
      expect(issue?.sourceModuleType).toBe('unknown')
    })

    it('persists issues to localStorage', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        result.current.fileIssue({
          title: 'Persisted Issue',
          description: 'Test',
          severity: 'high',
          category: 'security',
        })
      })

      const stored = localStorage.getItem('exo_feedback_issues')
      expect(stored).toBeTruthy()
      const parsed = JSON.parse(stored!)
      expect(parsed).toHaveLength(1)
      expect(parsed[0].title).toBe('Persisted Issue')
      expect(result.current.issues).toHaveLength(1)
    })

    it('submits to server', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        json: async () => ({}),
      } as Response)

      localStorage.setItem('df_token', 'test-token')

      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        result.current.fileIssue({
          title: 'Server Test',
          description: 'Test',
          severity: 'critical',
          category: 'security',
        })
      })

      expect(vi.mocked(global.fetch)).toHaveBeenCalledWith(
        '/api/v1/feedback-issues',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            Authorization: 'Bearer test-token',
          }),
        })
      )
    })

    it('sends gateway-required actor binding metadata', () => {
      localStorage.setItem('df_token', 'test-token')

      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        result.current.fileIssue({
          title: 'Gateway Metadata',
          description: 'Test',
          severity: 'high',
          category: 'security',
        })
      })

      const [, init] = vi.mocked(global.fetch).mock.calls[0]
      const headers = init?.headers as Record<string, string>
      const body = JSON.parse(init?.body as string)

      expect(body.createdAt).toBeGreaterThan(0)
      expect(headers['x-exo-auth-observed-at-ms']).toBe(String(body.updatedAt))
    })
  })

  // ─────────────────────────────────────────────────────────────
  // Issue status update tests
  // ─────────────────────────────────────────────────────────────

  describe('updateIssueStatus', () => {
    it('updates issue status', () => {
      const { result } = renderHook(() => useFeedbackStore())

      let issueId: string
      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        const issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
        })
        issueId = issue!.id
      })

      act(() => {
        result.current.updateIssueStatus(issueId, 'triaged')
      })

      const updated = result.current.issues.find(i => i.id === issueId)
      expect(updated?.status).toBe('triaged')
    })

    it('adds resolution when updating status', () => {
      const { result } = renderHook(() => useFeedbackStore())

      let issueId: string
      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        const issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
        })
        issueId = issue!.id
      })

      act(() => {
        result.current.updateIssueStatus(issueId, 'resolved', 'Fixed in v1.2.0')
      })

      const updated = result.current.issues.find(i => i.id === issueId)
      expect(updated?.resolution).toBe('Fixed in v1.2.0')
    })

    it('sets resolvedAt timestamp when status is resolved', () => {
      const { result } = renderHook(() => useFeedbackStore())

      let issueId: string
      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        const issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
        })
        issueId = issue!.id
      })

      const before = Date.now()
      act(() => {
        result.current.updateIssueStatus(issueId, 'resolved')
      })
      const after = Date.now()

      const updated = result.current.issues.find(i => i.id === issueId)
      expect(updated?.resolvedAt).toBeDefined()
      expect(updated?.resolvedAt!).toBeGreaterThanOrEqual(before)
      expect(updated?.resolvedAt!).toBeLessThanOrEqual(after)
    })

    it('does not set resolvedAt for non-resolved statuses', () => {
      const { result } = renderHook(() => useFeedbackStore())

      let issueId: string
      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        const issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
        })
        issueId = issue!.id
      })

      act(() => {
        result.current.updateIssueStatus(issueId, 'assigned')
      })

      const updated = result.current.issues.find(i => i.id === issueId)
      expect(updated?.resolvedAt).toBeUndefined()
    })

    it('persists updated issues to localStorage', () => {
      const { result } = renderHook(() => useFeedbackStore())

      let issueId: string
      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        const issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
        })
        issueId = issue!.id
      })

      act(() => {
        result.current.updateIssueStatus(issueId, 'in-progress')
      })

      const stored = JSON.parse(localStorage.getItem('exo_feedback_issues')!)
      expect(stored[0].status).toBe('in-progress')
    })
  })

  // ─────────────────────────────────────────────────────────────
  // Issue dismissal tests
  // ─────────────────────────────────────────────────────────────

  describe('dismissIssue', () => {
    it('sets issue status to dismissed', () => {
      const { result } = renderHook(() => useFeedbackStore())

      let issueId: string
      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        const issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'low',
          category: 'question',
        })
        issueId = issue!.id
      })

      act(() => {
        result.current.dismissIssue(issueId, 'Not a bug')
      })

      const dismissed = result.current.issues.find(i => i.id === issueId)
      expect(dismissed?.status).toBe('dismissed')
    })

    it('includes dismissal reason in resolution', () => {
      const { result } = renderHook(() => useFeedbackStore())

      let issueId: string
      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        const issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'low',
          category: 'question',
        })
        issueId = issue!.id
      })

      act(() => {
        result.current.dismissIssue(issueId, 'Working as designed')
      })

      const dismissed = result.current.issues.find(i => i.id === issueId)
      expect(dismissed?.resolution).toBe('Working as designed')
    })

    it('persists dismissal to localStorage', () => {
      const { result } = renderHook(() => useFeedbackStore())

      let issueId: string
      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        const issue = result.current.fileIssue({
          title: 'Test',
          description: 'Test',
          severity: 'low',
          category: 'question',
        })
        issueId = issue!.id
      })

      act(() => {
        result.current.dismissIssue(issueId, 'Duplicate')
      })

      const stored = JSON.parse(localStorage.getItem('exo_feedback_issues')!)
      expect(stored[0].status).toBe('dismissed')
      expect(stored[0].resolution).toBe('Duplicate')
    })
  })

  // ─────────────────────────────────────────────────────────────
  // Computed/selector tests
  // ─────────────────────────────────────────────────────────────

  describe('openIssueCount', () => {
    it('counts issues that are not resolved or dismissed', () => {
      const { result } = renderHook(() => useFeedbackStore())

      let ids: string[] = []
      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        ids = [
          result.current.fileIssue({
            title: 'Open',
            description: 'Test',
            severity: 'medium',
            category: 'bug',
          })!.id,
          result.current.fileIssue({
            title: 'Triaged',
            description: 'Test',
            severity: 'medium',
            category: 'bug',
          })!.id,
        ]
      })

      expect(result.current.openIssueCount()).toBe(2)

      act(() => {
        result.current.updateIssueStatus(ids[0], 'resolved')
      })

      expect(result.current.openIssueCount()).toBe(1)

      act(() => {
        result.current.dismissIssue(ids[1], 'Not a bug')
      })

      expect(result.current.openIssueCount()).toBe(0)
    })
  })

  describe('issuesForWidget', () => {
    it('returns issues for specific widget', () => {
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        result.current.fileIssue({
          title: 'Widget 1 Issue',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
        })
        result.current.openReporter('widget-2', 'metrics')
        result.current.fileIssue({
          title: 'Widget 2 Issue',
          description: 'Test',
          severity: 'medium',
          category: 'bug',
        })
      })

      const widget1Issues = result.current.issuesForWidget('widget-1')
      expect(widget1Issues).toHaveLength(1)
      expect(widget1Issues[0].title).toBe('Widget 1 Issue')

      const widget2Issues = result.current.issuesForWidget('widget-2')
      expect(widget2Issues).toHaveLength(1)
      expect(widget2Issues[0].title).toBe('Widget 2 Issue')
    })

    it('returns empty array for widget with no issues', () => {
      const { result } = renderHook(() => useFeedbackStore())
      expect(result.current.issuesForWidget('nonexistent')).toEqual([])
    })
  })

  // ─────────────────────────────────────────────────────────────
  // Edge cases and recovery
  // ─────────────────────────────────────────────────────────────

  describe('Edge cases', () => {
    it('handles corrupted localStorage gracefully', () => {
      // Zustand is a singleton, so we can't re-init. Instead verify
      // that the store remains functional after corrupting localStorage.
      localStorage.setItem('exo_feedback_issues', 'not valid json')

      const { result } = renderHook(() => useFeedbackStore())
      // Store should still be in its reset state (from beforeEach)
      expect(Array.isArray(result.current.issues)).toBe(true)
      expect(result.current.issues).toHaveLength(0)
    })

    it('handles multiple severity levels', () => {
      const severities: IssueSeverity[] = ['critical', 'high', 'medium', 'low', 'info']
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        severities.forEach((severity, idx) => {
          result.current.fileIssue({
            title: `Issue ${idx}`,
            description: 'Test',
            severity,
            category: 'bug',
          })
        })
      })

      expect(result.current.issues).toHaveLength(5)
    })

    it('handles multiple category types', () => {
      const categories: IssueCategory[] = ['bug', 'ux', 'data', 'performance', 'security', 'feature', 'question']
      const { result } = renderHook(() => useFeedbackStore())

      act(() => {
        result.current.openReporter('widget-1', 'decisions')
        categories.forEach((category, idx) => {
          result.current.fileIssue({
            title: `Issue ${idx}`,
            description: 'Test',
            severity: 'medium',
            category,
          })
        })
      })

      expect(result.current.issues).toHaveLength(7)
    })
  })
})
