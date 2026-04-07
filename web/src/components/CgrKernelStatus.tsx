import { useState, useEffect } from 'react'
import { cn } from '../lib/utils'
import { api } from '../lib/api'

type KernelState = 'loading' | 'ok' | 'error'

/**
 * CGR Kernel health-check badge.
 *
 * On mount, calls the /health endpoint. Displays a compact status indicator:
 *   - Green dot + "CGR Kernel: OK"   when the health check passes
 *   - Red dot   + "CGR Kernel: ERROR" when it fails or times out
 *   - Gray dot  + "CGR Kernel: ..."   while loading
 */
export function CgrKernelStatus() {
  const [state, setState] = useState<KernelState>('loading')

  useEffect(() => {
    let cancelled = false

    async function checkHealth() {
      try {
        const health = await api.health()
        if (!cancelled) {
          setState(health.status === 'ok' ? 'ok' : 'error')
        }
      } catch {
        if (!cancelled) {
          setState('error')
        }
      }
    }

    checkHealth()
    return () => { cancelled = true }
  }, [])

  const dotColor =
    state === 'ok' ? 'bg-urgency-low health-pulse'
    : state === 'error' ? 'bg-urgency-critical'
    : 'bg-slate-400'

  const labelText =
    state === 'ok' ? 'CGR Kernel: OK'
    : state === 'error' ? 'CGR Kernel: ERROR'
    : 'CGR Kernel: ...'

  const labelColor =
    state === 'ok' ? 'text-green-700'
    : state === 'error' ? 'text-red-700'
    : 'text-slate-500'

  return (
    <span
      className="inline-flex items-center gap-1.5"
      role="status"
      aria-label={labelText}
    >
      <span
        className={cn('inline-block w-2 h-2 rounded-full', dotColor)}
        aria-hidden="true"
      />
      <span className={cn('text-xs font-medium', labelColor)}>
        {labelText}
      </span>
    </span>
  )
}
