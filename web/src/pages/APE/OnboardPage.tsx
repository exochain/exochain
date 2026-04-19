/**
 * APE Onboarding — 5-step wizard that takes an AVC cohort member from
 * zero to a fully provisioned governance account with a personal board
 * of directors and agent team.
 *
 * Steps:
 *   0  Welcome       — what they're getting
 *   1  Account       — name, email, password
 *   2  Board         — name their board, pick governance style
 *   3  Team          — select agent specializations
 *   4  Launch        — confirmation + redirect to /APE/dashboard
 */

import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { cn } from '../../lib/utils'

// ── Board member role definitions ────────────────────────────────────

interface BoardRole {
  id: string
  title: string
  shortTitle: string
  icon: string
  description: string
  capabilities: string[]
  decisionClass: string
}

const BOARD_ROLES: BoardRole[] = [
  {
    id: 'ceo',
    title: 'Chief Executive',
    shortTitle: 'CEO',
    icon: '\u{1F3AF}',     // dart
    description: 'Strategic decisions, vision, overall direction',
    capabilities: ['CreateDecision', 'AdvanceDecision'],
    decisionClass: 'Strategic',
  },
  {
    id: 'cfo',
    title: 'Chief Financial',
    shortTitle: 'CFO',
    icon: '\u{1F4B0}',     // money bag
    description: 'Financial analysis, treasury, budget allocation',
    capabilities: ['CastVote', 'CreateDecision'],
    decisionClass: 'Financial',
  },
  {
    id: 'cto',
    title: 'Chief Technology',
    shortTitle: 'CTO',
    icon: '\u{1F6E1}',     // shield
    description: 'Technical architecture, security, infrastructure',
    capabilities: ['CastVote', 'CreateDecision'],
    decisionClass: 'Operational',
  },
  {
    id: 'counsel',
    title: 'General Counsel',
    shortTitle: 'Legal',
    icon: '\u{2696}',      // scales
    description: 'Legal compliance, risk assessment, contracts',
    capabilities: ['CastVote', 'GrantDelegation'],
    decisionClass: 'Constitutional',
  },
  {
    id: 'coo',
    title: 'Chief Operations',
    shortTitle: 'COO',
    icon: '\u{2699}',      // gear
    description: 'Process optimization, execution, logistics',
    capabilities: ['AdvanceDecision', 'CastVote'],
    decisionClass: 'Operational',
  },
  {
    id: 'cio',
    title: 'Chief Intelligence',
    shortTitle: 'CIO',
    icon: '\u{1F50D}',     // magnifying glass
    description: 'Research, market analysis, intelligence gathering',
    capabilities: ['CreateDecision', 'CastVote'],
    decisionClass: 'Strategic',
  },
]

const GOVERNANCE_STYLES = [
  {
    id: 'consensus',
    name: 'Consensus',
    description: 'All board members must agree — cautious but thorough',
    icon: '\u{1F91D}',  // handshake
  },
  {
    id: 'majority',
    name: 'Majority Rule',
    description: 'Simple majority carries the vote — balanced pace',
    icon: '\u{1F5F3}',  // ballot box
  },
  {
    id: 'executive',
    name: 'Executive Authority',
    description: 'CEO decides, board advises — fast-moving',
    icon: '\u{26A1}',   // lightning
  },
]

const STEP_LABELS = ['Welcome', 'Account', 'Your Board', 'Your Team', 'Launch']

// ── Component ────────────────────────────────────────────────────────

export function OnboardPage() {
  const navigate = useNavigate()
  const [step, setStep] = useState(0)

  // Step 1 — Account
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  // Step 2 — Board
  const [boardName, setBoardName] = useState('')
  const [governanceStyle, setGovernanceStyle] = useState('majority')

  // Step 3 — Team
  const [selectedRoles, setSelectedRoles] = useState<Set<string>>(
    new Set(['ceo', 'cfo', 'cto', 'counsel']) // sensible defaults
  )

  const [error, setError] = useState('')
  const [launching, setLaunching] = useState(false)

  function toggleRole(id: string) {
    setSelectedRoles(prev => {
      const next = new Set(prev)
      if (next.has(id)) {
        if (next.size <= 2) return prev // min 2 board members
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  function validateStep(): string | null {
    if (step === 1) {
      if (!displayName.trim()) return 'Display name is required'
      if (!email.trim() || !email.includes('@')) return 'Valid email is required'
      if (password.length < 8) return 'Password must be at least 8 characters'
      if (password !== confirmPassword) return 'Passwords do not match'
    }
    if (step === 2) {
      if (!boardName.trim()) return 'Give your board a name'
    }
    if (step === 3) {
      if (selectedRoles.size < 2) return 'Select at least 2 board members'
    }
    return null
  }

  function next() {
    const err = validateStep()
    if (err) {
      setError(err)
      return
    }
    setError('')
    if (step === 3) {
      // Moving to launch step
      setStep(4)
      return
    }
    setStep(s => s + 1)
  }

  function back() {
    setError('')
    setStep(s => Math.max(0, s - 1))
  }

  async function handleLaunch() {
    setLaunching(true)
    setError('')

    // Persist onboarding state to localStorage so the dashboard can read it
    const onboardingData = {
      displayName: displayName.trim(),
      email: email.trim(),
      boardName: boardName.trim(),
      governanceStyle,
      boardMembers: BOARD_ROLES.filter(r => selectedRoles.has(r.id)),
      createdAt: new Date().toISOString(),
    }
    localStorage.setItem('ape_onboarding', JSON.stringify(onboardingData))

    // A-031: Only seed the dev-bypass key when the build explicitly opts
    // in via VITE_ALLOW_DEV_BYPASS=true. In a production bundle this
    // block evaporates (both conditions are compile-time false) so
    // end-users cannot auto-escalate to admin via onboarding.
    if (import.meta.env.DEV && import.meta.env.VITE_ALLOW_DEV_BYPASS === 'true') {
      localStorage.setItem('df_dev_bypass', '1')
      localStorage.setItem('df_token', 'ape-onboard-token')
    }

    // Try to register with the backend if available
    try {
      const res = await fetch('/api/v1/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          displayName: displayName.trim(),
          email: email.trim(),
          password,
        }),
      })
      if (res.ok) {
        const data = await res.json()
        if (data.token) localStorage.setItem('df_token', data.token)
      }
      // If backend unavailable, dev bypass handles it
    } catch {
      // Backend not available — dev bypass will handle auth
    }

    // Brief pause for the launch animation
    await new Promise(r => setTimeout(r, 1200))
    navigate('/APE/dashboard', { replace: true })
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex flex-col">
      {/* Progress bar */}
      <div className="w-full bg-slate-800/50 border-b border-slate-700">
        <div className="max-w-3xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            {STEP_LABELS.map((label, i) => (
              <div key={label} className="flex items-center">
                <div className="flex flex-col items-center">
                  <div
                    className={cn(
                      'w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all duration-300',
                      i < step
                        ? 'bg-emerald-500 text-white'
                        : i === step
                          ? 'bg-blue-500 text-white ring-2 ring-blue-400 ring-offset-2 ring-offset-slate-900'
                          : 'bg-slate-700 text-slate-500'
                    )}
                  >
                    {i < step ? '\u2713' : i + 1}
                  </div>
                  <span
                    className={cn(
                      'mt-1 text-xs font-medium hidden sm:block',
                      i <= step ? 'text-slate-300' : 'text-slate-600'
                    )}
                  >
                    {label}
                  </span>
                </div>
                {i < STEP_LABELS.length - 1 && (
                  <div
                    className={cn(
                      'w-8 sm:w-16 h-0.5 mx-1 sm:mx-2 mb-4 transition-colors',
                      i < step ? 'bg-emerald-500' : 'bg-slate-700'
                    )}
                  />
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Step content */}
      <div className="flex-1 flex items-center justify-center px-4 py-8">
        <div className="w-full max-w-2xl">
          {error && (
            <div className="mb-4 rounded-lg bg-red-500/10 border border-red-500/30 p-3 text-sm text-red-300">
              {error}
            </div>
          )}

          {/* ── Step 0: Welcome ─────────────────────────────── */}
          {step === 0 && (
            <div className="text-center">
              <div className="text-6xl mb-6">{'\u{1F680}'}</div>
              <h1 className="text-4xl font-bold text-white mb-3">
                Welcome to ExoChain
              </h1>
              <p className="text-lg text-slate-400 mb-2">
                Autonomous Portfolio Engine
              </p>
              <div className="mt-8 max-w-lg mx-auto text-left space-y-4">
                <FeatureCard
                  icon={'\u{1F3DB}'}
                  title="Your Own Board of Directors"
                  desc="Assemble a personal governance council of AI agents that deliberate, vote, and execute on your behalf."
                />
                <FeatureCard
                  icon={'\u{1F916}'}
                  title="Agent Teams That Serve You"
                  desc="Each board member commands specialized agents — research, analysis, execution — working 24/7."
                />
                <FeatureCard
                  icon={'\u{1F512}'}
                  title="Constitutional Governance"
                  desc="Every action is audited, every decision is transparent, every agent is accountable to you."
                />
              </div>
              <button
                onClick={() => setStep(1)}
                className="mt-10 px-8 py-3 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl text-lg transition-colors"
              >
                Get Started
              </button>
              <p className="mt-4 text-xs text-slate-600">
                AVC Cohort Onboarding
              </p>
            </div>
          )}

          {/* ── Step 1: Account ─────────────────────────────── */}
          {step === 1 && (
            <div className="bg-slate-800/50 rounded-2xl border border-slate-700 p-8">
              <h2 className="text-2xl font-bold text-white mb-1">Create Your Account</h2>
              <p className="text-sm text-slate-400 mb-6">
                Your governance identity on the ExoChain network.
              </p>
              <form
                onSubmit={(e: FormEvent) => { e.preventDefault(); next() }}
                className="space-y-4"
              >
                <Field label="Display Name" id="onb-name">
                  <input
                    id="onb-name"
                    type="text"
                    required
                    autoComplete="name"
                    autoFocus
                    value={displayName}
                    onChange={e => setDisplayName(e.target.value)}
                    className={inputClass}
                    placeholder="Your name"
                  />
                </Field>
                <Field label="Email" id="onb-email">
                  <input
                    id="onb-email"
                    type="email"
                    required
                    autoComplete="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    className={inputClass}
                    placeholder="you@example.com"
                  />
                </Field>
                <div className="grid grid-cols-2 gap-4">
                  <Field label="Password" id="onb-pw">
                    <input
                      id="onb-pw"
                      type="password"
                      required
                      autoComplete="new-password"
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      className={inputClass}
                      placeholder="Min 8 characters"
                    />
                  </Field>
                  <Field label="Confirm" id="onb-pw2">
                    <input
                      id="onb-pw2"
                      type="password"
                      required
                      autoComplete="new-password"
                      value={confirmPassword}
                      onChange={e => setConfirmPassword(e.target.value)}
                      className={inputClass}
                      placeholder="Repeat password"
                    />
                  </Field>
                </div>
                <div className="flex justify-between pt-4">
                  <button type="button" onClick={back} className={backBtnClass}>Back</button>
                  <button type="submit" className={nextBtnClass}>Continue</button>
                </div>
              </form>
            </div>
          )}

          {/* ── Step 2: Board Setup ────────────────────────── */}
          {step === 2 && (
            <div className="bg-slate-800/50 rounded-2xl border border-slate-700 p-8">
              <h2 className="text-2xl font-bold text-white mb-1">Name Your Board</h2>
              <p className="text-sm text-slate-400 mb-6">
                Your Board of Directors will govern your autonomous portfolio.
                Every decision passes through them.
              </p>
              <Field label="Board Name" id="onb-board">
                <input
                  id="onb-board"
                  type="text"
                  autoFocus
                  value={boardName}
                  onChange={e => setBoardName(e.target.value)}
                  className={inputClass}
                  placeholder={`${displayName || 'My'}'s Board of Directors`}
                />
              </Field>

              <div className="mt-6">
                <label className="block text-sm font-medium text-slate-300 mb-3">
                  Governance Style
                </label>
                <div className="grid gap-3">
                  {GOVERNANCE_STYLES.map(gs => (
                    <button
                      key={gs.id}
                      type="button"
                      onClick={() => setGovernanceStyle(gs.id)}
                      className={cn(
                        'flex items-start gap-3 p-4 rounded-xl border text-left transition-all',
                        governanceStyle === gs.id
                          ? 'border-blue-500 bg-blue-500/10 ring-1 ring-blue-500/50'
                          : 'border-slate-600 bg-slate-800/30 hover:border-slate-500'
                      )}
                    >
                      <span className="text-2xl mt-0.5">{gs.icon}</span>
                      <div>
                        <div className={cn(
                          'font-semibold text-sm',
                          governanceStyle === gs.id ? 'text-blue-300' : 'text-slate-300'
                        )}>
                          {gs.name}
                        </div>
                        <div className="text-xs text-slate-500 mt-0.5">{gs.description}</div>
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex justify-between pt-6">
                <button type="button" onClick={back} className={backBtnClass}>Back</button>
                <button type="button" onClick={next} className={nextBtnClass}>Continue</button>
              </div>
            </div>
          )}

          {/* ── Step 3: Team Assembly ──────────────────────── */}
          {step === 3 && (
            <div className="bg-slate-800/50 rounded-2xl border border-slate-700 p-8">
              <h2 className="text-2xl font-bold text-white mb-1">Assemble Your Team</h2>
              <p className="text-sm text-slate-400 mb-6">
                Select the board members who will serve on{' '}
                <span className="text-slate-300 font-medium">{boardName || 'your board'}</span>.
                Each brings specialized agents. Minimum 2.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {BOARD_ROLES.map(role => {
                  const selected = selectedRoles.has(role.id)
                  return (
                    <button
                      key={role.id}
                      type="button"
                      onClick={() => toggleRole(role.id)}
                      className={cn(
                        'flex items-start gap-3 p-4 rounded-xl border text-left transition-all',
                        selected
                          ? 'border-emerald-500 bg-emerald-500/10 ring-1 ring-emerald-500/50'
                          : 'border-slate-600 bg-slate-800/30 hover:border-slate-500'
                      )}
                    >
                      <span className="text-2xl">{role.icon}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={cn(
                            'font-semibold text-sm',
                            selected ? 'text-emerald-300' : 'text-slate-300'
                          )}>
                            {role.title}
                          </span>
                          <span className={cn(
                            'text-xs px-1.5 py-0.5 rounded font-mono',
                            selected
                              ? 'bg-emerald-500/20 text-emerald-400'
                              : 'bg-slate-700 text-slate-500'
                          )}>
                            {role.shortTitle}
                          </span>
                        </div>
                        <div className="text-xs text-slate-500 mt-1">{role.description}</div>
                        <div className="flex flex-wrap gap-1 mt-2">
                          {role.capabilities.map(c => (
                            <span
                              key={c}
                              className="text-2xs px-1.5 py-0.5 rounded bg-slate-700/50 text-slate-500"
                            >
                              {c}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className={cn(
                        'w-5 h-5 rounded border-2 flex items-center justify-center flex-shrink-0 mt-1 transition-colors',
                        selected
                          ? 'border-emerald-500 bg-emerald-500 text-white'
                          : 'border-slate-600'
                      )}>
                        {selected && <span className="text-xs">{'\u2713'}</span>}
                      </div>
                    </button>
                  )
                })}
              </div>
              <div className="mt-4 text-xs text-slate-500 text-center">
                {selectedRoles.size} board member{selectedRoles.size !== 1 ? 's' : ''} selected
              </div>
              <div className="flex justify-between pt-4">
                <button type="button" onClick={back} className={backBtnClass}>Back</button>
                <button type="button" onClick={next} className={nextBtnClass}>
                  Assemble Board
                </button>
              </div>
            </div>
          )}

          {/* ── Step 4: Launch ─────────────────────────────── */}
          {step === 4 && (
            <div className="text-center">
              {!launching ? (
                <>
                  <div className="text-6xl mb-6">{'\u2705'}</div>
                  <h2 className="text-3xl font-bold text-white mb-3">Ready to Launch</h2>
                  <p className="text-slate-400 mb-8 max-w-md mx-auto">
                    <span className="text-white font-medium">{boardName}</span> is assembled with{' '}
                    <span className="text-emerald-400 font-medium">{selectedRoles.size} board members</span>{' '}
                    operating under{' '}
                    <span className="text-blue-400 font-medium">
                      {GOVERNANCE_STYLES.find(g => g.id === governanceStyle)?.name}
                    </span>{' '}
                    governance.
                  </p>

                  <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6 max-w-md mx-auto mb-8 text-left">
                    <div className="text-xs font-medium text-slate-500 uppercase mb-3">Your Board</div>
                    <div className="space-y-2">
                      {BOARD_ROLES.filter(r => selectedRoles.has(r.id)).map(role => (
                        <div key={role.id} className="flex items-center gap-2 text-sm">
                          <span>{role.icon}</span>
                          <span className="text-slate-300">{role.title}</span>
                          <span className="text-xs text-slate-600 font-mono ml-auto">{role.shortTitle}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="flex justify-center gap-4">
                    <button type="button" onClick={back} className={backBtnClass}>Back</button>
                    <button
                      type="button"
                      onClick={handleLaunch}
                      className="px-10 py-3 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-xl text-lg transition-colors"
                    >
                      Launch My Board {'\u{1F680}'}
                    </button>
                  </div>
                </>
              ) : (
                <div className="animate-pulse">
                  <div className="text-6xl mb-6">{'\u{1F680}'}</div>
                  <h2 className="text-2xl font-bold text-white mb-2">Launching...</h2>
                  <p className="text-slate-500">Provisioning your board and agent team</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Shared UI pieces ────────────────────────────────────────────────

function FeatureCard({ icon, title, desc }: { icon: string; title: string; desc: string }) {
  return (
    <div className="flex items-start gap-4 bg-slate-800/40 border border-slate-700/50 rounded-xl p-4">
      <span className="text-2xl">{icon}</span>
      <div>
        <div className="font-semibold text-slate-200 text-sm">{title}</div>
        <div className="text-xs text-slate-500 mt-0.5">{desc}</div>
      </div>
    </div>
  )
}

function Field({ label, id, children }: { label: string; id: string; children: React.ReactNode }) {
  return (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-slate-300 mb-1">
        {label}
      </label>
      {children}
    </div>
  )
}

const inputClass =
  'block w-full rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'

const nextBtnClass =
  'px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg text-sm transition-colors'

const backBtnClass =
  'px-6 py-2 text-slate-400 hover:text-slate-200 font-medium rounded-lg text-sm transition-colors'
