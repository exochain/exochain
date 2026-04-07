import { useState, useEffect, useCallback, useRef } from 'react'
import { Outlet, Link, useLocation, useNavigate } from 'react-router-dom'
import { cn } from '../lib/utils'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { AmbientStatusBar } from './AmbientStatusBar'
import { ThemeSwitcher } from './ThemeSwitcher'
import { CouncilAIPanel } from './CouncilAIPanel'
import { useCouncil } from '../lib/CouncilContext'
import { CgrKernelStatus } from './CgrKernelStatus'
import type { HealthInfo } from '../lib/types'

interface NavItem {
  path: string
  label: string
  ariaLabel: string
  /** SVG path data for mobile/tablet bottom nav icons */
  icon: string
}

const navItems: NavItem[] = [
  {
    path: '/',
    label: 'Command',
    ariaLabel: 'Command center — governance control surface',
    // Grid icon
    icon: 'M4 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1V5zm10 0a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM4 15a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1v-4zm10 0a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z',
  },
  {
    path: '/decisions',
    label: 'Decisions',
    ariaLabel: 'Decision dashboard',
    // Home icon
    icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-4 0a1 1 0 01-1-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 01-1 1h-2z',
  },
  {
    path: '/delegations',
    label: 'Delegations',
    ariaLabel: 'Authority delegations',
    // Link icon
    icon: 'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1',
  },
  {
    path: '/decisions/new',
    label: '+ New',
    ariaLabel: 'Create new decision',
    // Plus icon
    icon: 'M12 4v16m8-8H4',
  },
]

const sidebarNavItems = [
  ...navItems.slice(0, 3),
  {
    path: '/audit',
    label: 'Audit',
    ariaLabel: 'Governance audit trail',
    icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2',
  },
  {
    path: '/constitution',
    label: 'Constitution',
    ariaLabel: 'Governance constitution',
    icon: '',
  },
  {
    path: '/identity',
    label: 'Identity',
    ariaLabel: 'Governance identity profile',
    icon: '',
  },
  {
    path: '/agents',
    label: 'Agents',
    ariaLabel: 'Agent registry and management',
    icon: '',
  },
  {
    path: '/dev',
    label: 'Dev Board',
    ariaLabel: 'Development completeness board',
    icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01',
  },
  navItems[3], // + New
]

const applicationNavItems: NavItem[] = [
  {
    path: '/applications/livesafe',
    label: 'LiveSafe.ai',
    ariaLabel: 'LiveSafe.ai integration status',
    icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
  },
]

/** External application links (open in new tab). */
const externalNavItems: { href: string; label: string; ariaLabel: string }[] = [
  {
    href: import.meta.env.DEV ? 'http://localhost:3000' : '/command-base',
    label: 'Command Base',
    ariaLabel: 'CommandBase.ai — task force operations hub',
  },
]

export function Layout() {
  const location = useLocation()
  const navigate = useNavigate()
  const { user, isAuthenticated, logout } = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [statusBarExpanded, setStatusBarExpanded] = useState(true)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const userMenuRef = useRef<HTMLDivElement>(null)
  const { togglePanel, openTicketCount } = useCouncil()

  // Close user menu on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setUserMenuOpen(false)
      }
    }
    if (userMenuOpen) {
      document.addEventListener('mousedown', handleClick)
      return () => document.removeEventListener('mousedown', handleClick)
    }
  }, [userMenuOpen])

  // Ambient status data
  const [health, setHealth] = useState<HealthInfo | null>(null)
  const [decisions, setDecisions] = useState<{ pending: number; overdue: number; voting: number }>({
    pending: 0,
    overdue: 0,
    voting: 0,
  })
  const [chainInfo, setChainInfo] = useState<{ verified: boolean; length: number }>({
    verified: false,
    length: 0,
  })

  // Fetch health + decision counts + chain integrity on mount
  useEffect(() => {
    let cancelled = false

    async function fetchAmbientData() {
      try {
        const [healthData, decisionList, auditVerify] = await Promise.allSettled([
          api.health(),
          api.decisions.list(),
          api.audit.verify(),
        ])

        if (cancelled) return

        if (healthData.status === 'fulfilled') {
          setHealth(healthData.value)
        }

        if (decisionList.status === 'fulfilled') {
          const list = decisionList.value
          setDecisions({
            pending: list.filter(d => d.status === 'Created' || d.status === 'Deliberation').length,
            overdue: list.filter(d => d.status === 'RatificationExpired' || d.status === 'DegradedGovernance').length,
            voting: list.filter(d => d.status === 'Voting').length,
          })
        }

        if (auditVerify.status === 'fulfilled') {
          setChainInfo({
            verified: auditVerify.value.verified,
            length: auditVerify.value.chainLength,
          })
        }
      } catch {
        // Ambient data is non-critical; fail silently
      }
    }

    fetchAmbientData()
    return () => { cancelled = true }
  }, [])

  // Close sidebar on navigation (mobile/tablet)
  useEffect(() => {
    setSidebarOpen(false)
  }, [location.pathname])

  const closeSidebar = useCallback(() => setSidebarOpen(false), [])

  // Keyboard shortcut: Ctrl+J to toggle Council AI
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'j') {
        e.preventDefault()
        togglePanel()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [togglePanel])

  const isActive = (path: string) => {
    if (path === '/') return location.pathname === '/'
    return location.pathname.startsWith(path)
  }

  return (
    <div className="min-h-screen flex flex-col bg-surface-base font-display">
      {/* Skip to main content — WCAG 2.2 AA */}
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>

      {/* Header */}
      <header className="sticky top-0 z-30 bg-surface-raised border-b border-border-subtle" role="banner">
        <div className="flex items-center justify-between h-14 px-4 desktop:pl-0">
          {/* Hamburger for mobile/tablet */}
          <button
            className="desktop:hidden p-2 -ml-2 rounded-md text-text-gov-secondary hover:bg-surface-overlay focus-visible:outline-2 focus-visible:outline-accent-primary"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label={sidebarOpen ? 'Close navigation menu' : 'Open navigation menu'}
            aria-expanded={sidebarOpen}
            aria-controls="sidebar-nav"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              {sidebarOpen ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              )}
            </svg>
          </button>

          {/* Logo */}
          <Link
            to="/"
            className="text-lg font-bold tracking-tight text-text-gov-primary desktop:w-sidebar desktop:text-center desktop:border-r desktop:border-border-subtle desktop:py-3"
            aria-label="decision.forum home"
          >
            decision.forum
          </Link>

          {/* Breadcrumb area / spacer */}
          <div className="hidden desktop:flex flex-1 items-center px-6 justify-between">
            <nav aria-label="Breadcrumb">
              <span className="text-sm text-text-gov-secondary">
                {getBreadcrumb(location.pathname)}
              </span>
            </nav>
            <CgrKernelStatus />
          </div>

          {/* Theme + User menu */}
          <div className="flex items-center gap-2">
          <ThemeSwitcher />
          <div className="relative" ref={userMenuRef}>
            {isAuthenticated && user ? (
              <>
                <button
                  onClick={() => setUserMenuOpen(!userMenuOpen)}
                  className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-surface-overlay focus-visible:outline-2 focus-visible:outline-accent-primary"
                  aria-label="User menu"
                  aria-expanded={userMenuOpen}
                  aria-haspopup="true"
                >
                  <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold">
                    {user.displayName.charAt(0).toUpperCase()}
                  </div>
                  <span className="hidden tablet:block text-sm font-medium text-text-gov-primary max-w-[120px] truncate">
                    {user.displayName}
                  </span>
                  <span className={cn(
                    'hidden tablet:inline-flex items-center rounded-full px-1.5 py-0.5 text-2xs font-semibold',
                    user.trustScore >= 900 ? 'bg-green-100 text-green-800'
                      : user.trustScore >= 700 ? 'bg-blue-100 text-blue-800'
                      : user.trustScore >= 500 ? 'bg-slate-100 text-slate-700'
                      : user.trustScore >= 300 ? 'bg-amber-100 text-amber-800'
                      : 'bg-red-100 text-red-800'
                  )}>
                    {user.trustScore}
                  </span>
                </button>

                {userMenuOpen && (
                  <div className="absolute right-0 mt-1 w-56 bg-white rounded-lg shadow-lg border border-slate-200 py-1 z-50">
                    {/* AI Section */}
                    <div className="px-3 py-1.5">
                      <span className="text-2xs font-semibold uppercase tracking-wider text-slate-400">AI & Council</span>
                    </div>
                    <button
                      onClick={() => { setUserMenuOpen(false); togglePanel() }}
                      className="flex items-center justify-between w-full text-left px-4 py-2 text-sm text-slate-700 hover:bg-violet-50 hover:text-violet-700 focus-visible:outline-2 focus-visible:outline-accent-primary"
                    >
                      <span className="flex items-center gap-2">
                        <svg className="w-4 h-4 text-violet-500" viewBox="0 0 24 24" fill="currentColor">
                          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
                        </svg>
                        Council AI
                      </span>
                      <div className="flex items-center gap-1">
                        <kbd className="text-2xs text-slate-400 bg-slate-100 px-1 rounded font-mono">^J</kbd>
                        {openTicketCount > 0 && (
                          <span className="inline-flex items-center justify-center min-w-[1.25rem] h-5 rounded-full bg-violet-500 text-white text-2xs font-bold px-1">
                            {openTicketCount}
                          </span>
                        )}
                      </div>
                    </button>
                    <Link
                      to="/agents"
                      onClick={() => setUserMenuOpen(false)}
                      className="flex items-center gap-2 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-accent-primary"
                    >
                      <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                      </svg>
                      Agent Registry
                    </Link>

                    <hr className="my-1 border-slate-200" />

                    {/* Identity Section */}
                    <div className="px-3 py-1.5">
                      <span className="text-2xs font-semibold uppercase tracking-wider text-slate-400">Identity</span>
                    </div>
                    <Link
                      to="/identity"
                      onClick={() => setUserMenuOpen(false)}
                      className="flex items-center gap-2 px-4 py-2 text-sm text-slate-700 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-accent-primary"
                    >
                      <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                      </svg>
                      Governance Identity
                    </Link>
                    <Link
                      to="/identity/pace"
                      onClick={() => setUserMenuOpen(false)}
                      className="flex items-center gap-2 px-4 py-2 text-sm text-slate-700 hover:bg-emerald-50 hover:text-emerald-700 focus-visible:outline-2 focus-visible:outline-accent-primary"
                    >
                      <svg className="w-4 h-4 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                      PACE Enrollment
                    </Link>

                    <hr className="my-1 border-slate-200" />

                    {/* Dev Section */}
                    <Link
                      to="/dev"
                      onClick={() => setUserMenuOpen(false)}
                      className="flex items-center gap-2 px-4 py-2 text-sm text-slate-700 hover:bg-blue-50 hover:text-blue-700 focus-visible:outline-2 focus-visible:outline-accent-primary"
                    >
                      <svg className="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
                      </svg>
                      Dev Completeness
                    </Link>

                    <hr className="my-1 border-slate-200" />

                    <button
                      onClick={() => { setUserMenuOpen(false); logout(); navigate('/login') }}
                      className="flex items-center gap-2 w-full text-left px-4 py-2 text-sm text-slate-700 hover:bg-slate-50 focus-visible:outline-2 focus-visible:outline-accent-primary"
                    >
                      <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                      </svg>
                      Sign Out
                    </button>
                  </div>
                )}
              </>
            ) : (
              <Link
                to="/login"
                className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
              >
                Sign In
              </Link>
            )}
          </div>

          </div>{/* end theme+user */}

          {/* Tablet status toggle */}
          <button
            className="hidden tablet:block desktop:hidden p-2 rounded-md text-text-gov-secondary hover:bg-surface-overlay"
            onClick={() => setStatusBarExpanded(!statusBarExpanded)}
            aria-label={statusBarExpanded ? 'Collapse status bar' : 'Expand status bar'}
            aria-expanded={statusBarExpanded}
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={statusBarExpanded ? 'M5 15l7-7 7 7' : 'M19 9l-7 7-7-7'} />
            </svg>
          </button>
        </div>
      </header>

      {/* Tablet ambient status bar (collapsible) */}
      <div className={cn(
        'hidden tablet:block desktop:hidden transition-all overflow-hidden',
        statusBarExpanded ? 'max-h-20' : 'max-h-0'
      )}>
        <AmbientStatusBar
          pendingCount={decisions.pending}
          overdueCount={decisions.overdue}
          votingCount={decisions.voting}
          healthOk={health?.status === 'ok'}
          chainVerified={chainInfo.verified}
          chainLength={chainInfo.length}
          mode="topbar"
        />
      </div>

      {/* Body: sidebar + main */}
      <div className="flex flex-1 relative">
        {/* Sidebar overlay backdrop (mobile/tablet) */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 z-40 bg-black/30 desktop:hidden"
            onClick={closeSidebar}
            aria-hidden="true"
          />
        )}

        {/* Sidebar */}
        <aside
          id="sidebar-nav"
          className={cn(
            'fixed top-14 bottom-0 left-0 z-50 w-sidebar bg-surface-raised border-r border-border-subtle flex flex-col overflow-y-auto transition-transform duration-200',
            'desktop:static desktop:translate-x-0 desktop:z-auto',
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          )}
          role="complementary"
          aria-label="Situation room sidebar"
        >
          {/* Ambient Status */}
          <AmbientStatusBar
            pendingCount={decisions.pending}
            overdueCount={decisions.overdue}
            votingCount={decisions.voting}
            healthOk={health?.status === 'ok'}
            chainVerified={chainInfo.verified}
            chainLength={chainInfo.length}
            mode="sidebar"
          />

          <hr className="border-border-subtle" />

          {/* Quick Navigation */}
          <nav className="flex-1 px-3 py-4" aria-label="Quick navigation">
            <h2 className="px-2 text-xs font-semibold uppercase tracking-wider text-text-gov-secondary mb-2">
              Navigation
            </h2>
            <ul className="space-y-0.5">
              {sidebarNavItems.map((item) => (
                <li key={item.path}>
                  <Link
                    to={item.path}
                    aria-label={item.ariaLabel}
                    aria-current={isActive(item.path) ? 'page' : undefined}
                    className={cn(
                      'flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                      isActive(item.path)
                        ? 'bg-accent-primary/10 text-accent-primary'
                        : 'text-text-gov-secondary hover:bg-surface-overlay hover:text-text-gov-primary'
                    )}
                  >
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>

            {/* Applications section */}
            <h2 className="px-2 text-xs font-semibold uppercase tracking-wider text-text-gov-secondary mb-2 mt-5">
              Applications
            </h2>
            <ul className="space-y-0.5">
              {applicationNavItems.map((item) => (
                <li key={item.path}>
                  <Link
                    to={item.path}
                    aria-label={item.ariaLabel}
                    aria-current={isActive(item.path) ? 'page' : undefined}
                    className={cn(
                      'flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors',
                      isActive(item.path)
                        ? 'bg-accent-primary/10 text-accent-primary'
                        : 'text-text-gov-secondary hover:bg-surface-overlay hover:text-text-gov-primary'
                    )}
                  >
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>

            {/* External links */}
            <h2 className="px-2 text-xs font-semibold uppercase tracking-wider text-text-gov-secondary mb-2 mt-5">
              External
            </h2>
            <ul className="space-y-0.5">
              {externalNavItems.map((item) => (
                <li key={item.href}>
                  <a
                    href={item.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={item.ariaLabel}
                    className="flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors text-text-gov-secondary hover:bg-surface-overlay hover:text-text-gov-primary"
                  >
                    {item.label}
                    <svg className="w-3 h-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        </aside>

        {/* Main content area */}
        <main
          id="main-content"
          className="flex-1 min-w-0 px-4 tablet:px-6 desktop:px-8 py-6 desktop:py-8"
          role="main"
        >
          <Outlet />
        </main>
      </div>

      {/* Mobile bottom navigation bar */}
      <nav
        className="tablet:hidden fixed bottom-0 inset-x-0 z-30 bg-surface-raised border-t border-border-subtle safe-area-bottom"
        aria-label="Mobile navigation"
      >
        <ul className="flex items-center justify-around h-14">
          {navItems.map((item) => (
            <li key={item.path} className="flex-1">
              <button
                onClick={() => navigate(item.path)}
                aria-label={item.ariaLabel}
                aria-current={isActive(item.path) ? 'page' : undefined}
                className={cn(
                  'flex flex-col items-center justify-center w-full h-14 gap-0.5 text-2xs font-medium transition-colors',
                  isActive(item.path)
                    ? 'text-accent-primary'
                    : 'text-text-gov-secondary'
                )}
              >
                <span className="relative">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                  </svg>
                  {/* Badge counts on mobile nav icons */}
                  {item.path === '/' && (decisions.pending > 0 || decisions.overdue > 0) && (
                    <span className="absolute -top-1.5 -right-2">
                      <AmbientStatusBar
                        pendingCount={decisions.pending}
                        overdueCount={decisions.overdue}
                        votingCount={0}
                        healthOk={true}
                        chainVerified={true}
                        chainLength={0}
                        mode="badges"
                      />
                    </span>
                  )}
                  {item.path === '/audit' && decisions.voting > 0 && (
                    <span className="absolute -top-1.5 -right-2 inline-flex items-center justify-center min-w-[1.25rem] h-5 rounded-full bg-status-voting text-white text-2xs font-bold px-1">
                      {decisions.voting}
                    </span>
                  )}
                </span>
                <span>{item.label}</span>
              </button>
            </li>
          ))}
        </ul>
      </nav>

      {/* Tablet bottom tab bar */}
      <nav
        className="hidden tablet:block desktop:hidden fixed bottom-0 inset-x-0 z-30 bg-surface-raised border-t border-border-subtle"
        aria-label="Tablet navigation"
      >
        <ul className="flex items-center justify-around h-14">
          {navItems.map((item) => (
            <li key={item.path} className="flex-1">
              <button
                onClick={() => navigate(item.path)}
                aria-label={item.ariaLabel}
                aria-current={isActive(item.path) ? 'page' : undefined}
                className={cn(
                  'flex flex-col items-center justify-center w-full h-14 gap-0.5 text-xs font-medium transition-colors',
                  isActive(item.path)
                    ? 'text-accent-primary'
                    : 'text-text-gov-secondary'
                )}
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                </svg>
                <span>{item.label}</span>
              </button>
            </li>
          ))}
        </ul>
      </nav>

      {/* Bottom padding for mobile/tablet to account for fixed bottom nav */}
      <div className="h-14 desktop:hidden" aria-hidden="true" />

      {/* Floating Council AI button */}
      <button
        onClick={togglePanel}
        className="fixed bottom-20 tablet:bottom-20 desktop:bottom-6 right-6 z-30 w-12 h-12 rounded-full bg-gradient-to-br from-violet-500 to-blue-500 text-white shadow-lg hover:shadow-xl hover:scale-105 transition-all flex items-center justify-center"
        aria-label="Open Council AI assistant"
        title="Council AI (Ctrl+J)"
      >
        <svg className="w-6 h-6" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
        </svg>
        {openTicketCount > 0 && (
          <span className="absolute -top-1 -right-1 inline-flex items-center justify-center min-w-[1.25rem] h-5 rounded-full bg-red-500 text-white text-2xs font-bold px-1 shadow">
            {openTicketCount}
          </span>
        )}
      </button>

      {/* Council AI Panel */}
      <CouncilAIPanel />
    </div>
  )
}

/** Generate breadcrumb text from the current path. */
function getBreadcrumb(pathname: string): string {
  if (pathname === '/') return 'Command Center'
  if (pathname === '/decisions') return 'Decisions'
  if (pathname === '/decisions/new') return 'Decisions / New Decision'
  if (pathname.startsWith('/decisions/')) return 'Decisions / Decision Dossier'
  if (pathname === '/delegations') return 'Authority Map'
  if (pathname === '/audit') return 'Audit Ledger'
  if (pathname === '/constitution') return 'Constitution'
  if (pathname === '/identity') return 'Governance Identity'
  if (pathname === '/agents') return 'Agent Registry'
  if (pathname === '/identity/pace') return 'Identity / PACE Enrollment'
  if (pathname === '/dev') return 'Development Completeness'
  if (pathname === '/applications/livesafe') return 'Applications / LiveSafe.ai'
  return ''
}
