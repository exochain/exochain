import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react'
import { api } from './api'
import type { PaceStatus } from './types'

export interface AuthUser {
  did: string
  displayName: string
  email: string
  roles: string[]
  paceStatus: PaceStatus
  trustTier: string
  trustScore: number
}

interface AuthContextType {
  user: AuthUser | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (email: string, password: string) => Promise<void>
  register: (displayName: string, email: string, password: string) => Promise<void>
  logout: () => void
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | null>(null)

const TOKEN_KEY = 'df_token'
const REFRESH_KEY = 'df_refresh_token'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(TOKEN_KEY))
  const [isLoading, setIsLoading] = useState(true)

  const storeTokens = useCallback((accessToken: string, refreshToken: string) => {
    localStorage.setItem(TOKEN_KEY, accessToken)
    localStorage.setItem(REFRESH_KEY, refreshToken)
    setToken(accessToken)
  }, [])

  const clearAuth = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(REFRESH_KEY)
    setToken(null)
    setUser(null)
  }, [])

  const refreshUser = useCallback(async () => {
    try {
      const profile = await api.auth.me()
      setUser({
        did: profile.did,
        displayName: profile.displayName,
        email: profile.email,
        roles: profile.roles,
        paceStatus: profile.paceStatus,
        trustTier: profile.trustTier,
        trustScore: profile.trustScore,
      })
    } catch {
      clearAuth()
    }
  }, [clearAuth])

  // On mount, validate stored token
  useEffect(() => {
    // Dev preview mode: skip API validation when backend is unavailable
    if (import.meta.env.DEV && localStorage.getItem('df_dev_bypass') === '1') {
      setUser({
        did: 'did:exo:dev-preview',
        displayName: 'Dev Preview',
        email: 'dev@exochain.io',
        roles: ['admin'],
        paceStatus: 'verified' as PaceStatus,
        trustTier: 'Gold',
        trustScore: 7500,
      })
      if (!token) {
        localStorage.setItem(TOKEN_KEY, 'dev-preview-token')
        setToken('dev-preview-token')
      }
      setIsLoading(false)
      return
    }
    if (token) {
      refreshUser().finally(() => setIsLoading(false))
    } else {
      setIsLoading(false)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const login = useCallback(async (email: string, password: string) => {
    const res = await api.auth.login({ email, password })
    storeTokens(res.token, res.refreshToken)
    setUser({
      did: res.user.did,
      displayName: res.user.displayName,
      email: res.user.email,
      roles: res.user.roles,
      paceStatus: res.user.paceStatus,
      trustTier: res.user.trustTier,
      trustScore: res.user.trustScore,
    })
  }, [storeTokens])

  const register = useCallback(async (displayName: string, email: string, password: string) => {
    const res = await api.auth.register({ displayName, email, password })
    storeTokens(res.token, res.refreshToken)
    setUser({
      did: res.did,
      displayName: res.displayName,
      email: res.email,
      roles: [],
      paceStatus: res.paceStatus,
      trustTier: 'Untrusted',
      trustScore: 0,
    })
  }, [storeTokens])

  const logout = useCallback(() => {
    api.auth.logout().catch(() => { /* best-effort */ })
    clearAuth()
  }, [clearAuth])

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return ctx
}
