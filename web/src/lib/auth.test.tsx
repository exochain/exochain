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

import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider, useAuth } from './auth'

function renderedValue(value: unknown): string {
  return typeof value === 'string' ? value : `non-string:${typeof value}`
}

function AuthProbe() {
  const auth = useAuth()

  return (
    <dl>
      <dt>Loading</dt>
      <dd data-testid="loading">{auth.isLoading ? 'loading' : 'ready'}</dd>
      <dt>Display Name</dt>
      <dd data-testid="display-name">{renderedValue(auth.user?.displayName ?? 'none')}</dd>
      <dt>Email</dt>
      <dd data-testid="email">{renderedValue(auth.user?.email ?? 'none')}</dd>
      <dt>Token</dt>
      <dd data-testid="token">{auth.token ?? 'none'}</dd>
    </dl>
  )
}

function renderAuthProvider() {
  return render(
    <AuthProvider>
      <AuthProbe />
    </AuthProvider>
  )
}

describe('AuthProvider dev bypass onboarding storage', () => {
  beforeEach(() => {
    vi.stubEnv('VITE_ALLOW_DEV_BYPASS', 'true')
    localStorage.setItem('df_dev_bypass', '1')
  })

  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('falls back to the dev preview user when onboarding storage is malformed JSON', async () => {
    localStorage.setItem('ape_onboarding', '{not-json')

    renderAuthProvider()

    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'))
    expect(screen.getByTestId('display-name')).toHaveTextContent('Dev Preview')
    expect(screen.getByTestId('email')).toHaveTextContent('dev@exochain.io')
    expect(screen.getByTestId('token')).toHaveTextContent('dev-preview-token')
  })

  it('falls back to typed defaults when onboarding fields are not strings', async () => {
    localStorage.setItem(
      'ape_onboarding',
      JSON.stringify({
        displayName: { text: 'not a string' },
        email: ['dev@example.invalid'],
      })
    )

    renderAuthProvider()

    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'))
    expect(screen.getByTestId('display-name')).toHaveTextContent('Dev Preview')
    expect(screen.getByTestId('email')).toHaveTextContent('dev@exochain.io')
    expect(screen.getByTestId('token')).toHaveTextContent('dev-preview-token')
  })

  it('uses valid onboarding strings for the dev preview user', async () => {
    localStorage.setItem(
      'ape_onboarding',
      JSON.stringify({
        displayName: 'Ada Lovelace',
        email: 'ada@example.invalid',
      })
    )

    renderAuthProvider()

    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'))
    expect(screen.getByTestId('display-name')).toHaveTextContent('Ada Lovelace')
    expect(screen.getByTestId('email')).toHaveTextContent('ada@example.invalid')
    expect(screen.getByTestId('token')).toHaveTextContent('dev-preview-token')
  })
})
