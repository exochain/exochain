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

import { Routes, Route } from 'react-router-dom'
import { Layout } from './components/Layout'
import { RequireAuth } from './components/RequireAuth'
import { DashboardPage } from './pages/DashboardPage'
import { CommandCenterPage } from './pages/CommandCenterPage'
import { DecisionDetailPage } from './pages/DecisionDetailPage'
import { CreateDecisionPage } from './pages/CreateDecisionPage'
import { DelegationsPage } from './pages/DelegationsPage'
import { AuditTrailPage } from './pages/AuditTrailPage'
import { ConstitutionPage } from './pages/ConstitutionPage'
import { LoginPage } from './pages/LoginPage'
import { RegisterPage } from './pages/RegisterPage'
import { IdentityPage } from './pages/IdentityPage'
import { AgentsPage } from './pages/AgentsPage'
import { PaceWizardPage } from './pages/PaceWizardPage'
import { DevBoardPage } from './pages/DevBoardPage'
import { LiveSafePage } from './pages/LiveSafePage'
import { OnboardPage } from './pages/APE/OnboardPage'
import { APEDashboardPage } from './pages/APE/APEDashboardPage'

export default function App() {
  return (
    <Routes>
      {/* Public routes */}
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />

      {/* APE onboarding — public, no auth required */}
      <Route path="/APE" element={<OnboardPage />} />
      <Route path="/APE/onboard" element={<OnboardPage />} />

      {/* APE dashboard — auth required, wraps Command Center with board sidebar */}
      <Route element={<RequireAuth><Layout /></RequireAuth>}>
        <Route path="/APE/dashboard" element={<APEDashboardPage />} />
        <Route path="/" element={<CommandCenterPage />} />
        <Route path="/decisions" element={<DashboardPage />} />
        <Route path="/decisions/:id" element={<DecisionDetailPage />} />
        <Route path="/decisions/new" element={<CreateDecisionPage />} />
        <Route path="/delegations" element={<DelegationsPage />} />
        <Route path="/audit" element={<AuditTrailPage />} />
        <Route path="/constitution" element={<ConstitutionPage />} />
        <Route path="/identity" element={<IdentityPage />} />
        <Route path="/identity/pace" element={<PaceWizardPage />} />
        <Route path="/agents" element={<AgentsPage />} />
        <Route path="/dev" element={<DevBoardPage />} />
        <Route path="/applications/livesafe" element={<LiveSafePage />} />
      </Route>
    </Routes>
  )
}
