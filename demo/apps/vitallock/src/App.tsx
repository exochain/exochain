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

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { initCrypto } from '@/lib/crypto';
import Navigation from '@/components/Navigation';
import Login from '@/pages/Login';
import Dashboard from '@/pages/Dashboard';
import Compose from '@/pages/Compose';
import Inbox from '@/pages/Inbox';
import PaceNetwork from '@/pages/PaceNetwork';
import Afterlife from '@/pages/Afterlife';
import DigitalAssets from '@/pages/DigitalAssets';
import Family from '@/pages/Family';
import Settings from '@/pages/Settings';

function AuthenticatedLayout() {
  const { auth, logout } = useAuth();
  const [odentityScore] = useState(0);

  if (!auth) return <Navigate to="/login" replace />;

  return (
    <div className="flex min-h-screen bg-black">
      <Navigation
        displayName={auth.displayName}
        odentityScore={odentityScore}
        onLogout={logout}
      />
      <main className="flex-1 overflow-y-auto">
        <Routes>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/compose" element={<Compose />} />
          <Route path="/inbox" element={<Inbox />} />
          <Route path="/pace" element={<PaceNetwork />} />
          <Route path="/afterlife" element={<Afterlife />} />
          <Route path="/assets" element={<DigitalAssets />} />
          <Route path="/family" element={<Family />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  const { isAuthenticated } = useAuth();

  // Initialize WASM crypto engine on app startup
  useEffect(() => {
    initCrypto().catch(console.error);
  }, []);

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/login"
          element={isAuthenticated ? <Navigate to="/dashboard" replace /> : <Login />}
        />
        <Route path="/*" element={<AuthenticatedLayout />} />
      </Routes>
    </BrowserRouter>
  );
}
