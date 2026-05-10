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

import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import { cn } from '@/lib/utils';
import {
  LayoutDashboard,
  FilePlus2,
  Users,
  FileSearch,
  KeyRound,
  Settings,
  LogOut,
  ShieldCheck,
} from 'lucide-react';

const links = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/proposals/new', label: 'New Proposal', icon: FilePlus2 },
  { to: '/council', label: 'Council', icon: Users },
  { to: '/evidence', label: 'Evidence', icon: FileSearch },
  { to: '/keys', label: 'Keys', icon: KeyRound },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export default function Navigation() {
  const { auth, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <aside className="w-64 flex-shrink-0 bg-xc-slate border-r border-white/5 flex flex-col h-full">
      {/* Logo */}
      <div className="p-6 flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-xc-indigo-500 to-xc-purple-500 flex items-center justify-center">
          <ShieldCheck className="w-5 h-5 text-white" />
        </div>
        <div>
          <span className="font-heading font-bold text-white text-lg">CrossChecked</span>
          <span className="text-xc-indigo-400 text-lg">.ai</span>
        </div>
      </div>

      {/* User info */}
      <div className="px-6 pb-4 border-b border-white/5">
        <p className="text-sm font-medium text-white truncate">{auth?.displayName}</p>
        <p className="text-xs text-gray-400 truncate font-mono">{auth?.did?.slice(0, 24)}...</p>
        <span className="inline-block mt-1 text-xs px-2 py-0.5 rounded bg-xc-indigo-500/20 text-xc-indigo-400 capitalize">
          {auth?.role || 'member'}
        </span>
      </div>

      {/* Links */}
      <nav className="flex-1 py-4 px-3 space-y-1">
        {links.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
                isActive
                  ? 'bg-xc-indigo-500/15 text-xc-indigo-400 border-r-2 border-xc-indigo-500'
                  : 'text-gray-400 hover:text-white hover:bg-white/5',
              )
            }
          >
            <Icon className="w-4.5 h-4.5" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Sign out */}
      <div className="p-4 border-t border-white/5">
        <button
          onClick={handleLogout}
          className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-sm font-medium text-gray-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
        >
          <LogOut className="w-4.5 h-4.5" />
          Sign Out
        </button>
      </div>
    </aside>
  );
}
