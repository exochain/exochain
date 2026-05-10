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

import { Link, useLocation } from 'react-router-dom';
import { cn } from '@/lib/utils';
import {
  LayoutDashboard, FileText, QrCode, Users, Clock, Heart, Settings, LogOut, Shield,
} from 'lucide-react';

const NAV_ITEMS = [
  { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/plans', label: 'Emergency Plans', icon: FileText },
  { path: '/ice-card', label: 'ICE Card', icon: QrCode },
  { path: '/pace', label: 'PACE Network', icon: Users },
  { path: '/golden-hour', label: 'Golden Hour', icon: Clock },
  { path: '/wellness', label: 'Wellness Checks', icon: Heart },
  { path: '/settings', label: 'Settings', icon: Settings },
];

interface Props {
  displayName: string;
  onLogout: () => void;
}

export default function Navigation({ displayName, onLogout }: Props) {
  const location = useLocation();

  return (
    <nav className="w-64 bg-[#0d1a2e] border-r border-white/5 flex flex-col h-screen sticky top-0">
      {/* Logo */}
      <div className="p-6 border-b border-white/5">
        <div className="flex items-center gap-2">
          <Shield className="text-blue-400" size={22} />
          <h1 className="text-xl font-heading font-bold text-white">
            Live<span className="text-blue-400">Safe</span>
          </h1>
        </div>
        <p className="text-[10px] text-white/20 mt-1">Powered by EXOCHAIN</p>
      </div>

      {/* User */}
      <div className="p-4 border-b border-white/5">
        <p className="text-sm font-medium text-white truncate">{displayName}</p>
        <p className="text-[10px] text-white/30 mt-0.5">Protected</p>
      </div>

      {/* Links */}
      <div className="flex-1 py-2 overflow-y-auto">
        {NAV_ITEMS.map(({ path, label, icon: Icon }) => (
          <Link
            key={path}
            to={path}
            className={cn(
              'flex items-center gap-3 px-4 py-2.5 text-sm transition-colors',
              location.pathname === path
                ? 'bg-blue-500/10 text-blue-400 border-r-2 border-blue-400'
                : 'text-white/40 hover:text-white hover:bg-white/5',
            )}
          >
            <Icon size={16} />
            {label}
          </Link>
        ))}
      </div>

      <button
        onClick={onLogout}
        className="flex items-center gap-3 px-4 py-3 text-sm text-white/30 hover:text-red-400 border-t border-white/5 transition-colors"
      >
        <LogOut size={16} />
        Sign Out
      </button>
    </nav>
  );
}
