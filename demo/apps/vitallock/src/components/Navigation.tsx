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
  Home, Mail, Send, Users, Shield, FileBox, Heart, Settings, LogOut,
} from 'lucide-react';

const NAV_ITEMS = [
  { path: '/dashboard', label: 'Dashboard', icon: Home },
  { path: '/compose', label: 'Compose', icon: Send },
  { path: '/inbox', label: 'Inbox', icon: Mail },
  { path: '/pace', label: 'PACE Network', icon: Users },
  { path: '/afterlife', label: 'Afterlife', icon: Heart },
  { path: '/assets', label: 'Digital Assets', icon: FileBox },
  { path: '/family', label: 'Family', icon: Shield },
  { path: '/settings', label: 'Settings', icon: Settings },
];

interface Props {
  displayName: string;
  odentityScore: number;
  onLogout: () => void;
}

export default function Navigation({ displayName, odentityScore, onLogout }: Props) {
  const location = useLocation();

  return (
    <nav className="w-64 bg-zinc-950 border-r border-zinc-800 flex flex-col h-screen sticky top-0">
      {/* Logo */}
      <div className="p-6 border-b border-zinc-800">
        <h1 className="text-2xl font-bold tracking-tighter">
          VITAL<span className="text-emerald-400">LOCK</span>
        </h1>
        <p className="text-[10px] text-zinc-500 mt-1">Powered by EXOCHAIN</p>
      </div>

      {/* User + Score */}
      <div className="p-4 border-b border-zinc-800">
        <p className="text-sm font-medium text-white truncate">{displayName}</p>
        <div className="flex items-center gap-2 mt-2">
          <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-emerald-400 rounded-full transition-all"
              style={{ width: `${odentityScore}%` }}
            />
          </div>
          <span className="text-[10px] text-emerald-400 font-mono">{odentityScore}</span>
        </div>
        <p className="text-[10px] text-zinc-500 mt-1">0dentity Score</p>
      </div>

      {/* Nav Links */}
      <div className="flex-1 py-2 overflow-y-auto">
        {NAV_ITEMS.map(({ path, label, icon: Icon }) => (
          <Link
            key={path}
            to={path}
            className={cn(
              'flex items-center gap-3 px-4 py-2.5 text-sm transition-colors',
              location.pathname === path
                ? 'bg-emerald-400/10 text-emerald-400 border-r-2 border-emerald-400'
                : 'text-zinc-400 hover:text-white hover:bg-zinc-900',
            )}
          >
            <Icon size={16} />
            {label}
          </Link>
        ))}
      </div>

      {/* Logout */}
      <button
        onClick={onLogout}
        className="flex items-center gap-3 px-4 py-3 text-sm text-zinc-500 hover:text-red-400 border-t border-zinc-800 transition-colors"
      >
        <LogOut size={16} />
        Sign Out
      </button>
    </nav>
  );
}
