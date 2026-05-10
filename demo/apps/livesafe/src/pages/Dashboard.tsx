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

import { useAuth } from '@/hooks/useAuth';
import {
  Shield, FileText, QrCode, Users, Clock, Heart,
  AlertTriangle, CheckCircle, TrendingUp,
} from 'lucide-react';
import { Link } from 'react-router-dom';

function QuickAction({ to, icon: Icon, label, color, description }: {
  to: string; icon: React.ElementType; label: string; color: string; description: string;
}) {
  return (
    <Link
      to={to}
      className="p-5 bg-white/[0.03] border border-white/10 rounded-xl hover:border-blue-400/30 transition-all group"
    >
      <div className="flex items-center gap-3 mb-2">
        <div className={`w-9 h-9 rounded-lg ${color} flex items-center justify-center`}>
          <Icon size={16} className="text-white" />
        </div>
        <span className="text-sm font-medium text-white group-hover:text-blue-400 transition-colors">
          {label}
        </span>
      </div>
      <p className="text-xs text-white/30">{description}</p>
    </Link>
  );
}

export default function Dashboard() {
  const { auth } = useAuth();

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-heading font-bold text-white">Welcome back, {auth?.displayName}</h2>
        <p className="text-sm text-white/40 mt-1">Your safety overview</p>
      </div>

      {/* Readiness Score */}
      <div className="bg-gradient-to-r from-blue-500/20 via-blue-500/10 to-cyan-500/10 border border-blue-400/20 rounded-2xl p-8 mb-8">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-blue-300 font-medium mb-1 uppercase tracking-wider">Preparedness Score</p>
            <div className="flex items-end gap-2">
              <p className="text-6xl font-heading font-bold text-white">28</p>
              <p className="text-lg text-white/40 mb-2">/ 100</p>
            </div>
            <p className="text-sm text-blue-200/40 mt-2">
              Complete your emergency plans and PACE network to improve
            </p>
          </div>
          <div className="w-28 h-28 rounded-full border-4 border-blue-400/20 flex items-center justify-center relative">
            <svg className="absolute inset-0 w-full h-full -rotate-90" viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="46" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="6" />
              <circle cx="50" cy="50" r="46" fill="none" stroke="#3b82f6" strokeWidth="6"
                strokeDasharray={`${28 * 2.89} ${100 * 2.89}`} strokeLinecap="round" />
            </svg>
            <TrendingUp size={28} className="text-blue-400" />
          </div>
        </div>
      </div>

      {/* Checklist */}
      <div className="bg-white/[0.03] border border-white/10 rounded-xl p-6 mb-8">
        <h3 className="text-sm font-heading font-semibold text-white mb-4 flex items-center gap-2">
          <Shield size={16} className="text-blue-400" />
          Getting Started Checklist
        </h3>
        <div className="space-y-3">
          {[
            { label: 'Create your first emergency plan', done: false, to: '/plans' },
            { label: 'Set up your ICE card', done: false, to: '/ice-card' },
            { label: 'Name 4 PACE trustees', done: false, to: '/pace' },
            { label: 'Configure Golden Hour protocols', done: false, to: '/golden-hour' },
            { label: 'Send first wellness check', done: false, to: '/wellness' },
          ].map(({ label, done, to }) => (
            <Link
              key={label}
              to={to}
              className="flex items-center gap-3 p-3 rounded-lg hover:bg-white/5 transition-colors"
            >
              {done ? (
                <CheckCircle size={18} className="text-blue-400 shrink-0" />
              ) : (
                <div className="w-[18px] h-[18px] rounded-full border-2 border-white/20 shrink-0" />
              )}
              <span className={`text-sm ${done ? 'text-white/40 line-through' : 'text-white/70'}`}>
                {label}
              </span>
            </Link>
          ))}
        </div>
      </div>

      {/* Quick Actions Grid */}
      <h3 className="text-sm font-heading font-semibold text-white mb-4">Quick Actions</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <QuickAction
          to="/plans"
          icon={FileText}
          label="Emergency Plans"
          color="bg-blue-500/20"
          description="Create response plans for disasters, unrest, and threats"
        />
        <QuickAction
          to="/ice-card"
          icon={QrCode}
          label="ICE Card"
          color="bg-cyan-500/20"
          description="Digital emergency card with medical info and contacts"
        />
        <QuickAction
          to="/pace"
          icon={Users}
          label="PACE Network"
          color="bg-teal-500/20"
          description="Build your 1:4 trusted safety network"
        />
        <QuickAction
          to="/golden-hour"
          icon={Clock}
          label="Golden Hour"
          color="bg-amber-500/20"
          description="First 60 minutes response protocols"
        />
        <QuickAction
          to="/wellness"
          icon={Heart}
          label="Wellness Checks"
          color="bg-red-500/20"
          description="Regular check-ins with your safety network"
        />
        <QuickAction
          to="/settings"
          icon={AlertTriangle}
          label="Alert Settings"
          color="bg-purple-500/20"
          description="Configure notifications and alert thresholds"
        />
      </div>
    </div>
  );
}
