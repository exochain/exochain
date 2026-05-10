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

import { useQuery } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { getOdentityScore, getInbox, getPaceNetwork, getAssets, getAfterlifeMessages } from '@/lib/api';
import { Mail, Users, FileBox, Heart, Shield, TrendingUp } from 'lucide-react';

function StatCard({ icon: Icon, label, value, color }: {
  icon: React.ElementType; label: string; value: string | number; color: string;
}) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
      <div className="flex items-center gap-3 mb-3">
        <Icon size={18} className={color} />
        <span className="text-xs text-zinc-400">{label}</span>
      </div>
      <p className="text-2xl font-bold text-white">{value}</p>
    </div>
  );
}

export default function Dashboard() {
  const { auth } = useAuth();
  const did = auth?.did || '';

  const { data: score } = useQuery({
    queryKey: ['odentity', did],
    queryFn: () => getOdentityScore(did),
    enabled: !!did,
  });

  const { data: inbox } = useQuery({
    queryKey: ['inbox', did],
    queryFn: () => getInbox(did),
    enabled: !!did,
  });

  const { data: pace } = useQuery({
    queryKey: ['pace', did],
    queryFn: () => getPaceNetwork(did),
    enabled: !!did,
  });

  const { data: assets } = useQuery({
    queryKey: ['assets', did],
    queryFn: () => getAssets(did),
    enabled: !!did,
  });

  const { data: afterlife } = useQuery({
    queryKey: ['afterlife', did],
    queryFn: () => getAfterlifeMessages(did),
    enabled: !!did,
  });

  const unreadCount = inbox?.filter(m => !m.read_at_ms).length || 0;
  const paceAccepted = pace?.filter(m => m.invitation_status === 'accepted').length || 0;

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-white">Dashboard</h2>
        <p className="text-sm text-zinc-400 mt-1">
          Welcome back, {auth?.displayName}
        </p>
      </div>

      {/* 0dentity Score Hero */}
      <div className="bg-gradient-to-r from-emerald-500/20 to-emerald-400/5 border border-emerald-400/30 rounded-2xl p-6 mb-8">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-emerald-400 font-medium mb-1">0DENTITY SCORE</p>
            <p className="text-5xl font-bold text-white">{score?.score || 0}</p>
            <p className="text-xs text-zinc-400 mt-2">
              {(score?.score || 0) >= 70
                ? 'Keystore fortified'
                : 'Complete PACE network to strengthen'}
            </p>
          </div>
          <div className="w-24 h-24 rounded-full border-4 border-emerald-400/30 flex items-center justify-center">
            <TrendingUp size={32} className="text-emerald-400" />
          </div>
        </div>

        {/* Score breakdown */}
        {score?.breakdown && (
          <div className="mt-4 grid grid-cols-3 gap-2">
            {Object.entries(score.breakdown).map(([key, val]) => (
              <div key={key} className="text-center">
                <p className="text-xs text-emerald-400 font-mono">{val}</p>
                <p className="text-[9px] text-zinc-500 capitalize">
                  {key.replace(/_/g, ' ')}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard
          icon={Mail}
          label="Unread Messages"
          value={unreadCount}
          color="text-blue-400"
        />
        <StatCard
          icon={Users}
          label="PACE Trustees"
          value={`${paceAccepted}/4`}
          color="text-emerald-400"
        />
        <StatCard
          icon={FileBox}
          label="Digital Assets"
          value={assets?.length || 0}
          color="text-amber-400"
        />
        <StatCard
          icon={Heart}
          label="Afterlife Messages"
          value={afterlife?.length || 0}
          color="text-rose-400"
        />
      </div>

      {/* PACE Network Quick View */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <Shield size={16} className="text-emerald-400" />
          <h3 className="text-sm font-medium text-white">PACE Network Health</h3>
        </div>
        <div className="grid grid-cols-4 gap-3">
          {['Primary', 'Alternate', 'Contingency', 'Emergency'].map(role => {
            const member = pace?.find(m => m.role === role);
            const isAccepted = member?.invitation_status === 'accepted';
            return (
              <div
                key={role}
                className={`rounded-lg p-3 text-center border ${
                  isAccepted
                    ? 'border-emerald-400/30 bg-emerald-400/5'
                    : member
                      ? 'border-amber-400/30 bg-amber-400/5'
                      : 'border-zinc-700 bg-zinc-800/50'
                }`}
              >
                <p className="text-[10px] text-zinc-400 mb-1">{role}</p>
                <p className="text-xs font-medium text-white truncate">
                  {member?.trustee_name || 'Empty'}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
