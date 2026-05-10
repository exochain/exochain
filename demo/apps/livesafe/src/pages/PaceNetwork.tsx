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

import { useState } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { PACE_ROLES } from '@/lib/utils';
import { cn } from '@/lib/utils';
import {
  Users, Plus, X, Shield, CheckCircle, Clock, UserPlus, Key,
} from 'lucide-react';

interface PaceMember {
  id: string;
  name: string;
  email: string;
  role: string;
  relationship: string;
  status: 'pending' | 'accepted';
}

const RELATIONSHIPS = [
  'Spouse/Partner', 'Child', 'Parent', 'Sibling', 'Close Friend',
  'Neighbor', 'Coworker', 'Attorney', 'Medical Professional', 'Other',
];

export default function PaceNetwork() {
  const { auth } = useAuth();
  const [members, setMembers] = useState<PaceMember[]>([]);
  const [showInvite, setShowInvite] = useState(false);
  const [inviteRole, setInviteRole] = useState('');
  const [form, setForm] = useState({ name: '', email: '', relationship: '' });

  const getMember = (role: string) => members.find(m => m.role === role);

  const sendInvite = () => {
    if (!form.name || !form.email) return;
    setMembers(prev => [...prev, {
      id: crypto.randomUUID(),
      name: form.name,
      email: form.email,
      role: inviteRole,
      relationship: form.relationship,
      status: 'pending',
    }]);
    setShowInvite(false);
    setForm({ name: '', email: '', relationship: '' });
  };

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-heading font-bold text-white">PACE Network</h2>
        <p className="text-sm text-white/40 mt-1">
          Your 1:4 trusted safety network — the people who have your back
        </p>
      </div>

      {/* Explainer */}
      <div className="bg-blue-500/5 border border-blue-400/20 rounded-xl p-6 mb-8">
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center shrink-0">
            <Key size={18} className="text-blue-400" />
          </div>
          <div>
            <h3 className="text-sm font-heading font-semibold text-white mb-1">How PACE Protects You</h3>
            <p className="text-xs text-white/40 leading-relaxed">
              PACE stands for Primary, Alternate, Contingency, Emergency — a military communication
              framework adapted for civilian safety. Your master key is split into 4 Shamir shares
              (3-of-4 threshold). Each trustee holds one encrypted shard. In an emergency, 3 of your
              4 trustees must agree before any action is taken on your behalf.
            </p>
            <p className="text-xs text-blue-300/60 mt-2">
              When you invite someone, they join LiveSafe too — and name their own 4 trustees.
              One person becomes five. The safety network grows exponentially.
            </p>
          </div>
        </div>
      </div>

      {/* PACE Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {PACE_ROLES.map(({ key, label, color, description }) => {
          const member = getMember(key);
          return (
            <div
              key={key}
              className={cn(
                'rounded-xl border-2 p-5 transition-all',
                member
                  ? member.status === 'accepted'
                    ? 'border-blue-400/30 bg-blue-500/5'
                    : 'border-amber-400/30 bg-amber-500/5'
                  : 'border-dashed border-white/15 bg-white/[0.02] cursor-pointer hover:border-blue-400/30',
              )}
              onClick={!member ? () => { setInviteRole(key); setShowInvite(true); } : undefined}
            >
              <div className="flex items-center justify-between mb-3">
                <span className={cn('w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-white', color)}>
                  {key[0]}
                </span>
                {member ? (
                  member.status === 'accepted'
                    ? <CheckCircle size={14} className="text-blue-400" />
                    : <Clock size={14} className="text-amber-400" />
                ) : (
                  <UserPlus size={14} className="text-white/20" />
                )}
              </div>

              <p className="text-[11px] text-white/40 mb-2">{label}</p>

              {member ? (
                <>
                  <p className="text-sm font-medium text-white truncate">{member.name}</p>
                  <p className="text-xs text-white/30 truncate">{member.email}</p>
                  {member.relationship && (
                    <p className="text-[10px] text-white/20 mt-1">{member.relationship}</p>
                  )}
                  <div className="mt-3 flex items-center gap-1">
                    <Shield size={10} className="text-white/20" />
                    <span className="text-[10px] text-white/20">
                      {member.status === 'accepted' ? 'Shard confirmed' : 'Invitation sent'}
                    </span>
                  </div>
                </>
              ) : (
                <div className="text-center py-3">
                  <UserPlus size={18} className="mx-auto text-white/15 mb-1" />
                  <p className="text-xs text-white/20">Invite {key}</p>
                  <p className="text-[10px] text-white/15 mt-1">{description}</p>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Network Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-white/[0.03] border border-white/10 rounded-xl p-4 text-center">
          <p className="text-2xl font-heading font-bold text-white">{members.length}</p>
          <p className="text-[11px] text-white/30">Trustees Named</p>
        </div>
        <div className="bg-white/[0.03] border border-white/10 rounded-xl p-4 text-center">
          <p className="text-2xl font-heading font-bold text-white">
            {members.filter(m => m.status === 'accepted').length}
          </p>
          <p className="text-[11px] text-white/30">Shards Confirmed</p>
        </div>
        <div className="bg-white/[0.03] border border-white/10 rounded-xl p-4 text-center">
          <p className="text-2xl font-heading font-bold text-white">0</p>
          <p className="text-[11px] text-white/30">You Guard</p>
        </div>
      </div>

      {/* Invite Modal */}
      {showInvite && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#0f1d32] border border-white/10 rounded-2xl p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-heading font-bold text-white">
                Invite {inviteRole} Trustee
              </h3>
              <button onClick={() => setShowInvite(false)}>
                <X size={18} className="text-white/30" />
              </button>
            </div>

            <p className="text-xs text-white/40 mb-6">
              This person will receive an invitation to join your safety network.
              When they accept, they'll hold an encrypted key shard and join LiveSafe themselves.
            </p>

            <div className="space-y-4">
              <div>
                <label className="text-xs text-white/50 mb-1 block">Name</label>
                <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-blue-400" />
              </div>
              <div>
                <label className="text-xs text-white/50 mb-1 block">Email</label>
                <input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })}
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-blue-400" />
              </div>
              <div>
                <label className="text-xs text-white/50 mb-1 block">Relationship</label>
                <select value={form.relationship} onChange={(e) => setForm({ ...form, relationship: e.target.value })}
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-blue-400">
                  <option value="">Select...</option>
                  {RELATIONSHIPS.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
            </div>

            <button
              onClick={sendInvite}
              disabled={!form.name || !form.email}
              className="w-full mt-6 bg-blue-500 hover:bg-blue-600 disabled:bg-white/10 text-white font-semibold py-3 rounded-xl transition-colors flex items-center justify-center gap-2"
            >
              <Users size={16} />
              Send Invitation
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
