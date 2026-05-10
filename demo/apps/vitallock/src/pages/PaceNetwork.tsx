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
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { getPaceNetwork, getResponsibilities, inviteTrustee } from '@/lib/api';
import PaceMemberCard from '@/components/PaceMemberCard';
import { Users, Shield, Plus, X } from 'lucide-react';

const ROLES = ['Primary', 'Alternate', 'Contingency', 'Emergency'] as const;
const RELATIONSHIPS = [
  'Spouse/Partner', 'Child', 'Parent', 'Sibling', 'Grandchild',
  'Close Friend', 'Attorney', 'Medical Professional', 'Other',
];

export default function PaceNetwork() {
  const { auth } = useAuth();
  const queryClient = useQueryClient();
  const did = auth?.did || '';

  const [showInvite, setShowInvite] = useState(false);
  const [inviteRole, setInviteRole] = useState('');
  const [form, setForm] = useState({ name: '', email: '', relationship: '' });

  const { data: network } = useQuery({
    queryKey: ['pace', did],
    queryFn: () => getPaceNetwork(did),
    enabled: !!did,
  });

  const { data: responsibilities } = useQuery({
    queryKey: ['responsibilities', did],
    queryFn: () => getResponsibilities(did),
    enabled: !!did,
  });

  const inviteMutation = useMutation({
    mutationFn: () =>
      inviteTrustee({
        owner_did: did,
        trustee_email: form.email,
        trustee_name: form.name,
        role: inviteRole,
        relationship: form.relationship,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['pace'] });
      setShowInvite(false);
      setForm({ name: '', email: '', relationship: '' });
    },
  });

  const getMemberForRole = (role: string) =>
    network?.find(m => m.role === role);

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-white">ICE-PACE Network</h2>
        <p className="text-sm text-zinc-400 mt-1">
          Your 1:4 trustee network for key sharding and death verification
        </p>
      </div>

      {/* Explainer */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 mb-8">
        <div className="flex items-start gap-3">
          <Shield size={20} className="text-emerald-400 mt-0.5" />
          <div>
            <p className="text-sm text-white font-medium mb-1">
              How PACE Works
            </p>
            <p className="text-xs text-zinc-400 leading-relaxed">
              Your master key is split into 4 Shamir shares (3-of-4 threshold).
              Each PACE trustee holds one encrypted share. If you pass away,
              3 of your 4 trustees must confirm to release your afterlife messages
              and digital assets to beneficiaries.
            </p>
          </div>
        </div>
      </div>

      {/* PACE Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {ROLES.map(role => {
          const member = getMemberForRole(role);
          return (
            <PaceMemberCard
              key={role}
              role={role}
              trusteeName={member?.trustee_name}
              trusteeEmail={member?.trustee_email}
              status={
                member
                  ? (member.invitation_status as 'pending' | 'accepted' | 'declined')
                  : 'empty'
              }
              relationship={member?.relationship || undefined}
              onInvite={() => {
                setInviteRole(role);
                setShowInvite(true);
              }}
            />
          );
        })}
      </div>

      {/* Responsibilities */}
      {responsibilities && responsibilities.trustee_of_count > 0 && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 mb-8">
          <div className="flex items-center gap-2 mb-4">
            <Users size={16} className="text-amber-400" />
            <h3 className="text-sm font-medium text-white">
              You are a trusted guardian for {responsibilities.trustee_of_count} {responsibilities.trustee_of_count === 1 ? 'person' : 'people'}
            </h3>
          </div>
          <div className="space-y-2">
            {responsibilities.responsibilities.map((r, i) => (
              <div key={i} className="flex items-center justify-between px-3 py-2 bg-zinc-800 rounded-lg">
                <span className="text-xs text-white">{r.owner_name}</span>
                <span className="text-[10px] text-zinc-500">{r.role}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Invite Modal */}
      {showInvite && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-bold text-white">
                Invite {inviteRole} Trustee
              </h3>
              <button onClick={() => setShowInvite(false)}>
                <X size={18} className="text-zinc-500" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs text-zinc-500 mb-1">Name</label>
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400"
                />
              </div>
              <div>
                <label className="block text-xs text-zinc-500 mb-1">Email</label>
                <input
                  type="email"
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400"
                />
              </div>
              <div>
                <label className="block text-xs text-zinc-500 mb-1">Relationship</label>
                <select
                  value={form.relationship}
                  onChange={(e) => setForm({ ...form, relationship: e.target.value })}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400"
                >
                  <option value="">Select...</option>
                  {RELATIONSHIPS.map(r => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </select>
              </div>
            </div>

            <button
              onClick={() => inviteMutation.mutate()}
              disabled={inviteMutation.isPending || !form.name || !form.email}
              className="w-full mt-6 bg-emerald-500 hover:bg-emerald-600 disabled:bg-zinc-700 text-black font-semibold py-3 rounded-xl transition-colors flex items-center justify-center gap-2"
            >
              <Plus size={16} />
              {inviteMutation.isPending ? 'Sending...' : 'Send Invitation'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
