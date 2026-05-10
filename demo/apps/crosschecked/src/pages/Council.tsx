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
import { listProposals, castVote, resolveDeliberation, getClearance } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import { cn } from '@/lib/utils';
import StatusBadge from '@/components/StatusBadge';
import { Loader2, Vote, Gavel, CheckCircle2, XCircle, MinusCircle } from 'lucide-react';

export default function Council() {
  const { auth } = useAuth();
  const queryClient = useQueryClient();

  const { data: proposals = [], isLoading } = useQuery({
    queryKey: ['proposals', 'deliberating'],
    queryFn: () => listProposals('deliberating'),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-xc-indigo-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="mb-8">
        <h1 className="font-heading font-bold text-2xl text-white">Council</h1>
        <p className="text-sm text-gray-400 mt-1">Active deliberations and governance votes</p>
      </div>

      {proposals.length === 0 ? (
        <div className="text-center py-16 text-gray-500">
          <Vote className="w-12 h-12 mx-auto mb-4 opacity-30" />
          <p className="text-sm">No active deliberations</p>
          <p className="text-xs mt-1">Proposals in the deliberating state will appear here</p>
        </div>
      ) : (
        <div className="space-y-6">
          {proposals.map((p) => (
            <DeliberationCard
              key={p.id}
              proposal={p}
              actorDid={auth!.did}
              onAction={() => queryClient.invalidateQueries({ queryKey: ['proposals', 'deliberating'] })}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function DeliberationCard({
  proposal,
  actorDid,
  onAction,
}: {
  proposal: { id: string; title: string; status: string; decision_class: string; method: string };
  actorDid: string;
  onAction: () => void;
}) {
  const [stance, setStance] = useState<string>('');
  const [rationale, setRationale] = useState('');

  const { data: clearance } = useQuery({
    queryKey: ['clearance', proposal.id],
    queryFn: () => getClearance(proposal.id),
  });

  const voteMutation = useMutation({
    mutationFn: () =>
      castVote(proposal.id, { voter_did: actorDid, choice: stance, rationale: rationale || undefined }),
    onSuccess: () => {
      setStance('');
      setRationale('');
      onAction();
    },
  });

  const resolveMutation = useMutation({
    mutationFn: () => resolveDeliberation(proposal.id, actorDid),
    onSuccess: onAction,
  });

  const approvals = clearance?.approvals?.length ?? 0;
  const rejections = clearance?.rejections?.length ?? 0;
  const abstentions = clearance?.abstentions?.length ?? 0;
  const totalVotes = approvals + rejections + abstentions;

  const stanceOptions = [
    { value: 'approve', label: 'Approve', icon: CheckCircle2, color: 'text-emerald-400 border-emerald-400/30 bg-emerald-500/10' },
    { value: 'reject', label: 'Reject', icon: XCircle, color: 'text-red-400 border-red-400/30 bg-red-500/10' },
    { value: 'abstain', label: 'Abstain', icon: MinusCircle, color: 'text-gray-400 border-gray-400/30 bg-gray-500/10' },
  ];

  return (
    <div className="rounded-xl border border-white/5 bg-xc-slate/40 p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="font-heading font-semibold text-white">{proposal.title}</h3>
          <div className="flex items-center gap-2 mt-1">
            <StatusBadge status={proposal.status} />
            <span className="text-xs text-gray-500">{proposal.decision_class}</span>
          </div>
        </div>
      </div>

      {/* Vote progress */}
      <div className="mb-4 p-3 rounded-lg bg-xc-navy/50 border border-white/5">
        <div className="flex items-center justify-between text-xs text-gray-400 mb-2">
          <span>Vote Progress</span>
          <span>{totalVotes} vote{totalVotes !== 1 ? 's' : ''}</span>
        </div>
        <div className="flex gap-1 h-2 rounded-full overflow-hidden bg-white/5">
          {approvals > 0 && (
            <div
              className="bg-emerald-500 rounded-l-full"
              style={{ width: `${(approvals / Math.max(totalVotes, 1)) * 100}%` }}
            />
          )}
          {abstentions > 0 && (
            <div
              className="bg-gray-500"
              style={{ width: `${(abstentions / Math.max(totalVotes, 1)) * 100}%` }}
            />
          )}
          {rejections > 0 && (
            <div
              className="bg-red-500 rounded-r-full"
              style={{ width: `${(rejections / Math.max(totalVotes, 1)) * 100}%` }}
            />
          )}
        </div>
        <div className="flex items-center gap-4 mt-2 text-xs">
          <span className="text-emerald-400">{approvals} approve</span>
          <span className="text-gray-400">{abstentions} abstain</span>
          <span className="text-red-400">{rejections} reject</span>
        </div>
      </div>

      {/* Vote panel */}
      <div className="space-y-3">
        <div className="flex gap-2">
          {stanceOptions.map((opt) => (
            <button
              key={opt.value}
              onClick={() => setStance(opt.value)}
              className={cn(
                'flex items-center gap-1.5 px-3 py-2 rounded-lg border text-sm font-medium transition-all',
                stance === opt.value ? opt.color : 'border-white/10 text-gray-400 hover:border-white/20',
              )}
            >
              <opt.icon className="w-4 h-4" />
              {opt.label}
            </button>
          ))}
        </div>

        <textarea
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
          rows={2}
          placeholder="Rationale (optional)"
          className="w-full px-4 py-2.5 rounded-lg bg-xc-navy border border-white/10 text-white text-sm placeholder:text-gray-500 focus:outline-none focus:border-xc-indigo-500 transition-colors resize-none"
        />

        <div className="flex items-center gap-3">
          <button
            onClick={() => voteMutation.mutate()}
            disabled={!stance || voteMutation.isPending}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-xc-indigo-500 to-xc-purple-500 text-white font-medium text-sm hover:shadow-lg hover:shadow-xc-indigo-500/25 transition-all disabled:opacity-50"
          >
            {voteMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            Cast Vote
          </button>

          <button
            onClick={() => resolveMutation.mutate()}
            disabled={resolveMutation.isPending}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-white/10 text-gray-300 text-sm hover:border-white/20 transition-colors disabled:opacity-50"
          >
            {resolveMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            <Gavel className="w-4 h-4" />
            Resolve
          </button>
        </div>
      </div>
    </div>
  );
}
