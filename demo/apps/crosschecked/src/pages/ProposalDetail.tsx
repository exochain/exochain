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
import { useParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getProposal,
  transitionStatus,
  triggerCrosscheck,
  synthesize,
  anchor,
  openDeliberation,
  getCustody,
  listEvidence,
} from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import { cn, formatDate } from '@/lib/utils';
import ProposalStatusFlow from '@/components/ProposalStatusFlow';
import PanelGrid from '@/components/PanelGrid';
import FiveByFiveMatrix from '@/components/FiveByFiveMatrix';
import CustodyTimeline from '@/components/CustodyTimeline';
import AnchorReceipt from '@/components/AnchorReceipt';
import StatusBadge from '@/components/StatusBadge';
import {
  Copy,
  Check,
  FileText,
  BarChart3,
  Shield,
  Link as LinkIcon,
  Loader2,
  AlertTriangle,
  GitBranch,
  Eye,
  Anchor as AnchorIcon,
} from 'lucide-react';

type Tab = 'overview' | 'opinions' | 'report' | 'evidence' | 'custody' | 'anchoring';

export default function ProposalDetail() {
  const { id } = useParams<{ id: string }>();
  const { auth } = useAuth();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [copied, setCopied] = useState(false);

  const { data: proposal, isLoading } = useQuery({
    queryKey: ['proposal', id],
    queryFn: () => getProposal(id!),
    enabled: !!id,
  });

  const { data: custody = [] } = useQuery({
    queryKey: ['custody', id],
    queryFn: () => getCustody(id!),
    enabled: !!id && activeTab === 'custody',
  });

  const { data: evidence = [] } = useQuery({
    queryKey: ['evidence', id],
    queryFn: () => listEvidence(id!),
    enabled: !!id && activeTab === 'evidence',
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['proposal', id] });
    queryClient.invalidateQueries({ queryKey: ['custody', id] });
  };

  const submitMutation = useMutation({
    mutationFn: () => transitionStatus(id!, 'submitted', auth!.did),
    onSuccess: invalidate,
  });

  const crosscheckMutation = useMutation({
    mutationFn: () => triggerCrosscheck(id!, auth!.did),
    onSuccess: invalidate,
  });

  const synthesizeMutation = useMutation({
    mutationFn: () => synthesize(id!, { actor_did: auth!.did }),
    onSuccess: invalidate,
  });

  const anchorMutation = useMutation({
    mutationFn: () => anchor(id!, auth!.did),
    onSuccess: invalidate,
  });

  const deliberateMutation = useMutation({
    mutationFn: () => openDeliberation(id!, { participants: [auth!.did], actor_did: auth!.did }),
    onSuccess: invalidate,
  });

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (isLoading || !proposal) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-xc-indigo-400 animate-spin" />
      </div>
    );
  }

  const tabs: { key: Tab; label: string; icon: typeof FileText }[] = [
    { key: 'overview', label: 'Overview', icon: FileText },
    { key: 'opinions', label: 'Opinions', icon: BarChart3 },
    { key: 'report', label: 'Report', icon: Eye },
    { key: 'evidence', label: 'Evidence', icon: Shield },
    { key: 'custody', label: 'Custody', icon: GitBranch },
    { key: 'anchoring', label: 'Anchoring', icon: AnchorIcon },
  ];

  const opinions = proposal.opinions || [];
  const report = proposal.report || {};
  const anchorData = proposal.anchor || null;

  return (
    <div className="p-8 max-w-5xl mx-auto">
      {/* Status flow */}
      <div className="mb-8 p-6 rounded-xl border border-white/5 bg-xc-slate/40">
        <ProposalStatusFlow currentStatus={proposal.status} />
      </div>

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="font-heading font-bold text-2xl text-white">{proposal.title}</h1>
          <div className="flex items-center gap-3 mt-2">
            <StatusBadge status={proposal.status} />
            <span className="text-xs text-gray-500 capitalize">{proposal.method}</span>
            <span className="text-xs text-gray-500">{proposal.decision_class}</span>
            {proposal.full_5x5 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400">
                5x5
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 border-b border-white/5">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={cn(
              'flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px',
              activeTab === tab.key
                ? 'text-xc-indigo-400 border-xc-indigo-500'
                : 'text-gray-400 border-transparent hover:text-gray-300',
            )}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="mb-8">
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {proposal.context && (
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-2">Context</h3>
                <p className="text-sm text-gray-300 leading-relaxed bg-xc-slate/40 rounded-lg p-4 border border-white/5">
                  {proposal.context}
                </p>
              </div>
            )}
            {proposal.decision && (
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-2">Decision</h3>
                <p className="text-sm text-gray-300 leading-relaxed bg-xc-slate/40 rounded-lg p-4 border border-white/5">
                  {proposal.decision}
                </p>
              </div>
            )}
            {proposal.consequences && (
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-2">Consequences</h3>
                <p className="text-sm text-gray-300 leading-relaxed bg-xc-slate/40 rounded-lg p-4 border border-white/5">
                  {proposal.consequences}
                </p>
              </div>
            )}
            {proposal.record_hash && (
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-2">Record Hash</h3>
                <div className="flex items-center gap-2 bg-xc-slate/40 rounded-lg p-4 border border-white/5">
                  <code className="text-xs font-mono text-gray-300 flex-1 break-all">
                    {proposal.record_hash}
                  </code>
                  <button
                    onClick={() => copyHash(proposal.record_hash)}
                    className="p-1.5 rounded hover:bg-white/5 transition-colors flex-shrink-0"
                  >
                    {copied ? (
                      <Check className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Copy className="w-4 h-4 text-gray-500" />
                    )}
                  </button>
                </div>
              </div>
            )}
            <div className="text-xs text-gray-500">
              Created {formatDate(proposal.created_at_ms)}
              {proposal.author_did && (
                <span className="ml-2 font-mono">{proposal.author_did.slice(0, 24)}...</span>
              )}
            </div>
          </div>
        )}

        {activeTab === 'opinions' && (
          <div>
            {opinions.length === 0 ? (
              <div className="text-center py-12 text-gray-500 text-sm">
                No opinions submitted yet. Trigger crosscheck to generate opinions.
              </div>
            ) : proposal.full_5x5 ? (
              <FiveByFiveMatrix opinions={opinions} />
            ) : (
              <PanelGrid opinions={opinions} />
            )}
          </div>
        )}

        {activeTab === 'report' && (
          <div className="space-y-6">
            {report.synthesis ? (
              <>
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-2">Synthesis</h3>
                  <p className="text-sm text-gray-300 leading-relaxed bg-xc-slate/40 rounded-lg p-4 border border-white/5">
                    {report.synthesis}
                  </p>
                </div>

                {report.dissent && (
                  <div>
                    <h3 className="text-sm font-medium text-gray-400 mb-2">Dissent</h3>
                    <p className="text-sm text-gray-300 leading-relaxed bg-xc-slate/40 rounded-lg p-4 border border-white/5">
                      {report.dissent}
                    </p>
                  </div>
                )}

                {report.independence && (
                  <div>
                    <h3 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-2">
                      <Shield className="w-4 h-4" />
                      Independence Analysis
                    </h3>
                    <div className="bg-xc-slate/40 rounded-lg p-4 border border-white/5 space-y-3">
                      <div className="flex items-center gap-3">
                        <span className="text-xs text-gray-400">Result:</span>
                        <span
                          className={cn(
                            'text-xs font-medium px-2 py-0.5 rounded',
                            report.independence.independent
                              ? 'bg-emerald-500/20 text-emerald-400'
                              : 'bg-red-500/20 text-red-400',
                          )}
                        >
                          {report.independence.independent ? 'Independent' : 'Correlated'}
                        </span>
                      </div>
                      {report.independence.clusters && (
                        <div>
                          <span className="text-xs text-gray-400">Clusters: </span>
                          <span className="text-xs text-gray-300">
                            {report.independence.clusters} detected
                          </span>
                          <div className="flex gap-1 mt-2">
                            {Array.from({ length: report.independence.clusters }).map((_, i) => (
                              <div
                                key={i}
                                className="h-3 flex-1 rounded-sm bg-xc-indigo-500/30"
                                style={{ opacity: 0.5 + (i * 0.5) / Math.max(report.independence.clusters - 1, 1) }}
                              />
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {report.coordination && report.coordination.signals && report.coordination.signals.length > 0 && (
                  <div>
                    <h3 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400" />
                      Coordination Signals
                    </h3>
                    <ul className="space-y-2">
                      {report.coordination.signals.map((sig: string, i: number) => (
                        <li
                          key={i}
                          className="text-sm text-amber-300 bg-amber-500/5 rounded-lg p-3 border border-amber-500/10"
                        >
                          {sig}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            ) : (
              <div className="text-center py-12 text-gray-500 text-sm">
                No synthesis report available. Run crosscheck and synthesize first.
              </div>
            )}
          </div>
        )}

        {activeTab === 'evidence' && (
          <div>
            {evidence.length === 0 ? (
              <div className="text-center py-12 text-gray-500 text-sm">
                No evidence items attached
              </div>
            ) : (
              <div className="space-y-3">
                {evidence.map((item: any, i: number) => (
                  <div
                    key={item.id || i}
                    className="rounded-lg border border-white/5 bg-xc-slate/40 p-4"
                  >
                    <div className="flex items-start justify-between mb-2">
                      <span className="text-xs px-2 py-0.5 rounded bg-xc-indigo-500/20 text-xc-indigo-400 capitalize">
                        {item.kind}
                      </span>
                      {item.content_hash && (
                        <code className="text-[10px] font-mono text-gray-500">
                          {item.content_hash.slice(0, 12)}...
                        </code>
                      )}
                    </div>
                    <p className="text-sm text-gray-300">{item.description}</p>
                    {item.uri && (
                      <a
                        href={item.uri}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-xc-indigo-400 hover:underline mt-2 inline-flex items-center gap-1"
                      >
                        <LinkIcon className="w-3 h-3" />
                        {item.uri}
                      </a>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'custody' && <CustodyTimeline events={custody} />}

        {activeTab === 'anchoring' && <AnchorReceipt anchor={anchorData} />}
      </div>

      {/* Action buttons */}
      <div className="flex items-center gap-3 pt-6 border-t border-white/5">
        {proposal.status === 'draft' && (
          <ActionButton
            label="Submit for Review"
            loading={submitMutation.isPending}
            onClick={() => submitMutation.mutate()}
          />
        )}
        {proposal.status === 'submitted' && (
          <ActionButton
            label="Trigger Crosscheck"
            loading={crosscheckMutation.isPending}
            onClick={() => crosscheckMutation.mutate()}
          />
        )}
        {proposal.status === 'crosschecking' && (
          <ActionButton
            label="Synthesize Report"
            loading={synthesizeMutation.isPending}
            onClick={() => synthesizeMutation.mutate()}
          />
        )}
        {proposal.status === 'verified' && (
          <ActionButton
            label="Anchor to Chain"
            loading={anchorMutation.isPending}
            onClick={() => anchorMutation.mutate()}
          />
        )}
        {proposal.status === 'anchored' && (
          <ActionButton
            label="Open Deliberation"
            loading={deliberateMutation.isPending}
            onClick={() => deliberateMutation.mutate()}
          />
        )}
      </div>
    </div>
  );
}

function ActionButton({
  label,
  loading,
  onClick,
}: {
  label: string;
  loading: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-gradient-to-r from-xc-indigo-500 to-xc-purple-500 text-white font-medium text-sm hover:shadow-lg hover:shadow-xc-indigo-500/25 transition-all disabled:opacity-50"
    >
      {loading && <Loader2 className="w-4 h-4 animate-spin" />}
      {label}
    </button>
  );
}
