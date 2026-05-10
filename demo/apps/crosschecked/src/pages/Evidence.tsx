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
import { listProposals, listEvidence, addEvidence } from '@/lib/api';
import { FileSearch, Plus, Loader2, Link as LinkIcon, Hash, X } from 'lucide-react';

export default function Evidence() {
  const queryClient = useQueryClient();
  const [selectedProposal, setSelectedProposal] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [kind, setKind] = useState('document');
  const [description, setDescription] = useState('');
  const [uri, setUri] = useState('');

  const { data: proposals = [] } = useQuery({
    queryKey: ['proposals'],
    queryFn: () => listProposals(),
  });

  const { data: evidence = [], isLoading: loadingEvidence } = useQuery({
    queryKey: ['evidence', selectedProposal],
    queryFn: () => listEvidence(selectedProposal),
    enabled: !!selectedProposal,
  });

  const addMutation = useMutation({
    mutationFn: () =>
      addEvidence(selectedProposal, {
        kind,
        description,
        uri: uri || undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['evidence', selectedProposal] });
      setShowForm(false);
      setDescription('');
      setUri('');
    },
  });

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="font-heading font-bold text-2xl text-white">Evidence</h1>
          <p className="text-sm text-gray-400 mt-1">Manage supporting evidence for proposals</p>
        </div>
        {selectedProposal && (
          <button
            onClick={() => setShowForm(true)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-xc-indigo-500 to-xc-purple-500 text-white font-medium text-sm"
          >
            <Plus className="w-4 h-4" />
            Add Evidence
          </button>
        )}
      </div>

      {/* Proposal selector */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-400 mb-1.5">Select Proposal</label>
        <select
          value={selectedProposal}
          onChange={(e) => setSelectedProposal(e.target.value)}
          className="w-full max-w-md px-4 py-2.5 rounded-lg bg-xc-slate border border-white/10 text-white text-sm focus:outline-none focus:border-xc-indigo-500"
        >
          <option value="">Choose a proposal...</option>
          {proposals.map((p) => (
            <option key={p.id} value={p.id}>
              {p.title}
            </option>
          ))}
        </select>
      </div>

      {/* Add form */}
      {showForm && (
        <div className="mb-6 rounded-xl border border-xc-indigo-500/20 bg-xc-slate/60 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-white">Add Evidence Item</h3>
            <button onClick={() => setShowForm(false)} className="p-1 hover:bg-white/5 rounded">
              <X className="w-4 h-4 text-gray-400" />
            </button>
          </div>
          <div className="space-y-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Kind</label>
              <select
                value={kind}
                onChange={(e) => setKind(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-xc-navy border border-white/10 text-white text-sm focus:outline-none focus:border-xc-indigo-500"
              >
                <option value="document">Document</option>
                <option value="data">Data</option>
                <option value="testimony">Testimony</option>
                <option value="analysis">Analysis</option>
                <option value="precedent">Precedent</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Description</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
                className="w-full px-3 py-2 rounded-lg bg-xc-navy border border-white/10 text-white text-sm focus:outline-none focus:border-xc-indigo-500 resize-none"
                placeholder="Describe this evidence"
                required
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">URI (optional)</label>
              <input
                type="text"
                value={uri}
                onChange={(e) => setUri(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-xc-navy border border-white/10 text-white text-sm focus:outline-none focus:border-xc-indigo-500"
                placeholder="https://..."
              />
            </div>
            <button
              onClick={() => addMutation.mutate()}
              disabled={!description || addMutation.isPending}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-xc-indigo-500 to-xc-purple-500 text-white font-medium text-sm disabled:opacity-50"
            >
              {addMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              Submit Evidence
            </button>
          </div>
        </div>
      )}

      {/* Evidence list */}
      {!selectedProposal ? (
        <div className="text-center py-16 text-gray-500">
          <FileSearch className="w-12 h-12 mx-auto mb-4 opacity-30" />
          <p className="text-sm">Select a proposal to view evidence</p>
        </div>
      ) : loadingEvidence ? (
        <div className="flex items-center justify-center h-32">
          <Loader2 className="w-5 h-5 text-xc-indigo-400 animate-spin" />
        </div>
      ) : evidence.length === 0 ? (
        <div className="text-center py-12 text-gray-500 text-sm">
          No evidence items for this proposal
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
                  <div className="flex items-center gap-1">
                    <Hash className="w-3 h-3 text-gray-500" />
                    <code className="text-[10px] font-mono text-gray-500">
                      {item.content_hash.slice(0, 12)}...
                    </code>
                  </div>
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
  );
}
