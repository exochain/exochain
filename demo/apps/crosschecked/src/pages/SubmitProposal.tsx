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
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { createProposal } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import { METHODS, DECISION_CLASSES } from '@/lib/utils';
import { Send, Loader2, Grid3X3 } from 'lucide-react';

export default function SubmitProposal() {
  const { auth } = useAuth();
  const navigate = useNavigate();

  const [title, setTitle] = useState('');
  const [context, setContext] = useState('');
  const [decision, setDecision] = useState('');
  const [consequences, setConsequences] = useState('');
  const [method, setMethod] = useState<string>(METHODS[0]);
  const [decisionClass, setDecisionClass] = useState<string>(DECISION_CLASSES[0]);
  const [full5x5, setFull5x5] = useState(false);

  const mutation = useMutation({
    mutationFn: () =>
      createProposal({
        author_did: auth!.did,
        title,
        context,
        decision: decision || undefined,
        consequences: consequences || undefined,
        method,
        decision_class: decisionClass,
        full_5x5: full5x5,
      }),
    onSuccess: (data) => {
      navigate(`/proposals/${data.id}`);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate();
  };

  return (
    <div className="p-8 max-w-3xl mx-auto">
      <div className="mb-8">
        <h1 className="font-heading font-bold text-2xl text-white">New Proposal</h1>
        <p className="text-sm text-gray-400 mt-1">Submit a decision for crosscheck review</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Title */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">Title</label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="w-full px-4 py-2.5 rounded-lg bg-xc-navy border border-white/10 text-white text-sm placeholder:text-gray-500 focus:outline-none focus:border-xc-indigo-500 transition-colors"
            placeholder="Brief title for your proposal"
            required
          />
        </div>

        {/* Context */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">Context</label>
          <textarea
            value={context}
            onChange={(e) => setContext(e.target.value)}
            rows={4}
            className="w-full px-4 py-2.5 rounded-lg bg-xc-navy border border-white/10 text-white text-sm placeholder:text-gray-500 focus:outline-none focus:border-xc-indigo-500 transition-colors resize-none"
            placeholder="Background context and situation description"
            required
          />
        </div>

        {/* Decision */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">Decision</label>
          <textarea
            value={decision}
            onChange={(e) => setDecision(e.target.value)}
            rows={3}
            className="w-full px-4 py-2.5 rounded-lg bg-xc-navy border border-white/10 text-white text-sm placeholder:text-gray-500 focus:outline-none focus:border-xc-indigo-500 transition-colors resize-none"
            placeholder="What decision is being proposed?"
          />
        </div>

        {/* Consequences */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">Consequences</label>
          <textarea
            value={consequences}
            onChange={(e) => setConsequences(e.target.value)}
            rows={3}
            className="w-full px-4 py-2.5 rounded-lg bg-xc-navy border border-white/10 text-white text-sm placeholder:text-gray-500 focus:outline-none focus:border-xc-indigo-500 transition-colors resize-none"
            placeholder="Expected consequences and impact"
          />
        </div>

        {/* Method & Class */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">Method</label>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="w-full px-4 py-2.5 rounded-lg bg-xc-navy border border-white/10 text-white text-sm focus:outline-none focus:border-xc-indigo-500 transition-colors"
            >
              {METHODS.map((m) => (
                <option key={m} value={m}>
                  {m.charAt(0).toUpperCase() + m.slice(1)}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1.5">Decision Class</label>
            <select
              value={decisionClass}
              onChange={(e) => setDecisionClass(e.target.value)}
              className="w-full px-4 py-2.5 rounded-lg bg-xc-navy border border-white/10 text-white text-sm focus:outline-none focus:border-xc-indigo-500 transition-colors"
            >
              {DECISION_CLASSES.map((dc) => (
                <option key={dc} value={dc}>
                  {dc}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* 5x5 Toggle */}
        <div className="flex items-center gap-3 p-4 rounded-lg border border-white/5 bg-xc-slate/40">
          <button
            type="button"
            onClick={() => setFull5x5(!full5x5)}
            className={`relative w-11 h-6 rounded-full transition-colors ${
              full5x5 ? 'bg-xc-indigo-500' : 'bg-white/10'
            }`}
          >
            <span
              className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${
                full5x5 ? 'translate-x-5' : ''
              }`}
            />
          </button>
          <div className="flex items-center gap-2">
            <Grid3X3 className="w-4 h-4 text-xc-indigo-400" />
            <div>
              <p className="text-sm font-medium text-white">Enable Full 5x5 Treatment</p>
              <p className="text-xs text-gray-500">
                5 panels x 5 digital-rights properties for comprehensive analysis
              </p>
            </div>
          </div>
        </div>

        {/* Error */}
        {mutation.isError && (
          <p className="text-sm text-red-400">
            {(mutation.error as Error).message || 'Failed to create proposal'}
          </p>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={mutation.isPending}
          className="w-full py-3 rounded-lg bg-gradient-to-r from-xc-indigo-500 to-xc-purple-500 text-white font-medium text-sm hover:shadow-lg hover:shadow-xc-indigo-500/25 transition-all disabled:opacity-50 flex items-center justify-center gap-2"
        >
          {mutation.isPending ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Creating proposal...
            </>
          ) : (
            <>
              <Send className="w-4 h-4" />
              Submit Proposal
            </>
          )}
        </button>
      </form>
    </div>
  );
}
