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

import { cn } from '@/lib/utils';
import { PANEL_COLORS } from '@/lib/utils';
import StanceTag from '@/components/StanceTag';
import { AlertTriangle, Bot } from 'lucide-react';

interface Opinion {
  agent_did: string;
  agent_label?: string;
  model?: string;
  stance: string;
  summary: string;
  rationale?: string;
  confidence?: number;
  risks?: string[];
  panel?: string;
  property?: string;
}

interface OpinionCardProps {
  opinion: Opinion;
  compact?: boolean;
}

export default function OpinionCard({ opinion, compact = false }: OpinionCardProps) {
  const confidence = opinion.confidence ?? 0;

  return (
    <div className={cn('rounded-lg border border-white/5 bg-xc-slate/60 p-4', compact && 'p-3')}>
      {/* Header */}
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="flex items-center gap-2 min-w-0">
          <Bot className="w-4 h-4 text-gray-400 flex-shrink-0" />
          <span className="text-sm font-medium text-white truncate">
            {opinion.agent_label || opinion.agent_did.slice(0, 16)}
          </span>
        </div>
        <StanceTag stance={opinion.stance} size={compact ? 'sm' : 'md'} />
      </div>

      {/* Model & Panel badges */}
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        {opinion.model && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-gray-400 font-mono">
            {opinion.model}
          </span>
        )}
        {opinion.panel && (
          <span
            className={cn(
              'text-[10px] px-1.5 py-0.5 rounded font-medium',
              PANEL_COLORS[opinion.panel] || 'bg-gray-500/20 text-gray-400',
            )}
          >
            {opinion.panel}
          </span>
        )}
        {opinion.property && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 font-medium">
            {opinion.property}
          </span>
        )}
      </div>

      {/* Summary */}
      <p className={cn('text-sm text-gray-300 mb-3', compact && 'text-xs line-clamp-3')}>
        {opinion.summary}
      </p>

      {/* Confidence bar */}
      <div className="mb-3">
        <div className="flex justify-between text-xs text-gray-400 mb-1">
          <span>Confidence</span>
          <span>{(confidence * 100).toFixed(0)}%</span>
        </div>
        <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
          <div
            className={cn(
              'h-full rounded-full transition-all',
              confidence >= 0.8
                ? 'bg-emerald-500'
                : confidence >= 0.5
                  ? 'bg-amber-500'
                  : 'bg-red-500',
            )}
            style={{ width: `${confidence * 100}%` }}
          />
        </div>
      </div>

      {/* Risks */}
      {opinion.risks && opinion.risks.length > 0 && !compact && (
        <div className="space-y-1.5">
          <span className="text-xs font-medium text-gray-400 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> Risks
          </span>
          <ul className="space-y-1">
            {opinion.risks.map((risk, i) => (
              <li key={i} className="text-xs text-gray-400 pl-3 border-l border-red-500/30">
                {risk}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
