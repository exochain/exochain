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
import { STATUSES } from '@/lib/utils';
import { Check } from 'lucide-react';

interface ProposalStatusFlowProps {
  currentStatus: string;
}

export default function ProposalStatusFlow({ currentStatus }: ProposalStatusFlowProps) {
  const currentIdx = STATUSES.indexOf(currentStatus as any);
  // Exclude 'rejected' from flow line; show it specially
  const flowStatuses = STATUSES.filter((s) => s !== 'rejected');
  const isRejected = currentStatus === 'rejected';

  return (
    <div className="w-full">
      <div className="flex items-center justify-between">
        {flowStatuses.map((status, i) => {
          const isCurrent = status === currentStatus;
          const isPast = !isRejected && currentIdx > i;

          return (
            <div key={status} className="flex items-center flex-1 last:flex-none">
              <div className="flex flex-col items-center">
                <div
                  className={cn(
                    'w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium border-2 transition-all',
                    isCurrent
                      ? 'bg-xc-indigo-500 border-xc-indigo-400 text-white shadow-lg shadow-xc-indigo-500/30'
                      : isPast
                        ? 'bg-emerald-500/20 border-emerald-500 text-emerald-400'
                        : 'bg-white/5 border-white/10 text-gray-500',
                  )}
                >
                  {isPast ? <Check className="w-4 h-4" /> : i + 1}
                </div>
                <span
                  className={cn(
                    'mt-1.5 text-[10px] font-medium capitalize whitespace-nowrap',
                    isCurrent ? 'text-xc-indigo-400' : isPast ? 'text-emerald-400' : 'text-gray-500',
                  )}
                >
                  {status}
                </span>
              </div>
              {i < flowStatuses.length - 1 && (
                <div
                  className={cn(
                    'flex-1 h-px mx-2 mt-[-16px]',
                    isPast ? 'bg-emerald-500/40' : 'bg-white/10',
                  )}
                />
              )}
            </div>
          );
        })}
      </div>

      {isRejected && (
        <div className="mt-3 text-center">
          <span className="inline-flex items-center px-3 py-1 rounded-full bg-red-500/20 text-red-400 text-xs font-medium">
            Rejected
          </span>
        </div>
      )}
    </div>
  );
}
