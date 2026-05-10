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

import { cn, timeAgo } from '@/lib/utils';
import { Clock, ShieldCheck, User } from 'lucide-react';

interface CustodyEvent {
  actor_did: string;
  role?: string;
  action: string;
  timestamp_ms: number;
  signature?: string;
}

interface CustodyTimelineProps {
  events: CustodyEvent[];
}

export default function CustodyTimeline({ events }: CustodyTimelineProps) {
  if (!events || events.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500 text-sm">
        No custody events recorded
      </div>
    );
  }

  return (
    <div className="relative pl-6">
      {/* Vertical line */}
      <div className="absolute left-2.5 top-0 bottom-0 w-px bg-white/10" />

      <div className="space-y-6">
        {events.map((event, i) => (
          <div key={i} className="relative">
            {/* Dot */}
            <div
              className={cn(
                'absolute -left-[14px] top-1.5 w-3 h-3 rounded-full border-2',
                event.signature
                  ? 'bg-xc-indigo-500 border-xc-indigo-400'
                  : 'bg-xc-slate border-gray-500',
              )}
            />

            <div className="bg-xc-slate/60 rounded-lg border border-white/5 p-4 ml-2">
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="flex items-center gap-2">
                  <User className="w-3.5 h-3.5 text-gray-400" />
                  <span className="text-sm font-mono text-gray-300 truncate max-w-[200px]">
                    {event.actor_did.slice(0, 20)}...
                  </span>
                  {event.role && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-xc-indigo-500/20 text-xc-indigo-400 capitalize">
                      {event.role}
                    </span>
                  )}
                </div>
                {event.signature && (
                  <ShieldCheck className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                )}
              </div>

              <p className="text-sm text-white mb-2">{event.action}</p>

              <div className="flex items-center gap-1.5 text-xs text-gray-500">
                <Clock className="w-3 h-3" />
                {timeAgo(event.timestamp_ms)}
                <span className="ml-2 font-mono text-[10px]">
                  {new Date(event.timestamp_ms).toISOString()}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
