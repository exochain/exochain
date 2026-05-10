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
import { getAfterlifeMessages } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { Heart, Clock, CheckCircle, Lock } from 'lucide-react';

export default function Afterlife() {
  const { auth } = useAuth();
  const did = auth?.did || '';

  const { data: messages } = useQuery({
    queryKey: ['afterlife', did],
    queryFn: () => getAfterlifeMessages(did),
    enabled: !!did,
  });

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-white">Afterlife Messages</h2>
        <p className="text-sm text-zinc-400 mt-1">
          Messages to be delivered after your passing is verified by PACE trustees
        </p>
      </div>

      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 mb-8">
        <div className="flex items-start gap-3">
          <Heart size={20} className="text-rose-400 mt-0.5" />
          <p className="text-xs text-zinc-400 leading-relaxed">
            These messages are encrypted and stored securely. They will only be
            released when 3 of your 4 PACE trustees confirm your passing. You can
            set a delay period before release. You can edit or delete these messages
            at any time while you are alive.
          </p>
        </div>
      </div>

      {(!messages || messages.length === 0) ? (
        <div className="text-center py-16 text-zinc-500">
          <Heart size={32} className="mx-auto mb-3 opacity-50" />
          <p className="text-sm">No afterlife messages yet</p>
          <p className="text-xs mt-1">
            Create one from the Compose page by enabling "Delete-on-Death"
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {messages.map(msg => (
            <div
              key={msg.id}
              className="bg-zinc-900 border border-zinc-800 rounded-xl p-5"
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Lock size={14} className="text-rose-400" />
                  <span className="text-sm font-medium text-white">
                    {msg.subject || `[${msg.content_type}]`}
                  </span>
                </div>
                {msg.released ? (
                  <span className="flex items-center gap-1 text-xs text-emerald-400">
                    <CheckCircle size={12} /> Released
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-xs text-amber-400">
                    <Clock size={12} /> Pending
                  </span>
                )}
              </div>
              <p className="text-xs text-zinc-500">
                To: {msg.recipient_did.slice(0, 30)}...
              </p>
              <div className="flex items-center gap-4 mt-3 text-[10px] text-zinc-600">
                <span>Created: {formatDate(msg.created_at_ms)}</span>
                {msg.release_delay_hours > 0 && (
                  <span>Delay: {msg.release_delay_hours}h after verification</span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
