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
import { Shield, Clock, CheckCircle, AlertTriangle, UserPlus } from 'lucide-react';

const ROLE_CONFIG: Record<string, { color: string; label: string }> = {
  Primary: { color: 'border-emerald-400 bg-emerald-400/10', label: 'P' },
  Alternate: { color: 'border-blue-400 bg-blue-400/10', label: 'A' },
  Contingency: { color: 'border-amber-400 bg-amber-400/10', label: 'C' },
  Emergency: { color: 'border-red-400 bg-red-400/10', label: 'E' },
};

const STATUS_ICON = {
  pending: Clock,
  accepted: CheckCircle,
  declined: AlertTriangle,
  empty: UserPlus,
};

interface Props {
  role: string;
  trusteeName?: string;
  trusteeEmail?: string;
  status: 'pending' | 'accepted' | 'declined' | 'empty';
  relationship?: string;
  onInvite?: () => void;
}

export default function PaceMemberCard({
  role, trusteeName, trusteeEmail, status, relationship, onInvite,
}: Props) {
  const config = ROLE_CONFIG[role] || ROLE_CONFIG.Primary;
  const StatusIcon = STATUS_ICON[status] || Clock;

  return (
    <div
      className={cn(
        'rounded-xl border-2 p-4 transition-all',
        status === 'empty'
          ? 'border-dashed border-zinc-700 bg-zinc-900/50 cursor-pointer hover:border-zinc-600'
          : config.color,
      )}
      onClick={status === 'empty' ? onInvite : undefined}
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className={cn(
            'w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold',
            status === 'empty' ? 'bg-zinc-800 text-zinc-500' : config.color,
          )}>
            {config.label}
          </span>
          <span className="text-xs font-medium text-zinc-400">{role}</span>
        </div>
        <StatusIcon
          size={16}
          className={cn(
            status === 'accepted' && 'text-emerald-400',
            status === 'pending' && 'text-amber-400',
            status === 'declined' && 'text-red-400',
            status === 'empty' && 'text-zinc-600',
          )}
        />
      </div>

      {status === 'empty' ? (
        <div className="text-center py-2">
          <UserPlus size={20} className="mx-auto text-zinc-600 mb-1" />
          <p className="text-xs text-zinc-500">Invite {role}</p>
        </div>
      ) : (
        <>
          <p className="text-sm font-medium text-white truncate">{trusteeName}</p>
          <p className="text-xs text-zinc-500 truncate">{trusteeEmail}</p>
          {relationship && (
            <p className="text-[10px] text-zinc-600 mt-1">{relationship}</p>
          )}
          <div className="mt-2 flex items-center gap-1">
            <Shield size={10} className="text-zinc-600" />
            <span className="text-[10px] text-zinc-600">
              {status === 'accepted' ? 'Shard confirmed' : 'Awaiting acceptance'}
            </span>
          </div>
        </>
      )}
    </div>
  );
}
