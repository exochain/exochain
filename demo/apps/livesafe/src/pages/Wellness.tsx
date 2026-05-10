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
import { useAuth } from '@/hooks/useAuth';
import { Heart, CheckCircle, Clock, AlertTriangle, Send } from 'lucide-react';
import { timeAgo } from '@/lib/utils';

interface WellnessCheck {
  id: string;
  type: 'sent' | 'received';
  from_name: string;
  status: 'pending' | 'ok' | 'help' | 'expired';
  created_at_ms: number;
  responded_at_ms: number | null;
}

export default function Wellness() {
  const { auth } = useAuth();
  const [checks, setChecks] = useState<WellnessCheck[]>([]);
  const [sending, setSending] = useState(false);

  const sendCheckIn = () => {
    setSending(true);
    setTimeout(() => {
      setChecks(prev => [{
        id: crypto.randomUUID(),
        type: 'sent',
        from_name: auth?.displayName || '',
        status: 'ok',
        created_at_ms: Date.now(),
        responded_at_ms: Date.now(),
      }, ...prev]);
      setSending(false);
    }, 500);
  };

  return (
    <div className="p-8 max-w-2xl">
      <div className="mb-8">
        <h2 className="text-2xl font-heading font-bold text-white">Wellness Checks</h2>
        <p className="text-sm text-white/40 mt-1">
          Regular check-ins with your safety network — the anti-churn heartbeat
        </p>
      </div>

      {/* Explainer */}
      <div className="bg-white/[0.03] border border-white/10 rounded-xl p-5 mb-8">
        <div className="flex items-start gap-3">
          <Heart size={18} className="text-red-400 mt-0.5 shrink-0" />
          <div>
            <p className="text-sm text-white font-medium mb-1">How Wellness Checks Work</p>
            <p className="text-xs text-white/40 leading-relaxed">
              Periodic "I'm OK" signals to your PACE trustees. If you go silent for too long,
              your trustees are notified and can initiate a welfare check. This simple heartbeat
              keeps your safety network active and ensures someone notices if something goes wrong.
            </p>
          </div>
        </div>
      </div>

      {/* Check In Button */}
      <button
        onClick={sendCheckIn}
        disabled={sending}
        className="w-full bg-blue-500 hover:bg-blue-600 disabled:bg-white/10 text-white font-semibold py-5 rounded-xl text-lg transition-all flex items-center justify-center gap-3 mb-8"
      >
        {sending ? (
          <>Sending...</>
        ) : (
          <>
            <Send size={18} />
            I'm OK — Send Wellness Check
          </>
        )}
      </button>

      {/* Status Cards */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        <div className="bg-white/[0.03] border border-white/10 rounded-xl p-4 text-center">
          <CheckCircle size={18} className="text-blue-400 mx-auto mb-2" />
          <p className="text-xl font-heading font-bold text-white">{checks.length}</p>
          <p className="text-[11px] text-white/30">Check-ins Sent</p>
        </div>
        <div className="bg-white/[0.03] border border-white/10 rounded-xl p-4 text-center">
          <Clock size={18} className="text-amber-400 mx-auto mb-2" />
          <p className="text-xl font-heading font-bold text-white">
            {checks.length > 0 ? timeAgo(checks[0].created_at_ms) : 'Never'}
          </p>
          <p className="text-[11px] text-white/30">Last Check-in</p>
        </div>
        <div className="bg-white/[0.03] border border-white/10 rounded-xl p-4 text-center">
          <AlertTriangle size={18} className="text-white/20 mx-auto mb-2" />
          <p className="text-xl font-heading font-bold text-white">0</p>
          <p className="text-[11px] text-white/30">Alerts</p>
        </div>
      </div>

      {/* History */}
      <h3 className="text-sm font-heading font-semibold text-white/60 mb-3 uppercase tracking-wider">
        Check-in History
      </h3>
      {checks.length === 0 ? (
        <div className="text-center py-12 text-white/20">
          <Heart size={32} className="mx-auto mb-3 opacity-50" />
          <p className="text-sm">No check-ins yet</p>
          <p className="text-xs mt-1">Send your first wellness check to get started</p>
        </div>
      ) : (
        <div className="space-y-2">
          {checks.map(check => (
            <div key={check.id} className="flex items-center justify-between bg-white/[0.03] border border-white/10 rounded-lg px-4 py-3">
              <div className="flex items-center gap-3">
                <CheckCircle size={14} className="text-blue-400" />
                <div>
                  <p className="text-sm text-white">Wellness check sent</p>
                  <p className="text-[11px] text-white/30">{timeAgo(check.created_at_ms)}</p>
                </div>
              </div>
              <span className="text-xs text-blue-300 bg-blue-500/10 px-2 py-0.5 rounded">OK</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
