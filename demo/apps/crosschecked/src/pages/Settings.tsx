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

import { useAuth } from '@/hooks/useAuth';
import { PANELS } from '@/lib/utils';
import { ShieldCheck, User, Info, Layers } from 'lucide-react';

export default function Settings() {
  const { auth } = useAuth();

  return (
    <div className="p-8 max-w-3xl mx-auto">
      <div className="mb-8">
        <h1 className="font-heading font-bold text-2xl text-white">Settings</h1>
        <p className="text-sm text-gray-400 mt-1">Identity and system information</p>
      </div>

      {/* Identity */}
      <div className="rounded-xl border border-white/5 bg-xc-slate/40 p-6 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <User className="w-5 h-5 text-xc-indigo-400" />
          <h2 className="font-heading font-semibold text-white">Identity</h2>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-gray-500 uppercase tracking-wider">DID</label>
            <p className="text-sm font-mono text-gray-300 mt-1 break-all">{auth?.did}</p>
          </div>
          <div>
            <label className="text-xs text-gray-500 uppercase tracking-wider">Display Name</label>
            <p className="text-sm text-white mt-1">{auth?.displayName}</p>
          </div>
          <div>
            <label className="text-xs text-gray-500 uppercase tracking-wider">Role</label>
            <span className="inline-block mt-1 text-xs px-2 py-0.5 rounded bg-xc-indigo-500/20 text-xc-indigo-400 capitalize">
              {auth?.role || 'member'}
            </span>
          </div>
        </div>
      </div>

      {/* About */}
      <div className="rounded-xl border border-white/5 bg-xc-slate/40 p-6 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <Info className="w-5 h-5 text-xc-indigo-400" />
          <h2 className="font-heading font-semibold text-white">About CrossChecked</h2>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-gray-500 uppercase tracking-wider">Version</label>
            <p className="text-sm text-gray-300 mt-1">v0.1.0-beta</p>
          </div>
          <div>
            <label className="text-xs text-gray-500 uppercase tracking-wider">Trust Fabric</label>
            <p className="text-sm text-gray-300 mt-1">
              EXOCHAIN CGR Kernel -- hash-chained custody, multi-panel crosscheck, constitutional governance
            </p>
          </div>
          <div>
            <label className="text-xs text-gray-500 uppercase tracking-wider">Panels</label>
            <div className="flex flex-wrap gap-2 mt-2">
              {PANELS.map((panel) => (
                <span
                  key={panel}
                  className="text-xs px-2.5 py-1 rounded-md bg-xc-indigo-500/10 text-xc-indigo-400 border border-xc-indigo-500/20"
                >
                  {panel}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Powered by */}
      <div className="rounded-xl border border-white/5 bg-gradient-to-br from-xc-indigo-500/5 to-xc-purple-500/5 p-6 text-center">
        <div className="flex items-center justify-center gap-2 mb-2">
          <Layers className="w-5 h-5 text-xc-indigo-400" />
          <ShieldCheck className="w-5 h-5 text-xc-purple-400" />
        </div>
        <p className="text-sm font-heading font-semibold text-white">
          Powered by <span className="text-xc-indigo-400">EXOCHAIN</span>
        </p>
        <p className="text-xs text-gray-500 mt-1">
          Cryptographic governance runtime for plural intelligence
        </p>
      </div>
    </div>
  );
}
