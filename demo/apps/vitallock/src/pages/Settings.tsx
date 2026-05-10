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
import { Settings as SettingsIcon, Key, Shield, Copy } from 'lucide-react';

export default function Settings() {
  const { auth } = useAuth();

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="p-8 max-w-2xl">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-white">Settings</h2>
      </div>

      {/* Identity */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <Shield size={16} className="text-emerald-400" />
          <h3 className="text-sm font-medium text-white">Identity</h3>
        </div>
        <div className="space-y-3">
          <div>
            <label className="block text-[10px] text-zinc-500 mb-1">DID</label>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs text-emerald-400 bg-zinc-800 rounded px-3 py-2 font-mono">
                {auth?.did}
              </code>
              <button onClick={() => copyToClipboard(auth?.did || '')} className="text-zinc-500 hover:text-white">
                <Copy size={14} />
              </button>
            </div>
          </div>
          <div>
            <label className="block text-[10px] text-zinc-500 mb-1">Display Name</label>
            <p className="text-sm text-white">{auth?.displayName}</p>
          </div>
        </div>
      </div>

      {/* Keys */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <Key size={16} className="text-amber-400" />
          <h3 className="text-sm font-medium text-white">Cryptographic Keys</h3>
        </div>
        <div className="space-y-3">
          <div>
            <label className="block text-[10px] text-zinc-500 mb-1">
              X25519 Public Key (share with message senders)
            </label>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-[10px] text-emerald-400 bg-zinc-800 rounded px-3 py-2 font-mono truncate">
                {auth?.x25519PublicHex}
              </code>
              <button onClick={() => copyToClipboard(auth?.x25519PublicHex || '')} className="text-zinc-500 hover:text-white shrink-0">
                <Copy size={14} />
              </button>
            </div>
          </div>
          <div>
            <label className="block text-[10px] text-zinc-500 mb-1">
              Ed25519 Public Key (for signature verification)
            </label>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-[10px] text-emerald-400 bg-zinc-800 rounded px-3 py-2 font-mono truncate">
                {auth?.ed25519PublicHex}
              </code>
              <button onClick={() => copyToClipboard(auth?.ed25519PublicHex || '')} className="text-zinc-500 hover:text-white shrink-0">
                <Copy size={14} />
              </button>
            </div>
          </div>
        </div>
        <p className="text-[10px] text-zinc-600 mt-3">
          Secret keys are derived from your passphrase and never leave this device.
        </p>
      </div>

      {/* About */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <SettingsIcon size={16} className="text-zinc-400" />
          <h3 className="text-sm font-medium text-white">About VitalLock</h3>
        </div>
        <div className="text-xs text-zinc-400 space-y-1">
          <p>Version: 0.1.0-beta</p>
          <p>Trust Fabric: EXOCHAIN v0.1.0-beta</p>
          <p>Encryption: X25519 + XChaCha20-Poly1305</p>
          <p>Key Sharding: Shamir (3-of-4 threshold)</p>
          <p>Post-Quantum: ML-DSA-65 (NIST FIPS 204) ready</p>
        </div>
      </div>
    </div>
  );
}
