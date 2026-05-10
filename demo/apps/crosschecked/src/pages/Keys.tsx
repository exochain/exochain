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
import { useMutation } from '@tanstack/react-query';
import { registerKey, getKey } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import { KeyRound, Search, Loader2, Copy, Check, ShieldCheck } from 'lucide-react';

export default function Keys() {
  const { auth } = useAuth();
  const [lookupDid, setLookupDid] = useState('');
  const [lookupResult, setLookupResult] = useState<{ actor_did: string; public_key_b64: string } | null>(null);
  const [lookupError, setLookupError] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [registerSuccess, setRegisterSuccess] = useState(false);
  const [copied, setCopied] = useState(false);

  const registerMutation = useMutation({
    mutationFn: () =>
      registerKey({ actor_did: auth!.did, public_key_b64: publicKey }),
    onSuccess: () => {
      setRegisterSuccess(true);
      setPublicKey('');
      setTimeout(() => setRegisterSuccess(false), 3000);
    },
  });

  const lookupMutation = useMutation({
    mutationFn: () => getKey(lookupDid),
    onSuccess: (data) => {
      setLookupResult(data);
      setLookupError('');
    },
    onError: () => {
      setLookupResult(null);
      setLookupError('Key not found for this DID');
    },
  });

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-8 max-w-3xl mx-auto">
      <div className="mb-8">
        <h1 className="font-heading font-bold text-2xl text-white">Key Management</h1>
        <p className="text-sm text-gray-400 mt-1">Register and lookup public keys for attestation</p>
      </div>

      {/* Register key */}
      <div className="rounded-xl border border-white/5 bg-xc-slate/40 p-6 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <KeyRound className="w-5 h-5 text-xc-indigo-400" />
          <h2 className="font-heading font-semibold text-white">Register Public Key</h2>
        </div>
        <div className="space-y-3">
          <div>
            <label className="block text-xs text-gray-400 mb-1">Your DID</label>
            <div className="px-3 py-2 rounded-lg bg-xc-navy border border-white/5 text-sm font-mono text-gray-400">
              {auth?.did}
            </div>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Public Key (Base64)</label>
            <textarea
              value={publicKey}
              onChange={(e) => setPublicKey(e.target.value)}
              rows={3}
              className="w-full px-3 py-2 rounded-lg bg-xc-navy border border-white/10 text-white text-sm font-mono focus:outline-none focus:border-xc-indigo-500 resize-none"
              placeholder="Paste your base64-encoded public key"
            />
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => registerMutation.mutate()}
              disabled={!publicKey || registerMutation.isPending}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-xc-indigo-500 to-xc-purple-500 text-white font-medium text-sm disabled:opacity-50"
            >
              {registerMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              Register Key
            </button>
            {registerSuccess && (
              <span className="text-xs text-emerald-400 flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5" /> Key registered
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Lookup key */}
      <div className="rounded-xl border border-white/5 bg-xc-slate/40 p-6">
        <div className="flex items-center gap-2 mb-4">
          <Search className="w-5 h-5 text-xc-indigo-400" />
          <h2 className="font-heading font-semibold text-white">Lookup Key</h2>
        </div>
        <div className="space-y-3">
          <div>
            <label className="block text-xs text-gray-400 mb-1">DID to Lookup</label>
            <input
              type="text"
              value={lookupDid}
              onChange={(e) => setLookupDid(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-xc-navy border border-white/10 text-white text-sm font-mono focus:outline-none focus:border-xc-indigo-500"
              placeholder="did:key:z..."
            />
          </div>
          <button
            onClick={() => lookupMutation.mutate()}
            disabled={!lookupDid || lookupMutation.isPending}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-white/10 text-gray-300 text-sm hover:border-white/20 disabled:opacity-50"
          >
            {lookupMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            <Search className="w-4 h-4" />
            Lookup
          </button>

          {lookupError && <p className="text-xs text-red-400">{lookupError}</p>}

          {lookupResult && (
            <div className="mt-4 p-4 rounded-lg bg-xc-navy border border-white/5">
              <div className="mb-2">
                <label className="text-xs text-gray-500">Actor DID</label>
                <p className="text-sm font-mono text-gray-300 break-all">{lookupResult.actor_did}</p>
              </div>
              <div>
                <label className="text-xs text-gray-500">Public Key (Base64)</label>
                <div className="flex items-start gap-2">
                  <code className="text-sm font-mono text-gray-300 break-all flex-1">
                    {lookupResult.public_key_b64}
                  </code>
                  <button
                    onClick={() => copyToClipboard(lookupResult.public_key_b64)}
                    className="p-1 rounded hover:bg-white/5 flex-shrink-0"
                  >
                    {copied ? (
                      <Check className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Copy className="w-4 h-4 text-gray-500" />
                    )}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
