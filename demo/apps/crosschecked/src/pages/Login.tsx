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
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import { cn } from '@/lib/utils';
import { ShieldCheck, Loader2, Lock, User } from 'lucide-react';

interface LoginProps {
  mode: 'login' | 'register';
}

async function deriveDidFromPassphrase(passphrase: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(passphrase);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  return `did:key:z${hex.slice(0, 48)}`;
}

export default function Login({ mode }: LoginProps) {
  const [activeTab, setActiveTab] = useState<'login' | 'register'>(mode);
  const [displayName, setDisplayName] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const did = await deriveDidFromPassphrase(passphrase);
      const name = activeTab === 'register' ? displayName : `User ${did.slice(-6)}`;
      login({ did, displayName: name, role: 'steward' });
      navigate('/dashboard');
    } catch {
      setError('Authentication failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-xc-navy flex items-center justify-center p-6">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex items-center justify-center gap-3 mb-8">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-xc-indigo-500 to-xc-purple-500 flex items-center justify-center">
            <ShieldCheck className="w-6 h-6 text-white" />
          </div>
          <span className="font-heading font-bold text-white text-xl">
            CrossChecked<span className="text-xc-indigo-400">.ai</span>
          </span>
        </div>

        {/* Card */}
        <div className="rounded-xl border border-white/10 bg-xc-slate/60 p-8">
          {/* Tabs */}
          <div className="flex mb-6 border-b border-white/10">
            <button
              onClick={() => setActiveTab('login')}
              className={cn(
                'flex-1 pb-3 text-sm font-medium transition-colors',
                activeTab === 'login'
                  ? 'text-xc-indigo-400 border-b-2 border-xc-indigo-500'
                  : 'text-gray-400 hover:text-gray-300',
              )}
            >
              Sign In
            </button>
            <button
              onClick={() => setActiveTab('register')}
              className={cn(
                'flex-1 pb-3 text-sm font-medium transition-colors',
                activeTab === 'register'
                  ? 'text-xc-indigo-400 border-b-2 border-xc-indigo-500'
                  : 'text-gray-400 hover:text-gray-300',
              )}
            >
              Create Account
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {activeTab === 'register' && (
              <div>
                <label className="block text-xs text-gray-400 mb-1.5">Display Name</label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                  <input
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-xc-navy border border-white/10 text-white text-sm placeholder:text-gray-500 focus:outline-none focus:border-xc-indigo-500 transition-colors"
                    placeholder="Your display name"
                    required
                  />
                </div>
              </div>
            )}

            <div>
              <label className="block text-xs text-gray-400 mb-1.5">Passphrase</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-xc-navy border border-white/10 text-white text-sm placeholder:text-gray-500 focus:outline-none focus:border-xc-indigo-500 transition-colors"
                  placeholder="Enter your passphrase"
                  required
                />
              </div>
            </div>

            {error && (
              <p className="text-xs text-red-400">{error}</p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-xc-indigo-500 to-xc-purple-500 text-white font-medium text-sm hover:shadow-lg hover:shadow-xc-indigo-500/25 transition-all disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Deriving identity...
                </>
              ) : activeTab === 'login' ? (
                'Sign In'
              ) : (
                'Create Account'
              )}
            </button>
          </form>

          {/* Status */}
          <div className="mt-6 pt-4 border-t border-white/5 flex items-center justify-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-xs text-gray-500">Secure kernel ready</span>
          </div>
        </div>

        {/* Back link */}
        <div className="mt-6 text-center">
          <Link to="/" className="text-xs text-gray-500 hover:text-gray-400 transition-colors">
            Back to CrossChecked.ai
          </Link>
        </div>
      </div>
    </div>
  );
}
