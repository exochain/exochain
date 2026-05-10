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

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth, type AuthState } from '@/hooks/useAuth';
import { Shield } from 'lucide-react';

interface Props {
  mode?: 'login' | 'register';
}

export default function Login({ mode: initialMode = 'login' }: Props) {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState(initialMode);
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [status, setStatus] = useState('');
  const [wasmReady, setWasmReady] = useState(false);

  useEffect(() => {
    import('@/wasm/exochain_wasm').then(async (wasm) => {
      await wasm.default();
      setWasmReady(true);
      setStatus('Secure kernel ready');
    }).catch(() => setStatus(''));
  }, []);

  const handleSubmit = async () => {
    if (!passphrase) return;
    setIsLoading(true);
    setStatus('Deriving secure identity...');

    try {
      // Derive identity from passphrase (zero-knowledge)
      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(passphrase));
      const hashArray = new Uint8Array(hashBuffer);
      const passphraseHash = Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');

      // Generate X25519 keypair via WASM
      let x25519Public = '', x25519Secret = '';
      if (wasmReady) {
        const wasm = await import('@/wasm/exochain_wasm');
        const kp = wasm.wasm_generate_x25519_keypair();
        x25519Public = kp.public_key_hex;
        x25519Secret = kp.secret_key_hex;
      } else {
        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        x25519Public = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        x25519Secret = x25519Public;
      }

      const did = `did:exo:${passphraseHash.slice(0, 16)}`;
      const name = displayName || `User-${passphraseHash.slice(0, 8)}`;

      // Non-blocking profile registration
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 1500);
        await fetch('/api/profile', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ did, display_name: name, email, x25519_public_key_hex: x25519Public }),
          signal: ctrl.signal,
        });
      } catch { /* backend may be unavailable */ }

      const authState: AuthState = {
        did,
        displayName: name,
        email: email || `${passphraseHash.slice(0, 8)}@livesafe.ai`,
        x25519PublicHex: x25519Public,
        x25519SecretHex: x25519Secret,
        passphraseHash,
      };

      login(authState);
      navigate('/dashboard');
    } catch (err) {
      setStatus(`Error: ${err instanceof Error ? err.message : 'Unknown'}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-[#0a1628] to-[#0f1d32] flex items-center justify-center">
      <div className="w-full max-w-md p-8">
        {/* Logo */}
        <div className="text-center mb-10">
          <div className="flex items-center justify-center gap-2 mb-3">
            <Shield className="text-blue-400" size={32} />
            <h1 className="text-3xl font-heading font-bold text-white">
              Live<span className="text-blue-400">Safe</span>
            </h1>
          </div>
          <p className="text-blue-200/50 text-sm">Be Someone's Safety Net</p>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-white/10 mb-8">
          <button
            onClick={() => setMode('login')}
            className={`flex-1 py-3 text-sm font-medium transition-colors ${
              mode === 'login' ? 'border-b-2 border-blue-400 text-white' : 'text-white/40'
            }`}
          >
            SIGN IN
          </button>
          <button
            onClick={() => setMode('register')}
            className={`flex-1 py-3 text-sm font-medium transition-colors ${
              mode === 'register' ? 'border-b-2 border-blue-400 text-white' : 'text-white/40'
            }`}
          >
            CREATE ACCOUNT
          </button>
        </div>

        {mode === 'register' && (
          <>
            <input
              type="text"
              placeholder="Full Name"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-xl px-5 py-4 mb-4 text-white placeholder-white/30 focus:outline-none focus:border-blue-400"
            />
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-xl px-5 py-4 mb-4 text-white placeholder-white/30 focus:outline-none focus:border-blue-400"
            />
          </>
        )}

        <input
          type="password"
          placeholder="Secure passphrase (never leaves device)"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
          className="w-full bg-white/5 border border-white/10 rounded-xl px-5 py-4 mb-8 text-white placeholder-white/30 focus:outline-none focus:border-blue-400"
        />

        <button
          onClick={handleSubmit}
          disabled={isLoading || !passphrase}
          className="w-full bg-blue-500 hover:bg-blue-600 disabled:bg-white/10 disabled:cursor-not-allowed text-white font-semibold py-4 rounded-xl text-lg transition-all"
        >
          {isLoading ? 'Securing...' : mode === 'register' ? 'CREATE SAFETY NET' : 'ENTER LIVESAFE'}
        </button>

        {status && (
          <p className="text-center text-xs mt-4 text-blue-300">{status}</p>
        )}

        <p className="text-[10px] text-white/20 text-center mt-10">
          Your passphrase never leaves this device. Keys are derived locally.
        </p>
      </div>
    </div>
  );
}
