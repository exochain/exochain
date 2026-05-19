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
import { useAuth, type AuthState } from '@/hooks/useAuth';
import {
  initCrypto, isCryptoReady,
  generateX25519Keypair as genX25519Wasm,
} from '@/lib/crypto';

export default function Login() {
  const { login } = useAuth();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [displayName, setDisplayName] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [status, setStatus] = useState('');

  // Initialize WASM on mount
  useEffect(() => {
    initCrypto().then(() => setStatus('EXOCHAIN CGR Kernel ready'));
  }, []);

  const handleSubmit = async () => {
    if (!passphrase) return;
    setIsLoading(true);
    setStatus('Deriving zero-knowledge identity...');

    try {
      // Ensure WASM is ready
      if (!isCryptoReady()) await initCrypto();

      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(passphrase));
      const hashArray = new Uint8Array(hashBuffer);
      const identityDigestHex = Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');

      // Generate X25519 keypair via WASM (real Diffie-Hellman crypto)
      const x25519Kp = genX25519Wasm();
      const x25519Public = x25519Kp.public_key_hex;
      const x25519Secret = x25519Kp.secret_key_hex;

      // Derive DID from passphrase hash (deterministic across sessions)
      const did = `did:exo:${identityDigestHex.slice(0, 16)}`;
      const name = displayName || `User-${identityDigestHex.slice(0, 8)}`;

      setStatus('Initializing sharded keystore...');

      // Register profile (non-blocking — skip if backend unavailable)
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 1500);
        await fetch('/api/profile', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ did, display_name: name, x25519_public_key_hex: x25519Public }),
          signal: ctrl.signal,
        });
        clearTimeout(timer);
      } catch {
        // Backend unavailable — continue without profile registration
      }

      const authState: AuthState = {
        did,
        displayName: name,
        x25519PublicHex: x25519Public,
        x25519SecretHex: x25519Secret,
      };

      login(authState);
    } catch (err) {
      setStatus(`Error: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-zinc-950 to-black flex items-center justify-center text-white font-sans">
      <div className="w-full max-w-md p-8">
        {/* Logo */}
        <div className="text-center mb-10">
          <h1 className="text-5xl font-bold tracking-tighter">
            VITAL<span className="text-emerald-400">LOCK</span>
          </h1>
          <p className="text-emerald-400 text-sm mt-2">The Privacy Company</p>
          <p className="text-zinc-400 text-xs mt-1">
            Privacy by physics. Secrets that survive you.
          </p>
        </div>

        {/* Mode tabs */}
        <div className="flex border-b border-zinc-800 mb-8">
          <button
            onClick={() => setMode('login')}
            className={`flex-1 py-3 text-sm font-medium transition-colors ${
              mode === 'login'
                ? 'border-b-2 border-emerald-400 text-white'
                : 'text-zinc-400'
            }`}
          >
            SIGN IN
          </button>
          <button
            onClick={() => setMode('register')}
            className={`flex-1 py-3 text-sm font-medium transition-colors ${
              mode === 'register'
                ? 'border-b-2 border-emerald-400 text-white'
                : 'text-zinc-400'
            }`}
          >
            CREATE ACCOUNT
          </button>
        </div>

        {mode === 'register' && (
          <input
            type="text"
            placeholder="Display Name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            className="w-full bg-zinc-900 border border-zinc-700 rounded-xl px-5 py-4 mb-4 focus:outline-none focus:border-emerald-400 text-white placeholder-zinc-500"
          />
        )}

        <input
          type="password"
          placeholder="Zero-knowledge passphrase (never leaves device)"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
          className="w-full bg-zinc-900 border border-zinc-700 rounded-xl px-5 py-4 mb-8 focus:outline-none focus:border-emerald-400 text-white placeholder-zinc-500"
        />

        <button
          onClick={handleSubmit}
          disabled={isLoading || !passphrase}
          className="w-full bg-emerald-500 hover:bg-emerald-600 disabled:bg-zinc-700 disabled:cursor-not-allowed text-black font-semibold py-5 rounded-2xl text-lg transition-all duration-200"
        >
          {isLoading ? 'Verifying...' : 'LOCK IDENTITY & ENTER'}
        </button>

        {status && (
          <p className="text-center text-xs mt-6 text-emerald-400">{status}</p>
        )}

        <div className="text-[10px] text-zinc-500 text-center mt-12 leading-relaxed">
          Your secrets are safe here.<br />
          Log in once. Drag the people you trust.<br />
          Type the message only they should see.<br />
          Lock. Send. That's it.
        </div>
      </div>
    </div>
  );
}
