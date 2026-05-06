import { useState, useEffect } from 'react';
import { Shield } from 'lucide-react';

interface Props {
  mode?: 'login' | 'register';
}

export default function Login({ mode: initialMode = 'login' }: Props) {
  const [mode, setMode] = useState(initialMode);
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [status, setStatus] = useState('');
  const cryptoUnavailable =
    'LiveSafe EXOCHAIN crypto is unavailable: this adjacent prototype has no tested browser WASM/core adapter configured';

  useEffect(() => {
    setStatus(cryptoUnavailable);
  }, [cryptoUnavailable]);

  const handleSubmit = async () => {
    if (!passphrase) return;
    setIsLoading(true);
    setStatus(cryptoUnavailable);
    setIsLoading(false);
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
