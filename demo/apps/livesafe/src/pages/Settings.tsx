import { useAuth } from '@/hooks/useAuth';
import { Settings as SettingsIcon, Shield, Key, Copy, Bell } from 'lucide-react';

export default function Settings() {
  const { auth } = useAuth();

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="p-8 max-w-2xl">
      <div className="mb-8">
        <h2 className="text-2xl font-heading font-bold text-white">Settings</h2>
      </div>

      {/* Identity */}
      <div className="bg-white/[0.03] border border-white/10 rounded-xl p-5 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <Shield size={16} className="text-blue-400" />
          <h3 className="text-sm font-heading font-semibold text-white">Identity</h3>
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-[10px] text-white/30 mb-1 block">DID</label>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs text-blue-300 bg-white/5 rounded px-3 py-2 font-mono">{auth?.did}</code>
              <button onClick={() => copyToClipboard(auth?.did || '')} className="text-white/30 hover:text-white">
                <Copy size={14} />
              </button>
            </div>
          </div>
          <div>
            <label className="text-[10px] text-white/30 mb-1 block">Display Name</label>
            <p className="text-sm text-white">{auth?.displayName}</p>
          </div>
          <div>
            <label className="text-[10px] text-white/30 mb-1 block">Email</label>
            <p className="text-sm text-white">{auth?.email}</p>
          </div>
        </div>
      </div>

      {/* Keys */}
      <div className="bg-white/[0.03] border border-white/10 rounded-xl p-5 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <Key size={16} className="text-amber-400" />
          <h3 className="text-sm font-heading font-semibold text-white">Cryptographic Keys</h3>
        </div>
        <div>
          <label className="text-[10px] text-white/30 mb-1 block">X25519 Public Key (for key exchange)</label>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-[10px] text-blue-300 bg-white/5 rounded px-3 py-2 font-mono truncate">
              {auth?.x25519PublicHex}
            </code>
            <button onClick={() => copyToClipboard(auth?.x25519PublicHex || '')} className="text-white/30 hover:text-white shrink-0">
              <Copy size={14} />
            </button>
          </div>
        </div>
        <p className="text-[10px] text-white/20 mt-3">
          Keys derived from your passphrase via HKDF. Never stored. Never transmitted.
        </p>
      </div>

      {/* Notifications */}
      <div className="bg-white/[0.03] border border-white/10 rounded-xl p-5 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <Bell size={16} className="text-cyan-400" />
          <h3 className="text-sm font-heading font-semibold text-white">Notifications</h3>
        </div>
        <div className="space-y-3">
          {[
            { label: 'Wellness check reminders', default: true },
            { label: 'PACE trustee activity', default: true },
            { label: 'Emergency alerts (your area)', default: true },
            { label: 'Network growth milestones', default: false },
          ].map(({ label, default: defaultOn }) => (
            <label key={label} className="flex items-center justify-between cursor-pointer">
              <span className="text-sm text-white/60">{label}</span>
              <input type="checkbox" defaultChecked={defaultOn}
                className="w-4 h-4 rounded border-white/20 bg-white/5 text-blue-500 focus:ring-blue-500" />
            </label>
          ))}
        </div>
      </div>

      {/* About */}
      <div className="bg-white/[0.03] border border-white/10 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <SettingsIcon size={16} className="text-white/40" />
          <h3 className="text-sm font-heading font-semibold text-white">About LiveSafe</h3>
        </div>
        <div className="text-xs text-white/30 space-y-1">
          <p>Version: 0.1.0-beta</p>
          <p>EXOCHAIN-adjacent prototype</p>
          <p>Key Sharding: Shamir (3-of-4 threshold)</p>
          <p>ICE Card: QR/NFC with consent-gated access</p>
          <p>PACE: Primary / Alternate / Contingency / Emergency</p>
        </div>
      </div>
    </div>
  );
}
