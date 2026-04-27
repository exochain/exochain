import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { getTemplates } from '@/lib/api';
import { encryptMessage, isCryptoReady } from '@/lib/crypto';
import { Lock, Heart, Key, FileText, Clock } from 'lucide-react';

const CONTENT_TYPES = [
  { value: 'Text', label: 'Message', icon: FileText },
  { value: 'Password', label: 'Password', icon: Key },
  { value: 'Secret', label: 'Secret', icon: Lock },
  { value: 'AfterlifeMessage', label: 'Afterlife', icon: Heart },
];

export default function Compose() {
  const { auth } = useAuth();
  const queryClient = useQueryClient();

  const [recipientDid, setRecipientDid] = useState('');
  const [recipientX25519, setRecipientX25519] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [contentType, setContentType] = useState('Text');
  const [releaseOnDeath, setReleaseOnDeath] = useState(false);
  const [releaseDelay, setReleaseDelay] = useState(0);
  const [selectedTemplate, setSelectedTemplate] = useState('');
  const [status, setStatus] = useState<{ type: 'success' | 'error'; msg: string } | null>(null);

  const { data: templates } = useQuery({
    queryKey: ['templates', auth?.did],
    queryFn: () => getTemplates(auth?.did),
    enabled: !!auth,
  });

  const sendMutation = useMutation({
    mutationFn: async () => {
      if (!isCryptoReady()) throw new Error('WASM not initialized');

      const messageId = crypto.randomUUID();
      const createdPhysicalMs = BigInt(Date.now());
      const createdLogical = 0;

      // Encrypt client-side — plaintext never leaves the browser
      const envelope = encryptMessage(
        body,
        contentType,
        auth!.did,
        recipientDid,
        auth!.ed25519SecretHex,
        recipientX25519,
        messageId,
        createdPhysicalMs,
        createdLogical,
        releaseOnDeath,
        releaseDelay,
      );

      // Store encrypted envelope on server (server only sees ciphertext)
      const res = await fetch('/api/messages/compose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          envelope,
          sender_did: auth!.did,
          recipient_did: recipientDid,
          content_type: contentType,
          subject,
          release_on_death: releaseOnDeath,
          release_delay_hours: releaseDelay,
        }),
      });
      if (!res.ok) throw new Error('Failed to store message');
      return { id: envelope.id };
    },
    onSuccess: (data) => {
      setStatus({ type: 'success', msg: `Message locked & sent (${data.id.slice(0, 8)}...)` });
      setBody('');
      setSubject('');
      setRecipientDid('');
      setRecipientX25519('');
      queryClient.invalidateQueries({ queryKey: ['inbox'] });
      queryClient.invalidateQueries({ queryKey: ['afterlife'] });
    },
    onError: (err: Error) => {
      setStatus({ type: 'error', msg: err.message });
    },
  });

  const applyTemplate = (templateId: string) => {
    const tmpl = templates?.find(t => t.id === templateId);
    if (tmpl) {
      if (tmpl.subject_template) setSubject(tmpl.subject_template);
      setBody(tmpl.body_template);
      setContentType(tmpl.content_type);
      if (tmpl.content_type === 'AfterlifeMessage') setReleaseOnDeath(true);
    }
    setSelectedTemplate(templateId);
  };

  return (
    <div className="p-8 max-w-3xl">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-white">Compose Message</h2>
        <p className="text-sm text-zinc-400 mt-1">
          Encrypt and send a private message
        </p>
      </div>

      {/* Content Type Selector */}
      <div className="flex gap-2 mb-6">
        {CONTENT_TYPES.map(({ value, label, icon: Icon }) => (
          <button
            key={value}
            onClick={() => {
              setContentType(value);
              if (value === 'AfterlifeMessage') setReleaseOnDeath(true);
            }}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm transition-colors ${
              contentType === value
                ? 'bg-emerald-400/20 text-emerald-400 border border-emerald-400/30'
                : 'bg-zinc-900 text-zinc-400 border border-zinc-800 hover:border-zinc-700'
            }`}
          >
            <Icon size={14} />
            {label}
          </button>
        ))}
      </div>

      {/* Templates */}
      {templates && templates.length > 0 && (
        <div className="mb-6">
          <label className="block text-xs text-zinc-500 mb-2">Template</label>
          <select
            value={selectedTemplate}
            onChange={(e) => applyTemplate(e.target.value)}
            className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:border-emerald-400"
          >
            <option value="">No template</option>
            {templates.map(t => (
              <option key={t.id} value={t.id}>{t.name}</option>
            ))}
          </select>
        </div>
      )}

      {/* Recipient */}
      <div className="space-y-4 mb-6">
        <div>
          <label className="block text-xs text-zinc-500 mb-2">Recipient DID</label>
          <input
            type="text"
            placeholder="did:exo:recipient"
            value={recipientDid}
            onChange={(e) => setRecipientDid(e.target.value)}
            className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400 placeholder-zinc-600"
          />
        </div>
        <div>
          <label className="block text-xs text-zinc-500 mb-2">
            Recipient X25519 Public Key (hex)
          </label>
          <input
            type="text"
            placeholder="Recipient's encryption public key"
            value={recipientX25519}
            onChange={(e) => setRecipientX25519(e.target.value)}
            className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400 placeholder-zinc-600 font-mono text-xs"
          />
        </div>
      </div>

      {/* Subject */}
      <div className="mb-4">
        <label className="block text-xs text-zinc-500 mb-2">Subject</label>
        <input
          type="text"
          placeholder="Message subject"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400 placeholder-zinc-600"
        />
      </div>

      {/* Body */}
      <div className="mb-6">
        <label className="block text-xs text-zinc-500 mb-2">Message</label>
        <textarea
          placeholder={
            contentType === 'Password'
              ? 'Enter the password or credential...'
              : contentType === 'AfterlifeMessage'
                ? 'Write your message to be delivered after your passing...'
                : 'Type your secret message...'
          }
          value={body}
          onChange={(e) => setBody(e.target.value)}
          rows={8}
          className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400 placeholder-zinc-600 resize-none"
        />
      </div>

      {/* Death Toggle */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Heart size={16} className={releaseOnDeath ? 'text-rose-400' : 'text-zinc-600'} />
            <div>
              <p className="text-sm text-white">Delete-on-Death</p>
              <p className="text-xs text-zinc-500">
                Release this message after your passing is verified by PACE trustees
              </p>
            </div>
          </div>
          <button
            onClick={() => setReleaseOnDeath(!releaseOnDeath)}
            className={`w-12 h-6 rounded-full transition-colors relative ${
              releaseOnDeath ? 'bg-emerald-400' : 'bg-zinc-700'
            }`}
          >
            <span
              className={`absolute top-0.5 w-5 h-5 rounded-full bg-white transition-transform ${
                releaseOnDeath ? 'left-[26px]' : 'left-0.5'
              }`}
            />
          </button>
        </div>

        {releaseOnDeath && (
          <div className="mt-4 flex items-center gap-3">
            <Clock size={14} className="text-zinc-500" />
            <label className="text-xs text-zinc-500">Release delay (hours):</label>
            <input
              type="number"
              min={0}
              value={releaseDelay}
              onChange={(e) => setReleaseDelay(parseInt(e.target.value) || 0)}
              className="w-20 bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs text-white focus:outline-none focus:border-emerald-400"
            />
          </div>
        )}
      </div>

      {/* Send Button */}
      <button
        onClick={() => sendMutation.mutate()}
        disabled={sendMutation.isPending || !recipientDid || !recipientX25519 || !body}
        className="w-full bg-emerald-500 hover:bg-emerald-600 disabled:bg-zinc-700 disabled:cursor-not-allowed text-black font-semibold py-4 rounded-2xl text-lg transition-all duration-200 flex items-center justify-center gap-3"
      >
        {sendMutation.isPending ? (
          <>Encrypting & Signing...</>
        ) : (
          <>
            <Lock size={18} />
            LOCK & SEND
          </>
        )}
      </button>

      {/* Status */}
      {status && (
        <p className={`text-center text-xs mt-4 ${
          status.type === 'success' ? 'text-emerald-400' : 'text-red-400'
        }`}>
          {status.msg}
        </p>
      )}
    </div>
  );
}
