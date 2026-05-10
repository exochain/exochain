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
import { useQuery, useMutation } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { getInbox, getSent } from '@/lib/api';
import { decryptMessage, isCryptoReady } from '@/lib/crypto';
import { timeAgo } from '@/lib/utils';
import { Mail, Send, Lock, Unlock, Eye, Key, FileText, Heart } from 'lucide-react';

const TYPE_ICON: Record<string, React.ElementType> = {
  Text: FileText, Password: Key, Secret: Lock,
  AfterlifeMessage: Heart, Template: FileText, Attachment: FileText,
};

export default function Inbox() {
  const { auth } = useAuth();
  const did = auth?.did || '';
  const [tab, setTab] = useState<'inbox' | 'sent'>('inbox');
  const [selectedMsg, setSelectedMsg] = useState<string | null>(null);
  const [decryptedContent, setDecryptedContent] = useState<string | null>(null);
  const [decryptError, setDecryptError] = useState<string | null>(null);
  const [senderPublicHex, setSenderPublicHex] = useState('');

  const { data: inbox } = useQuery({
    queryKey: ['inbox', did],
    queryFn: () => getInbox(did),
    enabled: !!did,
  });

  const { data: sent } = useQuery({
    queryKey: ['sent', did],
    queryFn: () => getSent(did),
    enabled: !!did,
  });

  const decryptMutation = useMutation({
    mutationFn: async (msgId: string) => {
      if (!isCryptoReady()) throw new Error('WASM not initialized');

      // Fetch the encrypted envelope from the server
      const res = await fetch(`/api/messages/envelope/${msgId}`);
      if (!res.ok) throw new Error('Failed to fetch envelope');
      const { envelope } = await res.json();

      // Decrypt client-side — server never sees plaintext
      return decryptMessage(
        JSON.stringify(envelope),
        auth!.x25519SecretHex,
        senderPublicHex,
      );
    },
    onSuccess: (data) => {
      setDecryptedContent(data.plaintext);
      setDecryptError(null);
    },
    onError: (err: Error) => {
      setDecryptError(err.message);
      setDecryptedContent(null);
    },
  });

  const messages = tab === 'inbox' ? inbox : sent;

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-white">Messages</h2>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-zinc-900 rounded-lg p-1 w-fit">
        <button
          onClick={() => { setTab('inbox'); setSelectedMsg(null); setDecryptedContent(null); }}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm transition-colors ${
            tab === 'inbox' ? 'bg-emerald-400/20 text-emerald-400' : 'text-zinc-400'
          }`}
        >
          <Mail size={14} /> Inbox ({inbox?.length || 0})
        </button>
        <button
          onClick={() => { setTab('sent'); setSelectedMsg(null); setDecryptedContent(null); }}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm transition-colors ${
            tab === 'sent' ? 'bg-emerald-400/20 text-emerald-400' : 'text-zinc-400'
          }`}
        >
          <Send size={14} /> Sent ({sent?.length || 0})
        </button>
      </div>

      {/* Message List */}
      <div className="space-y-2">
        {(!messages || messages.length === 0) && (
          <div className="text-center py-16 text-zinc-500">
            <Mail size={32} className="mx-auto mb-3 opacity-50" />
            <p className="text-sm">No messages yet</p>
            <p className="text-xs mt-1">
              {tab === 'inbox' ? 'Messages you receive will appear here' : 'Messages you send will appear here'}
            </p>
          </div>
        )}

        {messages?.map((msg) => {
          const Icon = TYPE_ICON[msg.content_type] || FileText;
          const isSelected = selectedMsg === msg.id;
          const isRead = 'read_at_ms' in msg && msg.read_at_ms;

          return (
            <div key={msg.id}>
              <button
                onClick={() => {
                  setSelectedMsg(isSelected ? null : msg.id);
                  setDecryptedContent(null);
                  setDecryptError(null);
                }}
                className={`w-full text-left rounded-xl border p-4 transition-colors ${
                  isSelected
                    ? 'border-emerald-400/30 bg-emerald-400/5'
                    : isRead
                      ? 'border-zinc-800 bg-zinc-900/50'
                      : 'border-zinc-800 bg-zinc-900'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon size={16} className={isRead ? 'text-zinc-600' : 'text-emerald-400'} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <p className={`text-sm truncate ${isRead ? 'text-zinc-400' : 'font-medium text-white'}`}>
                        {msg.subject || `[${msg.content_type}]`}
                      </p>
                      <span className="text-[10px] text-zinc-500 ml-2 shrink-0">
                        {timeAgo(msg.created_at_ms)}
                      </span>
                    </div>
                    <p className="text-xs text-zinc-500 truncate mt-0.5">
                      {tab === 'inbox'
                        ? `From: ${('sender_did' in msg ? msg.sender_did : '').slice(0, 24)}...`
                        : `To: ${('recipient_did' in msg ? msg.recipient_did : '').slice(0, 24)}...`}
                    </p>
                  </div>
                  {!isRead && tab === 'inbox' && (
                    <span className="w-2 h-2 rounded-full bg-emerald-400 shrink-0" />
                  )}
                </div>
              </button>

              {/* Decrypt Panel */}
              {isSelected && tab === 'inbox' && (
                <div className="mt-2 ml-4 p-4 bg-zinc-900 border border-zinc-800 rounded-lg">
                  {!decryptedContent ? (
                    <div className="space-y-3">
                      <div>
                        <label className="block text-xs text-zinc-500 mb-1">
                          Sender's Ed25519 Public Key (hex)
                        </label>
                        <input
                          type="text"
                          placeholder="Sender's public key to verify signature"
                          value={senderPublicHex}
                          onChange={(e) => setSenderPublicHex(e.target.value)}
                          className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-emerald-400 placeholder-zinc-600"
                        />
                      </div>
                      <button
                        onClick={() => decryptMutation.mutate(msg.id)}
                        disabled={decryptMutation.isPending || !senderPublicHex}
                        className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 disabled:bg-zinc-700 text-black font-medium rounded-lg text-sm transition-colors"
                      >
                        <Unlock size={14} />
                        {decryptMutation.isPending ? 'Decrypting...' : 'Unlock Message'}
                      </button>
                      {decryptError && (
                        <p className="text-xs text-red-400">{decryptError}</p>
                      )}
                    </div>
                  ) : (
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Eye size={14} className="text-emerald-400" />
                        <span className="text-xs text-emerald-400">Decrypted</span>
                      </div>
                      <pre className="text-sm text-white whitespace-pre-wrap bg-zinc-800 rounded-lg p-4 font-mono">
                        {decryptedContent}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
