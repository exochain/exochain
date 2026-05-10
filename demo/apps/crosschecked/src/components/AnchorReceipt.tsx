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
import { Anchor, Copy, Check, Hash, Link } from 'lucide-react';

interface AnchorData {
  anchor_id?: string;
  chain?: string;
  record_hash?: string;
  txid?: string;
  audit_seq?: number;
  timestamp_ms?: number;
}

interface AnchorReceiptProps {
  anchor: AnchorData;
}

export default function AnchorReceipt({ anchor }: AnchorReceiptProps) {
  const [copied, setCopied] = useState<string | null>(null);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  if (!anchor) {
    return (
      <div className="text-center py-8 text-gray-500 text-sm">
        No anchor receipt available
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-6">
      <div className="flex items-center gap-2 mb-4">
        <Anchor className="w-5 h-5 text-cyan-400" />
        <h3 className="text-sm font-heading font-semibold text-white">Chain Anchor Receipt</h3>
      </div>

      <div className="space-y-4">
        {/* Chain */}
        {anchor.chain && (
          <div>
            <label className="text-xs text-gray-500 uppercase tracking-wider">Chain</label>
            <div className="flex items-center gap-2 mt-1">
              <Link className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-sm font-medium text-white">{anchor.chain}</span>
            </div>
          </div>
        )}

        {/* Record Hash */}
        {anchor.record_hash && (
          <div>
            <label className="text-xs text-gray-500 uppercase tracking-wider">Record Hash</label>
            <div className="flex items-center gap-2 mt-1">
              <Hash className="w-3.5 h-3.5 text-gray-400" />
              <code className="text-sm font-mono text-gray-300">
                {anchor.record_hash.slice(0, 16)}...{anchor.record_hash.slice(-8)}
              </code>
              <button
                onClick={() => copyToClipboard(anchor.record_hash!, 'hash')}
                className="p-1 rounded hover:bg-white/5 transition-colors"
              >
                {copied === 'hash' ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5 text-gray-500" />
                )}
              </button>
            </div>
          </div>
        )}

        {/* TXID */}
        {anchor.txid && (
          <div>
            <label className="text-xs text-gray-500 uppercase tracking-wider">Transaction ID</label>
            <div className="flex items-center gap-2 mt-1">
              <code className="text-sm font-mono text-gray-300">
                {anchor.txid.slice(0, 16)}...{anchor.txid.slice(-8)}
              </code>
              <button
                onClick={() => copyToClipboard(anchor.txid!, 'txid')}
                className="p-1 rounded hover:bg-white/5 transition-colors"
              >
                {copied === 'txid' ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5 text-gray-500" />
                )}
              </button>
            </div>
          </div>
        )}

        {/* Audit Sequence */}
        {anchor.audit_seq !== undefined && (
          <div>
            <label className="text-xs text-gray-500 uppercase tracking-wider">Audit Sequence</label>
            <p className="text-sm font-mono text-white mt-1">#{anchor.audit_seq}</p>
          </div>
        )}
      </div>
    </div>
  );
}
