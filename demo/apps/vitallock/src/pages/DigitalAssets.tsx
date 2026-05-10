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
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { getAssets, uploadAsset } from '@/lib/api';
import { FileBox, Plus, X, File, Image, Video, FileText } from 'lucide-react';

const ASSET_TYPES = [
  { value: 'document', label: 'Document', icon: FileText },
  { value: 'photo', label: 'Photo', icon: Image },
  { value: 'video', label: 'Video', icon: Video },
  { value: 'other', label: 'Other', icon: File },
];

export default function DigitalAssets() {
  const { auth } = useAuth();
  const queryClient = useQueryClient();
  const did = auth?.did || '';
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ name: '', type: 'document', description: '' });

  const { data: assets } = useQuery({
    queryKey: ['assets', did],
    queryFn: () => getAssets(did),
    enabled: !!did,
  });

  const addMutation = useMutation({
    mutationFn: () =>
      uploadAsset({
        owner_did: did,
        asset_type: form.type,
        name: form.name,
        description: form.description,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assets'] });
      setShowAdd(false);
      setForm({ name: '', type: 'document', description: '' });
    },
  });

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold text-white">Digital Assets</h2>
          <p className="text-sm text-zinc-400 mt-1">
            Encrypted files and documents for your digital legacy
          </p>
        </div>
        <button
          onClick={() => setShowAdd(true)}
          className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-black font-medium rounded-lg text-sm transition-colors"
        >
          <Plus size={14} /> Add Asset
        </button>
      </div>

      {(!assets || assets.length === 0) ? (
        <div className="text-center py-16 text-zinc-500">
          <FileBox size={32} className="mx-auto mb-3 opacity-50" />
          <p className="text-sm">No digital assets yet</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {assets.map(asset => {
            const typeConfig = ASSET_TYPES.find(t => t.value === asset.asset_type) || ASSET_TYPES[3];
            const Icon = typeConfig.icon;
            return (
              <div key={asset.id} className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
                <div className="flex items-center gap-3 mb-3">
                  <Icon size={20} className="text-amber-400" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-white truncate">{asset.name}</p>
                    <p className="text-[10px] text-zinc-500">{typeConfig.label}</p>
                  </div>
                </div>
                {asset.description && (
                  <p className="text-xs text-zinc-400 mb-3">{asset.description}</p>
                )}
                <div className="flex items-center justify-between text-[10px] text-zinc-600">
                  <span>
                    Beneficiary: {asset.beneficiary_did ? asset.beneficiary_did.slice(0, 20) + '...' : 'None'}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Add Modal */}
      {showAdd && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-bold text-white">Add Digital Asset</h3>
              <button onClick={() => setShowAdd(false)}>
                <X size={18} className="text-zinc-500" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-zinc-500 mb-1">Name</label>
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400"
                />
              </div>
              <div>
                <label className="block text-xs text-zinc-500 mb-1">Type</label>
                <select
                  value={form.type}
                  onChange={(e) => setForm({ ...form, type: e.target.value })}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400"
                >
                  {ASSET_TYPES.map(t => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-zinc-500 mb-1">Description</label>
                <textarea
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  rows={3}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400 resize-none"
                />
              </div>
            </div>
            <button
              onClick={() => addMutation.mutate()}
              disabled={addMutation.isPending || !form.name}
              className="w-full mt-6 bg-emerald-500 hover:bg-emerald-600 disabled:bg-zinc-700 text-black font-semibold py-3 rounded-xl transition-colors"
            >
              {addMutation.isPending ? 'Encrypting...' : 'Store Asset'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
