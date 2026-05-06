import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { getFamily, inviteFamily } from '@/lib/api';
import { Shield, X, UserPlus, CheckCircle, Clock } from 'lucide-react';

const RELATIONSHIPS = [
  'Spouse/Partner', 'Child', 'Parent', 'Sibling', 'Grandchild',
  'Close Friend', 'Attorney', 'Other',
];

export default function Family() {
  const { auth } = useAuth();
  const queryClient = useQueryClient();
  const did = auth?.did || '';
  const [showInvite, setShowInvite] = useState(false);
  const [form, setForm] = useState({ name: '', email: '', relationship: '', access: 'view' });

  const { data: members } = useQuery({
    queryKey: ['family', did],
    queryFn: () => getFamily(did),
    enabled: !!did,
  });

  const inviteMutation = useMutation({
    mutationFn: () =>
      inviteFamily({
        owner_did: did,
        member_name: form.name,
        member_email: form.email,
        relationship: form.relationship,
        access_level: form.access,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['family'] });
      setShowInvite(false);
      setForm({ name: '', email: '', relationship: '', access: 'view' });
    },
  });

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold text-white">Family Members</h2>
          <p className="text-sm text-zinc-400 mt-1">
            Manage access to your digital legacy
          </p>
        </div>
        <button
          onClick={() => setShowInvite(true)}
          className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-black font-medium rounded-lg text-sm transition-colors"
        >
          <UserPlus size={14} /> Invite
        </button>
      </div>

      {(!members || members.length === 0) ? (
        <div className="text-center py-16 text-zinc-500">
          <Shield size={32} className="mx-auto mb-3 opacity-50" />
          <p className="text-sm">No family members added yet</p>
        </div>
      ) : (
        <div className="space-y-3">
          {members.map(m => (
            <div key={m.id} className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-white">{m.member_name}</p>
                <p className="text-xs text-zinc-500">{m.member_email}</p>
                <div className="flex items-center gap-3 mt-2">
                  <span className="text-[10px] text-zinc-600">{m.relationship}</span>
                  <span className="text-[10px] px-2 py-0.5 bg-zinc-800 rounded text-zinc-400">
                    {m.access_level}
                  </span>
                </div>
              </div>
              {m.status === 'active' ? (
                <CheckCircle size={16} className="text-emerald-400" />
              ) : (
                <Clock size={16} className="text-amber-400" />
              )}
            </div>
          ))}
        </div>
      )}

      {showInvite && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-bold text-white">Invite Family Member</h3>
              <button onClick={() => setShowInvite(false)}>
                <X size={18} className="text-zinc-500" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-zinc-500 mb-1">Name</label>
                <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400" />
              </div>
              <div>
                <label className="block text-xs text-zinc-500 mb-1">Email</label>
                <input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400" />
              </div>
              <div>
                <label className="block text-xs text-zinc-500 mb-1">Relationship</label>
                <select value={form.relationship} onChange={(e) => setForm({ ...form, relationship: e.target.value })} className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400">
                  <option value="">Select...</option>
                  {RELATIONSHIPS.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-zinc-500 mb-1">Access Level</label>
                <select value={form.access} onChange={(e) => setForm({ ...form, access: e.target.value })} className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-emerald-400">
                  <option value="view">View Only</option>
                  <option value="limited">Limited</option>
                  <option value="full">Full Access</option>
                </select>
              </div>
            </div>
            <button onClick={() => inviteMutation.mutate()} disabled={inviteMutation.isPending || !form.name || !form.email || !form.relationship} className="w-full mt-6 bg-emerald-500 hover:bg-emerald-600 disabled:bg-zinc-700 text-black font-semibold py-3 rounded-xl transition-colors">
              {inviteMutation.isPending ? 'Sending...' : 'Send Invitation'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
