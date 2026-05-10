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
import { Link, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { listProposals } from '@/lib/api';
import { cn, formatDate, STATUSES } from '@/lib/utils';
import StatusBadge from '@/components/StatusBadge';
import {
  Plus,
  FileText,
  Clock,
  CheckCircle2,
  XCircle,
  Filter,
} from 'lucide-react';

export default function Dashboard() {
  const [statusFilter, setStatusFilter] = useState('');
  const navigate = useNavigate();

  const { data: proposals = [], isLoading } = useQuery({
    queryKey: ['proposals', statusFilter],
    queryFn: () => listProposals(statusFilter || undefined),
  });

  const total = proposals.length;
  const pending = proposals.filter((p) => ['draft', 'submitted', 'crosschecking'].includes(p.status)).length;
  const ratified = proposals.filter((p) => p.status === 'ratified').length;
  const rejected = proposals.filter((p) => p.status === 'rejected').length;

  const stats = [
    { label: 'Total Proposals', value: total, icon: FileText, color: 'text-xc-indigo-400' },
    { label: 'Pending', value: pending, icon: Clock, color: 'text-amber-400' },
    { label: 'Ratified', value: ratified, icon: CheckCircle2, color: 'text-emerald-400' },
    { label: 'Rejected', value: rejected, icon: XCircle, color: 'text-red-400' },
  ];

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="font-heading font-bold text-2xl text-white">Dashboard</h1>
          <p className="text-sm text-gray-400 mt-1">Proposal overview and management</p>
        </div>
        <Link
          to="/proposals/new"
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-xc-indigo-500 to-xc-purple-500 text-white font-medium text-sm hover:shadow-lg hover:shadow-xc-indigo-500/25 transition-all"
        >
          <Plus className="w-4 h-4" />
          New Proposal
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        {stats.map((s) => (
          <div
            key={s.label}
            className="rounded-xl border border-white/5 bg-xc-slate/40 p-5"
          >
            <div className="flex items-center gap-2 mb-2">
              <s.icon className={cn('w-4 h-4', s.color)} />
              <span className="text-xs text-gray-400">{s.label}</span>
            </div>
            <p className="text-2xl font-heading font-bold text-white">{s.value}</p>
          </div>
        ))}
      </div>

      {/* Filter */}
      <div className="flex items-center gap-3 mb-4">
        <Filter className="w-4 h-4 text-gray-400" />
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-xc-slate border border-white/10 rounded-lg px-3 py-1.5 text-sm text-gray-300 focus:outline-none focus:border-xc-indigo-500"
        >
          <option value="">All Statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-white/5 bg-xc-slate/40 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/5">
              <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wider px-4 py-3">
                Title
              </th>
              <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wider px-4 py-3">
                Status
              </th>
              <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wider px-4 py-3 hidden md:table-cell">
                Method
              </th>
              <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wider px-4 py-3 hidden md:table-cell">
                Class
              </th>
              <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wider px-4 py-3 hidden lg:table-cell">
                Created
              </th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={5} className="px-4 py-12 text-center text-gray-500 text-sm">
                  Loading proposals...
                </td>
              </tr>
            ) : proposals.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-12 text-center text-gray-500 text-sm">
                  No proposals found. Create your first one.
                </td>
              </tr>
            ) : (
              proposals.map((p) => (
                <tr
                  key={p.id}
                  onClick={() => navigate(`/proposals/${p.id}`)}
                  className="border-b border-white/5 last:border-0 hover:bg-white/[0.02] cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3">
                    <span className="text-sm font-medium text-white">{p.title}</span>
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={p.status} />
                  </td>
                  <td className="px-4 py-3 hidden md:table-cell">
                    <span className="text-xs text-gray-400 capitalize">{p.method}</span>
                  </td>
                  <td className="px-4 py-3 hidden md:table-cell">
                    <span className="text-xs text-gray-400">{p.decision_class}</span>
                  </td>
                  <td className="px-4 py-3 hidden lg:table-cell">
                    <span className="text-xs text-gray-500">{formatDate(p.created_at_ms)}</span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
