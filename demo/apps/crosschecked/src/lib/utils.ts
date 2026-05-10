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

import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) { return twMerge(clsx(inputs)); }

export function formatDate(ms: number): string {
  return new Date(ms).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

export function timeAgo(ms: number): string {
  const diff = Date.now() - ms;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export const PANELS = ['Governance', 'Legal', 'Architecture', 'Security', 'Operations'] as const;
export const PROPERTIES = ['Storable', 'Diffable', 'Transferable', 'Auditable', 'Contestable'] as const;
export const STANCES = ['support', 'oppose', 'amend', 'abstain'] as const;
export const METHODS = ['mosaic', 'adversarial', 'redteam', 'debate', 'jury'] as const;
export const DECISION_CLASSES = ['Operational', 'Procedural', 'Strategic', 'Constitutional'] as const;
export const STATUSES = ['draft', 'submitted', 'crosschecking', 'verified', 'anchored', 'deliberating', 'ratified', 'rejected'] as const;

export const STANCE_COLORS: Record<string, string> = {
  support: 'bg-emerald-500/20 text-emerald-400 border-emerald-400/30',
  oppose: 'bg-red-500/20 text-red-400 border-red-400/30',
  amend: 'bg-amber-500/20 text-amber-400 border-amber-400/30',
  abstain: 'bg-gray-500/20 text-gray-400 border-gray-400/30',
};

export const STATUS_COLORS: Record<string, string> = {
  draft: 'bg-gray-500/20 text-gray-400', submitted: 'bg-blue-500/20 text-blue-400',
  crosschecking: 'bg-purple-500/20 text-purple-400', verified: 'bg-emerald-500/20 text-emerald-400',
  anchored: 'bg-cyan-500/20 text-cyan-400', deliberating: 'bg-amber-500/20 text-amber-400',
  ratified: 'bg-emerald-500/20 text-emerald-300', rejected: 'bg-red-500/20 text-red-400',
};

export const PANEL_COLORS: Record<string, string> = {
  Governance: 'bg-indigo-500/20 text-indigo-400', Legal: 'bg-blue-500/20 text-blue-400',
  Architecture: 'bg-cyan-500/20 text-cyan-400', Security: 'bg-red-500/20 text-red-400',
  Operations: 'bg-amber-500/20 text-amber-400',
};
