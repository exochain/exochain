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

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(ms: number): string {
  return new Date(ms).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

export function timeAgo(ms: number): string {
  const diff = Date.now() - ms;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(ms);
}

/** Emergency scenario types */
export const SCENARIO_TYPES = [
  { id: 'natural-disaster', label: 'Natural Disaster', icon: 'CloudLightning', description: 'Earthquake, hurricane, tornado, flood, wildfire' },
  { id: 'medical', label: 'Medical Emergency', icon: 'Heart', description: 'Heart attack, stroke, severe allergic reaction, injury' },
  { id: 'civil-unrest', label: 'Civil Unrest', icon: 'AlertTriangle', description: 'Protests, riots, curfew, martial law' },
  { id: 'fire', label: 'Fire', icon: 'Flame', description: 'House fire, workplace fire, wildfire evacuation' },
  { id: 'active-threat', label: 'Active Threat', icon: 'ShieldAlert', description: 'Active shooter, hostile intruder, bomb threat' },
  { id: 'infrastructure', label: 'Infrastructure Failure', icon: 'Zap', description: 'Power grid failure, water contamination, communications blackout' },
  { id: 'pandemic', label: 'Pandemic', icon: 'Bug', description: 'Quarantine, shelter-in-place, supply chain disruption' },
  { id: 'evacuation', label: 'Evacuation', icon: 'Navigation', description: 'Forced evacuation, displacement, relocation' },
] as const;

/** PACE role definitions */
export const PACE_ROLES = [
  { key: 'Primary', label: 'Primary (P)', color: 'bg-blue-500', description: 'Your first point of contact in any emergency' },
  { key: 'Alternate', label: 'Alternate (A)', color: 'bg-cyan-500', description: 'Steps in when Primary is unreachable' },
  { key: 'Contingency', label: 'Contingency (C)', color: 'bg-amber-500', description: 'Backup when both P and A are unavailable' },
  { key: 'Emergency', label: 'Emergency (E)', color: 'bg-red-500', description: 'Last resort — activated only in extreme circumstances' },
] as const;
