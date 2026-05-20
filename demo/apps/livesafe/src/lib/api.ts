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

const API_BASE = '/api';
const AUTH_STORAGE_KEY = 'livesafe_auth';

function authToken() {
  try {
    const raw = sessionStorage.getItem(AUTH_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.apiToken === 'string' && parsed.apiToken.length > 0) {
      return parsed.apiToken;
    }
  } catch {
    return null;
  }
  return null;
}

function apiHeaders(headersInit?: HeadersInit) {
  const headers = new Headers(headersInit);
  if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (!headers.has('Authorization')) {
    const token = authToken();
    if (token) headers.set('Authorization', `Bearer ${token}`);
  }
  return headers;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: apiHeaders(options?.headers),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `API error: ${res.status}`);
  }
  return res.json();
}

// ── Profile ──
export const updateProfile = (data: {
  did: string; display_name: string; email: string; x25519_public_key_hex?: string;
}) => request('/profile', { method: 'POST', body: JSON.stringify(data) });

export const getProfile = (did: string) => request(`/profile/${did}`);

// ── Emergency Plans ──
export interface EmergencyPlan {
  id: string;
  owner_did: string;
  scenario_type: string;
  name: string;
  rally_point: string | null;
  go_bag_checklist: string[];
  communication_plan: string;
  evacuation_routes: string[];
  special_instructions: string | null;
  golden_hour_steps: string[];
  created_at_ms: number;
  updated_at_ms: number;
}

export const createPlan = (data: Omit<EmergencyPlan, 'id' | 'created_at_ms' | 'updated_at_ms'>) =>
  request<{ id: string }>('/plans', { method: 'POST', body: JSON.stringify(data) });

export const getPlans = (did: string) =>
  request<EmergencyPlan[]>(`/plans/${did}`);

export const updatePlan = (id: string, data: Partial<EmergencyPlan>) =>
  request(`/plans/${id}`, { method: 'PUT', body: JSON.stringify(data) });

// ── ICE Cards ──
export interface IceCard {
  id: string;
  owner_did: string;
  full_name: string;
  date_of_birth: string | null;
  blood_type: string | null;
  allergies: string[];
  medications: string[];
  medical_conditions: string[];
  emergency_contacts: Array<{ name: string; phone: string; relationship: string }>;
  insurance_info: string | null;
  organ_donor: boolean;
  dnr: boolean;
  special_instructions: string | null;
  qr_token: string;
  card_status: string;
  created_at_ms: number;
}

export const createIceCard = (data: Omit<IceCard, 'id' | 'qr_token' | 'card_status' | 'created_at_ms'>) =>
  request<{ id: string; qr_token: string }>('/ice-card', { method: 'POST', body: JSON.stringify(data) });

export const getIceCard = (did: string) =>
  request<IceCard>(`/ice-card/${did}`);

export const scanIceCard = (token: string, responderDid: string) =>
  request<{ card: IceCard; consent_expires_at_ms: number }>(`/ice-card/scan/${token}`, {
    method: 'POST', body: JSON.stringify({ responder_did: responderDid }),
  });

// ── PACE Network ──
export const inviteTrustee = (data: {
  owner_did: string; trustee_email: string; trustee_name: string;
  role: string; relationship?: string;
}) => request<{ invitation_token: string }>('/pace/invite', {
  method: 'POST', body: JSON.stringify(data),
});

export const acceptInvitation = (data: {
  invitation_token: string; trustee_did: string;
}) => request<{ accepted: boolean }>('/pace/accept', {
  method: 'POST', body: JSON.stringify(data),
});

export const getPaceNetwork = (did: string) =>
  request<Array<{
    id: number; trustee_did: string | null; trustee_email: string;
    trustee_name: string; role: string; invitation_status: string;
  }>>(`/pace/network/${did}`);

export const getResponsibilities = (did: string) =>
  request<{ count: number; networks: Array<{ owner_did: string; owner_name: string; role: string }> }>(
    `/pace/responsibilities/${did}`
  );

// ── Wellness Checks ──
export const sendWellnessCheck = (did: string) =>
  request<{ sent: boolean }>('/wellness/check-in', {
    method: 'POST', body: JSON.stringify({ did }),
  });

export const respondToWellness = (checkId: string, status: 'ok' | 'help') =>
  request('/wellness/respond', {
    method: 'POST', body: JSON.stringify({ check_id: checkId, status }),
  });

export const getWellnessHistory = (did: string) =>
  request<Array<{
    id: string; status: string; responded_at_ms: number | null; created_at_ms: number;
  }>>(`/wellness/${did}`);

// ── Keys ──
export const generateX25519Keypair = () =>
  request<{ public_key_hex: string; secret_key_hex: string }>('/keys/generate', { method: 'POST' });
