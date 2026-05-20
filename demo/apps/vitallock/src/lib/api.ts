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

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `API error: ${res.status}`);
  }
  return res.json();
}

// ── Messaging ──
export const composeMessage = (data: {
  plaintext: string;
  content_type: string;
  sender_did: string;
  recipient_did: string;
  sender_signing_key_hex: string;
  recipient_x25519_public_hex: string;
  release_on_death?: boolean;
  release_delay_hours?: number;
  subject?: string;
}) => request<{ id: string; status: string }>('/messages/compose', {
  method: 'POST',
  body: JSON.stringify(data),
});

export const getInbox = (did: string) =>
  request<Array<{
    id: string; sender_did: string; content_type: string;
    subject: string | null; created_at_ms: number; read_at_ms: number | null;
  }>>(`/messages/inbox/${did}`);

export const getSent = (did: string) =>
  request<Array<{
    id: string; recipient_did: string; content_type: string;
    subject: string | null; created_at_ms: number;
  }>>(`/messages/sent/${did}`);

export const openMessage = (data: {
  message_id: string;
  recipient_x25519_secret_hex: string;
  sender_ed25519_public_hex: string;
}) => request<{ plaintext: string; content_type: string }>('/messages/open', {
  method: 'POST',
  body: JSON.stringify(data),
});

export const getAfterlifeMessages = (did: string) =>
  request<Array<{
    id: string; recipient_did: string; content_type: string;
    subject: string | null; release_delay_hours: number; released: boolean;
  }>>(`/messages/afterlife/${did}`);

// ── PACE Network ──
export const inviteTrustee = (data: {
  owner_did: string;
  trustee_email: string;
  trustee_name: string;
  role: string;
  relationship?: string;
  shamir_share_encrypted?: string;
}) => request<{ invitation_token: string }>('/pace/invite', {
  method: 'POST',
  body: JSON.stringify(data),
});

export const acceptInvitation = (data: {
  invitation_token: string;
  trustee_did: string;
  trustee_ed25519_public_key_hex: string;
}) => request<{ accepted: boolean }>('/pace/accept', {
  method: 'POST',
  body: JSON.stringify(data),
});

export const getPaceNetwork = (did: string) =>
  request<Array<{
    id: number; trustee_did: string | null; trustee_ed25519_public_key_hex: string | null; trustee_email: string;
    trustee_name: string; role: string; relationship: string | null;
    invitation_status: string;
  }>>(`/pace/network/${did}`);

export const getResponsibilities = (did: string) =>
  request<{ trustee_of_count: number; responsibilities: Array<{
    owner_did: string; role: string; owner_name: string;
  }> }>(`/pace/responsibilities/${did}`);

// ── Death Verification ──
export const initiateDeath = (data: {
  subject_did: string;
  initiated_by_did: string;
  required_confirmations?: number;
  claim_nonce_hex: string;
  initiator_signature_hex: string;
  created_physical_ms: number;
  created_logical: number;
}) => request<{ id: string; status: string }>('/death/initiate', {
  method: 'POST',
  body: JSON.stringify(data),
});

export const confirmDeath = (data: {
  verification_id: string;
  trustee_did: string;
  signature_hex: string;
  confirmed_physical_ms: number;
  confirmed_logical: number;
}) => request<{ verified: boolean; confirmations: number }>('/death/confirm', {
  method: 'POST',
  body: JSON.stringify(data),
});

// ── Digital Assets ──
export const uploadAsset = (data: {
  owner_did: string;
  asset_type: string;
  name: string;
  description?: string;
}) => request<{ id: string }>('/assets', {
  method: 'POST',
  body: JSON.stringify(data),
});

export const getAssets = (did: string) =>
  request<Array<{
    id: string; asset_type: string; name: string;
    description: string | null; beneficiary_did: string | null;
  }>>(`/assets/${did}`);

// ── 0dentity ──
export const getOdentityScore = (did: string) =>
  request<{
    did: string; score: number;
    breakdown: Record<string, number>;
  }>(`/odentity/${did}`);

// ── Profile ──
export const updateProfile = (data: {
  did: string;
  display_name?: string;
  x25519_public_key_hex?: string;
}) => request<{ did: string }>('/profile', {
  method: 'POST',
  body: JSON.stringify(data),
});

export const getProfile = (did: string) =>
  request<{
    did: string; display_name: string | null;
    odentity_score: number; onboarding_complete: boolean;
    subscription_tier: string;
  }>(`/profile/${did}`);

// ── Templates ──
export const getTemplates = (did?: string) =>
  request<Array<{
    id: string; name: string; content_type: string;
    subject_template: string | null; body_template: string;
  }>>(`/templates${did ? `?did=${did}` : ''}`);

// ── Family ──
export const inviteFamily = (data: {
  owner_did: string;
  member_name: string;
  member_email: string;
  relationship: string;
  access_level?: string;
}) => request<{ invited: boolean }>('/family/invite', {
  method: 'POST',
  body: JSON.stringify(data),
});

export const getFamily = (did: string) =>
  request<Array<{
    id: number; member_name: string; member_email: string;
    relationship: string; access_level: string; status: string;
  }>>(`/family/${did}`);

// ── Keys ──
export const generateX25519Keypair = () =>
  request<{ public_key_hex: string; secret_key_hex: string }>('/keys/generate', {
    method: 'POST',
  });
