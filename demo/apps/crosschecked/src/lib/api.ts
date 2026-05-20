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

const API = '/api';
const AUTH_STORAGE_KEY = 'crosschecked_auth';

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

async function req<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, { ...opts, headers: apiHeaders(opts?.headers) });
  if (!res.ok) { const e = await res.json().catch(() => ({ error: res.statusText })); throw new Error(e.error || `API ${res.status}`); }
  return res.json();
}

// Proposals
export const createProposal = (d: { author_did: string; title: string; context: string; decision?: string; consequences?: string; method?: string; decision_class?: string; full_5x5?: boolean }) =>
  req<{ id: string }>('/proposals', { method: 'POST', body: JSON.stringify(d) });
export const listProposals = (status?: string) => req<Array<{ id: string; title: string; status: string; decision_class: string; method: string; full_5x5: boolean; created_at_ms: number }>>(`/proposals${status ? `?status=${status}` : ''}`);
export const getProposal = (id: string) => req<any>(`/proposals/${id}`);
export const transitionStatus = (id: string, status: string, actor_did: string) => req(`/proposals/${id}/status`, { method: 'PUT', body: JSON.stringify({ status, actor_did }) });
export const getHash = (id: string) => req<{ hash: string }>(`/proposals/${id}/hash`);

// Evidence
export const addEvidence = (id: string, d: { kind: string; description: string; uri?: string; content_hash?: string }) =>
  req<{ id: string }>(`/proposals/${id}/evidence`, { method: 'POST', body: JSON.stringify(d) });
export const listEvidence = (id: string) => req<any[]>(`/proposals/${id}/evidence`);

// CrossCheck
export const getTemplate = (id: string) => req<any>(`/proposals/${id}/crosscheck/template`);
export const triggerCrosscheck = (id: string, actor_did: string) => req(`/proposals/${id}/crosscheck`, { method: 'POST', body: JSON.stringify({ actor_did }) });
export const submitOpinion = (id: string, d: { agent_did: string; agent_kind?: string; agent_label?: string; model?: string; stance: string; summary: string; rationale?: string; confidence?: number; risks?: string[]; panel?: string; property?: string }) =>
  req<{ id: string; stance: string }>(`/proposals/${id}/opinions`, { method: 'POST', body: JSON.stringify(d) });
export const synthesize = (id: string, d: { actor_did: string; synthesis?: string; dissent?: string }) =>
  req<{ id: string; report_hash: string; independence: any; coordination: any; dissenters: string[] }>(`/proposals/${id}/synthesize`, { method: 'POST', body: JSON.stringify(d) });

// Attestation & Clearance
export const attest = (id: string, d: { actor_did: string; role?: string; attestation: string; notes?: string; signature?: string; public_key_b64?: string }) =>
  req(`/proposals/${id}/attest`, { method: 'POST', body: JSON.stringify(d) });
export const getClearance = (id: string) => req<{ quorum_met: boolean; approvals: any[]; rejections: any[]; abstentions: any[] }>(`/proposals/${id}/clearance`);
export const issueClearance = (id: string, actor_did: string) => req<{ certificate_id: string; quorum_met: boolean }>(`/proposals/${id}/clear`, { method: 'POST', body: JSON.stringify({ actor_did }) });

// Anchoring
export const anchor = (id: string, actor_did: string) => req<{ anchor_id: string; chain: string; record_hash: string }>(`/proposals/${id}/anchor`, { method: 'POST', body: JSON.stringify({ actor_did }) });

// Council
export const openDeliberation = (id: string, d: { participants: string[]; actor_did: string }) => req<{ deliberation_id: string }>(`/proposals/${id}/deliberate`, { method: 'POST', body: JSON.stringify(d) });
export const castVote = (id: string, d: { voter_did: string; choice: string; rationale?: string }) => req(`/proposals/${id}/vote`, { method: 'POST', body: JSON.stringify(d) });
export const resolveDeliberation = (id: string, actor_did?: string) => req<{ result: string; votes_for: number; votes_against: number }>(`/proposals/${id}/resolve`, { method: 'POST', body: JSON.stringify({ actor_did }) });

// Custody & Keys
export const getCustody = (id: string) => req<any[]>(`/proposals/${id}/custody`);
export const registerKey = (d: { actor_did: string; public_key_b64: string }) => req('/keys', { method: 'POST', body: JSON.stringify(d) });
export const getKey = (did: string) => req<{ actor_did: string; public_key_b64: string }>(`/keys/${did}`);
