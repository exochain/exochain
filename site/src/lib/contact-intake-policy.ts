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

export type ContactPayload = {
  name: string;
  email: string;
  organization: string;
  role: string;
  intendedUse: string;
};

export type ContactRateLimitBucket = {
  bucket: string;
  maxRequests: number;
  windowSeconds: number;
};

type ContactPayloadResult =
  | {
      ok: true;
      deliver: true;
      payload: ContactPayload;
    }
  | {
      ok: true;
      deliver: false;
      payload: ContactPayload;
    }
  | {
      ok: false;
      status: 400 | 413;
      error: string;
    };

export const CONTACT_BODY_MAX_BYTES = 8192;
export const CONTACT_HONEYPOT_FIELD = 'website';
export const CONTACT_FIELD_LIMITS = {
  name: 120,
  email: 254,
  organization: 160,
  role: 80,
  intendedUse: 2000,
  clientAddress: 128,
};

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function clean(value: unknown, maxLength: number): string {
  if (typeof value !== 'string') {
    return '';
  }
  return value.trim().slice(0, maxLength);
}

function hasOversizedField(value: unknown, maxLength: number): boolean {
  return typeof value === 'string' && value.trim().length > maxLength;
}

function emptyPayload(): ContactPayload {
  return {
    name: '',
    email: '',
    organization: '',
    role: '',
    intendedUse: '',
  };
}

export function validateContactPayload(data: Record<string, unknown>): ContactPayloadResult {
  if (typeof data[CONTACT_HONEYPOT_FIELD] === 'string' && data[CONTACT_HONEYPOT_FIELD].trim()) {
    return {
      ok: true,
      deliver: false,
      payload: emptyPayload(),
    };
  }

  if (hasOversizedField(data.name, CONTACT_FIELD_LIMITS.name)) {
    return { ok: false, status: 413, error: 'Name is too long.' };
  }
  if (hasOversizedField(data.email, CONTACT_FIELD_LIMITS.email)) {
    return { ok: false, status: 413, error: 'Email is too long.' };
  }
  if (hasOversizedField(data.organization, CONTACT_FIELD_LIMITS.organization)) {
    return { ok: false, status: 413, error: 'Organization is too long.' };
  }
  if (hasOversizedField(data.role, CONTACT_FIELD_LIMITS.role)) {
    return { ok: false, status: 413, error: 'Role is too long.' };
  }
  if (hasOversizedField(data.intendedUse, CONTACT_FIELD_LIMITS.intendedUse)) {
    return { ok: false, status: 413, error: 'Intended use is too long.' };
  }

  const payload = {
    name: clean(data.name, CONTACT_FIELD_LIMITS.name),
    email: clean(data.email, CONTACT_FIELD_LIMITS.email).toLowerCase(),
    organization: clean(data.organization, CONTACT_FIELD_LIMITS.organization),
    role: clean(data.role, CONTACT_FIELD_LIMITS.role),
    intendedUse: clean(data.intendedUse, CONTACT_FIELD_LIMITS.intendedUse),
  };

  if (!payload.name) {
    return { ok: false, status: 400, error: 'Name is required.' };
  }
  if (!payload.email) {
    return { ok: false, status: 400, error: 'Email is required.' };
  }
  if (!EMAIL_PATTERN.test(payload.email)) {
    return { ok: false, status: 400, error: 'A valid email is required.' };
  }

  return {
    ok: true,
    deliver: true,
    payload,
  };
}

export function normalizeClientAddress(value: string | null | undefined): string {
  const firstAddress = (value || '').split(',')[0]?.trim() || '';
  if (!firstAddress) {
    return 'unknown';
  }
  return firstAddress.slice(0, CONTACT_FIELD_LIMITS.clientAddress);
}

export function getContactRateLimitBuckets(input: {
  email: string;
  clientAddress: string;
}): ContactRateLimitBucket[] {
  return [
    {
      bucket: 'contact:global:minute',
      maxRequests: 30,
      windowSeconds: 60,
    },
    {
      bucket: `contact:ip:${input.clientAddress}:hour`,
      maxRequests: 3,
      windowSeconds: 3600,
    },
    {
      bucket: `contact:email:${input.email}:day`,
      maxRequests: 5,
      windowSeconds: 86400,
    },
    {
      bucket: 'contact:global:day',
      maxRequests: 200,
      windowSeconds: 86400,
    },
  ];
}
