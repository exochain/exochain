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

'use client';

import { FormEvent, useState } from 'react';
import { CONTACT_FIELD_LIMITS, CONTACT_HONEYPOT_FIELD } from '@/lib/contact-intake-policy';

type SubmitStatus = { type: 'idle' | 'success' | 'error'; message: string };

export function ContactForm() {
  const [status, setStatus] = useState<SubmitStatus>({ type: 'idle', message: '' });
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);

    setIsSubmitting(true);
    setStatus({ type: 'idle', message: '' });

    try {
      const response = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formData.get('name'),
          email: formData.get('email'),
          organization: formData.get('organization'),
          role: formData.get('role'),
          intendedUse: formData.get('intendedUse'),
          [CONTACT_HONEYPOT_FIELD]: formData.get(CONTACT_HONEYPOT_FIELD),
        }),
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data?.error || 'Submission failed. Please try again.');
      }

      setStatus({ type: 'success', message: 'Thanks — your inquiry is queued for support.' });
      form.reset();
    } catch (error) {
      setStatus({
        type: 'error',
        message: error instanceof Error ? error.message : 'Unable to submit form right now.',
      });
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <form className="space-y-4 text-sm" onSubmit={onSubmit}>
      <div className="grid grid-cols-2 gap-3">
        <label className="block">
          <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Name</div>
          <input
            name="name"
            className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent"
            maxLength={CONTACT_FIELD_LIMITS.name}
            required
          />
        </label>
        <label className="block">
          <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Email</div>
          <input
            name="email"
            className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent"
            type="email"
            maxLength={CONTACT_FIELD_LIMITS.email}
            required
          />
        </label>
      </div>
      <label className="block">
        <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Organization</div>
        <input
          name="organization"
          className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent"
          maxLength={CONTACT_FIELD_LIMITS.organization}
        />
      </label>
      <label className="block">
        <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Role</div>
        <select
          name="role"
          className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent"
        >
          <option>Developer</option>
          <option>Enterprise / Buyer</option>
          <option>Validator / Node Operator</option>
          <option>Researcher</option>
          <option>Press</option>
          <option>Other</option>
        </select>
      </label>
      <label className="block">
        <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Intended use</div>
        <textarea
          name="intendedUse"
          className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent min-h-[120px]"
          maxLength={CONTACT_FIELD_LIMITS.intendedUse}
        />
      </label>
      <input
        aria-hidden="true"
        autoComplete="off"
        className="hidden"
        maxLength={CONTACT_FIELD_LIMITS.organization}
        name={CONTACT_HONEYPOT_FIELD}
        tabIndex={-1}
        type="text"
      />
      <button
        type="submit"
        disabled={isSubmitting}
        className="border hairline rounded-sm px-3 py-2 text-sm disabled:opacity-50"
      >
        {isSubmitting ? 'Submitting…' : 'Submit'}
      </button>
      {status.message && (
        <p
          className={`text-xs ${status.type === 'success' ? 'text-emerald-500' : 'text-amber-500'}`}
        >
          {status.message}
        </p>
      )}
      <p className="text-xs text-ink/60 dark:text-vellum-soft/60">
        Submissions are queued for support review.
      </p>
    </form>
  );
}
