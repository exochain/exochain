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

import { Eyebrow, H1, Lede } from '@/components/ui/Section';
import { Pill } from '@/components/ui/Pill';
import * as React from 'react';

export function AppPageHead({
  eyebrow,
  title,
  lede,
  pills,
  right
}: {
  eyebrow: string;
  title: string;
  lede?: string;
  pills?: React.ReactNode;
  right?: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 mb-6">
      <div>
        <Eyebrow>{eyebrow}</Eyebrow>
        <H1 className="mt-3 text-3xl">{title}</H1>
        {lede && <Lede className="mt-2 max-w-2xl">{lede}</Lede>}
        {pills && <div className="mt-3 flex flex-wrap gap-2">{pills}</div>}
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </div>
  );
}

export function AuditNote({ children }: { children?: React.ReactNode }) {
  return (
    <div className="mt-3 text-xs text-ink/60 dark:text-vellum-soft/60">
      {children ?? 'This action writes to the audit log.'}
    </div>
  );
}

export { Pill };
