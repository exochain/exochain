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

import * as React from 'react';
import { Pill } from './Pill';

export function KPI({
  label,
  value,
  hint,
  mock
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  mock?: boolean;
}) {
  return (
    <div className="border border-ink/10 dark:border-vellum-soft/10 rounded-md px-4 py-3 bg-white/50 dark:bg-ink-soft">
      <div className="flex items-center gap-2 text-eyebrow text-ink/50 dark:text-vellum-soft/50">
        <span>{label}</span>
        {mock && <Pill tone="mock">mock</Pill>}
      </div>
      <div className="mt-1 text-2xl font-semibold tracking-tightish font-mono">
        {value}
      </div>
      {hint && (
        <div className="text-xs text-ink/60 dark:text-vellum-soft/60 mt-1">
          {hint}
        </div>
      )}
    </div>
  );
}
