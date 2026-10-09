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

import { useEffect, useState } from 'react';

const PROBE_PATHS = ['/health', '/ready'] as const;

export function LiveGatewayProbe() {
  const [text, setText] = useState('Reading same-origin /health and /ready.');

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      const parts: string[] = [];
      for (const path of PROBE_PATHS) {
        try {
          const response = await fetch(path, { headers: { accept: 'application/json' } });
          const body = await response.text();
          parts.push(`${path} HTTP ${response.status}\n${body}`);
        } catch (error) {
          const message = error instanceof Error ? error.message : 'fetch failed';
          parts.push(`${path} unreachable (${message})`);
        }
      }
      if (!cancelled) {
        setText(parts.join('\n\n'));
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <pre className="mt-4 overflow-x-auto rounded-md border hairline bg-ink/5 p-4 text-xs font-mono whitespace-pre-wrap">
      {text}
    </pre>
  );
}
