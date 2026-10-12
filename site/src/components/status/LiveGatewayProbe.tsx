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
const PROBE_TIMEOUT_MS = 5000;

type ProbePath = (typeof PROBE_PATHS)[number];

type ProbeResult = {
  path: ProbePath;
  text: string;
};

async function readProbe(path: ProbePath, signal: AbortSignal): Promise<string> {
  try {
    const response = await fetch(path, {
      headers: { accept: 'application/json' },
      signal
    });
    const body = await response.text();
    return `${path} HTTP ${response.status}\n${body}`;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'fetch failed';
    return `${path} unreachable (${message})`;
  }
}

export function LiveGatewayProbe() {
  const [probes, setProbes] = useState<ProbeResult[]>(
    PROBE_PATHS.map((path) => ({ path, text: `Reading ${path}.` }))
  );

  useEffect(() => {
    let active = true;
    const cleanups: Array<() => void> = [];

    for (const path of PROBE_PATHS) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
      cleanups.push(() => {
        clearTimeout(timer);
        controller.abort();
      });
      void readProbe(path, controller.signal).then((text) => {
        if (!active) {
          return;
        }
        setProbes((current) =>
          current.map((probe) => (probe.path === path ? { path, text } : probe))
        );
      });
    }

    return () => {
      active = false;
      for (const cleanup of cleanups) {
        cleanup();
      }
    };
  }, []);

  return (
    <div className="mt-4 space-y-3">
      {probes.map((probe) => (
        <pre
          key={probe.path}
          className="overflow-x-auto rounded-md border hairline bg-ink/5 p-4 text-xs font-mono whitespace-pre-wrap"
        >
          {probe.text}
        </pre>
      ))}
    </div>
  );
}
