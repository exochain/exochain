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

import { PANELS, PROPERTIES, STANCE_COLORS, PANEL_COLORS } from '@/lib/utils';
import { cn } from '@/lib/utils';

interface Opinion {
  agent_did: string;
  agent_label?: string;
  stance: string;
  summary: string;
  confidence?: number;
  panel?: string;
  property?: string;
}

interface FiveByFiveMatrixProps {
  opinions: Opinion[];
}

export default function FiveByFiveMatrix({ opinions }: FiveByFiveMatrixProps) {
  const lookup = new Map<string, Opinion>();
  for (const op of opinions) {
    if (op.panel && op.property) {
      lookup.set(`${op.panel}::${op.property}`, op);
    }
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr>
            <th className="p-2 text-xs text-gray-500 text-left w-28" />
            {PROPERTIES.map((prop) => (
              <th key={prop} className="p-2 text-xs font-medium text-cyan-400 text-center">
                {prop}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {PANELS.map((panel) => (
            <tr key={panel}>
              <td className="p-2">
                <span
                  className={cn(
                    'text-xs px-2 py-0.5 rounded font-medium whitespace-nowrap',
                    PANEL_COLORS[panel],
                  )}
                >
                  {panel}
                </span>
              </td>
              {PROPERTIES.map((prop) => {
                const op = lookup.get(`${panel}::${prop}`);
                return (
                  <td key={prop} className="p-1.5">
                    {op ? (
                      <div
                        className={cn(
                          'rounded-md border p-2 text-center',
                          STANCE_COLORS[op.stance] || 'bg-gray-500/20 text-gray-400 border-gray-400/30',
                        )}
                        title={op.summary}
                      >
                        <div className="text-xs font-medium capitalize">{op.stance}</div>
                        <div className="text-[10px] mt-0.5 opacity-70">
                          {((op.confidence ?? 0) * 100).toFixed(0)}%
                        </div>
                      </div>
                    ) : (
                      <div className="rounded-md border border-dashed border-white/10 p-2 text-center text-[10px] text-gray-600">
                        --
                      </div>
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
