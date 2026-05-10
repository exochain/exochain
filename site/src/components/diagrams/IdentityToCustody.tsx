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

// Diagram 2: Identity → Authority → Volition → Consent → Execution → Custody Receipt
export function IdentityToCustodyDiagram({
  className = ''
}: {
  className?: string;
}) {
  const stages = [
    { label: 'Identity', sub: 'who an actor is' },
    { label: 'Authority', sub: 'what it may invoke' },
    { label: 'Volition', sub: 'delegated intent' },
    { label: 'Consent', sub: 'principal grant' },
    { label: 'Execution', sub: 'what it actually did' },
    { label: 'Custody Receipt', sub: 'evidentiary record' }
  ];
  const w = 920;
  const h = 160;
  const stepW = w / stages.length;
  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      className={`w-full h-auto text-ink dark:text-vellum-soft ${className}`}
      role="img"
      aria-label="Six stages: Identity, Authority, Volition, Consent, Execution, Custody Receipt."
    >
      {stages.map((s, i) => {
        const x = i * stepW;
        return (
          <g key={s.label} transform={`translate(${x},20)`}>
            <rect
              width={stepW - 12}
              height="120"
              rx="4"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.2"
            />
            <text
              x={(stepW - 12) / 2}
              y="32"
              textAnchor="middle"
              fontSize="10"
              letterSpacing="2"
              fill="currentColor"
              opacity="0.65"
            >
              {String(i + 1).padStart(2, '0')}
            </text>
            <text
              x={(stepW - 12) / 2}
              y="62"
              textAnchor="middle"
              fontSize="14"
              fontWeight="600"
              fill="currentColor"
            >
              {s.label}
            </text>
            <text
              x={(stepW - 12) / 2}
              y="86"
              textAnchor="middle"
              fontSize="11"
              fill="currentColor"
              opacity="0.7"
            >
              {s.sub}
            </text>
            {i < stages.length - 1 && (
              <line
                x1={stepW - 12}
                y1="60"
                x2={stepW}
                y2="60"
                stroke="currentColor"
                strokeWidth="1.2"
              />
            )}
          </g>
        );
      })}
    </svg>
  );
}
