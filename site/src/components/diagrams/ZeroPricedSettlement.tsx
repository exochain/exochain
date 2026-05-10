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

// Diagram 5: Zero-priced launch settlement flow
export function ZeroPricedSettlementDiagram({
  className = ''
}: {
  className?: string;
}) {
  return (
    <svg
      viewBox="0 0 800 220"
      className={`w-full h-auto text-ink dark:text-vellum-soft ${className}`}
      role="img"
      aria-label="Trust receipt issued; quote requested with amount zero and ZeroFeeReason; settlement receipt issued with amount zero."
    >
      <defs>
        <marker id="zps-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
          <path d="M0 0 L10 5 L0 10 z" fill="currentColor" />
        </marker>
      </defs>
      {[
        { x: 20, label: 'Trust Receipt', sub: 'execution evidence' },
        { x: 240, label: 'Settlement Quote', sub: 'amount = 0\nZeroFeeReason: launch_policy_zero' },
        { x: 500, label: 'Settlement Receipt', sub: 'amount = 0\nsigned · chained' }
      ].map((c) => (
        <g key={c.label} transform={`translate(${c.x},40)`}>
          <rect width="220" height="140" rx="6" fill="none" stroke="currentColor" strokeWidth="1.3" />
          <text x="20" y="34" fontSize="11" letterSpacing="2" fill="currentColor" opacity="0.6">{c.label.toUpperCase()}</text>
          {c.sub.split('\n').map((line, i) => (
            <text key={i} x="20" y={70 + i * 22} fontSize="13" fill="currentColor">{line}</text>
          ))}
        </g>
      ))}
      <g stroke="currentColor" strokeWidth="1.4" fill="none" markerEnd="url(#zps-arrow)">
        <line x1="240" y1="110" x2="260" y2="110" />
        <line x1="500" y1="110" x2="520" y2="110" />
      </g>
      <text x="400" y="210" textAnchor="middle" fontSize="11" fill="currentColor" opacity="0.65">
        The transaction mechanism is preserved. Pricing is suppressed by policy until governance amends it.
      </text>
    </svg>
  );
}
