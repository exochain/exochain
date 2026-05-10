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

// Diagram 4: Internet / Extranet / Intranet surfaces
export function SurfaceMapDiagram({ className = '' }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 880 240"
      className={`w-full h-auto text-ink dark:text-vellum-soft ${className}`}
      role="img"
      aria-label="Three surfaces: public Internet, authenticated Extranet, internal Intranet."
    >
      {[
        {
          x: 20,
          label: 'Internet',
          sub: 'public',
          rows: ['exochain.io', 'docs · trust center · status', 'press · research · contact']
        },
        {
          x: 310,
          label: 'Extranet',
          sub: 'authenticated · OIDC',
          rows: ['app.exochain.io', 'AVC issuance · validation · receipts', 'audit exports · API keys']
        },
        {
          x: 600,
          label: 'Intranet',
          sub: 'internal · SSO · MFA · step-up',
          rows: ['internal.exochain.io', 'governance · pricing policy · incidents', 'security queue · content · logs']
        }
      ].map((c) => (
        <g key={c.label} transform={`translate(${c.x},20)`}>
          <rect width="260" height="200" rx="6" fill="none" stroke="currentColor" strokeWidth="1.3" />
          <text x="20" y="34" fontSize="11" letterSpacing="2" fill="currentColor" opacity="0.6">SURFACE</text>
          <text x="20" y="60" fontSize="22" fontWeight="600" fill="currentColor">{c.label}</text>
          <text x="20" y="80" fontSize="12" fill="currentColor" opacity="0.7">{c.sub}</text>
          <g transform="translate(20,108)" fill="currentColor" fontSize="12" opacity="0.85">
            {c.rows.map((row, i) => (
              <text key={i} x="0" y={i * 22}>{row}</text>
            ))}
          </g>
        </g>
      ))}
    </svg>
  );
}
