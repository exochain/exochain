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

// Diagram 3: Blockchain mechanism vs. chain-of-custody purpose
export function MechanismVsPurposeDiagram({
  className = ''
}: {
  className?: string;
}) {
  return (
    <svg
      viewBox="0 0 760 260"
      className={`w-full h-auto text-ink dark:text-vellum-soft ${className}`}
      role="img"
      aria-label="Two columns. Left: blockchain mechanism (sequence, finality, signatures). Right: chain-of-custody purpose (responsibility, evidence, revocation)."
    >
      {/* Left column */}
      <g transform="translate(20,20)">
        <text x="0" y="0" fontSize="11" letterSpacing="2" fill="currentColor" opacity="0.6">MECHANISM</text>
        <text x="0" y="22" fontSize="22" fontWeight="600" fill="currentColor">Blockchain</text>
        <g transform="translate(0,50)" stroke="currentColor" strokeWidth="1.3" fill="none">
          {[0, 1, 2, 3, 4].map((i) => (
            <g key={i} transform={`translate(${i * 60},0)`}>
              <rect width="50" height="40" rx="3" />
              <line x1="50" y1="20" x2="60" y2="20" />
            </g>
          ))}
        </g>
        <g transform="translate(0,110)" fill="currentColor" fontSize="12" opacity="0.85">
          <text x="0" y="0">· deterministic ordering</text>
          <text x="0" y="20">· cryptographic signatures</text>
          <text x="0" y="40">· quorum / finality</text>
          <text x="0" y="60">· verifiable history</text>
        </g>
      </g>
      {/* Divider */}
      <line x1="380" y1="20" x2="380" y2="240" stroke="currentColor" strokeWidth="1" opacity="0.25" strokeDasharray="2 4" />
      {/* Right column */}
      <g transform="translate(420,20)">
        <text x="0" y="0" fontSize="11" letterSpacing="2" fill="currentColor" opacity="0.6">PURPOSE</text>
        <text x="0" y="22" fontSize="22" fontWeight="600" fill="currentColor">Chain-of-Custody</text>
        <g transform="translate(0,50)" stroke="currentColor" strokeWidth="1.3" fill="none">
          {[0, 1, 2, 3, 4].map((i) => (
            <g key={i} transform={`translate(${i * 60},0)`}>
              <rect width="50" height="40" rx="3" />
              <circle cx="25" cy="20" r="6" />
              <line x1="50" y1="20" x2="60" y2="20" />
            </g>
          ))}
        </g>
        <g transform="translate(0,110)" fill="currentColor" fontSize="12" opacity="0.85">
          <text x="0" y="0">· identity → authority → volition</text>
          <text x="0" y="20">· consent · policy · execution</text>
          <text x="0" y="40">· revocation cascades</text>
          <text x="0" y="60">· evidentiary accountability</text>
        </g>
      </g>
    </svg>
  );
}
