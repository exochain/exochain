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

// Diagram 1: Human → AVC → Agent → EXOCHAIN → Trust Receipt
// Restrained, line-based. No glow. Theme-aware via currentColor.
export function CustodyFlowDiagram({
  className = ''
}: {
  className?: string;
}) {
  return (
    <svg
      viewBox="0 0 880 220"
      className={`w-full h-auto text-ink dark:text-vellum-soft ${className}`}
      role="img"
      aria-label="Human delegates to an Agent via an Autonomous Volition Credential. The Agent acts. EXOCHAIN records a trust receipt."
    >
      <defs>
        <marker
          id="cf-arrow"
          viewBox="0 0 10 10"
          refX="8"
          refY="5"
          markerWidth="8"
          markerHeight="8"
          orient="auto-start-reverse"
        >
          <path d="M0 0 L10 5 L0 10 z" fill="currentColor" />
        </marker>
      </defs>
      {/* Human */}
      <g transform="translate(20,60)">
        <rect width="120" height="100" rx="6" fill="none" stroke="currentColor" strokeWidth="1.4" />
        <text x="60" y="36" textAnchor="middle" fontSize="11" letterSpacing="2" fill="currentColor">HUMAN</text>
        <text x="60" y="60" textAnchor="middle" fontSize="13" fill="currentColor">Principal</text>
        <text x="60" y="78" textAnchor="middle" fontSize="11" fill="currentColor" opacity="0.7">declares intent</text>
      </g>
      {/* AVC */}
      <g transform="translate(200,40)">
        <rect width="160" height="140" rx="6" fill="none" stroke="currentColor" strokeWidth="1.4" />
        <text x="80" y="32" textAnchor="middle" fontSize="11" letterSpacing="2" fill="currentColor">AVC</text>
        <text x="80" y="58" textAnchor="middle" fontSize="13" fill="currentColor">Autonomous</text>
        <text x="80" y="74" textAnchor="middle" fontSize="13" fill="currentColor">Volition</text>
        <text x="80" y="90" textAnchor="middle" fontSize="13" fill="currentColor">Credential</text>
        <text x="80" y="116" textAnchor="middle" fontSize="11" fill="currentColor" opacity="0.7">scope · expiry · signature</text>
      </g>
      {/* Agent */}
      <g transform="translate(420,60)">
        <rect width="120" height="100" rx="6" fill="none" stroke="currentColor" strokeWidth="1.4" />
        <text x="60" y="36" textAnchor="middle" fontSize="11" letterSpacing="2" fill="currentColor">AGENT</text>
        <text x="60" y="60" textAnchor="middle" fontSize="13" fill="currentColor">Subject</text>
        <text x="60" y="78" textAnchor="middle" fontSize="11" fill="currentColor" opacity="0.7">acts within scope</text>
      </g>
      {/* EXOCHAIN */}
      <g transform="translate(600,40)">
        <rect width="160" height="140" rx="6" fill="none" stroke="currentColor" strokeWidth="1.4" />
        <text x="80" y="32" textAnchor="middle" fontSize="11" letterSpacing="2" fill="currentColor">EXOCHAIN</text>
        <text x="80" y="58" textAnchor="middle" fontSize="13" fill="currentColor">Custody-Native</text>
        <text x="80" y="74" textAnchor="middle" fontSize="13" fill="currentColor">Blockchain</text>
        <text x="80" y="90" textAnchor="middle" fontSize="13" fill="currentColor">+ Verifiers</text>
        <text x="80" y="116" textAnchor="middle" fontSize="11" fill="currentColor" opacity="0.7">validates · records · attests</text>
      </g>
      {/* Trust Receipt */}
      <g transform="translate(780,60)">
        <rect width="80" height="100" rx="6" fill="none" stroke="currentColor" strokeWidth="1.4" />
        <text x="40" y="36" textAnchor="middle" fontSize="11" letterSpacing="2" fill="currentColor">RECEIPT</text>
        <text x="40" y="62" textAnchor="middle" fontSize="11" fill="currentColor">Trust</text>
        <text x="40" y="78" textAnchor="middle" fontSize="11" fill="currentColor">+ Settlement</text>
      </g>
      {/* Arrows */}
      <g stroke="currentColor" strokeWidth="1.4" fill="none" markerEnd="url(#cf-arrow)">
        <line x1="140" y1="110" x2="200" y2="110" />
        <line x1="360" y1="110" x2="420" y2="110" />
        <line x1="540" y1="110" x2="600" y2="110" />
        <line x1="760" y1="110" x2="780" y2="110" />
      </g>
      {/* Revocation back-arrow */}
      <g stroke="currentColor" strokeWidth="1" strokeDasharray="3 3" fill="none" markerEnd="url(#cf-arrow)" opacity="0.55">
        <path d="M 820 60 C 820 20, 280 20, 280 40" />
      </g>
      <text x="540" y="22" textAnchor="middle" fontSize="10" letterSpacing="2" fill="currentColor" opacity="0.6">REVOCATION · CASCADES THROUGH AVC</text>
    </svg>
  );
}
