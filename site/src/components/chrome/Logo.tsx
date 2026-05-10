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

// EXOCHAIN wordmark — restrained, geometric. Hand-drawn SVG.
export function Logo({
  variant = 'full',
  className = ''
}: {
  variant?: 'full' | 'mark';
  className?: string;
}) {
  if (variant === 'mark') {
    return (
      <svg
        className={className}
        viewBox="0 0 32 32"
        fill="none"
        aria-hidden="true"
      >
        <rect
          x="3"
          y="3"
          width="26"
          height="26"
          rx="4"
          stroke="currentColor"
          strokeWidth="1.5"
        />
        <path
          d="M9 16h14M16 9v14"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="square"
        />
        <circle cx="16" cy="16" r="3.5" stroke="currentColor" strokeWidth="1.5" />
      </svg>
    );
  }
  return (
    <span
      className={`inline-flex items-center gap-2 font-semibold tracking-eyebrow text-[15px] ${className}`}
    >
      <svg viewBox="0 0 32 32" className="h-5 w-5" fill="none" aria-hidden="true">
        <rect
          x="3"
          y="3"
          width="26"
          height="26"
          rx="4"
          stroke="currentColor"
          strokeWidth="1.5"
        />
        <path
          d="M9 16h14M16 9v14"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="square"
        />
        <circle
          cx="16"
          cy="16"
          r="3.5"
          stroke="currentColor"
          strokeWidth="1.5"
        />
      </svg>
      EXOCHAIN
    </span>
  );
}
