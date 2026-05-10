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

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        display: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      screens: {
        tablet: '768px',
        desktop: '1280px',
      },
      spacing: {
        sidebar: '240px',
      },
      width: {
        sidebar: '240px',
      },
      minWidth: {
        sidebar: '240px',
      },
      colors: {
        governance: {
          50: '#f0f7ff',
          100: '#e0efff',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          900: '#1e3a5f',
        },
        urgency: {
          critical: '#DC2626',
          high: '#EA580C',
          moderate: '#CA8A04',
          low: '#16A34A',
          neutral: '#6B7280',
        },
        status: {
          created: '#94A3B8',
          deliberation: '#3B82F6',
          voting: '#EAB308',
          approved: '#22C55E',
          rejected: '#EF4444',
          void: '#6B7280',
          contested: '#F97316',
          ratification: '#8B5CF6',
          expired: '#991B1B',
          degraded: '#D97706',
        },
        surface: {
          base: '#F8FAFC',
          raised: '#FFFFFF',
          overlay: '#F1F5F9',
        },
        'text-gov': {
          primary: '#0F172A',
          secondary: '#64748B',
        },
        'border-subtle': '#E2E8F0',
        'accent-primary': '#2563EB',
        'accent-hover': '#1D4ED8',
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.875rem' }],
      },
    },
  },
  plugins: [],
}
