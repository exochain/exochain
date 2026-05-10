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

import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./src/**/*.{ts,tsx,mdx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Restrained palette per SPEC §12. No neon, no glow.
        ink: {
          DEFAULT: '#0B0E14',
          deep: '#06080C',
          soft: '#11141C'
        },
        vellum: {
          DEFAULT: '#F5F2EA',
          soft: '#FAF7F0',
          deep: '#E8E2D2'
        },
        slate: {
          50: '#F4F5F7',
          100: '#E4E7EC',
          200: '#C7CCD6',
          300: '#9AA1AE',
          400: '#6E7585',
          500: '#4B515E',
          600: '#363B45',
          700: '#252932',
          800: '#181B22',
          900: '#0F1218'
        },
        custody: {
          DEFAULT: '#3FB6C8',
          deep: '#1F7C8C',
          glow: '#7AD4E2'
        },
        signal: {
          DEFAULT: '#D9A24E',
          deep: '#9C6F26',
          soft: '#F1C681'
        },
        alert: {
          DEFAULT: '#C0524A',
          deep: '#8E342D',
          soft: '#E08A82'
        },
        verify: {
          DEFAULT: '#5A8C5C',
          deep: '#37633A',
          soft: '#9AC09C'
        }
      },
      fontFamily: {
        sans: ['"Inter"', 'system-ui', 'sans-serif'],
        serif: ['"IBM Plex Serif"', 'Georgia', 'serif'],
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', 'ui-monospace', 'monospace']
      },
      letterSpacing: {
        tightish: '-0.01em',
        eyebrow: '0.18em'
      },
      maxWidth: {
        prose: '68ch',
        page: '1200px'
      }
    }
  },
  plugins: []
};

export default config;
