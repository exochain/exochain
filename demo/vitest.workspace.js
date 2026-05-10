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

import { defineWorkspace } from 'vitest/config';

export default defineWorkspace([
  {
    test: {
      name: 'services',
      include: ['services/*/src/*.test.js'],
      environment: 'node',
      coverage: {
        provider: 'v8',
        include: ['services/*/src/index.js'],
        thresholds: { perFile: true, lines: 80, functions: 80, branches: 70, statements: 80 },
      },
    },
  },
  {
    esbuild: { jsx: 'automatic' },
    test: {
      name: 'web',
      include: ['web/src/**/*.test.{js,jsx}'],
      environment: 'jsdom',
      globals: true,
      setupFiles: ['web/src/test-setup.js'],
      coverage: {
        provider: 'v8',
        include: ['web/src/**/*.{js,jsx}'],
        exclude: ['web/src/main.jsx'],
        thresholds: { lines: 70, functions: 70, branches: 60, statements: 70 },
      },
    },
  },
]);
