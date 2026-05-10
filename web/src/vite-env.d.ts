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

/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * When set to the literal string `'true'` AND the build is in DEV mode,
   * allows the Council dashboard to bypass backend auth using a localStorage
   * flag. ALWAYS unset in production builds. See docs/audit A-031.
   */
  readonly VITE_ALLOW_DEV_BYPASS?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
