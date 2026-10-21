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

import { readFileSync } from 'node:fs';
import path from 'node:path';

export type PublicStatusFeature = {
  package: string;
  feature: string;
  boundary: string;
};

export type PublicStatusCapability = {
  name: string;
  posture: string;
};

export type PublicStatus = {
  maturity: string;
  maturity_summary: string;
  spec: {
    normative_version: string;
    normative_document: string;
    authority_record: string;
    engineering_version: string;
    engineering_document: string;
    v2_3_present_in_repository: boolean;
  };
  publication: {
    version: string;
    observed_at: string;
    github_published_at: string;
    github_url: string;
    native_archive_contents: string;
    runtime_deployment_claimed: boolean;
    pypi_package: string;
  };
  gap_registry: {
    path: string;
    header_amended: string;
    header_records_release: string;
    note: string;
  };
  default_off_features: PublicStatusFeature[];
  bounded_capabilities: PublicStatusCapability[];
};

/** Repository path of the node-packaged status facts, relative to `site/`. */
export const CANONICAL_PUBLIC_STATUS_PATH = '../crates/exo-node/src/public-status.json';

export function canonicalPublicStatusPath(): string {
  return path.resolve(process.cwd(), CANONICAL_PUBLIC_STATUS_PATH);
}

export function loadPublicStatus(): PublicStatus {
  const raw = readFileSync(canonicalPublicStatusPath(), 'utf8');
  return JSON.parse(raw) as PublicStatus;
}
