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

import type { Metadata } from 'next';

/**
 * Preferred canonical origin. exochain.com, exochain.ai, and exochain.net
 * serve the same pages. Copy does not branch on the request host.
 * Search metadata points at exochain.com so the three hostnames do not
 * compete as duplicate documents.
 */
export const CANONICAL_ORIGIN = 'https://exochain.com';

export const PUBLIC_HOSTS = ['exochain.com', 'exochain.ai', 'exochain.net'] as const;

export const MIRROR_ORIGINS = ['https://exochain.ai', 'https://exochain.net'] as const;

export const LEGAL_ENTITY = 'EXOCHAIN PBC';
export const LEGAL_EMAIL = 'legal@exochain.com';

export const PRODUCT_CHANNEL = 'beta';
export const RELEASE_VERSION = 'v0.2.7';
export const NORMATIVE_SPEC = 'v2.2';
export const CORE_LICENSE = 'Apache-2.0';

export const SITE_NAME = 'EXOCHAIN';

export const SITE_TITLE = 'EXOCHAIN — The trust fabric for autonomous commerce';

export const SITE_DESCRIPTION =
  'EXOCHAIN is the trust fabric for autonomous commerce. Proof of Authority is a working category concept: a portable, independently verifiable claim that an agent action falls within valid delegated authority, satisfies constraints, and has an attributable outcome.';

export function canonicalUrl(path: string): string {
  const normalized = path.startsWith('/') ? path : `/${path}`;
  if (normalized === '/') {
    return `${CANONICAL_ORIGIN}/`;
  }
  return `${CANONICAL_ORIGIN}${normalized}`;
}

export function mirrorUrls(path: string): string[] {
  const normalized = path.startsWith('/') ? path : `/${path}`;
  const suffix = normalized === '/' ? '/' : normalized;
  return MIRROR_ORIGINS.map((origin) => `${origin}${suffix}`);
}

export function publicMetadata(input: {
  title: string;
  description: string;
  path: string;
  absoluteTitle?: string;
}): Metadata {
  const canonical = canonicalUrl(input.path);
  const socialTitle = input.absoluteTitle ?? `${input.title} · EXOCHAIN`;
  return {
    title: input.absoluteTitle ? { absolute: input.absoluteTitle } : input.title,
    description: input.description,
    alternates: {
      canonical,
      languages: {
        en: canonical,
        'x-default': canonical,
      },
    },
    openGraph: {
      title: socialTitle,
      description: input.description,
      url: canonical,
      type: 'website',
      siteName: SITE_NAME,
    },
    twitter: {
      card: 'summary',
      title: socialTitle,
      description: input.description,
    },
    other: {
      'exochain:mirror-hosts': mirrorUrls(input.path).join(' '),
    },
  };
}

export function withCanonical(metadata: Metadata, path: string): Metadata {
  const canonical = canonicalUrl(path);
  const openGraph =
    metadata.openGraph && typeof metadata.openGraph === 'object' ? metadata.openGraph : {};
  return {
    ...metadata,
    alternates: {
      canonical,
      languages: {
        en: canonical,
        'x-default': canonical,
      },
    },
    openGraph: {
      ...openGraph,
      url: canonical,
    },
  };
}
