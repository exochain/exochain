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

import * as React from 'react';

export function Section({
  children,
  className = '',
  width = 'page',
  id
}: {
  children: React.ReactNode;
  className?: string;
  width?: 'page' | 'prose';
  id?: string;
}) {
  return (
    <section id={id} className={`px-6 md:px-10 ${className}`}>
      <div
        className={
          width === 'prose'
            ? 'mx-auto max-w-prose'
            : 'mx-auto max-w-page'
        }
      >
        {children}
      </div>
    </section>
  );
}

export function Eyebrow({
  children,
  className = ''
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`text-eyebrow text-ink/50 dark:text-vellum-soft/50 ${className}`}
    >
      {children}
    </div>
  );
}

export function H1({
  children,
  className = ''
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <h1
      className={`text-4xl md:text-5xl font-semibold tracking-tightish leading-[1.1] ${className}`}
    >
      {children}
    </h1>
  );
}

export function H2({
  children,
  className = ''
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <h2
      className={`text-2xl md:text-3xl font-semibold tracking-tightish ${className}`}
    >
      {children}
    </h2>
  );
}

export function Lede({
  children,
  className = ''
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <p
      className={`text-lg md:text-xl text-ink/80 dark:text-vellum-soft/80 leading-[1.55] ${className}`}
    >
      {children}
    </p>
  );
}
