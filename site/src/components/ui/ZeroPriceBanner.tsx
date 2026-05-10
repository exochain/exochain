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

import { Pill } from './Pill';

export function ZeroPriceBanner({
  variant = 'page'
}: {
  variant?: 'page' | 'inline';
}) {
  const body = (
    <>
      <Pill tone="custody">Zero-priced launch settlement</Pill>
      <span className="text-sm text-ink/80 dark:text-vellum-soft/80">
        The transaction mechanism is live. Every active price resolves to{' '}
        <span className="font-mono">0 EXO</span> with an explicit{' '}
        <span className="font-mono">ZeroFeeReason</span>. Future governance
        amendments may enable nonzero pricing.
      </span>
    </>
  );
  if (variant === 'inline') {
    return (
      <div className="flex flex-wrap items-center gap-3 text-sm">
        {body}
      </div>
    );
  }
  return (
    <div className="border border-custody/30 bg-custody/[0.06] rounded-md px-4 py-3 flex flex-wrap items-center gap-3">
      {body}
    </div>
  );
}
