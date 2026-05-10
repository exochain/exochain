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
import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'EXOCHAIN — Chain-of-custody for autonomous execution',
    template: '%s · EXOCHAIN'
  },
  description:
    'EXOCHAIN is chain-of-custody infrastructure for autonomous execution. Credential autonomous intent, verify delegated authority, and preserve evidentiary custody for agents, holons, humans, and AI-native systems.',
  metadataBase: new URL('https://exochain.io'),
  openGraph: {
    title: 'EXOCHAIN — Chain-of-custody for autonomous execution',
    description:
      'Custody-native blockchain. Credentialed volition. Evidentiary execution.',
    type: 'website'
  },
  robots: { index: true, follow: true }
};

export default function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
